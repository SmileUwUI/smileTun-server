package server

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"smiletun-server/config"
	"smiletun-server/crypto"
	"smiletun-server/logger"
	"smiletun-server/users"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const FirstPacketSize = chacha20poly1305.NonceSize + 16 + 8 + chacha20poly1305.Overhead // NonceSize + UsernameSize + TimestampSize + AEADtagSize

type Client struct {
	addr           string
	conn           *net.TCPConn
	user           *users.User
	countRecv      uint32
	countSent      uint32
	countRecvBytes uint32
	countSentBytes uint32
	sessionKey     []byte
	createdAt      time.Time
	lastActive     time.Time
	mu             sync.RWMutex
}

func (c *Client) computeNextSessionKey(salt []byte) {
	hasher := sha256.New()
	hasher.Write(c.sessionKey)
	hasher.Write([]byte(":"))
	hasher.Write(salt)

	c.sessionKey = hasher.Sum(nil)
}

type Server struct {
	config      *config.Config
	users       *users.Users
	listener    net.Listener
	wg          sync.WaitGroup
	clientCount int32
	clients     map[string]*Client
	logger      *logger.Logger

	stopCh chan struct{}
	mu     sync.RWMutex
}

func NewServer(cfg *config.Config, usersDB *users.Users, logger *logger.Logger) *Server {
	logger.Info("Creating new server instance")
	return &Server{
		config:  cfg,
		users:   usersDB,
		clients: make(map[string]*Client),
		stopCh:  make(chan struct{}),
		logger:  logger,
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.logger.Info("Starting TCP server on %s", addr)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Error("Failed to start TCP server on %s: %v", addr, err)
		return fmt.Errorf("failed to start TCP server: %w", err)
	}

	s.listener = listener
	s.logger.Info("TCP proxy server listening on %s", addr)

	s.logger.Debug("Starting accept connections goroutine")
	go s.acceptConnections()

	s.logger.Debug("Starting cleanup idle clients goroutine")
	go s.cleanupIdleClients()

	s.logger.Info("Server started successfully")
	return nil
}

func (s *Server) acceptConnections() {
	s.logger.Debug("Accept connections loop started")

	for {
		select {
		case <-s.stopCh:
			s.logger.Info("Accept connections loop stopped by stop signal")
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					s.logger.Debug("Accept interrupted during shutdown")
					return
				default:
					s.logger.Error("Failed to accept connection: %v", err)
					continue
				}
			}

			s.mu.RLock()
			clientCount := int(s.clientCount)
			maxClients := s.config.MaxClients
			s.mu.RUnlock()

			s.logger.Debug("New connection from %s, current clients: %d/%d", conn.RemoteAddr(), clientCount, maxClients)

			if clientCount >= maxClients {
				s.logger.Debug("Max clients reached (%d/%d), rejecting connection from %s", clientCount, maxClients, conn.RemoteAddr())
				conn.Close()
				continue
			}

			s.wg.Add(1)
			s.incrementClientCount()
			s.logger.Debug("Starting handle connection goroutine for %s", conn.RemoteAddr())
			go s.handleConnection(conn)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()
	s.logger.Info("Handling new connection from %s", clientAddr)

	defer func() {
		s.logger.Debug("Closing connection from %s", clientAddr)
		s.wg.Done()
		s.decrementClientCount()
		s.logger.Info("Connection from %s closed", clientAddr)
	}()

	s.logger.Debug("Setting read deadline to 15 seconds for %s", clientAddr)
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	s.logger.Debug("Reading first packet from %s (size: %d bytes)", clientAddr, FirstPacketSize)
	firstPacket := make([]byte, FirstPacketSize)
	if _, err := io.ReadFull(conn, firstPacket); err != nil {
		s.logger.Error("Failed to read first packet from %s: %v", clientAddr, err)
		conn.Close()
		return
	}
	s.logger.Debug("First packet received from %s", clientAddr)

	nonce := firstPacket[:12]
	s.logger.Trace("Extracted nonce from %s: %x", clientAddr, nonce)

	s.logger.Debug("Decrypting first packet from %s with init password", clientAddr)
	plainPacket, err := crypto.DecryptChaCha20Poly1305(firstPacket[12:], nonce, s.config.InitPassword[:])
	if err != nil {
		s.logger.Error("Failed to decrypt first packet from %s: %v", clientAddr, err)
		conn.Close()
		return
	}
	s.logger.Debug("First packet decrypted successfully from %s", clientAddr)

	timestamp := int64(binary.BigEndian.Uint64(plainPacket[16:24]))
	currentTime := time.Now().Unix()
	timeDiff := currentTime - timestamp

	s.logger.Debug("Timestamp from %s: %d, current: %d, diff: %d", clientAddr, timestamp, currentTime, timeDiff)

	if timeDiff > 5 {
		s.logger.Debug("Invalid timestamp from %s: %d (current: %d), diff: %d", clientAddr, timestamp, currentTime, timeDiff)
		conn.Close()
		return
	}
	s.logger.Debug("Timestamp validation passed for %s", clientAddr)

	var username [16]byte
	copy(username[:], plainPacket[:16])
	s.logger.Debug("Extracted username from %s: %x", clientAddr, username)

	s.logger.Debug("Looking up user %x in database", username)
	user := s.users.GetUser(username)
	if user == nil {
		s.logger.Debug("User not found from %s: %x", clientAddr, username)
		conn.Close()
		return
	}
	s.logger.Info("User %x authenticated successfully from %s", username[:8], clientAddr)

	s.logger.Debug("Generating 32-byte salt for %s", clientAddr)
	salt := crypto.RandomBytes(32)
	s.logger.Trace("Generated salt for %s: %x", clientAddr, salt)

	s.logger.Debug("Encrypting salt with init password for %s", clientAddr)
	rawSaltPacket, nonce, err := crypto.EncryptChaCha20Poly1305(salt, s.config.InitPassword[:])

	if err != nil {
		s.logger.Error("Failed to encrypt salt for %s: %v", clientAddr, err)
		conn.Close()
		return
	}
	s.logger.Debug("Salt encrypted successfully for %s", clientAddr)

	packet := make([]byte, len(rawSaltPacket)+len(nonce))
	copy(packet[:12], nonce)
	copy(packet[12:], rawSaltPacket)

	trashPacket := crypto.Trashfication(packet, 400, 1300)
	s.logger.Debug("Sending salt packet to %s (size: %d bytes, after trash: %d)", clientAddr, len(packet), len(trashPacket))

	if _, err := conn.Write(trashPacket); err != nil {
		s.logger.Error("Failed to send salt to %s: %v", clientAddr, err)
		conn.Close()
		return
	}
	s.logger.Debug("Salt packet sent to %s", clientAddr)

	s.logger.Debug("Deriving session key for %s", clientAddr)
	sessionKeyHasher := sha256.New()
	password := user.GetPassword()

	sessionKeyHasher.Write(password[:])
	sessionKeyHasher.Write([]byte(":"))
	sessionKeyHasher.Write(salt)
	sessionKey := sessionKeyHasher.Sum(nil)
	s.logger.Debug("Session key derived for %s", clientAddr)

	s.logger.Info("New client registered: %s", clientAddr)

	s.logger.Debug("Adding client %s to clients map", clientAddr)
	client := s.addClient(conn, user, sessionKey)

	s.logger.Debug("Removing read deadline for %s", clientAddr)
	conn.SetDeadline(time.Time{})

	s.logger.Debug("Starting client handler goroutine for %s", clientAddr)
	go s.handleClient(client)
}

func (s *Server) addClient(conn net.Conn, user *users.User, sessionKey []byte) (client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()

	addr := conn.RemoteAddr().String()
	s.logger.Debug("Adding client %s to server registry", addr)

	connTCP := conn.(*net.TCPConn)
	connTCP.SetNoDelay(true)

	client = &Client{
		addr:           addr,
		conn:           connTCP,
		user:           user,
		countRecvBytes: 0,
		countSentBytes: 0,
		sessionKey:     sessionKey,
		createdAt:      time.Now(),
		lastActive:     time.Now(),
	}

	s.clients[addr] = client
	s.logger.Info("Client %s added successfully, total clients: %d", addr, len(s.clients))

	return client
}

func (s *Server) cleanupIdleClients() {
	s.logger.Debug("Cleanup idle clients loop started")
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			s.logger.Info("Cleanup idle clients loop stopped")
			return
		case <-ticker.C:
			s.logger.Debug("Running idle clients cleanup check")

			s.mu.Lock()
			idleCount := 0
			for addr, client := range s.clients {
				idleTime := time.Since(client.lastActive)
				if idleTime > 10*time.Minute {
					s.logger.Info("Closing idle client: %s (idle for %v)", addr, idleTime)
					client.conn.Close()
					delete(s.clients, addr)
					idleCount++
				}
			}
			s.mu.Unlock()

			if idleCount > 0 {
				s.logger.Info("Closed %d idle clients", idleCount)
			} else {
				s.logger.Debug("No idle clients found")
			}
		}
	}
}

func (s *Server) handleClient(client *Client) {
	defer client.conn.Close()
	clientAddr := client.addr
	s.logger.Info("Starting client handler for %s", clientAddr)

	for {
		select {
		case <-s.stopCh:
			s.logger.Info("Client handler for %s stopped by server shutdown", clientAddr)
			return
		default:
			lenRawPacketBytes := make([]byte, 2)
			n, err := client.conn.Read(lenRawPacketBytes)
			if err != nil {
				s.logger.Error("Socket read error from %s: %v", clientAddr, err)
				return
			}

			lenRawPacketBytes[0] = lenRawPacketBytes[0] ^ client.sessionKey[0]
			lenRawPacketBytes[1] = lenRawPacketBytes[1] ^ client.sessionKey[1]
			lenRawPacket := binary.BigEndian.Uint16(lenRawPacketBytes)

			encrypted := make([]byte, lenRawPacket-2)
			s.logger.Trace("Reading encrypted data from %s", clientAddr)
			n, err = client.conn.Read(encrypted)
			if err != nil {
				s.logger.Error("Socket read error from %s: %v", clientAddr, err)
				return
			}

			s.logger.Debug("Received packet #%d from %s (size: %d bytes)", client.countRecv, clientAddr, n)

			packet := NewEncryptedPacket(encrypted, s.logger)
			err = packet.Decrypt(client.sessionKey, n, clientAddr)
			if err != nil {
				s.logger.Error("Error processing the packet: %v", err)
				continue
			}

			client.countRecv++
			client.computeNextSessionKey(packet.Salt)

			s.logger.Info("Decrypted packet #%d from %s (size: %d bytes)", client.countRecv, clientAddr, len(packet.Data))
			s.logger.Trace("Plaintext data from %s: %x", clientAddr, packet.Data)

			client.mu.Lock()
			client.lastActive = time.Now()
			client.countRecvBytes += uint32(len(packet.Data))
			client.mu.Unlock()

			s.logger.Debug("Client %s stats updated - received: %d bytes, total packets: %d",
				clientAddr, client.countRecvBytes, client.countRecv)
			s.logger.Debug("______________________________________________________________________________")
		}
	}
}

func (s *Server) incrementClientCount() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientCount++
	s.logger.Debug("Client count incremented to %d", s.clientCount)
}

func (s *Server) decrementClientCount() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientCount--
	s.logger.Debug("Client count decremented to %d", s.clientCount)
}

func (s *Server) GetClientCount() int32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.logger.Trace("GetClientCount called, returning %d", s.clientCount)
	return s.clientCount
}
