package server

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"smiletun-server/config"
	"smiletun-server/crypto"
	"smiletun-server/users"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const FirstPacketSize = chacha20poly1305.NonceSize + 16 + 8 + chacha20poly1305.Overhead // NonceSize + UsernameSize + TimestampSize + AEADtagSize

type Client struct {
	addr       string
	conn       net.Conn
	user       *users.User
	countRecv  uint32
	countSent  uint32
	sessionKey []byte
	createdAt  time.Time
	lastActive time.Time
	mu         sync.RWMutex
}

type Server struct {
	config      *config.Config
	users       *users.Users
	listener    net.Listener
	wg          sync.WaitGroup
	clientCount int32
	clients     map[string]*Client

	stopCh chan struct{}
	mu     sync.RWMutex
}

func NewServer(cfg *config.Config, usersDB *users.Users) *Server {
	return &Server{
		config:  cfg,
		users:   usersDB,
		clients: make(map[string]*Client),
		stopCh:  make(chan struct{}),
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start TCP server: %w", err)
	}

	s.listener = listener
	log.Printf("TCP proxy server listening on %s", addr)

	go s.acceptConnections()
	go s.cleanupIdleClients()

	for {

	}

	return nil
}

func (s *Server) acceptConnections() {
	for {
		select {
		case <-s.stopCh:
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					return
				default:
					log.Printf("Failed to accept connection: %v", err)
					continue
				}
			}

			s.mu.RLock()
			if int(s.clientCount) >= s.config.MaxClients {
				s.mu.RUnlock()
				log.Printf("Max clients reached, rejecting connection from %s", conn.RemoteAddr())
				conn.Close()
				continue
			}
			s.mu.RUnlock()

			s.wg.Add(1)
			s.incrementClientCount()
			go s.handleConnection(conn)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer s.decrementClientCount()
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(15 * time.Second))

	firstPacket := make([]byte, FirstPacketSize)
	if _, err := io.ReadFull(conn, firstPacket); err != nil {
		log.Printf("Failed to read first packet from %s: %v", conn.RemoteAddr(), err)
		return
	}

	nonce := firstPacket[:12]

	plainPacket, err := crypto.DecryptChaCha20Poly1305(firstPacket[12:], nonce, s.config.InitPassword[:])
	if err != nil {
		log.Printf("Failed to decrypt first packet from %s: %v", conn.RemoteAddr(), err)
		return
	}

	timestamp := int64(binary.BigEndian.Uint64(plainPacket[16:]))
	currentTime := time.Now().Unix()

	if currentTime-timestamp > 5 {
		log.Printf("Invalid timestamp from %s: %d (current: %d)", conn.RemoteAddr(), timestamp, currentTime)
		return
	}

	var username [16]byte
	copy(username[:], plainPacket[:16])

	user := s.users.GetUser(username)
	if user == nil {
		log.Printf("User not found from %s: %x", conn.RemoteAddr(), username)
		return
	}

	salt := crypto.RandomBytes(32)

	rawSaltPacket, nonce, err := crypto.EncryptChaCha20Poly1305(salt, s.config.InitPassword[:])

	if err != nil {
		log.Printf("Failed to encrypt salt: %v", err)
		return
	}

	packet := make([]byte, len(rawSaltPacket)+len(nonce))
	copy(packet[:12], nonce)
	copy(packet[12:], rawSaltPacket)

	if _, err := conn.Write(crypto.Trashfication(packet, 400, 1300)); err != nil {
		log.Printf("Failed to send salt: %v", err)
		return
	}

	sessionKeyHasher := sha256.New()
	password := user.GetPassword()

	sessionKeyHasher.Write(password[:])
	sessionKeyHasher.Write([]byte(":"))
	sessionKeyHasher.Write(salt)

	log.Printf("New client %s", conn.RemoteAddr())

	s.addClient(conn, user, sessionKeyHasher.Sum(nil))
	conn.SetDeadline(time.Time{})
}

func (s *Server) addClient(conn net.Conn, user *users.User, sessionKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	addr := conn.RemoteAddr().String()

	s.clients[addr] = &Client{
		addr:       addr,
		conn:       conn,
		user:       user,
		countRecv:  0,
		countSent:  0,
		sessionKey: sessionKey,
		createdAt:  time.Now(),
		lastActive: time.Now(),
	}
}

func (s *Server) cleanupIdleClients() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.mu.Lock()
			for addr, client := range s.clients {
				if time.Since(client.lastActive) > 10*time.Minute {
					log.Printf("Closing idle client: %s", addr)
					client.conn.Close()
					delete(s.clients, addr)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) incrementClientCount() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientCount++
}

func (s *Server) decrementClientCount() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientCount--
}

func (s *Server) GetClientCount() int32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientCount
}
