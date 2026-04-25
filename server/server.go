package server

import (
	"fmt"
	"net"
	"smiletun-server/config"
	"smiletun-server/logger"
	"smiletun-server/users"
	"sync"
	"time"
)

type Server struct {
	config      *config.Config
	users       *users.Users
	ipPool      *IPPool
	listener    net.Listener
	wg          sync.WaitGroup
	clientCount int32
	clients     map[string]*Client
	logger      *logger.Logger
	tunnel      *LinuxTunnel

	stopCh chan struct{}
	mu     sync.RWMutex
}

func NewServer(cfg *config.Config, usersDB *users.Users, logger *logger.Logger) (server *Server, err error) {
	logger.Info("Creating new server instance")
	ippool, err := NewIPPool("10.8.83.0/24")
	if err != nil {
		return nil, fmt.Errorf("error creating ip pool: %v", err)
	}

	return &Server{
		config:  cfg,
		users:   usersDB,
		ipPool:  ippool,
		clients: make(map[string]*Client),
		stopCh:  make(chan struct{}),
		logger:  logger,
	}, nil
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

	s.tunnel, err = NewTunnel(
		"tun0",
		1500,
		net.ParseIP("10.8.83.1"),
		net.IPv4Mask(255, 255, 255, 0),
		[]*net.IPNet{
			{IP: net.ParseIP("0.0.0.0"), Mask: net.CIDRMask(0, 32)},
		},
	)

	if err != nil {
		s.logger.Error("Failed to create tunnel: %v", err)
		return err
	}

	err = s.tunnel.Up()
	if err != nil {
		s.logger.Error("Failed to up tunnel: %v", err)
		return err
	}

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

	connTCP := conn.(*net.TCPConn)
	connTCP.SetNoDelay(true)

	now := time.Now()

	client := &Client{
		addr:            conn.RemoteAddr().String(),
		conn:            connTCP,
		countRecv:       0,
		countSent:       0,
		countRecvBytes:  0,
		countSentBytes:  0,
		sessionRecvKey:  []byte{},
		sessionSentKey:  []byte{},
		createdAt:       now,
		lastActive:      now,
		logger:          s.logger,
		maxPacketLength: 4096,
	}

	err := client.handshakeStage1(s.config.InitPassword, s.users)
	if err != nil {
		s.logger.Error("Error during handshake: %v", err)
		return
	}

	clientIP := s.ipPool.AcquireIP()
	err = client.handshakeStage2(&clientIP)
	if err != nil {
		s.logger.Error("Error during handshake: %v", err)
		s.ipPool.ReleaseIP(clientIP)
		return
	}

	s.logger.Info("New client registered: %s", clientAddr)

	s.logger.Debug("Adding client %s to clients map", clientAddr)
	s.clients[clientIP.String()] = client

	s.logger.Debug("Removing read deadline for %s", clientAddr)
	conn.SetDeadline(time.Time{})

	s.logger.Debug("Starting client handler goroutine for %s", clientAddr)
	go s.handleClient(client)
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
			packet, err := client.ReadAndDecryptStreamingPacket()
			if err != nil {
				s.logger.Error("Failed to read and decrypt packet from %s: %v", client.addr, err)
				if err.Error() == "EOF" {
					return
				}
				continue
			}

			client.countRecv++
			client.computeNextSessionRecvKey(packet.Salt)

			s.logger.Info("Decrypted packet #%d from %s (size: %d bytes)", client.countRecv, clientAddr, len(packet.Data))
			s.logger.Trace("Plaintext data from %s: %x", clientAddr, packet.Data)

			client.mu.Lock()
			client.lastActive = time.Now()
			client.countRecvBytes += uint32(len(packet.Data))
			client.mu.Unlock()

			_, err = s.tunnel.Write(packet.Data[8:])
			if err != nil {
				s.logger.Error("Write error to TUN interface for %s: %v", clientAddr, err)
			}

			s.logger.Debug("Client %s stats updated - received: %d bytes, total packets: %d",
				clientAddr, client.countRecvBytes, client.countRecv)
			s.logger.Debug("______________________________________________________________________________")
		}
	}
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
