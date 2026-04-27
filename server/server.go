package server

import (
	"fmt"
	"net"
	"smiletun-server/config"
	"smiletun-server/crypto"
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

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Error("Failed to start TCP server on %s: %v", addr, err)
		return fmt.Errorf("failed to start TCP server: %w", err)
	}

	s.listener = listener

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

	go s.acceptConnections()

	go s.tunnelReader()

	go s.cleanupIdleClients()

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
					s.logger.Error("Failed to accept connection: %v", err)
					continue
				}
			}

			s.mu.RLock()
			clientCount := int(s.clientCount)
			maxClients := s.config.MaxClients
			s.mu.RUnlock()

			if clientCount >= maxClients {
				conn.Close()
				continue
			}

			s.wg.Add(1)
			s.incrementClientCount()

			go s.handleConnection(conn)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		s.wg.Done()
		s.decrementClientCount()
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

	s.clients[clientIP.String()] = client

	conn.SetDeadline(time.Time{})

	go s.handleClient(client)
}

func (s *Server) tunnelReader() {
	for {
		rawPacket := make([]byte, 65535)
		n, err := s.tunnel.Read(rawPacket)
		if err != nil {
			s.logger.Error("Failed to read from tunnel: %v", err)
			continue
		}
		rawPacket = rawPacket[:n]
		if n < 20 {
			continue
		}

		dstIP := rawPacket[16:20]

		s.mu.Lock()
		client, ok := s.clients[fmt.Sprintf("%d.%d.%d.%d", dstIP[0], dstIP[1], dstIP[2], dstIP[3])]
		s.mu.Unlock()
		if !ok {
			continue
		}

		salt, err := crypto.RandomBytes(8)
		if err != nil {
			s.logger.Error("Salt generation error: %v", err)
			continue
		}

		packet := NewPlainPacket()
		packet.AddData(rawPacket)
		err = packet.PackageAssembly(client.sessionSentKey, salt, false, false)
		if err != nil {
			s.logger.Error("Error assembly a packet: %v", err)
			continue
		}

		_, err = client.conn.Write(packet.GetRawData())
		if err != nil {
			s.logger.Error("Error write: %v", err)
			continue
		}

		client.computeNextSessionSentKey(salt)
		client.countSent++
	}
}

func (s *Server) handleClient(client *Client) {
	defer client.conn.Close()
	clientAddr := client.addr

	for {
		select {
		case <-s.stopCh:
			return
		default:
			packet, err := client.readPacket()
			if err != nil {
				s.logger.Error("%v", err)
				if err.Error() == "EOF" {
					return
				}
				continue
			}
			err = packet.DecodeAndDecrypt(client.sessionRecvKey, true)
			if err != nil {
				s.logger.Error("%v", err)
				continue
			}

			client.countRecv++
			client.computeNextSessionRecvKey(packet.GetSalt())

			client.mu.Lock()
			client.lastActive = time.Now()
			client.countRecvBytes += uint32(len(packet.GetRawData()))
			client.mu.Unlock()

			packetForTunnel := packet.GetPlainData()

			_, err = s.tunnel.Write(packetForTunnel)
			if err != nil {
				s.logger.Error("Write error to TUN interface for %s: %v", clientAddr, err)
			}
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
			return
		case <-ticker.C:

			s.mu.Lock()
			idleCount := 0
			for addr, client := range s.clients {
				idleTime := time.Since(client.lastActive)
				if idleTime > 10*time.Minute {
					client.conn.Close()
					s.ipPool.ReleaseIP(*client.localIP)
					delete(s.clients, addr)
					idleCount++
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
