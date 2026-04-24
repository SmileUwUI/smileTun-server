package server

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"smiletun-server/crypto"
	"smiletun-server/logger"
	"smiletun-server/users"
	"sync"
	"time"
)

type Client struct {
	addr            string
	conn            *net.TCPConn
	user            *users.User
	countRecv       uint32
	countSent       uint32
	countRecvBytes  uint32
	countSentBytes  uint32
	sessionKey      []byte
	createdAt       time.Time
	lastActive      time.Time
	logger          *logger.Logger
	maxPacketLength uint16
	localIP         *net.IP
	mu              sync.RWMutex
}

func (c *Client) computeNextSessionKey(salt []byte) {
	hasher := sha256.New()
	hasher.Write(c.sessionKey)
	hasher.Write([]byte(":"))
	hasher.Write(salt)

	c.sessionKey = hasher.Sum(nil)
}

func (c *Client) ReadAndDecryptPacketFixedLength(length uint16) (packet []byte, err error) {
	rawPacket := make([]byte, c.maxPacketLength)
	if _, err = c.conn.Read(rawPacket); err != nil {
		c.logger.Error("Failed to read packet from %s: %v", c.addr, err)
		c.conn.Close()
		return nil, err
	}

	cipherPacket := rawPacket[:length]
	plainPacket, err := crypto.DecryptChaCha20Poly1305(cipherPacket[12:], cipherPacket[:12], c.sessionKey)
	if err != nil {
		c.logger.Error("Failed to decrypt packet from %s: %v", c.addr, err)
		c.conn.Close()
		return nil, err
	}

	return plainPacket, nil
}

func (c *Client) WriteAndEncryptPacket(packet []byte, minTrashficationLength int, maxTrashficationLength int) (err error) {
	rawPacket, nonce, err := crypto.EncryptChaCha20Poly1305(packet, c.sessionKey)
	if err != nil {
		c.logger.Error("Failed to encrypt packet for %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	packet = make([]byte, len(rawPacket)+len(nonce))
	copy(packet[:12], nonce)
	copy(packet[12:], rawPacket)

	trashPacket := crypto.Trashfication(packet, minTrashficationLength, maxTrashficationLength)

	if _, err = c.conn.Write(trashPacket); err != nil {
		c.logger.Error("Failed to send packet to %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	return nil
}

func (c *Client) ReadAndDecryptStreamingPacket() (packet *StreamingPacket, err error) {
	lenRawPacketBytes := make([]byte, 2)
	n, err := c.conn.Read(lenRawPacketBytes)
	if err != nil {
		c.logger.Error("Socket read error from %s: %v", c.addr, err)
		return nil, err
	}

	lenRawPacketBytes[0] = lenRawPacketBytes[0] ^ c.sessionKey[0]
	lenRawPacketBytes[1] = lenRawPacketBytes[1] ^ c.sessionKey[1]
	lenRawPacket := binary.BigEndian.Uint16(lenRawPacketBytes)

	encrypted := make([]byte, lenRawPacket-2)
	c.logger.Trace("Reading encrypted data from %s", c.addr)
	n, err = c.conn.Read(encrypted)
	if err != nil {
		c.logger.Error("Socket read error from %s: %v", c.addr, err)
		return nil, err
	}

	c.logger.Debug("Received packet #%d from %s (size: %d bytes)", c.countRecv, c.addr, n)

	packet = NewEncryptedPacket(encrypted, c.logger)
	err = packet.Decrypt(c.sessionKey, n, c.addr)
	if err != nil {
		c.logger.Error("Error processing the packet: %v", err)
		return nil, err
	}

	return packet, nil
}
