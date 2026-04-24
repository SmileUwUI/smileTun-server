package server

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"smiletun-server/crypto"
	"smiletun-server/users"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const FirstPacketSize = chacha20poly1305.NonceSize + 16 + 8 + chacha20poly1305.Overhead // NonceSize + UsernameSize + TimestampSize + AEADtagSize
const ThirdPacketSize = chacha20poly1305.NonceSize + 1 + chacha20poly1305.Overhead      // NonceSize + MagicByteSize + AEADtagSize

func (c *Client) handshakeStage1(initPassword [32]byte, users *users.Users) (err error) {
	clientAddr := c.conn.RemoteAddr().String()
	c.sessionKey = initPassword[:]

	c.logger.Debug("Setting read deadline to 15 seconds for %s", clientAddr)
	c.conn.SetDeadline(time.Now().Add(15 * time.Second))

	c.logger.Debug("Reading first packet from %s (size: %d bytes)", clientAddr, FirstPacketSize)
	firstPacket, err := c.ReadAndDecryptPacketFixedLength(uint16(FirstPacketSize))
	if err != nil {
		c.logger.Error("Failed to read and decrypt packet from %s: %v", clientAddr, err)
		c.conn.Close()
		return err
	}

	c.logger.Debug("First packet received from %s", clientAddr)

	timestamp := int64(binary.BigEndian.Uint64(firstPacket[16:24]))
	currentTime := time.Now().Unix()
	timeDiff := currentTime - timestamp

	c.logger.Debug("Timestamp from %s: %d, current: %d, diff: %d", clientAddr, timestamp, currentTime, timeDiff)

	if timeDiff > 5 {
		c.conn.Close()
		return fmt.Errorf("invalid timestamp from %s: %d (current: %d), diff: %d", clientAddr, timestamp, currentTime, timeDiff)
	}

	username := firstPacket[:16]

	c.logger.Debug("Looking up user %x in database", username)
	user := users.GetUser([16]byte(username))
	if user == nil {
		c.logger.Debug("User not found from %s: %x", clientAddr, username)
		c.conn.Close()
		return
	}

	salt := crypto.RandomBytes(32)
	err = c.WriteAndEncryptPacket(salt, 400, 1300)

	c.logger.Debug("Salt packet sent to %s", clientAddr)

	c.logger.Debug("Deriving session key for %s", clientAddr)
	sessionKeyHasher := sha256.New()
	password := user.GetPassword()

	sessionKeyHasher.Write(password[:])
	sessionKeyHasher.Write([]byte(":"))
	sessionKeyHasher.Write(salt)
	c.sessionKey = sessionKeyHasher.Sum(nil)
	c.logger.Debug("Session key derived for %s", clientAddr)

	return nil
}

func (c *Client) handshakeStage2(clientIP net.IP) (err error) {
	clientAddr := c.conn.RemoteAddr().String()

	thirdPacket := make([]byte, 4096)
	if _, err = c.conn.Read(thirdPacket); err != nil {
		c.logger.Error("Failed to read third packet from %s: %v", clientAddr, err)
		c.conn.Close()
		return err
	}

	packet := thirdPacket[:ThirdPacketSize]
	plainPacket, err := crypto.DecryptChaCha20Poly1305(packet[12:], packet[:12], c.sessionKey)
	if err != nil {
		c.logger.Error("Failed to decrypt first packet from %s: %v", clientAddr, err)
		c.conn.Close()
		return err
	}

	if plainPacket[0] != 0xFF {
		c.conn.Close()
		return fmt.Errorf("The client rejected the connection (addr: %s)", clientAddr)
	}

	plainIPPacket := make([]byte, 4)
	copy(plainIPPacket[:4], clientIP.To4())

	ciphetIPPacket, nonce, err := crypto.EncryptChaCha20Poly1305(plainIPPacket, c.sessionKey)
	if err != nil {
		c.logger.Error("Failed to encrypt ip for %s: %v", clientAddr, err)
		c.conn.Close()
		return
	}

	finallyPacket := make([]byte, len(ciphetIPPacket)+len(nonce))
	copy(finallyPacket[:12], nonce)
	copy(finallyPacket[12:], ciphetIPPacket)

	if _, err = c.conn.Write(finallyPacket); err != nil {
		c.logger.Error("Failed to send salt to %s: %v", clientAddr, err)
		c.conn.Close()
		return err
	}

	return nil
}
