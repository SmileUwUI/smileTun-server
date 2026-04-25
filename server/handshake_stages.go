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
	c.sessionSentKey = initPassword[:]
	c.sessionRecvKey = initPassword[:]

	c.logger.Debug("Setting read deadline to 15 seconds for %s", clientAddr)
	c.conn.SetDeadline(time.Now().Add(15 * time.Second))

	c.logger.Debug("Reading first packet from %s (size: %d bytes)", clientAddr, FirstPacketSize)
	firstPacket, err := c.ReadAndDecryptPacketFixedLength(uint16(FirstPacketSize))
	if err != nil {
		c.logger.Error("Failed to read and decrypt first packet from %s: %v", clientAddr, err)
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
	if err != nil {
		c.logger.Error("Failed to encrypt and write packet from %s: %v", clientAddr, err)
		c.conn.Close()
		return err
	}
	fmt.Println(salt)

	c.logger.Debug("Salt packet sent to %s", clientAddr)

	c.logger.Debug("Deriving session key for %s", clientAddr)

	sessionRecvKeyHasher := sha256.New()
	password := user.GetPassword()

	sessionRecvKeyHasher.Write(password[:])
	sessionRecvKeyHasher.Write([]byte(":"))
	sessionRecvKeyHasher.Write(salt[0:16])
	c.sessionRecvKey = sessionRecvKeyHasher.Sum(nil)

	sessionSentKeyHasher := sha256.New()

	sessionSentKeyHasher.Write(password[:])
	sessionSentKeyHasher.Write([]byte(":"))
	sessionSentKeyHasher.Write(salt[16:32])
	c.sessionSentKey = sessionSentKeyHasher.Sum(nil)

	c.logger.Debug("Session key derived for %s", clientAddr)

	return nil
}

func (c *Client) handshakeStage2(clientIP *net.IP) (err error) {
	clientAddr := c.conn.RemoteAddr().String()

	packet, err := c.ReadAndDecryptPacketFixedLength(ThirdPacketSize)
	if err != nil {
		c.logger.Error("Failed to read and decrypt third packet from %s: %v", clientAddr, err)
		c.conn.Close()
		return err
	}

	if packet[0] != 0xFF {
		c.conn.Close()
		return fmt.Errorf("The client rejected the connection (addr: %s)", clientAddr)
	}

	err = c.WriteAndEncryptPacket(clientIP.To4(), 400, 1300)
	if err != nil {
		c.logger.Error("Failed to encrypt and write packet from %s: %v", clientAddr, err)
		c.conn.Close()
		return err
	}

	c.localIP = clientIP

	return nil
}
