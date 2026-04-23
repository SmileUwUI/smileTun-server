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

	c.logger.Debug("Setting read deadline to 15 seconds for %s", clientAddr)
	c.conn.SetDeadline(time.Now().Add(15 * time.Second))

	c.logger.Debug("Reading first packet from %s (size: %d bytes)", clientAddr, FirstPacketSize)
	firstPacket := make([]byte, 4096)
	if _, err = c.conn.Read(firstPacket); err != nil {
		c.logger.Error("Failed to read first packet from %s: %v", clientAddr, err)
		c.conn.Close()
		return err
	}
	firstPacket = firstPacket[:FirstPacketSize]

	c.logger.Debug("First packet received from %s", clientAddr)

	nonce := firstPacket[:12]
	c.logger.Trace("Extracted nonce from %s: %x", clientAddr, nonce)

	c.logger.Debug("Decrypting first packet from %s with init password", clientAddr)
	plainPacket, err := crypto.DecryptChaCha20Poly1305(firstPacket[12:], nonce, initPassword[:])
	if err != nil {
		c.logger.Error("Failed to decrypt first packet from %s: %v", clientAddr, err)
		c.conn.Close()
		return err
	}
	c.logger.Debug("First packet decrypted successfully from %s", clientAddr)

	timestamp := int64(binary.BigEndian.Uint64(plainPacket[16:24]))
	currentTime := time.Now().Unix()
	timeDiff := currentTime - timestamp

	c.logger.Debug("Timestamp from %s: %d, current: %d, diff: %d", clientAddr, timestamp, currentTime, timeDiff)

	if timeDiff > 5 {
		c.conn.Close()
		return fmt.Errorf("invalid timestamp from %s: %d (current: %d), diff: %d", clientAddr, timestamp, currentTime, timeDiff)
	}
	c.logger.Debug("Timestamp validation passed for %s", clientAddr)

	var username [16]byte
	copy(username[:], plainPacket[:16])
	c.logger.Debug("Extracted username from %s: %x", clientAddr, username)

	c.logger.Debug("Looking up user %x in database", username)
	user := users.GetUser(username)
	if user == nil {
		c.logger.Debug("User not found from %s: %x", clientAddr, username)
		c.conn.Close()
		return
	}
	c.logger.Info("User %x authenticated successfully from %s", username[:8], clientAddr)

	c.logger.Debug("Generating 32-byte salt for %s", clientAddr)
	salt := crypto.RandomBytes(32)
	c.logger.Trace("Generated salt for %s: %x", clientAddr, salt)

	c.logger.Debug("Encrypting salt with init password for %s", clientAddr)
	rawSaltPacket, nonce, err := crypto.EncryptChaCha20Poly1305(salt, initPassword[:])

	if err != nil {
		c.logger.Error("Failed to encrypt salt for %s: %v", clientAddr, err)
		c.conn.Close()
		return
	}
	c.logger.Debug("Salt encrypted successfully for %s", clientAddr)

	packet := make([]byte, len(rawSaltPacket)+len(nonce))
	copy(packet[:12], nonce)
	copy(packet[12:], rawSaltPacket)

	trashPacket := crypto.Trashfication(packet, 400, 1300)
	c.logger.Debug("Sending salt packet to %s (size: %d bytes, after trash: %d)", clientAddr, len(packet), len(trashPacket))

	if _, err = c.conn.Write(trashPacket); err != nil {
		c.logger.Error("Failed to send salt to %s: %v", clientAddr, err)
		c.conn.Close()
		return err
	}

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
