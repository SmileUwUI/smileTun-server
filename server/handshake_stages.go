package server

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"smiletun-server/crypto"
	"smiletun-server/users"
	"time"
)

func (c *Client) handshakeStage1(initPassword [32]byte, users *users.Users) (err error) {
	c.conn.SetDeadline(time.Now().Add(15 * time.Second))
	c.sessionRecvKey = initPassword[:]
	c.sessionSentKey = initPassword[:]

	usernamePacket, err := c.readPacket()
	if err != nil {
		c.logger.Error("%v", err)
		c.conn.Close()
		return err
	}

	err = usernamePacket.DecodeAndDecrypt(initPassword[:], false)
	if err != nil {
		c.logger.Error("%v", err)
		c.conn.Close()
		return err
	}

	timestamp := int64(binary.BigEndian.Uint64(usernamePacket.GetPlainData()[16:24]))
	currentTime := time.Now().Unix()
	timeDiff := currentTime - timestamp

	if timeDiff > 5 {
		c.conn.Close()
		return fmt.Errorf("invalid timestamp")
	}

	username := usernamePacket.GetPlainData()[:16]

	user := users.GetUser([16]byte(username))
	if user == nil {
		c.conn.Close()
		return fmt.Errorf("user not found (username: %x)", username)
	}

	salt := crypto.RandomBytes(32)
	saltPacket := NewPlainPacket()
	saltPacket.AddData(salt)
	saltPacket.PackageAssembly(initPassword[:], []byte{})

	if _, err = c.conn.Write(saltPacket.GetRawData()); err != nil {
		c.logger.Error("%v", err)
		c.conn.Close()
		return err
	}

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

	return nil
}

func (c *Client) handshakeStage2(clientIP *net.IP) (err error) {

	packet, err := c.readPacket()
	if err != nil {
		c.logger.Error("%v", err)
		c.conn.Close()
		return err
	}

	err = packet.DecodeAndDecrypt(c.sessionRecvKey, false)
	if err != nil {
		c.logger.Error("%v", err)
		c.conn.Close()
		return err
	}

	if packet.GetPlainData()[0] != 0xFF {
		c.conn.Close()
		return fmt.Errorf("the client rejected the connection")
	}

	ipPacket := NewPlainPacket()
	ipPacket.AddData(clientIP.To4())
	ipPacket.PackageAssembly(c.sessionSentKey, []byte{})

	if _, err = c.conn.Write(ipPacket.GetRawData()); err != nil {
		c.logger.Error("%v", err)
		c.conn.Close()
		return err
	}

	c.localIP = clientIP

	return nil
}
