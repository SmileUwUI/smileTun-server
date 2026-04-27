package server

import (
	"crypto/ecdh"
	"crypto/rand"
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

	timestampBytes, err := usernamePacket.GetSlicePlainData(16, 24)
	if err != nil {
		c.logger.Error("Error retrieving the timestamp")
		c.conn.Close()
		return err
	}

	timestamp := int64(binary.BigEndian.Uint64(timestampBytes))
	currentTime := time.Now().Unix()
	timeDiff := currentTime - timestamp

	if timeDiff > 5 {
		c.conn.Close()
		return fmt.Errorf("invalid timestamp")
	}

	username, err := usernamePacket.GetSlicePlainData(0, 16)
	if err != nil {
		c.logger.Error("Error retrieving the username")
		c.conn.Close()
		return err
	}

	user := users.GetUser([16]byte(username))
	if user == nil {
		c.conn.Close()
		return fmt.Errorf("user not found (username: %x)", username)
	}

	salt, err := crypto.RandomBytes(32)
	if err != nil {
		c.logger.Error("salt generation error: %v", err)
		return err
	}

	saltPacket := NewPlainPacket()
	saltPacket.AddData(salt)
	err = saltPacket.PackageAssembly(initPassword[:], []byte{}, false, false)
	if err != nil {
		c.logger.Error("Error assembly a salt packet: %v", err)
		c.conn.Close()
		return err
	}

	if _, err = c.conn.Write(saltPacket.GetRawData()); err != nil {
		c.logger.Error("%v", err)
		c.conn.Close()
		return err
	}

	sessionRecvKeyHasher := sha256.New()
	password := user.GetPassword()
	firstSalt, err := saltPacket.GetSlicePlainData(0, 16)
	if err != nil {
		c.logger.Error("Error retrieving the first salt: %v", err)
		c.conn.Close()
		return err
	}
	sessionRecvKeyHasher.Write(password[:])
	sessionRecvKeyHasher.Write([]byte(":"))
	sessionRecvKeyHasher.Write(firstSalt)
	c.sessionRecvKey = sessionRecvKeyHasher.Sum(nil)

	sessionSentKeyHasher := sha256.New()
	secondSalt, err := saltPacket.GetSlicePlainData(16, 32)
	if err != nil {
		c.logger.Error("Error retrieving the second salt: %v", err)
		c.conn.Close()
		return err
	}
	sessionSentKeyHasher.Write(password[:])
	sessionSentKeyHasher.Write([]byte(":"))
	sessionSentKeyHasher.Write(secondSalt)
	c.sessionSentKey = sessionSentKeyHasher.Sum(nil)

	return nil
}

func (c *Client) handshakeStage2(clientIP *net.IP) (err error) {
	packet, err := c.readPacket()
	if err != nil {
		c.logger.Error("Error reading the packet containing the connection establishment confirmation and the client's public key: %v", err)
		c.conn.Close()
		return err
	}

	err = packet.DecodeAndDecrypt(c.sessionRecvKey, false)
	if err != nil {
		c.logger.Error("Decoding and decryption error for the packet containing the connection establishment acknowledgment and the client's public key: %v", err)
		c.conn.Close()
		return err
	}

	confirmationByte, err := packet.GetSlicePlainData(0, 1)
	if err != nil {
		c.logger.Error("Error retrieving the second salt: %v", err)
		c.conn.Close()
		return err
	}

	if confirmationByte[0] != 0xFF {
		c.conn.Close()
		return fmt.Errorf("the client rejected the connection")
	}

	publicClientKeyBytes, err := packet.GetSlicePlainData(1, packet.GetSizePlainData())
	if err != nil {
		c.logger.Error("Error retrieving the second salt: %v", err)
		c.conn.Close()
		return err
	}

	curve := ecdh.P256()

	c.logger.Debug("Parsing the client's public key")
	publicClientKey, err := curve.NewPublicKey(publicClientKeyBytes)
	if err != nil {
		c.logger.Error("Error parsing the client's public key: %v", err)
		return err
	}

	c.logger.Debug("Generating a keypair for ECDH")
	privateServerKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		c.logger.Error("Error generating the keypair")
		return err
	}

	publicServerKey := privateServerKey.PublicKey()

	ipPacket := NewPlainPacket()
	ipPacket.AddData(clientIP.To4())
	ipPacket.AddData(publicServerKey.Bytes())
	err = ipPacket.PackageAssembly(c.sessionSentKey, []byte{}, false, false)
	if err != nil {
		c.logger.Error("Error assembly a ip packet: %v", err)
		c.conn.Close()
		return err
	}

	if _, err = c.conn.Write(ipPacket.GetRawData()); err != nil {
		c.logger.Error("%v", err)
		c.conn.Close()
		return err
	}

	c.localIP = clientIP

	c.logger.Debug("Conducting the ECDH")
	secret, err := privateServerKey.ECDH(publicClientKey)
	if err != nil {
		c.logger.Error("ECDH execution error: %v", err)
		return err
	}
	c.computeNextSessionRecvKey(secret)
	c.computeNextSessionSentKey(secret)

	return nil
}
