package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"smiletun-server/crypto"
	"smiletun-server/logger"
)

type Packet struct {
	SourceAddress      *net.IP
	DestinationAddress *net.IP
	Salt               []byte
	Data               []byte
	EncryptedData      []byte
	logger             *logger.Logger
}

func NewEncryptedPacket(EncryptedData []byte, logger *logger.Logger) (packet *Packet) {
	return &Packet{
		Data:          []byte{},
		EncryptedData: EncryptedData,
		logger:        logger,
	}
}

func (p *Packet) Decrypt(sessionKey []byte, totalLength int, clientAddr string) (err error) {
	lenCipherPacketBytes := p.EncryptedData[0:2]
	p.logger.Trace("Length bytes from %s: %x", clientAddr, lenCipherPacketBytes)

	lenCipherPacketBytes[0] = lenCipherPacketBytes[0] ^ sessionKey[2]
	lenCipherPacketBytes[1] = lenCipherPacketBytes[1] ^ sessionKey[3]

	lenPacket := binary.BigEndian.Uint16(lenCipherPacketBytes)
	p.logger.Debug("Packet length from %s: %d bytes", clientAddr, lenPacket)
	if lenPacket > uint16(totalLength) {
		return fmt.Errorf("error: The length of the encrypted data data exceeds the total length")
	}

	cipherPacket := p.EncryptedData[2:lenPacket]
	p.logger.Trace("Cipher packet from %s size: %d bytes", clientAddr, len(cipherPacket))

	p.logger.Trace("Decrypting packet from %s", clientAddr)
	p.Data, err = crypto.DecryptChaCha20Poly1305(cipherPacket[12:], cipherPacket[:12], sessionKey)
	if err != nil {
		return err
	}

	if len(p.Data) <= 8 {
		return fmt.Errorf("the length of the decrypted packet is too short")
	}

	p.Salt = p.Data[0:8]

	p.logger.Debug("Recalculation of the session key for address %s", clientAddr)

	return nil
}
