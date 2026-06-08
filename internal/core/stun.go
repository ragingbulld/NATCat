package core

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	stunMagic          = 0x2112A442
	stunBindingRequest = 0x0001
	stunBindingSuccess = 0x0101
	stunMappedAddress  = 0x0001
	stunXORMappedAddr  = 0x0020
)

type stunResult struct {
	TID    [12]byte
	IP     net.IP
	Port   int
	Source string
}

func stunTCP(conn net.Conn) (stunResult, error) {
	request, tid, err := stunRequest()
	if err != nil {
		return stunResult{}, err
	}

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return stunResult{}, err
	}
	defer conn.SetDeadline(time.Time{})

	if _, err := conn.Write(request); err != nil {
		return stunResult{}, err
	}

	header := make([]byte, 20)
	if _, err := io.ReadFull(conn, header); err != nil {
		return stunResult{}, err
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return stunResult{}, err
	}

	result, err := parseSTUN(append(header, body...))
	if err != nil {
		return stunResult{}, err
	}
	if result.TID != tid {
		return stunResult{}, errors.New("stun transaction mismatch")
	}
	return result, nil
}

func stunRequest() ([]byte, [12]byte, error) {
	var tid [12]byte
	if _, err := rand.Read(tid[:]); err != nil {
		return nil, tid, err
	}

	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint32(msg[4:8], stunMagic)
	copy(msg[8:20], tid[:])
	return msg, tid, nil
}

func parseSTUN(packet []byte) (stunResult, error) {
	if len(packet) < 20 {
		return stunResult{}, errors.New("short stun packet")
	}
	msgType := binary.BigEndian.Uint16(packet[0:2])
	if msgType != stunBindingSuccess {
		return stunResult{}, fmt.Errorf("unexpected stun message 0x%04x", msgType)
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if 20+length > len(packet) {
		return stunResult{}, errors.New("invalid stun length")
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagic {
		return stunResult{}, errors.New("invalid stun magic")
	}

	var tid [12]byte
	copy(tid[:], packet[8:20])
	body := packet[20 : 20+length]

	for pos := 0; pos+4 <= len(body); {
		attrType := binary.BigEndian.Uint16(body[pos : pos+2])
		attrLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		valueStart := pos + 4
		valueEnd := valueStart + attrLen
		if valueEnd > len(body) {
			return stunResult{}, errors.New("invalid stun attribute")
		}

		value := body[valueStart:valueEnd]
		if attrType == stunMappedAddress || attrType == stunXORMappedAddr {
			result, err := parseMappedAddress(attrType, value, tid)
			if err != nil {
				return stunResult{}, err
			}
			result.TID = tid
			return result, nil
		}

		pos = valueEnd
		if rem := pos % 4; rem != 0 {
			pos += 4 - rem
		}
	}

	return stunResult{}, errors.New("mapped address missing")
}

func parseMappedAddress(attrType uint16, value []byte, tid [12]byte) (stunResult, error) {
	if len(value) < 4 {
		return stunResult{}, errors.New("short mapped address")
	}

	family := value[1]
	port := binary.BigEndian.Uint16(value[2:4])
	if attrType == stunXORMappedAddr {
		port ^= uint16(stunMagic >> 16)
	}

	switch family {
	case 0x01:
		if len(value) < 8 {
			return stunResult{}, errors.New("short ipv4 mapped address")
		}
		ip := make(net.IP, 4)
		copy(ip, value[4:8])
		if attrType == stunXORMappedAddr {
			magic := make([]byte, 4)
			binary.BigEndian.PutUint32(magic, stunMagic)
			for i := 0; i < 4; i++ {
				ip[i] ^= magic[i]
			}
		}
		return stunResult{IP: ip, Port: int(port)}, nil
	default:
		return stunResult{}, errors.New("unknown mapped address family")
	}
}
