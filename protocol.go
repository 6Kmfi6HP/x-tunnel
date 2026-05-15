package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	streamKindTCP   byte = 1
	streamKindUDP   byte = 2
	streamKindPing  byte = 3
	streamKindHello byte = 4
)

const (
	protocolVersion byte = 1
)

const (
	protocolStatusOK byte = iota
	protocolStatusUnsupportedVersion
	protocolStatusNoCommonCapabilities
)

const (
	protocolCapabilityTCP uint32 = 1 << iota
	protocolCapabilityUDP
	protocolCapabilityPing
	protocolCapabilityIPStrategy
)

const protocolHelloMagic = "XTUN"

type ProtocolHello struct {
	Version      byte
	Status       byte
	Capabilities uint32
	Message      string
}

func currentProtocolCapabilities() uint32 {
	return protocolCapabilityTCP |
		protocolCapabilityUDP |
		protocolCapabilityPing |
		protocolCapabilityIPStrategy
}

func currentProtocolHello() ProtocolHello {
	return ProtocolHello{
		Version:      protocolVersion,
		Status:       protocolStatusOK,
		Capabilities: currentProtocolCapabilities(),
	}
}

func writeProtocolHello(w io.Writer, hello ProtocolHello) error {
	if len(hello.Message) > 65535 {
		return fmt.Errorf("协议消息过长")
	}
	head := make([]byte, 12)
	copy(head[0:4], []byte(protocolHelloMagic))
	head[4] = hello.Version
	head[5] = hello.Status
	binary.BigEndian.PutUint16(head[6:8], uint16(len(hello.Message)))
	binary.BigEndian.PutUint32(head[8:12], hello.Capabilities)
	if _, err := w.Write(head); err != nil {
		return err
	}
	if hello.Message == "" {
		return nil
	}
	_, err := w.Write([]byte(hello.Message))
	return err
}

func readProtocolHello(r io.Reader) (ProtocolHello, error) {
	head := make([]byte, 12)
	if _, err := io.ReadFull(r, head); err != nil {
		return ProtocolHello{}, err
	}
	if string(head[0:4]) != protocolHelloMagic {
		return ProtocolHello{}, fmt.Errorf("协议魔数无效")
	}
	msgLen := int(binary.BigEndian.Uint16(head[6:8]))
	message := make([]byte, msgLen)
	if msgLen > 0 {
		if _, err := io.ReadFull(r, message); err != nil {
			return ProtocolHello{}, err
		}
	}
	return ProtocolHello{
		Version:      head[4],
		Status:       head[5],
		Message:      string(message),
		Capabilities: binary.BigEndian.Uint32(head[8:12]),
	}, nil
}

func negotiateProtocolHello(clientHello ProtocolHello) ProtocolHello {
	if clientHello.Version != protocolVersion {
		return ProtocolHello{
			Version: protocolVersion,
			Status:  protocolStatusUnsupportedVersion,
			Message: fmt.Sprintf("unsupported protocol version %d", clientHello.Version),
		}
	}
	caps := clientHello.Capabilities & currentProtocolCapabilities()
	required := protocolCapabilityTCP | protocolCapabilityPing
	if caps&required != required {
		return ProtocolHello{
			Version: protocolVersion,
			Status:  protocolStatusNoCommonCapabilities,
			Message: "missing required protocol capabilities",
		}
	}
	return ProtocolHello{
		Version:      protocolVersion,
		Status:       protocolStatusOK,
		Capabilities: caps,
	}
}

func readSmuxOpenHeader(r io.Reader) (byte, byte, string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, 0, "", err
	}
	kind := head[0]
	strategy := head[1]
	targetLen := int(binary.BigEndian.Uint16(head[2:4]))
	targetRaw := make([]byte, targetLen)
	if targetLen > 0 {
		if _, err := io.ReadFull(r, targetRaw); err != nil {
			return 0, 0, "", err
		}
	}
	return kind, strategy, string(targetRaw), nil
}

func writeSmuxOpenHeader(w io.Writer, kind byte, strategy byte, target string) error {
	if len(target) > 65535 {
		return fmt.Errorf("目标地址过长")
	}
	head := make([]byte, 4)
	head[0] = kind
	head[1] = strategy
	binary.BigEndian.PutUint16(head[2:4], uint16(len(target)))
	if _, err := w.Write(head); err != nil {
		return err
	}
	if len(target) == 0 {
		return nil
	}
	_, err := w.Write([]byte(target))
	return err
}

func writeChunk(w io.Writer, b []byte) error {
	if len(b) > 65535 {
		return fmt.Errorf("数据块过大")
	}
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(len(b)))
	if _, err := w.Write(h); err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	_, err := w.Write(b)
	return err
}

func readChunk(r io.Reader) ([]byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h))
	if n == 0 {
		return nil, nil
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeUDPReply(w io.Writer, addr string, payload []byte) error {
	if len(addr) > 65535 {
		return fmt.Errorf("地址过长")
	}
	if len(payload) > 65535 {
		return fmt.Errorf("数据块过大")
	}
	head := make([]byte, 4)
	binary.BigEndian.PutUint16(head[0:2], uint16(len(addr)))
	binary.BigEndian.PutUint16(head[2:4], uint16(len(payload)))
	if _, err := w.Write(head); err != nil {
		return err
	}
	if len(addr) > 0 {
		if _, err := w.Write([]byte(addr)); err != nil {
			return err
		}
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readUDPReply(r io.Reader) (string, []byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", nil, err
	}
	addrLen := int(binary.BigEndian.Uint16(head[0:2]))
	dataLen := int(binary.BigEndian.Uint16(head[2:4]))
	addrRaw := make([]byte, addrLen)
	if addrLen > 0 {
		if _, err := io.ReadFull(r, addrRaw); err != nil {
			return "", nil, err
		}
	}
	data := make([]byte, dataLen)
	if dataLen > 0 {
		if _, err := io.ReadFull(r, data); err != nil {
			return "", nil, err
		}
	}
	return string(addrRaw), data, nil
}
