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

func isSupportedStreamKind(kind byte) bool {
	switch kind {
	case streamKindTCP, streamKindUDP, streamKindPing, streamKindHello:
		return true
	default:
		return false
	}
}

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
	protocolCapabilityTCPStatus
)

const (
	tcpOpenStatusOK byte = iota
	tcpOpenStatusError
)

const protocolHelloMagic = "XTUN"

const maxProtocolFieldLen = 65535

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
		protocolCapabilityIPStrategy |
		protocolCapabilityTCPStatus
}

func currentProtocolHello() ProtocolHello {
	return ProtocolHello{
		Version:      protocolVersion,
		Status:       protocolStatusOK,
		Capabilities: currentProtocolCapabilities(),
	}
}

func writeProtocolHello(w io.Writer, hello ProtocolHello) error {
	if err := validateProtocolFieldLen("协议消息", len(hello.Message)); err != nil {
		return fmt.Errorf("协议消息过长")
	}
	head := make([]byte, 12)
	copy(head[0:4], []byte(protocolHelloMagic))
	head[4] = hello.Version
	head[5] = hello.Status
	binary.BigEndian.PutUint16(head[6:8], uint16(len(hello.Message)))
	binary.BigEndian.PutUint32(head[8:12], hello.Capabilities)
	if err := writeAll(w, head); err != nil {
		return err
	}
	return writeOptionalPayload(w, []byte(hello.Message))
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
	message, err := readExactPayload(r, msgLen)
	if err != nil {
		return ProtocolHello{}, err
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

func writeTCPOpenStatus(w io.Writer, status byte, message string) error {
	if err := validateProtocolFieldLen("TCP 打开状态消息", len(message)); err != nil {
		return fmt.Errorf("TCP 打开状态消息过长")
	}
	head := make([]byte, 3)
	head[0] = status
	binary.BigEndian.PutUint16(head[1:3], uint16(len(message)))
	if err := writeAll(w, head); err != nil {
		return err
	}
	return writeOptionalPayload(w, []byte(message))
}

func readTCPOpenStatus(r io.Reader) (byte, string, error) {
	head := make([]byte, 3)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, "", err
	}
	msgLen := int(binary.BigEndian.Uint16(head[1:3]))
	message, err := readExactPayload(r, msgLen)
	if err != nil {
		return 0, "", err
	}
	return head[0], string(message), nil
}

func readSmuxOpenHeader(r io.Reader) (byte, byte, string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, 0, "", err
	}
	kind := head[0]
	strategy := head[1]
	targetLen := int(binary.BigEndian.Uint16(head[2:4]))
	targetRaw, err := readExactPayload(r, targetLen)
	if err != nil {
		return 0, 0, "", err
	}
	return kind, strategy, string(targetRaw), nil
}

func writeSmuxOpenHeader(w io.Writer, kind byte, strategy byte, target string) error {
	if err := validateProtocolFieldLen("目标地址", len(target)); err != nil {
		return fmt.Errorf("目标地址过长")
	}
	head := make([]byte, 4)
	head[0] = kind
	head[1] = strategy
	binary.BigEndian.PutUint16(head[2:4], uint16(len(target)))
	if err := writeAll(w, head); err != nil {
		return err
	}
	return writeOptionalPayload(w, []byte(target))
}

func writeChunk(w io.Writer, b []byte) error {
	if err := validateProtocolFieldLen("数据块", len(b)); err != nil {
		return fmt.Errorf("数据块过大")
	}
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(len(b)))
	if err := writeAll(w, h); err != nil {
		return err
	}
	return writeOptionalPayload(w, b)
}

func readChunk(r io.Reader) ([]byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h))
	return readExactPayload(r, n)
}

func writeUDPReply(w io.Writer, addr string, payload []byte) error {
	if err := validateProtocolFieldLen("地址", len(addr)); err != nil {
		return fmt.Errorf("地址过长")
	}
	if err := validateHostPort(addr); err != nil {
		return fmt.Errorf("UDP 响应地址无效: %w", err)
	}
	if err := validateProtocolFieldLen("数据块", len(payload)); err != nil {
		return fmt.Errorf("数据块过大")
	}
	head := make([]byte, 4)
	binary.BigEndian.PutUint16(head[0:2], uint16(len(addr)))
	binary.BigEndian.PutUint16(head[2:4], uint16(len(payload)))
	if err := writeAll(w, head); err != nil {
		return err
	}
	if err := writeOptionalPayload(w, []byte(addr)); err != nil {
		return err
	}
	return writeOptionalPayload(w, payload)
}

func validateProtocolFieldLen(name string, length int) error {
	if length > maxProtocolFieldLen {
		return fmt.Errorf("%s长度超过 %d 字节", name, maxProtocolFieldLen)
	}
	return nil
}

func writeOptionalPayload(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, b []byte) error {
	_, err := writeAllCount(w, b)
	return err
}

func readExactPayload(r io.Reader, length int) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func writeAllCount(w io.Writer, b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n, err := w.Write(b)
		if n > len(b) {
			return total, io.ErrShortWrite
		}
		if n > 0 {
			total += n
			b = b[n:]
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func readUDPReply(r io.Reader) (string, []byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", nil, err
	}
	addrLen := int(binary.BigEndian.Uint16(head[0:2]))
	dataLen := int(binary.BigEndian.Uint16(head[2:4]))
	addrRaw, err := readExactPayload(r, addrLen)
	if err != nil {
		return "", nil, err
	}
	addr := string(addrRaw)
	if err := validateHostPort(addr); err != nil {
		return "", nil, fmt.Errorf("UDP 响应地址无效: %w", err)
	}
	data, err := readExactPayload(r, dataLen)
	if err != nil {
		return "", nil, err
	}
	return addr, data, nil
}
