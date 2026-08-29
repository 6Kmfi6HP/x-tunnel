package wire

import (
	"encoding/binary"
	"fmt"
	"io"

	"x-tunnel/internal/netaddr"
)

const (
	streamKindTCP  byte = 1
	streamKindUDP  byte = 2
	streamKindPing byte = 3
)

func isSupportedStreamKind(kind byte) bool {
	switch kind {
	case streamKindTCP, streamKindUDP, streamKindPing:
		return true
	default:
		return false
	}
}

const (
	protocolCapabilityTCP uint32 = 1 << iota
	protocolCapabilityUDP
	protocolCapabilityPing
	protocolCapabilityIPStrategy
	protocolCapabilityTCPStatus
	protocolCapabilityUDPStatus
	protocolCapabilityOpenStatusCode
)

const (
	tcpOpenStatusOK byte = iota
	tcpOpenStatusError
)

const (
	udpOpenStatusOK byte = iota
	udpOpenStatusError
)

const (
	openStatusCodeNone byte = iota
	openStatusCodeBadTarget
	openStatusCodePolicyDenied
	openStatusCodeDialFailed
	openStatusCodeResourceLimit
)

const maxProtocolFieldLen = 65535

func currentProtocolCapabilities() uint32 {
	return protocolCapabilityTCP |
		protocolCapabilityUDP |
		protocolCapabilityPing |
		protocolCapabilityIPStrategy |
		protocolCapabilityTCPStatus |
		protocolCapabilityUDPStatus |
		protocolCapabilityOpenStatusCode
}

func requiredProtocolCapabilities() uint32 {
	return protocolCapabilityTCP | protocolCapabilityPing
}

func writeTCPOpenStatus(w io.Writer, status byte, message string) error {
	return writeOpenStatus(w, "TCP 打开状态消息", status, message)
}

func readTCPOpenStatus(r io.Reader) (byte, string, error) {
	return readOpenStatus(r)
}

func writeTCPOpenStatusCode(w io.Writer, status byte, code byte, message string) error {
	return writeOpenStatusCode(w, "TCP 打开状态消息", status, code, message)
}

func readTCPOpenStatusCode(r io.Reader) (byte, byte, string, error) {
	return readOpenStatusCode(r)
}

func writeUDPOpenStatus(w io.Writer, status byte, message string) error {
	return writeOpenStatus(w, "UDP 打开状态消息", status, message)
}

func readUDPOpenStatus(r io.Reader) (byte, string, error) {
	return readOpenStatus(r)
}

func writeUDPOpenStatusCode(w io.Writer, status byte, code byte, message string) error {
	return writeOpenStatusCode(w, "UDP 打开状态消息", status, code, message)
}

func readUDPOpenStatusCode(r io.Reader) (byte, byte, string, error) {
	return readOpenStatusCode(r)
}

func writeOpenStatus(w io.Writer, fieldName string, status byte, message string) error {
	if err := validateProtocolFieldLen(fieldName, len(message)); err != nil {
		return err
	}
	var head [3]byte
	head[0] = status
	binary.BigEndian.PutUint16(head[1:3], uint16(len(message)))
	if err := writeAll(w, head[:]); err != nil {
		return err
	}
	return writeOptionalString(w, message)
}

func readOpenStatus(r io.Reader) (byte, string, error) {
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

func writeOpenStatusCode(w io.Writer, fieldName string, status byte, code byte, message string) error {
	if err := validateProtocolFieldLen(fieldName, len(message)); err != nil {
		return err
	}
	var head [4]byte
	head[0] = status
	head[1] = code
	binary.BigEndian.PutUint16(head[2:4], uint16(len(message)))
	if err := writeAll(w, head[:]); err != nil {
		return err
	}
	return writeOptionalString(w, message)
}

func readOpenStatusCode(r io.Reader) (byte, byte, string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, 0, "", err
	}
	msgLen := int(binary.BigEndian.Uint16(head[2:4]))
	message, err := readExactPayload(r, msgLen)
	if err != nil {
		return 0, 0, "", err
	}
	return head[0], head[1], string(message), nil
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
	var head [4]byte
	head[0] = kind
	head[1] = strategy
	binary.BigEndian.PutUint16(head[2:4], uint16(len(target)))
	if err := writeAll(w, head[:]); err != nil {
		return err
	}
	return writeOptionalString(w, target)
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
	var head [4]byte
	binary.BigEndian.PutUint16(head[0:2], uint16(len(addr)))
	binary.BigEndian.PutUint16(head[2:4], uint16(len(payload)))
	if err := writeAll(w, head[:]); err != nil {
		return err
	}
	if err := writeOptionalString(w, addr); err != nil {
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

func writeOptionalString(w io.Writer, payload string) error {
	if payload == "" {
		return nil
	}
	return writeAllString(w, payload)
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

func writeAllString(w io.Writer, s string) error {
	if sw, ok := w.(io.StringWriter); ok {
		for len(s) > 0 {
			n, err := sw.WriteString(s)
			if n > len(s) {
				return io.ErrShortWrite
			}
			if n > 0 {
				s = s[n:]
			}
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
		return nil
	}
	return writeAll(w, []byte(s))
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

const (
	StreamKindTCP  = streamKindTCP
	StreamKindUDP  = streamKindUDP
	StreamKindPing = streamKindPing

	ProtocolCapabilityTCP            = protocolCapabilityTCP
	ProtocolCapabilityUDP            = protocolCapabilityUDP
	ProtocolCapabilityPing           = protocolCapabilityPing
	ProtocolCapabilityIPStrategy     = protocolCapabilityIPStrategy
	ProtocolCapabilityTCPStatus      = protocolCapabilityTCPStatus
	ProtocolCapabilityUDPStatus      = protocolCapabilityUDPStatus
	ProtocolCapabilityOpenStatusCode = protocolCapabilityOpenStatusCode

	TCPOpenStatusOK    = tcpOpenStatusOK
	TCPOpenStatusError = tcpOpenStatusError
	UDPOpenStatusOK    = udpOpenStatusOK
	UDPOpenStatusError = udpOpenStatusError

	OpenStatusCodeNone          = openStatusCodeNone
	OpenStatusCodeBadTarget     = openStatusCodeBadTarget
	OpenStatusCodePolicyDenied  = openStatusCodePolicyDenied
	OpenStatusCodeDialFailed    = openStatusCodeDialFailed
	OpenStatusCodeResourceLimit = openStatusCodeResourceLimit

	MaxProtocolFieldLen = maxProtocolFieldLen
)

func IsSupportedStreamKind(kind byte) bool { return isSupportedStreamKind(kind) }

func CurrentProtocolCapabilities() uint32 { return currentProtocolCapabilities() }

func RequiredProtocolCapabilities() uint32 { return requiredProtocolCapabilities() }

func WriteTCPOpenStatus(w io.Writer, status byte, message string) error {
	return writeTCPOpenStatus(w, status, message)
}

func ReadTCPOpenStatus(r io.Reader) (byte, string, error) { return readTCPOpenStatus(r) }

func WriteTCPOpenStatusCode(w io.Writer, status byte, code byte, message string) error {
	return writeTCPOpenStatusCode(w, status, code, message)
}

func ReadTCPOpenStatusCode(r io.Reader) (byte, byte, string, error) {
	return readTCPOpenStatusCode(r)
}

func WriteUDPOpenStatus(w io.Writer, status byte, message string) error {
	return writeUDPOpenStatus(w, status, message)
}

func ReadUDPOpenStatus(r io.Reader) (byte, string, error) { return readUDPOpenStatus(r) }

func WriteUDPOpenStatusCode(w io.Writer, status byte, code byte, message string) error {
	return writeUDPOpenStatusCode(w, status, code, message)
}

func ReadUDPOpenStatusCode(r io.Reader) (byte, byte, string, error) {
	return readUDPOpenStatusCode(r)
}

func ReadSmuxOpenHeader(r io.Reader) (byte, byte, string, error) {
	return readSmuxOpenHeader(r)
}

func WriteSmuxOpenHeader(w io.Writer, kind byte, strategy byte, target string) error {
	return writeSmuxOpenHeader(w, kind, strategy, target)
}

func WriteChunk(w io.Writer, b []byte) error { return writeChunk(w, b) }

func ReadChunk(r io.Reader) ([]byte, error) { return readChunk(r) }

func WriteUDPReply(w io.Writer, addr string, payload []byte) error {
	return writeUDPReply(w, addr, payload)
}

func ReadUDPReply(r io.Reader) (string, []byte, error) { return readUDPReply(r) }

func WriteAll(w io.Writer, b []byte) error { return writeAll(w, b) }

func WriteAllCount(w io.Writer, b []byte) (int, error) { return writeAllCount(w, b) }

func validateHostPort(value string) error {
	return netaddr.ValidateHostPort(value)
}
