package wire

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	protocolV2Version byte = 2

	v2FrameTypeChannelInit   byte = 1
	v2FrameTypeChannelAccept byte = 2
	v2FrameTypeChannelReject byte = 3
)

const (
	v2RecordSessionID           uint16 = 0x8001
	v2RecordChannelID           uint16 = 0x8002
	v2RecordClientNonce         uint16 = 0x8003
	v2RecordTimestamp           uint16 = 0x8004
	v2RecordCapabilities        uint16 = 0x8005
	v2RecordAuthProof           uint16 = 0x8006
	v2RecordClientName          uint16 = 0x0007
	v2RecordBuildInfo           uint16 = 0x0008
	v2RecordDesiredChannelCount uint16 = 0x0009
	v2RecordTransportHints      uint16 = 0x000a
	v2RecordPadding             uint16 = 0x000b

	v2RecordServerNonce  uint16 = 0x8010
	v2RecordServerTime   uint16 = 0x8011
	v2RecordMaxFrameSize uint16 = 0x0012
	v2RecordMaxStreams   uint16 = 0x0013
	v2RecordMessage      uint16 = 0x0015

	v2RecordRejectCode   uint16 = 0x8020
	v2RecordRejectReason uint16 = 0x0021
)

const (
	protocolCapabilityStreamOpenV2 uint64 = 1 << 7
	protocolCapabilityStatusV2     uint64 = 1 << 8
	protocolCapabilityChannelStats uint64 = 1 << 9
	protocolCapabilityDrainSignal  uint64 = 1 << 10
	protocolCapabilityDatagramV2   uint64 = 1 << 11
)

const (
	v2RejectUnsupportedVersion byte = iota + 1
	v2RejectMissingRequiredCapability
	v2RejectAuthenticationFailed
	v2RejectTimestampSkew
	v2RejectReplayDetected
	v2RejectResourceLimit
	v2RejectPolicyDenied
	v2RejectMalformedFrame
)

const (
	maxV2FrameSize = 16 * 1024
)

type V2Frame struct {
	Type    byte
	Version byte
	Flags   uint16
	Body    []byte
}

type V2TLV struct {
	Type  uint16
	Value []byte
}

type ChannelInit struct {
	SessionID    []byte
	ChannelID    uint32
	ClientNonce  []byte
	Timestamp    int64
	Capabilities uint64
	AuthProof    []byte
}

type ChannelAccept struct {
	Capabilities uint64
	ServerNonce  []byte
	ServerTime   int64
	MaxFrameSize uint32
	MaxStreams   uint32
	Message      string
}

type ChannelReject struct {
	Code    byte
	Message string
}

func currentProtocolCapabilitiesV2() uint64 {
	return uint64(currentProtocolCapabilities()) |
		protocolCapabilityChannelStats
}

func requiredProtocolCapabilitiesV2() uint64 {
	return uint64(protocolCapabilityTCP |
		protocolCapabilityPing |
		protocolCapabilityTCPStatus |
		protocolCapabilityOpenStatusCode)
}

func writeV2Frame(w io.Writer, frame V2Frame) error {
	if frame.Version == 0 {
		frame.Version = protocolV2Version
	}
	if frame.Version != protocolV2Version {
		return fmt.Errorf("v2 frame version invalid: %d", frame.Version)
	}
	if len(frame.Body) > maxV2FrameSize {
		return fmt.Errorf("v2 frame body too large: %d", len(frame.Body))
	}
	var head [8]byte
	head[0] = frame.Type
	head[1] = frame.Version
	binary.BigEndian.PutUint16(head[2:4], frame.Flags)
	binary.BigEndian.PutUint32(head[4:8], uint32(len(frame.Body)))
	if err := writeAll(w, head[:]); err != nil {
		return err
	}
	return writeOptionalPayload(w, frame.Body)
}

func readV2Frame(r io.Reader, maxSize int) (V2Frame, error) {
	if maxSize <= 0 {
		maxSize = maxV2FrameSize
	}
	head := make([]byte, 8)
	if _, err := io.ReadFull(r, head); err != nil {
		return V2Frame{}, err
	}
	frame := V2Frame{
		Type:    head[0],
		Version: head[1],
		Flags:   binary.BigEndian.Uint16(head[2:4]),
	}
	if frame.Version != protocolV2Version {
		return V2Frame{}, fmt.Errorf("v2 frame version invalid: %d", frame.Version)
	}
	bodyLen := int(binary.BigEndian.Uint32(head[4:8]))
	if bodyLen > maxSize {
		return V2Frame{}, fmt.Errorf("v2 frame body too large: %d", bodyLen)
	}
	body, err := readExactPayload(r, bodyLen)
	if err != nil {
		return V2Frame{}, err
	}
	frame.Body = body
	return frame, nil
}

func writeV2TLV(w io.Writer, typ uint16, value []byte) error {
	if len(value) > maxProtocolFieldLen {
		return fmt.Errorf("v2 record too large: type=0x%04x length=%d", typ, len(value))
	}
	var head [4]byte
	binary.BigEndian.PutUint16(head[0:2], typ)
	binary.BigEndian.PutUint16(head[2:4], uint16(len(value)))
	if err := writeAll(w, head[:]); err != nil {
		return err
	}
	return writeOptionalPayload(w, value)
}

func parseV2TLVs(body []byte, known map[uint16]bool) (map[uint16]V2TLV, error) {
	records := make(map[uint16]V2TLV)
	for len(body) > 0 {
		if len(body) < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		typ := binary.BigEndian.Uint16(body[0:2])
		length := int(binary.BigEndian.Uint16(body[2:4]))
		body = body[4:]
		if length > len(body) {
			return nil, io.ErrUnexpectedEOF
		}
		value := body[:length]
		body = body[length:]
		if _, exists := records[typ]; exists {
			return nil, fmt.Errorf("duplicate v2 record: 0x%04x", typ)
		}
		if known != nil && !known[typ] {
			if typ&0x8000 != 0 {
				return nil, fmt.Errorf("unknown critical v2 record: 0x%04x", typ)
			}
			continue
		}
		records[typ] = V2TLV{Type: typ, Value: value}
	}
	return records, nil
}

func encodeV2TLVs(records []V2TLV) ([]byte, error) {
	var buf bytes.Buffer
	total := 0
	for _, record := range records {
		if len(record.Value) > maxProtocolFieldLen {
			return nil, fmt.Errorf("v2 record too large: type=0x%04x length=%d", record.Type, len(record.Value))
		}
		total += 4 + len(record.Value)
	}
	buf.Grow(total)
	for _, record := range records {
		if err := writeV2TLV(&buf, record.Type, record.Value); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func writeChannelInit(w io.Writer, init ChannelInit) error {
	body, err := encodeChannelInit(init)
	if err != nil {
		return err
	}
	return writeV2Frame(w, V2Frame{Type: v2FrameTypeChannelInit, Version: protocolV2Version, Body: body})
}

func readChannelInit(r io.Reader, maxSize int) (ChannelInit, error) {
	frame, err := readV2Frame(r, maxSize)
	if err != nil {
		return ChannelInit{}, err
	}
	if frame.Type != v2FrameTypeChannelInit {
		return ChannelInit{}, fmt.Errorf("unexpected v2 frame type: %d", frame.Type)
	}
	return decodeChannelInit(frame.Body)
}

func encodeChannelInit(init ChannelInit) ([]byte, error) {
	if len(init.SessionID) != 16 {
		return nil, fmt.Errorf("session id must be 16 bytes")
	}
	if init.ChannelID == 0 {
		return nil, fmt.Errorf("channel id must be positive")
	}
	if len(init.ClientNonce) != 32 {
		return nil, fmt.Errorf("client nonce must be 32 bytes")
	}
	var cid [4]byte
	binary.BigEndian.PutUint32(cid[:], init.ChannelID)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(init.Timestamp))
	var caps [8]byte
	binary.BigEndian.PutUint64(caps[:], init.Capabilities)
	return encodeV2TLVs([]V2TLV{
		{Type: v2RecordSessionID, Value: init.SessionID},
		{Type: v2RecordChannelID, Value: cid[:]},
		{Type: v2RecordClientNonce, Value: init.ClientNonce},
		{Type: v2RecordTimestamp, Value: ts[:]},
		{Type: v2RecordCapabilities, Value: caps[:]},
		{Type: v2RecordAuthProof, Value: init.AuthProof},
	})
}

func decodeChannelInit(body []byte) (ChannelInit, error) {
	records, err := parseV2TLVs(body, map[uint16]bool{
		v2RecordSessionID:           true,
		v2RecordChannelID:           true,
		v2RecordClientNonce:         true,
		v2RecordTimestamp:           true,
		v2RecordCapabilities:        true,
		v2RecordAuthProof:           true,
		v2RecordClientName:          true,
		v2RecordBuildInfo:           true,
		v2RecordDesiredChannelCount: true,
		v2RecordTransportHints:      true,
		v2RecordPadding:             true,
	})
	if err != nil {
		return ChannelInit{}, err
	}
	get := func(typ uint16, size int) ([]byte, error) {
		record, ok := records[typ]
		if !ok {
			return nil, fmt.Errorf("missing required v2 record: 0x%04x", typ)
		}
		if size >= 0 && len(record.Value) != size {
			return nil, fmt.Errorf("invalid v2 record length: 0x%04x", typ)
		}
		return record.Value, nil
	}
	sessionID, err := get(v2RecordSessionID, 16)
	if err != nil {
		return ChannelInit{}, err
	}
	channelIDRaw, err := get(v2RecordChannelID, 4)
	if err != nil {
		return ChannelInit{}, err
	}
	nonce, err := get(v2RecordClientNonce, 32)
	if err != nil {
		return ChannelInit{}, err
	}
	timestampRaw, err := get(v2RecordTimestamp, 8)
	if err != nil {
		return ChannelInit{}, err
	}
	capsRaw, err := get(v2RecordCapabilities, 8)
	if err != nil {
		return ChannelInit{}, err
	}
	proof, err := get(v2RecordAuthProof, -1)
	if err != nil {
		return ChannelInit{}, err
	}
	channelID := binary.BigEndian.Uint32(channelIDRaw)
	if channelID == 0 {
		return ChannelInit{}, fmt.Errorf("channel id must be positive")
	}
	return ChannelInit{
		SessionID:    append([]byte(nil), sessionID...),
		ChannelID:    channelID,
		ClientNonce:  append([]byte(nil), nonce...),
		Timestamp:    int64(binary.BigEndian.Uint64(timestampRaw)),
		Capabilities: binary.BigEndian.Uint64(capsRaw),
		AuthProof:    append([]byte(nil), proof...),
	}, nil
}

func writeChannelAccept(w io.Writer, accept ChannelAccept) error {
	body, err := encodeChannelAccept(accept)
	if err != nil {
		return err
	}
	return writeV2Frame(w, V2Frame{Type: v2FrameTypeChannelAccept, Version: protocolV2Version, Body: body})
}

func readChannelAcceptOrReject(r io.Reader, maxSize int) (ChannelAccept, ChannelReject, error) {
	frame, err := readV2Frame(r, maxSize)
	if err != nil {
		return ChannelAccept{}, ChannelReject{}, err
	}
	switch frame.Type {
	case v2FrameTypeChannelAccept:
		accept, err := decodeChannelAccept(frame.Body)
		return accept, ChannelReject{}, err
	case v2FrameTypeChannelReject:
		reject, err := decodeChannelReject(frame.Body)
		return ChannelAccept{}, reject, err
	default:
		return ChannelAccept{}, ChannelReject{}, fmt.Errorf("unexpected v2 frame type: %d", frame.Type)
	}
}

func encodeChannelAccept(accept ChannelAccept) ([]byte, error) {
	if len(accept.ServerNonce) != 32 {
		return nil, fmt.Errorf("server nonce must be 32 bytes")
	}
	var caps [8]byte
	binary.BigEndian.PutUint64(caps[:], accept.Capabilities)
	var serverTime [8]byte
	binary.BigEndian.PutUint64(serverTime[:], uint64(accept.ServerTime))
	records := []V2TLV{
		{Type: v2RecordCapabilities, Value: caps[:]},
		{Type: v2RecordServerNonce, Value: accept.ServerNonce},
		{Type: v2RecordServerTime, Value: serverTime[:]},
	}
	if accept.MaxFrameSize != 0 {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], accept.MaxFrameSize)
		records = append(records, V2TLV{Type: v2RecordMaxFrameSize, Value: raw[:]})
	}
	if accept.MaxStreams != 0 {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], accept.MaxStreams)
		records = append(records, V2TLV{Type: v2RecordMaxStreams, Value: raw[:]})
	}
	if accept.Message != "" {
		records = append(records, V2TLV{Type: v2RecordMessage, Value: []byte(accept.Message)})
	}
	return encodeV2TLVs(records)
}

func decodeChannelAccept(body []byte) (ChannelAccept, error) {
	records, err := parseV2TLVs(body, map[uint16]bool{
		v2RecordCapabilities: true,
		v2RecordServerNonce:  true,
		v2RecordServerTime:   true,
		v2RecordMaxFrameSize: true,
		v2RecordMaxStreams:   true,
		v2RecordMessage:      true,
		v2RecordPadding:      true,
	})
	if err != nil {
		return ChannelAccept{}, err
	}
	capsRecord, ok := records[v2RecordCapabilities]
	if !ok || len(capsRecord.Value) != 8 {
		return ChannelAccept{}, fmt.Errorf("invalid channel accept capabilities")
	}
	nonceRecord, ok := records[v2RecordServerNonce]
	if !ok || len(nonceRecord.Value) != 32 {
		return ChannelAccept{}, fmt.Errorf("invalid channel accept server nonce")
	}
	timeRecord, ok := records[v2RecordServerTime]
	if !ok || len(timeRecord.Value) != 8 {
		return ChannelAccept{}, fmt.Errorf("invalid channel accept server time")
	}
	accept := ChannelAccept{
		Capabilities: binary.BigEndian.Uint64(capsRecord.Value),
		ServerNonce:  append([]byte(nil), nonceRecord.Value...),
		ServerTime:   int64(binary.BigEndian.Uint64(timeRecord.Value)),
	}
	if record, ok := records[v2RecordMaxFrameSize]; ok {
		if len(record.Value) != 4 {
			return ChannelAccept{}, fmt.Errorf("invalid max frame size length")
		}
		accept.MaxFrameSize = binary.BigEndian.Uint32(record.Value)
	}
	if record, ok := records[v2RecordMaxStreams]; ok {
		if len(record.Value) != 4 {
			return ChannelAccept{}, fmt.Errorf("invalid max streams length")
		}
		accept.MaxStreams = binary.BigEndian.Uint32(record.Value)
	}
	if record, ok := records[v2RecordMessage]; ok {
		accept.Message = string(record.Value)
	}
	return accept, nil
}

func writeChannelReject(w io.Writer, reject ChannelReject) error {
	body, err := encodeChannelReject(reject)
	if err != nil {
		return err
	}
	return writeV2Frame(w, V2Frame{Type: v2FrameTypeChannelReject, Version: protocolV2Version, Body: body})
}

func encodeChannelReject(reject ChannelReject) ([]byte, error) {
	if reject.Code == 0 {
		reject.Code = v2RejectMalformedFrame
	}
	var code [2]byte
	binary.BigEndian.PutUint16(code[:], uint16(reject.Code))
	records := []V2TLV{{Type: v2RecordRejectCode, Value: code[:]}}
	if reject.Message != "" {
		records = append(records, V2TLV{Type: v2RecordRejectReason, Value: []byte(reject.Message)})
	}
	return encodeV2TLVs(records)
}

func decodeChannelReject(body []byte) (ChannelReject, error) {
	records, err := parseV2TLVs(body, map[uint16]bool{
		v2RecordRejectCode:   true,
		v2RecordRejectReason: true,
		v2RecordPadding:      true,
	})
	if err != nil {
		return ChannelReject{}, err
	}
	codeRecord, ok := records[v2RecordRejectCode]
	if !ok || len(codeRecord.Value) != 2 {
		return ChannelReject{}, fmt.Errorf("invalid channel reject code")
	}
	reject := ChannelReject{Code: byte(binary.BigEndian.Uint16(codeRecord.Value))}
	if record, ok := records[v2RecordRejectReason]; ok {
		reject.Message = string(record.Value)
	}
	return reject, nil
}

func computeV2AuthProof(token, serverName, path string, init ChannelInit) ([]byte, error) {
	authKey := make([]byte, sha256.Size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(token), []byte("x-tunnel-v2-auth"), []byte(serverName)), authKey); err != nil {
		return nil, err
	}
	transcript, err := channelInitTranscript(serverName, path, init)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write(transcript)
	return mac.Sum(nil), nil
}

func verifyV2AuthProof(token, serverName, path string, init ChannelInit) bool {
	want, err := computeV2AuthProof(token, serverName, path, ChannelInit{
		SessionID:    init.SessionID,
		ChannelID:    init.ChannelID,
		ClientNonce:  init.ClientNonce,
		Timestamp:    init.Timestamp,
		Capabilities: init.Capabilities,
	})
	if err != nil {
		return false
	}
	return hmac.Equal(want, init.AuthProof)
}

func channelInitTranscript(serverName, path string, init ChannelInit) ([]byte, error) {
	if len(init.SessionID) != 16 {
		return nil, fmt.Errorf("session id must be 16 bytes")
	}
	if len(init.ClientNonce) != 32 {
		return nil, fmt.Errorf("client nonce must be 32 bytes")
	}
	capacity := 76 + len(serverName) + len(path)
	transcript := make([]byte, 0, capacity)
	transcript = append(transcript, v2FrameTypeChannelInit, protocolV2Version, 0, 0)
	transcript = append(transcript, init.SessionID...)
	var scratch [8]byte
	binary.BigEndian.PutUint32(scratch[:4], init.ChannelID)
	transcript = append(transcript, scratch[:4]...)
	transcript = append(transcript, init.ClientNonce...)
	binary.BigEndian.PutUint64(scratch[:8], uint64(init.Timestamp))
	transcript = append(transcript, scratch[:8]...)
	binary.BigEndian.PutUint64(scratch[:8], init.Capabilities)
	transcript = append(transcript, scratch[:8]...)
	var err error
	transcript, err = appendTranscriptString(transcript, serverName)
	if err != nil {
		return nil, err
	}
	transcript, err = appendTranscriptString(transcript, path)
	if err != nil {
		return nil, err
	}
	return transcript, nil
}

func appendTranscriptString(dst []byte, value string) ([]byte, error) {
	if len(value) > maxProtocolFieldLen {
		return nil, fmt.Errorf("transcript string too long")
	}
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], uint16(len(value)))
	dst = append(dst, raw[:]...)
	dst = append(dst, value...)
	return dst, nil
}

func negotiateProtocolCapabilitiesV2(clientCaps uint64) (uint64, byte, string) {
	caps := clientCaps & currentProtocolCapabilitiesV2()
	required := requiredProtocolCapabilitiesV2()
	if caps&required != required {
		return 0, v2RejectMissingRequiredCapability, "missing required protocol capabilities"
	}
	return caps, 0, ""
}

func validateChannelInitTimestamp(now time.Time, timestamp int64, skew time.Duration) bool {
	if skew <= 0 {
		return true
	}
	then := time.Unix(timestamp, 0)
	if then.After(now.Add(skew)) {
		return false
	}
	return !then.Before(now.Add(-skew))
}

const (
	ProtocolV2Version = protocolV2Version

	V2FrameTypeChannelInit   = v2FrameTypeChannelInit
	V2FrameTypeChannelAccept = v2FrameTypeChannelAccept
	V2FrameTypeChannelReject = v2FrameTypeChannelReject

	V2RecordSessionID    = v2RecordSessionID
	V2RecordChannelID    = v2RecordChannelID
	V2RecordClientNonce  = v2RecordClientNonce
	V2RecordTimestamp    = v2RecordTimestamp
	V2RecordCapabilities = v2RecordCapabilities
	V2RecordAuthProof    = v2RecordAuthProof

	ProtocolCapabilityStreamOpenV2 = protocolCapabilityStreamOpenV2
	ProtocolCapabilityStatusV2     = protocolCapabilityStatusV2
	ProtocolCapabilityChannelStats = protocolCapabilityChannelStats
	ProtocolCapabilityDrainSignal  = protocolCapabilityDrainSignal
	ProtocolCapabilityDatagramV2   = protocolCapabilityDatagramV2

	V2RejectUnsupportedVersion        = v2RejectUnsupportedVersion
	V2RejectMissingRequiredCapability = v2RejectMissingRequiredCapability
	V2RejectAuthenticationFailed      = v2RejectAuthenticationFailed
	V2RejectTimestampSkew             = v2RejectTimestampSkew
	V2RejectReplayDetected            = v2RejectReplayDetected
	V2RejectResourceLimit             = v2RejectResourceLimit
	V2RejectPolicyDenied              = v2RejectPolicyDenied
	V2RejectMalformedFrame            = v2RejectMalformedFrame

	MaxV2FrameSize = maxV2FrameSize
)

func CurrentProtocolCapabilitiesV2() uint64 { return currentProtocolCapabilitiesV2() }

func RequiredProtocolCapabilitiesV2() uint64 { return requiredProtocolCapabilitiesV2() }

func WriteV2Frame(w io.Writer, frame V2Frame) error { return writeV2Frame(w, frame) }

func ReadV2Frame(r io.Reader, maxSize int) (V2Frame, error) { return readV2Frame(r, maxSize) }

func WriteV2TLV(w io.Writer, typ uint16, value []byte) error {
	return writeV2TLV(w, typ, value)
}

func ParseV2TLVs(body []byte, known map[uint16]bool) (map[uint16]V2TLV, error) {
	return parseV2TLVs(body, known)
}

func EncodeV2TLVs(records []V2TLV) ([]byte, error) { return encodeV2TLVs(records) }

func WriteChannelInit(w io.Writer, init ChannelInit) error { return writeChannelInit(w, init) }

func ReadChannelInit(r io.Reader, maxSize int) (ChannelInit, error) {
	return readChannelInit(r, maxSize)
}

func EncodeChannelInit(init ChannelInit) ([]byte, error) { return encodeChannelInit(init) }

func DecodeChannelInit(body []byte) (ChannelInit, error) { return decodeChannelInit(body) }

func WriteChannelAccept(w io.Writer, accept ChannelAccept) error {
	return writeChannelAccept(w, accept)
}

func ReadChannelAcceptOrReject(r io.Reader, maxSize int) (ChannelAccept, ChannelReject, error) {
	return readChannelAcceptOrReject(r, maxSize)
}

func WriteChannelReject(w io.Writer, reject ChannelReject) error {
	return writeChannelReject(w, reject)
}

func ComputeV2AuthProof(token, serverName, path string, init ChannelInit) ([]byte, error) {
	return computeV2AuthProof(token, serverName, path, init)
}

func VerifyV2AuthProof(token, serverName, path string, init ChannelInit) bool {
	return verifyV2AuthProof(token, serverName, path, init)
}

func NegotiateProtocolCapabilitiesV2(clientCaps uint64) (uint64, byte, string) {
	return negotiateProtocolCapabilitiesV2(clientCaps)
}

func ValidateChannelInitTimestamp(now time.Time, timestamp int64, skew time.Duration) bool {
	return validateChannelInitTimestamp(now, timestamp, skew)
}
