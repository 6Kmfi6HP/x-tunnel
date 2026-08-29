package app

import (
	"io"

	"x-tunnel/internal/wire"
)

const (
	streamKindTCP  = wire.StreamKindTCP
	streamKindUDP  = wire.StreamKindUDP
	streamKindPing = wire.StreamKindPing

	protocolCapabilityTCP            = 1 << 0
	protocolCapabilityUDP            = 1 << 1
	protocolCapabilityPing           = 1 << 2
	protocolCapabilityIPStrategy     = 1 << 3
	protocolCapabilityTCPStatus      = 1 << 4
	protocolCapabilityUDPStatus      = 1 << 5
	protocolCapabilityOpenStatusCode = 1 << 6
	protocolCapabilityChannelStats   = 1 << 9

	tcpOpenStatusOK    = wire.TCPOpenStatusOK
	tcpOpenStatusError = wire.TCPOpenStatusError
	udpOpenStatusOK    = wire.UDPOpenStatusOK
	udpOpenStatusError = wire.UDPOpenStatusError

	openStatusCodeNone          = wire.OpenStatusCodeNone
	openStatusCodeBadTarget     = wire.OpenStatusCodeBadTarget
	openStatusCodePolicyDenied  = wire.OpenStatusCodePolicyDenied
	openStatusCodeDialFailed    = wire.OpenStatusCodeDialFailed
	openStatusCodeResourceLimit = wire.OpenStatusCodeResourceLimit

	maxProtocolFieldLen = wire.MaxProtocolFieldLen
	maxV2FrameSize      = wire.MaxV2FrameSize

	v2RejectAuthenticationFailed = wire.V2RejectAuthenticationFailed
	v2RejectTimestampSkew        = wire.V2RejectTimestampSkew
	v2RejectReplayDetected       = wire.V2RejectReplayDetected
	v2RejectResourceLimit        = wire.V2RejectResourceLimit
	v2RejectMalformedFrame       = wire.V2RejectMalformedFrame
)

type ChannelInit = wire.ChannelInit
type ChannelAccept = wire.ChannelAccept
type ChannelReject = wire.ChannelReject

func isSupportedStreamKind(kind byte) bool { return wire.IsSupportedStreamKind(kind) }

func currentProtocolCapabilities() uint32 { return wire.CurrentProtocolCapabilities() }

func requiredProtocolCapabilities() uint32 { return wire.RequiredProtocolCapabilities() }

func currentProtocolCapabilitiesV2() uint64 { return wire.CurrentProtocolCapabilitiesV2() }

func requiredProtocolCapabilitiesV2() uint64 { return wire.RequiredProtocolCapabilitiesV2() }

func writeChannelInit(w io.Writer, init ChannelInit) error { return wire.WriteChannelInit(w, init) }

func readChannelInit(r io.Reader, maxSize int) (ChannelInit, error) {
	return wire.ReadChannelInit(r, maxSize)
}

func writeChannelAccept(w io.Writer, accept ChannelAccept) error {
	return wire.WriteChannelAccept(w, accept)
}

func readChannelAcceptOrReject(r io.Reader, maxSize int) (ChannelAccept, ChannelReject, error) {
	return wire.ReadChannelAcceptOrReject(r, maxSize)
}

func writeChannelReject(w io.Writer, reject ChannelReject) error {
	return wire.WriteChannelReject(w, reject)
}

func computeV2AuthProof(token, serverName, path string, init ChannelInit) ([]byte, error) {
	return wire.ComputeV2AuthProof(token, serverName, path, init)
}

func verifyV2AuthProof(token, serverName, path string, init ChannelInit) bool {
	return wire.VerifyV2AuthProof(token, serverName, path, init)
}

func negotiateProtocolCapabilitiesV2(clientCaps uint64) (uint64, byte, string) {
	return wire.NegotiateProtocolCapabilitiesV2(clientCaps)
}

func writeTCPOpenStatus(w io.Writer, status byte, message string) error {
	return wire.WriteTCPOpenStatus(w, status, message)
}

func readTCPOpenStatus(r io.Reader) (byte, string, error) { return wire.ReadTCPOpenStatus(r) }

func writeTCPOpenStatusCode(w io.Writer, status byte, code byte, message string) error {
	return wire.WriteTCPOpenStatusCode(w, status, code, message)
}

func readTCPOpenStatusCode(r io.Reader) (byte, byte, string, error) {
	return wire.ReadTCPOpenStatusCode(r)
}

func writeUDPOpenStatus(w io.Writer, status byte, message string) error {
	return wire.WriteUDPOpenStatus(w, status, message)
}

func readUDPOpenStatus(r io.Reader) (byte, string, error) { return wire.ReadUDPOpenStatus(r) }

func writeUDPOpenStatusCode(w io.Writer, status byte, code byte, message string) error {
	return wire.WriteUDPOpenStatusCode(w, status, code, message)
}

func readUDPOpenStatusCode(r io.Reader) (byte, byte, string, error) {
	return wire.ReadUDPOpenStatusCode(r)
}

func readSmuxOpenHeader(r io.Reader) (byte, byte, string, error) {
	return wire.ReadSmuxOpenHeader(r)
}

func writeSmuxOpenHeader(w io.Writer, kind byte, strategy byte, target string) error {
	return wire.WriteSmuxOpenHeader(w, kind, strategy, target)
}

func writeChunk(w io.Writer, b []byte) error { return wire.WriteChunk(w, b) }

func readChunk(r io.Reader) ([]byte, error) { return wire.ReadChunk(r) }

func writeUDPReply(w io.Writer, addr string, payload []byte) error {
	return wire.WriteUDPReply(w, addr, payload)
}

func readUDPReply(r io.Reader) (string, []byte, error) { return wire.ReadUDPReply(r) }

func writeAll(w io.Writer, b []byte) error { return wire.WriteAll(w, b) }

func writeAllCount(w io.Writer, b []byte) (int, error) { return wire.WriteAllCount(w, b) }
