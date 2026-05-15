package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseIPStrategy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want byte
	}{
		{name: "default empty", in: "", want: IPStrategyDefault},
		{name: "ipv4 only", in: "4", want: IPStrategyIPv4Only},
		{name: "ipv6 only", in: "6", want: IPStrategyIPv6Only},
		{name: "ipv4 preferred", in: "4,6", want: IPStrategyPv4Pv6},
		{name: "ipv6 preferred", in: "6,4", want: IPStrategyPv6Pv4},
		{name: "spaces", in: " 4, 6 ", want: IPStrategyPv4Pv6},
		{name: "unknown", in: "7", want: IPStrategyDefault},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseIPStrategy(tt.in); got != tt.want {
				t.Fatalf("parseIPStrategy(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestBaseReconnectDelay(t *testing.T) {
	oldCfg := cfg
	defer func() { cfg = oldCfg }()
	cfg.ReconnectDelay = time.Second
	cfg.ReconnectMaxDelay = 5 * time.Second

	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 0, want: time.Second},
		{attempt: 1, want: 2 * time.Second},
		{attempt: 2, want: 4 * time.Second},
		{attempt: 3, want: 5 * time.Second},
		{attempt: 10, want: 5 * time.Second},
	}

	for _, tt := range tests {
		if got := baseReconnectDelay(tt.attempt); got != tt.want {
			t.Fatalf("baseReconnectDelay(%d) = %s, want %s", tt.attempt, got, tt.want)
		}
	}
}

func TestReconnectDelayJitterBounds(t *testing.T) {
	oldCfg := cfg
	defer func() { cfg = oldCfg }()
	cfg.ReconnectDelay = time.Second
	cfg.ReconnectMaxDelay = 10 * time.Second
	cfg.ReconnectJitter = 500 * time.Millisecond

	got := reconnectDelay(1)
	if got < 2*time.Second {
		t.Fatalf("reconnectDelay below base: %s", got)
	}
	if got >= 2500*time.Millisecond {
		t.Fatalf("reconnectDelay above jitter bound: %s", got)
	}

	cfg.ReconnectJitter = 0
	if got := reconnectDelay(1); got != 2*time.Second {
		t.Fatalf("reconnectDelay without jitter = %s, want 2s", got)
	}
}

func TestSleepWithContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if sleepWithContext(ctx, time.Second) {
		t.Fatal("sleepWithContext returned true for canceled context")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("sleepWithContext took too long after cancellation: %s", elapsed)
	}
}

func TestVersionString(t *testing.T) {
	oldVersion, oldCommit, oldDate := buildVersion, buildCommit, buildDate
	defer func() {
		buildVersion, buildCommit, buildDate = oldVersion, oldCommit, oldDate
	}()
	buildVersion = "1.2.3"
	buildCommit = "abc123"
	buildDate = "2026-05-16"
	want := "x-tunnel version=1.2.3 commit=abc123 build=2026-05-16"
	if got := versionString(); got != want {
		t.Fatalf("versionString() = %q, want %q", got, want)
	}
}

func TestWriteMetrics(t *testing.T) {
	oldStreams := atomic.LoadUint64(&serverStreamSeq)
	oldUDP := atomic.LoadUint64(&udpAssociationSeq)
	oldReconnects := atomic.LoadUint64(&clientReconnectSeq)
	defer func() {
		atomic.StoreUint64(&serverStreamSeq, oldStreams)
		atomic.StoreUint64(&udpAssociationSeq, oldUDP)
		atomic.StoreUint64(&clientReconnectSeq, oldReconnects)
		serverSessions.Delete("metrics-test")
	}()
	atomic.StoreUint64(&serverStreamSeq, 7)
	atomic.StoreUint64(&udpAssociationSeq, 3)
	atomic.StoreUint64(&clientReconnectSeq, 2)
	serverSessions.Store("metrics-test", &ClientSession{clientID: "metrics-test"})

	var buf bytes.Buffer
	writeMetrics(&buf)
	got := buf.String()
	for _, want := range []string{
		"x_tunnel_server_streams_total 7",
		"x_tunnel_udp_associations_total 3",
		"x_tunnel_client_reconnects_total 2",
		"x_tunnel_server_sessions",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, got)
		}
	}
}

func TestValidateToken(t *testing.T) {
	valid := []string{"", "local-test-token", "abc.DEF_123~"}
	for _, token := range valid {
		if err := validateToken(token); err != nil {
			t.Fatalf("validateToken(%q) returned error: %v", token, err)
		}
	}

	invalid := []string{"has space", "bad,comma", "bad/slash", "bad\nline"}
	for _, token := range invalid {
		if err := validateToken(token); err == nil {
			t.Fatalf("validateToken(%q) accepted invalid token", token)
		}
	}
}

func TestValidateListenRule(t *testing.T) {
	valid := []string{
		"ws://127.0.0.1:18080/tunnel",
		"wss://:18443/tunnel",
		"socks5://user:pass@127.0.0.1:11080",
		"http://127.0.0.1:18080",
		"tcp://127.0.0.1:12000/127.0.0.1:19090",
	}
	for _, rule := range valid {
		if err := validateListenRule(rule); err != nil {
			t.Fatalf("validateListenRule(%q) returned error: %v", rule, err)
		}
	}

	invalid := []string{
		"",
		"ftp://127.0.0.1:21",
		"ws://127.0.0.1",
		"socks5://127.0.0.1:70000",
		"tcp://127.0.0.1:12000",
		"tcp://127.0.0.1:12000/",
	}
	for _, rule := range invalid {
		if err := validateListenRule(rule); err == nil {
			t.Fatalf("validateListenRule(%q) accepted invalid rule", rule)
		}
	}
}

func TestValidateDialIPOverride(t *testing.T) {
	valid := []string{"127.0.0.1", "127.0.0.1:443", "2001:db8::1", "[2001:db8::1]:443"}
	for _, value := range valid {
		if err := validateDialIPOverride(value); err != nil {
			t.Fatalf("validateDialIPOverride(%q) returned error: %v", value, err)
		}
	}

	invalid := []string{"example.com", "127.0.0.1:0", "127.0.0.1:70000", "[2001:db8::1]:0"}
	for _, value := range invalid {
		if err := validateDialIPOverride(value); err == nil {
			t.Fatalf("validateDialIPOverride(%q) accepted invalid override", value)
		}
	}
}

func TestTargetPolicyAllows(t *testing.T) {
	policy, err := parseTargetPolicy("10.0.0.0/8,2001:db8::/32", "10.0.9.0/24")
	if err != nil {
		t.Fatalf("parseTargetPolicy returned error: %v", err)
	}

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{name: "allowed ipv4", target: "10.1.2.3:443", want: true},
		{name: "denied before allow", target: "10.0.9.1:443", want: false},
		{name: "outside allow", target: "192.0.2.1:443", want: false},
		{name: "domain denied with allow policy", target: "example.com:443", want: false},
		{name: "allowed ipv6", target: "[2001:db8::1]:443", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := policy.Allows(tt.target)
			if got != tt.want {
				t.Fatalf("TargetPolicy.Allows(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestTargetPolicyDenyOnlyAllowsDomains(t *testing.T) {
	policy, err := parseTargetPolicy("", "127.0.0.0/8")
	if err != nil {
		t.Fatalf("parseTargetPolicy returned error: %v", err)
	}
	if ok, _ := policy.Allows("127.0.0.1:80"); ok {
		t.Fatal("deny-only policy allowed denied IP")
	}
	if ok, _ := policy.Allows("example.com:80"); !ok {
		t.Fatal("deny-only policy rejected domain target")
	}
}

func TestParseTargetPolicyRejectsInvalidCIDR(t *testing.T) {
	if _, err := parseTargetPolicy("not-a-cidr", ""); err == nil {
		t.Fatal("parseTargetPolicy accepted invalid allow CIDR")
	}
	if _, err := parseTargetPolicy("", "not-a-cidr"); err == nil {
		t.Fatal("parseTargetPolicy accepted invalid deny CIDR")
	}
}

func TestParseSOCKS5Addr(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		host     string
		username string
		password string
	}{
		{
			name: "with scheme and auth", in: "socks5://user:pass@127.0.0.1:1080",
			host: "127.0.0.1:1080", username: "user", password: "pass",
		},
		{
			name: "without auth", in: "socks5://127.0.0.1:1080",
			host: "127.0.0.1:1080",
		},
		{
			name: "without scheme", in: "user:pass@example.com:1080",
			host: "example.com:1080", username: "user", password: "pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSOCKS5Addr(tt.in)
			if err != nil {
				t.Fatalf("parseSOCKS5Addr returned error: %v", err)
			}
			if got.Host != tt.host || got.Username != tt.username || got.Password != tt.password {
				t.Fatalf("parseSOCKS5Addr(%q) = %#v, want host=%q username=%q password=%q", tt.in, got, tt.host, tt.username, tt.password)
			}
		})
	}
}

func TestParseAuthAndAddr(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		host     string
		username string
		password string
	}{
		{name: "with auth", in: "user:pass@0.0.0.0:1080", host: "0.0.0.0:1080", username: "user", password: "pass"},
		{name: "without auth", in: "127.0.0.1:8080", host: "127.0.0.1:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, username, password, err := parseAuthAndAddr(tt.in)
			if err != nil {
				t.Fatalf("parseAuthAndAddr returned error: %v", err)
			}
			if host != tt.host || username != tt.username || password != tt.password {
				t.Fatalf("parseAuthAndAddr(%q) = %q, %q, %q; want %q, %q, %q", tt.in, host, username, password, tt.host, tt.username, tt.password)
			}
		})
	}
}

func TestSmuxOpenHeaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSmuxOpenHeader(&buf, streamKindTCP, IPStrategyPv4Pv6, "example.com:443"); err != nil {
		t.Fatalf("writeSmuxOpenHeader returned error: %v", err)
	}

	kind, strategy, target, err := readSmuxOpenHeader(&buf)
	if err != nil {
		t.Fatalf("readSmuxOpenHeader returned error: %v", err)
	}
	if kind != streamKindTCP || strategy != IPStrategyPv4Pv6 || target != "example.com:443" {
		t.Fatalf("header = kind %d strategy %d target %q", kind, strategy, target)
	}
}

func TestSmuxOpenHeaderRejectsOversizedTarget(t *testing.T) {
	err := writeSmuxOpenHeader(io.Discard, streamKindTCP, IPStrategyDefault, strings.Repeat("x", 65536))
	if err == nil {
		t.Fatal("writeSmuxOpenHeader accepted oversized target")
	}
}

func TestReadSmuxOpenHeaderMalformed(t *testing.T) {
	if _, _, _, err := readSmuxOpenHeader(bytes.NewReader([]byte{streamKindTCP, IPStrategyDefault})); err == nil {
		t.Fatal("readSmuxOpenHeader accepted short header")
	}

	raw := []byte{streamKindTCP, IPStrategyDefault, 0, 5, 'a'}
	if _, _, _, err := readSmuxOpenHeader(bytes.NewReader(raw)); err == nil {
		t.Fatal("readSmuxOpenHeader accepted truncated target")
	}
}

func TestProtocolConstants(t *testing.T) {
	if protocolVersion != 1 {
		t.Fatalf("protocolVersion = %d, want 1", protocolVersion)
	}
	if protocolStatusOK != 0 {
		t.Fatalf("protocolStatusOK = %d, want 0", protocolStatusOK)
	}
}

func TestProtocolHelloRoundTrip(t *testing.T) {
	if protocolStatusOK != 0 {
		t.Fatalf("protocolStatusOK = %d, want 0", protocolStatusOK)
	}

	var buf bytes.Buffer
	want := ProtocolHello{
		Version:      protocolVersion,
		Status:       protocolStatusOK,
		Capabilities: protocolCapabilityTCP | protocolCapabilityPing,
		Message:      "ok",
	}
	if err := writeProtocolHello(&buf, want); err != nil {
		t.Fatalf("writeProtocolHello returned error: %v", err)
	}

	got, err := readProtocolHello(&buf)
	if err != nil {
		t.Fatalf("readProtocolHello returned error: %v", err)
	}
	if got != want {
		t.Fatalf("readProtocolHello = %#v, want %#v", got, want)
	}
}

func TestProtocolHelloRejectsOversizedMessage(t *testing.T) {
	err := writeProtocolHello(io.Discard, ProtocolHello{Message: strings.Repeat("x", 65536)})
	if err == nil {
		t.Fatal("writeProtocolHello accepted oversized message")
	}
}

func TestReadProtocolHelloMalformed(t *testing.T) {
	if _, err := readProtocolHello(bytes.NewReader([]byte("bad"))); err == nil {
		t.Fatal("readProtocolHello accepted short frame")
	}

	raw := make([]byte, 12)
	copy(raw[0:4], []byte("NOPE"))
	if _, err := readProtocolHello(bytes.NewReader(raw)); err == nil {
		t.Fatal("readProtocolHello accepted bad magic")
	}

	raw = make([]byte, 12)
	copy(raw[0:4], []byte(protocolHelloMagic))
	raw[6], raw[7] = 0, 5
	raw = append(raw, 'x')
	if _, err := readProtocolHello(bytes.NewReader(raw)); err == nil {
		t.Fatal("readProtocolHello accepted truncated message")
	}
}

func TestNegotiateProtocolHello(t *testing.T) {
	ok := negotiateProtocolHello(ProtocolHello{
		Version:      protocolVersion,
		Capabilities: currentProtocolCapabilities(),
	})
	if ok.Status != protocolStatusOK {
		t.Fatalf("negotiateProtocolHello status = %d, want OK", ok.Status)
	}
	if ok.Capabilities != currentProtocolCapabilities() {
		t.Fatalf("negotiateProtocolHello caps = 0x%x, want 0x%x", ok.Capabilities, currentProtocolCapabilities())
	}

	unsupported := negotiateProtocolHello(ProtocolHello{
		Version:      protocolVersion + 1,
		Capabilities: currentProtocolCapabilities(),
	})
	if unsupported.Status != protocolStatusUnsupportedVersion {
		t.Fatalf("unsupported version status = %d", unsupported.Status)
	}

	noCommon := negotiateProtocolHello(ProtocolHello{
		Version:      protocolVersion,
		Capabilities: 1 << 31,
	})
	if noCommon.Status != protocolStatusNoCommonCapabilities {
		t.Fatalf("no common capability status = %d", noCommon.Status)
	}

	missingRequired := negotiateProtocolHello(ProtocolHello{
		Version:      protocolVersion,
		Capabilities: protocolCapabilityUDP,
	})
	if missingRequired.Status != protocolStatusNoCommonCapabilities {
		t.Fatalf("missing required capability status = %d", missingRequired.Status)
	}
}

func TestChunkRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello")
	if err := writeChunk(&buf, payload); err != nil {
		t.Fatalf("writeChunk returned error: %v", err)
	}
	got, err := readChunk(&buf)
	if err != nil {
		t.Fatalf("readChunk returned error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("readChunk = %q, want %q", got, payload)
	}
}

func TestChunkZeroLength(t *testing.T) {
	var buf bytes.Buffer
	if err := writeChunk(&buf, nil); err != nil {
		t.Fatalf("writeChunk returned error: %v", err)
	}
	got, err := readChunk(&buf)
	if err != nil {
		t.Fatalf("readChunk returned error: %v", err)
	}
	if got != nil {
		t.Fatalf("readChunk zero length = %v, want nil", got)
	}
}

func TestChunkRejectsOversizedPayload(t *testing.T) {
	err := writeChunk(io.Discard, []byte(strings.Repeat("x", 65536)))
	if err == nil {
		t.Fatal("writeChunk accepted oversized payload")
	}
}

func TestUDPReplyRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("dns-response")
	if err := writeUDPReply(&buf, "1.2.3.4:53", payload); err != nil {
		t.Fatalf("writeUDPReply returned error: %v", err)
	}
	addr, got, err := readUDPReply(&buf)
	if err != nil {
		t.Fatalf("readUDPReply returned error: %v", err)
	}
	if addr != "1.2.3.4:53" || !bytes.Equal(got, payload) {
		t.Fatalf("readUDPReply = addr %q payload %q", addr, got)
	}
}

func TestUDPReplyRejectsOversizedFields(t *testing.T) {
	if err := writeUDPReply(io.Discard, strings.Repeat("x", 65536), nil); err == nil {
		t.Fatal("writeUDPReply accepted oversized addr")
	}
	if err := writeUDPReply(io.Discard, "1.2.3.4:53", []byte(strings.Repeat("x", 65536))); err == nil {
		t.Fatal("writeUDPReply accepted oversized payload")
	}
}

func TestSOCKS5UDPPacketRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		port       int
		wantTarget string
	}{
		{name: "ipv4", host: "1.2.3.4", port: 53, wantTarget: "1.2.3.4:53"},
		{name: "domain", host: "example.com", port: 443, wantTarget: "example.com:443"},
		{name: "ipv6", host: "2001:db8::1", port: 443, wantTarget: "[2001:db8::1]:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := []byte("payload")
			packet, err := buildSOCKS5UDPPacket(tt.host, tt.port, payload)
			if err != nil {
				t.Fatalf("buildSOCKS5UDPPacket returned error: %v", err)
			}
			target, got, err := parseSOCKS5UDPPacket(packet)
			if err != nil {
				t.Fatalf("parseSOCKS5UDPPacket returned error: %v", err)
			}
			if target != tt.wantTarget || !bytes.Equal(got, payload) {
				t.Fatalf("parseSOCKS5UDPPacket = target %q payload %q, want target %q payload %q", target, got, tt.wantTarget, payload)
			}
		})
	}
}

func TestSOCKS5UDPPacketMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "too short", raw: []byte{0, 0, 0}},
		{name: "fragmented", raw: []byte{0, 0, 1, 1, 1, 2, 3, 4, 0, 53}},
		{name: "unknown atyp", raw: []byte{0, 0, 0, 9, 0, 53}},
		{name: "truncated domain", raw: []byte{0, 0, 0, 3, 5, 'a'}},
		{name: "truncated port", raw: []byte{0, 0, 0, 1, 1, 2, 3, 4, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := parseSOCKS5UDPPacket(tt.raw); err == nil {
				t.Fatalf("parseSOCKS5UDPPacket accepted malformed packet %v", tt.raw)
			}
		})
	}
}

func TestBuildSOCKS5UDPPacketRejectsOversizedDomain(t *testing.T) {
	if _, err := buildSOCKS5UDPPacket(strings.Repeat("x", 256), 53, nil); err == nil {
		t.Fatal("buildSOCKS5UDPPacket accepted oversized domain")
	}
}
