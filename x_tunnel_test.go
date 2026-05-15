package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/smux"
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

func TestParseIPStrategyStrict(t *testing.T) {
	valid := map[string]byte{
		"":       IPStrategyDefault,
		"4":      IPStrategyIPv4Only,
		"6":      IPStrategyIPv6Only,
		"4,6":    IPStrategyPv4Pv6,
		" 6, 4 ": IPStrategyPv6Pv4,
	}
	for in, want := range valid {
		got, err := parseIPStrategyStrict(in)
		if err != nil {
			t.Fatalf("parseIPStrategyStrict(%q) returned error: %v", in, err)
		}
		if got != want {
			t.Fatalf("parseIPStrategyStrict(%q) = %d, want %d", in, got, want)
		}
	}
	for _, in := range []string{"7", "4,4", "4,6,6", "ipv4"} {
		if _, err := parseIPStrategyStrict(in); err == nil {
			t.Fatalf("parseIPStrategyStrict(%q) accepted invalid strategy", in)
		}
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
	oldSourceRejects := atomic.LoadUint64(&serverSourceRejectSeq)
	oldAuthRejects := atomic.LoadUint64(&serverAuthRejectSeq)
	oldClientRejects := atomic.LoadUint64(&serverClientRejectSeq)
	oldStreamRejects := atomic.LoadUint64(&serverStreamRejectSeq)
	oldTargetRejects := atomic.LoadUint64(&serverTargetRejectSeq)
	oldUnsupportedStreams := atomic.LoadUint64(&serverUnsupportedStreamSeq)
	defer func() {
		atomic.StoreUint64(&serverStreamSeq, oldStreams)
		atomic.StoreUint64(&udpAssociationSeq, oldUDP)
		atomic.StoreUint64(&clientReconnectSeq, oldReconnects)
		atomic.StoreUint64(&serverSourceRejectSeq, oldSourceRejects)
		atomic.StoreUint64(&serverAuthRejectSeq, oldAuthRejects)
		atomic.StoreUint64(&serverClientRejectSeq, oldClientRejects)
		atomic.StoreUint64(&serverStreamRejectSeq, oldStreamRejects)
		atomic.StoreUint64(&serverTargetRejectSeq, oldTargetRejects)
		atomic.StoreUint64(&serverUnsupportedStreamSeq, oldUnsupportedStreams)
		serverSessions.Delete("metrics-test")
	}()
	atomic.StoreUint64(&serverStreamSeq, 7)
	atomic.StoreUint64(&udpAssociationSeq, 3)
	atomic.StoreUint64(&clientReconnectSeq, 2)
	atomic.StoreUint64(&serverSourceRejectSeq, 11)
	atomic.StoreUint64(&serverAuthRejectSeq, 13)
	atomic.StoreUint64(&serverClientRejectSeq, 17)
	atomic.StoreUint64(&serverStreamRejectSeq, 19)
	atomic.StoreUint64(&serverTargetRejectSeq, 23)
	atomic.StoreUint64(&serverUnsupportedStreamSeq, 29)
	serverSessions.Store("metrics-test", &ClientSession{clientID: "metrics-test"})

	var buf bytes.Buffer
	writeMetrics(&buf)
	got := buf.String()
	for _, want := range []string{
		"x_tunnel_server_streams_total 7",
		"x_tunnel_udp_associations_total 3",
		"x_tunnel_client_reconnects_total 2",
		"x_tunnel_server_source_rejections_total 11",
		"x_tunnel_server_auth_rejections_total 13",
		"x_tunnel_server_client_session_rejections_total 17",
		"x_tunnel_server_stream_rejections_total 19",
		"x_tunnel_server_target_rejections_total 23",
		"x_tunnel_server_unsupported_streams_total 29",
		"x_tunnel_server_sessions",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, got)
		}
	}
}

func TestLoadConfigFileAppliesUnsetFlags(t *testing.T) {
	oldCfg := cfg
	oldListen, oldForward, oldToken := listenAddr, forwardAddr, token
	oldMetrics, oldConnectionNum := metricsAddr, connectionNum
	oldMaxClients := maxClientSessions
	oldMaxStreams := maxStreamsPerClient
	oldAllow, oldDeny := targetAllowCIDRs, targetDenyCIDRs
	oldAllowHosts, oldDenyHosts := targetAllowHosts, targetDenyHosts
	oldClientCA, oldClientCert, oldClientKey := clientCAFile, clientCertFile, clientKeyFile
	defer func() {
		cfg = oldCfg
		listenAddr, forwardAddr, token = oldListen, oldForward, oldToken
		metricsAddr, connectionNum = oldMetrics, oldConnectionNum
		maxClientSessions = oldMaxClients
		maxStreamsPerClient = oldMaxStreams
		targetAllowCIDRs, targetDenyCIDRs = oldAllow, oldDeny
		targetAllowHosts, targetDenyHosts = oldAllowHosts, oldDenyHosts
		clientCAFile, clientCertFile, clientKeyFile = oldClientCA, oldClientCert, oldClientKey
	}()
	listenAddr, forwardAddr, token, metricsAddr = "", "", "", ""
	targetAllowCIDRs, targetDenyCIDRs = "", ""
	targetAllowHosts, targetDenyHosts = "", ""
	clientCAFile, clientCertFile, clientKeyFile = "", "", ""
	cfg.DialTimeout = 3 * time.Second
	cfg.ReconnectJitter = 500 * time.Millisecond
	connectionNum = 3
	maxClientSessions = 0
	maxStreamsPerClient = 0

	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"listen": "socks5://127.0.0.1:11080",
		"forward": "ws://127.0.0.1:18080/tunnel",
		"token": "config-token",
		"metrics": "127.0.0.1:19099",
		"allow-target": "10.0.0.0/8",
		"deny_target": "10.0.9.0/24",
		"allow-host": "api.example.com",
		"deny_host": "*.blocked.example.com",
		"client-ca": "ca.pem",
		"client_cert": "client.pem",
		"client-key": "client-key.pem",
		"dial_timeout": "250ms",
		"reconnect_jitter": "0s",
		"connections": 2,
		"max-clients": 4,
		"max-streams": 8
	}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, map[string]bool{"token": true}); err != nil {
		t.Fatalf("loadConfigFile returned error: %v", err)
	}
	if listenAddr != "socks5://127.0.0.1:11080" {
		t.Fatalf("listenAddr = %q", listenAddr)
	}
	if forwardAddr != "ws://127.0.0.1:18080/tunnel" {
		t.Fatalf("forwardAddr = %q", forwardAddr)
	}
	if token != "" {
		t.Fatalf("token should not be overridden by config when flag is seen, got %q", token)
	}
	if metricsAddr != "127.0.0.1:19099" {
		t.Fatalf("metricsAddr = %q", metricsAddr)
	}
	if targetAllowCIDRs != "10.0.0.0/8" {
		t.Fatalf("targetAllowCIDRs = %q", targetAllowCIDRs)
	}
	if targetDenyCIDRs != "10.0.9.0/24" {
		t.Fatalf("targetDenyCIDRs = %q", targetDenyCIDRs)
	}
	if targetAllowHosts != "api.example.com" {
		t.Fatalf("targetAllowHosts = %q", targetAllowHosts)
	}
	if targetDenyHosts != "*.blocked.example.com" {
		t.Fatalf("targetDenyHosts = %q", targetDenyHosts)
	}
	if clientCAFile != "ca.pem" || clientCertFile != "client.pem" || clientKeyFile != "client-key.pem" {
		t.Fatalf("client mTLS config = %q %q %q", clientCAFile, clientCertFile, clientKeyFile)
	}
	if cfg.DialTimeout != 250*time.Millisecond {
		t.Fatalf("DialTimeout = %s, want 250ms", cfg.DialTimeout)
	}
	if cfg.ReconnectJitter != 0 {
		t.Fatalf("ReconnectJitter = %s, want 0", cfg.ReconnectJitter)
	}
	if connectionNum != 2 {
		t.Fatalf("connectionNum = %d, want 2", connectionNum)
	}
	if maxStreamsPerClient != 8 {
		t.Fatalf("maxStreamsPerClient = %d, want 8", maxStreamsPerClient)
	}
	if maxClientSessions != 4 {
		t.Fatalf("maxClientSessions = %d, want 4", maxClientSessions)
	}
}

func TestLoadConfigFileRejectsInvalidDuration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"dial_timeout":"soon"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err == nil {
		t.Fatal("loadConfigFile accepted invalid duration")
	}
}

func TestLoadConfigFileRejectsNegativeJitter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"reconnect_jitter":"-1s"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err == nil {
		t.Fatal("loadConfigFile accepted negative reconnect jitter")
	}
}

func TestLoadConfigFileRejectsNegativeMaxStreams(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"max_streams":-1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err == nil {
		t.Fatal("loadConfigFile accepted negative max stream limit")
	}
}

func TestLoadConfigFileRejectsNegativeMaxClients(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"max_clients":-1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err == nil {
		t.Fatal("loadConfigFile accepted negative max client limit")
	}
}

func TestValidateGlobalConfig(t *testing.T) {
	oldCfg := cfg
	oldMaxClients := maxClientSessions
	oldMaxStreams := maxStreamsPerClient
	defer func() {
		cfg = oldCfg
		maxClientSessions = oldMaxClients
		maxStreamsPerClient = oldMaxStreams
	}()
	cfg = GlobalConfig{
		DialTimeout:        time.Second,
		WSHandshakeTimeout: time.Second,
		ReconnectDelay:     time.Second,
		ReconnectMaxDelay:  time.Second,
		ReconnectJitter:    0,
		RTTProbeTimeout:    time.Second,
		DNSQueryTimeout:    time.Second,
		ECHRetryDelay:      time.Second,
		UDPReadTimeout:     time.Second,
		ShutdownTimeout:    time.Second,
		ReadBuf:            64 * 1024,
	}
	maxClientSessions = 0
	maxStreamsPerClient = 0
	if err := validateGlobalConfig(); err != nil {
		t.Fatalf("validateGlobalConfig rejected zero jitter: %v", err)
	}
	maxClientSessions = -1
	if err := validateGlobalConfig(); err == nil {
		t.Fatal("validateGlobalConfig accepted negative client limit")
	}
	maxClientSessions = 0
	maxStreamsPerClient = -1
	if err := validateGlobalConfig(); err == nil {
		t.Fatal("validateGlobalConfig accepted negative max stream limit")
	}
	maxStreamsPerClient = 0
	cfg.ReconnectJitter = -time.Nanosecond
	if err := validateGlobalConfig(); err == nil {
		t.Fatal("validateGlobalConfig accepted negative jitter")
	}
	cfg.ReconnectJitter = 0
	cfg.ReconnectMaxDelay = 500 * time.Millisecond
	if err := validateGlobalConfig(); err == nil {
		t.Fatal("validateGlobalConfig accepted max delay below initial delay")
	}
	cfg.ReconnectMaxDelay = time.Second
	cfg.DialTimeout = 0
	if err := validateGlobalConfig(); err == nil {
		t.Fatal("validateGlobalConfig accepted zero dial timeout")
	}
}

func TestParseUDPBlockPorts(t *testing.T) {
	ports, err := parseUDPBlockPorts("443, 8443,443")
	if err != nil {
		t.Fatalf("parseUDPBlockPorts returned error: %v", err)
	}
	for _, port := range []int{443, 8443} {
		if _, ok := ports[port]; !ok {
			t.Fatalf("parseUDPBlockPorts missing port %d", port)
		}
	}
	if len(ports) != 2 {
		t.Fatalf("parseUDPBlockPorts size = %d, want 2", len(ports))
	}

	ports, err = parseUDPBlockPorts("")
	if err != nil {
		t.Fatalf("parseUDPBlockPorts empty returned error: %v", err)
	}
	if ports != nil {
		t.Fatalf("parseUDPBlockPorts empty = %#v, want nil", ports)
	}
}

func TestParseUDPBlockPortsRejectsInvalid(t *testing.T) {
	for _, raw := range []string{"0", "65536", "abc", "443abc", "53, bad"} {
		if _, err := parseUDPBlockPorts(raw); err == nil {
			t.Fatalf("parseUDPBlockPorts(%q) accepted invalid input", raw)
		}
	}
}

func TestBuildDNSQueryValidatesDomain(t *testing.T) {
	query, err := buildDNSQuery("Example.COM.", typeHTTPS)
	if err != nil {
		t.Fatalf("buildDNSQuery returned error: %v", err)
	}
	wantQuestion := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
		byte(typeHTTPS >> 8), byte(typeHTTPS), 0, 1,
	}
	if !bytes.Equal(query[12:], wantQuestion) {
		t.Fatalf("DNS question = %v, want %v", query[12:], wantQuestion)
	}

	invalid := []string{
		"",
		".",
		"example..com",
		"bad host.example",
		"-bad.example",
		"bad-.example",
		"bad_underscore.example",
		"例.example",
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("a", 250) + ".com",
	}
	for _, domain := range invalid {
		if _, err := buildDNSQuery(domain, typeHTTPS); err == nil {
			t.Fatalf("buildDNSQuery(%q) accepted invalid domain", domain)
		}
	}
}

func TestQueryDoHRejectsOversizedResponse(t *testing.T) {
	oldCfg := cfg
	defer func() { cfg = oldCfg }()
	cfg.DNSQueryTimeout = time.Second

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(bytes.Repeat([]byte{0}, maxDNSMessageSize+1))
	}))
	defer server.Close()

	if _, err := queryDoH("example.com", server.URL); err == nil || !strings.Contains(err.Error(), "DNS 响应过大") {
		t.Fatalf("queryDoH oversized response err = %v", err)
	}
}

func TestClientSessionStreamLimitAccounting(t *testing.T) {
	oldMaxStreams := maxStreamsPerClient
	defer func() {
		maxStreamsPerClient = oldMaxStreams
	}()
	session := &ClientSession{clientID: "test-client", channels: make(map[uint64]*WSChannel)}

	maxStreamsPerClient = 2
	if active, ok := session.tryAcquireStream(); !ok || active != 1 {
		t.Fatalf("first acquire = active %d ok %v, want active 1 ok true", active, ok)
	}
	if active, ok := session.tryAcquireStream(); !ok || active != 2 {
		t.Fatalf("second acquire = active %d ok %v, want active 2 ok true", active, ok)
	}
	if active, ok := session.tryAcquireStream(); ok || active != 2 {
		t.Fatalf("third acquire = active %d ok %v, want active 2 ok false", active, ok)
	}
	if got := session.activeStreamCount(); got != 2 {
		t.Fatalf("activeStreamCount = %d, want 2", got)
	}
	session.releaseStream()
	if got := session.activeStreamCount(); got != 1 {
		t.Fatalf("activeStreamCount after release = %d, want 1", got)
	}
	if active, ok := session.tryAcquireStream(); !ok || active != 2 {
		t.Fatalf("acquire after release = active %d ok %v, want active 2 ok true", active, ok)
	}

	maxStreamsPerClient = 0
	if _, ok := session.tryAcquireStream(); !ok {
		t.Fatal("unlimited maxStreamsPerClient rejected a stream")
	}
}

func TestClientSessionLimitAllowsExistingClient(t *testing.T) {
	oldMaxClients := maxClientSessions
	defer func() {
		maxClientSessions = oldMaxClients
		serverSessionsMu.Lock()
		serverSessions.Range(func(key, _ any) bool {
			serverSessions.Delete(key)
			return true
		})
		serverSessionsMu.Unlock()
	}()
	serverSessionsMu.Lock()
	serverSessions.Range(func(key, _ any) bool {
		serverSessions.Delete(key)
		return true
	})
	serverSessionsMu.Unlock()

	maxClientSessions = 1
	first, ok := getOrCreateClientSession("client-a")
	if !ok || first == nil {
		t.Fatalf("first client session = %v ok %v, want non-nil ok true", first, ok)
	}
	again, ok := getOrCreateClientSession("client-a")
	if !ok || again != first {
		t.Fatalf("existing client session = %v ok %v, want original ok true", again, ok)
	}
	if second, ok := getOrCreateClientSession("client-b"); ok || second != nil {
		t.Fatalf("second client session = %v ok %v, want nil ok false", second, ok)
	}

	serverSessionsMu.Lock()
	serverSessions.Delete("client-a")
	serverSessionsMu.Unlock()
	second, ok := getOrCreateClientSession("client-b")
	if !ok || second == nil {
		t.Fatalf("second client after release = %v ok %v, want non-nil ok true", second, ok)
	}
}

func TestValidateMTLSConfig(t *testing.T) {
	oldCert, oldKey := certFile, keyFile
	oldClientCA, oldClientCert, oldClientKey := clientCAFile, clientCertFile, clientKeyFile
	defer func() {
		certFile, keyFile = oldCert, oldKey
		clientCAFile, clientCertFile, clientKeyFile = oldClientCA, oldClientCert, oldClientKey
	}()

	certFile, keyFile = "", ""
	clientCAFile, clientCertFile, clientKeyFile = "ca.pem", "", ""
	if err := validateMTLSConfig(true, "ws"); err == nil {
		t.Fatal("validateMTLSConfig allowed client CA on ws server")
	}

	if err := validateMTLSConfig(true, "wss"); err != nil {
		t.Fatalf("validateMTLSConfig rejected client CA on wss server: %v", err)
	}

	clientCAFile = ""
	certFile, keyFile = "server.pem", "server-key.pem"
	if err := validateMTLSConfig(false, ""); err == nil {
		t.Fatal("validateMTLSConfig allowed server cert/key in client mode")
	}

	certFile, keyFile = "", ""
	clientCertFile, clientKeyFile = "client.pem", ""
	if err := validateMTLSConfig(false, ""); err == nil {
		t.Fatal("validateMTLSConfig allowed incomplete client cert/key pair")
	}

	clientCertFile, clientKeyFile = "client.pem", "client-key.pem"
	if err := validateMTLSConfig(false, ""); err != nil {
		t.Fatalf("validateMTLSConfig rejected complete client cert/key pair: %v", err)
	}

	clientCAFile = "ca.pem"
	if err := validateMTLSConfig(false, ""); err == nil {
		t.Fatal("validateMTLSConfig allowed client CA in client mode")
	}
}

func TestLoadConfigFileRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"unknown": true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err == nil {
		t.Fatal("loadConfigFile accepted unknown field")
	}
}

func TestLoadConfigFileRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"listen":"ws://127.0.0.1:18080/tunnel"} {}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err == nil {
		t.Fatal("loadConfigFile accepted trailing JSON value")
	}
}

func TestLoadConfigFileRejectsDuplicateTargetAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"allow_target":"10.0.0.0/8","allow-target":"10.0.1.0/24"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err == nil {
		t.Fatal("loadConfigFile accepted duplicate allow target aliases")
	}
}

func TestLoadConfigFileRejectsDuplicateHostAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"allow_host":"api.example.com","allow-host":"www.example.com"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err == nil {
		t.Fatal("loadConfigFile accepted duplicate allow host aliases")
	}
}

func TestLoadConfigFileRejectsDuplicateMaxStreamAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"max_streams":8,"max-streams":16}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err == nil {
		t.Fatal("loadConfigFile accepted duplicate max stream aliases")
	}
}

func TestLoadConfigFileRejectsDuplicateMaxClientAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"max_clients":8,"max-clients":16}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err == nil {
		t.Fatal("loadConfigFile accepted duplicate max client aliases")
	}
}

func TestLoadConfigFileRejectsDuplicateClientAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"client_ca":"ca.pem","client-ca":"other-ca.pem"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err == nil {
		t.Fatal("loadConfigFile accepted duplicate client CA aliases")
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
		"WS://127.0.0.1:18080/tunnel",
		"wss://:18443/tunnel",
		"socks5://user:pass@127.0.0.1:11080",
		"http://user:pass@127.0.0.1:18080",
		"http://127.0.0.1:18080",
		"tcp://127.0.0.1:12000/127.0.0.1:19090",
		"TCP://127.0.0.1:12000/127.0.0.1:19090",
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
		"socks5://user@127.0.0.1:11080",
		"http://user:@127.0.0.1:18080",
		"http://:pass@127.0.0.1:18080",
		"tcp://127.0.0.1:12000",
		"tcp://127.0.0.1:12000/",
	}
	for _, rule := range invalid {
		if err := validateListenRule(rule); err == nil {
			t.Fatalf("validateListenRule(%q) accepted invalid rule", rule)
		}
	}
}

func TestParseTCPForwardRule(t *testing.T) {
	listen, target, err := parseTCPForwardRule("tcp://127.0.0.1:12000/127.0.0.1:19090")
	if err != nil {
		t.Fatalf("parseTCPForwardRule returned error: %v", err)
	}
	if listen != "127.0.0.1:12000" || target != "127.0.0.1:19090" {
		t.Fatalf("parseTCPForwardRule = listen %q target %q", listen, target)
	}
	for _, rule := range []string{
		"udp://127.0.0.1:12000/127.0.0.1:19090",
		"tcp://127.0.0.1:12000",
		"tcp://127.0.0.1:12000/",
		"tcp://127.0.0.1:12000/127.0.0.1:19090/extra",
	} {
		if _, _, err := parseTCPForwardRule(rule); err == nil {
			t.Fatalf("parseTCPForwardRule(%q) accepted invalid rule", rule)
		}
	}
}

func TestClassifyListeners(t *testing.T) {
	listeners, isServer, serverListen, serverScheme, err := classifyListeners("TCP://127.0.0.1:12000/127.0.0.1:19090,SOCKS5://127.0.0.1:11080")
	if err != nil {
		t.Fatalf("classifyListeners client returned error: %v", err)
	}
	if isServer || serverListen != "" || serverScheme != "" {
		t.Fatalf("classifyListeners client server fields = %v %q %q", isServer, serverListen, serverScheme)
	}
	if len(listeners) != 2 || listeners[0].Scheme != "tcp" || !strings.HasPrefix(listeners[0].Raw, "tcp://") || listeners[1].Scheme != "socks5" {
		t.Fatalf("classifyListeners client listeners = %#v", listeners)
	}

	listeners, isServer, serverListen, serverScheme, err = classifyListeners("WSS://0.0.0.0:443/tunnel")
	if err != nil {
		t.Fatalf("classifyListeners server returned error: %v", err)
	}
	if !isServer || serverScheme != "wss" || serverListen != "wss://0.0.0.0:443/tunnel" || len(listeners) != 1 {
		t.Fatalf("classifyListeners server = listeners %#v isServer %v listen %q scheme %q", listeners, isServer, serverListen, serverScheme)
	}

	if _, _, _, _, err := classifyListeners("ws://127.0.0.1:18080/tunnel,socks5://127.0.0.1:11080"); err == nil {
		t.Fatal("classifyListeners accepted mixed server/client listeners")
	}
	if _, _, _, _, err := classifyListeners("ws://127.0.0.1:18080/tunnel,wss://127.0.0.1:18443/tunnel"); err == nil {
		t.Fatal("classifyListeners accepted multiple server listeners")
	}
	if _, _, _, _, err := classifyListeners(""); err == nil {
		t.Fatal("classifyListeners accepted empty listener list")
	}
}

func TestValidateClientStartupConfig(t *testing.T) {
	cfg, err := validateClientStartupConfig("wss://example.com/tunnel", 2, "client.pem", "client-key.pem", true, false, "443,8443")
	if err != nil {
		t.Fatalf("validateClientStartupConfig returned error: %v", err)
	}
	if cfg.ForwardScheme != "wss" || !cfg.Fallback || !cfg.AutoFallback {
		t.Fatalf("validateClientStartupConfig fallback fields = %#v", cfg)
	}
	if _, ok := cfg.UDPBlockPorts[8443]; !ok {
		t.Fatalf("validateClientStartupConfig ports = %#v", cfg.UDPBlockPorts)
	}

	invalid := []struct {
		name    string
		forward string
		n       int
		cert    string
		key     string
		block   string
	}{
		{name: "missing forward", forward: "", n: 1},
		{name: "bad scheme", forward: "http://example.com/tunnel", n: 1},
		{name: "missing host", forward: "ws:///tunnel", n: 1},
		{name: "zero connections", forward: "ws://example.com/tunnel", n: 0},
		{name: "client cert on ws", forward: "ws://example.com/tunnel", n: 1, cert: "client.pem", key: "client-key.pem"},
		{name: "bad block", forward: "ws://example.com/tunnel", n: 1, block: "443abc"},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := validateClientStartupConfig(tt.forward, tt.n, tt.cert, tt.key, false, false, tt.block); err == nil {
				t.Fatal("validateClientStartupConfig accepted invalid input")
			}
		})
	}
}

func TestParseSourceCIDRs(t *testing.T) {
	nets, err := parseSourceCIDRs("127.0.0.0/8, ::1/128")
	if err != nil {
		t.Fatalf("parseSourceCIDRs returned error: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("parseSourceCIDRs returned %d networks, want 2", len(nets))
	}
	for _, raw := range []string{"", "127.0.0.0/8,", "not-a-cidr"} {
		if _, err := parseSourceCIDRs(raw); err == nil {
			t.Fatalf("parseSourceCIDRs(%q) accepted invalid source filter", raw)
		}
	}
}

func validTestGlobalConfig() GlobalConfig {
	return GlobalConfig{
		DialTimeout:        time.Second,
		WSHandshakeTimeout: time.Second,
		ReconnectDelay:     time.Second,
		ReconnectMaxDelay:  time.Second,
		ReconnectJitter:    0,
		RTTProbeTimeout:    time.Second,
		DNSQueryTimeout:    time.Second,
		ECHRetryDelay:      time.Second,
		UDPReadTimeout:     time.Second,
		ShutdownTimeout:    time.Second,
		ReadBuf:            64 * 1024,
	}
}

func withValidStartupGlobals(t *testing.T) func() {
	t.Helper()
	oldCfg := cfg
	oldListen, oldForward, oldIP, oldBlock := listenAddr, forwardAddr, ipAddr, udpBlockPortsStr
	oldCert, oldKey := certFile, keyFile
	oldClientCA, oldClientCert, oldClientKey := clientCAFile, clientCertFile, clientKeyFile
	oldToken, oldMetrics := token, metricsAddr
	oldCIDR := cidrs
	oldAllow, oldDeny := targetAllowCIDRs, targetDenyCIDRs
	oldAllowHosts, oldDenyHosts := targetAllowHosts, targetDenyHosts
	oldMaxClients, oldMaxStreams := maxClientSessions, maxStreamsPerClient
	oldConnections, oldInsecure, oldFallback := connectionNum, insecure, fallback
	oldIPS := ips

	cfg = validTestGlobalConfig()
	listenAddr = "socks5://127.0.0.1:11080"
	forwardAddr = "ws://127.0.0.1:18080/tunnel"
	ipAddr, udpBlockPortsStr = "", ""
	certFile, keyFile = "", ""
	clientCAFile, clientCertFile, clientKeyFile = "", "", ""
	token, metricsAddr = "local-test-token", ""
	cidrs = "0.0.0.0/0,::/0"
	targetAllowCIDRs, targetDenyCIDRs = "", ""
	targetAllowHosts, targetDenyHosts = "", ""
	maxClientSessions, maxStreamsPerClient = 0, 0
	connectionNum, insecure, fallback = 1, false, false
	ips = ""

	return func() {
		cfg = oldCfg
		listenAddr, forwardAddr, ipAddr, udpBlockPortsStr = oldListen, oldForward, oldIP, oldBlock
		certFile, keyFile = oldCert, oldKey
		clientCAFile, clientCertFile, clientKeyFile = oldClientCA, oldClientCert, oldClientKey
		token, metricsAddr = oldToken, oldMetrics
		cidrs = oldCIDR
		targetAllowCIDRs, targetDenyCIDRs = oldAllow, oldDeny
		targetAllowHosts, targetDenyHosts = oldAllowHosts, oldDenyHosts
		maxClientSessions, maxStreamsPerClient = oldMaxClients, oldMaxStreams
		connectionNum, insecure, fallback = oldConnections, oldInsecure, oldFallback
		ips = oldIPS
	}
}

func TestValidateServerStartupConfig(t *testing.T) {
	policy, socksConfig, err := validateServerStartupConfig("socks5://user:pass@127.0.0.1:1080", "10.0.0.0/8", "", "api.example.com", "")
	if err != nil {
		t.Fatalf("validateServerStartupConfig returned error: %v", err)
	}
	if policy == nil || socksConfig == nil || socksConfig.Host != "127.0.0.1:1080" || socksConfig.Username != "user" {
		t.Fatalf("validateServerStartupConfig policy=%#v socks=%#v", policy, socksConfig)
	}
	if _, _, err := validateServerStartupConfig("socks5://127.0.0.1", "", "", "", ""); err == nil {
		t.Fatal("validateServerStartupConfig accepted SOCKS5 proxy without port")
	}
}

func TestValidateStartupConfigValidModes(t *testing.T) {
	restore := withValidStartupGlobals(t)
	defer restore()

	ips = "6,4"
	startup, err := validateStartupConfig()
	if err != nil {
		t.Fatalf("validateStartupConfig client returned error: %v", err)
	}
	if startup.IsServer || startup.Client.ForwardScheme != "ws" || len(startup.Listeners) != 1 || startup.IPStrategy != IPStrategyPv6Pv4 {
		t.Fatalf("validateStartupConfig client = %#v", startup)
	}

	listenAddr = "ws://127.0.0.1:18080/tunnel"
	forwardAddr = ""
	targetAllowCIDRs = "127.0.0.0/8"
	startup, err = validateStartupConfig()
	if err != nil {
		t.Fatalf("validateStartupConfig server returned error: %v", err)
	}
	if !startup.IsServer || startup.ServerScheme != "ws" || startup.TargetPolicy == nil || len(startup.SourceCIDRs) == 0 {
		t.Fatalf("validateStartupConfig server = %#v", startup)
	}
}

func TestValidateStartupConfigRejectsCommonErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func()
	}{
		{name: "bad metrics", setup: func() { metricsAddr = "127.0.0.1" }},
		{name: "bad ip override", setup: func() { ipAddr = "example.com" }},
		{name: "bad ip strategy", setup: func() { ips = "4,4" }},
		{name: "missing client forward", setup: func() { forwardAddr = "" }},
		{name: "bad forward scheme", setup: func() { forwardAddr = "http://127.0.0.1:18080/tunnel" }},
		{name: "bad source cidr", setup: func() {
			listenAddr = "ws://127.0.0.1:18080/tunnel"
			forwardAddr = ""
			cidrs = "not-a-cidr"
		}},
		{name: "client cert on ws", setup: func() {
			clientCertFile = "client.pem"
			clientKeyFile = "client-key.pem"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := withValidStartupGlobals(t)
			defer restore()
			tt.setup()
			if _, err := validateStartupConfig(); err == nil {
				t.Fatal("validateStartupConfig accepted invalid startup config")
			}
		})
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
	policy, err := parseTargetPolicy("10.0.0.0/8,2001:db8::/32", "10.0.9.0/24", "", "")
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
	policy, err := parseTargetPolicy("", "127.0.0.0/8", "", "")
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
	if _, err := parseTargetPolicy("not-a-cidr", "", "", ""); err == nil {
		t.Fatal("parseTargetPolicy accepted invalid allow CIDR")
	}
	if _, err := parseTargetPolicy("", "not-a-cidr", "", ""); err == nil {
		t.Fatal("parseTargetPolicy accepted invalid deny CIDR")
	}
}

func TestTargetPolicyAllowsHosts(t *testing.T) {
	policy, err := parseTargetPolicy("", "", "api.example.com,*.svc.example.com", "bad.example.com,*.blocked.example.com")
	if err != nil {
		t.Fatalf("parseTargetPolicy returned error: %v", err)
	}
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{name: "exact", target: "api.example.com:443", want: true},
		{name: "trailing dot", target: "api.example.com.:443", want: true},
		{name: "case insensitive", target: "API.EXAMPLE.COM:443", want: true},
		{name: "wildcard subdomain", target: "a.svc.example.com:443", want: true},
		{name: "wildcard nested", target: "a.b.svc.example.com:443", want: true},
		{name: "wildcard excludes apex", target: "svc.example.com:443", want: false},
		{name: "wildcard does not overmatch suffix", target: "badsvc.example.com:443", want: false},
		{name: "deny host wins", target: "bad.example.com:443", want: false},
		{name: "deny wildcard wins", target: "api.blocked.example.com:443", want: false},
		{name: "ip denied by host allow policy", target: "127.0.0.1:443", want: false},
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

func TestTargetPolicyDenyHostOnlyAllowsOtherTargets(t *testing.T) {
	policy, err := parseTargetPolicy("", "", "", "blocked.example.com")
	if err != nil {
		t.Fatalf("parseTargetPolicy returned error: %v", err)
	}
	if ok, _ := policy.Allows("blocked.example.com:443"); ok {
		t.Fatal("deny-host policy allowed blocked host")
	}
	if ok, _ := policy.Allows("api.example.com:443"); !ok {
		t.Fatal("deny-host-only policy rejected unrelated host")
	}
	if ok, _ := policy.Allows("127.0.0.1:443"); !ok {
		t.Fatal("deny-host-only policy rejected IP target")
	}
}

func TestParseTargetPolicyRejectsInvalidHostPattern(t *testing.T) {
	if _, err := parseTargetPolicy("", "", "*example.com", ""); err == nil {
		t.Fatal("parseTargetPolicy accepted invalid wildcard host")
	}
	if _, err := parseTargetPolicy("", "", "127.0.0.1", ""); err == nil {
		t.Fatal("parseTargetPolicy accepted IP host pattern")
	}
	if _, err := parseTargetPolicy("", "", "api.example.com:443", ""); err == nil {
		t.Fatal("parseTargetPolicy accepted host pattern with port")
	}
	if _, err := parseTargetPolicy("", "", "bad host.example", ""); err == nil {
		t.Fatal("parseTargetPolicy accepted host pattern with whitespace")
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

func TestSocks5ConnectRejectsTruncatedBoundAddress(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	go func() {
		req := make([]byte, 10)
		_, _ = io.ReadFull(server, req)
		_, _ = server.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0})
		_ = server.Close()
	}()

	if err := socks5Connect(client, "127.0.0.1:80"); err == nil {
		t.Fatal("socks5Connect accepted truncated bound IPv4 response")
	}
}

func TestHandleSOCKS5UserPassAuthRejectsShortRequest(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	errCh := make(chan error, 1)
	go func() {
		errCh <- handleSOCKS5UserPassAuth(server, &ProxyConfig{Username: "user", Password: "pass"})
	}()

	_, _ = client.Write([]byte{0x01, 0x04, 'u'})
	_ = client.Close()
	if err := <-errCh; err == nil {
		t.Fatal("handleSOCKS5UserPassAuth accepted short auth request")
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

func TestParseAuthAndAddrRejectsIncompleteAuth(t *testing.T) {
	for _, in := range []string{"user@127.0.0.1:8080", "user:@127.0.0.1:8080", ":pass@127.0.0.1:8080", "user:pass@", ""} {
		if _, _, _, err := parseAuthAndAddr(in); err == nil {
			t.Fatalf("parseAuthAndAddr(%q) accepted invalid auth/listen address", in)
		}
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

func TestIsSupportedStreamKind(t *testing.T) {
	for _, kind := range []byte{streamKindTCP, streamKindUDP, streamKindPing, streamKindHello} {
		if !isSupportedStreamKind(kind) {
			t.Fatalf("isSupportedStreamKind(%d) = false, want true", kind)
		}
	}
	for _, kind := range []byte{0, 5, 255} {
		if isSupportedStreamKind(kind) {
			t.Fatalf("isSupportedStreamKind(%d) = true, want false", kind)
		}
	}
}

func TestHandleSmuxStreamRejectsUnsupportedKind(t *testing.T) {
	oldUnsupportedStreams := atomic.LoadUint64(&serverUnsupportedStreamSeq)
	defer atomic.StoreUint64(&serverUnsupportedStreamSeq, oldUnsupportedStreams)
	atomic.StoreUint64(&serverUnsupportedStreamSeq, 0)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	serverSession, err := smux.Server(serverConn, nil)
	if err != nil {
		t.Fatalf("smux server: %v", err)
	}
	defer serverSession.Close()
	clientSession, err := smux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("smux client: %v", err)
	}
	defer clientSession.Close()

	accepted := make(chan *smux.Stream, 1)
	acceptErr := make(chan error, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- stream
	}()

	clientStream, err := clientSession.OpenStream()
	if err != nil {
		t.Fatalf("open smux stream: %v", err)
	}
	defer clientStream.Close()
	if err := writeSmuxOpenHeader(clientStream, 99, IPStrategyDefault, "unsupported.example:443"); err != nil {
		t.Fatalf("write unsupported stream header: %v", err)
	}

	var serverStream *smux.Stream
	select {
	case serverStream = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept smux stream: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for accepted smux stream")
	}

	done := make(chan struct{})
	session := &ClientSession{clientID: "unsupported-kind-test", channels: make(map[uint64]*WSChannel)}
	go func() {
		defer close(done)
		handleSmuxStream(session, &WSChannel{id: 1, session: session}, serverStream)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for unsupported stream handler")
	}
	if got := atomic.LoadUint64(&serverUnsupportedStreamSeq); got != 1 {
		t.Fatalf("serverUnsupportedStreamSeq = %d, want 1", got)
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

func TestTCPOpenStatusRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeTCPOpenStatus(&buf, tcpOpenStatusError, "dial failed"); err != nil {
		t.Fatalf("writeTCPOpenStatus returned error: %v", err)
	}
	status, message, err := readTCPOpenStatus(&buf)
	if err != nil {
		t.Fatalf("readTCPOpenStatus returned error: %v", err)
	}
	if status != tcpOpenStatusError || message != "dial failed" {
		t.Fatalf("readTCPOpenStatus = status %d message %q", status, message)
	}
}

func TestTCPOpenStatusRejectsOversizedMessage(t *testing.T) {
	if err := writeTCPOpenStatus(io.Discard, tcpOpenStatusError, strings.Repeat("x", 65536)); err == nil {
		t.Fatal("writeTCPOpenStatus accepted oversized message")
	}
}

func TestReadTCPOpenStatusMalformed(t *testing.T) {
	if _, _, err := readTCPOpenStatus(bytes.NewReader([]byte{tcpOpenStatusOK})); err == nil {
		t.Fatal("readTCPOpenStatus accepted short frame")
	}
	raw := []byte{tcpOpenStatusError, 0, 5, 'x'}
	if _, _, err := readTCPOpenStatus(bytes.NewReader(raw)); err == nil {
		t.Fatal("readTCPOpenStatus accepted truncated message")
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

func FuzzReadSmuxOpenHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{streamKindTCP, IPStrategyDefault, 0, 0})
	f.Add([]byte{streamKindTCP, IPStrategyPv4Pv6, 0, 15, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', ':', '4', '4', '3'})
	f.Fuzz(func(t *testing.T, raw []byte) {
		kind, strategy, target, err := readSmuxOpenHeader(bytes.NewReader(raw))
		if err != nil {
			return
		}
		var buf bytes.Buffer
		if err := writeSmuxOpenHeader(&buf, kind, strategy, target); err != nil {
			t.Fatalf("writeSmuxOpenHeader after successful read returned error: %v", err)
		}
	})
}

func FuzzReadProtocolHello(f *testing.F) {
	f.Add([]byte{})
	var ok bytes.Buffer
	if err := writeProtocolHello(&ok, currentProtocolHello()); err != nil {
		f.Fatalf("seed protocol hello: %v", err)
	}
	f.Add(ok.Bytes())
	f.Add([]byte{'X', 'T', 'U', 'N', protocolVersion, protocolStatusOK, 0, 1, 0, 0, 0, 1, 'x'})
	f.Fuzz(func(t *testing.T, raw []byte) {
		hello, err := readProtocolHello(bytes.NewReader(raw))
		if err != nil {
			return
		}
		var buf bytes.Buffer
		if err := writeProtocolHello(&buf, hello); err != nil {
			t.Fatalf("writeProtocolHello after successful read returned error: %v", err)
		}
	})
}

func FuzzReadTCPOpenStatus(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{tcpOpenStatusOK, 0, 0})
	f.Add([]byte{tcpOpenStatusError, 0, 4, 'f', 'a', 'i', 'l'})
	f.Fuzz(func(t *testing.T, raw []byte) {
		status, message, err := readTCPOpenStatus(bytes.NewReader(raw))
		if err != nil {
			return
		}
		var buf bytes.Buffer
		if err := writeTCPOpenStatus(&buf, status, message); err != nil {
			t.Fatalf("writeTCPOpenStatus after successful read returned error: %v", err)
		}
	})
}

func FuzzReadChunk(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 5, 'h', 'e', 'l', 'l', 'o'})
	f.Fuzz(func(t *testing.T, raw []byte) {
		payload, err := readChunk(bytes.NewReader(raw))
		if err != nil {
			return
		}
		var buf bytes.Buffer
		if err := writeChunk(&buf, payload); err != nil {
			t.Fatalf("writeChunk after successful read returned error: %v", err)
		}
	})
}

func FuzzReadUDPReply(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 10, 0, 4, '1', '.', '2', '.', '3', '.', '4', ':', '5', '3', 'p', 'o', 'n', 'g'})
	f.Fuzz(func(t *testing.T, raw []byte) {
		addr, payload, err := readUDPReply(bytes.NewReader(raw))
		if err != nil {
			return
		}
		var buf bytes.Buffer
		if err := writeUDPReply(&buf, addr, payload); err != nil {
			t.Fatalf("writeUDPReply after successful read returned error: %v", err)
		}
	})
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

func TestExampleConfigFilesLoad(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("examples", "*.json"))
	if err != nil {
		t.Fatalf("glob examples: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no example config files found")
	}

	oldCfg := cfg
	oldListen, oldForward, oldToken := listenAddr, forwardAddr, token
	oldIP, oldBlock := ipAddr, udpBlockPortsStr
	oldCert, oldKey := certFile, keyFile
	oldClientCA, oldClientCert, oldClientKey := clientCAFile, clientCertFile, clientKeyFile
	oldMetrics, oldCIDR := metricsAddr, cidrs
	oldAllow, oldDeny := targetAllowCIDRs, targetDenyCIDRs
	oldAllowHosts, oldDenyHosts := targetAllowHosts, targetDenyHosts
	oldMaxClients, oldMaxStreams := maxClientSessions, maxStreamsPerClient
	oldDNS, oldECH, oldIPS := dnsServer, echDomain, ips
	oldConnections, oldInsecure, oldFallback := connectionNum, insecure, fallback
	defer func() {
		cfg = oldCfg
		listenAddr, forwardAddr, token = oldListen, oldForward, oldToken
		ipAddr, udpBlockPortsStr = oldIP, oldBlock
		certFile, keyFile = oldCert, oldKey
		clientCAFile, clientCertFile, clientKeyFile = oldClientCA, oldClientCert, oldClientKey
		metricsAddr, cidrs = oldMetrics, oldCIDR
		targetAllowCIDRs, targetDenyCIDRs = oldAllow, oldDeny
		targetAllowHosts, targetDenyHosts = oldAllowHosts, oldDenyHosts
		maxClientSessions, maxStreamsPerClient = oldMaxClients, oldMaxStreams
		dnsServer, echDomain, ips = oldDNS, oldECH, oldIPS
		connectionNum, insecure, fallback = oldConnections, oldInsecure, oldFallback
	}()

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg = oldCfg
			listenAddr, forwardAddr, token = "", "", ""
			ipAddr, udpBlockPortsStr = "", ""
			certFile, keyFile = "", ""
			clientCAFile, clientCertFile, clientKeyFile = "", "", ""
			metricsAddr, cidrs = "", "0.0.0.0/0,::/0"
			targetAllowCIDRs, targetDenyCIDRs = "", ""
			targetAllowHosts, targetDenyHosts = "", ""
			maxClientSessions, maxStreamsPerClient = 0, 0
			dnsServer, echDomain, ips = "https://doh.pub/dns-query", "cloudflare-ech.com", ""
			connectionNum, insecure, fallback = 3, false, false

			if err := loadConfigFile(path, map[string]bool{}); err != nil {
				t.Fatalf("loadConfigFile(%s) returned error: %v", path, err)
			}
			if listenAddr == "" {
				t.Fatalf("example %s did not set listen", path)
			}
			if _, err := validateStartupConfig(); err != nil {
				t.Fatalf("validateStartupConfig(%s): %v", path, err)
			}
		})
	}
}
