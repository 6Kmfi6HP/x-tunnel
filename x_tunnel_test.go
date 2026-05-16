package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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

func TestValidateIPStrategyValue(t *testing.T) {
	for _, strategy := range []byte{IPStrategyDefault, IPStrategyIPv4Only, IPStrategyIPv6Only, IPStrategyPv4Pv6, IPStrategyPv6Pv4} {
		if err := validateIPStrategyValue(strategy); err != nil {
			t.Fatalf("validateIPStrategyValue(%d) returned error: %v", strategy, err)
		}
	}
	for _, strategy := range []byte{5, 99, 255} {
		if err := validateIPStrategyValue(strategy); err == nil {
			t.Fatalf("validateIPStrategyValue(%d) accepted invalid strategy", strategy)
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
	oldUDPActive := atomic.LoadUint64(&udpAssociationActiveSeq)
	oldReconnects := atomic.LoadUint64(&clientReconnectSeq)
	oldSourceRejects := atomic.LoadUint64(&serverSourceRejectSeq)
	oldAuthRejects := atomic.LoadUint64(&serverAuthRejectSeq)
	oldClientRejects := atomic.LoadUint64(&serverClientRejectSeq)
	oldStreamRejects := atomic.LoadUint64(&serverStreamRejectSeq)
	oldTargetRejects := atomic.LoadUint64(&serverTargetRejectSeq)
	oldUnsupportedStreams := atomic.LoadUint64(&serverUnsupportedStreamSeq)
	oldServerProtocolOK := atomic.LoadUint64(&serverProtocolOKSeq)
	oldServerProtocolRejects := atomic.LoadUint64(&serverProtocolRejectSeq)
	oldServerProtocolFailures := atomic.LoadUint64(&serverProtocolFailureSeq)
	oldClientProtocolOK := atomic.LoadUint64(&clientProtocolOKSeq)
	oldClientProtocolLegacy := atomic.LoadUint64(&clientProtocolLegacySeq)
	oldClientProtocolFailures := atomic.LoadUint64(&clientProtocolFailureSeq)
	defer func() {
		atomic.StoreUint64(&serverStreamSeq, oldStreams)
		atomic.StoreUint64(&udpAssociationSeq, oldUDP)
		atomic.StoreUint64(&udpAssociationActiveSeq, oldUDPActive)
		atomic.StoreUint64(&clientReconnectSeq, oldReconnects)
		atomic.StoreUint64(&serverSourceRejectSeq, oldSourceRejects)
		atomic.StoreUint64(&serverAuthRejectSeq, oldAuthRejects)
		atomic.StoreUint64(&serverClientRejectSeq, oldClientRejects)
		atomic.StoreUint64(&serverStreamRejectSeq, oldStreamRejects)
		atomic.StoreUint64(&serverTargetRejectSeq, oldTargetRejects)
		atomic.StoreUint64(&serverUnsupportedStreamSeq, oldUnsupportedStreams)
		atomic.StoreUint64(&serverProtocolOKSeq, oldServerProtocolOK)
		atomic.StoreUint64(&serverProtocolRejectSeq, oldServerProtocolRejects)
		atomic.StoreUint64(&serverProtocolFailureSeq, oldServerProtocolFailures)
		atomic.StoreUint64(&clientProtocolOKSeq, oldClientProtocolOK)
		atomic.StoreUint64(&clientProtocolLegacySeq, oldClientProtocolLegacy)
		atomic.StoreUint64(&clientProtocolFailureSeq, oldClientProtocolFailures)
		serverSessions.Delete("metrics-test")
	}()
	atomic.StoreUint64(&serverStreamSeq, 7)
	atomic.StoreUint64(&udpAssociationSeq, 3)
	atomic.StoreUint64(&udpAssociationActiveSeq, 2)
	atomic.StoreUint64(&clientReconnectSeq, 2)
	atomic.StoreUint64(&serverSourceRejectSeq, 11)
	atomic.StoreUint64(&serverAuthRejectSeq, 13)
	atomic.StoreUint64(&serverClientRejectSeq, 17)
	atomic.StoreUint64(&serverStreamRejectSeq, 19)
	atomic.StoreUint64(&serverTargetRejectSeq, 23)
	atomic.StoreUint64(&serverUnsupportedStreamSeq, 29)
	atomic.StoreUint64(&serverProtocolOKSeq, 31)
	atomic.StoreUint64(&serverProtocolRejectSeq, 37)
	atomic.StoreUint64(&serverProtocolFailureSeq, 41)
	atomic.StoreUint64(&clientProtocolOKSeq, 43)
	atomic.StoreUint64(&clientProtocolLegacySeq, 47)
	atomic.StoreUint64(&clientProtocolFailureSeq, 53)
	serverSessions.Store("metrics-test", &ClientSession{
		clientID:      "metrics-test",
		channels:      map[uint64]*WSChannel{1: &WSChannel{id: 1}, 2: &WSChannel{id: 2}},
		activeStreams: 5,
	})

	var buf bytes.Buffer
	writeMetrics(&buf)
	got := buf.String()
	for _, want := range []string{
		"x_tunnel_server_streams_total 7",
		"x_tunnel_udp_associations_total 3",
		"x_tunnel_udp_associations_active 2",
		"x_tunnel_client_reconnects_total 2",
		"x_tunnel_server_source_rejections_total 11",
		"x_tunnel_server_auth_rejections_total 13",
		"x_tunnel_server_client_session_rejections_total 17",
		"x_tunnel_server_stream_rejections_total 19",
		"x_tunnel_server_target_rejections_total 23",
		"x_tunnel_server_unsupported_streams_total 29",
		"x_tunnel_server_protocol_negotiations_total 31",
		"x_tunnel_server_protocol_negotiation_rejections_total 37",
		"x_tunnel_server_protocol_negotiation_failures_total 41",
		"x_tunnel_client_protocol_negotiations_total 43",
		"x_tunnel_client_protocol_legacy_sessions_total 47",
		"x_tunnel_client_protocol_negotiation_failures_total 53",
		"x_tunnel_server_sessions 1",
		"x_tunnel_server_channels 2",
		"x_tunnel_server_active_streams 5",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, got)
		}
	}
}

func TestShutdownHTTPServerStopsRealServer(t *testing.T) {
	oldCfg := cfg
	t.Cleanup(func() { cfg = oldCfg })
	cfg.ShutdownTimeout = time.Second

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test http server: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})}
	shutdownDone := make(chan struct{})
	go func() {
		shutdownHTTPServer(ctx, server, cfg.ShutdownTimeout)
		close(shutdownDone)
	}()
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(ln)
	}()

	client := http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("GET before shutdown: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read response before shutdown: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("response body before shutdown = %q, want ok", body)
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("server.Serve returned %v, want ErrServerClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop after context cancellation")
	}
	select {
	case <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("shutdownHTTPServer did not return after context cancellation")
	}
}

func TestRunMetricsServerReturnsOnListenError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runMetricsServer(ctx, "127.0.0.1:notaport")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runMetricsServer did not return after listen error")
	}
	cancel()
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

func TestValidateECHLookupConfig(t *testing.T) {
	valid := []struct {
		domain string
		server string
	}{
		{domain: "cloudflare-ech.com", server: "https://doh.pub/dns-query"},
		{domain: "cloudflare-ech.com", server: "http://doh.pub:8053/dns-query"},
		{domain: "cloudflare-ech.com", server: "https://[2001:4860:4860::8888]/dns-query"},
		{domain: "example.com.", server: "8.8.8.8"},
		{domain: "example.com", server: "8.8.8.8:53"},
		{domain: "example.com", server: "[2001:4860:4860::8888]:53"},
	}
	for _, tt := range valid {
		if err := validateECHLookupConfig(tt.domain, tt.server); err != nil {
			t.Fatalf("validateECHLookupConfig(%q, %q) returned error: %v", tt.domain, tt.server, err)
		}
	}

	invalid := []struct {
		domain string
		server string
	}{
		{domain: "", server: "https://doh.pub/dns-query"},
		{domain: "bad host.example", server: "https://doh.pub/dns-query"},
		{domain: "example.com", server: ""},
		{domain: "example.com", server: "https:///dns-query"},
		{domain: "example.com", server: "https://user:pass@doh.pub/dns-query"},
		{domain: "example.com", server: "https://bad_host.example/dns-query"},
		{domain: "example.com", server: "https://doh.pub:0/dns-query"},
		{domain: "example.com", server: "https://2001:4860:4860::8888/dns-query"},
		{domain: "example.com", server: "ftp://dns.example.com"},
		{domain: "example.com", server: "8.8.8.8:0"},
		{domain: "example.com", server: "2001:4860:4860::8888"},
	}
	for _, tt := range invalid {
		if err := validateECHLookupConfig(tt.domain, tt.server); err == nil {
			t.Fatalf("validateECHLookupConfig(%q, %q) accepted invalid config", tt.domain, tt.server)
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

func TestParseDNSResponseRejectsInvalidStatus(t *testing.T) {
	seed, err := dnsHTTPSResponseSeed([]byte("ech"))
	if err != nil {
		t.Fatalf("build DNS response seed: %v", err)
	}

	queryLike := append([]byte(nil), seed...)
	queryLike[2] &^= 0x80
	if _, err := parseDNSResponse(queryLike); err == nil || !strings.Contains(err.Error(), "不是响应") {
		t.Fatalf("parseDNSResponse query-like err = %v", err)
	}

	nxdomain := append([]byte(nil), seed...)
	nxdomain[3] = nxdomain[3]&0xF0 | 3
	if _, err := parseDNSResponse(nxdomain); err == nil || !strings.Contains(err.Error(), "DNS 响应错误码") {
		t.Fatalf("parseDNSResponse rcode err = %v", err)
	}
}

func TestQueryDNSUDPReturnsECH(t *testing.T) {
	oldCfg := cfg
	defer func() { cfg = oldCfg }()
	cfg.DNSQueryTimeout = time.Second

	addr := startDNSUDPResponder(t, []byte("udp-ech"))
	got, err := queryDNSUDP("example.com", addr)
	if err != nil {
		t.Fatalf("queryDNSUDP returned error: %v", err)
	}
	if want := base64.StdEncoding.EncodeToString([]byte("udp-ech")); got != want {
		t.Fatalf("queryDNSUDP = %q, want %q", got, want)
	}
}

func TestQueryDNSUDPReadsLargeECHResponse(t *testing.T) {
	oldCfg := cfg
	defer func() { cfg = oldCfg }()
	cfg.DNSQueryTimeout = time.Second

	largeECH := bytes.Repeat([]byte("x"), 5000)
	addr := startDNSUDPResponder(t, largeECH)
	got, err := queryDNSUDP("example.com", addr)
	if err != nil {
		t.Fatalf("queryDNSUDP large ECH returned error: %v", err)
	}
	if want := base64.StdEncoding.EncodeToString(largeECH); got != want {
		t.Fatalf("queryDNSUDP large ECH length = %d, want %d", len(got), len(want))
	}
}

func TestQueryHTTPSRecordDispatchesTransports(t *testing.T) {
	oldCfg := cfg
	defer func() { cfg = oldCfg }()
	cfg.DNSQueryTimeout = time.Second

	udpAddr := startDNSUDPResponder(t, []byte("dispatch-udp"))
	got, err := queryHTTPSRecord("example.com", udpAddr)
	if err != nil {
		t.Fatalf("queryHTTPSRecord UDP returned error: %v", err)
	}
	if want := base64.StdEncoding.EncodeToString([]byte("dispatch-udp")); got != want {
		t.Fatalf("queryHTTPSRecord UDP = %q, want %q", got, want)
	}

	dohResponse, err := dnsHTTPSResponseSeed([]byte("dispatch-doh"))
	if err != nil {
		t.Fatalf("build DoH response seed: %v", err)
	}
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("dns") == "" {
			t.Error("DoH request missing dns query parameter")
		}
		if got := r.Header.Get("Accept"); got != "application/dns-message" {
			t.Errorf("DoH Accept header = %q, want application/dns-message", got)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohResponse)
	}))
	defer doh.Close()

	got, err = queryHTTPSRecord("example.com", doh.URL)
	if err != nil {
		t.Fatalf("queryHTTPSRecord DoH returned error: %v", err)
	}
	if want := base64.StdEncoding.EncodeToString([]byte("dispatch-doh")); got != want {
		t.Fatalf("queryHTTPSRecord DoH = %q, want %q", got, want)
	}
}

func startDNSUDPResponder(t *testing.T, ech []byte) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP DNS responder: %v", err)
	}
	response, err := dnsHTTPSResponseSeed(ech)
	if err != nil {
		t.Fatalf("build DNS response seed: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			done <- err
			return
		}
		if n == 0 {
			done <- errors.New("empty DNS query")
			return
		}
		_, err = conn.WriteToUDP(response, addr)
		done <- err
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("UDP DNS responder failed: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for UDP DNS responder")
		}
	})
	return conn.LocalAddr().String()
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
	unlimited := &ClientSession{}
	if active, ok := unlimited.tryAcquireStream(); !ok || active != 1 {
		t.Fatalf("unlimited acquire = active %d ok %v, want active 1 ok true", active, ok)
	}
	if got := unlimited.activeStreamCount(); got != 1 {
		t.Fatalf("unlimited activeStreamCount = %d, want 1", got)
	}
	unlimited.releaseStream()
	if got := unlimited.activeStreamCount(); got != 0 {
		t.Fatalf("unlimited activeStreamCount after release = %d, want 0", got)
	}
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

func newChannelTestWebSocket(t *testing.T) *websocket.Conn {
	t.Helper()
	client, server := newTestWSNetConnPair(t)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return server.ws
}

func TestClientSessionChannelLifecycle(t *testing.T) {
	serverSessionsMu.Lock()
	serverSessions.Delete("channel-lifecycle-test")
	serverSessionsMu.Unlock()

	session := &ClientSession{clientID: "channel-lifecycle-test", channels: make(map[uint64]*WSChannel)}
	serverSessions.Store(session.clientID, session)
	t.Cleanup(func() {
		serverSessionsMu.Lock()
		serverSessions.Delete(session.clientID)
		serverSessionsMu.Unlock()
	})

	first := session.addChannel(newChannelTestWebSocket(t), 0)
	if first.id != 1 {
		t.Fatalf("first channel id = %d, want 1", first.id)
	}
	preferred := session.addChannel(newChannelTestWebSocket(t), 7)
	if preferred.id != 7 {
		t.Fatalf("preferred channel id = %d, want 7", preferred.id)
	}

	oldPreferredConn := preferred.conn
	replacement := session.addChannel(newChannelTestWebSocket(t), 7)
	if replacement.id != 7 {
		t.Fatalf("replacement channel id = %d, want 7", replacement.id)
	}
	_ = oldPreferredConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := oldPreferredConn.NextReader(); err == nil {
		t.Fatal("replaced websocket remained readable, want closed")
	}

	stale := &WSChannel{id: replacement.id, conn: newChannelTestWebSocket(t), session: session}
	session.removeChannel(replacement.id, stale)
	if got := len(session.channels); got != 2 {
		t.Fatalf("channels after stale remove = %d, want 2", got)
	}

	session.removeChannel(first.id, first)
	if got := len(session.channels); got != 1 {
		t.Fatalf("channels after first remove = %d, want 1", got)
	}
	if _, ok := serverSessions.Load(session.clientID); !ok {
		t.Fatal("server session deleted before last channel was removed")
	}

	session.removeChannel(replacement.id, replacement)
	if got := len(session.channels); got != 0 {
		t.Fatalf("channels after final remove = %d, want 0", got)
	}
	if _, ok := serverSessions.Load(session.clientID); ok {
		t.Fatal("server session remained after final channel remove")
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

func TestLoadCertPoolFromFile(t *testing.T) {
	caPath, _, _ := writeClientMTLSFiles(t)
	pool, err := loadCertPoolFromFile(caPath)
	if err != nil {
		t.Fatalf("loadCertPoolFromFile returned error: %v", err)
	}
	if pool == nil || len(pool.Subjects()) == 0 {
		t.Fatal("loadCertPoolFromFile returned an empty cert pool")
	}

	invalidPath := filepath.Join(t.TempDir(), "invalid-ca.pem")
	if err := os.WriteFile(invalidPath, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("write invalid CA file: %v", err)
	}
	if _, err := loadCertPoolFromFile(invalidPath); err == nil {
		t.Fatal("loadCertPoolFromFile accepted invalid PEM")
	}
	if _, err := loadCertPoolFromFile(filepath.Join(t.TempDir(), "missing-ca.pem")); err == nil {
		t.Fatal("loadCertPoolFromFile accepted missing file")
	}
}

func TestApplyClientCertificate(t *testing.T) {
	preserveTLSGlobals(t)

	cfgTLS := &tls.Config{}
	if err := applyClientCertificate(cfgTLS); err != nil {
		t.Fatalf("applyClientCertificate no-op returned error: %v", err)
	}
	if len(cfgTLS.Certificates) != 0 {
		t.Fatalf("client certificates after no-op = %d, want 0", len(cfgTLS.Certificates))
	}

	_, certPath, keyPath := writeClientMTLSFiles(t)
	clientCertFile, clientKeyFile = certPath, ""
	if err := applyClientCertificate(cfgTLS); err == nil {
		t.Fatal("applyClientCertificate accepted incomplete cert/key pair")
	}

	clientCertFile, clientKeyFile = certPath, keyPath
	if err := applyClientCertificate(cfgTLS); err != nil {
		t.Fatalf("applyClientCertificate returned error: %v", err)
	}
	if len(cfgTLS.Certificates) != 1 {
		t.Fatalf("client certificates = %d, want 1", len(cfgTLS.Certificates))
	}
	if len(cfgTLS.Certificates[0].Certificate) == 0 {
		t.Fatal("loaded client certificate has no certificate chain")
	}
}

func TestConfigureServerClientAuth(t *testing.T) {
	preserveTLSGlobals(t)

	cfgTLS := &tls.Config{}
	clientCAFile = ""
	if err := configureServerClientAuth(cfgTLS); err != nil {
		t.Fatalf("configureServerClientAuth no-op returned error: %v", err)
	}
	if cfgTLS.ClientAuth != tls.NoClientCert || cfgTLS.ClientCAs != nil {
		t.Fatalf("configureServerClientAuth no-op changed config: auth=%v CAs=%v", cfgTLS.ClientAuth, cfgTLS.ClientCAs)
	}

	caPath, _, _ := writeClientMTLSFiles(t)
	clientCAFile = caPath
	if err := configureServerClientAuth(cfgTLS); err != nil {
		t.Fatalf("configureServerClientAuth returned error: %v", err)
	}
	if cfgTLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", cfgTLS.ClientAuth)
	}
	if cfgTLS.ClientCAs == nil || len(cfgTLS.ClientCAs.Subjects()) == 0 {
		t.Fatal("configureServerClientAuth did not load client CAs")
	}

	clientCAFile = filepath.Join(t.TempDir(), "missing-ca.pem")
	if err := configureServerClientAuth(&tls.Config{}); err == nil {
		t.Fatal("configureServerClientAuth accepted missing CA file")
	}
}

func TestBuildStandardTLSConfig(t *testing.T) {
	preserveTLSGlobals(t)
	_, certPath, keyPath := writeClientMTLSFiles(t)
	clientCertFile, clientKeyFile = certPath, keyPath
	insecure = true

	cfgTLS, err := buildStandardTLSConfig("tls.example")
	if err != nil {
		t.Fatalf("buildStandardTLSConfig returned error: %v", err)
	}
	if cfgTLS.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", cfgTLS.MinVersion)
	}
	if cfgTLS.ServerName != "tls.example" {
		t.Fatalf("ServerName = %q, want tls.example", cfgTLS.ServerName)
	}
	if !cfgTLS.InsecureSkipVerify {
		t.Fatal("buildStandardTLSConfig did not preserve insecure=true")
	}
	if cfgTLS.RootCAs == nil {
		t.Fatal("buildStandardTLSConfig did not load system roots")
	}
	if len(cfgTLS.Certificates) != 1 {
		t.Fatalf("client certificates = %d, want 1", len(cfgTLS.Certificates))
	}
}

func TestBuildUnifiedTLSConfigBranches(t *testing.T) {
	preserveTLSGlobals(t)
	clientCertFile, clientKeyFile = "", ""
	insecure = true
	fallback = false
	setTestECHList(nil)
	if _, err := buildUnifiedTLSConfig("ech.example"); err == nil {
		t.Fatal("buildUnifiedTLSConfig accepted missing ECH config")
	}

	setTestECHList([]byte{0x01, 0x02, 0x03})
	cfgTLS, err := buildUnifiedTLSConfig("ech.example")
	if err != nil {
		t.Fatalf("buildUnifiedTLSConfig ECH branch returned error: %v", err)
	}
	if cfgTLS.ServerName != "ech.example" {
		t.Fatalf("ECH ServerName = %q, want ech.example", cfgTLS.ServerName)
	}
	if !bytes.Equal(cfgTLS.EncryptedClientHelloConfigList, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("ECH config list = %v, want [1 2 3]", cfgTLS.EncryptedClientHelloConfigList)
	}
	if !cfgTLS.InsecureSkipVerify {
		t.Fatal("buildUnifiedTLSConfig did not preserve insecure=true on ECH branch")
	}

	fallback = true
	setTestECHList(nil)
	cfgTLS, err = buildUnifiedTLSConfig("fallback.example")
	if err != nil {
		t.Fatalf("buildUnifiedTLSConfig fallback branch returned error: %v", err)
	}
	if cfgTLS.ServerName != "fallback.example" {
		t.Fatalf("fallback ServerName = %q, want fallback.example", cfgTLS.ServerName)
	}
	if len(cfgTLS.EncryptedClientHelloConfigList) != 0 {
		t.Fatalf("fallback ECH config list = %v, want empty", cfgTLS.EncryptedClientHelloConfigList)
	}
	if !cfgTLS.InsecureSkipVerify {
		t.Fatal("buildUnifiedTLSConfig did not preserve insecure=true on fallback branch")
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert returned error: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("generateSelfSignedCert returned no certificate chain")
	}
	if cert.PrivateKey == nil {
		t.Fatal("generateSelfSignedCert returned nil private key")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated certificate: %v", err)
	}
	if len(parsed.ExtKeyUsage) != 1 || parsed.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("ExtKeyUsage = %v, want server auth", parsed.ExtKeyUsage)
	}
	if time.Now().After(parsed.NotAfter) {
		t.Fatalf("generated certificate is expired: %v", parsed.NotAfter)
	}
}

func preserveTLSGlobals(t *testing.T) {
	t.Helper()
	oldClientCA, oldClientCert, oldClientKey := clientCAFile, clientCertFile, clientKeyFile
	oldInsecure, oldFallback := insecure, fallback
	echListMu.RLock()
	oldECHList := append([]byte(nil), echList...)
	echListMu.RUnlock()
	t.Cleanup(func() {
		clientCAFile, clientCertFile, clientKeyFile = oldClientCA, oldClientCert, oldClientKey
		insecure, fallback = oldInsecure, oldFallback
		setTestECHList(oldECHList)
	})
}

func setTestECHList(value []byte) {
	echListMu.Lock()
	defer echListMu.Unlock()
	echList = append([]byte(nil), value...)
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

func TestValidateHostPortRejectsWhitespace(t *testing.T) {
	if err := validateListenHostPort(":8080"); err != nil {
		t.Fatalf("validateListenHostPort accepted empty listen host before: %v", err)
	}
	if err := validateHostPort("Example.COM:443"); err != nil {
		t.Fatalf("validateHostPort rejected uppercase hostname: %v", err)
	}
	if err := validateHostPort("example.com.:443"); err != nil {
		t.Fatalf("validateHostPort rejected trailing-dot hostname: %v", err)
	}
	for _, value := range []string{"bad host:80", "example.com:80\t", "example.com:\n80"} {
		if err := validateHostPort(value); err == nil {
			t.Fatalf("validateHostPort(%q) accepted whitespace", value)
		}
		if err := validateListenHostPort(value); err == nil {
			t.Fatalf("validateListenHostPort(%q) accepted whitespace", value)
		}
	}
}

func TestValidateHostPortRejectsInvalidHostname(t *testing.T) {
	for _, value := range []string{"bad_host.example:80", "-bad.example:80", "bad-.example:80", ".example.com:80", "example..com:80"} {
		if err := validateHostPort(value); err == nil {
			t.Fatalf("validateHostPort(%q) accepted invalid hostname", value)
		}
	}
}

func TestValidateListenRule(t *testing.T) {
	longCredential := strings.Repeat("u", 256)
	valid := []string{
		"ws://127.0.0.1:18080/tunnel",
		"WS://127.0.0.1:18080/tunnel",
		"wss://:18443/tunnel",
		"socks5://user:pass@127.0.0.1:11080",
		"http://user:pass@127.0.0.1:18080",
		"http://" + longCredential + ":pass@127.0.0.1:18080",
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
		"socks5://" + longCredential + ":pass@127.0.0.1:11080",
		"http://user:@127.0.0.1:18080",
		"http://:pass@127.0.0.1:18080",
		"http://bad host:18080",
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
	oldDNS, oldECH := dnsServer, echDomain

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
	dnsServer, echDomain = "https://doh.pub/dns-query", "cloudflare-ech.com"

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
		dnsServer, echDomain = oldDNS, oldECH
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
	if _, _, err := validateServerStartupConfig("socks5://user@127.0.0.1:1080", "", "", "", ""); err == nil {
		t.Fatal("validateServerStartupConfig accepted incomplete SOCKS5 auth")
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
		{name: "bad ech dns config", setup: func() {
			forwardAddr = "wss://example.com/tunnel"
			fallback = false
			echDomain = "bad host.example"
		}},
		{name: "bad dns server config", setup: func() {
			forwardAddr = "wss://example.com/tunnel"
			fallback = false
			dnsServer = "ftp://dns.example.com"
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

func TestEnsureTargetAllowed(t *testing.T) {
	oldPolicy := targetPolicy
	t.Cleanup(func() {
		targetPolicy = oldPolicy
	})

	targetPolicy = nil
	if err := ensureTargetAllowed("192.0.2.1:443"); err != nil {
		t.Fatalf("ensureTargetAllowed with nil policy returned error: %v", err)
	}

	policy, err := parseTargetPolicy("10.0.0.0/8", "", "", "blocked.example.com")
	if err != nil {
		t.Fatalf("parseTargetPolicy returned error: %v", err)
	}
	targetPolicy = policy

	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{name: "allowed CIDR target", target: "10.1.2.3:443", wantErr: false},
		{name: "outside allow CIDR", target: "192.0.2.1:443", wantErr: true},
		{name: "denied host target", target: "blocked.example.com:443", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ensureTargetAllowed(tt.target)
			if tt.wantErr && err == nil {
				t.Fatalf("ensureTargetAllowed(%q) returned nil, want error", tt.target)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ensureTargetAllowed(%q) returned error: %v", tt.target, err)
			}
		})
	}
}

func newTestWSNetConnPair(t *testing.T) (*wsNetConn, *wsNetConn) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	serverConnCh := make(chan *websocket.Conn, 1)
	serverErrCh := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErrCh <- err
			return
		}
		serverConnCh <- conn
	}))
	t.Cleanup(server.Close)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	clientWS, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial test websocket: %v", err)
	}

	var serverWS *websocket.Conn
	select {
	case serverWS = <-serverConnCh:
	case err := <-serverErrCh:
		_ = clientWS.Close()
		t.Fatalf("upgrade test websocket: %v", err)
	case <-time.After(time.Second):
		_ = clientWS.Close()
		t.Fatal("timed out waiting for test websocket upgrade")
	}

	client := newWSNetConn(clientWS)
	serverConn := newWSNetConn(serverWS)
	t.Cleanup(func() {
		_ = client.Close()
		_ = serverConn.Close()
	})
	return client, serverConn
}

func TestHandleWebSocketChannelNegotiatesHelloAndCleansUp(t *testing.T) {
	oldCfg := cfg
	t.Cleanup(func() { cfg = oldCfg })
	cfg.RTTProbeTimeout = time.Second

	const clientID = "channel-hello-test"
	serverSessions.Delete(clientID)
	t.Cleanup(func() { serverSessions.Delete(clientID) })

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	ready := make(chan *WSChannel, 1)
	done := make(chan struct{})
	serverErr := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		session := &ClientSession{
			clientID: clientID,
			channels: make(map[uint64]*WSChannel),
		}
		serverSessions.Store(clientID, session)
		ch := session.addChannel(wsConn, 7)
		ready <- ch
		go func() {
			handleWebSocketChannel(ch)
			close(done)
		}()
	}))
	t.Cleanup(server.Close)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	clientWS, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial test websocket: %v", err)
	}
	clientConn := newWSNetConn(clientWS)

	var ch *WSChannel
	select {
	case ch = <-ready:
	case err := <-serverErr:
		_ = clientConn.Close()
		t.Fatalf("upgrade websocket: %v", err)
	case <-time.After(time.Second):
		_ = clientConn.Close()
		t.Fatal("timed out waiting for websocket channel")
	}

	clientSession, err := smux.Client(clientConn, nil)
	if err != nil {
		_ = clientConn.Close()
		t.Fatalf("create smux client: %v", err)
	}
	caps, legacy, err := negotiateClientProtocol(clientSession, time.Second)
	if err != nil {
		_ = clientSession.Close()
		_ = clientConn.Close()
		t.Fatalf("negotiate protocol over websocket channel: %v", err)
	}
	if legacy {
		t.Fatal("negotiateClientProtocol reported legacy mode")
	}
	if caps != currentProtocolCapabilities() {
		t.Fatalf("negotiated caps = 0x%x, want 0x%x", caps, currentProtocolCapabilities())
	}
	if got := atomic.LoadUint32(&ch.capabilities); got != currentProtocolCapabilities() {
		t.Fatalf("channel capabilities = 0x%x, want 0x%x", got, currentProtocolCapabilities())
	}

	_ = clientSession.Close()
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleWebSocketChannel did not return after client close")
	}
	ch.session.mu.RLock()
	channelCount := len(ch.session.channels)
	ch.session.mu.RUnlock()
	if channelCount != 0 {
		t.Fatalf("session has %d channels after cleanup, want 0", channelCount)
	}
	if _, ok := serverSessions.Load(clientID); ok {
		t.Fatal("serverSessions still contains closed test session")
	}
}

func TestDialWebSocketWithECHWSMetadata(t *testing.T) {
	oldCfg := cfg
	oldToken := token
	t.Cleanup(func() {
		cfg = oldCfg
		token = oldToken
	})
	cfg.WSHandshakeTimeout = time.Second
	cfg.DialTimeout = time.Second
	cfg.ReadBuf = 1024
	token = "ws-test-token"

	type dialRequest struct {
		clientID    string
		channelID   string
		subprotocol string
	}
	requests := make(chan dialRequest, 1)
	upgrader := websocket.Upgrader{
		CheckOrigin:  func(*http.Request) bool { return true },
		Subprotocols: []string{"ws-test-token"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		requests <- dialRequest{
			clientID:    r.URL.Query().Get("client_id"),
			channelID:   r.URL.Query().Get("channel_id"),
			subprotocol: conn.Subprotocol(),
		}
		_ = conn.Close()
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, err := dialWebSocketWithECH(wsURL, 1, "", "client-123", 7)
	if err != nil {
		t.Fatalf("dialWebSocketWithECH returned error: %v", err)
	}
	_ = conn.Close()

	select {
	case req := <-requests:
		if req.clientID != "client-123" || req.channelID != "7" || req.subprotocol != "ws-test-token" {
			t.Fatalf("dial metadata = %#v, want client_id client-123 channel_id 7 subprotocol ws-test-token", req)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for websocket dial metadata")
	}
}

func TestDialWebSocketWithECHMapsUnauthorized(t *testing.T) {
	oldCfg := cfg
	t.Cleanup(func() { cfg = oldCfg })
	cfg.WSHandshakeTimeout = time.Second
	cfg.DialTimeout = time.Second
	cfg.ReadBuf = 1024

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	if _, err := dialWebSocketWithECH(wsURL, 1, "", "", 0); err == nil || !strings.Contains(err.Error(), "认证失败") {
		t.Fatalf("dialWebSocketWithECH unauthorized err = %v", err)
	}
}

func TestDialWebSocketWithECHWSSFallbackInsecure(t *testing.T) {
	oldCfg := cfg
	oldToken := token
	oldFallback := fallback
	oldInsecure := insecure
	t.Cleanup(func() {
		cfg = oldCfg
		token = oldToken
		fallback = oldFallback
		insecure = oldInsecure
	})
	cfg.WSHandshakeTimeout = time.Second
	cfg.DialTimeout = time.Second
	cfg.ReadBuf = 1024
	token = "wss-test-token"
	fallback = true
	insecure = true

	type dialRequest struct {
		clientID    string
		channelID   string
		subprotocol string
	}
	requests := make(chan dialRequest, 1)
	upgrader := websocket.Upgrader{
		CheckOrigin:  func(*http.Request) bool { return true },
		Subprotocols: []string{"wss-test-token"},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade wss websocket: %v", err)
			return
		}
		requests <- dialRequest{
			clientID:    r.URL.Query().Get("client_id"),
			channelID:   r.URL.Query().Get("channel_id"),
			subprotocol: conn.Subprotocol(),
		}
		_ = conn.Close()
	}))
	defer server.Close()

	wssURL := "wss" + strings.TrimPrefix(server.URL, "https")
	conn, err := dialWebSocketWithECH(wssURL, 1, "", "client-wss", 11)
	if err != nil {
		t.Fatalf("dialWebSocketWithECH wss fallback returned error: %v", err)
	}
	_ = conn.Close()

	select {
	case req := <-requests:
		if req.clientID != "client-wss" || req.channelID != "11" || req.subprotocol != "wss-test-token" {
			t.Fatalf("wss dial metadata = %#v, want client_id client-wss channel_id 11 subprotocol wss-test-token", req)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for wss dial metadata")
	}
}

func TestWSNetConnReadWrite(t *testing.T) {
	client, server := newTestWSNetConnPair(t)
	deadline := time.Now().Add(time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	n, err := client.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("client Write returned error: %v", err)
	}
	if n != len("hello") {
		t.Fatalf("client Write n = %d, want %d", n, len("hello"))
	}
	first := make([]byte, 2)
	if n, err := io.ReadFull(server, first); err != nil || n != len(first) {
		t.Fatalf("server partial read = %d, %v", n, err)
	}
	if string(first) != "he" {
		t.Fatalf("server first read = %q, want he", first)
	}
	second := make([]byte, 3)
	if n, err := io.ReadFull(server, second); err != nil || n != len(second) {
		t.Fatalf("server second read = %d, %v", n, err)
	}
	if string(second) != "llo" {
		t.Fatalf("server second read = %q, want llo", second)
	}

	n, err = server.Write([]byte("world"))
	if err != nil {
		t.Fatalf("server Write returned error: %v", err)
	}
	if n != len("world") {
		t.Fatalf("server Write n = %d, want %d", n, len("world"))
	}
	reply := make([]byte, 5)
	if n, err := io.ReadFull(client, reply); err != nil || n != len(reply) {
		t.Fatalf("client read reply = %d, %v", n, err)
	}
	if string(reply) != "world" {
		t.Fatalf("client reply = %q, want world", reply)
	}
}

func TestWSNetConnAddressesDeadlinesAndClose(t *testing.T) {
	client, server := newTestWSNetConnPair(t)
	if client.LocalAddr() == nil || client.RemoteAddr() == nil {
		t.Fatalf("client addresses = local %v remote %v, want non-nil", client.LocalAddr(), client.RemoteAddr())
	}
	if server.LocalAddr() == nil || server.RemoteAddr() == nil {
		t.Fatalf("server addresses = local %v remote %v, want non-nil", server.LocalAddr(), server.RemoteAddr())
	}
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline returned error: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	if err := server.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline returned error: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	select {
	case <-client.Dead():
	case <-time.After(time.Second):
		t.Fatal("client Dead channel did not close")
	}
	if !errors.Is(client.DeadErr(), io.EOF) {
		t.Fatalf("client DeadErr = %v, want %v", client.DeadErr(), io.EOF)
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

func TestParseSOCKS5AddrRejectsIncompleteAuth(t *testing.T) {
	for _, in := range []string{
		"socks5://user@127.0.0.1:1080",
		"socks5://user:@127.0.0.1:1080",
		"socks5://:pass@127.0.0.1:1080",
		"socks5://user:pass@",
		"user@example.com:1080",
	} {
		if _, err := parseSOCKS5Addr(in); err == nil {
			t.Fatalf("parseSOCKS5Addr(%q) accepted incomplete auth", in)
		}
	}
}

func TestParseSOCKS5AddrRejectsOversizedAuth(t *testing.T) {
	longCredential := strings.Repeat("u", 256)
	for _, in := range []string{
		"socks5://" + longCredential + ":pass@127.0.0.1:1080",
		"socks5://user:" + longCredential + "@127.0.0.1:1080",
	} {
		if _, err := parseSOCKS5Addr(in); err == nil {
			t.Fatalf("parseSOCKS5Addr(%q) accepted oversized auth", in)
		}
	}
}

func TestDialViaSocks5AuthProxy(t *testing.T) {
	targetAddr := startOneShotTCPEcho(t)
	proxyAddr := startAuthSOCKS5TCPProxy(t, "user", "pass")

	oldConfig := socks5Config
	oldCfg := cfg
	t.Cleanup(func() {
		socks5Config = oldConfig
		cfg = oldCfg
	})
	cfg.DialTimeout = time.Second
	socks5Config = &SOCKS5Config{Host: proxyAddr, Username: "user", Password: "pass"}

	conn, err := dialViaSocks5("tcp", targetAddr)
	if err != nil {
		t.Fatalf("dialViaSocks5 returned error: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set dialViaSocks5 conn deadline: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write through dialViaSocks5 conn: %v", err)
	}
	reply := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read through dialViaSocks5 conn: %v", err)
	}
	if string(reply) != "echo:ping" {
		t.Fatalf("dialViaSocks5 reply = %q, want echo:ping", reply)
	}
}

func TestDialTCPWithStrategyLiteralIP(t *testing.T) {
	oldCfg := cfg
	t.Cleanup(func() { cfg = oldCfg })
	cfg.DialTimeout = time.Second

	targetAddr := startOneShotTCPEcho(t)
	conn, err := dialTCPWithStrategy(targetAddr, IPStrategyIPv6Only)
	if err != nil {
		t.Fatalf("dialTCPWithStrategy literal IPv4 returned error: %v", err)
	}
	assertTCPEcho(t, conn, "literal-ip")
}

func TestDialTCPWithStrategyLocalhostFamilies(t *testing.T) {
	oldCfg := cfg
	t.Cleanup(func() { cfg = oldCfg })
	cfg.DialTimeout = time.Second

	covered := false
	if localhostHasFamily(t, false) {
		v4Addr := startOneShotTCPEchoOn(t, "tcp4", "127.0.0.1:0")
		_, v4Port, err := net.SplitHostPort(v4Addr)
		if err != nil {
			t.Fatalf("split IPv4 listener address: %v", err)
		}
		conn, err := dialTCPWithStrategy(net.JoinHostPort("localhost", v4Port), IPStrategyIPv4Only)
		if err != nil {
			t.Fatalf("dialTCPWithStrategy IPv4-only localhost returned error: %v", err)
		}
		assertTCPEcho(t, conn, "localhost-v4")
		covered = true
	}

	if localhostHasFamily(t, true) {
		v6Ln, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Logf("IPv6 loopback listener unavailable: %v", err)
		} else {
			v6Addr := startOneShotTCPEchoWithListener(t, v6Ln)
			_, v6Port, err := net.SplitHostPort(v6Addr)
			if err != nil {
				t.Fatalf("split IPv6 listener address: %v", err)
			}
			conn, err := dialTCPWithStrategy(net.JoinHostPort("localhost", v6Port), IPStrategyIPv6Only)
			if err != nil {
				t.Fatalf("dialTCPWithStrategy IPv6-only localhost returned error: %v", err)
			}
			assertTCPEcho(t, conn, "localhost-v6")
			covered = true
		}
	}

	if !covered {
		t.Skip("localhost has no usable loopback TCP family")
	}
}

func TestDialTCPWithStrategyPreferredFamilies(t *testing.T) {
	oldCfg := cfg
	t.Cleanup(func() { cfg = oldCfg })
	cfg.DialTimeout = time.Second

	covered := false
	if localhostHasFamily(t, false) {
		v4Addr := startOneShotTCPEchoOn(t, "tcp4", "127.0.0.1:0")
		_, v4Port, err := net.SplitHostPort(v4Addr)
		if err != nil {
			t.Fatalf("split IPv4 listener address: %v", err)
		}
		conn, err := dialTCPWithStrategy(net.JoinHostPort("localhost", v4Port), IPStrategyPv4Pv6)
		if err != nil {
			t.Fatalf("dialTCPWithStrategy IPv4-preferred localhost returned error: %v", err)
		}
		assertTCPEcho(t, conn, "localhost-prefer-v4")
		covered = true
	}

	if localhostHasFamily(t, true) {
		v6Ln, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Logf("IPv6 loopback listener unavailable: %v", err)
		} else {
			v6Addr := startOneShotTCPEchoWithListener(t, v6Ln)
			_, v6Port, err := net.SplitHostPort(v6Addr)
			if err != nil {
				t.Fatalf("split IPv6 listener address: %v", err)
			}
			conn, err := dialTCPWithStrategy(net.JoinHostPort("localhost", v6Port), IPStrategyPv6Pv4)
			if err != nil {
				t.Fatalf("dialTCPWithStrategy IPv6-preferred localhost returned error: %v", err)
			}
			assertTCPEcho(t, conn, "localhost-prefer-v6")
			covered = true
		}
	}

	if !covered {
		t.Skip("localhost has no usable preferred TCP family")
	}
}

func localhostHasFamily(t *testing.T, ipv6 bool) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, "localhost")
	if err != nil {
		t.Skipf("localhost resolution unavailable: %v", err)
	}
	for _, ip := range ips {
		if ipv6 && ip.IP.To4() == nil && ip.IP.To16() != nil {
			return true
		}
		if !ipv6 && ip.IP.To4() != nil {
			return true
		}
	}
	return false
}

func startOneShotTCPEcho(t *testing.T) string {
	t.Helper()
	return startOneShotTCPEchoOn(t, "tcp", "127.0.0.1:0")
}

func startOneShotTCPEchoOn(t *testing.T, network, address string) string {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("listen TCP echo: %v", err)
	}
	return startOneShotTCPEchoWithListener(t, ln)
}

func startOneShotTCPEchoWithListener(t *testing.T, ln net.Listener) string {
	t.Helper()
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			done <- err
			return
		}
		_, err = conn.Write(append([]byte("echo:"), buf[:n]...))
		done <- err
	}()
	t.Cleanup(func() {
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("TCP echo failed: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("TCP echo did not finish")
		}
	})
	return ln.Addr().String()
}

func assertTCPEcho(t *testing.T, conn net.Conn, message string) {
	t.Helper()
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set TCP echo conn deadline: %v", err)
	}
	if _, err := conn.Write([]byte(message)); err != nil {
		t.Fatalf("write TCP echo payload: %v", err)
	}
	reply := make([]byte, len("echo:")+len(message))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read TCP echo reply: %v", err)
	}
	if string(reply) != "echo:"+message {
		t.Fatalf("TCP echo reply = %q, want %q", reply, "echo:"+message)
	}
}

func TestSocks5HandshakeWithAuthOffersOnlyUserPass(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	errCh := make(chan error, 1)
	go func() {
		errCh <- socks5Handshake(client, &SOCKS5Config{Username: "user", Password: "pass"})
	}()

	head := make([]byte, 2)
	if _, err := io.ReadFull(server, head); err != nil {
		t.Fatalf("read SOCKS5 greeting head: %v", err)
	}
	if !bytes.Equal(head, []byte{0x05, 0x01}) {
		t.Fatalf("SOCKS5 greeting head = %v, want [5 1]", head)
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(server, methods); err != nil {
		t.Fatalf("read SOCKS5 methods: %v", err)
	}
	if !bytes.Equal(methods, []byte{0x02}) {
		t.Fatalf("SOCKS5 methods = %v, want [2]", methods)
	}
	if _, err := server.Write([]byte{0x05, 0x02}); err != nil {
		t.Fatalf("write SOCKS5 method selection: %v", err)
	}
	if got := readSOCKS5AuthRequest(t, server); got != "user:pass" {
		t.Fatalf("SOCKS5 auth request = %q, want %q", got, "user:pass")
	}
	if _, err := server.Write([]byte{0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 auth response: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("socks5Handshake returned error: %v", err)
	}
}

func TestSocks5HandshakeRejectsUnofferedMethod(t *testing.T) {
	tests := []struct {
		name         string
		config       *SOCKS5Config
		serverMethod byte
	}{
		{name: "auth config rejects no auth", config: &SOCKS5Config{Username: "user", Password: "pass"}, serverMethod: 0x00},
		{name: "no auth config rejects userpass", config: &SOCKS5Config{}, serverMethod: 0x02},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			_ = server.SetDeadline(time.Now().Add(time.Second))
			_ = client.SetDeadline(time.Now().Add(time.Second))

			errCh := make(chan error, 1)
			go func() {
				errCh <- socks5Handshake(client, tt.config)
			}()
			head := make([]byte, 2)
			if _, err := io.ReadFull(server, head); err != nil {
				t.Fatalf("read SOCKS5 greeting head: %v", err)
			}
			methods := make([]byte, int(head[1]))
			if _, err := io.ReadFull(server, methods); err != nil {
				t.Fatalf("read SOCKS5 methods: %v", err)
			}
			if _, err := server.Write([]byte{0x05, tt.serverMethod}); err != nil {
				t.Fatalf("write SOCKS5 method selection: %v", err)
			}
			if err := <-errCh; err == nil {
				t.Fatalf("socks5Handshake accepted unoffered method 0x%02x after offering %v", tt.serverMethod, methods)
			}
		})
	}
}

func TestSocks5HandshakeHandlesProgressiveShortWrites(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	errCh := make(chan error, 1)
	go func() {
		errCh <- socks5Handshake(oneByteConn{Conn: client}, &SOCKS5Config{})
	}()

	head := make([]byte, 2)
	if _, err := io.ReadFull(server, head); err != nil {
		t.Fatalf("read SOCKS5 greeting head: %v", err)
	}
	if !bytes.Equal(head, []byte{0x05, 0x01}) {
		t.Fatalf("SOCKS5 greeting head = %v, want [5 1]", head)
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(server, methods); err != nil {
		t.Fatalf("read SOCKS5 methods: %v", err)
	}
	if !bytes.Equal(methods, []byte{0x00}) {
		t.Fatalf("SOCKS5 methods = %v, want [0]", methods)
	}
	if _, err := server.Write([]byte{0x05, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 method selection: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("socks5Handshake returned error: %v", err)
	}
}

func TestUpstreamSOCKS5WritersRejectShortWrites(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "method greeting",
			run: func() error {
				return socks5Handshake(shortWriteNoErrorConn{}, &SOCKS5Config{})
			},
		},
		{
			name: "userpass auth",
			run: func() error {
				return socks5UserPassAuthSrv(shortWriteNoErrorConn{}, "user", "pass")
			},
		},
		{
			name: "connect request",
			run: func() error {
				return socks5Connect(shortWriteNoErrorConn{}, "127.0.0.1:80")
			},
		},
		{
			name: "udp associate request",
			run: func() error {
				return writeSOCKS5UDPAssociate(shortWriteNoErrorWriter{})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err != io.ErrShortWrite {
				t.Fatalf("writer error = %v, want %v", err, io.ErrShortWrite)
			}
		})
	}
}

func readSOCKS5AuthRequest(t *testing.T, r io.Reader) string {
	t.Helper()
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		t.Fatalf("read SOCKS5 auth head: %v", err)
	}
	if head[0] != 0x01 {
		t.Fatalf("SOCKS5 auth version = %d, want 1", head[0])
	}
	username := make([]byte, int(head[1]))
	if _, err := io.ReadFull(r, username); err != nil {
		t.Fatalf("read SOCKS5 username: %v", err)
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(r, plen); err != nil {
		t.Fatalf("read SOCKS5 password length: %v", err)
	}
	password := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(r, password); err != nil {
		t.Fatalf("read SOCKS5 password: %v", err)
	}
	return string(username) + ":" + string(password)
}

func TestSocks5UserPassAuthSrvRejectsOversizedCredentials(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(100 * time.Millisecond))

	if err := socks5UserPassAuthSrv(client, strings.Repeat("u", 256), "pass"); err == nil {
		t.Fatal("socks5UserPassAuthSrv accepted oversized username")
	}
}

func TestSocks5UserPassAuthSrvRejectsInvalidResponseVersion(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	errCh := make(chan error, 1)
	go func() {
		errCh <- socks5UserPassAuthSrv(client, "user", "pass")
	}()

	if got := readSOCKS5AuthRequest(t, server); got != "user:pass" {
		t.Fatalf("SOCKS5 auth request = %q, want user:pass", got)
	}
	if _, err := server.Write([]byte{0x02, 0x00}); err != nil {
		t.Fatalf("write invalid auth response version: %v", err)
	}
	if err := <-errCh; err == nil {
		t.Fatal("socks5UserPassAuthSrv accepted invalid auth response version")
	}
}

func TestSocks5UserPassAuthSrvHandlesProgressiveShortWrites(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	errCh := make(chan error, 1)
	go func() {
		errCh <- socks5UserPassAuthSrv(oneByteConn{Conn: client}, "user", "pass")
	}()

	if got := readSOCKS5AuthRequest(t, server); got != "user:pass" {
		t.Fatalf("SOCKS5 auth request = %q, want user:pass", got)
	}
	if _, err := server.Write([]byte{0x01, 0x00}); err != nil {
		t.Fatalf("write auth response: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("socks5UserPassAuthSrv returned error: %v", err)
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

func TestSocks5ConnectRejectsInvalidResponseHeader(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
	}{
		{name: "bad version", response: []byte{0x04, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80}},
		{name: "bad rsv", response: []byte{0x05, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0, 80}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			_ = server.SetDeadline(time.Now().Add(time.Second))
			_ = client.SetDeadline(time.Now().Add(time.Second))

			go func() {
				req := make([]byte, 10)
				_, _ = io.ReadFull(server, req)
				_, _ = server.Write(tt.response)
			}()

			if err := socks5Connect(client, "127.0.0.1:80"); err == nil {
				t.Fatal("socks5Connect accepted invalid response header")
			}
		})
	}
}

func TestSocks5ConnectHandlesProgressiveShortWrites(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	errCh := make(chan error, 1)
	go func() {
		errCh <- socks5Connect(oneByteConn{Conn: client}, "127.0.0.1:80")
	}()

	req := make([]byte, 10)
	if _, err := io.ReadFull(server, req); err != nil {
		t.Fatalf("read SOCKS5 connect request: %v", err)
	}
	want := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80}
	if !bytes.Equal(req, want) {
		t.Fatalf("SOCKS5 connect request = %v, want %v", req, want)
	}
	if _, err := server.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatalf("write SOCKS5 connect response: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("socks5Connect returned error: %v", err)
	}
}

func TestSocks5ConnectRejectsInvalidTargetPort(t *testing.T) {
	tests := []string{
		":80",
		"bad host:80",
		"127.0.0.1:abc",
		"127.0.0.1:0",
		"127.0.0.1:65536",
		net.JoinHostPort(strings.Repeat("a", 256), "80"),
	}
	for _, target := range tests {
		t.Run(target, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(100 * time.Millisecond))
			if err := socks5Connect(client, target); err == nil {
				t.Fatalf("socks5Connect(%q) accepted invalid target", target)
			}
		})
	}
}

func TestNewSOCKS5UDPRelayRejectsInvalidAssociateResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     string
	}{
		{name: "bad version", response: []byte{0x04, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 53}, want: "版本"},
		{name: "bad rsv", response: []byte{0x05, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0, 53}, want: "RSV"},
		{name: "unknown address type", response: []byte{0x05, 0x00, 0x00, 0x09}, want: "地址类型无效"},
		{name: "zero relay port", response: []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}, want: "端口"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxyAddr, waitProxy := startSOCKS5UDPAssociateResponse(t, tt.response)
			oldConfig := socks5Config
			socks5Config = &SOCKS5Config{Host: proxyAddr}
			t.Cleanup(func() { socks5Config = oldConfig })

			relay, err := newSOCKS5UDPRelay("127.0.0.1:53")
			if relay != nil {
				_ = relay.Close()
			}
			if err == nil {
				t.Fatal("newSOCKS5UDPRelay accepted invalid UDP ASSOCIATE response")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("newSOCKS5UDPRelay error = %v, want %q", err, tt.want)
			}
			waitProxy()
		})
	}
}

func TestNewSOCKS5UDPRelayAcceptsIPv6AssociateRelay(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	response := []byte{0x05, 0x00, 0x00, 0x04}
	response = append(response, ip.To16()...)
	response = append(response, 0x14, 0xe9)
	proxyAddr, waitProxy := startSOCKS5UDPAssociateResponse(t, response)

	oldConfig := socks5Config
	socks5Config = &SOCKS5Config{Host: proxyAddr}
	t.Cleanup(func() { socks5Config = oldConfig })

	relay, err := newSOCKS5UDPRelay("127.0.0.1:53")
	if err != nil {
		t.Fatalf("newSOCKS5UDPRelay returned error: %v", err)
	}
	defer relay.Close()
	waitProxy()

	if relay.relayAddr == nil || !relay.relayAddr.IP.Equal(ip) || relay.relayAddr.Port != 5353 {
		t.Fatalf("relay addr = %#v, want [%s]:5353", relay.relayAddr, ip)
	}
}

func TestDirectUDPRelayerRoundTrip(t *testing.T) {
	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen target UDP: %v", err)
	}
	defer targetConn.Close()
	localConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen local UDP: %v", err)
	}

	relay := &DirectUDPRelayer{
		conn:   localConn,
		target: targetConn.LocalAddr().(*net.UDPAddr),
	}

	if n, err := relay.Write([]byte("ping")); err != nil || n != len("ping") {
		t.Fatalf("DirectUDPRelayer.Write = n %d err %v, want n %d nil", n, err, len("ping"))
	}

	buf := make([]byte, 64)
	if err := targetConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set target read deadline: %v", err)
	}
	n, clientAddr, err := targetConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("target read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("target payload = %q, want ping", buf[:n])
	}
	if _, err := targetConn.WriteToUDP([]byte("pong"), clientAddr); err != nil {
		t.Fatalf("target write response: %v", err)
	}
	if err := relay.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("DirectUDPRelayer.SetReadDeadline returned error: %v", err)
	}
	n, src, err := relay.Read(buf)
	if err != nil {
		t.Fatalf("DirectUDPRelayer.Read returned error: %v", err)
	}
	if src != targetConn.LocalAddr().String() || string(buf[:n]) != "pong" {
		t.Fatalf("DirectUDPRelayer.Read = src %q payload %q, want src %q payload pong", src, buf[:n], targetConn.LocalAddr().String())
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("DirectUDPRelayer.Close returned error: %v", err)
	}
}

func TestSOCKS5UDPRelayRoundTripAndClose(t *testing.T) {
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen SOCKS5 relay UDP: %v", err)
	}
	defer relayConn.Close()
	localConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen local UDP: %v", err)
	}
	tcpServer, tcpClient := net.Pipe()
	defer tcpClient.Close()

	targetAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5353}
	relay := &SOCKS5UDPRelay{
		tcpConn:    tcpServer,
		udpConn:    localConn,
		relayAddr:  relayConn.LocalAddr().(*net.UDPAddr),
		targetAddr: targetAddr,
	}

	if n, err := relay.Write([]byte("query")); err != nil || n <= len("query") {
		t.Fatalf("SOCKS5UDPRelay.Write = n %d err %v, want wrapped datagram write", n, err)
	}
	buf := make([]byte, 128)
	if err := relayConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set relay read deadline: %v", err)
	}
	n, _, err := relayConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("relay UDP read: %v", err)
	}
	target, payload, err := parseSOCKS5UDPPacket(buf[:n])
	if err != nil {
		t.Fatalf("parse SOCKS5 UDP relay write: %v", err)
	}
	if target != targetAddr.String() || string(payload) != "query" {
		t.Fatalf("SOCKS5UDPRelay.Write packet = target %q payload %q, want target %q payload query", target, payload, targetAddr.String())
	}

	response, err := buildSOCKS5UDPPacket("8.8.8.8", 53, []byte("response"))
	if err != nil {
		t.Fatalf("build SOCKS5 UDP response: %v", err)
	}
	if _, err := relayConn.WriteToUDP(response, localConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write SOCKS5 UDP response: %v", err)
	}
	if err := relay.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SOCKS5UDPRelay.SetReadDeadline returned error: %v", err)
	}
	n, src, err := relay.Read(buf)
	if err != nil {
		t.Fatalf("SOCKS5UDPRelay.Read returned error: %v", err)
	}
	if src != "8.8.8.8:53" || string(buf[:n]) != "response" {
		t.Fatalf("SOCKS5UDPRelay.Read = src %q payload %q, want src 8.8.8.8:53 payload response", src, buf[:n])
	}

	if err := relay.Close(); err != nil {
		t.Fatalf("SOCKS5UDPRelay.Close returned error: %v", err)
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("SOCKS5UDPRelay.Close second call returned error: %v", err)
	}
	if _, err := relay.Write([]byte("again")); err == nil {
		t.Fatal("SOCKS5UDPRelay.Write succeeded after Close")
	}
}

func TestSOCKS5UDPRelayReadRejectsOversizedPayload(t *testing.T) {
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen SOCKS5 relay UDP: %v", err)
	}
	defer relayConn.Close()
	localConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen local UDP: %v", err)
	}
	tcpServer, tcpClient := net.Pipe()
	defer tcpClient.Close()
	relay := &SOCKS5UDPRelay{
		tcpConn: tcpServer,
		udpConn: localConn,
	}
	defer relay.Close()

	response, err := buildSOCKS5UDPPacket("8.8.8.8", 53, []byte("too-large"))
	if err != nil {
		t.Fatalf("build SOCKS5 UDP response: %v", err)
	}
	if _, err := relayConn.WriteToUDP(response, localConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write SOCKS5 UDP response: %v", err)
	}
	if err := relay.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SOCKS5UDPRelay.SetReadDeadline returned error: %v", err)
	}
	buf := make([]byte, 3)
	n, src, err := relay.Read(buf)
	if err == nil {
		t.Fatal("SOCKS5UDPRelay.Read accepted oversized payload")
	}
	if n != 0 || src != "" {
		t.Fatalf("SOCKS5UDPRelay.Read = n %d src %q on oversized payload, want zero values", n, src)
	}
	if !strings.Contains(err.Error(), "exceeds buffer") {
		t.Fatalf("SOCKS5UDPRelay.Read error = %v, want exceeds buffer", err)
	}
}

func TestSOCKS5UDPRelayReadUnblocksOnClose(t *testing.T) {
	localConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen local UDP: %v", err)
	}
	tcpServer, tcpClient := net.Pipe()
	defer tcpClient.Close()
	relay := &SOCKS5UDPRelay{
		tcpConn: tcpServer,
		udpConn: localConn,
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, _, err := relay.Read(buf)
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	if err := relay.Close(); err != nil {
		t.Fatalf("SOCKS5UDPRelay.Close returned error: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("SOCKS5UDPRelay.Read returned nil after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS5UDPRelay.Read did not unblock after Close")
	}
}

func startSOCKS5UDPAssociateResponse(t *testing.T, response []byte) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen SOCKS5 UDP associate proxy: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))

		head := make([]byte, 2)
		if _, err := io.ReadFull(conn, head); err != nil {
			errCh <- err
			return
		}
		methods := make([]byte, int(head[1]))
		if _, err := io.ReadFull(conn, methods); err != nil {
			errCh <- err
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			errCh <- err
			return
		}
		req := make([]byte, 10)
		if _, err := io.ReadFull(conn, req); err != nil {
			errCh <- err
			return
		}
		_, err = conn.Write(response)
		errCh <- err
	}()
	return listener.Addr().String(), func() {
		t.Helper()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("SOCKS5 UDP associate proxy failed: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("SOCKS5 UDP associate proxy did not finish")
		}
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

func TestHandleSOCKS5UserPassAuthRejectsInvalidVersion(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	errCh := make(chan error, 1)
	go func() {
		errCh <- handleSOCKS5UserPassAuth(server, &ProxyConfig{Username: "user", Password: "pass"})
	}()

	if _, err := client.Write([]byte{0x02, 0x04}); err != nil {
		t.Fatalf("write invalid auth version: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if !bytes.Equal(resp, []byte{0x01, 0x01}) {
		t.Fatalf("SOCKS5 auth response = %v, want [1 1]", resp)
	}
	if err := <-errCh; err == nil {
		t.Fatal("handleSOCKS5UserPassAuth accepted invalid auth version")
	}
}

func TestReadLocalSOCKS5Request(t *testing.T) {
	tests := []struct {
		name       string
		raw        []byte
		command    byte
		atyp       byte
		wantTarget string
	}{
		{
			name:       "IPv4 connect",
			raw:        []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80},
			command:    0x01,
			atyp:       0x01,
			wantTarget: "127.0.0.1:80",
		},
		{
			name:       "domain UDP associate",
			raw:        append([]byte{0x05, 0x03, 0x00, 0x03, 11}, append([]byte("example.com"), 0, 53)...),
			command:    0x03,
			atyp:       0x03,
			wantTarget: "example.com:53",
		},
		{
			name:       "IPv6 connect",
			raw:        []byte{0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb},
			command:    0x01,
			atyp:       0x04,
			wantTarget: "[2001:db8::1]:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, reply, err := readLocalSOCKS5Request(bytes.NewReader(tt.raw))
			if err != nil {
				t.Fatalf("readLocalSOCKS5Request returned error: %v", err)
			}
			if reply != 0 {
				t.Fatalf("readLocalSOCKS5Request reply = 0x%02x, want 0", reply)
			}
			if req.command != tt.command || req.atyp != tt.atyp || req.target != tt.wantTarget {
				t.Fatalf("readLocalSOCKS5Request = command 0x%02x atyp 0x%02x target %q, want command 0x%02x atyp 0x%02x target %q", req.command, req.atyp, req.target, tt.command, tt.atyp, tt.wantTarget)
			}
		})
	}
}

func TestReadLocalSOCKS5RequestMalformedReplyStatus(t *testing.T) {
	tests := []struct {
		name      string
		raw       []byte
		wantReply byte
	}{
		{
			name:      "nonzero RSV",
			raw:       []byte{0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0, 80},
			wantReply: 0x01,
		},
		{
			name:      "unsupported ATYP",
			raw:       []byte{0x05, 0x01, 0x00, 0x09},
			wantReply: 0x08,
		},
		{
			name:      "zero CONNECT port",
			raw:       []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0},
			wantReply: 0x04,
		},
		{
			name:      "empty CONNECT domain",
			raw:       []byte{0x05, 0x01, 0x00, 0x03, 0, 0, 80},
			wantReply: 0x04,
		},
		{
			name:      "whitespace CONNECT domain",
			raw:       append([]byte{0x05, 0x01, 0x00, 0x03, 8}, append([]byte("bad host"), 0, 80)...),
			wantReply: 0x04,
		},
		{
			name:      "invalid CONNECT domain",
			raw:       append([]byte{0x05, 0x01, 0x00, 0x03, 16}, append([]byte("bad_host.example"), 0, 80)...),
			wantReply: 0x04,
		},
		{
			name:      "truncated address",
			raw:       []byte{0x05, 0x01, 0x00, 0x01, 127},
			wantReply: 0x00,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, reply, err := readLocalSOCKS5Request(bytes.NewReader(tt.raw)); err == nil {
				t.Fatal("readLocalSOCKS5Request accepted malformed request")
			} else if reply != tt.wantReply {
				t.Fatalf("readLocalSOCKS5Request reply = 0x%02x, want 0x%02x", reply, tt.wantReply)
			}
		})
	}
}

func TestHandleSOCKS5MethodSelectionHandlesProgressiveShortWrites(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	done := make(chan struct{})
	go func() {
		handleSOCKS5(oneByteConn{Conn: server}, &ProxyConfig{})
		close(done)
	}()

	if err := writeAll(client, []byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read SOCKS5 method selection: %v", err)
	}
	if !bytes.Equal(resp, []byte{0x05, 0x00}) {
		t.Fatalf("SOCKS5 method selection = %v, want [5 0]", resp)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleSOCKS5 did not return after client close")
	}
}

func TestHandleSOCKS5UserPassAuthHandlesProgressiveShortWrites(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	errCh := make(chan error, 1)
	go func() {
		errCh <- handleSOCKS5UserPassAuth(oneByteConn{Conn: server}, &ProxyConfig{Username: "user", Password: "pass"})
	}()

	if err := writeAll(client, []byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'}); err != nil {
		t.Fatalf("write SOCKS5 auth request: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read SOCKS5 auth response: %v", err)
	}
	if !bytes.Equal(resp, []byte{0x01, 0x00}) {
		t.Fatalf("SOCKS5 auth response = %v, want [1 0]", resp)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("handleSOCKS5UserPassAuth returned error: %v", err)
	}
}

func TestHandleSOCKS5UDPAssociateHandlesProgressiveShortWrites(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	done := make(chan struct{})
	go func() {
		handleSOCKS5UDP(oneByteConn{Conn: server}, &ProxyConfig{Host: "127.0.0.1:0"})
		close(done)
	}()

	resp := make([]byte, 10)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read SOCKS5 UDP associate response: %v", err)
	}
	if !bytes.Equal(resp[:4], []byte{0x05, 0x00, 0x00, 0x01}) {
		t.Fatalf("SOCKS5 UDP associate response head = %v, want [5 0 0 1]", resp[:4])
	}
	if port := int(resp[8])<<8 | int(resp[9]); port == 0 {
		t.Fatalf("SOCKS5 UDP associate port = %d, want non-zero", port)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleSOCKS5UDP did not return after client close")
	}
}

func TestHandleSOCKS5RejectsZeroConnectPort(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	go handleSOCKS5(server, &ProxyConfig{})
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil {
		t.Fatalf("read SOCKS5 method: %v", err)
	}
	if !bytes.Equal(method, []byte{0x05, 0x00}) {
		t.Fatalf("SOCKS5 method = %v, want [5 0]", method)
	}
	if _, err := client.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		t.Fatalf("write SOCKS5 connect: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read SOCKS5 connect response: %v", err)
	}
	if resp[1] == 0x00 {
		t.Fatalf("SOCKS5 zero-port connect succeeded: %v", resp)
	}
}

func TestHandleSOCKS5RejectsNonzeroRequestReservedByte(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	go handleSOCKS5(server, &ProxyConfig{})
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil {
		t.Fatalf("read SOCKS5 method: %v", err)
	}
	if !bytes.Equal(method, []byte{0x05, 0x00}) {
		t.Fatalf("SOCKS5 method = %v, want [5 0]", method)
	}
	if _, err := client.Write([]byte{0x05, 0x01, 0x01, 0x01}); err != nil {
		t.Fatalf("write SOCKS5 request with nonzero RSV: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read SOCKS5 response: %v", err)
	}
	if resp[1] == 0x00 {
		t.Fatalf("SOCKS5 nonzero RSV request succeeded: %v", resp)
	}
}

func TestHandleSOCKS5RejectsUnsupportedCommand(t *testing.T) {
	for _, cmd := range []byte{0x02, 0x09} {
		t.Run(fmt.Sprintf("cmd_0x%02x", cmd), func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			_ = server.SetDeadline(time.Now().Add(time.Second))
			_ = client.SetDeadline(time.Now().Add(time.Second))

			go handleSOCKS5(server, &ProxyConfig{})
			if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
				t.Fatalf("write SOCKS5 greeting: %v", err)
			}
			method := make([]byte, 2)
			if _, err := io.ReadFull(client, method); err != nil {
				t.Fatalf("read SOCKS5 method: %v", err)
			}
			if !bytes.Equal(method, []byte{0x05, 0x00}) {
				t.Fatalf("SOCKS5 method = %v, want [5 0]", method)
			}
			if _, err := client.Write([]byte{0x05, cmd, 0x00, 0x01, 127, 0, 0, 1, 0, 80}); err != nil {
				t.Fatalf("write SOCKS5 unsupported command request: %v", err)
			}
			resp := make([]byte, 10)
			if _, err := io.ReadFull(client, resp); err != nil {
				t.Fatalf("read SOCKS5 unsupported command response: %v", err)
			}
			if resp[1] != 0x07 {
				t.Fatalf("SOCKS5 unsupported command status = 0x%02x, want 0x07", resp[1])
			}
		})
	}
}

func TestHandleSOCKS5RejectsUnsupportedAddressType(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	go handleSOCKS5(server, &ProxyConfig{})
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil {
		t.Fatalf("read SOCKS5 method: %v", err)
	}
	if !bytes.Equal(method, []byte{0x05, 0x00}) {
		t.Fatalf("SOCKS5 method = %v, want [5 0]", method)
	}
	if _, err := client.Write([]byte{0x05, 0x01, 0x00, 0x09}); err != nil {
		t.Fatalf("write SOCKS5 unsupported ATYP request: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read SOCKS5 unsupported ATYP response: %v", err)
	}
	if resp[1] != 0x08 {
		t.Fatalf("SOCKS5 unsupported ATYP status = 0x%02x, want 0x08", resp[1])
	}
}

func TestHandleSOCKS5RejectsMissingUserPassMethod(t *testing.T) {
	got := socks5MethodSelection(t, &ProxyConfig{Username: "user", Password: "pass"}, []byte{0x00})
	if !bytes.Equal(got, []byte{0x05, 0xff}) {
		t.Fatalf("SOCKS5 method selection = %v, want [5 255]", got)
	}
}

func TestHandleSOCKS5RejectsMissingNoAuthMethod(t *testing.T) {
	got := socks5MethodSelection(t, &ProxyConfig{}, []byte{0x02})
	if !bytes.Equal(got, []byte{0x05, 0xff}) {
		t.Fatalf("SOCKS5 method selection = %v, want [5 255]", got)
	}
}

func TestHandleSOCKS5SelectsConfiguredMethod(t *testing.T) {
	tests := []struct {
		name    string
		config  *ProxyConfig
		methods []byte
		want    []byte
	}{
		{
			name:    "auth proxy selects userpass when no-auth is also offered",
			config:  &ProxyConfig{Username: "user", Password: "pass"},
			methods: []byte{0x00, 0x02},
			want:    []byte{0x05, 0x02},
		},
		{
			name:    "no-auth proxy selects no-auth when userpass is also offered",
			config:  &ProxyConfig{},
			methods: []byte{0x02, 0x00},
			want:    []byte{0x05, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := socks5MethodSelection(t, tt.config, tt.methods)
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("SOCKS5 method selection = %v, want %v", got, tt.want)
			}
		})
	}
}

func socks5MethodSelection(t *testing.T, cfgp *ProxyConfig, methods []byte) []byte {
	t.Helper()
	if len(methods) > 255 {
		t.Fatalf("too many methods: %d", len(methods))
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	go handleSOCKS5(server, cfgp)
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := client.Write(greeting); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read SOCKS5 method selection: %v", err)
	}
	return resp
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

func TestHandleHTTPRejectsProxyAuth(t *testing.T) {
	wrongAuth := base64.StdEncoding.EncodeToString([]byte("user:wrong"))
	tests := []struct {
		name    string
		request string
	}{
		{
			name:    "missing auth",
			request: "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:    "wrong auth",
			request: "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic " + wrongAuth + "\r\n\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := handleHTTPResponse(t, tt.request, &ProxyConfig{Username: "user", Password: "pass"})
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Fatalf("HTTP status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
			}
			if resp.Status != "407 Proxy Authentication Required" {
				t.Fatalf("HTTP status line = %q, want 407 Proxy Authentication Required", resp.Status)
			}
			if got := resp.Header.Get("Proxy-Authenticate"); got == "" {
				t.Fatal("missing Proxy-Authenticate header")
			}
			if resp.ContentLength != 0 {
				t.Fatalf("ContentLength = %d, want 0", resp.ContentLength)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read auth response body: %v", err)
			}
			if len(body) != 0 {
				t.Fatalf("auth response body = %q, want empty", body)
			}
		})
	}
}

func TestSanitizeHTTPProxyRequestClearsCloseState(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	req.RequestURI = "http://example.com/path"
	req.Header.Set("Connection", "close, X-Hop")
	req.Header.Set("X-Hop", "drop-me")
	req.Close = true

	sanitizeHTTPProxyRequest(req)
	if req.Close {
		t.Fatal("sanitizeHTTPProxyRequest left req.Close set")
	}
	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatalf("write sanitized request: %v", err)
	}
	for _, forbidden := range []string{"Connection: close", "X-Hop: drop-me"} {
		if strings.Contains(buf.String(), forbidden) {
			t.Fatalf("sanitized request still contains %q:\n%s", forbidden, buf.String())
		}
	}
}

func TestValidHTTPProxyBasicAuth(t *testing.T) {
	token := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	tests := []struct {
		name string
		auth string
		want bool
	}{
		{name: "standard", auth: "Basic " + token, want: true},
		{name: "case insensitive scheme", auth: "bAsIc " + token, want: true},
		{name: "optional whitespace", auth: "Basic \t " + token, want: true},
		{name: "leading and trailing whitespace", auth: "  Basic\t" + token + "  ", want: true},
		{name: "wrong credentials", auth: "Basic " + base64.StdEncoding.EncodeToString([]byte("user:wrong")), want: false},
		{name: "invalid base64", auth: "Basic not-base64", want: false},
		{name: "extra fields", auth: "Basic " + token + " extra", want: false},
		{name: "wrong scheme", auth: "Bearer " + token, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validHTTPProxyBasicAuth(tt.auth, "user", "pass"); got != tt.want {
				t.Fatalf("validHTTPProxyBasicAuth(%q) = %v, want %v", tt.auth, got, tt.want)
			}
		})
	}
}

func handleHTTPResponse(t *testing.T, request string, cfgp *ProxyConfig) *http.Response {
	t.Helper()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	go handleHTTP(server, cfgp)
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatalf("write HTTP proxy request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read HTTP proxy response: %v", err)
	}
	return resp
}

func TestWebSocketRequestHasToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{name: "single token", header: "secret-token", want: true},
		{name: "token in list", header: "other, secret-token", want: true},
		{name: "token later in list with spaces", header: "other,  secret-token , final", want: true},
		{name: "missing token", header: "other, final", want: false},
		{name: "partial token", header: "secret-token-extra", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/tunnel", nil)
			req.Header.Set("Sec-WebSocket-Protocol", tt.header)
			if got := webSocketRequestHasToken(req, "secret-token"); got != tt.want {
				t.Fatalf("webSocketRequestHasToken(%q) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}

func TestHTTPProxyTarget(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			name: "connect default port",
			req:  &http.Request{Method: http.MethodConnect, Host: "example.com", URL: &url.URL{}},
			want: "example.com:443",
		},
		{
			name: "absolute url default port",
			req:  &http.Request{Method: http.MethodGet, Host: "example.com", URL: &url.URL{Scheme: "http", Host: "example.com"}},
			want: "example.com:80",
		},
		{
			name: "absolute url explicit port",
			req:  &http.Request{Method: http.MethodGet, Host: "example.com:8080", URL: &url.URL{Scheme: "http", Host: "example.com:8080"}},
			want: "example.com:8080",
		},
		{
			name: "origin form default port",
			req:  &http.Request{Method: http.MethodGet, Host: "example.com", URL: &url.URL{Path: "/"}},
			want: "example.com:80",
		},
		{
			name: "ipv6 host default port",
			req:  &http.Request{Method: http.MethodGet, Host: "[2001:db8::1]", URL: &url.URL{Path: "/"}},
			want: "[2001:db8::1]:80",
		},
		{
			name: "uppercase hostname",
			req:  &http.Request{Method: http.MethodGet, Host: "Example.COM", URL: &url.URL{Path: "/"}},
			want: "Example.COM:80",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := httpProxyTarget(tt.req)
			if err != nil {
				t.Fatalf("httpProxyTarget returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("httpProxyTarget = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHTTPProxyTargetRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
	}{
		{
			name: "empty target",
			req:  &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/"}},
		},
		{
			name: "bad port",
			req:  &http.Request{Method: http.MethodGet, Host: "example.com:bad", URL: &url.URL{Path: "/"}},
		},
		{
			name: "host mismatch",
			req:  &http.Request{Method: http.MethodGet, Host: "other.example", URL: &url.URL{Scheme: "http", Host: "example.com"}},
		},
		{
			name: "userinfo absolute url",
			req:  &http.Request{Method: http.MethodGet, Host: "example.com", URL: &url.URL{Scheme: "http", Host: "example.com", User: url.User("user")}},
		},
		{
			name: "https absolute url",
			req:  &http.Request{Method: http.MethodGet, Host: "example.com", URL: &url.URL{Scheme: "https", Host: "example.com"}},
		},
		{
			name: "ftp absolute url",
			req:  &http.Request{Method: http.MethodGet, Host: "example.com", URL: &url.URL{Scheme: "ftp", Host: "example.com"}},
		},
		{
			name: "unbracketed ipv6",
			req:  &http.Request{Method: http.MethodGet, Host: "2001:db8::1", URL: &url.URL{Path: "/"}},
		},
		{
			name: "invalid domain underscore",
			req:  &http.Request{Method: http.MethodGet, Host: "bad_host.example", URL: &url.URL{Path: "/"}},
		},
		{
			name: "invalid domain hyphen prefix",
			req:  &http.Request{Method: http.MethodGet, Host: "-bad.example", URL: &url.URL{Path: "/"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := httpProxyTarget(tt.req); err == nil {
				t.Fatalf("httpProxyTarget = %q, want error", got)
			}
		})
	}
}

func TestHandleHTTPRejectsMalformedProxyTarget(t *testing.T) {
	resp := handleHTTPResponse(t, "GET / HTTP/1.1\r\nHost: example.com:bad\r\n\r\n", &ProxyConfig{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("HTTP status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandleHTTPRejectsUnsupportedAbsoluteFormScheme(t *testing.T) {
	resp := handleHTTPResponse(t, "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", &ProxyConfig{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("HTTP status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestStripHTTPProxyHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Proxy-Authorization", "Basic secret")
	h.Set("Proxy-Connection", "keep-alive")
	h.Set("Connection", "keep-alive, X-Hop")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("TE", "trailers")
	h.Set("Trailer", "X-Trailer")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Upgrade", "websocket")
	h.Set("X-Hop", "remove me")
	h.Set("User-Agent", "x-tunnel-test")

	stripHTTPProxyHeaders(h)

	for _, name := range []string{
		"Proxy-Authorization",
		"Proxy-Connection",
		"Connection",
		"Keep-Alive",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"X-Hop",
	} {
		if got := h.Get(name); got != "" {
			t.Fatalf("%s header = %q, want removed", name, got)
		}
	}
	if got := h.Get("User-Agent"); got != "x-tunnel-test" {
		t.Fatalf("User-Agent header = %q, want x-tunnel-test", got)
	}
}

func TestAddHTTPProxyViaHeader(t *testing.T) {
	h := http.Header{}
	addHTTPProxyViaHeader(h)
	if got := h.Values("Via"); len(got) != 1 || got[0] != httpProxyViaValue {
		t.Fatalf("Via headers = %q, want [%q]", got, httpProxyViaValue)
	}

	h.Set("Via", "1.0 upstream-proxy")
	addHTTPProxyViaHeader(h)
	got := h.Values("Via")
	if len(got) != 2 || got[0] != "1.0 upstream-proxy" || got[1] != httpProxyViaValue {
		t.Fatalf("Via headers = %q, want existing value plus %q", got, httpProxyViaValue)
	}
}

func TestHandleHTTPPostOpensStreamBeforeBodyComplete(t *testing.T) {
	oldPool := echPool
	oldCfg := cfg
	oldIPStrategy := ipStrategy
	defer func() {
		echPool = oldPool
		cfg = oldCfg
		ipStrategy = oldIPStrategy
	}()
	cfg.DialTimeout = time.Second
	ipStrategy = IPStrategyDefault

	serverConn, clientConn := net.Pipe()
	serverSession, err := smux.Server(serverConn, nil)
	if err != nil {
		t.Fatalf("smux server: %v", err)
	}
	clientSession, err := smux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("smux client: %v", err)
	}
	t.Cleanup(func() {
		serverSession.Close()
		clientSession.Close()
		serverConn.Close()
		clientConn.Close()
	})
	echPool = &ECHPool{
		smuxConns:   []*smux.Session{clientSession},
		channelRTT:  []int64{1},
		channelCaps: []uint32{0},
	}

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

	proxyServer, proxyClient := net.Pipe()
	_ = proxyServer.SetDeadline(time.Now().Add(time.Second))
	_ = proxyClient.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleHTTP(proxyServer, &ProxyConfig{})
	}()

	reqHead := "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n"
	if err := writeAll(proxyClient, []byte(reqHead)); err != nil {
		t.Fatalf("write HTTP proxy POST head: %v", err)
	}

	var serverStream *smux.Stream
	select {
	case serverStream = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept smux stream: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for smux stream before POST body was complete")
	}
	if err := serverStream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set server stream deadline: %v", err)
	}
	kind, strategy, target, err := readSmuxOpenHeader(serverStream)
	if err != nil {
		t.Fatalf("read POST smux header: %v", err)
	}
	if kind != streamKindTCP || strategy != IPStrategyDefault || target != "example.com:80" {
		t.Fatalf("POST smux header = kind %d strategy %d target %q", kind, strategy, target)
	}

	br := bufio.NewReader(serverStream)
	requestLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read forwarded request line: %v", err)
	}
	if requestLine != "POST /upload HTTP/1.1\r\n" {
		t.Fatalf("forwarded request line = %q", requestLine)
	}
	var forwardedHeaders strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read forwarded request header: %v", err)
		}
		if line == "\r\n" {
			break
		}
		forwardedHeaders.WriteString(line)
	}
	headers := forwardedHeaders.String()
	for _, want := range []string{"Host: example.com\r\n", "Content-Length: 4\r\n", "Via: " + httpProxyViaValue + "\r\n"} {
		if !strings.Contains(headers, want) {
			t.Fatalf("forwarded headers missing %q:\n%s", want, headers)
		}
	}

	if err := writeAll(proxyClient, []byte("body")); err != nil {
		t.Fatalf("write delayed POST body: %v", err)
	}
	body := make([]byte, 4)
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatalf("read forwarded POST body: %v", err)
	}
	if string(body) != "body" {
		t.Fatalf("forwarded POST body = %q, want body", body)
	}
	_ = serverStream.Close()
	_ = proxyClient.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HTTP handler shutdown")
	}
}

func TestHandleHTTPConnectForwardsBufferedClientBytes(t *testing.T) {
	oldPool := echPool
	oldCfg := cfg
	oldIPStrategy := ipStrategy
	defer func() {
		echPool = oldPool
		cfg = oldCfg
		ipStrategy = oldIPStrategy
	}()
	cfg.DialTimeout = time.Second
	ipStrategy = IPStrategyDefault

	serverConn, clientConn := net.Pipe()
	serverSession, err := smux.Server(serverConn, nil)
	if err != nil {
		t.Fatalf("smux server: %v", err)
	}
	clientSession, err := smux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("smux client: %v", err)
	}
	t.Cleanup(func() {
		serverSession.Close()
		clientSession.Close()
		serverConn.Close()
		clientConn.Close()
	})
	echPool = &ECHPool{
		smuxConns:   []*smux.Session{clientSession},
		channelRTT:  []int64{1},
		channelCaps: []uint32{0},
	}

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

	proxyServer, proxyClient := net.Pipe()
	_ = proxyServer.SetDeadline(time.Now().Add(time.Second))
	_ = proxyClient.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleHTTP(proxyServer, &ProxyConfig{})
	}()

	early := []byte("early-client-bytes")
	req := append([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"), early...)
	if err := writeAll(proxyClient, req); err != nil {
		t.Fatalf("write CONNECT request with early bytes: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(proxyClient), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var serverStream *smux.Stream
	select {
	case serverStream = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept smux stream: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for CONNECT smux stream")
	}
	if err := serverStream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set server stream deadline: %v", err)
	}
	kind, strategy, target, err := readSmuxOpenHeader(serverStream)
	if err != nil {
		t.Fatalf("read CONNECT smux header: %v", err)
	}
	if kind != streamKindTCP || strategy != IPStrategyDefault || target != "example.com:443" {
		t.Fatalf("CONNECT smux header = kind %d strategy %d target %q", kind, strategy, target)
	}
	got := make([]byte, len(early))
	if _, err := io.ReadFull(serverStream, got); err != nil {
		t.Fatalf("read buffered CONNECT bytes: %v", err)
	}
	if !bytes.Equal(got, early) {
		t.Fatalf("buffered CONNECT bytes = %q, want %q", got, early)
	}

	proxyClient.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for CONNECT handler shutdown")
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

func TestSmuxOpenHeaderWireBytes(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSmuxOpenHeader(&buf, streamKindTCP, IPStrategyPv6Pv4, "h:1"); err != nil {
		t.Fatalf("writeSmuxOpenHeader returned error: %v", err)
	}
	want := []byte{0x01, 0x04, 0x00, 0x03, 'h', ':', '1'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("smux open header bytes = %x, want %x", buf.Bytes(), want)
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

func TestValidateSmuxStreamTarget(t *testing.T) {
	for _, target := range []string{"example.com:443", "127.0.0.1:80", "[2001:db8::1]:53"} {
		if err := validateSmuxStreamTarget(target); err != nil {
			t.Fatalf("validateSmuxStreamTarget(%q) returned error: %v", target, err)
		}
	}

	for _, target := range []string{"", "example.com", "example.com:0", "example.com:bad", ":443", "bad host:443"} {
		if err := validateSmuxStreamTarget(target); err == nil {
			t.Fatalf("validateSmuxStreamTarget(%q) accepted malformed target", target)
		}
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

func openAcceptedSmuxTestStream(t *testing.T, kind byte) (*smux.Stream, *smux.Stream) {
	return openAcceptedSmuxTestStreamWithHeader(t, kind, IPStrategyDefault, "")
}

func openAcceptedSmuxTestStreamWithHeader(t *testing.T, kind, strategy byte, target string) (*smux.Stream, *smux.Stream) {
	t.Helper()

	clientStream, serverStream := openRawAcceptedSmuxTestStream(t)
	if err := clientStream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set client stream deadline: %v", err)
	}
	if err := writeSmuxOpenHeader(clientStream, kind, strategy, target); err != nil {
		t.Fatalf("write smux open header: %v", err)
	}
	return clientStream, serverStream
}

func openRawAcceptedSmuxTestStream(t *testing.T) (*smux.Stream, *smux.Stream) {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	serverSession, err := smux.Server(serverConn, nil)
	if err != nil {
		t.Fatalf("smux server: %v", err)
	}
	clientSession, err := smux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("smux client: %v", err)
	}

	t.Cleanup(func() {
		serverSession.Close()
		clientSession.Close()
		serverConn.Close()
		clientConn.Close()
	})

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
	t.Cleanup(func() {
		clientStream.Close()
	})

	select {
	case serverStream := <-accepted:
		return clientStream, serverStream
	case err := <-acceptErr:
		t.Fatalf("accept smux stream: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for accepted smux stream")
	}
	return nil, nil
}

func TestHandleSmuxStreamPingEcho(t *testing.T) {
	oldCfg := cfg
	defer func() {
		cfg = oldCfg
	}()
	cfg.RTTProbeTimeout = time.Second

	clientStream, serverStream := openAcceptedSmuxTestStream(t, streamKindPing)
	payload := []byte("12345678")
	if err := writeAll(clientStream, payload); err != nil {
		t.Fatalf("write ping payload: %v", err)
	}

	done := make(chan struct{})
	session := &ClientSession{clientID: "ping-echo-test", channels: make(map[uint64]*WSChannel)}
	go func() {
		defer close(done)
		handleSmuxStream(session, &WSChannel{id: 1, session: session}, serverStream)
	}()

	ack := make([]byte, len(payload))
	if _, err := io.ReadFull(clientStream, ack); err != nil {
		t.Fatalf("read ping ack: %v", err)
	}
	if !bytes.Equal(ack, payload) {
		t.Fatalf("ping ack = %q, want %q", ack, payload)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ping echo handler")
	}
}

func TestHandleSmuxStreamPingDeadline(t *testing.T) {
	oldCfg := cfg
	defer func() {
		cfg = oldCfg
	}()
	cfg.RTTProbeTimeout = 50 * time.Millisecond

	_, serverStream := openAcceptedSmuxTestStream(t, streamKindPing)
	done := make(chan struct{})
	session := &ClientSession{clientID: "ping-deadline-test", channels: make(map[uint64]*WSChannel)}
	go func() {
		defer close(done)
		handleSmuxStream(session, &WSChannel{id: 1, session: session}, serverStream)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for half-open ping stream handler")
	}
}

func TestHandleSmuxStreamOpenHeaderDeadline(t *testing.T) {
	oldCfg := cfg
	defer func() {
		cfg = oldCfg
	}()
	cfg.RTTProbeTimeout = 50 * time.Millisecond

	_, serverStream := openRawAcceptedSmuxTestStream(t)
	done := make(chan struct{})
	session := &ClientSession{clientID: "open-header-deadline-test", channels: make(map[uint64]*WSChannel)}
	go func() {
		defer close(done)
		handleSmuxStream(session, &WSChannel{id: 1, session: session}, serverStream)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for half-open smux header handler")
	}
}

func TestHandleSmuxStreamTruncatedOpenHeaderTargetDeadline(t *testing.T) {
	oldCfg := cfg
	defer func() {
		cfg = oldCfg
	}()
	cfg.RTTProbeTimeout = 50 * time.Millisecond

	clientStream, serverStream := openRawAcceptedSmuxTestStream(t)
	if err := clientStream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set client stream deadline: %v", err)
	}
	raw := []byte{streamKindTCP, IPStrategyDefault, 0, 5, 'a'}
	if err := writeAll(clientStream, raw); err != nil {
		t.Fatalf("write truncated smux open header target: %v", err)
	}

	done := make(chan struct{})
	session := &ClientSession{clientID: "truncated-open-header-target-test", channels: make(map[uint64]*WSChannel)}
	go func() {
		defer close(done)
		handleSmuxStream(session, &WSChannel{id: 1, session: session}, serverStream)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for truncated smux header target handler")
	}
}

func TestHandleSmuxStreamRejectsMalformedTCPTargetWithStatus(t *testing.T) {
	oldTargetRejects := atomic.LoadUint64(&serverTargetRejectSeq)
	defer atomic.StoreUint64(&serverTargetRejectSeq, oldTargetRejects)
	atomic.StoreUint64(&serverTargetRejectSeq, 0)

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
	_ = clientStream.SetDeadline(time.Now().Add(time.Second))
	if err := writeSmuxOpenHeader(clientStream, streamKindTCP, IPStrategyDefault, ""); err != nil {
		t.Fatalf("write malformed TCP stream header: %v", err)
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
	session := &ClientSession{clientID: "malformed-target-test", channels: make(map[uint64]*WSChannel)}
	ch := &WSChannel{id: 1, session: session, capabilities: protocolCapabilityTCPStatus}
	go func() {
		defer close(done)
		handleSmuxStream(session, ch, serverStream)
	}()

	status, message, err := readTCPOpenStatus(clientStream)
	if err != nil {
		t.Fatalf("read TCP open status: %v", err)
	}
	if status != tcpOpenStatusError || !strings.Contains(message, "目标地址无效") {
		t.Fatalf("TCP open status = %d %q, want target validation error", status, message)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for malformed target handler")
	}
	if got := atomic.LoadUint64(&serverTargetRejectSeq); got != 1 {
		t.Fatalf("serverTargetRejectSeq = %d, want 1", got)
	}
}

func TestHandleSmuxStreamRejectsInvalidIPStrategyWithStatus(t *testing.T) {
	oldTargetRejects := atomic.LoadUint64(&serverTargetRejectSeq)
	defer atomic.StoreUint64(&serverTargetRejectSeq, oldTargetRejects)
	atomic.StoreUint64(&serverTargetRejectSeq, 0)

	clientStream, serverStream := openAcceptedSmuxTestStreamWithHeader(t, streamKindTCP, 99, "127.0.0.1:80")
	done := make(chan struct{})
	session := &ClientSession{clientID: "invalid-ip-strategy-test", channels: make(map[uint64]*WSChannel)}
	ch := &WSChannel{id: 1, session: session, capabilities: protocolCapabilityTCPStatus}
	go func() {
		defer close(done)
		handleSmuxStream(session, ch, serverStream)
	}()

	status, message, err := readTCPOpenStatus(clientStream)
	if err != nil {
		t.Fatalf("read TCP open status: %v", err)
	}
	if status != tcpOpenStatusError || !strings.Contains(message, "IP 策略无效") {
		t.Fatalf("TCP open status = %d %q, want IP strategy validation error", status, message)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for invalid TCP IP strategy handler")
	}
	if got := atomic.LoadUint64(&serverTargetRejectSeq); got != 1 {
		t.Fatalf("serverTargetRejectSeq = %d, want 1", got)
	}
}

func TestHandleSmuxStreamTCPStatusSuccessProxiesBytes(t *testing.T) {
	oldCfg := cfg
	oldTargetPolicy := targetPolicy
	oldSocks5Config := socks5Config
	t.Cleanup(func() {
		cfg = oldCfg
		targetPolicy = oldTargetPolicy
		socks5Config = oldSocks5Config
	})
	cfg.DialTimeout = time.Second
	targetPolicy = nil
	socks5Config = nil

	targetAddr := startOneShotTCPEcho(t)
	clientStream, serverStream := openAcceptedSmuxTestStreamWithHeader(t, streamKindTCP, IPStrategyDefault, targetAddr)
	done := make(chan struct{})
	session := &ClientSession{clientID: "tcp-status-success-test", channels: make(map[uint64]*WSChannel)}
	ch := &WSChannel{id: 1, session: session, capabilities: protocolCapabilityTCPStatus}
	go func() {
		defer close(done)
		handleSmuxStream(session, ch, serverStream)
	}()

	status, message, err := readTCPOpenStatus(clientStream)
	if err != nil {
		t.Fatalf("read TCP open status: %v", err)
	}
	if status != tcpOpenStatusOK || message != "" {
		t.Fatalf("TCP open status = %d %q, want OK empty message", status, message)
	}
	if err := clientStream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set client stream deadline: %v", err)
	}
	if _, err := clientStream.Write([]byte("ping")); err != nil {
		t.Fatalf("write proxied TCP payload: %v", err)
	}
	reply := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(clientStream, reply); err != nil {
		t.Fatalf("read proxied TCP reply: %v", err)
	}
	if string(reply) != "echo:ping" {
		t.Fatalf("proxied TCP reply = %q, want echo:ping", reply)
	}
	_ = clientStream.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP smux success handler")
	}
}

func TestHandleSmuxStreamRejectsInvalidUDPIPStrategy(t *testing.T) {
	oldTargetRejects := atomic.LoadUint64(&serverTargetRejectSeq)
	defer atomic.StoreUint64(&serverTargetRejectSeq, oldTargetRejects)
	atomic.StoreUint64(&serverTargetRejectSeq, 0)

	_, serverStream := openAcceptedSmuxTestStreamWithHeader(t, streamKindUDP, 99, "127.0.0.1:53")
	done := make(chan struct{})
	session := &ClientSession{clientID: "invalid-udp-ip-strategy-test", channels: make(map[uint64]*WSChannel)}
	go func() {
		defer close(done)
		handleSmuxStream(session, &WSChannel{id: 1, session: session}, serverStream)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for invalid UDP IP strategy handler")
	}
	if got := atomic.LoadUint64(&serverTargetRejectSeq); got != 1 {
		t.Fatalf("serverTargetRejectSeq = %d, want 1", got)
	}
}

func TestHandleSmuxStreamUDPProxiesDatagram(t *testing.T) {
	oldCfg := cfg
	oldTargetPolicy := targetPolicy
	oldSocks5Config := socks5Config
	t.Cleanup(func() {
		cfg = oldCfg
		targetPolicy = oldTargetPolicy
		socks5Config = oldSocks5Config
	})
	cfg.DialTimeout = time.Second
	cfg.UDPReadTimeout = 20 * time.Millisecond
	targetPolicy = nil
	socks5Config = nil

	targetAddr := startUDPEcho(t)
	clientStream, serverStream := openAcceptedSmuxTestStreamWithHeader(t, streamKindUDP, IPStrategyDefault, targetAddr)
	done := make(chan struct{})
	session := &ClientSession{clientID: "udp-smux-success-test", channels: make(map[uint64]*WSChannel)}
	go func() {
		defer close(done)
		handleSmuxStream(session, &WSChannel{id: 1, session: session}, serverStream)
	}()

	if err := clientStream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set client stream deadline: %v", err)
	}
	if err := writeChunk(clientStream, []byte("dns")); err != nil {
		t.Fatalf("write UDP smux chunk: %v", err)
	}
	addr, payload, err := readUDPReply(clientStream)
	if err != nil {
		t.Fatalf("read UDP smux reply: %v", err)
	}
	if addr != targetAddr || string(payload) != "echo:dns" {
		t.Fatalf("UDP smux reply = addr %q payload %q, want %q echo:dns", addr, payload, targetAddr)
	}
	_ = clientStream.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for UDP smux success handler")
	}
}

func TestHandleSmuxStreamHelloDeadline(t *testing.T) {
	oldCfg := cfg
	oldProtocolFailures := atomic.LoadUint64(&serverProtocolFailureSeq)
	defer func() {
		cfg = oldCfg
		atomic.StoreUint64(&serverProtocolFailureSeq, oldProtocolFailures)
	}()
	cfg.RTTProbeTimeout = 50 * time.Millisecond
	atomic.StoreUint64(&serverProtocolFailureSeq, 0)

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
	if err := writeSmuxOpenHeader(clientStream, streamKindHello, IPStrategyDefault, ""); err != nil {
		t.Fatalf("write hello stream header: %v", err)
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
	session := &ClientSession{clientID: "hello-deadline-test", channels: make(map[uint64]*WSChannel)}
	go func() {
		defer close(done)
		handleSmuxStream(session, &WSChannel{id: 1, session: session}, serverStream)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for half-open hello stream handler")
	}
	if got := atomic.LoadUint64(&serverProtocolFailureSeq); got != 1 {
		t.Fatalf("serverProtocolFailureSeq = %d, want 1", got)
	}
}

func TestHandleSmuxStreamRejectsUnsupportedProtocolHello(t *testing.T) {
	oldCfg := cfg
	oldProtocolRejects := atomic.LoadUint64(&serverProtocolRejectSeq)
	oldProtocolFailures := atomic.LoadUint64(&serverProtocolFailureSeq)
	defer func() {
		cfg = oldCfg
		atomic.StoreUint64(&serverProtocolRejectSeq, oldProtocolRejects)
		atomic.StoreUint64(&serverProtocolFailureSeq, oldProtocolFailures)
	}()
	cfg.RTTProbeTimeout = time.Second
	atomic.StoreUint64(&serverProtocolRejectSeq, 0)
	atomic.StoreUint64(&serverProtocolFailureSeq, 0)

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
	_ = clientStream.SetDeadline(time.Now().Add(time.Second))
	if err := writeSmuxOpenHeader(clientStream, streamKindHello, IPStrategyDefault, ""); err != nil {
		t.Fatalf("write hello stream header: %v", err)
	}
	hello := currentProtocolHello()
	hello.Version = protocolVersion + 1
	if err := writeProtocolHello(clientStream, hello); err != nil {
		t.Fatalf("write unsupported protocol hello: %v", err)
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
	session := &ClientSession{clientID: "hello-reject-test", channels: make(map[uint64]*WSChannel)}
	go func() {
		defer close(done)
		handleSmuxStream(session, &WSChannel{id: 1, session: session}, serverStream)
	}()

	response, err := readProtocolHello(clientStream)
	if err != nil {
		t.Fatalf("read protocol rejection response: %v", err)
	}
	if response.Status != protocolStatusUnsupportedVersion {
		t.Fatalf("protocol response status = %d, want %d", response.Status, protocolStatusUnsupportedVersion)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for unsupported protocol hello handler")
	}
	if got := atomic.LoadUint64(&serverProtocolRejectSeq); got != 1 {
		t.Fatalf("serverProtocolRejectSeq = %d, want 1", got)
	}
	if got := atomic.LoadUint64(&serverProtocolFailureSeq); got != 0 {
		t.Fatalf("serverProtocolFailureSeq = %d, want 0", got)
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

func TestProtocolHelloWireBytes(t *testing.T) {
	var buf bytes.Buffer
	hello := ProtocolHello{
		Version:      protocolVersion,
		Status:       protocolStatusNoCommonCapabilities,
		Capabilities: protocolCapabilityTCP | protocolCapabilityPing,
		Message:      "no",
	}
	if err := writeProtocolHello(&buf, hello); err != nil {
		t.Fatalf("writeProtocolHello returned error: %v", err)
	}
	want := []byte{'X', 'T', 'U', 'N', 0x01, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 'n', 'o'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("protocol hello bytes = %x, want %x", buf.Bytes(), want)
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

func TestTCPOpenStatusWireBytes(t *testing.T) {
	var buf bytes.Buffer
	if err := writeTCPOpenStatus(&buf, tcpOpenStatusError, "bad"); err != nil {
		t.Fatalf("writeTCPOpenStatus returned error: %v", err)
	}
	want := []byte{0x01, 0x00, 0x03, 'b', 'a', 'd'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("TCP open status bytes = %x, want %x", buf.Bytes(), want)
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

type protocolTimeoutTestError struct{}

func (protocolTimeoutTestError) Error() string   { return "timeout" }
func (protocolTimeoutTestError) Timeout() bool   { return true }
func (protocolTimeoutTestError) Temporary() bool { return false }

func newProtocolNegotiationSmuxPair(t *testing.T) (*smux.Session, *smux.Session) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	serverSession, err := smux.Server(serverConn, nil)
	if err != nil {
		t.Fatalf("smux server: %v", err)
	}
	clientSession, err := smux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("smux client: %v", err)
	}
	t.Cleanup(func() {
		serverSession.Close()
		clientSession.Close()
		serverConn.Close()
		clientConn.Close()
	})
	return serverSession, clientSession
}

func TestNegotiateClientProtocolSuccess(t *testing.T) {
	serverSession, clientSession := newProtocolNegotiationSmuxPair(t)
	serverDone := make(chan error, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()
		if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		kind, strategy, target, err := readSmuxOpenHeader(stream)
		if err != nil {
			serverDone <- err
			return
		}
		if kind != streamKindHello || strategy != IPStrategyDefault || target != "" {
			serverDone <- fmt.Errorf("hello open header = kind %d strategy %d target %q", kind, strategy, target)
			return
		}
		hello, err := readProtocolHello(stream)
		if err != nil {
			serverDone <- err
			return
		}
		serverDone <- writeProtocolHello(stream, negotiateProtocolHello(hello))
	}()

	caps, legacy, err := negotiateClientProtocol(clientSession, time.Second)
	if err != nil {
		t.Fatalf("negotiateClientProtocol returned error: %v", err)
	}
	if legacy {
		t.Fatal("negotiateClientProtocol reported legacy mode on successful hello")
	}
	if caps != currentProtocolCapabilities() {
		t.Fatalf("negotiateClientProtocol caps = 0x%x, want 0x%x", caps, currentProtocolCapabilities())
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server hello handler returned error: %v", err)
	}
}

func TestECHPoolProbeChannelRTTOnceUsesPingStream(t *testing.T) {
	oldCfg := cfg
	t.Cleanup(func() { cfg = oldCfg })
	cfg.RTTProbeTimeout = time.Second

	serverSession, clientSession := newProtocolNegotiationSmuxPair(t)
	serverDone := make(chan struct{})
	serverErr := make(chan error, 1)
	session := &ClientSession{clientID: "probe-rtt-test", channels: make(map[uint64]*WSChannel)}
	ch := &WSChannel{id: 1, session: session}
	go func() {
		stream, err := serverSession.AcceptStream()
		if err != nil {
			serverErr <- err
			return
		}
		handleSmuxStream(session, ch, stream)
		close(serverDone)
	}()

	p := &ECHPool{}
	rtt, err := p.probeChannelRTTOnce(clientSession, time.Second)
	if err != nil {
		t.Fatalf("probeChannelRTTOnce returned error: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("probeChannelRTTOnce RTT = %d, want positive duration", rtt)
	}

	select {
	case <-serverDone:
	case err := <-serverErr:
		t.Fatalf("accept ping stream: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ping stream handler")
	}
}

func TestNegotiateClientProtocolLegacyClose(t *testing.T) {
	serverSession, clientSession := newProtocolNegotiationSmuxPair(t)
	serverDone := make(chan error, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()
		if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		if _, _, _, err := readSmuxOpenHeader(stream); err != nil {
			serverDone <- err
			return
		}
		if _, err := readProtocolHello(stream); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	caps, legacy, err := negotiateClientProtocol(clientSession, time.Second)
	if err != nil {
		t.Fatalf("negotiateClientProtocol legacy close returned error: %v", err)
	}
	if !legacy || caps != 0 {
		t.Fatalf("negotiateClientProtocol legacy close = caps 0x%x legacy %v, want caps 0 legacy true", caps, legacy)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server legacy handler returned error: %v", err)
	}
}

func TestECHPoolOpenUDPStreamWritesHeader(t *testing.T) {
	serverSession, clientSession := newProtocolNegotiationSmuxPair(t)
	oldIPStrategy := ipStrategy
	t.Cleanup(func() { ipStrategy = oldIPStrategy })
	ipStrategy = IPStrategyPv4Pv6

	pool := &ECHPool{
		smuxConns:   []*smux.Session{clientSession},
		channelRTT:  []int64{int64(5 * time.Millisecond)},
		channelCaps: []uint32{currentProtocolCapabilities()},
	}
	serverDone := make(chan error, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()
		if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		kind, strategy, target, err := readSmuxOpenHeader(stream)
		if err != nil {
			serverDone <- err
			return
		}
		if kind != streamKindUDP || strategy != IPStrategyPv4Pv6 || target != "example.com:53" {
			serverDone <- fmt.Errorf("udp open header = kind %d strategy %d target %q", kind, strategy, target)
			return
		}
		serverDone <- nil
	}()

	stream, chID, decision, err := pool.openUDPStream("example.com:53")
	if err != nil {
		t.Fatalf("openUDPStream returned error: %v", err)
	}
	_ = stream.Close()
	if chID != 1 || decision != 1 {
		t.Fatalf("openUDPStream chID=%d decision=%d, want 1/1", chID, decision)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server read UDP open header: %v", err)
	}
}

func TestECHPoolOpenTCPStreamStatusError(t *testing.T) {
	serverSession, clientSession := newProtocolNegotiationSmuxPair(t)
	oldCfg := cfg
	oldIPStrategy := ipStrategy
	t.Cleanup(func() {
		cfg = oldCfg
		ipStrategy = oldIPStrategy
	})
	cfg.DialTimeout = time.Second
	ipStrategy = IPStrategyIPv6Only

	pool := &ECHPool{
		smuxConns:   []*smux.Session{clientSession},
		channelRTT:  []int64{int64(5 * time.Millisecond)},
		channelCaps: []uint32{protocolCapabilityTCPStatus},
	}
	serverDone := make(chan error, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()
		if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		kind, strategy, target, err := readSmuxOpenHeader(stream)
		if err != nil {
			serverDone <- err
			return
		}
		if kind != streamKindTCP || strategy != IPStrategyIPv6Only || target != "blocked.example:443" {
			serverDone <- fmt.Errorf("tcp open header = kind %d strategy %d target %q", kind, strategy, target)
			return
		}
		serverDone <- writeTCPOpenStatus(stream, tcpOpenStatusError, "blocked by policy")
	}()

	if stream, chID, decision, err := pool.openTCPStream("blocked.example:443"); err == nil {
		_ = stream.Close()
		t.Fatalf("openTCPStream succeeded with chID=%d decision=%d, want remote status error", chID, decision)
	} else if !strings.Contains(err.Error(), "blocked by policy") {
		t.Fatalf("openTCPStream error = %v, want blocked by policy", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server TCP status handler: %v", err)
	}
}

func TestECHPoolOpenTCPStreamStatusOK(t *testing.T) {
	serverSession, clientSession := newProtocolNegotiationSmuxPair(t)
	oldCfg := cfg
	oldIPStrategy := ipStrategy
	t.Cleanup(func() {
		cfg = oldCfg
		ipStrategy = oldIPStrategy
	})
	cfg.DialTimeout = time.Second
	ipStrategy = IPStrategyPv6Pv4

	pool := &ECHPool{
		smuxConns:   []*smux.Session{clientSession},
		channelRTT:  []int64{int64(5 * time.Millisecond)},
		channelCaps: []uint32{protocolCapabilityTCPStatus},
	}
	serverDone := make(chan error, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()
		if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		kind, strategy, target, err := readSmuxOpenHeader(stream)
		if err != nil {
			serverDone <- err
			return
		}
		if kind != streamKindTCP || strategy != IPStrategyPv6Pv4 || target != "ok.example:443" {
			serverDone <- fmt.Errorf("tcp open header = kind %d strategy %d target %q", kind, strategy, target)
			return
		}
		serverDone <- writeTCPOpenStatus(stream, tcpOpenStatusOK, "")
	}()

	stream, chID, decision, err := pool.openTCPStream("ok.example:443")
	if err != nil {
		t.Fatalf("openTCPStream returned error: %v", err)
	}
	_ = stream.Close()
	if chID != 1 || decision != 1 {
		t.Fatalf("openTCPStream chID=%d decision=%d, want 1/1", chID, decision)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server TCP OK handler: %v", err)
	}
}

func TestECHPoolOpenTCPStreamLegacyProxiesWithoutStatus(t *testing.T) {
	serverSession, clientSession := newProtocolNegotiationSmuxPair(t)
	oldIPStrategy := ipStrategy
	t.Cleanup(func() { ipStrategy = oldIPStrategy })
	ipStrategy = IPStrategyDefault

	pool := &ECHPool{
		smuxConns:   []*smux.Session{clientSession},
		channelRTT:  []int64{int64(5 * time.Millisecond)},
		channelCaps: []uint32{0},
	}
	serverDone := make(chan error, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()
		if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		kind, strategy, target, err := readSmuxOpenHeader(stream)
		if err != nil {
			serverDone <- err
			return
		}
		if kind != streamKindTCP || strategy != IPStrategyDefault || target != "legacy.example:443" {
			serverDone <- fmt.Errorf("legacy tcp open header = kind %d strategy %d target %q", kind, strategy, target)
			return
		}
		payload := make([]byte, len("legacy-request"))
		if _, err := io.ReadFull(stream, payload); err != nil {
			serverDone <- err
			return
		}
		if string(payload) != "legacy-request" {
			serverDone <- fmt.Errorf("legacy payload = %q", payload)
			return
		}
		serverDone <- writeAll(stream, []byte("legacy-response"))
	}()

	stream, chID, decision, err := pool.openTCPStream("legacy.example:443")
	if err != nil {
		t.Fatalf("openTCPStream legacy returned error: %v", err)
	}
	defer stream.Close()
	if chID != 1 || decision != 1 {
		t.Fatalf("openTCPStream legacy chID=%d decision=%d, want 1/1", chID, decision)
	}
	if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set legacy stream deadline: %v", err)
	}
	if err := writeAll(stream, []byte("legacy-request")); err != nil {
		t.Fatalf("write legacy request bytes: %v", err)
	}
	response := make([]byte, len("legacy-response"))
	if _, err := io.ReadFull(stream, response); err != nil {
		t.Fatalf("read legacy response bytes: %v", err)
	}
	if string(response) != "legacy-response" {
		t.Fatalf("legacy response = %q, want legacy-response", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server legacy TCP handler: %v", err)
	}
}

func TestHandleLocalTCPProxiesOverSmux(t *testing.T) {
	oldPool := echPool
	oldCfg := cfg
	oldIPStrategy := ipStrategy
	t.Cleanup(func() {
		echPool = oldPool
		cfg = oldCfg
		ipStrategy = oldIPStrategy
	})
	cfg.DialTimeout = time.Second
	ipStrategy = IPStrategyPv4Pv6

	serverSession, clientSession := newProtocolNegotiationSmuxPair(t)
	echPool = &ECHPool{
		smuxConns:   []*smux.Session{clientSession},
		channelRTT:  []int64{int64(5 * time.Millisecond)},
		channelCaps: []uint32{protocolCapabilityTCPStatus},
	}

	serverDone := make(chan error, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()
		if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		kind, strategy, target, err := readSmuxOpenHeader(stream)
		if err != nil {
			serverDone <- err
			return
		}
		if kind != streamKindTCP || strategy != IPStrategyPv4Pv6 || target != "tcp.example:443" {
			serverDone <- fmt.Errorf("local TCP header = kind %d strategy %d target %q", kind, strategy, target)
			return
		}
		if err := writeTCPOpenStatus(stream, tcpOpenStatusOK, ""); err != nil {
			serverDone <- err
			return
		}
		request := make([]byte, len("tcp-forward-request"))
		if _, err := io.ReadFull(stream, request); err != nil {
			serverDone <- err
			return
		}
		if string(request) != "tcp-forward-request" {
			serverDone <- fmt.Errorf("local TCP request = %q", request)
			return
		}
		serverDone <- writeAll(stream, []byte("tcp-forward-response"))
	}()

	localServer, localClient := net.Pipe()
	_ = localClient.SetDeadline(time.Now().Add(time.Second))
	_ = localServer.SetDeadline(time.Now().Add(time.Second))
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		handleLocalTCP(localServer, "tcp.example:443")
	}()

	if err := writeAll(localClient, []byte("tcp-forward-request")); err != nil {
		t.Fatalf("write local TCP request: %v", err)
	}
	response := make([]byte, len("tcp-forward-response"))
	if _, err := io.ReadFull(localClient, response); err != nil {
		t.Fatalf("read local TCP response: %v", err)
	}
	if string(response) != "tcp-forward-response" {
		t.Fatalf("local TCP response = %q, want tcp-forward-response", response)
	}
	_ = localClient.Close()

	if err := <-serverDone; err != nil {
		t.Fatalf("server local TCP stream handler: %v", err)
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for local TCP handler shutdown")
	}
}

func TestECHPoolOpenBestStreamNoUsableSessions(t *testing.T) {
	pool := &ECHPool{}
	if _, _, _, _, err := pool.openBestStream(); err == nil {
		t.Fatal("openBestStream with empty pool returned nil error")
	}

	serverSession, clientSession := newProtocolNegotiationSmuxPair(t)
	_ = serverSession.Close()
	_ = clientSession.Close()
	pool = &ECHPool{
		smuxConns:  []*smux.Session{nil, clientSession},
		channelRTT: []int64{0, 0},
	}
	if _, _, _, _, err := pool.openBestStream(); err == nil {
		t.Fatal("openBestStream with nil/closed sessions returned nil error")
	}
}

func TestECHPoolOpenBestStreamSkipsNilSessions(t *testing.T) {
	serverSession, clientSession := newProtocolNegotiationSmuxPair(t)
	waitAccepted := expectAcceptedSmuxStream(t, serverSession)
	pool := &ECHPool{
		smuxConns:   []*smux.Session{nil, clientSession},
		channelRTT:  []int64{0, int64(5 * time.Millisecond)},
		channelCaps: []uint32{0, protocolCapabilityTCPStatus},
	}

	stream, chID, decision, caps, err := pool.openBestStream()
	if err != nil {
		t.Fatalf("openBestStream returned error: %v", err)
	}
	_ = stream.Close()
	if chID != 2 || decision != 2 || caps != protocolCapabilityTCPStatus {
		t.Fatalf("openBestStream = chID %d decision %d caps 0x%x, want 2/2/TCPStatus", chID, decision, caps)
	}
	waitAccepted()
}

func TestECHPoolOpenBestStreamRoundRobinNearRTT(t *testing.T) {
	serverSession1, clientSession1 := newProtocolNegotiationSmuxPair(t)
	serverSession2, clientSession2 := newProtocolNegotiationSmuxPair(t)
	waitAccepted1 := expectAcceptedSmuxStream(t, serverSession1)
	waitAccepted2 := expectAcceptedSmuxStream(t, serverSession2)
	pool := &ECHPool{
		smuxConns:   []*smux.Session{clientSession1, clientSession2},
		channelRTT:  []int64{int64(5 * time.Millisecond), int64(8 * time.Millisecond)},
		channelCaps: []uint32{protocolCapabilityTCP, protocolCapabilityUDP},
	}

	stream, chID, decision, caps, err := pool.openBestStream()
	if err != nil {
		t.Fatalf("first openBestStream returned error: %v", err)
	}
	_ = stream.Close()
	if chID != 1 || decision != 1 || caps != protocolCapabilityTCP {
		t.Fatalf("first openBestStream = chID %d decision %d caps 0x%x, want 1/1/TCP", chID, decision, caps)
	}

	stream, chID, decision, caps, err = pool.openBestStream()
	if err != nil {
		t.Fatalf("second openBestStream returned error: %v", err)
	}
	_ = stream.Close()
	if chID != 2 || decision != 2 || caps != protocolCapabilityUDP {
		t.Fatalf("second openBestStream = chID %d decision %d caps 0x%x, want 2/2/UDP", chID, decision, caps)
	}
	waitAccepted1()
	waitAccepted2()
}

func expectAcceptedSmuxStream(t *testing.T, sess *smux.Session) func() {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		stream, err := sess.AcceptStream()
		if err == nil {
			_ = stream.Close()
		}
		done <- err
	}()
	return func() {
		t.Helper()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("accept smux stream: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for accepted smux stream")
		}
	}
}

func TestIsLegacyProtocolHelloError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "EOF", err: io.EOF, want: true},
		{name: "unexpected EOF", err: io.ErrUnexpectedEOF, want: true},
		{name: "timeout", err: protocolTimeoutTestError{}, want: true},
		{name: "ordinary error", err: errors.New("bad magic"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLegacyProtocolHelloError(tt.err); got != tt.want {
				t.Fatalf("isLegacyProtocolHelloError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
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

func TestReadUDPReplyMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "short header", raw: []byte{0, 1, 0}},
		{name: "empty address", raw: rawUDPReplyFrame("", []byte("payload"))},
		{name: "invalid address host", raw: rawUDPReplyFrame("bad_host.example:53", nil)},
		{name: "invalid address port", raw: rawUDPReplyFrame("127.0.0.1:0", nil)},
		{name: "missing address port", raw: rawUDPReplyFrame("127.0.0.1", nil)},
		{name: "truncated address", raw: []byte{0, 4, 0, 0, '1', '.', '2'}},
		{name: "truncated payload", raw: []byte{0, 0, 0, 4, 'd', 'n'}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := readUDPReply(bytes.NewReader(tt.raw)); err == nil {
				t.Fatalf("readUDPReply accepted malformed frame %v", tt.raw)
			}
		})
	}
}

func rawUDPReplyFrame(addr string, payload []byte) []byte {
	b := []byte{byte(len(addr) >> 8), byte(len(addr)), byte(len(payload) >> 8), byte(len(payload))}
	b = append(b, addr...)
	b = append(b, payload...)
	return b
}

func TestUDPReplyRejectsOversizedFields(t *testing.T) {
	if err := writeUDPReply(io.Discard, strings.Repeat("x", 65536), nil); err == nil {
		t.Fatal("writeUDPReply accepted oversized addr")
	}
	if err := writeUDPReply(io.Discard, "1.2.3.4:53", []byte(strings.Repeat("x", 65536))); err == nil {
		t.Fatal("writeUDPReply accepted oversized payload")
	}
}

func TestUDPReplyRejectsInvalidAddress(t *testing.T) {
	for _, addr := range []string{"", "bad_host.example:53", "127.0.0.1:0", "127.0.0.1"} {
		if err := writeUDPReply(io.Discard, addr, nil); err == nil {
			t.Fatalf("writeUDPReply accepted invalid addr %q", addr)
		}
	}
}

type udpDatagramWriteFunc func([]byte, *net.UDPAddr) (int, error)

func (f udpDatagramWriteFunc) WriteToUDP(p []byte, addr *net.UDPAddr) (int, error) {
	return f(p, addr)
}

func TestWriteUDPDatagramWritesFullPayload(t *testing.T) {
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	payload := []byte("payload")
	var gotPayload []byte
	var gotAddr *net.UDPAddr
	writer := udpDatagramWriteFunc(func(p []byte, addr *net.UDPAddr) (int, error) {
		gotPayload = append([]byte(nil), p...)
		gotAddr = addr
		return len(p), nil
	})

	n, err := writeUDPDatagram(writer, payload, target)
	if err != nil {
		t.Fatalf("writeUDPDatagram returned error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("writeUDPDatagram n = %d, want %d", n, len(payload))
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("UDP payload = %q, want %q", gotPayload, payload)
	}
	if gotAddr != target {
		t.Fatalf("UDP target = %v, want %v", gotAddr, target)
	}
}

func TestWriteUDPDatagramRejectsShortWrites(t *testing.T) {
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	payload := []byte("payload")
	tests := []struct {
		name string
		n    int
	}{
		{name: "short", n: len(payload) - 1},
		{name: "over", n: len(payload) + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := udpDatagramWriteFunc(func([]byte, *net.UDPAddr) (int, error) {
				return tt.n, nil
			})
			n, err := writeUDPDatagram(writer, payload, target)
			if !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("writeUDPDatagram error = %v, want %v", err, io.ErrShortWrite)
			}
			if n != tt.n {
				t.Fatalf("writeUDPDatagram n = %d, want %d", n, tt.n)
			}
		})
	}
}

func TestWriteUDPDatagramPropagatesErrors(t *testing.T) {
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	payload := []byte("payload")
	wantErr := errors.New("write failed")
	writer := udpDatagramWriteFunc(func([]byte, *net.UDPAddr) (int, error) {
		return 3, wantErr
	})

	n, err := writeUDPDatagram(writer, payload, target)
	if !errors.Is(err, wantErr) {
		t.Fatalf("writeUDPDatagram error = %v, want %v", err, wantErr)
	}
	if n != 3 {
		t.Fatalf("writeUDPDatagram n = %d, want 3", n)
	}
}

func TestWriteUDPDatagramRejectsInvalidInputs(t *testing.T) {
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	payload := []byte("payload")
	writer := udpDatagramWriteFunc(func(p []byte, _ *net.UDPAddr) (int, error) {
		return len(p), nil
	})

	if _, err := writeUDPDatagram(nil, payload, target); err == nil {
		t.Fatal("writeUDPDatagram accepted nil writer")
	}
	if _, err := writeUDPDatagram(writer, payload, nil); err == nil {
		t.Fatal("writeUDPDatagram accepted nil target")
	}
}

type shortWriteNoErrorWriter struct{}

func (shortWriteNoErrorWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

type shortWriteNoErrorConn struct{}

func (shortWriteNoErrorConn) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func (shortWriteNoErrorConn) Write(p []byte) (int, error) {
	return shortWriteNoErrorWriter{}.Write(p)
}

func (shortWriteNoErrorConn) Close() error {
	return nil
}

func (shortWriteNoErrorConn) LocalAddr() net.Addr {
	return nil
}

func (shortWriteNoErrorConn) RemoteAddr() net.Addr {
	return nil
}

func (shortWriteNoErrorConn) SetDeadline(time.Time) error {
	return nil
}

func (shortWriteNoErrorConn) SetReadDeadline(time.Time) error {
	return nil
}

func (shortWriteNoErrorConn) SetWriteDeadline(time.Time) error {
	return nil
}

type oneByteWriter struct {
	bytes.Buffer
}

func (w *oneByteWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}

type oneByteConn struct {
	net.Conn
}

func (c oneByteConn) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return c.Conn.Write(p)
}

func TestProtocolWritersRejectShortWritesWithoutError(t *testing.T) {
	tests := []struct {
		name string
		run  func(io.Writer) error
	}{
		{name: "protocol hello", run: func(w io.Writer) error {
			return writeProtocolHello(w, ProtocolHello{Version: protocolVersion, Status: protocolStatusOK, Capabilities: currentProtocolCapabilities(), Message: "ok"})
		}},
		{name: "tcp open status", run: func(w io.Writer) error {
			return writeTCPOpenStatus(w, tcpOpenStatusError, "dial failed")
		}},
		{name: "smux open header", run: func(w io.Writer) error {
			return writeSmuxOpenHeader(w, streamKindTCP, IPStrategyDefault, "example.com:443")
		}},
		{name: "chunk", run: func(w io.Writer) error {
			return writeChunk(w, []byte("payload"))
		}},
		{name: "udp reply", run: func(w io.Writer) error {
			return writeUDPReply(w, "127.0.0.1:53", []byte("payload"))
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(shortWriteNoErrorWriter{}); err != io.ErrShortWrite {
				t.Fatalf("writer error = %v, want %v", err, io.ErrShortWrite)
			}
		})
	}
}

func TestLocalProxyResponseWritersHandleProgressiveShortWrites(t *testing.T) {
	tests := []struct {
		name string
		run  func(io.Writer) error
		want []byte
	}{
		{
			name: "SOCKS5 method selection",
			run: func(w io.Writer) error {
				return writeSOCKS5MethodSelection(w, 0x02)
			},
			want: []byte{0x05, 0x02},
		},
		{
			name: "SOCKS5 userpass reply",
			run: func(w io.Writer) error {
				return writeSOCKS5UserPassReply(w, 0x00)
			},
			want: []byte{0x01, 0x00},
		},
		{
			name: "SOCKS5 command reply",
			run: func(w io.Writer) error {
				return writeSOCKS5Reply(w, 0x07)
			},
			want: []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "SOCKS5 UDP associate reply",
			run: func(w io.Writer) error {
				return writeSOCKS5UDPAssociateReply(w, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080})
			},
			want: []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38},
		},
		{
			name: "HTTP proxy response",
			run: func(w io.Writer) error {
				return writeHTTPProxyResponse(w, "HTTP/1.1 200 OK\r\n\r\n")
			},
			want: []byte("HTTP/1.1 200 OK\r\n\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var w oneByteWriter
			if err := tt.run(&w); err != nil {
				t.Fatalf("writer returned error: %v", err)
			}
			if got := w.Bytes(); !bytes.Equal(got, tt.want) {
				t.Fatalf("writer output = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLocalProxyResponseWritersRejectShortWritesWithoutError(t *testing.T) {
	tests := []struct {
		name string
		run  func(io.Writer) error
	}{
		{
			name: "SOCKS5 method selection",
			run: func(w io.Writer) error {
				return writeSOCKS5MethodSelection(w, 0x02)
			},
		},
		{
			name: "SOCKS5 userpass reply",
			run: func(w io.Writer) error {
				return writeSOCKS5UserPassReply(w, 0x00)
			},
		},
		{
			name: "SOCKS5 command reply",
			run: func(w io.Writer) error {
				return writeSOCKS5Reply(w, 0x07)
			},
		},
		{
			name: "SOCKS5 UDP associate reply",
			run: func(w io.Writer) error {
				return writeSOCKS5UDPAssociateReply(w, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080})
			},
		},
		{
			name: "HTTP proxy response",
			run: func(w io.Writer) error {
				return writeHTTPProxyResponse(w, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(shortWriteNoErrorWriter{}); err != io.ErrShortWrite {
				t.Fatalf("writer error = %v, want %v", err, io.ErrShortWrite)
			}
		})
	}
}

func TestWriteSOCKS5UDPAssociateReplyRejectsInvalidAddress(t *testing.T) {
	tests := []struct {
		name string
		addr *net.UDPAddr
	}{
		{name: "nil", addr: nil},
		{name: "zero port", addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}},
		{name: "invalid ip", addr: &net.UDPAddr{Port: 1080}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := writeSOCKS5UDPAssociateReply(io.Discard, tt.addr); err == nil {
				t.Fatal("writeSOCKS5UDPAssociateReply accepted invalid address")
			}
		})
	}
}

func TestWriteAllHandlesProgressiveShortWrites(t *testing.T) {
	var w oneByteWriter
	if err := writeAll(&w, []byte("payload")); err != nil {
		t.Fatalf("writeAll returned error: %v", err)
	}
	if got := w.String(); got != "payload" {
		t.Fatalf("writeAll wrote %q, want payload", got)
	}
}

func TestWriteAllCountHandlesProgressiveShortWrites(t *testing.T) {
	var w oneByteWriter
	n, err := writeAllCount(&w, []byte("payload"))
	if err != nil {
		t.Fatalf("writeAllCount returned error: %v", err)
	}
	if n != len("payload") {
		t.Fatalf("writeAllCount wrote %d bytes, want %d", n, len("payload"))
	}
	if got := w.String(); got != "payload" {
		t.Fatalf("writeAllCount wrote %q, want payload", got)
	}
}

func TestWriteAllCountRejectsShortWritesWithoutProgress(t *testing.T) {
	n, err := writeAllCount(shortWriteNoErrorWriter{}, []byte("payload"))
	if err != io.ErrShortWrite {
		t.Fatalf("writeAllCount error = %v, want %v", err, io.ErrShortWrite)
	}
	if n != len("payload")-1 {
		t.Fatalf("writeAllCount wrote %d bytes, want %d", n, len("payload")-1)
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

func FuzzParseSOCKS5UDPPacket(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 1, 1, 1, 2, 3, 4, 0, 53})
	for _, seed := range []struct {
		host string
		port int
		data []byte
	}{
		{host: "1.2.3.4", port: 53, data: []byte("dns")},
		{host: "example.com", port: 443, data: []byte("payload")},
		{host: "2001:db8::1", port: 853, data: []byte("v6")},
	} {
		packet, err := buildSOCKS5UDPPacket(seed.host, seed.port, seed.data)
		if err != nil {
			f.Fatalf("seed SOCKS5 UDP packet: %v", err)
		}
		f.Add(packet)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		target, payload, err := parseSOCKS5UDPPacket(raw)
		if err != nil {
			return
		}
		if target == "" {
			t.Fatal("parseSOCKS5UDPPacket returned empty target")
		}
		if len(payload) > len(raw) {
			t.Fatalf("parseSOCKS5UDPPacket payload length %d exceeds raw length %d", len(payload), len(raw))
		}
	})
}

func FuzzParseSOCKS5UDPResp(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 9, 0, 53})
	for _, seed := range []struct {
		host string
		port int
		data []byte
	}{
		{host: "1.2.3.4", port: 53, data: []byte("dns")},
		{host: "example.com", port: 443, data: []byte("payload")},
		{host: "2001:db8::1", port: 853, data: []byte("v6")},
	} {
		packet, err := buildSOCKS5UDPPacket(seed.host, seed.port, seed.data)
		if err != nil {
			f.Fatalf("seed SOCKS5 UDP response: %v", err)
		}
		f.Add(packet)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		addr, payload, err := parseSOCKS5UDPResp(raw)
		if err != nil {
			return
		}
		if addr == "" {
			t.Fatal("parseSOCKS5UDPResp returned empty addr")
		}
		if len(payload) > len(raw) {
			t.Fatalf("parseSOCKS5UDPResp payload length %d exceeds raw length %d", len(payload), len(raw))
		}
	})
}

func FuzzParseDNSResponse(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	seed, err := dnsHTTPSResponseSeed([]byte("ech"))
	if err != nil {
		f.Fatalf("seed DNS response: %v", err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		ech, err := parseDNSResponse(raw)
		if err != nil {
			return
		}
		if ech != "" {
			if _, err := base64.StdEncoding.DecodeString(ech); err != nil {
				t.Fatalf("parseDNSResponse returned invalid base64 ECH: %v", err)
			}
		}
	})
}

func FuzzParseHTTPSRecord(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 0})
	f.Add([]byte{0, 1, 0, 0, 5, 0, 3, 'e', 'c', 'h'})
	f.Add([]byte{0, 1, 0, 0, 5, 0, 4, 'e', 'c'})
	f.Fuzz(func(t *testing.T, raw []byte) {
		ech := parseHTTPSRecord(raw)
		if ech != "" {
			if _, err := base64.StdEncoding.DecodeString(ech); err != nil {
				t.Fatalf("parseHTTPSRecord returned invalid base64 ECH: %v", err)
			}
		}
	})
}

func dnsHTTPSResponseSeed(ech []byte) ([]byte, error) {
	query, err := buildDNSQuery("example.com", typeHTTPS)
	if err != nil {
		return nil, err
	}
	response := append([]byte(nil), query...)
	response[2], response[3] = 0x81, 0x80
	response[6], response[7] = 0, 1
	rdata := []byte{0, 1, 0, 0, 5, byte(len(ech) >> 8), byte(len(ech))}
	rdata = append(rdata, ech...)
	answer := []byte{
		0xC0, 0x0C,
		byte(typeHTTPS >> 8), byte(typeHTTPS),
		0, 1,
		0, 0, 0, 60,
		byte(len(rdata) >> 8), byte(len(rdata)),
	}
	response = append(response, answer...)
	response = append(response, rdata...)
	return response, nil
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

func TestSOCKS5UDPPacketAcceptsShortDomainWithoutPayload(t *testing.T) {
	packet, err := buildSOCKS5UDPPacket("a", 53, nil)
	if err != nil {
		t.Fatalf("buildSOCKS5UDPPacket returned error: %v", err)
	}
	target, payload, err := parseSOCKS5UDPPacket(packet)
	if err != nil {
		t.Fatalf("parseSOCKS5UDPPacket returned error: %v", err)
	}
	if target != "a:53" || len(payload) != 0 {
		t.Fatalf("parseSOCKS5UDPPacket = target %q payload %q, want a:53 empty payload", target, payload)
	}
}

func TestSOCKS5UDPPacketMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "too short", raw: []byte{0, 0, 0}},
		{name: "nonzero reserved high", raw: []byte{1, 0, 0, 1, 1, 2, 3, 4, 0, 53}},
		{name: "nonzero reserved low", raw: []byte{0, 1, 0, 1, 1, 2, 3, 4, 0, 53}},
		{name: "fragmented", raw: []byte{0, 0, 1, 1, 1, 2, 3, 4, 0, 53}},
		{name: "unknown atyp", raw: []byte{0, 0, 0, 9, 0, 53}},
		{name: "empty domain", raw: []byte{0, 0, 0, 3, 0, 0, 53}},
		{name: "invalid domain", raw: append([]byte{0, 0, 0, 3, 16}, append([]byte("bad_host.example"), 0, 53)...)},
		{name: "truncated domain", raw: []byte{0, 0, 0, 3, 5, 'a'}},
		{name: "truncated port", raw: []byte{0, 0, 0, 1, 1, 2, 3, 4, 0}},
		{name: "zero port", raw: []byte{0, 0, 0, 1, 1, 2, 3, 4, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := parseSOCKS5UDPPacket(tt.raw); err == nil {
				t.Fatalf("parseSOCKS5UDPPacket accepted malformed packet %v", tt.raw)
			}
		})
	}
}

func TestSOCKS5UDPRespParsesIPv6Address(t *testing.T) {
	packet, err := buildSOCKS5UDPPacket("2001:db8::1", 853, []byte("dns"))
	if err != nil {
		t.Fatalf("buildSOCKS5UDPPacket returned error: %v", err)
	}
	addr, payload, err := parseSOCKS5UDPResp(packet)
	if err != nil {
		t.Fatalf("parseSOCKS5UDPResp returned error: %v", err)
	}
	if addr != "[2001:db8::1]:853" || !bytes.Equal(payload, []byte("dns")) {
		t.Fatalf("parseSOCKS5UDPResp = addr %q payload %q, want [2001:db8::1]:853 dns", addr, payload)
	}
}

func TestSOCKS5UDPRespAcceptsShortDomainWithoutPayload(t *testing.T) {
	packet, err := buildSOCKS5UDPPacket("a", 53, nil)
	if err != nil {
		t.Fatalf("buildSOCKS5UDPPacket returned error: %v", err)
	}
	addr, payload, err := parseSOCKS5UDPResp(packet)
	if err != nil {
		t.Fatalf("parseSOCKS5UDPResp returned error: %v", err)
	}
	if addr != "a:53" || len(payload) != 0 {
		t.Fatalf("parseSOCKS5UDPResp = addr %q payload %q, want a:53 empty payload", addr, payload)
	}
}

func TestSOCKS5UDPRespMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "too short", raw: []byte{0, 0, 0}},
		{name: "nonzero reserved high", raw: []byte{1, 0, 0, 1, 1, 2, 3, 4, 0, 53}},
		{name: "nonzero reserved low", raw: []byte{0, 1, 0, 1, 1, 2, 3, 4, 0, 53}},
		{name: "fragmented", raw: []byte{0, 0, 1, 1, 1, 2, 3, 4, 0, 53}},
		{name: "unknown atyp", raw: []byte{0, 0, 0, 9, 0, 53}},
		{name: "empty domain", raw: []byte{0, 0, 0, 3, 0, 0, 53}},
		{name: "invalid domain", raw: append([]byte{0, 0, 0, 3, 16}, append([]byte("bad_host.example"), 0, 53)...)},
		{name: "truncated domain", raw: []byte{0, 0, 0, 3, 5, 'a'}},
		{name: "truncated port", raw: []byte{0, 0, 0, 1, 1, 2, 3, 4, 0}},
		{name: "zero port", raw: []byte{0, 0, 0, 1, 1, 2, 3, 4, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := parseSOCKS5UDPResp(tt.raw); err == nil {
				t.Fatalf("parseSOCKS5UDPResp accepted malformed packet %v", tt.raw)
			}
		})
	}
}

func TestResolveUDPWithStrategyRejectsInvalidPort(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		strategy byte
	}{
		{name: "zero port", addr: "127.0.0.1:0", strategy: IPStrategyDefault},
		{name: "overflow port", addr: "127.0.0.1:65536", strategy: IPStrategyPv4Pv6},
		{name: "non numeric port", addr: "localhost:notaport", strategy: IPStrategyIPv4Only},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := resolveUDPWithStrategy(tt.addr, tt.strategy); err == nil {
				t.Fatalf("resolveUDPWithStrategy(%q, %d) accepted invalid port", tt.addr, tt.strategy)
			}
		})
	}
}

func TestResolveUDPWithStrategyLiteralIPs(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		strategy byte
		wantIP   net.IP
		wantPort int
	}{
		{name: "ipv4 ignores ipv6 only strategy", addr: "127.0.0.1:53", strategy: IPStrategyIPv6Only, wantIP: net.IPv4(127, 0, 0, 1), wantPort: 53},
		{name: "ipv6 ignores ipv4 only strategy", addr: "[::1]:5353", strategy: IPStrategyIPv4Only, wantIP: net.ParseIP("::1"), wantPort: 5353},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveUDPWithStrategy(tt.addr, tt.strategy)
			if err != nil {
				t.Fatalf("resolveUDPWithStrategy(%q, %d) returned error: %v", tt.addr, tt.strategy, err)
			}
			if !got.IP.Equal(tt.wantIP) || got.Port != tt.wantPort {
				t.Fatalf("resolveUDPWithStrategy(%q, %d) = %s, want %s:%d", tt.addr, tt.strategy, got, tt.wantIP, tt.wantPort)
			}
		})
	}
}

func TestResolveUDPWithStrategyLocalhostFamilies(t *testing.T) {
	oldCfg := cfg
	defer func() {
		cfg = oldCfg
	}()
	cfg.DialTimeout = time.Second

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, "localhost")
	if err != nil {
		t.Skipf("localhost resolution unavailable: %v", err)
	}
	hasV4, hasV6 := false, false
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			hasV4 = true
		} else if ip.IP.To16() != nil {
			hasV6 = true
		}
	}

	if hasV4 {
		got, err := resolveUDPWithStrategy("localhost:53", IPStrategyIPv4Only)
		if err != nil {
			t.Fatalf("resolveUDPWithStrategy IPv4-only localhost returned error: %v", err)
		}
		if got.IP.To4() == nil {
			t.Fatalf("IPv4-only localhost resolved to %s, want IPv4", got)
		}
	}
	if hasV6 {
		got, err := resolveUDPWithStrategy("localhost:53", IPStrategyIPv6Only)
		if err != nil {
			t.Fatalf("resolveUDPWithStrategy IPv6-only localhost returned error: %v", err)
		}
		if got.IP.To4() != nil {
			t.Fatalf("IPv6-only localhost resolved to %s, want IPv6", got)
		}
	}
	if hasV4 && hasV6 {
		got, err := resolveUDPWithStrategy("localhost:53", IPStrategyPv4Pv6)
		if err != nil {
			t.Fatalf("resolveUDPWithStrategy IPv4-preferred localhost returned error: %v", err)
		}
		if got.IP.To4() == nil {
			t.Fatalf("IPv4-preferred localhost resolved to %s, want IPv4", got)
		}
		got, err = resolveUDPWithStrategy("localhost:53", IPStrategyPv6Pv4)
		if err != nil {
			t.Fatalf("resolveUDPWithStrategy IPv6-preferred localhost returned error: %v", err)
		}
		if got.IP.To4() != nil {
			t.Fatalf("IPv6-preferred localhost resolved to %s, want IPv6", got)
		}
	}
}

func TestUDPAssociationHandleUDPResponseRejectsInvalidPort(t *testing.T) {
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen relay udp: %v", err)
	}
	defer relayConn.Close()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer clientConn.Close()

	assoc := &UDPAssociation{
		udpListener:   relayConn,
		clientUDPAddr: clientConn.LocalAddr().(*net.UDPAddr),
	}
	for _, addr := range []string{
		"127.0.0.1:0",
		"127.0.0.1:65536",
		"127.0.0.1:notaport",
	} {
		assoc.handleUDPResponse(addr, []byte("drop"))
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set client udp deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := clientConn.ReadFromUDP(buf)
	if err == nil {
		t.Fatalf("received UDP response for invalid port: %x", buf[:n])
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read UDP response error = %v, want timeout", err)
	}
}

func TestUDPAssociationSendWritesBoundTarget(t *testing.T) {
	clientStream, serverStream := openRawAcceptedSmuxTestStream(t)
	assoc := &UDPAssociation{
		id:        1,
		receiving: true,
		target:    "127.0.0.1:53",
		stream:    clientStream,
	}
	payload := []byte("dns-query")

	assoc.send("127.0.0.1:53", payload)

	if err := serverStream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set server stream deadline: %v", err)
	}
	got, err := readChunk(serverStream)
	if err != nil {
		t.Fatalf("read UDP stream chunk: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("UDP stream chunk = %q, want %q", got, payload)
	}
}

func TestUDPAssociationSendDropsChangedTarget(t *testing.T) {
	clientStream, serverStream := openRawAcceptedSmuxTestStream(t)
	assoc := &UDPAssociation{
		id:        2,
		receiving: true,
		target:    "127.0.0.1:53",
		stream:    clientStream,
	}

	assoc.send("127.0.0.1:54", []byte("leak"))

	if assoc.target != "127.0.0.1:53" {
		t.Fatalf("association target = %q, want original target", assoc.target)
	}
	if err := serverStream.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set server stream deadline: %v", err)
	}
	if got, err := readChunk(serverStream); err == nil {
		t.Fatalf("changed target wrote UDP stream chunk %q", got)
	}
}

func TestBuildSOCKS5UDPPacketRejectsOversizedDomain(t *testing.T) {
	if _, err := buildSOCKS5UDPPacket(strings.Repeat("x", 256), 53, nil); err == nil {
		t.Fatal("buildSOCKS5UDPPacket accepted oversized domain")
	}
}

func TestBuildSOCKS5UDPPacketRejectsEmptyHost(t *testing.T) {
	if _, err := buildSOCKS5UDPPacket("", 53, nil); err == nil {
		t.Fatal("buildSOCKS5UDPPacket accepted empty host")
	}
}

func TestBuildSOCKS5UDPPacketRejectsInvalidDomain(t *testing.T) {
	for _, host := range []string{"bad_host.example", "-bad.example", "bad-.example", "example..com"} {
		if _, err := buildSOCKS5UDPPacket(host, 53, nil); err == nil {
			t.Fatalf("buildSOCKS5UDPPacket accepted invalid domain %q", host)
		}
	}
}

func TestBuildSOCKS5UDPPacketRejectsInvalidPort(t *testing.T) {
	for _, port := range []int{-1, 0, 65536, 70000} {
		if _, err := buildSOCKS5UDPPacket("127.0.0.1", port, nil); err == nil {
			t.Fatalf("buildSOCKS5UDPPacket accepted invalid port %d", port)
		}
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
