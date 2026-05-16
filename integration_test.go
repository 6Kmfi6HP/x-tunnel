package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const integrationIOTimeout = 5 * time.Second

var (
	integrationBuildOnce   sync.Once
	integrationBuildDir    string
	integrationBuildPath   string
	integrationBuildOutput []byte
	integrationBuildErr    error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if integrationBuildDir != "" {
		_ = os.RemoveAll(integrationBuildDir)
	}
	os.Exit(code)
}

func buildIntegrationBinary(t *testing.T, ctx context.Context) string {
	t.Helper()
	integrationBuildOnce.Do(func() {
		integrationBuildDir, integrationBuildErr = os.MkdirTemp("", "x-tunnel-integration-")
		if integrationBuildErr != nil {
			return
		}
		integrationBuildPath = filepath.Join(integrationBuildDir, "x-tunnel")
		build := exec.CommandContext(ctx, "go", "build", "-o", integrationBuildPath, ".")
		integrationBuildOutput, integrationBuildErr = build.CombinedOutput()
	})
	if integrationBuildErr != nil {
		t.Fatalf("go build failed: %v\n%s", integrationBuildErr, integrationBuildOutput)
	}
	return integrationBuildPath
}

func TestLocalTunnelIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const body = "x-tunnel integration payload\n"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()
	targetAddr := strings.TrimPrefix(origin.URL, "http://")
	_, targetPort, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split origin addr: %v", err)
	}
	localhostTargetAddr := net.JoinHostPort("localhost", targetPort)

	binPath := buildIntegrationBinary(t, ctx)

	wsAddr := freeTCPAddr(t)
	socksAddr := freeTCPAddr(t)
	tcpAddr := freeTCPAddr(t)
	httpProxyAddr := freeTCPAddr(t)
	metricsAddr := freeTCPAddr(t)
	clientMetricsAddr := freeTCPAddr(t)

	serverLog := filepath.Join(t.TempDir(), "server.log")
	clientLog := filepath.Join(t.TempDir(), "client.log")
	badClientLog := filepath.Join(t.TempDir(), "bad-client.log")

	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "ws://"+wsAddr+"/tunnel",
		"-token", "integration-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "127.0.0.0/8",
		"-allow-host", "localhost",
		"-metrics", metricsAddr,
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wsAddr, server)
	waitTCP(t, ctx, metricsAddr, server)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "socks5://"+socksAddr+",tcp://"+tcpAddr+"/"+targetAddr+",http://"+httpProxyAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "integration-token",
		"-n", "1",
		"-metrics", clientMetricsAddr,
	)
	defer stopProcess(client)
	waitTCP(t, ctx, socksAddr, client)
	waitTCP(t, ctx, tcpAddr, client)
	waitTCP(t, ctx, httpProxyAddr, client)
	waitTCP(t, ctx, clientMetricsAddr, client)
	waitLogContains(t, ctx, clientLog, "协议协商成功", client)
	waitLogContains(t, ctx, serverLog, "协议协商成功", server)

	assertBody(t, "tcp forward", fetchHTTP(t, "http://"+tcpAddr+"/payload"), body)
	assertBody(t, "http proxy", fetchViaHTTPProxy(t, httpProxyAddr, "http://"+targetAddr+"/payload"), body)
	assertBody(t, "http proxy allow-host", fetchViaHTTPProxy(t, httpProxyAddr, "http://"+localhostTargetAddr+"/payload"), body)
	assertBody(t, "http connect", fetchViaHTTPConnect(t, httpProxyAddr, targetAddr, "/payload"), body)
	assertBody(t, "socks5", fetchViaSOCKS5(t, socksAddr, targetAddr, "/payload"), body)
	udpTargetAddr := startUDPEcho(t)
	assertBody(t, "socks5 udp", string(fetchUDPViaSOCKS5(t, socksAddr, udpTargetAddr, []byte("ping"))), "echo:ping")
	serverMetrics := fetchHTTP(t, "http://"+metricsAddr+"/metrics")
	assertMetrics(t, serverMetrics)
	assertMetricValue(t, serverMetrics, "x_tunnel_server_protocol_negotiations_total", "1")
	clientMetrics := fetchHTTP(t, "http://"+clientMetricsAddr+"/metrics")
	assertMetrics(t, clientMetrics)
	assertMetricValue(t, clientMetrics, "x_tunnel_client_protocol_negotiations_total", "1")
	assertMetricPresent(t, clientMetrics, "x_tunnel_client_rtt_probe_failures_total")
	assertMetricPresent(t, clientMetrics, "x_tunnel_client_channel_rtt_seconds")
	assertMetricValue(t, clientMetrics, `x_tunnel_client_channel_up{channel="1"}`, "1")
	assertMetricValue(
		t,
		clientMetrics,
		`x_tunnel_client_channel_capabilities{channel="1"}`,
		strconv.FormatUint(uint64(currentProtocolCapabilities()), 10),
	)

	badClient := startXTunnel(t, ctx, binPath, badClientLog,
		"-l", "socks5://"+freeTCPAddr(t),
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "wrong-token",
		"-n", "1",
	)
	defer stopProcess(badClient)
	waitLogContains(t, ctx, badClientLog, "认证失败", badClient)
	waitLogContains(t, ctx, serverLog, "Token 认证失败", server)
	assertMetricValue(t, fetchHTTP(t, "http://"+metricsAddr+"/metrics"), "x_tunnel_server_auth_rejections_total", "1")
}

func TestIntegrationLocalProxyAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const body = "x-tunnel local proxy auth payload\n"
	originHeaders := make(chan http.Header, 10)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHeaders <- r.Header.Clone()
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()
	targetAddr := strings.TrimPrefix(origin.URL, "http://")

	binPath := buildIntegrationBinary(t, ctx)

	wsAddr := freeTCPAddr(t)
	socksAddr := freeTCPAddr(t)
	httpProxyAddr := freeTCPAddr(t)
	serverLog := filepath.Join(t.TempDir(), "proxy-auth-server.log")
	clientLog := filepath.Join(t.TempDir(), "proxy-auth-client.log")

	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "ws://"+wsAddr+"/tunnel",
		"-token", "proxy-auth-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "127.0.0.0/8",
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wsAddr, server)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "socks5://user:pass@"+socksAddr+",http://user:pass@"+httpProxyAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "proxy-auth-token",
		"-n", "1",
	)
	defer stopProcess(client)
	waitTCP(t, ctx, socksAddr, client)
	waitTCP(t, ctx, httpProxyAddr, client)
	waitLogContains(t, ctx, clientLog, "协议协商成功", client)
	waitLogContains(t, ctx, serverLog, "协议协商成功", server)

	assertHTTPProxyAuthChallenge(t, "HTTP proxy without auth", fetchViaHTTPProxyAuthChallenge(t, httpProxyAddr, "http://"+targetAddr+"/payload", "", ""))
	assertHTTPProxyAuthChallenge(t, "HTTP proxy wrong auth", fetchViaHTTPProxyAuthChallenge(t, httpProxyAddr, "http://"+targetAddr+"/payload", "user", "wrong"))
	assertHTTPConnectAuthChallenge(t, httpProxyAddr, targetAddr, "", "")
	assertHTTPConnectAuthChallenge(t, httpProxyAddr, targetAddr, "user", "wrong")
	assertBody(t, "http proxy auth", fetchViaHTTPProxyWithAuth(t, httpProxyAddr, "http://"+targetAddr+"/payload", "user", "pass"), body)
	assertOriginHeaderAbsent(t, originHeaders, "Proxy-Authorization")
	rawHeaders := rawHTTPProxyGETWithAuth(t, httpProxyAddr, "http://"+targetAddr+"/headers", "user", "pass", originHeaders, map[string]string{
		"Proxy-Connection": "keep-alive",
		"Connection":       "X-Hop",
		"Via":              "1.0 upstream-proxy",
		"X-Hop":            "drop-me",
		"X-End-To-End":     "keep-me",
	})
	assertHeaderAbsent(t, rawHeaders, "Proxy-Authorization")
	assertHeaderAbsent(t, rawHeaders, "Proxy-Connection")
	assertHeaderAbsent(t, rawHeaders, "Connection")
	assertHeaderAbsent(t, rawHeaders, "X-Hop")
	assertHeaderValue(t, rawHeaders, "X-End-To-End", "keep-me")
	assertHeaderContainsValue(t, rawHeaders, "Via", "1.0 upstream-proxy")
	assertHeaderContainsValue(t, rawHeaders, "Via", httpProxyViaValue)
	assertBody(t, "http connect auth", fetchViaHTTPConnectWithAuth(t, httpProxyAddr, targetAddr, "/payload", "user", "pass"), body)
	assertOriginHeaderAbsent(t, originHeaders, "Via")

	if got := socks5SelectedMethod(t, socksAddr, []byte{0x00}); got != 0xff {
		t.Fatalf("SOCKS5 selected method without username/password support = 0x%02x, want 0xff", got)
	}
	if got := socks5UserPassAuthStatus(t, socksAddr, "user", "wrong"); got != 0x01 {
		t.Fatalf("SOCKS5 wrong auth status = %d, want 1", got)
	}
	assertBody(t, "socks5 auth", fetchViaSOCKS5WithAuth(t, socksAddr, targetAddr, "/payload", "user", "pass"), body)
}

func TestIntegrationUpstreamSOCKS5Auth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const body = "x-tunnel upstream socks auth payload\n"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()
	targetAddr := strings.TrimPrefix(origin.URL, "http://")
	upstreamAddr := startAuthSOCKS5TCPProxy(t, "upuser", "uppass")

	binPath := buildIntegrationBinary(t, ctx)

	okWSAddr := freeTCPAddr(t)
	okHTTPProxyAddr := freeTCPAddr(t)
	okServerLog := filepath.Join(t.TempDir(), "upstream-socks-ok-server.log")
	okClientLog := filepath.Join(t.TempDir(), "upstream-socks-ok-client.log")

	okServer := startXTunnel(t, ctx, binPath, okServerLog,
		"-l", "ws://"+okWSAddr+"/tunnel",
		"-token", "upstream-socks-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "127.0.0.0/8",
		"-f", "socks5://upuser:uppass@"+upstreamAddr,
	)
	defer stopProcess(okServer)
	waitTCP(t, ctx, okWSAddr, okServer)

	okClient := startXTunnel(t, ctx, binPath, okClientLog,
		"-l", "http://"+okHTTPProxyAddr,
		"-f", "ws://"+okWSAddr+"/tunnel",
		"-token", "upstream-socks-token",
		"-n", "1",
	)
	defer stopProcess(okClient)
	waitTCP(t, ctx, okHTTPProxyAddr, okClient)
	waitLogContains(t, ctx, okClientLog, "协议协商成功", okClient)
	assertBody(t, "upstream socks auth", fetchViaHTTPProxy(t, okHTTPProxyAddr, "http://"+targetAddr+"/payload"), body)

	badWSAddr := freeTCPAddr(t)
	badHTTPProxyAddr := freeTCPAddr(t)
	badServerLog := filepath.Join(t.TempDir(), "upstream-socks-bad-server.log")
	badClientLog := filepath.Join(t.TempDir(), "upstream-socks-bad-client.log")

	badServer := startXTunnel(t, ctx, binPath, badServerLog,
		"-l", "ws://"+badWSAddr+"/tunnel",
		"-token", "upstream-socks-bad-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "127.0.0.0/8",
		"-f", "socks5://upuser:wrong@"+upstreamAddr,
	)
	defer stopProcess(badServer)
	waitTCP(t, ctx, badWSAddr, badServer)

	badClient := startXTunnel(t, ctx, binPath, badClientLog,
		"-l", "http://"+badHTTPProxyAddr,
		"-f", "ws://"+badWSAddr+"/tunnel",
		"-token", "upstream-socks-bad-token",
		"-n", "1",
	)
	defer stopProcess(badClient)
	waitTCP(t, ctx, badHTTPProxyAddr, badClient)
	waitLogContains(t, ctx, badClientLog, "协议协商成功", badClient)
	if got := fetchViaHTTPProxyStatus(t, badHTTPProxyAddr, "http://"+targetAddr+"/payload"); got != http.StatusBadGateway {
		t.Fatalf("HTTP proxy status with bad upstream SOCKS5 auth = %d, want %d", got, http.StatusBadGateway)
	}
	waitLogContains(t, ctx, badServerLog, "SOCKS5握手失败", badServer)
}

func TestIntegrationLocalWSSFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const body = "x-tunnel wss fallback payload\n"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()
	targetAddr := strings.TrimPrefix(origin.URL, "http://")

	binPath := buildIntegrationBinary(t, ctx)

	wssAddr := freeTCPAddr(t)
	tcpAddr := freeTCPAddr(t)
	serverLog := filepath.Join(t.TempDir(), "wss-server.log")
	clientLog := filepath.Join(t.TempDir(), "wss-client.log")

	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "wss://"+wssAddr+"/tunnel",
		"-token", "wss-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "127.0.0.0/8",
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wssAddr, server)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "tcp://"+tcpAddr+"/"+targetAddr,
		"-f", "wss://"+wssAddr+"/tunnel",
		"-token", "wss-token",
		"-n", "1",
		"-insecure",
	)
	defer stopProcess(client)
	waitTCP(t, ctx, tcpAddr, client)
	waitLogContains(t, ctx, clientLog, "fallback 模式已启用", client)
	waitLogContains(t, ctx, clientLog, "协议协商成功", client)
	waitLogContains(t, ctx, serverLog, "协议协商成功", server)

	assertBody(t, "wss tcp forward", fetchHTTP(t, "http://"+tcpAddr+"/payload"), body)
}

func TestIntegrationLocalWSSMTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const body = "x-tunnel mtls payload\n"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()
	targetAddr := strings.TrimPrefix(origin.URL, "http://")

	binPath := buildIntegrationBinary(t, ctx)
	caPath, clientCertPath, clientKeyPath := writeClientMTLSFiles(t)

	wssAddr := freeTCPAddr(t)
	tcpAddr := freeTCPAddr(t)
	serverLog := filepath.Join(t.TempDir(), "mtls-server.log")
	clientLog := filepath.Join(t.TempDir(), "mtls-client.log")
	badClientLog := filepath.Join(t.TempDir(), "mtls-bad-client.log")

	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "wss://"+wssAddr+"/tunnel",
		"-token", "mtls-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "127.0.0.0/8",
		"-client-ca", caPath,
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wssAddr, server)
	waitLogContains(t, ctx, serverLog, "mTLS 客户端证书认证已启用", server)

	badClient := startXTunnel(t, ctx, binPath, badClientLog,
		"-l", "tcp://"+freeTCPAddr(t)+"/"+targetAddr,
		"-f", "wss://"+wssAddr+"/tunnel",
		"-token", "mtls-token",
		"-n", "1",
		"-insecure",
	)
	defer stopProcess(badClient)
	waitLogContains(t, ctx, badClientLog, "连接失败", badClient)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "tcp://"+tcpAddr+"/"+targetAddr,
		"-f", "wss://"+wssAddr+"/tunnel",
		"-token", "mtls-token",
		"-n", "1",
		"-insecure",
		"-client-cert", clientCertPath,
		"-client-key", clientKeyPath,
	)
	defer stopProcess(client)
	waitTCP(t, ctx, tcpAddr, client)
	waitLogContains(t, ctx, clientLog, "协议协商成功", client)
	waitLogContains(t, ctx, serverLog, "协议协商成功", server)

	assertBody(t, "wss mtls tcp forward", fetchHTTP(t, "http://"+tcpAddr+"/payload"), body)
}

func TestIntegrationMaxClientsRejectsNewClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const body = "x-tunnel max clients surviving session\n"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()
	targetAddr := strings.TrimPrefix(origin.URL, "http://")

	binPath := buildIntegrationBinary(t, ctx)

	wsAddr := freeTCPAddr(t)
	metricsAddr := freeTCPAddr(t)
	firstSocksAddr := freeTCPAddr(t)
	secondSocksAddr := freeTCPAddr(t)
	serverLog := filepath.Join(t.TempDir(), "max-clients-server.log")
	firstClientLog := filepath.Join(t.TempDir(), "max-clients-first.log")
	secondClientLog := filepath.Join(t.TempDir(), "max-clients-second.log")

	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "ws://"+wsAddr+"/tunnel",
		"-token", "max-clients-token",
		"-cidr", "127.0.0.1/32",
		"-max-clients", "1",
		"-metrics", metricsAddr,
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wsAddr, server)
	waitTCP(t, ctx, metricsAddr, server)

	firstClient := startXTunnel(t, ctx, binPath, firstClientLog,
		"-l", "socks5://"+firstSocksAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "max-clients-token",
		"-n", "1",
	)
	defer stopProcess(firstClient)
	waitTCP(t, ctx, firstSocksAddr, firstClient)
	waitLogContains(t, ctx, firstClientLog, "协议协商成功", firstClient)

	secondClient := startXTunnel(t, ctx, binPath, secondClientLog,
		"-l", "socks5://"+secondSocksAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "max-clients-token",
		"-n", "1",
	)
	defer stopProcess(secondClient)
	waitTCP(t, ctx, secondSocksAddr, secondClient)
	waitLogContains(t, ctx, serverLog, "拒绝客户端会话", server)
	waitLogContains(t, ctx, secondClientLog, "协议协商失败", secondClient)
	assertMetricValue(t, fetchHTTP(t, "http://"+metricsAddr+"/metrics"), "x_tunnel_server_client_session_rejections_total", "1")
	assertBody(t, "first client after max-clients rejection", fetchViaSOCKS5(t, firstSocksAddr, targetAddr, "/payload"), body)
}

func TestIntegrationSourceCIDRRejectionMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	binPath := buildIntegrationBinary(t, ctx)

	wsAddr := freeTCPAddr(t)
	metricsAddr := freeTCPAddr(t)
	serverLog := filepath.Join(t.TempDir(), "source-cidr-server.log")

	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "ws://"+wsAddr+"/tunnel",
		"-token", "source-cidr-token",
		"-cidr", "192.0.2.0/24",
		"-metrics", metricsAddr,
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wsAddr, server)
	waitTCP(t, ctx, metricsAddr, server)

	if got := fetchHTTPStatus(t, "http://"+wsAddr+"/tunnel"); got != http.StatusForbidden {
		t.Fatalf("source CIDR rejection status = %d, want %d", got, http.StatusForbidden)
	}
	assertMetricValue(t, fetchHTTP(t, "http://"+metricsAddr+"/metrics"), "x_tunnel_server_source_rejections_total", "1")
}

func TestIntegrationStartupValidationFailures(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	binPath := buildIntegrationBinary(t, ctx)

	longCredential := strings.Repeat("u", 256)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "bad metrics address",
			args: []string{"-l", "socks5://127.0.0.1:11080", "-f", "ws://127.0.0.1:1/tunnel", "-metrics", "bad"},
			want: "metrics 地址无效",
		},
		{
			name: "bad listener auth",
			args: []string{"-l", "socks5://user@127.0.0.1:11080", "-f", "ws://127.0.0.1:1/tunnel"},
			want: "监听地址无效",
		},
		{
			name: "bad source cidr",
			args: []string{"-l", "ws://127.0.0.1:18080/tunnel", "-token", "startup-smoke-token", "-cidr", "not-a-cidr"},
			want: "source CIDR 配置无效",
		},
		{
			name: "bad ip strategy",
			args: []string{"-l", "socks5://127.0.0.1:11080", "-f", "ws://127.0.0.1:1/tunnel", "-ips", "banana"},
			want: "-ips 参数无效",
		},
		{
			name: "bad upstream socks auth",
			args: []string{"-l", "ws://127.0.0.1:18080/tunnel", "-token", "startup-smoke-token", "-f", "socks5://" + longCredential + ":pass@127.0.0.1:1080"},
			want: "解析SOCKS5代理地址失败",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caseCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			runXTunnelExpectStartupFailure(t, caseCtx, binPath, tt.args, "[配置]", tt.want)
		})
	}
}

func TestIntegrationTCPStatusRejectsBlockedTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	binPath := buildIntegrationBinary(t, ctx)

	wsAddr := freeTCPAddr(t)
	socksAddr := freeTCPAddr(t)
	httpProxyAddr := freeTCPAddr(t)
	metricsAddr := freeTCPAddr(t)
	serverLog := filepath.Join(t.TempDir(), "tcp-status-server.log")
	clientLog := filepath.Join(t.TempDir(), "tcp-status-client.log")

	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "ws://"+wsAddr+"/tunnel",
		"-token", "tcp-status-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "10.0.0.0/8",
		"-metrics", metricsAddr,
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wsAddr, server)
	waitTCP(t, ctx, metricsAddr, server)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "socks5://"+socksAddr+",http://"+httpProxyAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "tcp-status-token",
		"-n", "1",
	)
	defer stopProcess(client)
	waitTCP(t, ctx, socksAddr, client)
	waitTCP(t, ctx, httpProxyAddr, client)
	waitLogContains(t, ctx, clientLog, "协议协商成功", client)

	if got := socks5ConnectReplyCode(t, socksAddr, "127.0.0.1:1"); got == 0x00 {
		t.Fatal("SOCKS5 connect unexpectedly succeeded for blocked target")
	}
	assertMetricValue(t, fetchHTTP(t, "http://"+metricsAddr+"/metrics"), "x_tunnel_server_target_rejections_total", "1")
	if got := fetchViaHTTPProxyStatus(t, httpProxyAddr, "http://127.0.0.1:1/blocked"); got != http.StatusForbidden {
		t.Fatalf("HTTP proxy blocked target status = %d, want %d", got, http.StatusForbidden)
	}
	waitLogContains(t, ctx, serverLog, "TCP 拒绝", server)
	assertMetricValue(t, fetchHTTP(t, "http://"+metricsAddr+"/metrics"), "x_tunnel_server_target_rejections_total", "2")
	assertNoUDPResponseViaSOCKS5(t, socksAddr, "127.0.0.1:53", []byte("blocked"))
	waitLogContains(t, ctx, serverLog, "UDP 拒绝", server)
	assertMetricValue(t, fetchHTTP(t, "http://"+metricsAddr+"/metrics"), "x_tunnel_server_target_rejections_total", "3")
}

type xtunnelProcess struct {
	cmd     *exec.Cmd
	logPath string
	done    chan struct{}
	err     error
}

func startXTunnel(t *testing.T, ctx context.Context, binPath, logPath string, args ...string) *xtunnelProcess {
	t.Helper()
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start x-tunnel %v: %v", args, err)
	}
	proc := &xtunnelProcess{cmd: cmd, logPath: logPath, done: make(chan struct{})}
	go func() {
		proc.err = cmd.Wait()
		close(proc.done)
	}()
	return proc
}

func runXTunnelExpectStartupFailure(t *testing.T, ctx context.Context, binPath string, args []string, wants ...string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, binPath, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("x-tunnel %v exited successfully, want failure\n%s", args, out)
	}
	if ctx.Err() != nil {
		t.Fatalf("x-tunnel %v timed out: %v\n%s", args, ctx.Err(), out)
	}
	for _, want := range wants {
		if !bytes.Contains(out, []byte(want)) {
			t.Fatalf("x-tunnel %v output missing %q:\n%s", args, want, out)
		}
	}
}

func stopProcess(proc *xtunnelProcess) {
	if proc == nil || proc.cmd == nil || proc.cmd.Process == nil {
		return
	}
	_ = proc.cmd.Process.Signal(os.Interrupt)
	select {
	case <-proc.done:
	case <-time.After(2 * time.Second):
		_ = proc.cmd.Process.Kill()
		<-proc.done
	}
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

func waitTCP(t *testing.T, ctx context.Context, addr string, procs ...*xtunnelProcess) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tcp %s did not open: %v", addr, err)
		}
		for _, proc := range procs {
			select {
			case <-proc.done:
				raw, _ := os.ReadFile(proc.logPath)
				t.Fatalf("x-tunnel exited while waiting for tcp %s: %v\nlog %s:\n%s", addr, proc.err, proc.logPath, raw)
			default:
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context ended while waiting for tcp %s: %v", addr, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func waitLogContains(t *testing.T, ctx context.Context, path, needle string, procs ...*xtunnelProcess) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, _ := os.ReadFile(path)
		if bytes.Contains(raw, []byte(needle)) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("log %s did not contain %q\n%s", path, needle, raw)
		}
		for _, proc := range procs {
			select {
			case <-proc.done:
				procLog, _ := os.ReadFile(proc.logPath)
				t.Fatalf("x-tunnel exited while waiting for log %s to contain %q: %v\nlog %s:\n%s", path, needle, proc.err, proc.logPath, procLog)
			default:
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context ended while waiting for log %q: %v", needle, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func fetchHTTP(t *testing.T, rawURL string) string {
	t.Helper()
	client := &http.Client{Timeout: integrationIOTimeout}
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	return readOKBody(t, resp)
}

func fetchHTTPStatus(t *testing.T, rawURL string) int {
	t.Helper()
	client := &http.Client{Timeout: integrationIOTimeout}
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func fetchViaHTTPProxy(t *testing.T, proxyAddr, rawURL string) string {
	t.Helper()
	client := httpProxyClient(t, proxyAddr, "", "")
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("proxy GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	return readOKBody(t, resp)
}

func fetchViaHTTPProxyWithAuth(t *testing.T, proxyAddr, rawURL, username, password string) string {
	t.Helper()
	client := httpProxyClient(t, proxyAddr, username, password)
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("authenticated proxy GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	return readOKBody(t, resp)
}

func fetchViaHTTPProxyStatus(t *testing.T, proxyAddr, rawURL string) int {
	t.Helper()
	client := httpProxyClient(t, proxyAddr, "", "")
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("proxy GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func fetchViaHTTPProxyStatusWithAuth(t *testing.T, proxyAddr, rawURL, username, password string) int {
	t.Helper()
	client := httpProxyClient(t, proxyAddr, username, password)
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("authenticated proxy GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func fetchViaHTTPProxyAuthChallenge(t *testing.T, proxyAddr, rawURL, username, password string) *http.Response {
	t.Helper()
	client := httpProxyClient(t, proxyAddr, username, password)
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("proxy auth challenge GET %s: %v", rawURL, err)
	}
	return resp
}

func assertHTTPProxyAuthChallenge(t *testing.T, label string, resp *http.Response) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("%s status = %d, want %d", label, resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if resp.Status != "407 Proxy Authentication Required" {
		t.Fatalf("%s status line = %q, want 407 Proxy Authentication Required", label, resp.Status)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got == "" {
		t.Fatalf("%s missing Proxy-Authenticate header", label)
	}
	if resp.ContentLength != 0 {
		t.Fatalf("%s ContentLength = %d, want 0", label, resp.ContentLength)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s read body: %v", label, err)
	}
	if len(body) != 0 {
		t.Fatalf("%s body = %q, want empty", label, body)
	}
}

func httpProxyClient(t *testing.T, proxyAddr, username, password string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	if username != "" || password != "" {
		proxyURL.User = url.UserPassword(username, password)
	}
	return &http.Client{
		Timeout:   integrationIOTimeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
}

func fetchViaHTTPConnect(t *testing.T, proxyAddr, targetAddr, path string) string {
	t.Helper()
	return fetchViaHTTPConnectWithAuth(t, proxyAddr, targetAddr, path, "", "")
}

func fetchViaHTTPConnectStatus(t *testing.T, proxyAddr, targetAddr string) int {
	t.Helper()
	return fetchViaHTTPConnectStatusWithAuth(t, proxyAddr, targetAddr, "", "")
}

func fetchViaHTTPConnectStatusWithAuth(t *testing.T, proxyAddr, targetAddr, username, password string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial HTTP proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		t.Fatalf("set HTTP proxy deadline: %v", err)
	}
	writeHTTPConnectRequest(t, conn, targetAddr, username, password)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	return parseHTTPStatusCode(t, status)
}

func assertHTTPConnectAuthChallenge(t *testing.T, proxyAddr, targetAddr, username, password string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial HTTP proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		t.Fatalf("set HTTP proxy deadline: %v", err)
	}
	writeHTTPConnectRequest(t, conn, targetAddr, username, password)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT auth challenge: %v", err)
	}
	label := "HTTP CONNECT auth challenge"
	if username != "" || password != "" {
		label = "HTTP CONNECT wrong auth"
	}
	assertHTTPProxyAuthChallenge(t, label, resp)
}

func fetchViaHTTPConnectWithAuth(t *testing.T, proxyAddr, targetAddr, path, username, password string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial HTTP proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		t.Fatalf("set HTTP proxy deadline: %v", err)
	}

	writeHTTPConnectRequest(t, conn, targetAddr, username, password)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if parseHTTPStatusCode(t, status) != http.StatusOK {
		t.Fatalf("CONNECT status = %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, targetAddr)
	return readHTTPResponseBody(t, br)
}

func writeHTTPConnectRequest(t *testing.T, w io.Writer, targetAddr, username, password string) {
	t.Helper()
	fmt.Fprintf(w, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	if username != "" || password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		fmt.Fprintf(w, "Proxy-Authorization: Basic %s\r\n", auth)
	}
	fmt.Fprint(w, "\r\n")
}

func rawHTTPProxyGETWithAuth(t *testing.T, proxyAddr, rawURL, username, password string, originHeaders <-chan http.Header, headers map[string]string) http.Header {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial HTTP proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		t.Fatalf("set HTTP proxy deadline: %v", err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse raw proxy URL: %v", err)
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n", rawURL, parsed.Host)
	if username != "" || password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		fmt.Fprintf(conn, "Proxy-Authorization: Basic %s\r\n", auth)
	}
	for name, value := range headers {
		fmt.Fprintf(conn, "%s: %s\r\n", name, value)
	}
	fmt.Fprint(conn, "\r\n")

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read raw proxy response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("raw proxy response status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return readOriginHeaders(t, originHeaders)
}

func readOriginHeaders(t *testing.T, ch <-chan http.Header) http.Header {
	t.Helper()
	if ch == nil {
		t.Fatal("origin header channel is nil")
	}
	select {
	case headers := <-ch:
		return headers
	case <-time.After(integrationIOTimeout):
		t.Fatal("timed out waiting for origin headers")
	}
	return nil
}

func assertOriginHeaderAbsent(t *testing.T, ch <-chan http.Header, name string) {
	t.Helper()
	assertHeaderAbsent(t, readOriginHeaders(t, ch), name)
}

func assertHeaderAbsent(t *testing.T, headers http.Header, name string) {
	t.Helper()
	if got := headers.Get(name); got != "" {
		t.Fatalf("origin header %s = %q, want absent", name, got)
	}
}

func assertHeaderValue(t *testing.T, headers http.Header, name, want string) {
	t.Helper()
	if got := headers.Get(name); got != want {
		t.Fatalf("origin header %s = %q, want %q", name, got, want)
	}
}

func assertHeaderContainsValue(t *testing.T, headers http.Header, name, want string) {
	t.Helper()
	for _, field := range headers.Values(name) {
		for _, part := range strings.Split(field, ",") {
			if strings.TrimSpace(part) == want {
				return
			}
		}
	}
	t.Fatalf("origin header %s values = %q, want value %q", name, headers.Values(name), want)
}

func parseHTTPStatusCode(t *testing.T, statusLine string) int {
	t.Helper()
	fields := strings.Fields(statusLine)
	if len(fields) < 2 {
		t.Fatalf("invalid HTTP status line %q", statusLine)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("invalid HTTP status code in %q: %v", statusLine, err)
	}
	return code
}

func fetchViaSOCKS5(t *testing.T, proxyAddr, targetAddr, path string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		t.Fatalf("set SOCKS5 deadline: %v", err)
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("read SOCKS5 greeting: %v", err)
	}
	if !bytes.Equal(greeting, []byte{0x05, 0x00}) {
		t.Fatalf("SOCKS5 greeting = %v", greeting)
	}

	writeSOCKS5ConnectRequest(t, conn, targetAddr)
	if got := readSOCKS5ConnectStatus(t, conn); got != 0x00 {
		t.Fatalf("SOCKS5 connect status = %d", got)
	}

	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, targetAddr)
	return readHTTPResponseBody(t, bufio.NewReader(conn))
}

func fetchViaSOCKS5WithAuth(t *testing.T, proxyAddr, targetAddr, path, username, password string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		t.Fatalf("set SOCKS5 deadline: %v", err)
	}

	if got := socks5UserPassAuthStatusConn(t, conn, username, password); got != 0x00 {
		t.Fatalf("SOCKS5 auth status = %d, want 0", got)
	}
	writeSOCKS5ConnectRequest(t, conn, targetAddr)
	if got := readSOCKS5ConnectStatus(t, conn); got != 0x00 {
		t.Fatalf("SOCKS5 connect status = %d", got)
	}

	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, targetAddr)
	return readHTTPResponseBody(t, bufio.NewReader(conn))
}

func socks5SelectedMethod(t *testing.T, proxyAddr string, methods []byte) byte {
	t.Helper()
	if len(methods) > 255 {
		t.Fatalf("too many SOCKS5 methods: %d", len(methods))
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		t.Fatalf("set SOCKS5 deadline: %v", err)
	}

	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read SOCKS5 method selection: %v", err)
	}
	if resp[0] != 0x05 {
		t.Fatalf("SOCKS5 method response version = %d, want 5", resp[0])
	}
	return resp[1]
}

func socks5UserPassAuthStatus(t *testing.T, proxyAddr, username, password string) byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		t.Fatalf("set SOCKS5 deadline: %v", err)
	}
	return socks5UserPassAuthStatusConn(t, conn, username, password)
}

func socks5UserPassAuthStatusConn(t *testing.T, conn net.Conn, username, password string) byte {
	t.Helper()
	if len(username) > 255 || len(password) > 255 {
		t.Fatalf("SOCKS5 username/password too long")
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write SOCKS5 auth greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("read SOCKS5 auth greeting: %v", err)
	}
	if !bytes.Equal(greeting, []byte{0x05, 0x02}) {
		t.Fatalf("SOCKS5 auth greeting = %v", greeting)
	}

	req := []byte{0x01, byte(len(username))}
	req = append(req, []byte(username)...)
	req = append(req, byte(len(password)))
	req = append(req, []byte(password)...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write SOCKS5 auth request: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read SOCKS5 auth status: %v", err)
	}
	if resp[0] != 0x01 {
		t.Fatalf("SOCKS5 auth status version = %d, want 1", resp[0])
	}
	return resp[1]
}

func socks5ConnectReplyCode(t *testing.T, proxyAddr, targetAddr string) byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		t.Fatalf("set SOCKS5 deadline: %v", err)
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("read SOCKS5 greeting: %v", err)
	}
	if !bytes.Equal(greeting, []byte{0x05, 0x00}) {
		t.Fatalf("SOCKS5 greeting = %v", greeting)
	}

	writeSOCKS5ConnectRequest(t, conn, targetAddr)
	return readSOCKS5ConnectStatus(t, conn)
}

func writeSOCKS5ConnectRequest(t *testing.T, conn net.Conn, targetAddr string) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse target port: %v", err)
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write SOCKS5 connect: %v", err)
	}
}

func readSOCKS5ConnectStatus(t *testing.T, r io.Reader) byte {
	t.Helper()
	resp := make([]byte, 10)
	if _, err := io.ReadFull(r, resp); err != nil {
		t.Fatalf("read SOCKS5 connect response: %v", err)
	}
	return resp[1]
}

func startAuthSOCKS5TCPProxy(t *testing.T, username, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen auth SOCKS5 proxy: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleAuthSOCKS5TCPProxyConn(conn, username, password)
		}
	}()
	return ln.Addr().String()
}

func handleAuthSOCKS5TCPProxyConn(conn net.Conn, username, password string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(integrationIOTimeout))
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	hasUserPass := false
	for _, method := range methods {
		if method == 0x02 {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		_, _ = conn.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
		return
	}
	if !readSOCKS5UserPassAuth(conn, username, password) {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return
	}
	target, ok := readSOCKS5ConnectTarget(conn)
	if !ok {
		return
	}
	upstream, err := net.DialTimeout("tcp", target, integrationIOTimeout)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, conn)
		_ = upstream.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		_ = conn.Close()
		done <- struct{}{}
	}()
	<-done
}

func readSOCKS5UserPassAuth(r io.Reader, username, password string) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil || head[0] != 0x01 {
		return false
	}
	uname := make([]byte, int(head[1]))
	if _, err := io.ReadFull(r, uname); err != nil {
		return false
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(r, plen); err != nil {
		return false
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(r, pass); err != nil {
		return false
	}
	return string(uname) == username && string(pass) == password
}

func readSOCKS5ConnectTarget(r io.Reader) (string, bool) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil || head[0] != 0x05 || head[1] != 0x01 {
		return "", false
	}
	var host string
	switch head[3] {
	case 0x01:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(r, raw); err != nil {
			return "", false
		}
		host = net.IP(raw).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", false
		}
		raw := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(r, raw); err != nil {
			return "", false
		}
		host = string(raw)
	case 0x04:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(r, raw); err != nil {
			return "", false
		}
		host = net.IP(raw).String()
	default:
		return "", false
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", false
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	return net.JoinHostPort(host, strconv.Itoa(port)), true
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve UDP addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen UDP echo: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(append([]byte("echo:"), buf[:n]...), peer)
		}
	}()
	return conn.LocalAddr().String()
}

func fetchUDPViaSOCKS5(t *testing.T, proxyAddr, targetAddr string, payload []byte) []byte {
	t.Helper()
	udpConn, relayAddr, cleanup := openSOCKS5UDPAssociation(t, proxyAddr)
	defer cleanup()
	writeUDPViaSOCKS5Relay(t, udpConn, relayAddr, targetAddr, payload)

	buf := make([]byte, 2048)
	n, _, err := udpConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read UDP response: %v", err)
	}
	_, gotPayload, err := parseSOCKS5UDPPacket(buf[:n])
	if err != nil {
		t.Fatalf("parse SOCKS5 UDP response: %v", err)
	}
	return gotPayload
}

func assertNoUDPResponseViaSOCKS5(t *testing.T, proxyAddr, targetAddr string, payload []byte) {
	t.Helper()
	udpConn, relayAddr, cleanup := openSOCKS5UDPAssociation(t, proxyAddr)
	defer cleanup()
	writeUDPViaSOCKS5Relay(t, udpConn, relayAddr, targetAddr, payload)
	if err := udpConn.SetDeadline(time.Now().Add(750 * time.Millisecond)); err != nil {
		t.Fatalf("set blocked UDP deadline: %v", err)
	}

	buf := make([]byte, 2048)
	n, _, err := udpConn.ReadFromUDP(buf)
	if err == nil {
		t.Fatalf("received UDP response for blocked target: %x", buf[:n])
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read blocked UDP response error = %v, want timeout", err)
	}
}

func openSOCKS5UDPAssociation(t *testing.T, proxyAddr string) (*net.UDPConn, *net.UDPAddr, func()) {
	t.Helper()
	control, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 proxy: %v", err)
	}
	if err := control.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		_ = control.Close()
		t.Fatalf("set SOCKS5 control deadline: %v", err)
	}

	if _, err := control.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = control.Close()
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(control, greeting); err != nil {
		_ = control.Close()
		t.Fatalf("read SOCKS5 greeting: %v", err)
	}
	if !bytes.Equal(greeting, []byte{0x05, 0x00}) {
		_ = control.Close()
		t.Fatalf("SOCKS5 greeting = %v", greeting)
	}

	if _, err := control.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		_ = control.Close()
		t.Fatalf("write UDP associate: %v", err)
	}
	relayAddr := readSOCKS5BoundAddr(t, control, proxyAddr)

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		_ = control.Close()
		t.Fatalf("listen local UDP: %v", err)
	}
	if err := udpConn.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		_ = udpConn.Close()
		_ = control.Close()
		t.Fatalf("set UDP deadline: %v", err)
	}
	cleanup := func() {
		_ = udpConn.Close()
		_ = control.Close()
	}
	return udpConn, relayAddr, cleanup
}

func writeUDPViaSOCKS5Relay(t *testing.T, udpConn *net.UDPConn, relayAddr *net.UDPAddr, targetAddr string, payload []byte) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split UDP target: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse UDP target port: %v", err)
	}
	packet, err := buildSOCKS5UDPPacket(host, port, payload)
	if err != nil {
		t.Fatalf("build SOCKS5 UDP packet: %v", err)
	}
	if _, err := udpConn.WriteToUDP(packet, relayAddr); err != nil {
		t.Fatalf("write UDP packet to SOCKS5 relay: %v", err)
	}
}

func readSOCKS5BoundAddr(t *testing.T, r io.Reader, proxyAddr string) *net.UDPAddr {
	t.Helper()
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		t.Fatalf("read SOCKS5 response head: %v", err)
	}
	if head[1] != 0x00 {
		t.Fatalf("SOCKS5 response status = %d", head[1])
	}
	var host string
	switch head[3] {
	case 0x01:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(r, raw); err != nil {
			t.Fatalf("read SOCKS5 IPv4 bound addr: %v", err)
		}
		host = net.IP(raw).String()
	case 0x04:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(r, raw); err != nil {
			t.Fatalf("read SOCKS5 IPv6 bound addr: %v", err)
		}
		host = net.IP(raw).String()
	case 0x03:
		lenRaw := make([]byte, 1)
		if _, err := io.ReadFull(r, lenRaw); err != nil {
			t.Fatalf("read SOCKS5 domain len: %v", err)
		}
		raw := make([]byte, int(lenRaw[0]))
		if _, err := io.ReadFull(r, raw); err != nil {
			t.Fatalf("read SOCKS5 domain bound addr: %v", err)
		}
		host = string(raw)
	default:
		t.Fatalf("unexpected SOCKS5 address type %d", head[3])
	}
	portRaw := make([]byte, 2)
	if _, err := io.ReadFull(r, portRaw); err != nil {
		t.Fatalf("read SOCKS5 bound port: %v", err)
	}
	port := int(portRaw[0])<<8 | int(portRaw[1])
	if host == "0.0.0.0" || host == "::" {
		proxyHost, _, err := net.SplitHostPort(proxyAddr)
		if err != nil {
			t.Fatalf("split proxy addr: %v", err)
		}
		host = proxyHost
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("resolve SOCKS5 UDP relay addr: %v", err)
	}
	return addr
}

func readOKBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(raw)
}

func readHTTPResponseBody(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("read HTTP response: %v", err)
	}
	defer resp.Body.Close()
	return readOKBody(t, resp)
}

func assertBody(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s body = %q, want %q", label, got, want)
	}
}

func assertMetrics(t *testing.T, got string) {
	t.Helper()
	for _, want := range []string{
		"x_tunnel_server_streams_total",
		"x_tunnel_udp_associations_total",
		"x_tunnel_client_reconnects_total",
		"x_tunnel_server_source_rejections_total",
		"x_tunnel_server_auth_rejections_total",
		"x_tunnel_server_client_session_rejections_total",
		"x_tunnel_server_stream_rejections_total",
		"x_tunnel_server_target_rejections_total",
		"x_tunnel_server_unsupported_streams_total",
		"x_tunnel_server_protocol_negotiations_total",
		"x_tunnel_server_protocol_negotiation_rejections_total",
		"x_tunnel_server_protocol_negotiation_failures_total",
		"x_tunnel_client_protocol_negotiations_total",
		"x_tunnel_client_protocol_legacy_sessions_total",
		"x_tunnel_client_protocol_negotiation_failures_total",
		"x_tunnel_server_sessions",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("metrics missing %q:\n%s", want, got)
		}
	}
}

func assertMetricPresent(t *testing.T, got, name string) {
	t.Helper()
	if !strings.Contains(got, name) {
		t.Fatalf("metrics missing %q:\n%s", name, got)
	}
}

func assertMetricValue(t *testing.T, got, name, want string) {
	t.Helper()
	for _, line := range strings.Split(got, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == name {
			if fields[1] != want {
				t.Fatalf("metric %s = %s, want %s:\n%s", name, fields[1], want, got)
			}
			return
		}
	}
	t.Fatalf("metrics missing value for %q:\n%s", name, got)
}

func writeClientMTLSFiles(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "x-tunnel-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "x-tunnel-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	caPath := filepath.Join(dir, "ca.pem")
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client-key.pem")
	writePEMFile(t, caPath, "CERTIFICATE", caDER)
	writePEMFile(t, clientCertPath, "CERTIFICATE", clientDER)
	writePEMFile(t, clientKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))
	return caPath, clientCertPath, clientKeyPath
}

func writePEMFile(t *testing.T, path, blockType string, bytes []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: bytes}); err != nil {
		t.Fatalf("write PEM %s: %v", path, err)
	}
}
