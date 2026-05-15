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
	"testing"
	"time"
)

const integrationIOTimeout = 5 * time.Second

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

	binPath := filepath.Join(t.TempDir(), "x-tunnel")
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

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
	waitTCP(t, ctx, wsAddr)
	waitTCP(t, ctx, metricsAddr)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "socks5://"+socksAddr+",tcp://"+tcpAddr+"/"+targetAddr+",http://"+httpProxyAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "integration-token",
		"-n", "1",
		"-metrics", clientMetricsAddr,
	)
	defer stopProcess(client)
	waitTCP(t, ctx, socksAddr)
	waitTCP(t, ctx, tcpAddr)
	waitTCP(t, ctx, httpProxyAddr)
	waitTCP(t, ctx, clientMetricsAddr)
	waitLogContains(t, ctx, clientLog, "协议协商成功")
	waitLogContains(t, ctx, serverLog, "协议协商成功")

	assertBody(t, "tcp forward", fetchHTTP(t, "http://"+tcpAddr+"/payload"), body)
	assertBody(t, "http proxy", fetchViaHTTPProxy(t, httpProxyAddr, "http://"+targetAddr+"/payload"), body)
	assertBody(t, "http proxy allow-host", fetchViaHTTPProxy(t, httpProxyAddr, "http://"+localhostTargetAddr+"/payload"), body)
	assertBody(t, "http connect", fetchViaHTTPConnect(t, httpProxyAddr, targetAddr, "/payload"), body)
	assertBody(t, "socks5", fetchViaSOCKS5(t, socksAddr, targetAddr, "/payload"), body)
	udpTargetAddr := startUDPEcho(t)
	assertBody(t, "socks5 udp", string(fetchUDPViaSOCKS5(t, socksAddr, udpTargetAddr, []byte("ping"))), "echo:ping")
	serverMetrics := fetchHTTP(t, "http://"+metricsAddr+"/metrics")
	assertMetrics(t, serverMetrics)
	assertMetricsContains(t, serverMetrics, "x_tunnel_server_protocol_negotiations_total 1")
	clientMetrics := fetchHTTP(t, "http://"+clientMetricsAddr+"/metrics")
	assertMetrics(t, clientMetrics)
	assertMetricsContains(t, clientMetrics, "x_tunnel_client_protocol_negotiations_total 1")

	badClient := startXTunnel(t, ctx, binPath, badClientLog,
		"-l", "socks5://"+freeTCPAddr(t),
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "wrong-token",
		"-n", "1",
	)
	defer stopProcess(badClient)
	waitLogContains(t, ctx, badClientLog, "认证失败")
	waitLogContains(t, ctx, serverLog, "Token 认证失败")
	assertMetricsContains(t, fetchHTTP(t, "http://"+metricsAddr+"/metrics"), "x_tunnel_server_auth_rejections_total 1")
}

func TestIntegrationLocalProxyAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const body = "x-tunnel local proxy auth payload\n"
	originSawProxyAuth := make(chan string, 10)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Proxy-Authorization"); got != "" {
			originSawProxyAuth <- got
		}
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()
	targetAddr := strings.TrimPrefix(origin.URL, "http://")

	binPath := filepath.Join(t.TempDir(), "x-tunnel")
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

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
	waitTCP(t, ctx, wsAddr)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "socks5://user:pass@"+socksAddr+",http://user:pass@"+httpProxyAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "proxy-auth-token",
		"-n", "1",
	)
	defer stopProcess(client)
	waitTCP(t, ctx, socksAddr)
	waitTCP(t, ctx, httpProxyAddr)
	waitLogContains(t, ctx, clientLog, "协议协商成功")
	waitLogContains(t, ctx, serverLog, "协议协商成功")

	if got := fetchViaHTTPProxyStatus(t, httpProxyAddr, "http://"+targetAddr+"/payload"); got != http.StatusProxyAuthRequired {
		t.Fatalf("HTTP proxy status without auth = %d, want %d", got, http.StatusProxyAuthRequired)
	}
	if got := fetchViaHTTPProxyStatusWithAuth(t, httpProxyAddr, "http://"+targetAddr+"/payload", "user", "wrong"); got != http.StatusProxyAuthRequired {
		t.Fatalf("HTTP proxy status with wrong auth = %d, want %d", got, http.StatusProxyAuthRequired)
	}
	if got := fetchViaHTTPConnectStatus(t, httpProxyAddr, targetAddr); got != http.StatusProxyAuthRequired {
		t.Fatalf("HTTP CONNECT status without auth = %d, want %d", got, http.StatusProxyAuthRequired)
	}
	if got := fetchViaHTTPConnectStatusWithAuth(t, httpProxyAddr, targetAddr, "user", "wrong"); got != http.StatusProxyAuthRequired {
		t.Fatalf("HTTP CONNECT status with wrong auth = %d, want %d", got, http.StatusProxyAuthRequired)
	}
	assertBody(t, "http proxy auth", fetchViaHTTPProxyWithAuth(t, httpProxyAddr, "http://"+targetAddr+"/payload", "user", "pass"), body)
	assertBody(t, "http connect auth", fetchViaHTTPConnectWithAuth(t, httpProxyAddr, targetAddr, "/payload", "user", "pass"), body)

	if got := socks5SelectedMethod(t, socksAddr, []byte{0x00}); got != 0xff {
		t.Fatalf("SOCKS5 selected method without username/password support = 0x%02x, want 0xff", got)
	}
	if got := socks5UserPassAuthStatus(t, socksAddr, "user", "wrong"); got != 0x01 {
		t.Fatalf("SOCKS5 wrong auth status = %d, want 1", got)
	}
	assertBody(t, "socks5 auth", fetchViaSOCKS5WithAuth(t, socksAddr, targetAddr, "/payload", "user", "pass"), body)
	select {
	case got := <-originSawProxyAuth:
		t.Fatalf("origin received Proxy-Authorization header %q", got)
	default:
	}
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

	binPath := filepath.Join(t.TempDir(), "x-tunnel")
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

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
	waitTCP(t, ctx, okWSAddr)

	okClient := startXTunnel(t, ctx, binPath, okClientLog,
		"-l", "http://"+okHTTPProxyAddr,
		"-f", "ws://"+okWSAddr+"/tunnel",
		"-token", "upstream-socks-token",
		"-n", "1",
	)
	defer stopProcess(okClient)
	waitTCP(t, ctx, okHTTPProxyAddr)
	waitLogContains(t, ctx, okClientLog, "协议协商成功")
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
	waitTCP(t, ctx, badWSAddr)

	badClient := startXTunnel(t, ctx, binPath, badClientLog,
		"-l", "http://"+badHTTPProxyAddr,
		"-f", "ws://"+badWSAddr+"/tunnel",
		"-token", "upstream-socks-bad-token",
		"-n", "1",
	)
	defer stopProcess(badClient)
	waitTCP(t, ctx, badHTTPProxyAddr)
	waitLogContains(t, ctx, badClientLog, "协议协商成功")
	if got := fetchViaHTTPProxyStatus(t, badHTTPProxyAddr, "http://"+targetAddr+"/payload"); got != http.StatusBadGateway {
		t.Fatalf("HTTP proxy status with bad upstream SOCKS5 auth = %d, want %d", got, http.StatusBadGateway)
	}
	waitLogContains(t, ctx, badServerLog, "SOCKS5握手失败")
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

	binPath := filepath.Join(t.TempDir(), "x-tunnel")
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

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
	waitTCP(t, ctx, wssAddr)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "tcp://"+tcpAddr+"/"+targetAddr,
		"-f", "wss://"+wssAddr+"/tunnel",
		"-token", "wss-token",
		"-n", "1",
		"-insecure",
	)
	defer stopProcess(client)
	waitTCP(t, ctx, tcpAddr)
	waitLogContains(t, ctx, clientLog, "fallback 模式已启用")
	waitLogContains(t, ctx, clientLog, "协议协商成功")
	waitLogContains(t, ctx, serverLog, "协议协商成功")

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

	binPath := filepath.Join(t.TempDir(), "x-tunnel")
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
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
	waitTCP(t, ctx, wssAddr)
	waitLogContains(t, ctx, serverLog, "mTLS 客户端证书认证已启用")

	badClient := startXTunnel(t, ctx, binPath, badClientLog,
		"-l", "tcp://"+freeTCPAddr(t)+"/"+targetAddr,
		"-f", "wss://"+wssAddr+"/tunnel",
		"-token", "mtls-token",
		"-n", "1",
		"-insecure",
	)
	defer stopProcess(badClient)
	waitLogContains(t, ctx, badClientLog, "连接失败")

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
	waitTCP(t, ctx, tcpAddr)
	waitLogContains(t, ctx, clientLog, "协议协商成功")
	waitLogContains(t, ctx, serverLog, "协议协商成功")

	assertBody(t, "wss mtls tcp forward", fetchHTTP(t, "http://"+tcpAddr+"/payload"), body)
}

func TestIntegrationMaxClientsRejectsNewClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	binPath := filepath.Join(t.TempDir(), "x-tunnel")
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

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
	waitTCP(t, ctx, wsAddr)
	waitTCP(t, ctx, metricsAddr)

	firstClient := startXTunnel(t, ctx, binPath, firstClientLog,
		"-l", "socks5://"+firstSocksAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "max-clients-token",
		"-n", "1",
	)
	defer stopProcess(firstClient)
	waitTCP(t, ctx, firstSocksAddr)
	waitLogContains(t, ctx, firstClientLog, "协议协商成功")

	secondClient := startXTunnel(t, ctx, binPath, secondClientLog,
		"-l", "socks5://"+secondSocksAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "max-clients-token",
		"-n", "1",
	)
	defer stopProcess(secondClient)
	waitTCP(t, ctx, secondSocksAddr)
	waitLogContains(t, ctx, serverLog, "拒绝客户端会话")
	waitLogContains(t, ctx, secondClientLog, "协议协商失败")
	assertMetricsContains(t, fetchHTTP(t, "http://"+metricsAddr+"/metrics"), "x_tunnel_server_client_session_rejections_total 1")
}

func TestIntegrationSourceCIDRRejectionMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	binPath := filepath.Join(t.TempDir(), "x-tunnel")
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

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
	waitTCP(t, ctx, wsAddr)
	waitTCP(t, ctx, metricsAddr)

	if got := fetchHTTPStatus(t, "http://"+wsAddr+"/tunnel"); got != http.StatusForbidden {
		t.Fatalf("source CIDR rejection status = %d, want %d", got, http.StatusForbidden)
	}
	assertMetricsContains(t, fetchHTTP(t, "http://"+metricsAddr+"/metrics"), "x_tunnel_server_source_rejections_total 1")
}

func TestIntegrationTCPStatusRejectsBlockedTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	binPath := filepath.Join(t.TempDir(), "x-tunnel")
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

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
	waitTCP(t, ctx, wsAddr)
	waitTCP(t, ctx, metricsAddr)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "socks5://"+socksAddr+",http://"+httpProxyAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "tcp-status-token",
		"-n", "1",
	)
	defer stopProcess(client)
	waitTCP(t, ctx, socksAddr)
	waitTCP(t, ctx, httpProxyAddr)
	waitLogContains(t, ctx, clientLog, "协议协商成功")

	if got := socks5ConnectReplyCode(t, socksAddr, "127.0.0.1:1"); got == 0x00 {
		t.Fatal("SOCKS5 connect unexpectedly succeeded for blocked target")
	}
	assertMetricsContains(t, fetchHTTP(t, "http://"+metricsAddr+"/metrics"), "x_tunnel_server_target_rejections_total 1")
	if got := fetchViaHTTPProxyStatus(t, httpProxyAddr, "http://127.0.0.1:1/blocked"); got != http.StatusBadGateway {
		t.Fatalf("HTTP proxy blocked target status = %d, want %d", got, http.StatusBadGateway)
	}
	waitLogContains(t, ctx, serverLog, "TCP 拒绝")
	assertMetricsContains(t, fetchHTTP(t, "http://"+metricsAddr+"/metrics"), "x_tunnel_server_target_rejections_total 2")
}

func startXTunnel(t *testing.T, ctx context.Context, binPath, logPath string, args ...string) *exec.Cmd {
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
	return cmd
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-done
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

func waitTCP(t *testing.T, ctx context.Context, addr string) {
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
		time.Sleep(50 * time.Millisecond)
	}
}

func waitLogContains(t *testing.T, ctx context.Context, path, needle string) {
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
	control, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 proxy: %v", err)
	}
	defer control.Close()
	if err := control.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		t.Fatalf("set SOCKS5 control deadline: %v", err)
	}

	if _, err := control.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(control, greeting); err != nil {
		t.Fatalf("read SOCKS5 greeting: %v", err)
	}
	if !bytes.Equal(greeting, []byte{0x05, 0x00}) {
		t.Fatalf("SOCKS5 greeting = %v", greeting)
	}

	if _, err := control.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write UDP associate: %v", err)
	}
	relayAddr := readSOCKS5BoundAddr(t, control, proxyAddr)

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("listen local UDP: %v", err)
	}
	defer udpConn.Close()
	if err := udpConn.SetDeadline(time.Now().Add(integrationIOTimeout)); err != nil {
		t.Fatalf("set UDP deadline: %v", err)
	}

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

func assertMetricsContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("metrics missing %q:\n%s", want, got)
	}
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
