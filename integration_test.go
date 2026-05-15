package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegrationLocalWebSocketTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "x-tunnel")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	targetBody := "x-tunnel integration ok"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, targetBody)
	}))
	t.Cleanup(target.Close)
	targetHost := strings.TrimPrefix(target.URL, "http://")

	serverAddr := freeLocalTCPAddr(t)
	tcpAddr := freeLocalTCPAddr(t)
	httpProxyAddr := freeLocalTCPAddr(t)
	tokenValue := "integration-token"

	serverLog := filepath.Join(tmp, "server.log")
	clientLog := filepath.Join(tmp, "client.log")
	server := startLoggedCommand(t, ctx, serverLog, bin,
		"-l", "ws://"+serverAddr+"/tunnel",
		"-token", tokenValue,
		"-cidr", "127.0.0.1/32",
	)
	t.Cleanup(func() { stopCommand(server) })
	waitForLog(t, serverLog, "WS 启动")

	client := startLoggedCommand(t, ctx, clientLog, bin,
		"-l", "http://"+httpProxyAddr+",tcp://"+tcpAddr+"/"+targetHost,
		"-f", "ws://"+serverAddr+"/tunnel",
		"-token", tokenValue,
		"-n", "1",
	)
	t.Cleanup(func() { stopCommand(client) })
	waitForLog(t, clientLog, "就绪 (smux)")

	if got := httpGet(t, "http://"+tcpAddr+"/"); got != targetBody {
		t.Fatalf("tcp forward body = %q, want %q", got, targetBody)
	}

	proxyURL, err := url.Parse("http://" + httpProxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	proxyClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	if got := httpGetWithClient(t, proxyClient, target.URL); got != targetBody {
		t.Fatalf("http proxy body = %q, want %q", got, targetBody)
	}
}

func freeLocalTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func startLoggedCommand(t *testing.T, ctx context.Context, logPath string, name string, args ...string) *exec.Cmd {
	t.Helper()
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s failed: %v", name, err)
	}
	return cmd
}

func stopCommand(cmd *exec.Cmd) {
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

func waitForLog(t *testing.T, path string, needle string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(path)
		if strings.Contains(string(raw), needle) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	raw, _ := os.ReadFile(path)
	t.Fatalf("log %s did not contain %q:\n%s", path, needle, raw)
}

func httpGet(t *testing.T, rawURL string) string {
	t.Helper()
	return httpGetWithClient(t, &http.Client{Timeout: 5 * time.Second}, rawURL)
}

func httpGetWithClient(t *testing.T, client *http.Client, rawURL string) string {
	t.Helper()
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
