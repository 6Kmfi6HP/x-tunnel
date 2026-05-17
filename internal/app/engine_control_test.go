package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func runtimeConfigForTest(t *testing.T, values runtimeValues) RuntimeConfig {
	t.Helper()
	startup, err := validateStartupConfigValues(values)
	if err != nil {
		t.Fatalf("validateStartupConfigValues: %v", err)
	}
	return newRuntimeConfig(values, startup)
}

func TestCheckConfigJSONDoesNotMutateRuntimeGlobals(t *testing.T) {
	before := currentRuntimeValues()
	t.Cleanup(before.applyGlobals)

	listenAddr = "socks5://127.0.0.1:19080"
	forwardAddr = "ws://127.0.0.1:19081/tunnel"
	token = "keep-runtime-token"
	websocketFrontProxyConfig = WebSocketFrontProxyConfig{
		Enabled: true,
		Type:    webSocketFrontProxyTypeHTTPConnect,
		Server:  "127.0.0.1:19082",
		Headers: map[string]string{
			"X-T5-Auth": "keep-header",
		},
	}
	current := currentRuntimeValues()

	raw := []byte(`{
  "listen": "socks5://127.0.0.1:1",
  "forward": "ws://127.0.0.1:1/tunnel",
  "token": "checked-token",
  "connections": 1
}`)
	if err := CheckConfigJSON(raw); err != nil {
		t.Fatalf("CheckConfigJSON returned error: %v", err)
	}
	if listenAddr != current.ListenAddr || forwardAddr != current.ForwardAddr || token != current.Token {
		t.Fatalf("CheckConfigJSON mutated runtime globals: got listen=%q forward=%q token=%q", listenAddr, forwardAddr, token)
	}
	if got := websocketFrontProxyConfig.Headers["X-T5-Auth"]; got != "keep-header" {
		t.Fatalf("CheckConfigJSON mutated front proxy headers: %q", got)
	}

	formatted, err := FormatConfigJSON(raw)
	if err != nil {
		t.Fatalf("FormatConfigJSON returned error: %v", err)
	}
	if !bytes.Contains(formatted, []byte("\n  \"listen\"")) {
		t.Fatalf("FormatConfigJSON did not indent JSON:\n%s", formatted)
	}
}

func TestFormatConfigJSONNormalizesAliases(t *testing.T) {
	raw := []byte(`{
  "listen": "wss://127.0.0.1:1/tunnel",
  "client-ca": "ca.pem",
  "allow-target": "127.0.0.0/8",
  "max-streams": 2
}`)
	formatted, err := FormatConfigJSON(raw)
	if err != nil {
		t.Fatalf("FormatConfigJSON returned error: %v", err)
	}
	if bytes.Contains(formatted, []byte(`"client-ca"`)) || bytes.Contains(formatted, []byte(`"allow-target"`)) || bytes.Contains(formatted, []byte(`"max-streams"`)) {
		t.Fatalf("FormatConfigJSON left alias keys in output:\n%s", formatted)
	}
	for _, want := range []string{`"client_ca"`, `"allow_target"`, `"max_streams"`} {
		if !bytes.Contains(formatted, []byte(want)) {
			t.Fatalf("FormatConfigJSON missing canonical key %s:\n%s", want, formatted)
		}
	}
}

type captureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *captureLogger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *captureLogger) contains(substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

func TestEngineStartCloseReleasesListener(t *testing.T) {
	values := defaultRuntimeValues()
	values.ListenAddr = "socks5://" + freeTCPAddr(t)
	values.ForwardAddr = "ws://127.0.0.1:1/tunnel"
	values.Token = "engine-token"
	values.ConnectionNum = 1
	values.Global.ReconnectDelay = 20 * time.Millisecond
	values.Global.ReconnectMaxDelay = 20 * time.Millisecond
	values.Global.ReconnectJitter = 0
	config := runtimeConfigForTest(t, values)

	logger := &captureLogger{}
	engine, err := NewEngine(config, RuntimeOptions{Build: BuildInfo{Version: "test", Commit: "commit"}, Logger: logger})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("Engine.Start: %v", err)
	}
	if !logger.contains("SOCKS5") {
		t.Fatalf("RuntimeOptions.Logger did not capture startup log: %#v", logger.lines)
	}
	status := engine.Status()
	if status.Mode != "client" {
		t.Fatalf("status mode = %q, want client", status.Mode)
	}
	var actual string
	for _, listener := range status.Listeners {
		if listener.Protocol == "socks5" {
			actual = strings.TrimPrefix(listener.Actual, "socks5://")
		}
	}
	if actual == "" {
		t.Fatalf("missing socks5 listener in status: %#v", status.Listeners)
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeCancel()
	if err := engine.Close(closeCtx); err != nil {
		t.Fatalf("Engine.Close: %v", err)
	}
	if err := engine.Close(closeCtx); err != nil {
		t.Fatalf("Engine.Close second call: %v", err)
	}
	ln, err := net.Listen("tcp", actual)
	if err != nil {
		t.Fatalf("listener %s was not released: %v", actual, err)
	}
	_ = ln.Close()
}

func TestEngineCloseBeforeStartDoesNotBlock(t *testing.T) {
	values := defaultRuntimeValues()
	values.ListenAddr = "socks5://" + freeTCPAddr(t)
	values.ForwardAddr = "ws://127.0.0.1:1/tunnel"
	values.Token = "engine-token"
	values.ConnectionNum = 1
	config := runtimeConfigForTest(t, values)

	engine, err := NewEngine(config, RuntimeOptions{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := engine.Close(ctx); err != nil {
		t.Fatalf("Engine.Close before start returned error: %v", err)
	}
}

func TestEngineStartReturnsBindError(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer occupied.Close()

	values := defaultRuntimeValues()
	values.ListenAddr = "socks5://" + occupied.Addr().String()
	values.ForwardAddr = "ws://127.0.0.1:1/tunnel"
	values.Token = "engine-token"
	values.ConnectionNum = 1
	config := runtimeConfigForTest(t, values)

	engine, err := NewEngine(config, RuntimeOptions{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	err = engine.Start(context.Background())
	if err == nil {
		t.Fatal("Engine.Start succeeded on occupied port")
	}
	if !strings.Contains(err.Error(), "listen.bind_failed") {
		t.Fatalf("Engine.Start error = %v, want listen.bind_failed", err)
	}
}

func TestReadyAndTokenFilesRequireControl(t *testing.T) {
	values := defaultRuntimeValues()
	values.ListenAddr = "socks5://" + freeTCPAddr(t)
	values.ForwardAddr = "ws://127.0.0.1:1/tunnel"
	values.Token = "engine-token"
	values.ConnectionNum = 1
	config := runtimeConfigForTest(t, values)

	if _, err := NewEngine(config, RuntimeOptions{ReadyFile: filepath.Join(t.TempDir(), "ready.json")}); err == nil {
		t.Fatal("NewEngine accepted ready file without control")
	}
	if _, err := NewEngine(config, RuntimeOptions{ControlTokenFile: filepath.Join(t.TempDir(), "token")}); err == nil {
		t.Fatal("NewEngine accepted token file without control")
	}
}

func TestControlAddrRequiresLoopback(t *testing.T) {
	if err := validateControlAddr("127.0.0.1:0"); err != nil {
		t.Fatalf("validateControlAddr rejected loopback: %v", err)
	}
	if err := validateControlAddr("[::1]:0"); err != nil {
		t.Fatalf("validateControlAddr rejected IPv6 loopback: %v", err)
	}
	if err := validateControlAddr("0.0.0.0:0"); err == nil {
		t.Fatal("validateControlAddr accepted non-loopback bind")
	}
}

func TestControlAPIReadyAuthStatusAndStop(t *testing.T) {
	values := defaultRuntimeValues()
	values.ListenAddr = "ws://" + freeTCPAddr(t) + "/tunnel"
	values.Token = "runtime-secret"
	config := runtimeConfigForTest(t, values)

	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready.json")
	tokenPath := filepath.Join(dir, "token")
	engine, err := NewEngine(config, RuntimeOptions{
		Build:            BuildInfo{Version: "control-test", Commit: "abc123"},
		ControlAddr:      "127.0.0.1:0",
		ReadyFile:        readyPath,
		ControlTokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := engine.Start(context.Background()); err != nil {
		t.Fatalf("Engine.Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = engine.Close(ctx)
	}()

	readyRaw, err := os.ReadFile(readyPath)
	if err != nil {
		t.Fatalf("read ready file: %v", err)
	}
	var ready readyInfo
	if err := json.Unmarshal(readyRaw, &ready); err != nil {
		t.Fatalf("decode ready file: %v", err)
	}
	if ready.ControlURL == "" || ready.TokenFile != tokenPath || ready.Version != "control-test" {
		t.Fatalf("ready file = %#v", ready)
	}
	tokenRaw, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	bearer := strings.TrimSpace(string(tokenRaw))
	if bearer == "" {
		t.Fatal("token file was empty")
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, body := controlRequest(t, client, http.MethodGet, ready.ControlURL+"/v1/health", "", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("health status=%d body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected CORS header: %q", got)
	}
	resp, body = controlRequest(t, client, http.MethodGet, ready.ControlURL+"/v1/version", "", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"version":"control-test"`) {
		t.Fatalf("version status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"control_api_version":1`) || !strings.Contains(body, `"stats"`) {
		t.Fatalf("version body missing control discovery fields: %s", body)
	}
	resp, _ = controlRequest(t, client, http.MethodGet, ready.ControlURL+"/v1/status", "wrong-token", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", resp.StatusCode)
	}
	resp, body = controlRequest(t, client, http.MethodGet, ready.ControlURL+"/v1/status", bearer, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status status=%d body=%s", resp.StatusCode, body)
	}
	if strings.Contains(body, "runtime-secret") {
		t.Fatalf("status leaked runtime token: %s", body)
	}
	if !strings.Contains(body, `"mode":"server"`) {
		t.Fatalf("status body missing server mode: %s", body)
	}
	resp, body = controlRequest(t, client, http.MethodGet, ready.ControlURL+"/v1/logs?limit=5", bearer, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"entries"`) {
		t.Fatalf("logs status=%d body=%s", resp.StatusCode, body)
	}
	resp, body = controlRequest(t, client, http.MethodGet, ready.ControlURL+"/v1/metrics", bearer, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "x_tunnel_server_sessions") {
		t.Fatalf("metrics status=%d body=%s", resp.StatusCode, body)
	}
	resp, body = controlRequest(t, client, http.MethodGet, ready.ControlURL+"/v1/stats", bearer, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"counters"`) || !strings.Contains(body, `"server"`) {
		t.Fatalf("stats status=%d body=%s", resp.StatusCode, body)
	}

	checkPayload := strings.NewReader(`{"listen":"socks5://127.0.0.1:1","forward":"ws://127.0.0.1:1/tunnel","connections":1}`)
	resp, body = controlRequest(t, client, http.MethodPost, ready.ControlURL+"/v1/config/check", bearer, checkPayload)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("config/check status=%d body=%s", resp.StatusCode, body)
	}
	formatPayload := strings.NewReader(`{"listen":"socks5://127.0.0.1:1","forward":"ws://127.0.0.1:1/tunnel","connections":1}`)
	resp, body = controlRequest(t, client, http.MethodPost, ready.ControlURL+"/v1/config/format", bearer, formatPayload)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "\n  \"listen\"") {
		t.Fatalf("config/format status=%d body=%s", resp.StatusCode, body)
	}
	resp, body = controlRequest(t, client, http.MethodPost, ready.ControlURL+"/v1/runtime/stop", bearer, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("runtime/stop status=%d body=%s", resp.StatusCode, body)
	}
	select {
	case <-engine.done:
	case <-time.After(2 * time.Second):
		t.Fatal("engine did not stop after runtime/stop")
	}
}

func controlRequest(t *testing.T, client *http.Client, method, target, token string, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, string(respBody)
}
