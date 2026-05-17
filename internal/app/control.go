package app

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type controlServer struct {
	engine    *Engine
	token     string
	tokenFile string
	baseURL   string
	server    *http.Server
	listener  *runtimeListener
}

type readyInfo struct {
	PID        int       `json:"pid"`
	Version    string    `json:"version"`
	Commit     string    `json:"commit"`
	ControlURL string    `json:"control_url"`
	TokenFile  string    `json:"token_file"`
	StartedAt  time.Time `json:"started_at"`
}

func startControlServer(ctx context.Context, engine *Engine, addr, tokenFile string) (*controlServer, error) {
	if err := validateControlAddr(addr); err != nil {
		return nil, err
	}
	token, tokenFile, err := writeControlTokenFile(tokenFile)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	control := &controlServer{
		engine:    engine,
		token:     token,
		tokenFile: tokenFile,
		baseURL:   "http://" + ln.Addr().String(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/version", control.handleVersion)
	mux.HandleFunc("/v1/health", control.handleHealth)
	mux.Handle("/v1/status", control.requireAuth(http.HandlerFunc(control.handleStatus)))
	mux.Handle("/v1/logs", control.requireAuth(http.HandlerFunc(control.handleLogs)))
	mux.Handle("/v1/metrics", control.requireAuth(http.HandlerFunc(control.handleMetrics)))
	mux.Handle("/v1/config/check", control.requireAuth(http.HandlerFunc(control.handleConfigCheck)))
	mux.Handle("/v1/config/format", control.requireAuth(http.HandlerFunc(control.handleConfigFormat)))
	mux.Handle("/v1/runtime/stop", control.requireAuth(http.HandlerFunc(control.handleStop)))
	control.server = &http.Server{Handler: mux}
	control.listener = newRuntimeListener("control", addr, control.baseURL, func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), engine.config.values.Global.ShutdownTimeout)
		defer cancel()
		return control.server.Shutdown(shutdownCtx)
	})

	go func() {
		<-ctx.Done()
		_ = control.listener.Close()
	}()
	go func() {
		err := control.server.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			control.listener.finish(err)
			engine.reportFatal(fmt.Errorf("control server failed: %w", err))
			return
		}
		control.listener.finish(nil)
	}()
	log.Printf("[control] HTTP 启动 %s", control.baseURL)
	return control, nil
}

func validateControlAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if strings.TrimSpace(port) == "" {
		return fmt.Errorf("control port 不能为空")
	}
	if port != "0" {
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			return fmt.Errorf("control port 必须在 1-65535 之间")
		}
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("control 只能绑定 127.0.0.1 或 ::1")
	}
	return nil
}

func writeControlTokenFile(path string) (string, string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	token := hex.EncodeToString(tokenBytes)
	if path == "" {
		f, err := os.CreateTemp("", "x-tunnel-control-token-*")
		if err != nil {
			return "", "", err
		}
		path = f.Name()
		if err := f.Close(); err != nil {
			return "", "", err
		}
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return "", "", err
		}
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		return "", "", err
	}
	return token, path, nil
}

func writeReadyFile(path string, info readyInfo) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *controlServer) readyInfo(build BuildInfo) readyInfo {
	return readyInfo{
		PID:        os.Getpid(),
		Version:    build.Version,
		Commit:     build.Commit,
		ControlURL: s.baseURL,
		TokenFile:  s.tokenFile,
		StartedAt:  s.engine.startedAt.UTC(),
	}
}

func (s *controlServer) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r.Header.Get("Authorization")) {
			writeControlJSON(w, http.StatusUnauthorized, map[string]any{
				"ok":    false,
				"error": "unauthorized",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *controlServer) authorized(header string) bool {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(fields[1]), []byte(s.token)) == 1
}

func (s *controlServer) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	writeControlJSON(w, http.StatusOK, map[string]any{
		"version": s.engine.options.Build.Version,
		"commit":  s.engine.options.Build.Commit,
		"build":   s.engine.options.Build.Date,
	})
}

func (s *controlServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	writeControlJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *controlServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	writeControlJSON(w, http.StatusOK, s.engine.Status())
}

func (s *controlServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	writeControlJSON(w, http.StatusOK, map[string]any{"entries": s.engine.logs.Entries(limit)})
}

func (s *controlServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	writeMetrics(w)
}

func (s *controlServer) handleConfigCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeControlJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := CheckConfigJSON(raw); err != nil {
		writeControlJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeControlJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *controlServer) handleConfigFormat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeControlJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	formatted, err := FormatConfigJSON(raw)
	if err != nil {
		writeControlJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(formatted)
}

func (s *controlServer) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeControlJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	writeControlJSON(w, http.StatusOK, map[string]any{"ok": true, "stopping": true})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.engine.config.values.Global.ShutdownTimeout)
		defer cancel()
		_ = s.engine.Close(ctx)
	}()
}

func writeControlJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
