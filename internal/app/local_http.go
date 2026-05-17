package app

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func startHTTPListener(ctx context.Context, addr string) (*runtimeListener, error) {
	h, u, p, err := parseAuthAndAddr(strings.TrimPrefix(addr, "http://"))
	if err != nil {
		return nil, fmt.Errorf("[客户端] HTTP地址解析失败: %w", err)
	}
	l, err := net.Listen("tcp", h)
	if err != nil {
		return nil, fmt.Errorf("[客户端] HTTP监听失败: %w", err)
	}
	listener := newRuntimeListener("http", addr, "http://"+l.Addr().String(), l.Close)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	log.Printf("[客户端] HTTP 代理: %s", h)
	cfgp := &ProxyConfig{u, p, h}
	go func() {
		defer listener.finish(nil)
		for {
			c, err := l.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			go handleHTTP(c, cfgp)
		}
	}()
	return listener, nil
}

func runHTTPListener(ctx context.Context, addr string) error {
	listener, err := startHTTPListener(ctx, addr)
	if err != nil {
		return err
	}
	<-listener.done
	return nil
}

func handleHTTP(c net.Conn, cfgp *ProxyConfig) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(cfg.DialTimeout))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	if cfgp.Username != "" {
		if !validHTTPProxyBasicAuth(req.Header.Get("Proxy-Authorization"), cfgp.Username, cfgp.Password) {
			_ = writeHTTPProxyResponse(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"代理\"\r\nContent-Length: 0\r\n\r\n")
			return
		}
	}
	sanitizeHTTPProxyRequest(req)

	target, err := httpProxyTarget(req)
	if err != nil {
		_ = writeHTTPProxyResponse(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}

	if req.Method != "CONNECT" {
		addHTTPProxyViaHeader(req.Header)
		req.RequestURI = ""
		req.URL.Scheme = ""
		req.URL.Host = ""
	}

	stream, _, decision, err := echPool.openTCPStream(target)
	if err != nil {
		log.Printf("[客户端] %s HTTP 打开失败 %s: %v", clientSourceAddr(c), target, err)
		status := httpStatusForOpenError(err)
		_ = writeHTTPProxyResponse(c, fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status)))
		return
	}
	if req.Method == "CONNECT" {
		if err := writeHTTPProxyResponse(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = stream.Close()
			return
		}
		if err := forwardBufferedHTTPBytes(br, stream); err != nil {
			_ = stream.Close()
			return
		}
	}
	if req.Method != "CONNECT" {
		if err := req.Write(stream); err != nil {
			_ = stream.Close()
			return
		}
	}
	logClientConnEvent(c, "HTTP", target, decision, true)
	defer logClientConnEvent(c, "HTTP", target, decision, false)
	proxyConnStream(c, stream)
}

func writeHTTPProxyResponse(w io.Writer, response string) error {
	return writeAll(w, []byte(response))
}

func validHTTPProxyBasicAuth(auth, username, password string) bool {
	fields := strings.Fields(auth)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return false
	}
	want := []byte(username + ":" + password)
	return subtle.ConstantTimeCompare(decoded, want) == 1
}

var httpHopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

const httpProxyViaValue = "1.1 x-tunnel"

func stripHTTPProxyHeaders(h http.Header) {
	for _, connection := range h.Values("Connection") {
		for _, token := range strings.Split(connection, ",") {
			if token = strings.TrimSpace(token); token != "" {
				h.Del(token)
			}
		}
	}
	for _, name := range httpHopByHopHeaders {
		h.Del(name)
	}
}

func addHTTPProxyViaHeader(h http.Header) {
	h.Add("Via", httpProxyViaValue)
}

func sanitizeHTTPProxyRequest(req *http.Request) {
	stripHTTPProxyHeaders(req.Header)
	req.Close = false
}

func forwardBufferedHTTPBytes(br *bufio.Reader, stream io.Writer) error {
	buffered := br.Buffered()
	if buffered == 0 {
		return nil
	}
	data := make([]byte, buffered)
	if _, err := io.ReadFull(br, data); err != nil {
		return err
	}
	return writeAll(stream, data)
}

func httpProxyTarget(req *http.Request) (string, error) {
	if req == nil {
		return "", fmt.Errorf("请求为空")
	}
	defaultPort := "80"
	if req.Method == "CONNECT" {
		defaultPort = "443"
	}

	target := strings.TrimSpace(req.Host)
	if req.Method != "CONNECT" && req.URL != nil && req.URL.IsAbs() {
		if !strings.EqualFold(req.URL.Scheme, "http") {
			return "", fmt.Errorf("不支持的代理 URL scheme: %s", req.URL.Scheme)
		}
		if req.URL.User != nil {
			return "", fmt.Errorf("代理目标不能包含 userinfo")
		}
		target = strings.TrimSpace(req.URL.Host)
		if req.Host != "" {
			hostTarget, err := normalizeHTTPProxyAuthority(req.Host, defaultPort)
			if err != nil {
				return "", err
			}
			urlTarget, err := normalizeHTTPProxyAuthority(target, defaultPort)
			if err != nil {
				return "", err
			}
			if !strings.EqualFold(hostTarget, urlTarget) {
				return "", fmt.Errorf("Host 与代理目标不一致")
			}
			return urlTarget, nil
		}
	}
	return normalizeHTTPProxyAuthority(target, defaultPort)
}

func normalizeHTTPProxyAuthority(authority, defaultPort string) (string, error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", fmt.Errorf("代理目标不能为空")
	}
	if strings.ContainsAny(authority, " \t\r\n") {
		return "", fmt.Errorf("代理目标包含非法字符")
	}
	if host, port, err := net.SplitHostPort(authority); err == nil {
		if strings.TrimSpace(host) == "" {
			return "", fmt.Errorf("host 不能为空")
		}
		if err := validateHostnameOrIP(host); err != nil {
			return "", err
		}
		if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
			return "", fmt.Errorf("port 必须在 1-65535 之间")
		}
		return net.JoinHostPort(host, port), nil
	}
	if strings.HasPrefix(authority, "[") {
		if !strings.HasSuffix(authority, "]") {
			return "", fmt.Errorf("IPv6 地址格式无效")
		}
		host := strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")
		if net.ParseIP(host) == nil {
			return "", fmt.Errorf("IPv6 地址格式无效")
		}
		return net.JoinHostPort(host, defaultPort), nil
	}
	if strings.Contains(authority, ":") {
		return "", fmt.Errorf("代理目标地址无效")
	}
	if err := validateHostnameOrIP(authority); err != nil {
		return "", err
	}
	return net.JoinHostPort(authority, defaultPort), nil
}
