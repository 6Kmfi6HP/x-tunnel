package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

var (
	serverSessionsMu sync.Mutex
	serverSessions   sync.Map // map[string]*ClientSession
	serverNonceCache = newNonceReplayCache(65536)
)

type nonceReplayCache struct {
	mu      sync.Mutex
	max     int
	entries map[string]time.Time
	order   []string
}

func newNonceReplayCache(max int) *nonceReplayCache {
	if max <= 0 {
		max = 65536
	}
	return &nonceReplayCache{max: max, entries: make(map[string]time.Time)}
}

func (c *nonceReplayCache) seenOrStore(sessionID []byte, channelID uint32, nonce []byte, now time.Time, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl > 0 {
		cutoff := now.Add(-ttl)
		filtered := c.order[:0]
		for _, key := range c.order {
			if t, ok := c.entries[key]; ok {
				if t.Before(cutoff) {
					delete(c.entries, key)
					continue
				}
				filtered = append(filtered, key)
			}
		}
		c.order = filtered
	}
	key := fmt.Sprintf("%x:%d:%x", sessionID, channelID, nonce)
	if _, ok := c.entries[key]; ok {
		return true
	}
	c.entries[key] = now
	c.order = append(c.order, key)
	for len(c.order) > c.max {
		old := c.order[0]
		delete(c.entries, old)
		copy(c.order, c.order[1:])
		c.order = c.order[:len(c.order)-1]
	}
	return false
}

type WSChannel struct {
	id           uint64
	conn         *websocket.Conn
	session      *ClientSession
	capabilities uint64
}

type ClientSession struct {
	nextChanID uint64

	clientID string

	mu            sync.RWMutex
	channels      map[uint64]*WSChannel
	activeStreams int
}

func getOrCreateClientSession(clientID string) (*ClientSession, bool) {
	serverSessionsMu.Lock()
	defer serverSessionsMu.Unlock()
	if v, ok := serverSessions.Load(clientID); ok {
		if cs, okType := v.(*ClientSession); okType && cs != nil {
			return cs, true
		}
		serverSessions.Delete(clientID)
	}
	if maxClientSessions > 0 && serverSessionCount() >= maxClientSessions {
		return nil, false
	}
	s := &ClientSession{
		clientID: clientID,
		channels: make(map[uint64]*WSChannel),
	}
	serverSessions.Store(clientID, s)
	return s, true
}

func serverSessionCount() int {
	count := 0
	serverSessions.Range(func(_, value any) bool {
		if cs, ok := value.(*ClientSession); ok && cs != nil {
			count++
		}
		return true
	})
	return count
}

func (s *ClientSession) addChannel(wsConn *websocket.Conn, preferredID uint64) *WSChannel {
	newID := preferredID
	if newID == 0 {
		newID = atomic.AddUint64(&s.nextChanID, 1)
	}
	ch := &WSChannel{
		id:      newID,
		conn:    wsConn,
		session: s,
	}
	var replaced *WSChannel
	s.mu.Lock()
	if old, ok := s.channels[ch.id]; ok {
		replaced = old
	}
	s.channels[ch.id] = ch
	s.mu.Unlock()
	if replaced != nil {
		_ = replaced.conn.Close()
	}
	return ch
}

func (s *ClientSession) removeChannel(id uint64, current *WSChannel) {
	s.mu.Lock()
	if ch, ok := s.channels[id]; ok && ch == current {
		delete(s.channels, id)
	}
	empty := len(s.channels) == 0
	s.mu.Unlock()

	if empty {
		log.Printf("[服务端] 客户端会话 %s 断开", s.clientID)
		serverSessionsMu.Lock()
		if current, ok := serverSessions.Load(s.clientID); ok && current == s {
			serverSessions.Delete(s.clientID)
		}
		serverSessionsMu.Unlock()
	}
}

func (s *ClientSession) tryAcquireStream() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxStreamsPerClient > 0 && s.activeStreams >= maxStreamsPerClient {
		return s.activeStreams, false
	}
	s.activeStreams++
	return s.activeStreams, true
}

func (s *ClientSession) releaseStream() {
	s.mu.Lock()
	if s.activeStreams > 0 {
		s.activeStreams--
	}
	s.mu.Unlock()
}

func (s *ClientSession) activeStreamCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeStreams
}

func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"SelfSigned"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}),
	)
}

func startWebSocketServer(ctx context.Context, addr string, allowedNets []*net.IPNet, shutdownTimeout time.Duration, onFatal func(error)) (*runtimeListener, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("[服务端] WS 地址无效: %w", err)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}

	upgrader := websocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  cfg.ReadBuf,
		WriteBufferSize: cfg.ReadBuf,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "错误的请求", http.StatusBadRequest)
			return
		}
		ip := net.ParseIP(clientIP)
		allowed := false
		for _, n := range allowedNets {
			if n.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			atomic.AddUint64(&serverSourceRejectSeq, 1)
			http.Error(w, "禁止访问", http.StatusForbidden)
			return
		}
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		go handlePreAuthWebSocketChannel(wsConn, clientIP, requestServerName(r), path)
	})

	server := &http.Server{Handler: mux}
	if u.Scheme == "wss" {
		if certFile != "" && keyFile != "" {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("[服务端] TLS 证书加载失败: %w", err)
			}
			server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
		} else {
			cert, err := generateSelfSignedCert()
			if err != nil {
				return nil, fmt.Errorf("[服务端] 生成自签名证书失败: %w", err)
			}
			server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
		}
		if err := configureServerClientAuth(server.TLSConfig); err != nil {
			return nil, fmt.Errorf("[服务端] mTLS 配置失败: %w", err)
		}
	}

	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		return nil, err
	}
	actual := u.Scheme + "://" + ln.Addr().String() + path
	listener := newRuntimeListener(u.Scheme, addr, actual, func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	})
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	if u.Scheme == "wss" {
		if clientCAFile != "" {
			log.Printf("[服务端] mTLS 客户端证书认证已启用")
		}
		log.Printf("[服务端] WSS 启动 %s%s", u.Host, path)
	} else {
		log.Printf("[服务端] WS 启动 %s%s", u.Host, path)
	}
	go func() {
		var err error
		if u.Scheme == "wss" {
			err = server.ServeTLS(ln, "", "")
		} else {
			err = server.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			listener.finish(err)
			if onFatal != nil {
				onFatal(fmt.Errorf("[服务端] %s 启动失败: %w", strings.ToUpper(u.Scheme), err))
			}
			return
		}
		listener.finish(nil)
	}()
	return listener, nil
}

func runWebSocketServer(ctx context.Context, addr string, allowedNets []*net.IPNet) error {
	listener, err := startWebSocketServer(ctx, addr, allowedNets, cfg.ShutdownTimeout, nil)
	if err != nil {
		return err
	}
	<-listener.done
	return nil
}

func shutdownHTTPServer(ctx context.Context, server *http.Server, timeout time.Duration) {
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("[服务端] HTTP 服务关闭失败: %v", err)
	}
}

func startMetricsServer(ctx context.Context, addr string, shutdownTimeout time.Duration) (*runtimeListener, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		writeMetrics(w)
	})
	server := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	listener := newRuntimeListener("metrics", addr, "http://"+ln.Addr().String()+"/metrics", func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	})
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	log.Printf("[metrics] HTTP 启动 %s/metrics", addr)
	go func() {
		err := server.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[metrics] HTTP 启动失败: %v", err)
			listener.finish(err)
			return
		}
		listener.finish(nil)
	}()
	return listener, nil
}

func runMetricsServer(ctx context.Context, addr string) {
	listener, err := startMetricsServer(ctx, addr, cfg.ShutdownTimeout)
	if err != nil {
		log.Printf("[metrics] HTTP 启动失败: %v", err)
		return
	}
	<-listener.done
}

func writeMetrics(w io.Writer) {
	fmt.Fprintf(w, "# TYPE x_tunnel_server_streams_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_streams_total %d\n", atomic.LoadUint64(&serverStreamSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_udp_associations_total counter\n")
	fmt.Fprintf(w, "x_tunnel_udp_associations_total %d\n", atomic.LoadUint64(&udpAssociationSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_udp_associations_active gauge\n")
	fmt.Fprintf(w, "x_tunnel_udp_associations_active %d\n", atomic.LoadUint64(&udpAssociationActiveSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_client_reconnects_total counter\n")
	fmt.Fprintf(w, "x_tunnel_client_reconnects_total %d\n", atomic.LoadUint64(&clientReconnectSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_source_rejections_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_source_rejections_total %d\n", atomic.LoadUint64(&serverSourceRejectSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_auth_rejections_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_auth_rejections_total %d\n", atomic.LoadUint64(&serverAuthRejectSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_client_session_rejections_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_client_session_rejections_total %d\n", atomic.LoadUint64(&serverClientRejectSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_stream_rejections_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_stream_rejections_total %d\n", atomic.LoadUint64(&serverStreamRejectSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_target_rejections_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_target_rejections_total %d\n", atomic.LoadUint64(&serverTargetRejectSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_unsupported_streams_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_unsupported_streams_total %d\n", atomic.LoadUint64(&serverUnsupportedStreamSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_protocol_negotiations_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_protocol_negotiations_total %d\n", atomic.LoadUint64(&serverProtocolOKSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_protocol_negotiation_rejections_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_protocol_negotiation_rejections_total %d\n", atomic.LoadUint64(&serverProtocolRejectSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_protocol_negotiation_failures_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_protocol_negotiation_failures_total %d\n", atomic.LoadUint64(&serverProtocolFailureSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_protocol_v2_accepts_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_protocol_v2_accepts_total %d\n", atomic.LoadUint64(&serverProtocolOKSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_protocol_v2_rejections_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_protocol_v2_rejections_total %d\n", atomic.LoadUint64(&serverProtocolRejectSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_protocol_v2_replay_rejections_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_protocol_v2_replay_rejections_total %d\n", atomic.LoadUint64(&serverProtocolReplaySeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_protocol_v2_auth_failures_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_protocol_v2_auth_failures_total %d\n", atomic.LoadUint64(&serverAuthRejectSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_client_protocol_negotiations_total counter\n")
	fmt.Fprintf(w, "x_tunnel_client_protocol_negotiations_total %d\n", atomic.LoadUint64(&clientProtocolOKSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_client_protocol_negotiation_failures_total counter\n")
	fmt.Fprintf(w, "x_tunnel_client_protocol_negotiation_failures_total %d\n", atomic.LoadUint64(&clientProtocolFailureSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_client_protocol_v2_success_total counter\n")
	fmt.Fprintf(w, "x_tunnel_client_protocol_v2_success_total %d\n", atomic.LoadUint64(&clientProtocolOKSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_client_protocol_v2_failures_total counter\n")
	fmt.Fprintf(w, "x_tunnel_client_protocol_v2_failures_total %d\n", atomic.LoadUint64(&clientProtocolFailureSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_client_rtt_probe_failures_total counter\n")
	fmt.Fprintf(w, "x_tunnel_client_rtt_probe_failures_total %d\n", atomic.LoadUint64(&clientRTTProbeFailureSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_runtime_bytes_sent_total counter\n")
	fmt.Fprintf(w, "x_tunnel_runtime_bytes_sent_total %d\n", atomic.LoadUint64(&runtimeBytesSentSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_runtime_bytes_received_total counter\n")
	fmt.Fprintf(w, "x_tunnel_runtime_bytes_received_total %d\n", atomic.LoadUint64(&runtimeBytesReceivedSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_sessions gauge\n")
	fmt.Fprintf(w, "x_tunnel_server_sessions %d\n", countServerSessions())
	fmt.Fprintf(w, "# TYPE x_tunnel_server_channels gauge\n")
	fmt.Fprintf(w, "x_tunnel_server_channels %d\n", countServerChannels())
	fmt.Fprintf(w, "# TYPE x_tunnel_server_active_streams gauge\n")
	fmt.Fprintf(w, "x_tunnel_server_active_streams %d\n", countServerActiveStreams())
	writeClientChannelMetrics(w, echPool)
}

func writeClientChannelMetrics(w io.Writer, pool *ECHPool) {
	if pool == nil {
		return
	}
	fmt.Fprintf(w, "# TYPE x_tunnel_client_channel_up gauge\n")
	fmt.Fprintf(w, "# TYPE x_tunnel_client_channel_rtt_seconds gauge\n")
	fmt.Fprintf(w, "# TYPE x_tunnel_client_channel_capabilities gauge\n")
	pool.wsConnsMu.RLock()
	defer pool.wsConnsMu.RUnlock()
	for i := range pool.channelRTT {
		up := 0
		if i < len(pool.smuxConns) && pool.smuxConns[i] != nil && !pool.smuxConns[i].IsClosed() {
			up = 1
		}
		var caps uint64
		if i < len(pool.channelCaps) {
			caps = pool.channelCaps[i]
		}
		rttSeconds := float64(atomic.LoadInt64(&pool.channelRTT[i])) / float64(time.Second)
		channelID := i + 1
		fmt.Fprintf(w, "x_tunnel_client_channel_up{channel=\"%d\"} %d\n", channelID, up)
		fmt.Fprintf(w, "x_tunnel_client_channel_rtt_seconds{channel=\"%d\"} %.9f\n", channelID, rttSeconds)
		fmt.Fprintf(w, "x_tunnel_client_channel_capabilities{channel=\"%d\"} %d\n", channelID, caps)
	}
}

func countServerSessions() int {
	count := 0
	serverSessions.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

func countServerChannels() int {
	count := 0
	serverSessions.Range(func(_, value any) bool {
		session, ok := value.(*ClientSession)
		if !ok || session == nil {
			return true
		}
		session.mu.RLock()
		count += len(session.channels)
		session.mu.RUnlock()
		return true
	})
	return count
}

func countServerActiveStreams() int {
	count := 0
	serverSessions.Range(func(_, value any) bool {
		session, ok := value.(*ClientSession)
		if !ok || session == nil {
			return true
		}
		count += session.activeStreamCount()
		return true
	})
	return count
}

// 根据 IP 策略拨号 TCP
func dialTCPWithStrategy(addr string, strategy byte) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return net.DialTimeout("tcp", addr, cfg.DialTimeout)
	}

	if ip := net.ParseIP(host); ip != nil {
		return net.DialTimeout("tcp", addr, cfg.DialTimeout)
	}

	if strategy == IPStrategyIPv4Only {
		return net.DialTimeout("tcp4", addr, cfg.DialTimeout)
	}
	if strategy == IPStrategyIPv6Only {
		return net.DialTimeout("tcp6", addr, cfg.DialTimeout)
	}

	if strategy == IPStrategyPv4Pv6 || strategy == IPStrategyPv6Pv4 {
		resolver := &net.Resolver{}
		ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
		defer cancel()
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}

		var v4, v6 net.IP
		for _, a := range addrs {
			if a.IP.To4() != nil {
				if v4 == nil {
					v4 = a.IP
				}
			} else {
				if v6 == nil {
					v6 = a.IP
				}
			}
			if v4 != nil && v6 != nil {
				break
			}
		}

		var selected net.IP
		if strategy == IPStrategyPv4Pv6 {
			if v4 != nil {
				selected = v4
			} else {
				selected = v6
			}
		} else {
			if v6 != nil {
				selected = v6
			} else {
				selected = v4
			}
		}

		if selected == nil {
			return nil, fmt.Errorf("未找到可用IP: %s", host)
		}

		target := net.JoinHostPort(selected.String(), port)
		return net.DialTimeout("tcp", target, cfg.DialTimeout)
	}

	return net.DialTimeout("tcp", addr, cfg.DialTimeout)
}

func resolveUDPWithStrategy(addr string, strategy byte) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ResolveUDPAddr("udp", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("port 必须在 1-65535 之间")
	}

	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}

	if strategy == IPStrategyIPv4Only {
		return net.ResolveUDPAddr("udp4", addr)
	}
	if strategy == IPStrategyIPv6Only {
		return net.ResolveUDPAddr("udp6", addr)
	}

	if strategy == IPStrategyPv4Pv6 || strategy == IPStrategyPv6Pv4 {
		resolver := &net.Resolver{}
		ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
		defer cancel()
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}

		var v4, v6 net.IP
		for _, a := range addrs {
			if a.IP.To4() != nil {
				if v4 == nil {
					v4 = a.IP
				}
			} else {
				if v6 == nil {
					v6 = a.IP
				}
			}
			if v4 != nil && v6 != nil {
				break
			}
		}

		var selected net.IP
		if strategy == IPStrategyPv4Pv6 {
			if v4 != nil {
				selected = v4
			} else {
				selected = v6
			}
		} else {
			if v6 != nil {
				selected = v6
			} else {
				selected = v4
			}
		}

		if selected == nil {
			return nil, fmt.Errorf("未找到可用IP: %s", host)
		}
		return &net.UDPAddr{IP: selected, Port: port}, nil
	}

	return net.ResolveUDPAddr("udp", addr)
}

// ======================== WebSocket 处理逻辑 ========================

func requestServerName(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSpace(host))
}

func handlePreAuthWebSocketChannel(wsConn *websocket.Conn, clientIP string, serverName string, path string) {
	netConn := newWSNetConn(wsConn)
	_ = netConn.SetDeadline(time.Now().Add(cfg.PreAuthTimeout))
	sess, err := smux.Server(netConn, nil)
	if err != nil {
		_ = wsConn.Close()
		log.Printf("[服务端] v2 预认证 smux 初始化失败: %v", err)
		return
	}
	defer sess.Close()

	stream, err := sess.AcceptStream()
	if err != nil {
		_ = wsConn.Close()
		atomic.AddUint64(&serverProtocolFailureSeq, 1)
		log.Printf("[服务端] v2 预认证等待 ChannelInit 失败: %v", err)
		return
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(cfg.PreAuthTimeout))
	init, err := readChannelInit(stream, maxV2FrameSize)
	if err != nil {
		atomic.AddUint64(&serverProtocolFailureSeq, 1)
		_ = writeChannelReject(stream, ChannelReject{Code: v2RejectMalformedFrame, Message: "malformed ChannelInit"})
		_ = wsConn.Close()
		log.Printf("[服务端] v2 ChannelInit 读取失败: %v", err)
		return
	}
	now := time.Now()
	if !validateChannelInitTime(now, init.Timestamp, cfg.AuthSkew) {
		atomic.AddUint64(&serverProtocolRejectSeq, 1)
		_ = writeChannelReject(stream, ChannelReject{Code: v2RejectTimestampSkew, Message: "timestamp skew"})
		_ = wsConn.Close()
		log.Printf("[服务端] v2 ChannelInit 时间戳拒绝，来源 IP: %s", clientIP)
		return
	}
	if !verifyV2AuthProof(token, serverName, path, init) {
		atomic.AddUint64(&serverAuthRejectSeq, 1)
		atomic.AddUint64(&serverProtocolFailureSeq, 1)
		_ = writeChannelReject(stream, ChannelReject{Code: v2RejectAuthenticationFailed, Message: "auth proof invalid"})
		_ = wsConn.Close()
		log.Printf("[服务端] v2 认证失败，来源 IP: %s", clientIP)
		return
	}
	if serverNonceCache.seenOrStore(init.SessionID, init.ChannelID, init.ClientNonce, now, cfg.AuthSkew) {
		atomic.AddUint64(&serverProtocolReplaySeq, 1)
		atomic.AddUint64(&serverProtocolRejectSeq, 1)
		_ = writeChannelReject(stream, ChannelReject{Code: v2RejectReplayDetected, Message: "nonce replay"})
		_ = wsConn.Close()
		log.Printf("[服务端] v2 ChannelInit nonce 重放，来源 IP: %s", clientIP)
		return
	}
	caps, rejectCode, rejectMessage := negotiateProtocolCapabilitiesV2(init.Capabilities)
	if rejectCode != 0 {
		atomic.AddUint64(&serverProtocolRejectSeq, 1)
		_ = writeChannelReject(stream, ChannelReject{Code: rejectCode, Message: rejectMessage})
		_ = wsConn.Close()
		log.Printf("[服务端] v2 协议能力拒绝: %s", rejectMessage)
		return
	}
	sessionID := hex.EncodeToString(init.SessionID)
	session, ok := getOrCreateClientSession(sessionID)
	if !ok {
		atomic.AddUint64(&serverClientRejectSeq, 1)
		_ = writeChannelReject(stream, ChannelReject{Code: v2RejectResourceLimit, Message: "max clients reached"})
		_ = wsConn.Close()
		log.Printf("[服务端] 拒绝 v2 客户端会话: session=%s max-clients=%d", shortID(sessionID), maxClientSessions)
		return
	}
	ch := session.addChannel(wsConn, uint64(init.ChannelID))
	atomic.StoreUint64(&ch.capabilities, caps)
	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		atomic.AddUint64(&serverProtocolFailureSeq, 1)
		session.removeChannel(ch.id, ch)
		_ = wsConn.Close()
		log.Printf("[服务端] v2 server nonce 生成失败: %v", err)
		return
	}
	accept := ChannelAccept{
		Capabilities: caps,
		ServerNonce:  serverNonce,
		ServerTime:   now.Unix(),
		MaxFrameSize: maxV2FrameSize,
	}
	if maxStreamsPerClient > 0 {
		accept.MaxStreams = uint32(maxStreamsPerClient)
	}
	if err := writeChannelAccept(stream, accept); err != nil {
		atomic.AddUint64(&serverProtocolFailureSeq, 1)
		session.removeChannel(ch.id, ch)
		_ = wsConn.Close()
		log.Printf("[服务端] v2 ChannelAccept 写入失败: %v", err)
		return
	}
	atomic.AddUint64(&serverProtocolOKSeq, 1)
	log.Printf("[服务端] v2 客户端通道 %d 连接, 会话ID: %s, IP: %s caps=0x%x", ch.id, shortID(sessionID), clientIP, caps)
	_ = stream.SetDeadline(time.Time{})
	_ = netConn.SetDeadline(time.Time{})
	handleAuthenticatedSmuxSession(ch, sess)
}

func validateChannelInitTime(now time.Time, timestamp int64, skew time.Duration) bool {
	if skew <= 0 {
		return true
	}
	then := time.Unix(timestamp, 0)
	return !then.Before(now.Add(-skew)) && !then.After(now.Add(skew))
}

func handleAuthenticatedSmuxSession(ch *WSChannel, sess *smux.Session) {
	wsConn := ch.conn
	session := ch.session

	defer func() {
		_ = wsConn.Close()
		session.removeChannel(ch.id, ch)
	}()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			log.Printf("[服务端] 客户端通道 %d 断开", ch.id)
			return
		}
		if active, ok := session.tryAcquireStream(); !ok {
			atomic.AddUint64(&serverStreamRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s 通道:%d 拒绝新 stream: active=%d max-streams=%d", shortID(session.clientID), ch.id, active, maxStreamsPerClient)
			rejectSmuxStreamDueToLimit(ch, stream)
			continue
		}
		go handleSmuxStream(session, ch, stream)
	}
}

func handleWebSocketChannel(ch *WSChannel) {
	netConn := newWSNetConn(ch.conn)
	sess, err := smux.Server(netConn, nil)
	if err != nil {
		log.Printf("[服务端] 通道 %d smux 初始化失败: %v", ch.id, err)
		_ = ch.conn.Close()
		ch.session.removeChannel(ch.id, ch)
		return
	}
	defer sess.Close()
	handleAuthenticatedSmuxSession(ch, sess)
}

func rejectSmuxStreamDueToLimit(ch *WSChannel, stream *smux.Stream) {
	defer stream.Close()
	timeout := cfg.RTTProbeTimeout
	if timeout <= 0 || timeout > 200*time.Millisecond {
		timeout = 200 * time.Millisecond
	}
	_ = stream.SetDeadline(time.Now().Add(timeout))
	kind, _, _, err := readSmuxOpenHeader(stream)
	_ = stream.SetDeadline(time.Time{})
	if err != nil {
		return
	}
	caps := atomic.LoadUint64(&ch.capabilities)
	if kind == streamKindTCP {
		_ = writeTCPOpenFailure(stream, caps, openStatusCodeResourceLimit, "max streams reached")
		return
	}
	if kind == streamKindUDP {
		_ = writeUDPOpenFailure(stream, caps, openStatusCodeResourceLimit, "max streams reached")
	}
}

func openStatusCodeName(code byte) string {
	switch code {
	case openStatusCodeNone:
		return "none"
	case openStatusCodeBadTarget:
		return "bad_target"
	case openStatusCodePolicyDenied:
		return "policy_denied"
	case openStatusCodeDialFailed:
		return "dial_failed"
	case openStatusCodeResourceLimit:
		return "resource_limit"
	default:
		return fmt.Sprintf("code_%d", code)
	}
}

func formatOpenStatusError(status byte, code byte, message string) string {
	if message == "" {
		message = fmt.Sprintf("status=%d", status)
	}
	if code == openStatusCodeNone {
		return message
	}
	return fmt.Sprintf("%s: %s", openStatusCodeName(code), message)
}

type remoteOpenError struct {
	network string
	status  byte
	code    byte
	message string
}

func (e *remoteOpenError) Error() string {
	return fmt.Sprintf("远端 %s 打开失败: %s", e.network, formatOpenStatusError(e.status, e.code, e.message))
}

func writeTCPOpenSuccess(w io.Writer, caps uint64) error {
	if caps&protocolCapabilityOpenStatusCode != 0 {
		return writeTCPOpenStatusCode(w, tcpOpenStatusOK, openStatusCodeNone, "")
	}
	return writeTCPOpenStatus(w, tcpOpenStatusOK, "")
}

func writeTCPOpenFailure(w io.Writer, caps uint64, code byte, message string) error {
	if caps&protocolCapabilityOpenStatusCode != 0 {
		return writeTCPOpenStatusCode(w, tcpOpenStatusError, code, message)
	}
	return writeTCPOpenStatus(w, tcpOpenStatusError, message)
}

func writeUDPOpenSuccess(w io.Writer, caps uint64) error {
	if caps&protocolCapabilityOpenStatusCode != 0 {
		return writeUDPOpenStatusCode(w, udpOpenStatusOK, openStatusCodeNone, "")
	}
	return writeUDPOpenStatus(w, udpOpenStatusOK, "")
}

func writeUDPOpenFailure(w io.Writer, caps uint64, code byte, message string) error {
	if caps&protocolCapabilityOpenStatusCode != 0 {
		return writeUDPOpenStatusCode(w, udpOpenStatusError, code, message)
	}
	return writeUDPOpenStatus(w, udpOpenStatusError, message)
}

func socks5ReplyForOpenError(err error) byte {
	var openErr *remoteOpenError
	if errors.As(err, &openErr) && openErr.code == openStatusCodePolicyDenied {
		return 0x02
	}
	return 0x05
}

func httpStatusForOpenError(err error) int {
	var openErr *remoteOpenError
	if errors.As(err, &openErr) && openErr.code == openStatusCodePolicyDenied {
		return http.StatusForbidden
	}
	return http.StatusBadGateway
}

func handleSmuxStream(session *ClientSession, ch *WSChannel, stream *smux.Stream) {
	defer func() {
		session.releaseStream()
		stream.Close()
	}()
	streamID := atomic.AddUint64(&serverStreamSeq, 1)
	_ = stream.SetDeadline(time.Now().Add(cfg.RTTProbeTimeout))
	kind, strategy, target, err := readSmuxOpenHeader(stream)
	if err != nil {
		return
	}
	_ = stream.SetDeadline(time.Time{})
	log.Printf("[服务端] stream=%d client=%s channel=%d kind=%d target=%s", streamID, shortID(session.clientID), ch.id, kind, target)
	if !isSupportedStreamKind(kind) {
		atomic.AddUint64(&serverUnsupportedStreamSeq, 1)
		log.Printf("[服务端] 客户ID:%s 不支持的 stream kind: %d, target=%s, 通道:%d", shortID(session.clientID), kind, target, ch.id)
		return
	}
	switch kind {
	case streamKindPing:
		_ = stream.SetDeadline(time.Now().Add(cfg.RTTProbeTimeout))
		defer stream.SetDeadline(time.Time{})
		payload := make([]byte, 8)
		if _, err := io.ReadFull(stream, payload); err != nil {
			return
		}
		_ = writeAll(stream, payload)
	case streamKindTCP:
		log.Printf("[服务端] 客户ID:%s TCP 打开: %s, 通道:%d", shortID(session.clientID), target, ch.id)
		caps := atomic.LoadUint64(&ch.capabilities)
		if err := validateIPStrategyValue(strategy); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s TCP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			_ = writeTCPOpenFailure(stream, caps, openStatusCodeBadTarget, err.Error())
			return
		}
		if err := validateSmuxStreamTarget(target); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s TCP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			_ = writeTCPOpenFailure(stream, caps, openStatusCodeBadTarget, err.Error())
			return
		}
		if err := ensureTargetAllowed(target); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s TCP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			_ = writeTCPOpenFailure(stream, caps, openStatusCodePolicyDenied, err.Error())
			return
		}
		var tcpConn net.Conn
		if socks5Config != nil {
			tcpConn, err = dialViaSocks5("tcp", target)
		} else {
			tcpConn, err = dialTCPWithStrategy(target, strategy)
		}
		if err != nil {
			log.Printf("[服务端] 客户ID:%s TCP 连接失败: %s, err=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			_ = writeTCPOpenFailure(stream, caps, openStatusCodeDialFailed, err.Error())
			return
		}
		if err := writeTCPOpenSuccess(stream, caps); err != nil {
			_ = tcpConn.Close()
			return
		}
		proxyConnStream(tcpConn, stream)
		log.Printf("[服务端] 客户ID:%s TCP 关闭: %s, 通道:%d", shortID(session.clientID), target, ch.id)
	case streamKindUDP:
		log.Printf("[服务端] 客户ID:%s SOCKS5 UDP 访问: %s, 通道:%d", shortID(session.clientID), target, ch.id)
		caps := atomic.LoadUint64(&ch.capabilities)
		if err := validateIPStrategyValue(strategy); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s UDP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			_ = writeUDPOpenFailure(stream, caps, openStatusCodeBadTarget, err.Error())
			return
		}
		if err := validateSmuxStreamTarget(target); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s UDP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			_ = writeUDPOpenFailure(stream, caps, openStatusCodeBadTarget, err.Error())
			return
		}
		if err := ensureTargetAllowed(target); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s UDP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			_ = writeUDPOpenFailure(stream, caps, openStatusCodePolicyDenied, err.Error())
			return
		}
		var relay UDPRelayer
		if socks5Config != nil {
			var socksRelay *SOCKS5UDPRelay
			socksRelay, err = newSOCKS5UDPRelay(target)
			if err != nil {
				log.Printf("[服务端] 客户ID:%s SOCKS5 UDP中继创建失败: %v, 通道:%d", shortID(session.clientID), err, ch.id)
				_ = writeUDPOpenFailure(stream, caps, openStatusCodeDialFailed, err.Error())
				return
			}
			relay = socksRelay
		} else {
			addr, errResolve := resolveUDPWithStrategy(target, strategy)
			if errResolve != nil {
				log.Printf("[服务端] 客户ID:%s UDP 解析失败: %s, err=%v, 通道:%d", shortID(session.clientID), target, errResolve, ch.id)
				_ = writeUDPOpenFailure(stream, caps, openStatusCodeDialFailed, errResolve.Error())
				return
			}
			udpConn, errListen := net.ListenUDP("udp", nil)
			if errListen != nil {
				log.Printf("[服务端] 客户ID:%s UDP 监听失败: %s, err=%v, 通道:%d", shortID(session.clientID), target, errListen, ch.id)
				_ = writeUDPOpenFailure(stream, caps, openStatusCodeDialFailed, errListen.Error())
				return
			}
			relay = &DirectUDPRelayer{conn: udpConn, target: addr}
		}
		if relay == nil {
			return
		}
		defer relay.Close()
		if err := writeUDPOpenSuccess(stream, caps); err != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer relay.Close()
			for {
				packet, e := readChunk(stream)
				if e != nil {
					return
				}
				if len(packet) == 0 {
					continue
				}
				if _, e = relay.Write(packet); e != nil {
					log.Printf("[服务端] 客户ID:%s UDP 写入失败: %s, err=%v, 通道:%d", shortID(session.clientID), target, e, ch.id)
					return
				}
			}
		}()
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		defer bufPool.Put(bufPtr)
		for {
			_ = relay.SetReadDeadline(time.Now().Add(cfg.UDPReadTimeout))
			n, addr, e := relay.Read(buf)
			if e != nil {
				if netErr, ok := e.(net.Error); ok && netErr.Timeout() {
					select {
					case <-done:
						return
					default:
						continue
					}
				}
				select {
				case <-done:
					return
				default:
				}
				log.Printf("[服务端] 客户ID:%s UDP 读取失败: %s, err=%v, 通道:%d", shortID(session.clientID), target, e, ch.id)
				return
			}
			if err := writeUDPReply(stream, addr, buf[:n]); err != nil {
				log.Printf("[服务端] 客户ID:%s UDP 响应写入失败: %s, err=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
				return
			}
		}
	}
}

// ======================== 多通道客户端池 ========================
