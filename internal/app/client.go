package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

type ECHPool struct {
	wsServerAddr  string
	connectionNum int
	targetIPs     []string
	clientID      string

	wsConnsMu     sync.RWMutex
	smuxConns     []*smux.Session
	channelRTT    []int64
	channelCaps   []uint64
	selectCounter uint64
}

func NewECHPool(addr string, n int, ips []string, clientID string) *ECHPool {
	total := n
	if len(ips) > 0 {
		total = len(ips) * n
	}
	p := &ECHPool{
		wsServerAddr:  addr,
		connectionNum: n,
		targetIPs:     ips,
		clientID:      clientID,
		smuxConns:     make([]*smux.Session, total),
		channelRTT:    make([]int64, total),
		channelCaps:   make([]uint64, total),
	}
	return p
}

func (p *ECHPool) Start(ctx context.Context) {
	for i := 0; i < len(p.smuxConns); i++ {
		ip := ""
		if len(p.targetIPs) > 0 {
			if idx := i / p.connectionNum; idx < len(p.targetIPs) {
				ip = p.targetIPs[idx]
			}
		}
		go p.dialAndServe(ctx, i, ip)
	}
}

func (p *ECHPool) dialAndServe(ctx context.Context, idx int, ip string) {
	chID := idx + 1
	ipLabel := ip
	if strings.TrimSpace(ipLabel) == "" {
		ipLabel = "自动解析"
	}
	reconnectAttempt := 0
	sleepBeforeReconnect := func(reason string) bool {
		delay := reconnectDelay(reconnectAttempt)
		atomic.AddUint64(&clientReconnectSeq, 1)
		log.Printf("[客户端] 通道 %d (IP:%s) %s，%s 后重试 (attempt=%d)", chID, ipLabel, reason, delay, reconnectAttempt+1)
		reconnectAttempt++
		return sleepWithContext(ctx, delay)
	}
	for {
		if ctx.Err() != nil {
			return
		}
		wsConn, err := dialWebSocketWithECH(p.wsServerAddr, 3, ip)
		if err != nil {
			if !sleepBeforeReconnect(fmt.Sprintf("连接失败: %v", err)) {
				return
			}
			continue
		}
		wsNet := newWSNetConn(wsConn)
		sess, err := smux.Client(wsNet, nil)
		if err != nil {
			_ = wsConn.Close()
			if !sleepBeforeReconnect(fmt.Sprintf("smux 初始化失败: %v", err)) {
				return
			}
			continue
		}
		caps, err := negotiateClientProtocol(sess, cfg.RTTProbeTimeout, p.clientID, uint32(chID), p.wsServerAddr)
		if err != nil {
			atomic.AddUint64(&clientProtocolFailureSeq, 1)
			_ = sess.Close()
			_ = wsConn.Close()
			if !sleepBeforeReconnect(fmt.Sprintf("协议协商失败: %v", err)) {
				return
			}
			continue
		}
		atomic.AddUint64(&clientProtocolOKSeq, 1)
		log.Printf("[客户端] 通道 %d (IP:%s) v2 协议协商成功: version=2 caps=0x%x", chID, ipLabel, caps)
		p.wsConnsMu.Lock()
		p.smuxConns[idx] = sess
		p.channelRTT[idx] = 0
		p.channelCaps[idx] = caps
		p.wsConnsMu.Unlock()
		log.Printf("[客户端] 通道 %d (IP:%s) 就绪 (smux)", chID, ipLabel)
		reconnectAttempt = 0
		if rtt, err := p.probeChannelRTTOnce(sess, cfg.RTTProbeTimeout); err == nil {
			atomic.StoreInt64(&p.channelRTT[idx], rtt)
		} else {
			atomic.AddUint64(&clientRTTProbeFailureSeq, 1)
		}

		done := make(chan error, 1)
		go p.probeChannelRTT(sess, idx, done)
		var probeErr error
		select {
		case probeErr = <-done:
		case <-wsNet.Dead():
			_ = sess.Close()
			<-done
			probeErr = wsNet.DeadErr()
			if probeErr == nil {
				probeErr = io.EOF
			}
		case <-ctx.Done():
			_ = sess.Close()
			<-done
			probeErr = ctx.Err()
		}

		_ = sess.Close()
		_ = wsConn.Close()

		p.wsConnsMu.Lock()
		p.smuxConns[idx] = nil
		p.channelRTT[idx] = 0
		p.channelCaps[idx] = 0
		p.wsConnsMu.Unlock()
		if probeErr != nil {
			log.Printf("[客户端] 通道 %d 断开原因: %v", chID, probeErr)
		}
		if ctx.Err() != nil {
			return
		}
		if !sleepBeforeReconnect("断开") {
			return
		}
	}
}

func (p *ECHPool) probeChannelRTT(sess *smux.Session, idx int, done chan error) {
	var exitErr error
	defer func() {
		done <- exitErr
		close(done)
	}()
	ticker := time.NewTicker(cfg.RTTProbeTimeout)
	defer ticker.Stop()
	for {
		rtt, err := p.probeChannelRTTOnce(sess, cfg.RTTProbeTimeout)
		if err != nil {
			atomic.AddUint64(&clientRTTProbeFailureSeq, 1)
			atomic.StoreInt64(&p.channelRTT[idx], int64(cfg.RTTProbeTimeout.Nanoseconds()))
			if sess.IsClosed() {
				exitErr = err
				return
			}
			<-ticker.C
			continue
		}
		atomic.StoreInt64(&p.channelRTT[idx], rtt)
		<-ticker.C
	}
}

func (p *ECHPool) probeChannelRTTOnce(sess *smux.Session, timeout time.Duration) (int64, error) {
	start := time.Now()
	s, err := sess.OpenStream()
	if err != nil {
		return 0, err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(timeout))
	if err := writeSmuxOpenHeader(s, streamKindPing, 0, ""); err != nil {
		return 0, err
	}
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(start.UnixNano()))
	if err := writeAll(s, payload); err != nil {
		return 0, err
	}
	ack := make([]byte, 8)
	if _, err := io.ReadFull(s, ack); err != nil {
		return 0, err
	}
	if !bytes.Equal(ack, payload) {
		return 0, fmt.Errorf("ping ack mismatch")
	}
	return time.Since(start).Nanoseconds(), nil
}

func negotiateClientProtocol(sess *smux.Session, timeout time.Duration, clientID string, channelID uint32, serverAddr string) (uint64, error) {
	s, err := sess.OpenStream()
	if err != nil {
		return 0, err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(timeout))
	sessionID, err := clientSessionIDBytes(clientID)
	if err != nil {
		return 0, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	serverName, serverPath, err := protocolAuthEndpoint(serverAddr)
	if err != nil {
		return 0, err
	}
	init := ChannelInit{
		SessionID:    sessionID,
		ChannelID:    channelID,
		ClientNonce:  nonce,
		Timestamp:    time.Now().Unix(),
		Capabilities: currentProtocolCapabilitiesV2(),
	}
	proof, err := computeV2AuthProof(token, serverName, serverPath, init)
	if err != nil {
		return 0, err
	}
	init.AuthProof = proof
	if err := writeChannelInit(s, init); err != nil {
		return 0, err
	}
	accept, reject, err := readChannelAcceptOrReject(s, maxV2FrameSize)
	if err != nil {
		return 0, err
	}
	if reject.Code != 0 {
		if reject.Code == v2RejectAuthenticationFailed {
			if reject.Message != "" {
				return 0, fmt.Errorf("认证失败: %s", reject.Message)
			}
			return 0, fmt.Errorf("认证失败")
		}
		if reject.Message != "" {
			return 0, fmt.Errorf("协议协商失败: reject=%d %s", reject.Code, reject.Message)
		}
		return 0, fmt.Errorf("协议协商失败: reject=%d", reject.Code)
	}
	required := requiredProtocolCapabilitiesV2()
	if accept.Capabilities&required != required {
		return 0, fmt.Errorf("协议能力不足: caps=0x%x", accept.Capabilities)
	}
	return accept.Capabilities, nil
}

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

func clientSessionIDBytes(clientID string) ([]byte, error) {
	id, err := uuid.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("client id invalid: %w", err)
	}
	return id[:], nil
}

func protocolAuthEndpoint(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	serverName := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if serverName == "" {
		return "", "", fmt.Errorf("server name is empty")
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return serverName, path, nil
}

const defaultWebSocketUserAgent = "Mozilla/5.0"

func webSocketRequestHeader() http.Header {
	header := make(http.Header)
	header.Set("User-Agent", defaultWebSocketUserAgent)
	header.Set("Accept-Language", "en-US,en;q=0.9")
	header.Set("Cache-Control", "no-cache")
	header.Set("Pragma", "no-cache")
	return header
}

func proxyConnStream(c net.Conn, stream *smux.Stream) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(stream, c)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, stream)
		done <- struct{}{}
	}()
	<-done

	// 立即关闭双方，强制中断另一方向的 io.Copy
	_ = stream.Close()
	_ = c.Close()

	<-done // 等待另一方向退出
}

func clientSourceAddr(c net.Conn) string {
	if ra := c.RemoteAddr(); ra != nil {
		return ra.String()
	}
	return "-"
}

func logClientConnEvent(c net.Conn, reqType, target string, chID int, opened bool) {
	arrow := "关闭"
	if opened {
		arrow = "打开"
	}
	log.Printf("[客户端] %s %s %s %s 通道 %d", clientSourceAddr(c), reqType, arrow, target, chID)
}

func (p *ECHPool) openBestStream() (*smux.Stream, int, int, uint64, error) {
	p.wsConnsMu.RLock()
	type candidate struct {
		idx int
		rtt int64
	}
	cands := make([]candidate, 0, len(p.smuxConns))
	for i, sess := range p.smuxConns {
		if sess == nil || sess.IsClosed() {
			continue
		}
		rtt := atomic.LoadInt64(&p.channelRTT[i])
		if rtt <= 0 {
			rtt = int64(cfg.RTTProbeTimeout.Nanoseconds())
		}
		cands = append(cands, candidate{idx: i, rtt: rtt})
	}
	p.wsConnsMu.RUnlock()
	if len(cands) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("无可用 smux 通道")
	}
	minRTT := cands[0].rtt
	for _, c := range cands[1:] {
		if c.rtt < minRTT {
			minRTT = c.rtt
		}
	}
	tieWindow := int64((10 * time.Millisecond).Nanoseconds())
	near := make([]candidate, 0, len(cands))
	for _, c := range cands {
		if c.rtt <= minRTT+tieWindow {
			near = append(near, c)
		}
	}
	pick := int(atomic.AddUint64(&p.selectCounter, 1)-1) % len(near)
	best := near[pick]
	p.wsConnsMu.RLock()
	sess := p.smuxConns[best.idx]
	caps := p.channelCaps[best.idx]
	p.wsConnsMu.RUnlock()
	if sess == nil || sess.IsClosed() {
		return nil, 0, 0, 0, fmt.Errorf("通道不可用")
	}
	decision := best.idx + 1
	s, err := sess.OpenStream()
	if err != nil {
		return nil, 0, 0, 0, err
	}
	return s, best.idx + 1, decision, caps, nil
}

func (p *ECHPool) openTCPStream(target string) (*smux.Stream, int, int, error) {
	s, chID, decision, caps, err := p.openBestStream()
	if err != nil {
		return nil, 0, 0, err
	}
	if err := writeSmuxOpenHeader(s, streamKindTCP, ipStrategy, target); err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	_ = s.SetDeadline(time.Now().Add(cfg.DialTimeout))
	var status byte
	var code byte
	var message string
	if caps&protocolCapabilityOpenStatusCode != 0 {
		status, code, message, err = readTCPOpenStatusCode(s)
	} else {
		status, message, err = readTCPOpenStatus(s)
	}
	_ = s.SetDeadline(time.Time{})
	if err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	if status != tcpOpenStatusOK {
		_ = s.Close()
		return nil, 0, 0, &remoteOpenError{network: "TCP", status: status, code: code, message: message}
	}
	return s, chID, decision, nil
}

func (p *ECHPool) openUDPStream(target string) (*smux.Stream, int, int, error) {
	s, chID, decision, caps, err := p.openBestStream()
	if err != nil {
		return nil, 0, 0, err
	}
	if err := writeSmuxOpenHeader(s, streamKindUDP, ipStrategy, target); err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	_ = s.SetDeadline(time.Now().Add(cfg.DialTimeout))
	var status byte
	var code byte
	var message string
	if caps&protocolCapabilityOpenStatusCode != 0 {
		status, code, message, err = readUDPOpenStatusCode(s)
	} else {
		status, message, err = readUDPOpenStatus(s)
	}
	_ = s.SetDeadline(time.Time{})
	if err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	if status != udpOpenStatusOK {
		_ = s.Close()
		return nil, 0, 0, &remoteOpenError{network: "UDP", status: status, code: code, message: message}
	}
	return s, chID, decision, nil
}

// ======================== TCP Forwarder ========================

func startTCPListener(ctx context.Context, rule string) (*runtimeListener, error) {
	lAddr, tAddr, err := parseTCPForwardRule(rule)
	if err != nil {
		return nil, fmt.Errorf("[客户端] TCP转发地址解析失败: %w", err)
	}
	l, err := net.Listen("tcp", lAddr)
	if err != nil {
		return nil, fmt.Errorf("[客户端] TCP监听失败: %w", err)
	}
	listener := newRuntimeListener("tcp", rule, "tcp://"+l.Addr().String()+"/"+tAddr, l.Close)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	log.Printf("[客户端] TCP转发: %s -> %s", lAddr, tAddr)
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
			go handleLocalTCP(c, tAddr)
		}
	}()
	return listener, nil
}

func runTCPListener(ctx context.Context, rule string) error {
	listener, err := startTCPListener(ctx, rule)
	if err != nil {
		return err
	}
	<-listener.done
	return nil
}

func handleLocalTCP(c net.Conn, target string) {
	stream, _, decision, err := echPool.openTCPStream(target)
	if err != nil {
		log.Printf("[客户端] %s TCP转发 打开失败 %s: %v", clientSourceAddr(c), target, err)
		_ = c.Close()
		return
	}
	logClientConnEvent(c, "TCP转发", target, decision, true)
	defer logClientConnEvent(c, "TCP转发", target, decision, false)
	proxyConnStream(c, stream)
}

// dialWebSocketWithECH：支持 ws:// 与 wss://；仅 wss 使用 TLS/ECH 逻辑。
// v2 通道身份、认证 proof 与 channel id 都在 WebSocket 升级后的
// ChannelInit 中发送；这里必须保持 URL query 与 Sec-WebSocket-Protocol 为空。
func dialWebSocketWithECH(addr string, retries int, ip string) (*websocket.Conn, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "wss" && scheme != "ws" {
		return nil, fmt.Errorf("仅支持 ws:// 或 wss:// (当前: %s)", u.Scheme)
	}

	dialURL := *u
	dialURL.RawQuery = ""
	dialAddr := dialURL.String()

	newDialer := func() websocket.Dialer {
		dialer := websocket.Dialer{
			HandshakeTimeout: cfg.WSHandshakeTimeout,
			ReadBufferSize:   cfg.ReadBuf,
			WriteBufferSize:  cfg.ReadBuf,
		}
		if ip != "" || frontProxyEnabled() {
			dialer.NetDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				target, err := resolveWebSocketDialTarget(address, ip)
				if err != nil {
					return nil, err
				}
				if frontProxyEnabled() {
					return dialWebSocketFrontProxy(ctx, target)
				}
				d := net.Dialer{Timeout: cfg.DialTimeout}
				return d.DialContext(ctx, network, target)
			}
		}
		return dialer
	}

	if scheme == "ws" {
		dialer := newDialer()
		conn, resp, err := dialer.Dial(dialAddr, webSocketRequestHeader())
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusUnauthorized {
				return nil, fmt.Errorf("认证失败")
			}
			return nil, err
		}
		return conn, nil
	}

	serverName := u.Hostname()
	for i := 1; i <= retries; i++ {
		tlsCfg, e := buildUnifiedTLSConfig(serverName)
		if e != nil {
			if i < retries {
				_ = refreshECH()
				time.Sleep(cfg.ECHRetryDelay)
				continue
			}
			return nil, e
		}

		dialer := newDialer()
		dialer.TLSClientConfig = tlsCfg

		conn, resp, err := dialer.Dial(dialAddr, webSocketRequestHeader())
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusUnauthorized {
				return nil, fmt.Errorf("认证失败")
			}
			if !fallback && (strings.Contains(err.Error(), "ECH") || strings.Contains(err.Error(), "ech")) && i < retries {
				_ = refreshECH()
				time.Sleep(cfg.ECHRetryDelay)
				continue
			}
			return nil, err
		}
		return conn, nil
	}
	return nil, fmt.Errorf("连接失败")
}

func resolveWebSocketDialTarget(address, ip string) (string, error) {
	if ip == "" {
		return address, nil
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("解析 WebSocket 目标地址失败 %q: %w", address, err)
	}
	if host, overridePort, err := net.SplitHostPort(ip); err == nil {
		return net.JoinHostPort(host, overridePort), nil
	}
	return net.JoinHostPort(ip, port), nil
}

// ======================== SOCKS5 / HTTP Proxy ========================
