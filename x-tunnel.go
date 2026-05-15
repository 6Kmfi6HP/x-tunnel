package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

type GlobalConfig struct {
	DialTimeout        time.Duration
	WSHandshakeTimeout time.Duration
	ReconnectDelay     time.Duration
	ReconnectMaxDelay  time.Duration
	ReconnectJitter    time.Duration
	RTTProbeTimeout    time.Duration
	DNSQueryTimeout    time.Duration
	ECHRetryDelay      time.Duration
	UDPReadTimeout     time.Duration
	ShutdownTimeout    time.Duration

	ReadBuf int
}

var cfg = GlobalConfig{
	DialTimeout:        3 * time.Second,
	WSHandshakeTimeout: 5 * time.Second,
	ReconnectDelay:     1 * time.Second,
	ReconnectMaxDelay:  30 * time.Second,
	ReconnectJitter:    500 * time.Millisecond,
	RTTProbeTimeout:    2 * time.Second,
	DNSQueryTimeout:    3 * time.Second,
	ECHRetryDelay:      2 * time.Second,
	UDPReadTimeout:     1 * time.Second,
	ShutdownTimeout:    5 * time.Second,
	ReadBuf:            64 * 1024,
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 64*1024); return &b }}

func baseReconnectDelay(attempt int) time.Duration {
	if cfg.ReconnectDelay <= 0 {
		return 0
	}
	delay := cfg.ReconnectDelay
	for i := 0; i < attempt; i++ {
		if cfg.ReconnectMaxDelay > 0 && delay >= cfg.ReconnectMaxDelay {
			return cfg.ReconnectMaxDelay
		}
		delay *= 2
		if cfg.ReconnectMaxDelay > 0 && delay > cfg.ReconnectMaxDelay {
			return cfg.ReconnectMaxDelay
		}
	}
	return delay
}

func reconnectDelay(attempt int) time.Duration {
	delay := baseReconnectDelay(attempt)
	if delay <= 0 || cfg.ReconnectJitter <= 0 {
		return delay
	}
	jitterLimit := cfg.ReconnectJitter
	if half := delay / 2; half > 0 && half < jitterLimit {
		jitterLimit = half
	}
	return delay + randomDuration(jitterLimit)
}

func randomDuration(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// ======================== 全局参数 ========================

var (
	listenAddr          string
	forwardAddr         string
	ipAddr              string
	udpBlockPortsStr    string
	certFile            string
	keyFile             string
	clientCAFile        string
	clientCertFile      string
	clientKeyFile       string
	configFile          string
	token               string
	showVersion         bool
	metricsAddr         string
	cidrs               string
	targetAllowCIDRs    string
	targetDenyCIDRs     string
	targetAllowHosts    string
	targetDenyHosts     string
	maxStreamsPerClient int
	connectionNum       int
	insecure            bool
	ips                 string

	dnsServer string
	echDomain string
	fallback  bool

	echListMu sync.RWMutex
	echList   []byte
	refreshMu sync.Mutex

	echPool *ECHPool

	clientID      string
	udpBlockPorts map[int]struct{}

	socks5Config *SOCKS5Config
	targetPolicy *TargetPolicy
	ipStrategy   byte

	serverStreamSeq    uint64
	udpAssociationSeq  uint64
	clientReconnectSeq uint64
)

var (
	buildVersion = "dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

const (
	IPStrategyDefault  byte = 0
	IPStrategyIPv4Only byte = 1
	IPStrategyIPv6Only byte = 2
	IPStrategyPv4Pv6   byte = 3
	IPStrategyPv6Pv4   byte = 4
)

type SOCKS5Config struct {
	Host     string
	Username string
	Password string
}

type TargetPolicy struct {
	Allow      []*net.IPNet
	Deny       []*net.IPNet
	AllowHosts []string
	DenyHosts  []string
}

func init() {
	flag.StringVar(&configFile, "config", "", "可选 JSON 配置文件路径；显式命令行参数优先")
	flag.StringVar(&listenAddr, "l", "", "监听地址 (支持多个，用逗号分隔)\n格式示例:\n  socks5://[user:pass@]0.0.0.0:1080\n  http://[user:pass@]0.0.0.0:8080\n  tcp://0.0.0.0:2000/1.2.3.4:22\n  ws://0.0.0.0:80/path (服务端模式)\n  wss://0.0.0.0:443/path (服务端模式)")
	flag.StringVar(&forwardAddr, "f", "", "服务地址/代理地址 (客户端模式: ws://host:port 或 wss://host:port | 服务端模式: socks5://[user:pass@]host:port)")
	flag.StringVar(&ipAddr, "ip", "", "指定解析的IP地址（仅客户端：将 ws/wss 主机名定向到该 IP 连接，多个IP用逗号分隔）")
	flag.StringVar(&udpBlockPortsStr, "block", "443", "客户端拦截 UDP 端口列表，逗号分隔，如 443,8443")
	flag.BoolVar(&insecure, "insecure", false, "客户端忽略证书校验（仅 wss 模式生效）")
	flag.StringVar(&certFile, "cert", "", "TLS证书文件路径（默认:自动生成，仅服务端）")
	flag.StringVar(&keyFile, "key", "", "TLS密钥文件路径（默认:自动生成，仅服务端）")
	flag.StringVar(&clientCAFile, "client-ca", "", "服务端用于校验客户端证书的 CA PEM 文件（仅 wss 服务端）")
	flag.StringVar(&clientCertFile, "client-cert", "", "客户端 mTLS 证书 PEM 文件（仅 wss 客户端）")
	flag.StringVar(&clientKeyFile, "client-key", "", "客户端 mTLS 私钥 PEM 文件（仅 wss 客户端）")
	flag.StringVar(&token, "token", "", "身份验证令牌（WebSocket Subprotocol）")
	flag.BoolVar(&showVersion, "version", false, "输出版本信息并退出")
	flag.StringVar(&metricsAddr, "metrics", "", "可选 metrics HTTP 监听地址，如 127.0.0.1:9090")
	flag.StringVar(&cidrs, "cidr", "0.0.0.0/0,::/0", "允许的来源 IP 范围 (CIDR),多个范围用逗号分隔")
	flag.StringVar(&targetAllowCIDRs, "allow-target", "", "服务端允许访问的目标 CIDR，多个用逗号分隔（留空表示不限制）")
	flag.StringVar(&targetDenyCIDRs, "deny-target", "", "服务端拒绝访问的目标 CIDR，多个用逗号分隔")
	flag.StringVar(&targetAllowHosts, "allow-host", "", "服务端允许访问的目标主机名，多个用逗号分隔，支持 *.example.com")
	flag.StringVar(&targetDenyHosts, "deny-host", "", "服务端拒绝访问的目标主机名，多个用逗号分隔，支持 *.example.com")
	flag.IntVar(&maxStreamsPerClient, "max-streams", 0, "服务端每个客户端允许的最大并发 smux stream 数（0 表示不限制）")
	flag.StringVar(&dnsServer, "dns", "https://doh.pub/dns-query", "查询 ECH 公钥所用的 DNS 服务器 (支持 DoH 或 UDP，仅 wss 模式生效)")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "用于查询 ECH 公钥的域名（仅 wss 模式生效）")
	flag.BoolVar(&fallback, "fallback", false, "是否禁用 ECH 并回落到普通 TLS 1.3（仅 wss 模式生效，默认 false）")
	flag.IntVar(&connectionNum, "n", 3, "每个IP建立的WebSocket连接数量")
	flag.StringVar(&ips, "ips", "", "服务端解析目标地址的IP偏好 (仅客户端有效)\n 4: 仅IPv4\n 6: 仅IPv6\n 4,6: IPv4优先\n 6,4: IPv6优先")
	flag.DurationVar(&cfg.DialTimeout, "dial-timeout", cfg.DialTimeout, "TCP/DNS 目标拨号超时时间")
	flag.DurationVar(&cfg.WSHandshakeTimeout, "ws-handshake-timeout", cfg.WSHandshakeTimeout, "WebSocket 握手超时时间")
	flag.DurationVar(&cfg.ReconnectDelay, "reconnect-delay", cfg.ReconnectDelay, "客户端重连初始退避时间")
	flag.DurationVar(&cfg.ReconnectMaxDelay, "reconnect-max-delay", cfg.ReconnectMaxDelay, "客户端重连最大退避时间")
	flag.DurationVar(&cfg.ReconnectJitter, "reconnect-jitter", cfg.ReconnectJitter, "客户端重连随机抖动上限")
	flag.DurationVar(&cfg.RTTProbeTimeout, "rtt-timeout", cfg.RTTProbeTimeout, "通道 RTT 探测超时时间")
	flag.DurationVar(&cfg.DNSQueryTimeout, "dns-timeout", cfg.DNSQueryTimeout, "ECH DNS 查询超时时间")
	flag.DurationVar(&cfg.ECHRetryDelay, "ech-retry-delay", cfg.ECHRetryDelay, "ECH 查询/刷新失败后的重试等待时间")
	flag.DurationVar(&cfg.UDPReadTimeout, "udp-read-timeout", cfg.UDPReadTimeout, "服务端 UDP relay 读轮询超时时间")
	flag.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", cfg.ShutdownTimeout, "收到退出信号后的优雅关闭超时时间")
}

func versionString() string {
	return fmt.Sprintf("x-tunnel version=%s commit=%s build=%s", buildVersion, buildCommit, buildDate)
}

type FileConfig struct {
	Listen             *string `json:"listen"`
	Forward            *string `json:"forward"`
	IP                 *string `json:"ip"`
	Block              *string `json:"block"`
	Cert               *string `json:"cert"`
	Key                *string `json:"key"`
	ClientCA           *string `json:"client_ca"`
	ClientCert         *string `json:"client_cert"`
	ClientKey          *string `json:"client_key"`
	ClientCAFlag       *string `json:"client-ca"`
	ClientCertFlag     *string `json:"client-cert"`
	ClientKeyFlag      *string `json:"client-key"`
	Token              *string `json:"token"`
	Metrics            *string `json:"metrics"`
	CIDR               *string `json:"cidr"`
	AllowTarget        *string `json:"allow_target"`
	DenyTarget         *string `json:"deny_target"`
	AllowHost          *string `json:"allow_host"`
	DenyHost           *string `json:"deny_host"`
	AllowTargetFlag    *string `json:"allow-target"`
	DenyTargetFlag     *string `json:"deny-target"`
	AllowHostFlag      *string `json:"allow-host"`
	DenyHostFlag       *string `json:"deny-host"`
	MaxStreams         *int    `json:"max_streams"`
	MaxStreamsFlag     *int    `json:"max-streams"`
	DNS                *string `json:"dns"`
	ECH                *string `json:"ech"`
	IPS                *string `json:"ips"`
	Connections        *int    `json:"connections"`
	Insecure           *bool   `json:"insecure"`
	Fallback           *bool   `json:"fallback"`
	DialTimeout        *string `json:"dial_timeout"`
	WSHandshakeTimeout *string `json:"ws_handshake_timeout"`
	ReconnectDelay     *string `json:"reconnect_delay"`
	ReconnectMaxDelay  *string `json:"reconnect_max_delay"`
	ReconnectJitter    *string `json:"reconnect_jitter"`
	RTTProbeTimeout    *string `json:"rtt_timeout"`
	DNSQueryTimeout    *string `json:"dns_timeout"`
	ECHRetryDelay      *string `json:"ech_retry_delay"`
	UDPReadTimeout     *string `json:"udp_read_timeout"`
	ShutdownTimeout    *string `json:"shutdown_timeout"`
}

func visitedFlags() map[string]bool {
	seen := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		seen[f.Name] = true
	})
	return seen
}

func loadConfigFile(path string, seen map[string]bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var fc FileConfig
	if err := dec.Decode(&fc); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("配置文件只能包含一个 JSON 对象")
	}
	allowTarget, err := singleStringConfigAlias("allow_target", "allow-target", fc.AllowTarget, fc.AllowTargetFlag)
	if err != nil {
		return err
	}
	denyTarget, err := singleStringConfigAlias("deny_target", "deny-target", fc.DenyTarget, fc.DenyTargetFlag)
	if err != nil {
		return err
	}
	allowHost, err := singleStringConfigAlias("allow_host", "allow-host", fc.AllowHost, fc.AllowHostFlag)
	if err != nil {
		return err
	}
	denyHost, err := singleStringConfigAlias("deny_host", "deny-host", fc.DenyHost, fc.DenyHostFlag)
	if err != nil {
		return err
	}
	maxStreams, err := singleIntConfigAlias("max_streams", "max-streams", fc.MaxStreams, fc.MaxStreamsFlag)
	if err != nil {
		return err
	}
	clientCA, err := singleStringConfigAlias("client_ca", "client-ca", fc.ClientCA, fc.ClientCAFlag)
	if err != nil {
		return err
	}
	clientCert, err := singleStringConfigAlias("client_cert", "client-cert", fc.ClientCert, fc.ClientCertFlag)
	if err != nil {
		return err
	}
	clientKey, err := singleStringConfigAlias("client_key", "client-key", fc.ClientKey, fc.ClientKeyFlag)
	if err != nil {
		return err
	}
	applyStringConfig(seen, "l", fc.Listen, &listenAddr)
	applyStringConfig(seen, "f", fc.Forward, &forwardAddr)
	applyStringConfig(seen, "ip", fc.IP, &ipAddr)
	applyStringConfig(seen, "block", fc.Block, &udpBlockPortsStr)
	applyStringConfig(seen, "cert", fc.Cert, &certFile)
	applyStringConfig(seen, "key", fc.Key, &keyFile)
	applyStringConfig(seen, "client-ca", clientCA, &clientCAFile)
	applyStringConfig(seen, "client-cert", clientCert, &clientCertFile)
	applyStringConfig(seen, "client-key", clientKey, &clientKeyFile)
	applyStringConfig(seen, "token", fc.Token, &token)
	applyStringConfig(seen, "metrics", fc.Metrics, &metricsAddr)
	applyStringConfig(seen, "cidr", fc.CIDR, &cidrs)
	applyStringConfig(seen, "allow-target", allowTarget, &targetAllowCIDRs)
	applyStringConfig(seen, "deny-target", denyTarget, &targetDenyCIDRs)
	applyStringConfig(seen, "allow-host", allowHost, &targetAllowHosts)
	applyStringConfig(seen, "deny-host", denyHost, &targetDenyHosts)
	applyStringConfig(seen, "dns", fc.DNS, &dnsServer)
	applyStringConfig(seen, "ech", fc.ECH, &echDomain)
	applyStringConfig(seen, "ips", fc.IPS, &ips)
	if fc.Connections != nil && !seen["n"] {
		connectionNum = *fc.Connections
	}
	if err := applyNonNegativeIntConfig(seen, "max-streams", maxStreams, &maxStreamsPerClient); err != nil {
		return err
	}
	if fc.Insecure != nil && !seen["insecure"] {
		insecure = *fc.Insecure
	}
	if fc.Fallback != nil && !seen["fallback"] {
		fallback = *fc.Fallback
	}
	if err := applyDurationConfig(seen, "dial-timeout", fc.DialTimeout, &cfg.DialTimeout); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "ws-handshake-timeout", fc.WSHandshakeTimeout, &cfg.WSHandshakeTimeout); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "reconnect-delay", fc.ReconnectDelay, &cfg.ReconnectDelay); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "reconnect-max-delay", fc.ReconnectMaxDelay, &cfg.ReconnectMaxDelay); err != nil {
		return err
	}
	if err := applyNonNegativeDurationConfig(seen, "reconnect-jitter", fc.ReconnectJitter, &cfg.ReconnectJitter); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "rtt-timeout", fc.RTTProbeTimeout, &cfg.RTTProbeTimeout); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "dns-timeout", fc.DNSQueryTimeout, &cfg.DNSQueryTimeout); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "ech-retry-delay", fc.ECHRetryDelay, &cfg.ECHRetryDelay); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "udp-read-timeout", fc.UDPReadTimeout, &cfg.UDPReadTimeout); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "shutdown-timeout", fc.ShutdownTimeout, &cfg.ShutdownTimeout); err != nil {
		return err
	}
	return nil
}

func singleStringConfigAlias(primaryName, aliasName string, primary, alias *string) (*string, error) {
	if primary != nil && alias != nil {
		return nil, fmt.Errorf("配置字段 %q 和 %q 不能同时设置", primaryName, aliasName)
	}
	if primary != nil {
		return primary, nil
	}
	return alias, nil
}

func singleIntConfigAlias(primaryName, aliasName string, primary, alias *int) (*int, error) {
	if primary != nil && alias != nil {
		return nil, fmt.Errorf("配置字段 %q 和 %q 不能同时设置", primaryName, aliasName)
	}
	if primary != nil {
		return primary, nil
	}
	return alias, nil
}

func applyStringConfig(seen map[string]bool, flagName string, value *string, target *string) {
	if value != nil && !seen[flagName] {
		*target = *value
	}
}

func applyDurationConfig(seen map[string]bool, flagName string, value *string, target *time.Duration) error {
	if value == nil || seen[flagName] {
		return nil
	}
	parsed, err := time.ParseDuration(*value)
	if err != nil {
		return fmt.Errorf("配置字段 %q duration 无效: %w", flagName, err)
	}
	if parsed <= 0 {
		return fmt.Errorf("配置字段 %q 必须大于 0", flagName)
	}
	*target = parsed
	return nil
}

func applyNonNegativeDurationConfig(seen map[string]bool, flagName string, value *string, target *time.Duration) error {
	if value == nil || seen[flagName] {
		return nil
	}
	parsed, err := time.ParseDuration(*value)
	if err != nil {
		return fmt.Errorf("配置字段 %q duration 无效: %w", flagName, err)
	}
	if parsed < 0 {
		return fmt.Errorf("配置字段 %q 不能小于 0", flagName)
	}
	*target = parsed
	return nil
}

func applyNonNegativeIntConfig(seen map[string]bool, flagName string, value *int, target *int) error {
	if value == nil || seen[flagName] {
		return nil
	}
	if *value < 0 {
		return fmt.Errorf("配置字段 %q 不能小于 0", flagName)
	}
	*target = *value
	return nil
}

func validateCertificatePair(certPath, keyPath string) error {
	if certPath == "" && keyPath == "" {
		return nil
	}
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("证书和私钥必须同时配置")
	}
	return nil
}

func validateGlobalConfig() error {
	checks := []struct {
		name  string
		value time.Duration
	}{
		{name: "dial-timeout", value: cfg.DialTimeout},
		{name: "ws-handshake-timeout", value: cfg.WSHandshakeTimeout},
		{name: "reconnect-delay", value: cfg.ReconnectDelay},
		{name: "reconnect-max-delay", value: cfg.ReconnectMaxDelay},
		{name: "rtt-timeout", value: cfg.RTTProbeTimeout},
		{name: "dns-timeout", value: cfg.DNSQueryTimeout},
		{name: "ech-retry-delay", value: cfg.ECHRetryDelay},
		{name: "udp-read-timeout", value: cfg.UDPReadTimeout},
		{name: "shutdown-timeout", value: cfg.ShutdownTimeout},
	}
	for _, check := range checks {
		if check.value <= 0 {
			return fmt.Errorf("%s 必须大于 0", check.name)
		}
	}
	if cfg.ReconnectJitter < 0 {
		return fmt.Errorf("reconnect-jitter 不能小于 0")
	}
	if cfg.ReconnectMaxDelay < cfg.ReconnectDelay {
		return fmt.Errorf("reconnect-max-delay 不能小于 reconnect-delay")
	}
	if maxStreamsPerClient < 0 {
		return fmt.Errorf("max-streams 不能小于 0")
	}
	return nil
}

func validateMTLSConfig(isServer bool, serverScheme string) error {
	if err := validateCertificatePair(certFile, keyFile); err != nil {
		return fmt.Errorf("server cert/key: %w", err)
	}
	if err := validateCertificatePair(clientCertFile, clientKeyFile); err != nil {
		return fmt.Errorf("client cert/key: %w", err)
	}
	if isServer {
		if clientCAFile != "" && serverScheme != "wss" {
			return fmt.Errorf("-client-ca 只能用于 wss 服务端")
		}
		if clientCertFile != "" || clientKeyFile != "" {
			return fmt.Errorf("-client-cert/-client-key 只能用于客户端模式")
		}
		return nil
	}
	if certFile != "" || keyFile != "" {
		return fmt.Errorf("-cert/-key 只能用于服务端模式")
	}
	if clientCAFile != "" {
		return fmt.Errorf("-client-ca 只能用于服务端模式")
	}
	return nil
}

func splitCommaList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func validateToken(value string) error {
	if value == "" {
		return nil
	}
	const separators = `()<>@,;:\"/[]?={} 	`
	for _, r := range value {
		if r < 33 || r > 126 || strings.ContainsRune(separators, r) {
			return fmt.Errorf("必须是合法的 WebSocket subprotocol token，不能包含空白、控制字符或 HTTP 分隔符")
		}
	}
	return nil
}

func validateHostPort(value string) error {
	return validateHostPortValue(value, false)
}

func validateListenHostPort(value string) error {
	return validateHostPortValue(value, true)
}

func validateHostPortValue(value string, allowEmptyHost bool) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return err
	}
	if !allowEmptyHost && strings.TrimSpace(host) == "" {
		return fmt.Errorf("host 不能为空")
	}
	if strings.TrimSpace(port) == "" {
		return fmt.Errorf("port 不能为空")
	}
	if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
		return fmt.Errorf("port 必须在 1-65535 之间")
	}
	return nil
}

func validateDialIPOverride(value string) error {
	if host, port, err := net.SplitHostPort(value); err == nil {
		if strings.TrimSpace(port) == "" {
			return fmt.Errorf("port 不能为空")
		}
		if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
			return fmt.Errorf("port 必须在 1-65535 之间")
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("host 必须是 IP 地址")
		}
		return nil
	}
	if net.ParseIP(value) == nil {
		return fmt.Errorf("必须是 IP 地址或 IP:port")
	}
	return nil
}

func validateListenRule(rule string) error {
	u, err := url.Parse(rule)
	if err != nil {
		return err
	}
	switch strings.ToLower(u.Scheme) {
	case "ws", "wss", "socks5", "http":
		if u.Host == "" {
			return fmt.Errorf("必须包含 host:port")
		}
		return validateListenHostPort(u.Host)
	case "tcp":
		raw := strings.TrimPrefix(rule, "tcp://")
		parts := strings.Split(raw, "/")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("格式必须是 tcp://listen_host:port/target_host:port")
		}
		if err := validateListenHostPort(parts[0]); err != nil {
			return fmt.Errorf("监听地址无效: %w", err)
		}
		if err := validateHostPort(parts[1]); err != nil {
			return fmt.Errorf("目标地址无效: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("不支持的监听协议 %q", u.Scheme)
	}
}

func main() {
	flag.Parse()

	if showVersion {
		fmt.Println(versionString())
		return
	}
	if configFile != "" {
		if err := loadConfigFile(configFile, visitedFlags()); err != nil {
			log.Fatalf("[配置] 读取配置文件失败: %v", err)
		}
	}
	if listenAddr == "" {
		flag.Usage()
		return
	}
	if err := validateToken(token); err != nil {
		log.Fatalf("[配置] token 无效: %v", err)
	}
	if err := validateGlobalConfig(); err != nil {
		log.Fatalf("[配置] 全局参数无效: %v", err)
	}
	if metricsAddr != "" {
		if err := validateListenHostPort(metricsAddr); err != nil {
			log.Fatalf("[配置] metrics 地址无效: %v", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if metricsAddr != "" {
		go runMetricsServer(ctx, metricsAddr)
	}

	ipStrategy = parseIPStrategy(ips)
	if ips != "" {
		log.Printf("[客户端] IP 访问策略: %s (code: %d)", ips, ipStrategy)
	}

	targetIPs := splitCommaList(ipAddr)
	for _, targetIP := range targetIPs {
		if err := validateDialIPOverride(targetIP); err != nil {
			log.Fatalf("[客户端] -ip 参数无效 %q: %v", targetIP, err)
		}
	}

	listeners := splitCommaList(listenAddr)
	if len(listeners) == 0 {
		log.Fatalf("[配置] 至少需要一个监听地址")
	}
	isServer := false
	serverListeners := 0
	for _, l := range listeners {
		if err := validateListenRule(l); err != nil {
			log.Fatalf("[配置] 监听地址无效 %q: %v", l, err)
		}
		if strings.HasPrefix(l, "ws://") || strings.HasPrefix(l, "wss://") {
			serverListeners++
			isServer = true
			listenAddr = l
		}
	}
	if isServer && (serverListeners != 1 || len(listeners) != 1) {
		log.Fatalf("[配置] 服务端模式只能配置一个 ws:// 或 wss:// 监听地址，不能与客户端监听器混用")
	}
	serverScheme := ""
	if isServer {
		if u, err := url.Parse(listenAddr); err == nil {
			serverScheme = strings.ToLower(u.Scheme)
		}
	}
	if err := validateMTLSConfig(isServer, serverScheme); err != nil {
		log.Fatalf("[配置] mTLS 配置无效: %v", err)
	}

	// ================= 服务端模式 =================
	if isServer {
		if token == "" {
			log.Printf("[服务端] 警告: 未配置 token，WebSocket 连接不会进行令牌认证")
		}
		var err error
		targetPolicy, err = parseTargetPolicy(targetAllowCIDRs, targetDenyCIDRs, targetAllowHosts, targetDenyHosts)
		if err != nil {
			log.Fatalf("[服务端] 目标访问策略无效: %v", err)
		}
		if forwardAddr != "" {
			config, err := parseSOCKS5Addr(forwardAddr)
			if err != nil {
				log.Fatalf("[服务端] 解析SOCKS5代理地址失败: %v", err)
			}
			if err := validateHostPort(config.Host); err != nil {
				log.Fatalf("[服务端] SOCKS5代理地址无效: %v", err)
			}
			socks5Config = config
			log.Printf("[服务端] 使用SOCKS5前置代理: %s", config.Host)
			if config.Username != "" {
				log.Printf("[服务端] SOCKS5代理认证已启用")
			}
		} else {
			log.Printf("[服务端] 直连模式（未配置SOCKS5代理）")
		}
		runWebSocketServer(ctx, listenAddr)
		return
	}

	// ================= 客户端模式 =================
	if forwardAddr == "" {
		log.Fatalf("[客户端] 客户端模式必须指定服务地址 (-f ws:// 或 -f wss://)")
	}
	if token == "" {
		log.Printf("[客户端] 警告: 未配置 token，将尝试连接未启用令牌认证的服务端")
	}
	if connectionNum <= 0 {
		log.Fatalf("[客户端] 参数 -n 必须大于 0 (当前: %d)", connectionNum)
	}

	forwardURL, err := url.Parse(forwardAddr)
	if err != nil {
		log.Fatalf("[客户端] 无效的服务地址: %v", err)
	}
	scheme := strings.ToLower(forwardURL.Scheme)
	if scheme != "wss" && scheme != "ws" {
		log.Fatalf("[客户端] 仅支持 ws:// 或 wss:// 协议 (当前: %s)", forwardURL.Scheme)
	}
	if forwardURL.Host == "" {
		log.Fatalf("[客户端] 服务地址必须包含 host:port")
	}
	if (clientCertFile != "" || clientKeyFile != "") && scheme != "wss" {
		log.Fatalf("[客户端] -client-cert/-client-key 只能用于 wss:// 服务地址")
	}

	if scheme == "wss" {
		if insecure {
			if !fallback {
				fallback = true
				log.Printf("[客户端] wss 模式且启用不校验证书（insecure）：已自动禁用 ECH（fallback）")
			} else {
				log.Printf("[客户端] wss 模式且启用不校验证书（insecure）")
			}
		}
		if !fallback {
			if err := prepareECH(); err != nil {
				log.Fatalf("[客户端] 获取 ECH 公钥失败: %v", err)
			}
		} else {
			log.Printf("[客户端] fallback 模式已启用：禁用 ECH，使用标准 TLS 1.3")
		}
	} else {
		if insecure {
			log.Printf("[客户端] ws 模式已忽略 insecure 参数")
		}
		if fallback {
			log.Printf("[客户端] ws 模式已忽略 fallback/ECH 参数")
		}
	}

	if udpBlockPortsStr != "" {
		udpBlockPorts = make(map[int]struct{})
		parts := strings.Split(udpBlockPortsStr, ",")
		for _, p := range parts {
			pp := strings.TrimSpace(p)
			if pp == "" {
				continue
			}
			var port int
			_, _ = fmt.Sscanf(pp, "%d", &port)
			if port > 0 && port < 65536 {
				udpBlockPorts[port] = struct{}{}
			}
		}
	}

	clientID = uuid.NewString()
	log.Printf("[客户端] 客户端ID: %s", clientID)

	echPool = NewECHPool(forwardAddr, connectionNum, targetIPs, clientID)
	echPool.Start(ctx)

	var wg sync.WaitGroup
	for _, listenerRule := range listeners {
		rule := strings.TrimSpace(listenerRule)
		if rule == "" {
			continue
		}

		if strings.HasPrefix(rule, "tcp://") {
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runTCPListener(ctx, r)
			}(rule)
		} else if strings.HasPrefix(rule, "socks5://") {
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runSOCKS5Listener(ctx, r)
			}(rule)
		} else if strings.HasPrefix(rule, "http://") {
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runHTTPListener(ctx, r)
			}(rule)
		} else {
			log.Printf("[客户端] 忽略未知协议的监听地址: %s", rule)
		}
	}
	wg.Wait()
}

func parseIPStrategy(s string) byte {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	switch s {
	case "4":
		return IPStrategyIPv4Only
	case "6":
		return IPStrategyIPv6Only
	case "4,6":
		return IPStrategyPv4Pv6
	case "6,4":
		return IPStrategyPv6Pv4
	default:
		return IPStrategyDefault
	}
}

func parseTargetPolicy(allowRaw, denyRaw, allowHostRaw, denyHostRaw string) (*TargetPolicy, error) {
	allow, err := parseCIDRList(allowRaw)
	if err != nil {
		return nil, fmt.Errorf("allow-target: %w", err)
	}
	deny, err := parseCIDRList(denyRaw)
	if err != nil {
		return nil, fmt.Errorf("deny-target: %w", err)
	}
	allowHosts, err := parseHostPatternList(allowHostRaw)
	if err != nil {
		return nil, fmt.Errorf("allow-host: %w", err)
	}
	denyHosts, err := parseHostPatternList(denyHostRaw)
	if err != nil {
		return nil, fmt.Errorf("deny-host: %w", err)
	}
	return &TargetPolicy{Allow: allow, Deny: deny, AllowHosts: allowHosts, DenyHosts: denyHosts}, nil
}

func parseCIDRList(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("CIDR %q 解析失败: %w", item, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func parseHostPatternList(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var patterns []string
	for _, part := range strings.Split(raw, ",") {
		item := normalizeTargetHost(part)
		if item == "" {
			continue
		}
		if err := validateHostPattern(item); err != nil {
			return nil, err
		}
		patterns = append(patterns, item)
	}
	return patterns, nil
}

func normalizeTargetHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	return strings.TrimSuffix(host, ".")
}

func validateHostPattern(pattern string) error {
	if strings.Contains(pattern, ":") {
		return fmt.Errorf("host pattern %q 不能包含端口", pattern)
	}
	if strings.Contains(pattern, "*") {
		if !strings.HasPrefix(pattern, "*.") || strings.Count(pattern, "*") != 1 {
			return fmt.Errorf("host pattern %q 只支持前缀通配符 *.example.com", pattern)
		}
		pattern = strings.TrimPrefix(pattern, "*.")
	}
	if net.ParseIP(pattern) != nil {
		return fmt.Errorf("host pattern %q 是 IP，目标 IP 请使用 CIDR 策略", pattern)
	}
	if !validHostname(pattern) {
		return fmt.Errorf("host pattern %q 不是合法主机名", pattern)
	}
	return nil
}

func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func (p *TargetPolicy) Allows(target string) (bool, string) {
	if p == nil || len(p.Allow) == 0 && len(p.Deny) == 0 && len(p.AllowHosts) == 0 && len(p.DenyHosts) == 0 {
		return true, ""
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return false, fmt.Sprintf("目标地址格式无效: %v", err)
	}
	host = normalizeTargetHost(host)
	ip := net.ParseIP(host)
	if ip == nil {
		for _, pattern := range p.DenyHosts {
			if hostPatternMatches(pattern, host) {
				return false, fmt.Sprintf("目标主机 %s 命中 deny-host %s", host, pattern)
			}
		}
		if len(p.AllowHosts) == 0 {
			if len(p.Allow) > 0 {
				return false, "目标是域名，无法证明其属于 allow-target CIDR"
			}
			return true, ""
		}
		for _, pattern := range p.AllowHosts {
			if hostPatternMatches(pattern, host) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("目标主机 %s 未命中 allow-host", host)
	}
	for _, n := range p.Deny {
		if n.Contains(ip) {
			return false, fmt.Sprintf("目标 %s 命中 deny-target %s", ip, n)
		}
	}
	if len(p.Allow) == 0 {
		if len(p.AllowHosts) > 0 {
			return false, fmt.Sprintf("目标 %s 未命中 allow-target；allow-host 不适用于 IP 目标", ip)
		}
		return true, ""
	}
	for _, n := range p.Allow {
		if n.Contains(ip) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("目标 %s 未命中 allow-target", ip)
}

func hostPatternMatches(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}

func ensureTargetAllowed(target string) error {
	if targetPolicy == nil {
		return nil
	}
	if ok, reason := targetPolicy.Allows(target); !ok {
		return errors.New(reason)
	}
	return nil
}

type wsNetConn struct {
	ws       *websocket.Conn
	readMu   sync.Mutex
	writeMu  sync.Mutex
	reader   io.Reader
	deadCh   chan struct{}
	deadMu   sync.Mutex
	deadErr  error
	deadOnce sync.Once
}

func newWSNetConn(ws *websocket.Conn) *wsNetConn {
	return &wsNetConn{ws: ws, deadCh: make(chan struct{})}
}

func (c *wsNetConn) signalDead(err error) {
	if err == nil {
		return
	}
	c.deadMu.Lock()
	if c.deadErr == nil {
		c.deadErr = err
	}
	c.deadMu.Unlock()
	c.deadOnce.Do(func() {
		close(c.deadCh)
	})
}

func (c *wsNetConn) Dead() <-chan struct{} { return c.deadCh }

func (c *wsNetConn) DeadErr() error {
	c.deadMu.Lock()
	defer c.deadMu.Unlock()
	return c.deadErr
}

func (c *wsNetConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.reader == nil {
			mt, r, err := c.ws.NextReader()
			if err != nil {
				c.signalDead(err)
				return 0, err
			}
			if mt != websocket.BinaryMessage {
				continue
			}
			c.reader = r
		}
		n, err := c.reader.Read(p)
		if errors.Is(err, io.EOF) {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		if err != nil {
			c.signalDead(err)
		}
		return n, err
	}
}

func (c *wsNetConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	w, err := c.ws.NextWriter(websocket.BinaryMessage)
	if err != nil {
		c.signalDead(err)
		return 0, err
	}
	n, writeErr := w.Write(p)
	closeErr := w.Close()
	if writeErr != nil {
		c.signalDead(writeErr)
		return n, writeErr
	}
	if closeErr != nil {
		c.signalDead(closeErr)
		return n, closeErr
	}
	return n, nil
}

func (c *wsNetConn) Close() error {
	err := c.ws.Close()
	if err != nil {
		c.signalDead(err)
	} else {
		c.signalDead(io.EOF)
	}
	return err
}

func (c *wsNetConn) LocalAddr() net.Addr {
	if nc := c.ws.UnderlyingConn(); nc != nil {
		return nc.LocalAddr()
	}
	return nil
}

func (c *wsNetConn) RemoteAddr() net.Addr {
	if nc := c.ws.UnderlyingConn(); nc != nil {
		return nc.RemoteAddr()
	}
	return nil
}

func (c *wsNetConn) SetDeadline(t time.Time) error {
	if err := c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.ws.SetWriteDeadline(t)
}

func (c *wsNetConn) SetReadDeadline(t time.Time) error { return c.ws.SetReadDeadline(t) }

func (c *wsNetConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

// ======================== SOCKS5 辅助函数 ========================

func parseSOCKS5Addr(addr string) (*SOCKS5Config, error) {
	addr = strings.TrimPrefix(addr, "socks5://")
	config := &SOCKS5Config{}

	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的SOCKS5地址格式")
		}
		auth := parts[0]
		if strings.Contains(auth, ":") {
			authParts := strings.SplitN(auth, ":", 2)
			config.Username = authParts[0]
			config.Password = authParts[1]
		}
		config.Host = parts[1]
	} else {
		config.Host = addr
	}
	return config, nil
}

func dialViaSocks5(network, addr string) (net.Conn, error) {
	if socks5Config == nil {
		return net.DialTimeout(network, addr, cfg.DialTimeout)
	}
	proxyConn, err := net.DialTimeout("tcp", socks5Config.Host, cfg.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("连接SOCKS5代理失败: %v", err)
	}
	if err := socks5Handshake(proxyConn, socks5Config); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("SOCKS5握手失败: %v", err)
	}
	if err := socks5Connect(proxyConn, addr); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT失败: %v", err)
	}
	return proxyConn, nil
}

func socks5Handshake(conn net.Conn, config *SOCKS5Config) error {
	var methods []byte
	if config.Username != "" && config.Password != "" {
		methods = []byte{0x00, 0x02}
	} else {
		methods = []byte{0x00}
	}
	greeting := make([]byte, 2+len(methods))
	greeting[0], greeting[1] = 0x05, byte(len(methods))
	copy(greeting[2:], methods)

	if _, err := conn.Write(greeting); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x05 {
		return fmt.Errorf("SOCKS 版本错误: %d", response[0])
	}
	switch response[1] {
	case 0x00:
		return nil
	case 0x02:
		return socks5UserPassAuthSrv(conn, config.Username, config.Password)
	case 0xFF:
		return errors.New("服务器不接受认证")
	default:
		return fmt.Errorf("认证方法错误: %d", response[1])
	}
}

func socks5UserPassAuthSrv(conn net.Conn, username, password string) error {
	authReq := make([]byte, 3+len(username)+len(password))
	authReq[0], authReq[1] = 0x01, byte(len(username))
	copy(authReq[2:], username)
	authReq[2+len(username)] = byte(len(password))
	copy(authReq[3+len(username):], password)

	if _, err := conn.Write(authReq); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[1] != 0x00 {
		return errors.New("认证失败")
	}
	return nil
}

func socks5Connect(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	var request []byte
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = make([]byte, 10)
			request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x01
			copy(request[4:8], ip4)
			request[8], request[9] = byte(port>>8), byte(port)
		} else {
			request = make([]byte, 22)
			request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x04
			copy(request[4:20], ip)
			request[20], request[21] = byte(port>>8), byte(port)
		}
	} else {
		request = make([]byte, 7+len(host))
		request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x03
		request[4] = byte(len(host))
		copy(request[5:], host)
		request[5+len(host)], request[6+len(host)] = byte(port>>8), byte(port)
	}

	if _, err := conn.Write(request); err != nil {
		return err
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[1] != 0x00 {
		return fmt.Errorf("状态码: %d", response[1])
	}
	switch response[3] {
	case 0x01:
		_, _ = io.ReadFull(conn, make([]byte, 6))
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		_, _ = io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
	case 0x04:
		_, _ = io.ReadFull(conn, make([]byte, 18))
	}
	return nil
}

// ======================== UDP Relayer (服务端用) ========================

type UDPRelayer interface {
	Read(buffer []byte) (int, *net.UDPAddr, error)
	Write(data []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

type DirectUDPRelayer struct {
	conn   *net.UDPConn
	target *net.UDPAddr
}

func (d *DirectUDPRelayer) Read(buffer []byte) (int, *net.UDPAddr, error) {
	return d.conn.ReadFromUDP(buffer)
}
func (d *DirectUDPRelayer) Write(data []byte) (int, error)    { return d.conn.WriteToUDP(data, d.target) }
func (d *DirectUDPRelayer) SetReadDeadline(t time.Time) error { return d.conn.SetReadDeadline(t) }
func (d *DirectUDPRelayer) Close() error                      { return d.conn.Close() }

type SOCKS5UDPRelay struct {
	tcpConn    net.Conn
	udpConn    *net.UDPConn
	relayAddr  *net.UDPAddr
	targetAddr *net.UDPAddr
	mu         sync.Mutex
	closed     bool
}

func newSOCKS5UDPRelay(targetAddr string) (*SOCKS5UDPRelay, error) {
	if socks5Config == nil {
		return nil, errors.New("SOCKS5配置为空")
	}
	tcpConn, err := net.DialTimeout("tcp", socks5Config.Host, cfg.DialTimeout)
	if err != nil {
		return nil, err
	}
	if err := socks5Handshake(tcpConn, socks5Config); err != nil {
		tcpConn.Close()
		return nil, err
	}
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := tcpConn.Write(req); err != nil {
		tcpConn.Close()
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, resp); err != nil {
		tcpConn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE拒绝: %d", resp[1])
	}
	var relayHost string
	switch resp[3] {
	case 0x01:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(tcpConn, ipBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		relayHost = net.IP(ipBuf).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(tcpConn, lenBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(tcpConn, domainBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		relayHost = string(domainBuf)
	case 0x04:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(tcpConn, ipBuf); err != nil {
			tcpConn.Close()
			return nil, err
		}
		relayHost = net.IP(ipBuf).String()
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, portBuf); err != nil {
		tcpConn.Close()
		return nil, err
	}
	relayPort := int(portBuf[0])<<8 | int(portBuf[1])

	if relayHost == "0.0.0.0" || relayHost == "::" {
		h, _, _ := net.SplitHostPort(socks5Config.Host)
		relayHost = h
	}
	rAddr, errResolve := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", relayHost, relayPort))
	if errResolve != nil {
		tcpConn.Close()
		return nil, errResolve
	}

	tAddr, errResolve := net.ResolveUDPAddr("udp", targetAddr)
	if errResolve != nil {
		tcpConn.Close()
		return nil, errResolve
	}

	localUDP, errListen := net.ListenUDP("udp", nil)
	if errListen != nil {
		tcpConn.Close()
		return nil, errListen
	}

	log.Printf("[服务端UDP] SOCKS5 UDP中继: %s -> %s", rAddr, targetAddr)
	return &SOCKS5UDPRelay{
		tcpConn:    tcpConn,
		udpConn:    localUDP,
		relayAddr:  rAddr,
		targetAddr: tAddr,
	}, nil
}

func (r *SOCKS5UDPRelay) Write(data []byte) (int, error) {
	if r == nil || r.udpConn == nil || r.relayAddr == nil || r.targetAddr == nil {
		return 0, errors.New("SOCKS5 UDP relay 未初始化")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, errors.New("closed")
	}
	pkt := buildSOCKS5UDPPacketData(r.targetAddr, data)
	return r.udpConn.WriteToUDP(pkt, r.relayAddr)
}

func (r *SOCKS5UDPRelay) Read(buffer []byte) (int, *net.UDPAddr, error) {
	if r == nil || r.udpConn == nil {
		return 0, nil, errors.New("SOCKS5 UDP relay 未初始化")
	}
	if r.closed {
		return 0, nil, errors.New("closed")
	}
	tmpPtr := bufPool.Get().(*[]byte)
	tmp := *tmpPtr
	defer bufPool.Put(tmpPtr)

	n, _, err := r.udpConn.ReadFromUDP(tmp)
	if err != nil {
		return 0, nil, err
	}
	srcAddr, payload, err := parseSOCKS5UDPResp(tmp[:n])
	if err != nil {
		return 0, nil, err
	}
	copy(buffer, payload)
	return len(payload), srcAddr, nil
}

func (r *SOCKS5UDPRelay) SetReadDeadline(t time.Time) error {
	if r == nil || r.udpConn == nil {
		return errors.New("SOCKS5 UDP relay 未初始化")
	}
	return r.udpConn.SetReadDeadline(t)
}

func (r *SOCKS5UDPRelay) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	_ = r.udpConn.Close()
	_ = r.tcpConn.Close()
	return nil
}

func buildSOCKS5UDPPacketData(target *net.UDPAddr, data []byte) []byte {
	packet := []byte{0x00, 0x00, 0x00}
	if ip4 := target.IP.To4(); ip4 != nil {
		packet = append(packet, 0x01)
		packet = append(packet, ip4...)
	} else {
		packet = append(packet, 0x04)
		packet = append(packet, target.IP...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(target.Port))
	packet = append(packet, portBytes...)
	packet = append(packet, data...)
	return packet
}

func parseSOCKS5UDPResp(packet []byte) (*net.UDPAddr, []byte, error) {
	if len(packet) < 10 {
		return nil, nil, fmt.Errorf("数据包过短")
	}
	atyp := packet[3]
	offset := 4
	var host string
	switch atyp {
	case 0x01:
		if offset+4 > len(packet) {
			return nil, nil, fmt.Errorf("IPv4地址长度过短")
		}
		host = net.IP(packet[offset : offset+4]).String()
		offset += 4
	case 0x03:
		if offset+1 > len(packet) {
			return nil, nil, fmt.Errorf("域名长度字段过短")
		}
		l := int(packet[offset])
		offset++
		if offset+l > len(packet) {
			return nil, nil, fmt.Errorf("域名长度不足")
		}
		host = string(packet[offset : offset+l])
		offset += l
	case 0x04:
		if offset+16 > len(packet) {
			return nil, nil, fmt.Errorf("IPv6地址长度过短")
		}
		host = net.IP(packet[offset : offset+16]).String()
		offset += 16
	default:
		return nil, nil, fmt.Errorf("地址类型无效: %d", atyp)
	}
	if offset+2 > len(packet) {
		return nil, nil, fmt.Errorf("端口字段过短")
	}
	port := int(packet[offset])<<8 | int(packet[offset+1])
	offset += 2
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if addr == nil {
		return nil, nil, fmt.Errorf("解析地址失败")
	}
	return addr, packet[offset:], nil
}

// ======================== ECH 相关（客户端） ========================

const typeHTTPS = 65
const maxDNSMessageSize = 65535

func prepareECH() error {
	for {
		log.Printf("[客户端] DNS查询 ECH: %s -> %s", dnsServer, echDomain)
		echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
		if err != nil {
			log.Printf("[客户端] DNS 查询失败: %v，重试...", err)
			time.Sleep(cfg.ECHRetryDelay)
			continue
		}
		if echBase64 == "" {
			log.Printf("[客户端] 未找到 ECH 参数，重试...")
			time.Sleep(cfg.ECHRetryDelay)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(echBase64)
		if err != nil {
			log.Printf("[客户端] ECH Base64 解码失败: %v，重试...", err)
			time.Sleep(cfg.ECHRetryDelay)
			continue
		}
		echListMu.Lock()
		echList = raw
		echListMu.Unlock()
		log.Printf("[客户端] ECHConfigList 长度: %d 字节", len(raw))
		return nil
	}
}

func refreshECH() error {
	if fallback {
		return nil
	}

	refreshMu.Lock()
	defer refreshMu.Unlock()
	log.Printf("[客户端] 刷新 ECH 配置...")
	return prepareECH()
}

func getECHList() ([]byte, error) {
	if fallback {
		return nil, nil
	}
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置尚未加载")
	}
	return echList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	cfgTLS := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     serverName,
		EncryptedClientHelloConfigList: echList,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝 ECH")
		},
		RootCAs: roots,
	}
	if err := applyClientCertificate(cfgTLS); err != nil {
		return nil, err
	}
	return cfgTLS, nil
}

func buildStandardTLSConfig(serverName string) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	cfgTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		RootCAs:            roots,
		InsecureSkipVerify: insecure, // 修正：fallback/标准TLS也要支持 -insecure
	}
	if err := applyClientCertificate(cfgTLS); err != nil {
		return nil, err
	}
	return cfgTLS, nil
}

func applyClientCertificate(cfgTLS *tls.Config) error {
	if clientCertFile == "" && clientKeyFile == "" {
		return nil
	}
	if err := validateCertificatePair(clientCertFile, clientKeyFile); err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return fmt.Errorf("加载客户端证书失败: %w", err)
	}
	cfgTLS.Certificates = append(cfgTLS.Certificates, cert)
	return nil
}

func loadCertPoolFromFile(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("没有找到可用 PEM CA 证书")
	}
	return pool, nil
}

func configureServerClientAuth(cfgTLS *tls.Config) error {
	if clientCAFile == "" {
		return nil
	}
	pool, err := loadCertPoolFromFile(clientCAFile)
	if err != nil {
		return err
	}
	cfgTLS.ClientAuth = tls.RequireAndVerifyClientCert
	cfgTLS.ClientCAs = pool
	return nil
}

func buildUnifiedTLSConfig(serverName string) (*tls.Config, error) {
	if fallback {
		return buildStandardTLSConfig(serverName)
	}
	ech, e := getECHList()
	if e != nil {
		return nil, e
	}
	cfgTLS, err := buildTLSConfigWithECH(serverName, ech)
	if err != nil {
		return nil, err
	}
	cfgTLS.InsecureSkipVerify = insecure
	return cfgTLS, nil
}

func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	if strings.HasPrefix(dnsServer, "http://") || strings.HasPrefix(dnsServer, "https://") {
		return queryDoH(domain, dnsServer)
	}
	return queryDNSUDP(domain, dnsServer)
}

func queryDNSUDP(domain, dnsServer string) (string, error) {
	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}

	query, err := buildDNSQuery(domain, typeHTTPS)
	if err != nil {
		return "", err
	}

	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		return "", fmt.Errorf("连接 DNS 服务器失败: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(cfg.DNSQueryTimeout))

	if _, err = conn.Write(query); err != nil {
		return "", fmt.Errorf("发送查询失败: %v", err)
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", fmt.Errorf("DNS 查询超时")
		}
		return "", fmt.Errorf("读取 DNS 响应失败: %v", err)
	}
	return parseDNSResponse(response[:n])
}

func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	dnsQuery, err := buildDNSQuery(domain, typeHTTPS)
	if err != nil {
		return "", err
	}
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	client := &http.Client{Timeout: cfg.DNSQueryTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH 状态码: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessageSize+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxDNSMessageSize {
		return "", fmt.Errorf("DNS 响应过大")
	}
	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) ([]byte, error) {
	domain = normalizeDNSName(domain)
	if err := validateDNSName(domain); err != nil {
		return nil, err
	}
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00)
	query = append(query, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query, nil
}

func normalizeDNSName(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func validateDNSName(domain string) error {
	if domain == "" {
		return fmt.Errorf("DNS 域名不能为空")
	}
	if len(domain) > 253 {
		return fmt.Errorf("DNS 域名过长")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return fmt.Errorf("DNS 域名包含空标签")
		}
		if len(label) > 63 {
			return fmt.Errorf("DNS 标签 %q 过长", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("DNS 标签 %q 不能以连字符开头或结尾", label)
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return fmt.Errorf("DNS 标签 %q 包含非法字符", label)
		}
	}
	return nil
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("响应过短")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("无答案记录")
	}
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5
	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)
		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== WebSocket 服务端 ========================

var serverSessions sync.Map // map[string]*ClientSession

type WSChannel struct {
	id      uint64
	conn    *websocket.Conn
	session *ClientSession
}

type ClientSession struct {
	nextChanID uint64

	clientID string

	mu            sync.RWMutex
	channels      map[uint64]*WSChannel
	activeStreams int
}

func getOrCreateClientSession(clientID string) *ClientSession {
	if v, ok := serverSessions.Load(clientID); ok {
		if cs, okType := v.(*ClientSession); okType && cs != nil {
			return cs
		}
		serverSessions.Delete(clientID)
	}
	s := &ClientSession{
		clientID: clientID,
		channels: make(map[uint64]*WSChannel),
	}
	actual, _ := serverSessions.LoadOrStore(clientID, s)
	if cs, ok := actual.(*ClientSession); ok && cs != nil {
		return cs
	}
	serverSessions.Store(clientID, s)
	return s
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
		serverSessions.Delete(s.clientID)
	}
}

func (s *ClientSession) tryAcquireStream() (int, bool) {
	if maxStreamsPerClient <= 0 {
		return 0, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeStreams >= maxStreamsPerClient {
		return s.activeStreams, false
	}
	s.activeStreams++
	return s.activeStreams, true
}

func (s *ClientSession) releaseStream() {
	if maxStreamsPerClient <= 0 {
		return
	}
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

func runWebSocketServer(ctx context.Context, addr string) {
	u, err := url.Parse(addr)
	if err != nil {
		log.Fatalf("[服务端] WS 地址无效: %v", err)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	var allowedNets []*net.IPNet
	for _, cidr := range strings.Split(cidrs, ",") {
		_, allowedNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			log.Fatalf("[服务端] CIDR 解析失败: %v", err)
		}
		allowedNets = append(allowedNets, allowedNet)
	}

	upgrader := websocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  cfg.ReadBuf,
		WriteBufferSize: cfg.ReadBuf,
	}
	if token != "" {
		upgrader.Subprotocols = []string{token}
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
			http.Error(w, "禁止访问", http.StatusForbidden)
			return
		}
		if token != "" {
			if r.Header.Get("Sec-WebSocket-Protocol") != token {
				log.Printf("[服务端] Token 认证失败，来源 IP: %s", clientIP)
				http.Error(w, "未授权", http.StatusUnauthorized)
				return
			}
		}
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		cid := r.URL.Query().Get("client_id")
		if cid == "" {
			cid = uuid.NewString()
		}
		channelID := uint64(0)
		if v := r.URL.Query().Get("channel_id"); v != "" {
			if parsed, parseErr := strconv.ParseUint(v, 10, 64); parseErr == nil {
				channelID = parsed
			}
		}
		session := getOrCreateClientSession(cid)
		ch := session.addChannel(wsConn, channelID)
		log.Printf("[服务端] 客户端通道 %d 连接, 客户端ID: %s, IP: %s", ch.id, cid, clientIP)
		go handleWebSocketChannel(ch)
	})

	server := &http.Server{Addr: u.Host, Handler: mux}
	go shutdownHTTPServer(ctx, server)

	if u.Scheme == "wss" {
		if certFile != "" && keyFile != "" {
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			if err := configureServerClientAuth(server.TLSConfig); err != nil {
				log.Fatalf("[服务端] mTLS 配置失败: %v", err)
			}
			if clientCAFile != "" {
				log.Printf("[服务端] mTLS 客户端证书认证已启用")
			}
			log.Printf("[服务端] WSS 启动 %s%s", u.Host, path)
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("[服务端] WSS 启动失败: %v", err)
			}
		} else {
			cert, err := generateSelfSignedCert()
			if err != nil {
				log.Fatalf("[服务端] 生成自签名证书失败: %v", err)
			}
			server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
			if err := configureServerClientAuth(server.TLSConfig); err != nil {
				log.Fatalf("[服务端] mTLS 配置失败: %v", err)
			}
			if clientCAFile != "" {
				log.Printf("[服务端] mTLS 客户端证书认证已启用")
			}
			log.Printf("[服务端] WSS 启动 %s%s", u.Host, path)
			if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("[服务端] WSS 启动失败: %v", err)
			}
		}
	} else {
		log.Printf("[服务端] WS 启动 %s%s", u.Host, path)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[服务端] WS 启动失败: %v", err)
		}
	}
}

func shutdownHTTPServer(ctx context.Context, server *http.Server) {
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("[服务端] HTTP 服务关闭失败: %v", err)
	}
}

func runMetricsServer(ctx context.Context, addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		writeMetrics(w)
	})
	server := &http.Server{Addr: addr, Handler: mux}
	go shutdownHTTPServer(ctx, server)
	log.Printf("[metrics] HTTP 启动 %s/metrics", addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("[metrics] HTTP 启动失败: %v", err)
	}
}

func writeMetrics(w io.Writer) {
	fmt.Fprintf(w, "# TYPE x_tunnel_server_streams_total counter\n")
	fmt.Fprintf(w, "x_tunnel_server_streams_total %d\n", atomic.LoadUint64(&serverStreamSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_udp_associations_total counter\n")
	fmt.Fprintf(w, "x_tunnel_udp_associations_total %d\n", atomic.LoadUint64(&udpAssociationSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_client_reconnects_total counter\n")
	fmt.Fprintf(w, "x_tunnel_client_reconnects_total %d\n", atomic.LoadUint64(&clientReconnectSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_sessions gauge\n")
	fmt.Fprintf(w, "x_tunnel_server_sessions %d\n", countServerSessions())
}

func countServerSessions() int {
	count := 0
	serverSessions.Range(func(_, _ any) bool {
		count++
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
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

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

func handleWebSocketChannel(ch *WSChannel) {
	wsConn := ch.conn
	session := ch.session

	defer func() {
		_ = wsConn.Close()
		session.removeChannel(ch.id, ch)
	}()
	netConn := newWSNetConn(wsConn)
	sess, err := smux.Server(netConn, nil)
	if err != nil {
		log.Printf("[服务端] 通道 %d smux 初始化失败: %v", ch.id, err)
		return
	}
	defer sess.Close()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			log.Printf("[服务端] 客户端通道 %d 断开", ch.id)
			return
		}
		if active, ok := session.tryAcquireStream(); !ok {
			log.Printf("[服务端] 客户ID:%s 通道:%d 拒绝新 stream: active=%d max-streams=%d", shortID(session.clientID), ch.id, active, maxStreamsPerClient)
			_ = stream.Close()
			continue
		}
		go handleSmuxStream(session, ch, stream)
	}
}

func handleSmuxStream(session *ClientSession, ch *WSChannel, stream *smux.Stream) {
	defer func() {
		session.releaseStream()
		stream.Close()
	}()
	streamID := atomic.AddUint64(&serverStreamSeq, 1)
	kind, strategy, target, err := readSmuxOpenHeader(stream)
	if err != nil {
		return
	}
	log.Printf("[服务端] stream=%d client=%s channel=%d kind=%d target=%s", streamID, shortID(session.clientID), ch.id, kind, target)
	switch kind {
	case streamKindHello:
		clientHello, err := readProtocolHello(stream)
		if err != nil {
			log.Printf("[服务端] 客户ID:%s 协议协商读取失败: %v, 通道:%d", shortID(session.clientID), err, ch.id)
			return
		}
		response := negotiateProtocolHello(clientHello)
		if err := writeProtocolHello(stream, response); err != nil {
			log.Printf("[服务端] 客户ID:%s 协议协商响应失败: %v, 通道:%d", shortID(session.clientID), err, ch.id)
			return
		}
		if response.Status != protocolStatusOK {
			log.Printf("[服务端] 客户ID:%s 协议协商拒绝: %s, 通道:%d", shortID(session.clientID), response.Message, ch.id)
			return
		}
		log.Printf("[服务端] 客户ID:%s 协议协商成功: version=%d caps=0x%x, 通道:%d", shortID(session.clientID), response.Version, response.Capabilities, ch.id)
	case streamKindPing:
		payload := make([]byte, 8)
		if _, err := io.ReadFull(stream, payload); err != nil {
			return
		}
		_, _ = stream.Write(payload)
	case streamKindTCP:
		log.Printf("[服务端] 客户ID:%s TCP 打开: %s, 通道:%d", shortID(session.clientID), target, ch.id)
		if err := ensureTargetAllowed(target); err != nil {
			log.Printf("[服务端] 客户ID:%s TCP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
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
			return
		}
		proxyConnStream(tcpConn, stream)
		log.Printf("[服务端] 客户ID:%s TCP 关闭: %s, 通道:%d", shortID(session.clientID), target, ch.id)
	case streamKindUDP:
		log.Printf("[服务端] 客户ID:%s SOCKS5 UDP 访问: %s, 通道:%d", shortID(session.clientID), target, ch.id)
		if err := ensureTargetAllowed(target); err != nil {
			log.Printf("[服务端] 客户ID:%s UDP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			return
		}
		var relay UDPRelayer
		if socks5Config != nil {
			var socksRelay *SOCKS5UDPRelay
			socksRelay, err = newSOCKS5UDPRelay(target)
			if err != nil {
				log.Printf("[服务端] 客户ID:%s SOCKS5 UDP中继创建失败: %v, 通道:%d", shortID(session.clientID), err, ch.id)
				return
			}
			relay = socksRelay
		} else {
			addr, errResolve := resolveUDPWithStrategy(target, strategy)
			if errResolve != nil {
				log.Printf("[服务端] 客户ID:%s UDP 解析失败: %s, err=%v, 通道:%d", shortID(session.clientID), target, errResolve, ch.id)
				return
			}
			udpConn, errListen := net.ListenUDP("udp", nil)
			if errListen != nil {
				log.Printf("[服务端] 客户ID:%s UDP 监听失败: %s, err=%v, 通道:%d", shortID(session.clientID), target, errListen, ch.id)
				return
			}
			relay = &DirectUDPRelayer{conn: udpConn, target: addr}
		}
		if relay == nil {
			return
		}
		defer relay.Close()
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
			if err := writeUDPReply(stream, addr.String(), buf[:n]); err != nil {
				log.Printf("[服务端] 客户ID:%s UDP 响应写入失败: %s, err=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
				return
			}
		}
	}
}

// ======================== 多通道客户端池 ========================

type ECHPool struct {
	wsServerAddr  string
	connectionNum int
	targetIPs     []string
	clientID      string

	wsConnsMu     sync.RWMutex
	smuxConns     []*smux.Session
	channelRTT    []int64
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
		wsConn, err := dialWebSocketWithECH(p.wsServerAddr, 3, ip, p.clientID, chID)
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
		legacyProtocol, err := negotiateClientProtocol(sess, cfg.RTTProbeTimeout)
		if err != nil {
			_ = sess.Close()
			_ = wsConn.Close()
			if !sleepBeforeReconnect(fmt.Sprintf("协议协商失败: %v", err)) {
				return
			}
			continue
		}
		if legacyProtocol {
			log.Printf("[客户端] 通道 %d (IP:%s) 使用旧协议模式（服务端未响应 hello）", chID, ipLabel)
		} else {
			log.Printf("[客户端] 通道 %d (IP:%s) 协议协商成功: version=%d caps=0x%x", chID, ipLabel, protocolVersion, currentProtocolCapabilities())
		}
		p.wsConnsMu.Lock()
		p.smuxConns[idx] = sess
		p.channelRTT[idx] = 0
		p.wsConnsMu.Unlock()
		log.Printf("[客户端] 通道 %d (IP:%s) 就绪 (smux)", chID, ipLabel)
		reconnectAttempt = 0
		if rtt, err := p.probeChannelRTTOnce(sess, cfg.RTTProbeTimeout); err == nil {
			atomic.StoreInt64(&p.channelRTT[idx], rtt)
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
	if _, err := s.Write(payload); err != nil {
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

func negotiateClientProtocol(sess *smux.Session, timeout time.Duration) (bool, error) {
	s, err := sess.OpenStream()
	if err != nil {
		return false, err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(timeout))
	if err := writeSmuxOpenHeader(s, streamKindHello, IPStrategyDefault, ""); err != nil {
		return false, err
	}
	if err := writeProtocolHello(s, currentProtocolHello()); err != nil {
		return false, err
	}
	response, err := readProtocolHello(s)
	if err != nil {
		if isLegacyProtocolHelloError(err) {
			return true, nil
		}
		return false, err
	}
	if response.Status != protocolStatusOK {
		if response.Message != "" {
			return false, fmt.Errorf("协议协商失败: %s", response.Message)
		}
		return false, fmt.Errorf("协议协商失败: status=%d", response.Status)
	}
	if response.Version != protocolVersion {
		return false, fmt.Errorf("协议版本不匹配: %d", response.Version)
	}
	required := protocolCapabilityTCP | protocolCapabilityPing
	if response.Capabilities&required != required {
		return false, fmt.Errorf("协议能力不足: caps=0x%x", response.Capabilities)
	}
	return false, nil
}

func isLegacyProtocolHelloError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
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

func (p *ECHPool) openBestStream() (*smux.Stream, int, int, error) {
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
		return nil, 0, 0, fmt.Errorf("无可用 smux 通道")
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
	p.wsConnsMu.RUnlock()
	if sess == nil || sess.IsClosed() {
		return nil, 0, 0, fmt.Errorf("通道不可用")
	}
	decision := best.idx + 1
	s, err := sess.OpenStream()
	if err != nil {
		return nil, 0, 0, err
	}
	return s, best.idx + 1, decision, nil
}

func (p *ECHPool) openTCPStream(target string) (*smux.Stream, int, int, error) {
	s, chID, decision, err := p.openBestStream()
	if err != nil {
		return nil, 0, 0, err
	}
	if err := writeSmuxOpenHeader(s, streamKindTCP, ipStrategy, target); err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	return s, chID, decision, nil
}

func (p *ECHPool) openUDPStream(target string) (*smux.Stream, int, int, error) {
	s, chID, decision, err := p.openBestStream()
	if err != nil {
		return nil, 0, 0, err
	}
	if err := writeSmuxOpenHeader(s, streamKindUDP, ipStrategy, target); err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	return s, chID, decision, nil
}

// ======================== TCP Forwarder ========================

func runTCPListener(ctx context.Context, rule string) {
	rule = strings.TrimPrefix(rule, "tcp://")
	parts := strings.Split(rule, "/")
	if len(parts) != 2 {
		return
	}
	lAddr, tAddr := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	l, err := net.Listen("tcp", lAddr)
	if err != nil {
		log.Fatalf("[客户端] TCP监听失败: %v", err)
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	log.Printf("[客户端] TCP转发: %s -> %s", lAddr, tAddr)
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

// dialWebSocketWithECH：支持 ws:// 与 wss://；仅 wss 使用 TLS/ECH 逻辑
func dialWebSocketWithECH(addr string, retries int, ip string, clientID string, channelID int) (*websocket.Conn, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "wss" && scheme != "ws" {
		return nil, fmt.Errorf("仅支持 ws:// 或 wss:// (当前: %s)", u.Scheme)
	}

	dialURL := *u
	q := dialURL.Query()
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	if channelID > 0 {
		q.Set("channel_id", strconv.Itoa(channelID))
	}
	dialURL.RawQuery = q.Encode()
	dialAddr := dialURL.String()

	newDialer := func() websocket.Dialer {
		dialer := websocket.Dialer{
			HandshakeTimeout: cfg.WSHandshakeTimeout,
			ReadBufferSize:   cfg.ReadBuf,
			WriteBufferSize:  cfg.ReadBuf,
		}
		if token != "" {
			dialer.Subprotocols = []string{token}
		}
		if ip != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(address)
				if host, p, err := net.SplitHostPort(ip); err == nil {
					return net.DialTimeout(network, net.JoinHostPort(host, p), cfg.DialTimeout)
				}
				return net.DialTimeout(network, net.JoinHostPort(ip, port), cfg.DialTimeout)
			}
		}
		return dialer
	}

	if scheme == "ws" {
		dialer := newDialer()
		conn, resp, err := dialer.Dial(dialAddr, nil)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusUnauthorized {
				return nil, fmt.Errorf("认证失败：Token 不匹配或未提供")
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

		conn, resp, err := dialer.Dial(dialAddr, nil)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusUnauthorized {
				return nil, fmt.Errorf("认证失败：Token 不匹配或未提供")
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

// ======================== SOCKS5 / HTTP Proxy ========================

type ProxyConfig struct {
	Username, Password, Host string
}

type UDPAssociation struct {
	id            uint64
	tcpConn       net.Conn
	udpListener   *net.UDPConn
	clientUDPAddr *net.UDPAddr
	pool          *ECHPool

	mu        sync.Mutex
	closed    bool
	receiving bool
	channelID int
	target    string
	stream    *smux.Stream
}

func parseAuthAndAddr(full string) (string, string, string, error) {
	u, p, h := "", "", full
	if strings.Contains(full, "@") {
		parts := strings.SplitN(full, "@", 2)
		if len(parts) != 2 {
			return "", "", "", fmt.Errorf("格式错误")
		}
		auth := parts[0]
		if strings.Contains(auth, ":") {
			ap := strings.SplitN(auth, ":", 2)
			u, p = ap[0], ap[1]
		}
		h = parts[1]
	}
	return h, u, p, nil
}

func runSOCKS5Listener(ctx context.Context, addr string) {
	h, u, p, err := parseAuthAndAddr(strings.TrimPrefix(addr, "socks5://"))
	if err != nil {
		log.Fatalf("[客户端] SOCKS5地址解析失败: %v", err)
	}
	l, err := net.Listen("tcp", h)
	if err != nil {
		log.Fatalf("[客户端] SOCKS5监听失败: %v", err)
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	log.Printf("[客户端] SOCKS5 代理: %s", h)
	cfgp := &ProxyConfig{u, p, h}
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go handleSOCKS5(c, cfgp)
	}
}

func handleSOCKS5(c net.Conn, cfgp *ProxyConfig) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(cfg.DialTimeout))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || buf[0] != 0x05 {
		return
	}
	methods := make([]byte, buf[1])
	_, _ = io.ReadFull(c, methods)
	if cfgp.Username != "" {
		_, _ = c.Write([]byte{0x05, 0x02})
		if err := handleSOCKS5UserPassAuth(c, cfgp); err != nil {
			return
		}
	} else {
		_, _ = c.Write([]byte{0x05, 0x00})
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	var target string
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		_, _ = io.ReadFull(c, b)
		target = net.IP(b).String()
	case 0x03:
		b := make([]byte, 1)
		_, _ = io.ReadFull(c, b)
		addr := make([]byte, b[0])
		_, _ = io.ReadFull(c, addr)
		target = string(addr)
	case 0x04:
		b := make([]byte, 16)
		_, _ = io.ReadFull(c, b)
		target = net.IP(b).String()
	}
	pb := make([]byte, 2)
	_, _ = io.ReadFull(c, pb)
	port := int(pb[0])<<8 | int(pb[1])
	target = net.JoinHostPort(target, fmt.Sprintf("%d", port))

	// 增强过滤逻辑：解析 host 判断是否为 IP，从而覆盖 ATYP=0x03 但内容为 IP 的情况
	host, _, _ := net.SplitHostPort(target)
	ip := net.ParseIP(host)

	if head[1] == 0x01 {
		if ipStrategy == IPStrategyIPv4Only {
			if head[3] == 0x04 || (ip != nil && ip.To4() == nil) {
				_, _ = c.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}
		}
		if ipStrategy == IPStrategyIPv6Only {
			if head[3] == 0x01 || (ip != nil && ip.To4() != nil) {
				_, _ = c.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}
		}
	}

	_ = c.SetDeadline(time.Time{})

	switch head[1] {
	case 0x01:
		handleSOCKS5Connect(c, target)
	case 0x03:
		handleSOCKS5UDP(c, cfgp)
	}
}

func handleSOCKS5UserPassAuth(c net.Conn, cfgp *ProxyConfig) error {
	b := make([]byte, 2)
	_, _ = io.ReadFull(c, b)
	u := make([]byte, b[1])
	_, _ = io.ReadFull(c, u)
	_, _ = io.ReadFull(c, b[:1])
	p := make([]byte, b[0])
	_, _ = io.ReadFull(c, p)
	if string(u) == cfgp.Username && string(p) == cfgp.Password {
		_, _ = c.Write([]byte{0x01, 0x00})
		return nil
	}
	_, _ = c.Write([]byte{0x01, 0x01})
	return errors.New("认证失败")
}

func handleSOCKS5Connect(c net.Conn, target string) {
	_, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		_ = c.Close()
		return
	}
	stream, _, decision, err := echPool.openTCPStream(target)
	if err != nil {
		log.Printf("[客户端] %s SOCKS5 打开失败 %s: %v", clientSourceAddr(c), target, err)
		_ = c.Close()
		return
	}
	logClientConnEvent(c, "SOCKS5", target, decision, true)
	defer logClientConnEvent(c, "SOCKS5", target, decision, false)
	proxyConnStream(c, stream)
}

func handleSOCKS5UDP(c net.Conn, cfgp *ProxyConfig) {
	host, _, _ := net.SplitHostPort(cfgp.Host)
	uAddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	ul, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		_ = c.Close()
		return
	}
	defer ul.Close()

	actual, ok := ul.LocalAddr().(*net.UDPAddr)
	if !ok || actual == nil {
		_ = c.Close()
		return
	}
	resp := []byte{0x05, 0x00, 0x00}
	if ip4 := actual.IP.To4(); ip4 != nil {
		resp = append(resp, 0x01)
		resp = append(resp, ip4...)
	} else {
		resp = append(resp, 0x04)
		resp = append(resp, actual.IP...)
	}
	resp = append(resp, byte(actual.Port>>8), byte(actual.Port))
	if _, err := c.Write(resp); err != nil {
		_ = c.Close()
		return
	}

	assoc := &UDPAssociation{
		id:          atomic.AddUint64(&udpAssociationSeq, 1),
		tcpConn:     c,
		udpListener: ul,
		pool:        echPool,
		channelID:   -1,
	}
	log.Printf("[客户端] udp_assoc=%d SOCKS5-UDP 关联打开 listener=%s client=%s", assoc.id, actual.String(), clientSourceAddr(c))

	go assoc.loop()
	b := make([]byte, 1)
	for {
		if _, err := c.Read(b); err != nil {
			assoc.Close()
			return
		}
	}
}

func (a *UDPAssociation) loop() {
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	for {
		n, addr, err := a.udpListener.ReadFromUDP(buf)
		if err != nil {
			return
		}
		a.mu.Lock()
		if a.clientUDPAddr == nil {
			a.clientUDPAddr = addr
		} else if a.clientUDPAddr.String() != addr.String() {
			a.mu.Unlock()
			continue
		}
		a.mu.Unlock()

		tgt, data, err := parseSOCKS5UDPPacket(buf[:n])
		if err == nil {
			h, ps, _ := net.SplitHostPort(tgt)
			if ip := net.ParseIP(h); ip != nil {
				if ipStrategy == IPStrategyIPv4Only && ip.To4() == nil {
					continue
				}
				if ipStrategy == IPStrategyIPv6Only && ip.To4() != nil {
					continue
				}
			}
			var prt int
			_, _ = fmt.Sscanf(ps, "%d", &prt)
			if _, ok := udpBlockPorts[prt]; ok {
				continue
			}
			a.send(tgt, data)
		}
	}
}

func (a *UDPAssociation) send(target string, data []byte) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	needStart := !a.receiving
	if needStart {
		a.receiving = true
		a.target = target
	}
	stream := a.stream
	a.mu.Unlock()

	if needStart {
		s, id, decision, err := a.pool.openUDPStream(target)
		if err != nil {
			log.Printf("[客户端] %s SOCKS5-UDP 打开失败 %s: %v", clientSourceAddr(a.tcpConn), target, err)
			a.Close()
			return
		}
		a.mu.Lock()
		a.stream = s
		a.channelID = id
		stream = s
		a.mu.Unlock()
		log.Printf("[客户端] udp_assoc=%d 绑定目标 %s 通道 %d", a.id, target, decision)
		logClientConnEvent(a.tcpConn, "SOCKS5-UDP", target, decision, true)
		go func() {
			for {
				addrStr, payload, e := readUDPReply(s)
				if e != nil {
					a.Close()
					return
				}
				a.handleUDPResponse(addrStr, payload)
			}
		}()
	} else {
		if target != "" && target != a.target {
			a.mu.Lock()
			a.target = target
			a.mu.Unlock()
		}
	}
	if stream == nil {
		a.Close()
		return
	}
	if err := writeChunk(stream, data); err != nil {
		a.Close()
	}
}

func (a *UDPAssociation) handleUDPResponse(addrStr string, data []byte) {
	host, portStr, _ := net.SplitHostPort(addrStr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	pkt, _ := buildSOCKS5UDPPacket(host, port, data)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.clientUDPAddr != nil {
		_, _ = a.udpListener.WriteToUDP(pkt, a.clientUDPAddr)
	}
}

func (a *UDPAssociation) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	stream := a.stream
	target := a.target
	chID := a.channelID
	a.closed = true
	a.stream = nil
	a.mu.Unlock()
	if stream != nil {
		_ = stream.Close()
	}
	if chID > 0 && target != "" {
		log.Printf("[客户端] udp_assoc=%d SOCKS5-UDP 关联关闭 target=%s 通道 %d", a.id, target, chID)
		logClientConnEvent(a.tcpConn, "SOCKS5-UDP", target, chID, false)
	}
	_ = a.udpListener.Close()
	if a.tcpConn != nil {
		_ = a.tcpConn.Close()
	}
}

func parseSOCKS5UDPPacket(b []byte) (string, []byte, error) {
	if len(b) < 10 || b[2] != 0 {
		return "", nil, errors.New("数据不合法")
	}
	off := 4
	var h string
	switch b[3] {
	case 0x01:
		if off+4 > len(b) {
			return "", nil, errors.New("IPv4地址长度过短")
		}
		h = net.IP(b[off : off+4]).String()
		off += 4
	case 0x03:
		if off+1 > len(b) {
			return "", nil, errors.New("域名长度不足")
		}
		l := int(b[off])
		off++
		if off+l > len(b) {
			return "", nil, errors.New("域名长度不足")
		}
		h = string(b[off : off+l])
		off += l
	case 0x04:
		if off+16 > len(b) {
			return "", nil, errors.New("IPv6地址长度过短")
		}
		h = net.IP(b[off : off+16]).String()
		off += 16
	default:
		return "", nil, errors.New("地址类型无效")
	}
	if off+2 > len(b) {
		return "", nil, errors.New("端口字段过短")
	}
	p := int(b[off])<<8 | int(b[off+1])
	off += 2
	t := fmt.Sprintf("%s:%d", h, p)
	if b[3] == 0x04 {
		t = fmt.Sprintf("[%s]:%d", h, p)
	}
	return t, b[off:], nil
}

func buildSOCKS5UDPPacket(h string, p int, d []byte) ([]byte, error) {
	buf := []byte{0, 0, 0}
	ip := net.ParseIP(h)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, 0x01)
		buf = append(buf, ip4...)
	} else if ip != nil {
		buf = append(buf, 0x04)
		buf = append(buf, ip...)
	} else {
		if len(h) > 255 {
			return nil, fmt.Errorf("域名过长")
		}
		buf = append(buf, 0x03, byte(len(h)))
		buf = append(buf, h...)
	}
	buf = append(buf, byte(p>>8), byte(p))
	buf = append(buf, d...)
	return buf, nil
}

func runHTTPListener(ctx context.Context, addr string) {
	h, u, p, _ := parseAuthAndAddr(strings.TrimPrefix(addr, "http://"))
	l, err := net.Listen("tcp", h)
	if err != nil {
		log.Fatalf("[客户端] HTTP监听失败: %v", err)
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	log.Printf("[客户端] HTTP 代理: %s", h)
	cfgp := &ProxyConfig{u, p, h}
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
		auth := req.Header.Get("Proxy-Authorization")
		ok := false
		if strings.HasPrefix(auth, "Basic ") {
			p, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
			pair := strings.SplitN(string(p), ":", 2)
			if len(pair) == 2 && pair[0] == cfgp.Username && pair[1] == cfgp.Password {
				ok = true
			}
		}
		if !ok {
			_, _ = c.Write([]byte("HTTP/1.1 407 需要认证\r\nProxy-Authenticate: Basic realm=\"代理\"\r\n\r\n"))
			return
		}
	}

	target := req.Host
	if !strings.Contains(target, ":") {
		if req.Method == "CONNECT" {
			target += ":443"
		} else {
			target += ":80"
		}
	}

	var first []byte

	if req.Method == "CONNECT" {
		_, _ = c.Write([]byte("HTTP/1.1 200 连接已建立\r\n\r\n"))
	} else {
		req.RequestURI = ""
		req.URL.Scheme = ""
		req.URL.Host = ""
		var buf bytes.Buffer
		_ = req.Write(&buf)
		first = buf.Bytes()
	}

	stream, _, decision, err := echPool.openTCPStream(target)
	if err != nil {
		log.Printf("[客户端] %s HTTP 打开失败 %s: %v", clientSourceAddr(c), target, err)
		return
	}
	if len(first) > 0 {
		if _, err := stream.Write(first); err != nil {
			_ = stream.Close()
			return
		}
	}
	logClientConnEvent(c, "HTTP", target, decision, true)
	defer logClientConnEvent(c, "HTTP", target, decision, false)
	proxyConnStream(c, stream)
}
