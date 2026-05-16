package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
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
	maxClientSessions   int
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

	serverStreamSeq            uint64
	udpAssociationSeq          uint64
	udpAssociationActiveSeq    uint64
	clientReconnectSeq         uint64
	serverSourceRejectSeq      uint64
	serverAuthRejectSeq        uint64
	serverClientRejectSeq      uint64
	serverStreamRejectSeq      uint64
	serverTargetRejectSeq      uint64
	serverUnsupportedStreamSeq uint64
	serverProtocolOKSeq        uint64
	serverProtocolRejectSeq    uint64
	serverProtocolFailureSeq   uint64
	clientProtocolOKSeq        uint64
	clientProtocolLegacySeq    uint64
	clientProtocolFailureSeq   uint64
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
	flag.IntVar(&maxClientSessions, "max-clients", 0, "服务端允许的最大并发客户端会话数（0 表示不限制）")
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
	MaxClients         *int    `json:"max_clients"`
	MaxClientsFlag     *int    `json:"max-clients"`
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
	maxClients, err := singleIntConfigAlias("max_clients", "max-clients", fc.MaxClients, fc.MaxClientsFlag)
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
	if err := applyNonNegativeIntConfig(seen, "max-clients", maxClients, &maxClientSessions); err != nil {
		return err
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
	if maxClientSessions < 0 {
		return fmt.Errorf("max-clients 不能小于 0")
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

func parseUDPBlockPorts(raw string) (map[int]struct{}, error) {
	parts := splitCommaList(raw)
	if len(parts) == 0 {
		return nil, nil
	}
	ports := make(map[int]struct{}, len(parts))
	for _, part := range parts {
		port, err := strconv.Atoi(part)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("端口 %q 必须是 1-65535 之间的整数", part)
		}
		ports[port] = struct{}{}
	}
	return ports, nil
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
	if strings.ContainsAny(value, " \t\r\n") {
		return fmt.Errorf("host:port 不能包含空白字符")
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return err
	}
	if !allowEmptyHost && strings.TrimSpace(host) == "" {
		return fmt.Errorf("host 不能为空")
	}
	if strings.TrimSpace(host) != "" {
		if err := validateHostnameOrIP(host); err != nil {
			return err
		}
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
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "ws", "wss", "socks5", "http":
		if u.Host == "" {
			return fmt.Errorf("必须包含 host:port")
		}
		if (scheme == "socks5" || scheme == "http") && u.User != nil {
			username := u.User.Username()
			password, ok := u.User.Password()
			if username == "" || !ok || password == "" {
				return fmt.Errorf("认证格式必须是 user:pass@host:port")
			}
			if scheme == "socks5" {
				if err := validateSOCKS5AuthLength(username, password); err != nil {
					return err
				}
			}
		}
		return validateListenHostPort(u.Host)
	case "tcp":
		listen, target, err := parseTCPForwardRule(rule)
		if err != nil {
			return err
		}
		if err := validateListenHostPort(listen); err != nil {
			return fmt.Errorf("监听地址无效: %w", err)
		}
		if err := validateHostPort(target); err != nil {
			return fmt.Errorf("目标地址无效: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("不支持的监听协议 %q", u.Scheme)
	}
}

func parseTCPForwardRule(rule string) (string, string, error) {
	u, err := url.Parse(rule)
	if err != nil {
		return "", "", err
	}
	if strings.ToLower(u.Scheme) != "tcp" {
		return "", "", fmt.Errorf("格式必须是 tcp://listen_host:port/target_host:port")
	}
	listen := strings.TrimSpace(u.Host)
	target := strings.TrimSpace(strings.TrimPrefix(u.Path, "/"))
	if listen == "" || target == "" || strings.Contains(target, "/") {
		return "", "", fmt.Errorf("格式必须是 tcp://listen_host:port/target_host:port")
	}
	return listen, target, nil
}

type listenerStartupConfig struct {
	Raw    string
	Scheme string
}

type clientStartupConfig struct {
	ForwardScheme string
	Fallback      bool
	AutoFallback  bool
	UDPBlockPorts map[int]struct{}
}

type startupConfig struct {
	Listeners    []listenerStartupConfig
	IsServer     bool
	ServerListen string
	ServerScheme string
	TargetIPs    []string
	IPStrategy   byte
	SourceCIDRs  []*net.IPNet
	TargetPolicy *TargetPolicy
	SOCKS5Config *SOCKS5Config
	Client       clientStartupConfig
}

func normalizeURLScheme(raw, scheme string) string {
	i := strings.Index(raw, ":")
	if i <= 0 || scheme == "" {
		return raw
	}
	return scheme + raw[i:]
}

func classifyListeners(raw string) ([]listenerStartupConfig, bool, string, string, error) {
	listenerStrings := splitCommaList(raw)
	if len(listenerStrings) == 0 {
		return nil, false, "", "", fmt.Errorf("至少需要一个监听地址")
	}
	listeners := make([]listenerStartupConfig, 0, len(listenerStrings))
	isServer := false
	serverListen := ""
	serverScheme := ""
	serverListeners := 0
	for _, l := range listenerStrings {
		u, err := url.Parse(l)
		if err != nil {
			return nil, false, "", "", fmt.Errorf("监听地址无效 %q: %w", l, err)
		}
		scheme := strings.ToLower(u.Scheme)
		normalized := normalizeURLScheme(l, scheme)
		if err := validateListenRule(normalized); err != nil {
			return nil, false, "", "", fmt.Errorf("监听地址无效 %q: %w", l, err)
		}
		listeners = append(listeners, listenerStartupConfig{Raw: normalized, Scheme: scheme})
		if scheme == "ws" || scheme == "wss" {
			serverListeners++
			isServer = true
			serverListen = normalized
			serverScheme = scheme
		}
	}
	if isServer && (serverListeners != 1 || len(listeners) != 1) {
		return nil, false, "", "", fmt.Errorf("服务端模式只能配置一个 ws:// 或 wss:// 监听地址，不能与客户端监听器混用")
	}
	return listeners, isServer, serverListen, serverScheme, nil
}

func validateServerStartupConfig(forward, allowCIDRs, denyCIDRs, allowHosts, denyHosts string) (*TargetPolicy, *SOCKS5Config, error) {
	policy, err := parseTargetPolicy(allowCIDRs, denyCIDRs, allowHosts, denyHosts)
	if err != nil {
		return nil, nil, fmt.Errorf("目标访问策略无效: %w", err)
	}
	if forward == "" {
		return policy, nil, nil
	}
	config, err := parseSOCKS5Addr(forward)
	if err != nil {
		return nil, nil, fmt.Errorf("解析SOCKS5代理地址失败: %w", err)
	}
	if err := validateHostPort(config.Host); err != nil {
		return nil, nil, fmt.Errorf("SOCKS5代理地址无效: %w", err)
	}
	return policy, config, nil
}

func validateClientStartupConfig(forward string, connections int, clientCert, clientKey string, insecureMode, fallbackMode bool, blockPortsRaw string) (clientStartupConfig, error) {
	if forward == "" {
		return clientStartupConfig{}, fmt.Errorf("客户端模式必须指定服务地址 (-f ws:// 或 -f wss://)")
	}
	if connections <= 0 {
		return clientStartupConfig{}, fmt.Errorf("参数 -n 必须大于 0 (当前: %d)", connections)
	}
	forwardURL, err := url.Parse(forward)
	if err != nil {
		return clientStartupConfig{}, fmt.Errorf("无效的服务地址: %w", err)
	}
	scheme := strings.ToLower(forwardURL.Scheme)
	if scheme != "wss" && scheme != "ws" {
		return clientStartupConfig{}, fmt.Errorf("仅支持 ws:// 或 wss:// 协议 (当前: %s)", forwardURL.Scheme)
	}
	if forwardURL.Host == "" {
		return clientStartupConfig{}, fmt.Errorf("服务地址必须包含 host:port")
	}
	if (clientCert != "" || clientKey != "") && scheme != "wss" {
		return clientStartupConfig{}, fmt.Errorf("-client-cert/-client-key 只能用于 wss:// 服务地址")
	}
	ports, err := parseUDPBlockPorts(blockPortsRaw)
	if err != nil {
		return clientStartupConfig{}, fmt.Errorf("-block 参数无效: %w", err)
	}
	fallback := fallbackMode
	autoFallback := false
	if scheme == "wss" && insecureMode && !fallback {
		fallback = true
		autoFallback = true
	}
	return clientStartupConfig{
		ForwardScheme: scheme,
		Fallback:      fallback,
		AutoFallback:  autoFallback,
		UDPBlockPorts: ports,
	}, nil
}

func validateStartupConfig() (*startupConfig, error) {
	if err := validateToken(token); err != nil {
		return nil, fmt.Errorf("token 无效: %w", err)
	}
	if err := validateGlobalConfig(); err != nil {
		return nil, fmt.Errorf("全局参数无效: %w", err)
	}
	if metricsAddr != "" {
		if err := validateListenHostPort(metricsAddr); err != nil {
			return nil, fmt.Errorf("metrics 地址无效: %w", err)
		}
	}
	targetIPs := splitCommaList(ipAddr)
	for _, targetIP := range targetIPs {
		if err := validateDialIPOverride(targetIP); err != nil {
			return nil, fmt.Errorf("-ip 参数无效 %q: %w", targetIP, err)
		}
	}
	ipStrategyValue, err := parseIPStrategyStrict(ips)
	if err != nil {
		return nil, fmt.Errorf("-ips 参数无效: %w", err)
	}
	listeners, isServer, serverListen, serverScheme, err := classifyListeners(listenAddr)
	if err != nil {
		return nil, err
	}
	if err := validateMTLSConfig(isServer, serverScheme); err != nil {
		return nil, fmt.Errorf("mTLS 配置无效: %w", err)
	}
	startup := &startupConfig{
		Listeners:    listeners,
		IsServer:     isServer,
		ServerListen: serverListen,
		ServerScheme: serverScheme,
		TargetIPs:    targetIPs,
		IPStrategy:   ipStrategyValue,
	}
	if isServer {
		sourceNets, err := parseSourceCIDRs(cidrs)
		if err != nil {
			return nil, fmt.Errorf("source CIDR 配置无效: %w", err)
		}
		policy, socksConfig, err := validateServerStartupConfig(forwardAddr, targetAllowCIDRs, targetDenyCIDRs, targetAllowHosts, targetDenyHosts)
		if err != nil {
			return nil, err
		}
		startup.SourceCIDRs = sourceNets
		startup.TargetPolicy = policy
		startup.SOCKS5Config = socksConfig
		return startup, nil
	}
	clientConfig, err := validateClientStartupConfig(forwardAddr, connectionNum, clientCertFile, clientKeyFile, insecure, fallback, udpBlockPortsStr)
	if err != nil {
		return nil, err
	}
	if clientConfig.ForwardScheme == "wss" && !clientConfig.Fallback {
		if err := validateECHLookupConfig(echDomain, dnsServer); err != nil {
			return nil, fmt.Errorf("ECH 查询配置无效: %w", err)
		}
	}
	startup.Client = clientConfig
	return startup, nil
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
	startup, err := validateStartupConfig()
	if err != nil {
		log.Fatalf("[配置] %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if metricsAddr != "" {
		go runMetricsServer(ctx, metricsAddr)
	}

	ipStrategy = startup.IPStrategy
	if ips != "" {
		log.Printf("[客户端] IP 访问策略: %s (code: %d)", ips, ipStrategy)
	}

	// ================= 服务端模式 =================
	if startup.IsServer {
		if token == "" {
			log.Printf("[服务端] 警告: 未配置 token，WebSocket 连接不会进行令牌认证")
		}
		targetPolicy = startup.TargetPolicy
		socks5Config = startup.SOCKS5Config
		if socks5Config != nil {
			log.Printf("[服务端] 使用SOCKS5前置代理: %s", socks5Config.Host)
			if socks5Config.Username != "" {
				log.Printf("[服务端] SOCKS5代理认证已启用")
			}
		} else {
			log.Printf("[服务端] 直连模式（未配置SOCKS5代理）")
		}
		runWebSocketServer(ctx, startup.ServerListen, startup.SourceCIDRs)
		return
	}

	// ================= 客户端模式 =================
	if token == "" {
		log.Printf("[客户端] 警告: 未配置 token，将尝试连接未启用令牌认证的服务端")
	}
	fallback = startup.Client.Fallback
	udpBlockPorts = startup.Client.UDPBlockPorts

	if startup.Client.ForwardScheme == "wss" {
		if insecure {
			if startup.Client.AutoFallback {
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

	clientID = uuid.NewString()
	log.Printf("[客户端] 客户端ID: %s", clientID)

	echPool = NewECHPool(forwardAddr, connectionNum, startup.TargetIPs, clientID)
	echPool.Start(ctx)

	var wg sync.WaitGroup
	for _, listenerRule := range startup.Listeners {
		rule := listenerRule.Raw
		switch listenerRule.Scheme {
		case "tcp":
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runTCPListener(ctx, r)
			}(rule)
		case "socks5":
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runSOCKS5Listener(ctx, r)
			}(rule)
		case "http":
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runHTTPListener(ctx, r)
			}(rule)
		default:
			log.Printf("[客户端] 忽略未知协议的监听地址: %s", rule)
		}
	}
	wg.Wait()
}

func parseIPStrategy(s string) byte {
	strategy, err := parseIPStrategyStrict(s)
	if err != nil {
		return IPStrategyDefault
	}
	return strategy
}

func parseIPStrategyStrict(s string) (byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	switch s {
	case "":
		return IPStrategyDefault, nil
	case "4":
		return IPStrategyIPv4Only, nil
	case "6":
		return IPStrategyIPv6Only, nil
	case "4,6":
		return IPStrategyPv4Pv6, nil
	case "6,4":
		return IPStrategyPv6Pv4, nil
	default:
		return IPStrategyDefault, fmt.Errorf("仅支持空值、4、6、4,6 或 6,4")
	}
}

func validateIPStrategyValue(strategy byte) error {
	switch strategy {
	case IPStrategyDefault, IPStrategyIPv4Only, IPStrategyIPv6Only, IPStrategyPv4Pv6, IPStrategyPv6Pv4:
		return nil
	default:
		return fmt.Errorf("IP 策略无效: %d", strategy)
	}
}

func validateECHLookupConfig(domain, server string) error {
	if _, err := buildDNSQuery(domain, typeHTTPS); err != nil {
		return fmt.Errorf("ech 域名无效: %w", err)
	}
	server = strings.TrimSpace(server)
	if server == "" {
		return fmt.Errorf("dns 服务器不能为空")
	}
	if strings.HasPrefix(server, "http://") || strings.HasPrefix(server, "https://") {
		u, err := url.Parse(server)
		if err != nil {
			return fmt.Errorf("dns DoH URL 无效: %w", err)
		}
		if u.Host == "" {
			return fmt.Errorf("dns DoH URL 必须包含 host")
		}
		return nil
	}
	if strings.Contains(server, "://") {
		return fmt.Errorf("dns 只支持 http(s) DoH URL 或 UDP host[:port]")
	}
	udpAddr := server
	if !strings.Contains(udpAddr, ":") {
		udpAddr += ":53"
	}
	if err := validateHostPort(udpAddr); err != nil {
		return fmt.Errorf("dns UDP 地址无效: %w", err)
	}
	return nil
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

func parseSourceCIDRs(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("至少需要一个 CIDR")
	}
	var nets []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			return nil, fmt.Errorf("CIDR 不能为空")
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
	host = strings.ToLower(strings.TrimSuffix(host, "."))
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

func validateHostnameOrIP(host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}
	host = normalizeTargetHost(host)
	if !validHostname(host) {
		return fmt.Errorf("host %q 不是合法 IP 或 DNS 主机名", host)
	}
	return nil
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

func validateSmuxStreamTarget(target string) error {
	if err := validateHostPort(target); err != nil {
		return fmt.Errorf("目标地址无效: %w", err)
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
	n, writeErr := writeAllCount(w, p)
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
		auth := parts[0]
		config.Host = strings.TrimSpace(parts[1])
		if auth == "" || config.Host == "" || !strings.Contains(auth, ":") {
			return nil, fmt.Errorf("认证格式必须是 user:pass@host:port")
		}
		authParts := strings.SplitN(auth, ":", 2)
		config.Username = authParts[0]
		config.Password = authParts[1]
		if config.Username == "" || config.Password == "" {
			return nil, fmt.Errorf("用户名和密码不能为空")
		}
		if err := validateSOCKS5AuthLength(config.Username, config.Password); err != nil {
			return nil, err
		}
	} else {
		config.Host = strings.TrimSpace(addr)
	}
	return config, nil
}

func validateSOCKS5AuthLength(username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("SOCKS5 用户名和密码长度必须不超过 255 字节")
	}
	return nil
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
		methods = []byte{0x02}
	} else {
		methods = []byte{0x00}
	}
	greeting := make([]byte, 2+len(methods))
	greeting[0], greeting[1] = 0x05, byte(len(methods))
	copy(greeting[2:], methods)

	if err := writeAll(conn, greeting); err != nil {
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
		if !bytes.Contains(methods, []byte{0x00}) {
			return fmt.Errorf("服务器选择了未提供的认证方法: %d", response[1])
		}
		return nil
	case 0x02:
		if !bytes.Contains(methods, []byte{0x02}) {
			return fmt.Errorf("服务器选择了未提供的认证方法: %d", response[1])
		}
		return socks5UserPassAuthSrv(conn, config.Username, config.Password)
	case 0xFF:
		return errors.New("服务器不接受认证")
	default:
		return fmt.Errorf("认证方法错误: %d", response[1])
	}
}

func socks5UserPassAuthSrv(conn net.Conn, username, password string) error {
	if err := validateSOCKS5AuthLength(username, password); err != nil {
		return err
	}
	authReq := make([]byte, 3+len(username)+len(password))
	authReq[0], authReq[1] = 0x01, byte(len(username))
	copy(authReq[2:], username)
	authReq[2+len(username)] = byte(len(password))
	copy(authReq[3+len(username):], password)

	if err := writeAll(conn, authReq); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x01 {
		return fmt.Errorf("SOCKS5 用户名密码认证响应版本错误: %d", response[0])
	}
	if response[1] != 0x00 {
		return errors.New("认证失败")
	}
	return nil
}

func socks5Connect(conn net.Conn, addr string) error {
	if err := validateHostPort(addr); err != nil {
		return err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

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
		if len(host) > 255 {
			return fmt.Errorf("域名过长")
		}
		request = make([]byte, 7+len(host))
		request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x03
		request[4] = byte(len(host))
		copy(request[5:], host)
		request[5+len(host)], request[6+len(host)] = byte(port>>8), byte(port)
	}

	if err := writeAll(conn, request); err != nil {
		return err
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x05 {
		return fmt.Errorf("SOCKS5 CONNECT响应版本错误: %d", response[0])
	}
	if response[2] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT响应 RSV 必须为 0")
	}
	if response[1] != 0x00 {
		return fmt.Errorf("状态码: %d", response[1])
	}
	switch response[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, make([]byte, 6)); err != nil {
			return err
		}
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenBuf[0])+2)); err != nil {
			return err
		}
	case 0x04:
		if _, err := io.ReadFull(conn, make([]byte, 18)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("地址类型无效: %d", response[3])
	}
	return nil
}

// ======================== UDP Relayer (服务端用) ========================

type UDPRelayer interface {
	Read(buffer []byte) (int, string, error)
	Write(data []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

type DirectUDPRelayer struct {
	conn   *net.UDPConn
	target *net.UDPAddr
}

func (d *DirectUDPRelayer) Read(buffer []byte) (int, string, error) {
	n, addr, err := d.conn.ReadFromUDP(buffer)
	if addr == nil {
		return n, "", err
	}
	return n, addr.String(), err
}
func (d *DirectUDPRelayer) Write(data []byte) (int, error) {
	return writeUDPDatagram(d.conn, data, d.target)
}
func (d *DirectUDPRelayer) SetReadDeadline(t time.Time) error { return d.conn.SetReadDeadline(t) }
func (d *DirectUDPRelayer) Close() error                      { return d.conn.Close() }

type udpDatagramWriter interface {
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

func writeUDPDatagram(w udpDatagramWriter, data []byte, addr *net.UDPAddr) (int, error) {
	if w == nil {
		return 0, errors.New("UDP writer 未初始化")
	}
	if addr == nil {
		return 0, errors.New("UDP 目标地址为空")
	}
	n, err := w.WriteToUDP(data, addr)
	if n > len(data) {
		return n, io.ErrShortWrite
	}
	if err != nil {
		return n, err
	}
	if n != len(data) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

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
	if err := writeSOCKS5UDPAssociate(tcpConn); err != nil {
		tcpConn.Close()
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, resp); err != nil {
		tcpConn.Close()
		return nil, err
	}
	if resp[0] != 0x05 {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE响应版本错误: %d", resp[0])
	}
	if resp[2] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE响应 RSV 必须为 0")
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
	default:
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE地址类型无效: %d", resp[3])
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, portBuf); err != nil {
		tcpConn.Close()
		return nil, err
	}
	relayPort := int(portBuf[0])<<8 | int(portBuf[1])
	if relayPort == 0 {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE端口必须在 1-65535 之间")
	}

	if relayHost == "0.0.0.0" || relayHost == "::" {
		h, _, _ := net.SplitHostPort(socks5Config.Host)
		relayHost = h
	}
	rAddr, errResolve := net.ResolveUDPAddr("udp", net.JoinHostPort(relayHost, strconv.Itoa(relayPort)))
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

func writeSOCKS5UDPAssociate(w io.Writer) error {
	return writeAll(w, []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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
	return writeUDPDatagram(r.udpConn, pkt, r.relayAddr)
}

func (r *SOCKS5UDPRelay) Read(buffer []byte) (int, string, error) {
	if r == nil || r.udpConn == nil {
		return 0, "", errors.New("SOCKS5 UDP relay 未初始化")
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return 0, "", errors.New("closed")
	}
	tmpPtr := bufPool.Get().(*[]byte)
	tmp := *tmpPtr
	defer bufPool.Put(tmpPtr)

	n, _, err := r.udpConn.ReadFromUDP(tmp)
	if err != nil {
		return 0, "", err
	}
	srcAddr, payload, err := parseSOCKS5UDPResp(tmp[:n])
	if err != nil {
		return 0, "", err
	}
	if len(payload) > len(buffer) {
		return 0, "", fmt.Errorf("SOCKS5 UDP payload length %d exceeds buffer length %d", len(payload), len(buffer))
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

func parseSOCKS5UDPResp(packet []byte) (string, []byte, error) {
	if len(packet) < 4 {
		return "", nil, fmt.Errorf("数据包过短")
	}
	if packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", nil, fmt.Errorf("RSV/FRAG 字段必须为 0")
	}
	atyp := packet[3]
	offset := 4
	var host string
	switch atyp {
	case 0x01:
		if offset+4 > len(packet) {
			return "", nil, fmt.Errorf("IPv4地址长度过短")
		}
		host = net.IP(packet[offset : offset+4]).String()
		offset += 4
	case 0x03:
		if offset+1 > len(packet) {
			return "", nil, fmt.Errorf("域名长度字段过短")
		}
		l := int(packet[offset])
		if l == 0 {
			return "", nil, fmt.Errorf("域名不能为空")
		}
		offset++
		if offset+l > len(packet) {
			return "", nil, fmt.Errorf("域名长度不足")
		}
		host = string(packet[offset : offset+l])
		offset += l
	case 0x04:
		if offset+16 > len(packet) {
			return "", nil, fmt.Errorf("IPv6地址长度过短")
		}
		host = net.IP(packet[offset : offset+16]).String()
		offset += 16
	default:
		return "", nil, fmt.Errorf("地址类型无效: %d", atyp)
	}
	if offset+2 > len(packet) {
		return "", nil, fmt.Errorf("端口字段过短")
	}
	port := int(packet[offset])<<8 | int(packet[offset+1])
	if port == 0 {
		return "", nil, fmt.Errorf("端口必须在 1-65535 之间")
	}
	offset += 2
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if err := validateHostPort(addr); err != nil {
		return "", nil, err
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

var (
	serverSessionsMu sync.Mutex
	serverSessions   sync.Map // map[string]*ClientSession
)

type WSChannel struct {
	id           uint64
	conn         *websocket.Conn
	session      *ClientSession
	capabilities uint32
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

func runWebSocketServer(ctx context.Context, addr string, allowedNets []*net.IPNet) {
	u, err := url.Parse(addr)
	if err != nil {
		log.Fatalf("[服务端] WS 地址无效: %v", err)
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
			atomic.AddUint64(&serverSourceRejectSeq, 1)
			http.Error(w, "禁止访问", http.StatusForbidden)
			return
		}
		if token != "" {
			if !webSocketRequestHasToken(r, token) {
				atomic.AddUint64(&serverAuthRejectSeq, 1)
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
		session, ok := getOrCreateClientSession(cid)
		if !ok {
			atomic.AddUint64(&serverClientRejectSeq, 1)
			log.Printf("[服务端] 拒绝客户端会话: client_id=%s max-clients=%d", shortID(cid), maxClientSessions)
			_ = wsConn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "max clients reached"), time.Now().Add(time.Second))
			_ = wsConn.Close()
			return
		}
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
	fmt.Fprintf(w, "# TYPE x_tunnel_client_protocol_negotiations_total counter\n")
	fmt.Fprintf(w, "x_tunnel_client_protocol_negotiations_total %d\n", atomic.LoadUint64(&clientProtocolOKSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_client_protocol_legacy_sessions_total counter\n")
	fmt.Fprintf(w, "x_tunnel_client_protocol_legacy_sessions_total %d\n", atomic.LoadUint64(&clientProtocolLegacySeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_client_protocol_negotiation_failures_total counter\n")
	fmt.Fprintf(w, "x_tunnel_client_protocol_negotiation_failures_total %d\n", atomic.LoadUint64(&clientProtocolFailureSeq))
	fmt.Fprintf(w, "# TYPE x_tunnel_server_sessions gauge\n")
	fmt.Fprintf(w, "x_tunnel_server_sessions %d\n", countServerSessions())
	fmt.Fprintf(w, "# TYPE x_tunnel_server_channels gauge\n")
	fmt.Fprintf(w, "x_tunnel_server_channels %d\n", countServerChannels())
	fmt.Fprintf(w, "# TYPE x_tunnel_server_active_streams gauge\n")
	fmt.Fprintf(w, "x_tunnel_server_active_streams %d\n", countServerActiveStreams())
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
			atomic.AddUint64(&serverStreamRejectSeq, 1)
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
	case streamKindHello:
		_ = stream.SetDeadline(time.Now().Add(cfg.RTTProbeTimeout))
		defer stream.SetDeadline(time.Time{})
		clientHello, err := readProtocolHello(stream)
		if err != nil {
			atomic.AddUint64(&serverProtocolFailureSeq, 1)
			log.Printf("[服务端] 客户ID:%s 协议协商读取失败: %v, 通道:%d", shortID(session.clientID), err, ch.id)
			return
		}
		response := negotiateProtocolHello(clientHello)
		if err := writeProtocolHello(stream, response); err != nil {
			atomic.AddUint64(&serverProtocolFailureSeq, 1)
			log.Printf("[服务端] 客户ID:%s 协议协商响应失败: %v, 通道:%d", shortID(session.clientID), err, ch.id)
			return
		}
		if response.Status != protocolStatusOK {
			atomic.AddUint64(&serverProtocolRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s 协议协商拒绝: %s, 通道:%d", shortID(session.clientID), response.Message, ch.id)
			return
		}
		atomic.StoreUint32(&ch.capabilities, response.Capabilities)
		atomic.AddUint64(&serverProtocolOKSeq, 1)
		log.Printf("[服务端] 客户ID:%s 协议协商成功: version=%d caps=0x%x, 通道:%d", shortID(session.clientID), response.Version, response.Capabilities, ch.id)
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
		sendOpenStatus := atomic.LoadUint32(&ch.capabilities)&protocolCapabilityTCPStatus != 0
		if err := validateIPStrategyValue(strategy); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s TCP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			if sendOpenStatus {
				_ = writeTCPOpenStatus(stream, tcpOpenStatusError, err.Error())
			}
			return
		}
		if err := validateSmuxStreamTarget(target); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s TCP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			if sendOpenStatus {
				_ = writeTCPOpenStatus(stream, tcpOpenStatusError, err.Error())
			}
			return
		}
		if err := ensureTargetAllowed(target); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s TCP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			if sendOpenStatus {
				_ = writeTCPOpenStatus(stream, tcpOpenStatusError, err.Error())
			}
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
			if sendOpenStatus {
				_ = writeTCPOpenStatus(stream, tcpOpenStatusError, err.Error())
			}
			return
		}
		if sendOpenStatus {
			if err := writeTCPOpenStatus(stream, tcpOpenStatusOK, ""); err != nil {
				_ = tcpConn.Close()
				return
			}
		}
		proxyConnStream(tcpConn, stream)
		log.Printf("[服务端] 客户ID:%s TCP 关闭: %s, 通道:%d", shortID(session.clientID), target, ch.id)
	case streamKindUDP:
		log.Printf("[服务端] 客户ID:%s SOCKS5 UDP 访问: %s, 通道:%d", shortID(session.clientID), target, ch.id)
		if err := validateIPStrategyValue(strategy); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s UDP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			return
		}
		if err := validateSmuxStreamTarget(target); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
			log.Printf("[服务端] 客户ID:%s UDP 拒绝: %s, reason=%v, 通道:%d", shortID(session.clientID), target, err, ch.id)
			return
		}
		if err := ensureTargetAllowed(target); err != nil {
			atomic.AddUint64(&serverTargetRejectSeq, 1)
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
			if err := writeUDPReply(stream, addr, buf[:n]); err != nil {
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
	channelCaps   []uint32
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
		channelCaps:   make([]uint32, total),
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
		caps, legacyProtocol, err := negotiateClientProtocol(sess, cfg.RTTProbeTimeout)
		if err != nil {
			atomic.AddUint64(&clientProtocolFailureSeq, 1)
			_ = sess.Close()
			_ = wsConn.Close()
			if !sleepBeforeReconnect(fmt.Sprintf("协议协商失败: %v", err)) {
				return
			}
			continue
		}
		if legacyProtocol {
			atomic.AddUint64(&clientProtocolLegacySeq, 1)
			log.Printf("[客户端] 通道 %d (IP:%s) 使用旧协议模式（服务端未响应 hello）", chID, ipLabel)
		} else {
			atomic.AddUint64(&clientProtocolOKSeq, 1)
			log.Printf("[客户端] 通道 %d (IP:%s) 协议协商成功: version=%d caps=0x%x", chID, ipLabel, protocolVersion, caps)
		}
		p.wsConnsMu.Lock()
		p.smuxConns[idx] = sess
		p.channelRTT[idx] = 0
		p.channelCaps[idx] = caps
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

func negotiateClientProtocol(sess *smux.Session, timeout time.Duration) (uint32, bool, error) {
	s, err := sess.OpenStream()
	if err != nil {
		return 0, false, err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(timeout))
	if err := writeSmuxOpenHeader(s, streamKindHello, IPStrategyDefault, ""); err != nil {
		return 0, false, err
	}
	if err := writeProtocolHello(s, currentProtocolHello()); err != nil {
		return 0, false, err
	}
	response, err := readProtocolHello(s)
	if err != nil {
		if isLegacyProtocolHelloError(err) {
			return 0, true, nil
		}
		return 0, false, err
	}
	if response.Status != protocolStatusOK {
		if response.Message != "" {
			return 0, false, fmt.Errorf("协议协商失败: %s", response.Message)
		}
		return 0, false, fmt.Errorf("协议协商失败: status=%d", response.Status)
	}
	if response.Version != protocolVersion {
		return 0, false, fmt.Errorf("协议版本不匹配: %d", response.Version)
	}
	required := protocolCapabilityTCP | protocolCapabilityPing
	if response.Capabilities&required != required {
		return 0, false, fmt.Errorf("协议能力不足: caps=0x%x", response.Capabilities)
	}
	return response.Capabilities, false, nil
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

func (p *ECHPool) openBestStream() (*smux.Stream, int, int, uint32, error) {
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
	if caps&protocolCapabilityTCPStatus != 0 {
		_ = s.SetDeadline(time.Now().Add(cfg.DialTimeout))
		status, message, err := readTCPOpenStatus(s)
		_ = s.SetDeadline(time.Time{})
		if err != nil {
			_ = s.Close()
			return nil, 0, 0, err
		}
		if status != tcpOpenStatusOK {
			_ = s.Close()
			if message == "" {
				message = fmt.Sprintf("status=%d", status)
			}
			return nil, 0, 0, fmt.Errorf("远端 TCP 打开失败: %s", message)
		}
	}
	return s, chID, decision, nil
}

func (p *ECHPool) openUDPStream(target string) (*smux.Stream, int, int, error) {
	s, chID, decision, _, err := p.openBestStream()
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
	lAddr, tAddr, err := parseTCPForwardRule(rule)
	if err != nil {
		log.Fatalf("[客户端] TCP转发地址解析失败: %v", err)
	}
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
	active    bool
	channelID int
	target    string
	stream    *smux.Stream
}

func parseAuthAndAddr(full string) (string, string, string, error) {
	u, p, h := "", "", full
	if strings.Contains(full, "@") {
		parts := strings.SplitN(full, "@", 2)
		auth := parts[0]
		h = strings.TrimSpace(parts[1])
		if auth == "" || h == "" || !strings.Contains(auth, ":") {
			return "", "", "", fmt.Errorf("认证格式必须是 user:pass@host:port")
		}
		ap := strings.SplitN(auth, ":", 2)
		u, p = ap[0], ap[1]
		if u == "" || p == "" {
			return "", "", "", fmt.Errorf("用户名和密码不能为空")
		}
	}
	if strings.TrimSpace(h) == "" {
		return "", "", "", fmt.Errorf("地址不能为空")
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
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if cfgp.Username != "" {
		if !bytes.Contains(methods, []byte{0x02}) {
			_ = writeSOCKS5MethodSelection(c, 0xff)
			return
		}
		if err := writeSOCKS5MethodSelection(c, 0x02); err != nil {
			return
		}
		if err := handleSOCKS5UserPassAuth(c, cfgp); err != nil {
			return
		}
	} else {
		if !bytes.Contains(methods, []byte{0x00}) {
			_ = writeSOCKS5MethodSelection(c, 0xff)
			return
		}
		if err := writeSOCKS5MethodSelection(c, 0x00); err != nil {
			return
		}
	}

	req, reply, err := readLocalSOCKS5Request(c)
	if err != nil {
		if reply != 0 {
			_ = writeSOCKS5Reply(c, reply)
		}
		return
	}

	// 增强过滤逻辑：解析 host 判断是否为 IP，从而覆盖 ATYP=0x03 但内容为 IP 的情况
	host, _, _ := net.SplitHostPort(req.target)
	ip := net.ParseIP(host)

	if req.command == 0x01 {
		if ipStrategy == IPStrategyIPv4Only {
			if req.atyp == 0x04 || (ip != nil && ip.To4() == nil) {
				_ = writeSOCKS5Reply(c, 0x02)
				return
			}
		}
		if ipStrategy == IPStrategyIPv6Only {
			if req.atyp == 0x01 || (ip != nil && ip.To4() != nil) {
				_ = writeSOCKS5Reply(c, 0x02)
				return
			}
		}
	}

	_ = c.SetDeadline(time.Time{})

	switch req.command {
	case 0x01:
		handleSOCKS5Connect(c, req.target)
	case 0x03:
		handleSOCKS5UDP(c, cfgp)
	default:
		_ = writeSOCKS5Reply(c, 0x07)
	}
}

type localSOCKS5Request struct {
	command byte
	atyp    byte
	target  string
}

func readLocalSOCKS5Request(r io.Reader) (localSOCKS5Request, byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return localSOCKS5Request{}, 0, err
	}
	if head[2] != 0x00 {
		return localSOCKS5Request{}, 0x01, fmt.Errorf("SOCKS5 请求 RSV 必须为 0")
	}

	host, err := readLocalSOCKS5RequestHost(r, head[3])
	if err != nil {
		if head[3] != 0x01 && head[3] != 0x03 && head[3] != 0x04 {
			return localSOCKS5Request{}, 0x08, err
		}
		return localSOCKS5Request{}, 0, err
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(r, pb); err != nil {
		return localSOCKS5Request{}, 0, err
	}
	port := int(pb[0])<<8 | int(pb[1])
	if head[1] == 0x01 && port == 0 {
		return localSOCKS5Request{}, 0x04, fmt.Errorf("SOCKS5 CONNECT 目标端口不能为 0")
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	if head[1] == 0x01 {
		if err := validateHostPort(target); err != nil {
			return localSOCKS5Request{}, 0x04, fmt.Errorf("SOCKS5 CONNECT目标无效: %w", err)
		}
	}

	return localSOCKS5Request{
		command: head[1],
		atyp:    head[3],
		target:  target,
	}, 0, nil
}

func readLocalSOCKS5RequestHost(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03:
		b := make([]byte, 1)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		addr := make([]byte, b[0])
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", err
		}
		return string(addr), nil
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	default:
		return "", fmt.Errorf("SOCKS5 地址类型不支持: %d", atyp)
	}
}

func writeSOCKS5MethodSelection(w io.Writer, method byte) error {
	return writeAll(w, []byte{0x05, method})
}

func writeSOCKS5UserPassReply(w io.Writer, status byte) error {
	return writeAll(w, []byte{0x01, status})
}

func writeSOCKS5Reply(w io.Writer, status byte) error {
	return writeAll(w, []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func writeSOCKS5UDPAssociateReply(w io.Writer, addr *net.UDPAddr) error {
	if addr == nil {
		return errors.New("SOCKS5 UDP ASSOCIATE 响应地址为空")
	}
	if addr.Port <= 0 || addr.Port > 65535 {
		return fmt.Errorf("SOCKS5 UDP ASSOCIATE 响应端口无效: %d", addr.Port)
	}
	resp := []byte{0x05, 0x00, 0x00}
	if ip4 := addr.IP.To4(); ip4 != nil {
		resp = append(resp, 0x01)
		resp = append(resp, ip4...)
	} else {
		ip16 := addr.IP.To16()
		if ip16 == nil {
			return errors.New("SOCKS5 UDP ASSOCIATE 响应地址无效")
		}
		resp = append(resp, 0x04)
		resp = append(resp, ip16...)
	}
	resp = append(resp, byte(addr.Port>>8), byte(addr.Port))
	return writeAll(w, resp)
}

func handleSOCKS5UserPassAuth(c net.Conn, cfgp *ProxyConfig) error {
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if b[0] != 0x01 {
		if err := writeSOCKS5UserPassReply(c, 0x01); err != nil {
			return err
		}
		return fmt.Errorf("SOCKS5 用户名密码认证版本无效: %d", b[0])
	}
	u := make([]byte, b[1])
	if _, err := io.ReadFull(c, u); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, b[:1]); err != nil {
		return err
	}
	p := make([]byte, b[0])
	if _, err := io.ReadFull(c, p); err != nil {
		return err
	}
	if string(u) == cfgp.Username && string(p) == cfgp.Password {
		return writeSOCKS5UserPassReply(c, 0x00)
	}
	if err := writeSOCKS5UserPassReply(c, 0x01); err != nil {
		return err
	}
	return errors.New("认证失败")
}

func handleSOCKS5Connect(c net.Conn, target string) {
	stream, _, decision, err := echPool.openTCPStream(target)
	if err != nil {
		log.Printf("[客户端] %s SOCKS5 打开失败 %s: %v", clientSourceAddr(c), target, err)
		_ = writeSOCKS5Reply(c, 0x05)
		_ = c.Close()
		return
	}
	if err := writeSOCKS5Reply(c, 0x00); err != nil {
		_ = stream.Close()
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
	if err := writeSOCKS5UDPAssociateReply(c, actual); err != nil {
		_ = c.Close()
		return
	}

	assoc := &UDPAssociation{
		id:          atomic.AddUint64(&udpAssociationSeq, 1),
		tcpConn:     c,
		udpListener: ul,
		pool:        echPool,
		active:      true,
		channelID:   -1,
	}
	atomic.AddUint64(&udpAssociationActiveSeq, 1)
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
			prt, err := strconv.Atoi(ps)
			if err != nil {
				continue
			}
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
			log.Printf("[客户端] udp_assoc=%d 丢弃不同目标 %s，已绑定目标 %s", a.id, target, a.target)
			return
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
	host, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}
	pkt, err := buildSOCKS5UDPPacket(host, port, data)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.clientUDPAddr != nil {
		_, _ = writeUDPDatagram(a.udpListener, pkt, a.clientUDPAddr)
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
	active := a.active
	a.active = false
	a.mu.Unlock()
	if active {
		atomic.AddUint64(&udpAssociationActiveSeq, ^uint64(0))
	}
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
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
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
		if l == 0 {
			return "", nil, errors.New("域名不能为空")
		}
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
	if p == 0 {
		return "", nil, errors.New("端口必须在 1-65535 之间")
	}
	off += 2
	t := fmt.Sprintf("%s:%d", h, p)
	if b[3] == 0x04 {
		t = fmt.Sprintf("[%s]:%d", h, p)
	}
	if err := validateHostPort(t); err != nil {
		return "", nil, err
	}
	return t, b[off:], nil
}

func buildSOCKS5UDPPacket(h string, p int, d []byte) ([]byte, error) {
	if p <= 0 || p > 65535 {
		return nil, fmt.Errorf("端口必须在 1-65535 之间")
	}
	buf := []byte{0, 0, 0}
	ip := net.ParseIP(h)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, 0x01)
		buf = append(buf, ip4...)
	} else if ip != nil {
		buf = append(buf, 0x04)
		buf = append(buf, ip...)
	} else {
		if h == "" {
			return nil, fmt.Errorf("域名不能为空")
		}
		if len(h) > 255 {
			return nil, fmt.Errorf("域名过长")
		}
		if err := validateHostnameOrIP(h); err != nil {
			return nil, err
		}
		buf = append(buf, 0x03, byte(len(h)))
		buf = append(buf, h...)
	}
	buf = append(buf, byte(p>>8), byte(p))
	buf = append(buf, d...)
	return buf, nil
}

func runHTTPListener(ctx context.Context, addr string) {
	h, u, p, err := parseAuthAndAddr(strings.TrimPrefix(addr, "http://"))
	if err != nil {
		log.Fatalf("[客户端] HTTP地址解析失败: %v", err)
	}
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
		if !validHTTPProxyBasicAuth(req.Header.Get("Proxy-Authorization"), cfgp.Username, cfgp.Password) {
			_ = writeHTTPProxyResponse(c, "HTTP/1.1 407 需要认证\r\nProxy-Authenticate: Basic realm=\"代理\"\r\n\r\n")
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
		_ = writeHTTPProxyResponse(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if req.Method == "CONNECT" {
		if err := writeHTTPProxyResponse(c, "HTTP/1.1 200 连接已建立\r\n\r\n"); err != nil {
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

func webSocketRequestHasToken(r *http.Request, want string) bool {
	for _, offered := range websocket.Subprotocols(r) {
		if subtle.ConstantTimeCompare([]byte(offered), []byte(want)) == 1 {
			return true
		}
	}
	return false
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
