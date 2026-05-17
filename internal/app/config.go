package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"x-tunnel/internal/netaddr"
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
	AuthSkew           time.Duration
	PreAuthTimeout     time.Duration

	ReadBuf int
}

func defaultGlobalConfig() GlobalConfig {
	return GlobalConfig{
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
		AuthSkew:           5 * time.Minute,
		PreAuthTimeout:     5 * time.Second,
		ReadBuf:            64 * 1024,
	}
}

var cfg = defaultGlobalConfig()

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
	controlAddr         string
	readyFile           string
	controlTokenFile    string
	checkConfigFile     string
	formatConfigFile    string

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
	serverProtocolReplaySeq    uint64
	clientProtocolOKSeq        uint64
	clientProtocolFailureSeq   uint64
	clientRTTProbeFailureSeq   uint64
	runtimeBytesSentSeq        uint64
	runtimeBytesReceivedSeq    uint64
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
	flag.StringVar(&token, "token", "", "v2 ChannelInit HMAC 预共享令牌（不会放入 URL 或 WebSocket Subprotocol）")
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
	flag.StringVar(&controlAddr, "control", "", "可选本地控制 API 监听地址，如 127.0.0.1:0")
	flag.StringVar(&readyFile, "ready-file", "", "可选 sidecar ready JSON 文件路径，需配合 -control 使用")
	flag.StringVar(&controlTokenFile, "control-token-file", "", "可选控制 API bearer token 文件路径，需配合 -control 使用")
	flag.StringVar(&checkConfigFile, "check-config", "", "离线校验 JSON 配置文件并退出；使用 - 从 stdin 读取")
	flag.StringVar(&formatConfigFile, "format-config", "", "离线格式化 JSON 配置文件到 stdout 并退出；使用 - 从 stdin 读取")
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
	flag.DurationVar(&cfg.AuthSkew, "auth-skew", cfg.AuthSkew, "v2 ChannelInit 时间戳允许偏差")
	flag.DurationVar(&cfg.PreAuthTimeout, "preauth-timeout", cfg.PreAuthTimeout, "v2 预认证阶段超时时间")
}

func versionString() string {
	return fmt.Sprintf("x-tunnel version=%s commit=%s build=%s", buildVersion, buildCommit, buildDate)
}

type FileConfig struct {
	Listen              *string                    `json:"listen"`
	Forward             *string                    `json:"forward"`
	IP                  *string                    `json:"ip"`
	Block               *string                    `json:"block"`
	Cert                *string                    `json:"cert"`
	Key                 *string                    `json:"key"`
	ClientCA            *string                    `json:"client_ca"`
	ClientCert          *string                    `json:"client_cert"`
	ClientKey           *string                    `json:"client_key"`
	ClientCAFlag        *string                    `json:"client-ca"`
	ClientCertFlag      *string                    `json:"client-cert"`
	ClientKeyFlag       *string                    `json:"client-key"`
	Token               *string                    `json:"token"`
	Metrics             *string                    `json:"metrics"`
	CIDR                *string                    `json:"cidr"`
	AllowTarget         *string                    `json:"allow_target"`
	DenyTarget          *string                    `json:"deny_target"`
	AllowHost           *string                    `json:"allow_host"`
	DenyHost            *string                    `json:"deny_host"`
	AllowTargetFlag     *string                    `json:"allow-target"`
	DenyTargetFlag      *string                    `json:"deny-target"`
	AllowHostFlag       *string                    `json:"allow-host"`
	DenyHostFlag        *string                    `json:"deny-host"`
	MaxClients          *int                       `json:"max_clients"`
	MaxClientsFlag      *int                       `json:"max-clients"`
	MaxStreams          *int                       `json:"max_streams"`
	MaxStreamsFlag      *int                       `json:"max-streams"`
	DNS                 *string                    `json:"dns"`
	ECH                 *string                    `json:"ech"`
	IPS                 *string                    `json:"ips"`
	Connections         *int                       `json:"connections"`
	Insecure            *bool                      `json:"insecure"`
	Fallback            *bool                      `json:"fallback"`
	WebSocketFrontProxy *WebSocketFrontProxyConfig `json:"websocket_front_proxy"`
	DialTimeout         *string                    `json:"dial_timeout"`
	WSHandshakeTimeout  *string                    `json:"ws_handshake_timeout"`
	ReconnectDelay      *string                    `json:"reconnect_delay"`
	ReconnectMaxDelay   *string                    `json:"reconnect_max_delay"`
	ReconnectJitter     *string                    `json:"reconnect_jitter"`
	RTTProbeTimeout     *string                    `json:"rtt_timeout"`
	DNSQueryTimeout     *string                    `json:"dns_timeout"`
	ECHRetryDelay       *string                    `json:"ech_retry_delay"`
	UDPReadTimeout      *string                    `json:"udp_read_timeout"`
	ShutdownTimeout     *string                    `json:"shutdown_timeout"`
	AuthSkew            *string                    `json:"auth_skew"`
	PreAuthTimeout      *string                    `json:"preauth_timeout"`
}

func visitedFlags() map[string]bool {
	seen := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		seen[f.Name] = true
	})
	return seen
}

type CLIOverrides map[string]bool

type runtimeValues struct {
	ListenAddr          string
	ForwardAddr         string
	IPAddr              string
	UDPBlockPortsStr    string
	CertFile            string
	KeyFile             string
	ClientCAFile        string
	ClientCertFile      string
	ClientKeyFile       string
	Token               string
	MetricsAddr         string
	CIDRs               string
	TargetAllowCIDRs    string
	TargetDenyCIDRs     string
	TargetAllowHosts    string
	TargetDenyHosts     string
	MaxClientSessions   int
	MaxStreamsPerClient int
	ConnectionNum       int
	Insecure            bool
	IPS                 string
	DNSServer           string
	ECHDomain           string
	Fallback            bool
	Global              GlobalConfig
	WebSocketFrontProxy WebSocketFrontProxyConfig
}

type RuntimeConfig struct {
	values     runtimeValues
	startup    *startupConfig
	ConfigHash string
}

func currentRuntimeValues() runtimeValues {
	return runtimeValues{
		ListenAddr:          listenAddr,
		ForwardAddr:         forwardAddr,
		IPAddr:              ipAddr,
		UDPBlockPortsStr:    udpBlockPortsStr,
		CertFile:            certFile,
		KeyFile:             keyFile,
		ClientCAFile:        clientCAFile,
		ClientCertFile:      clientCertFile,
		ClientKeyFile:       clientKeyFile,
		Token:               token,
		MetricsAddr:         metricsAddr,
		CIDRs:               cidrs,
		TargetAllowCIDRs:    targetAllowCIDRs,
		TargetDenyCIDRs:     targetDenyCIDRs,
		TargetAllowHosts:    targetAllowHosts,
		TargetDenyHosts:     targetDenyHosts,
		MaxClientSessions:   maxClientSessions,
		MaxStreamsPerClient: maxStreamsPerClient,
		ConnectionNum:       connectionNum,
		Insecure:            insecure,
		IPS:                 ips,
		DNSServer:           dnsServer,
		ECHDomain:           echDomain,
		Fallback:            fallback,
		Global:              cfg,
		WebSocketFrontProxy: cloneWebSocketFrontProxyConfig(websocketFrontProxyConfig),
	}
}

func defaultRuntimeValues() runtimeValues {
	return runtimeValues{
		UDPBlockPortsStr: "443",
		CIDRs:            "0.0.0.0/0,::/0",
		ConnectionNum:    3,
		DNSServer:        "https://doh.pub/dns-query",
		ECHDomain:        "cloudflare-ech.com",
		Global:           defaultGlobalConfig(),
	}
}

func (values runtimeValues) applyGlobals() {
	listenAddr = values.ListenAddr
	forwardAddr = values.ForwardAddr
	ipAddr = values.IPAddr
	udpBlockPortsStr = values.UDPBlockPortsStr
	certFile = values.CertFile
	keyFile = values.KeyFile
	clientCAFile = values.ClientCAFile
	clientCertFile = values.ClientCertFile
	clientKeyFile = values.ClientKeyFile
	token = values.Token
	metricsAddr = values.MetricsAddr
	cidrs = values.CIDRs
	targetAllowCIDRs = values.TargetAllowCIDRs
	targetDenyCIDRs = values.TargetDenyCIDRs
	targetAllowHosts = values.TargetAllowHosts
	targetDenyHosts = values.TargetDenyHosts
	maxClientSessions = values.MaxClientSessions
	maxStreamsPerClient = values.MaxStreamsPerClient
	connectionNum = values.ConnectionNum
	insecure = values.Insecure
	ips = values.IPS
	dnsServer = values.DNSServer
	echDomain = values.ECHDomain
	fallback = values.Fallback
	cfg = values.Global
	websocketFrontProxyConfig = cloneWebSocketFrontProxyConfig(values.WebSocketFrontProxy)
}

func newRuntimeConfig(values runtimeValues, startup *startupConfig) RuntimeConfig {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%#v", values)))
	return RuntimeConfig{
		values:     values,
		startup:    startup,
		ConfigHash: fmt.Sprintf("%x", sum[:]),
	}
}

func LoadConfig(path string, overrides CLIOverrides) (RuntimeConfig, error) {
	values := currentRuntimeValues()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return RuntimeConfig{}, err
		}
		if err := applyConfigJSONToValues(raw, map[string]bool(overrides), &values); err != nil {
			return RuntimeConfig{}, err
		}
	}
	if strings.TrimSpace(values.ListenAddr) == "" {
		return RuntimeConfig{}, fmt.Errorf("至少需要一个监听地址")
	}
	startup, err := validateStartupConfigValues(values)
	if err != nil {
		return RuntimeConfig{}, err
	}
	return newRuntimeConfig(values, startup), nil
}

func ValidateConfig(config RuntimeConfig) error {
	_, err := validateStartupConfigValues(config.values)
	return err
}

func CheckConfigJSON(raw []byte) error {
	values := defaultRuntimeValues()
	if err := applyConfigJSONToValues(raw, nil, &values); err != nil {
		return err
	}
	if strings.TrimSpace(values.ListenAddr) == "" {
		return fmt.Errorf("至少需要一个监听地址")
	}
	_, err := validateStartupConfigValues(values)
	return err
}

func FormatConfigJSON(raw []byte) ([]byte, error) {
	if err := CheckConfigJSON(raw); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	normalizeConfigFieldAliases(fields)
	formatted, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}
	formatted = append(formatted, '\n')
	return formatted, nil
}

func normalizeConfigFieldAliases(fields map[string]json.RawMessage) {
	aliases := map[string]string{
		"allow-target": "allow_target",
		"deny-target":  "deny_target",
		"allow-host":   "allow_host",
		"deny-host":    "deny_host",
		"max-clients":  "max_clients",
		"max-streams":  "max_streams",
		"client-ca":    "client_ca",
		"client-cert":  "client_cert",
		"client-key":   "client_key",
	}
	for alias, canonical := range aliases {
		if value, ok := fields[alias]; ok {
			fields[canonical] = value
			delete(fields, alias)
		}
	}
}

func loadConfigFile(path string, seen map[string]bool) error {
	values := currentRuntimeValues()
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := applyConfigJSONToValues(raw, seen, &values); err != nil {
		return err
	}
	values.applyGlobals()
	return nil
}

func applyConfigJSONToValues(raw []byte, seen map[string]bool, values *runtimeValues) error {
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
	applyStringConfig(seen, "l", fc.Listen, &values.ListenAddr)
	applyStringConfig(seen, "f", fc.Forward, &values.ForwardAddr)
	applyStringConfig(seen, "ip", fc.IP, &values.IPAddr)
	applyStringConfig(seen, "block", fc.Block, &values.UDPBlockPortsStr)
	applyStringConfig(seen, "cert", fc.Cert, &values.CertFile)
	applyStringConfig(seen, "key", fc.Key, &values.KeyFile)
	applyStringConfig(seen, "client-ca", clientCA, &values.ClientCAFile)
	applyStringConfig(seen, "client-cert", clientCert, &values.ClientCertFile)
	applyStringConfig(seen, "client-key", clientKey, &values.ClientKeyFile)
	applyStringConfig(seen, "token", fc.Token, &values.Token)
	applyStringConfig(seen, "metrics", fc.Metrics, &values.MetricsAddr)
	applyStringConfig(seen, "cidr", fc.CIDR, &values.CIDRs)
	applyStringConfig(seen, "allow-target", allowTarget, &values.TargetAllowCIDRs)
	applyStringConfig(seen, "deny-target", denyTarget, &values.TargetDenyCIDRs)
	applyStringConfig(seen, "allow-host", allowHost, &values.TargetAllowHosts)
	applyStringConfig(seen, "deny-host", denyHost, &values.TargetDenyHosts)
	applyStringConfig(seen, "dns", fc.DNS, &values.DNSServer)
	applyStringConfig(seen, "ech", fc.ECH, &values.ECHDomain)
	applyStringConfig(seen, "ips", fc.IPS, &values.IPS)
	if fc.Connections != nil && !seen["n"] {
		values.ConnectionNum = *fc.Connections
	}
	if err := applyNonNegativeIntConfig(seen, "max-clients", maxClients, &values.MaxClientSessions); err != nil {
		return err
	}
	if err := applyNonNegativeIntConfig(seen, "max-streams", maxStreams, &values.MaxStreamsPerClient); err != nil {
		return err
	}
	if fc.Insecure != nil && !seen["insecure"] {
		values.Insecure = *fc.Insecure
	}
	if fc.Fallback != nil && !seen["fallback"] {
		values.Fallback = *fc.Fallback
	}
	if fc.WebSocketFrontProxy != nil {
		values.WebSocketFrontProxy = cloneWebSocketFrontProxyConfig(*fc.WebSocketFrontProxy)
	} else {
		values.WebSocketFrontProxy = WebSocketFrontProxyConfig{}
	}
	if err := applyDurationConfig(seen, "dial-timeout", fc.DialTimeout, &values.Global.DialTimeout); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "ws-handshake-timeout", fc.WSHandshakeTimeout, &values.Global.WSHandshakeTimeout); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "reconnect-delay", fc.ReconnectDelay, &values.Global.ReconnectDelay); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "reconnect-max-delay", fc.ReconnectMaxDelay, &values.Global.ReconnectMaxDelay); err != nil {
		return err
	}
	if err := applyNonNegativeDurationConfig(seen, "reconnect-jitter", fc.ReconnectJitter, &values.Global.ReconnectJitter); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "rtt-timeout", fc.RTTProbeTimeout, &values.Global.RTTProbeTimeout); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "dns-timeout", fc.DNSQueryTimeout, &values.Global.DNSQueryTimeout); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "ech-retry-delay", fc.ECHRetryDelay, &values.Global.ECHRetryDelay); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "udp-read-timeout", fc.UDPReadTimeout, &values.Global.UDPReadTimeout); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "shutdown-timeout", fc.ShutdownTimeout, &values.Global.ShutdownTimeout); err != nil {
		return err
	}
	if err := applyNonNegativeDurationConfig(seen, "auth-skew", fc.AuthSkew, &values.Global.AuthSkew); err != nil {
		return err
	}
	if err := applyDurationConfig(seen, "preauth-timeout", fc.PreAuthTimeout, &values.Global.PreAuthTimeout); err != nil {
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
	return validateGlobalConfigValues(cfg, maxClientSessions, maxStreamsPerClient)
}

func validateGlobalConfigValues(global GlobalConfig, maxClients, maxStreams int) error {
	checks := []struct {
		name  string
		value time.Duration
	}{
		{name: "dial-timeout", value: global.DialTimeout},
		{name: "ws-handshake-timeout", value: global.WSHandshakeTimeout},
		{name: "reconnect-delay", value: global.ReconnectDelay},
		{name: "reconnect-max-delay", value: global.ReconnectMaxDelay},
		{name: "rtt-timeout", value: global.RTTProbeTimeout},
		{name: "dns-timeout", value: global.DNSQueryTimeout},
		{name: "ech-retry-delay", value: global.ECHRetryDelay},
		{name: "udp-read-timeout", value: global.UDPReadTimeout},
		{name: "shutdown-timeout", value: global.ShutdownTimeout},
		{name: "preauth-timeout", value: global.PreAuthTimeout},
	}
	for _, check := range checks {
		if check.value <= 0 {
			return fmt.Errorf("%s 必须大于 0", check.name)
		}
	}
	if global.ReconnectJitter < 0 {
		return fmt.Errorf("reconnect-jitter 不能小于 0")
	}
	if global.AuthSkew < 0 {
		return fmt.Errorf("auth-skew 不能小于 0")
	}
	if global.ReconnectMaxDelay < global.ReconnectDelay {
		return fmt.Errorf("reconnect-max-delay 不能小于 reconnect-delay")
	}
	if maxClients < 0 {
		return fmt.Errorf("max-clients 不能小于 0")
	}
	if maxStreams < 0 {
		return fmt.Errorf("max-streams 不能小于 0")
	}
	return nil
}

func validateMTLSConfig(isServer bool, serverScheme string) error {
	return validateMTLSConfigValues(isServer, serverScheme, currentRuntimeValues())
}

func validateMTLSConfigValues(isServer bool, serverScheme string, values runtimeValues) error {
	if err := validateCertificatePair(values.CertFile, values.KeyFile); err != nil {
		return fmt.Errorf("server cert/key: %w", err)
	}
	if err := validateCertificatePair(values.ClientCertFile, values.ClientKeyFile); err != nil {
		return fmt.Errorf("client cert/key: %w", err)
	}
	if isServer {
		if values.ClientCAFile != "" && serverScheme != "wss" {
			return fmt.Errorf("-client-ca 只能用于 wss 服务端")
		}
		if values.ClientCertFile != "" || values.ClientKeyFile != "" {
			return fmt.Errorf("-client-cert/-client-key 只能用于客户端模式")
		}
		return nil
	}
	if values.CertFile != "" || values.KeyFile != "" {
		return fmt.Errorf("-cert/-key 只能用于服务端模式")
	}
	if values.ClientCAFile != "" {
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
	for _, r := range value {
		if r < 32 || r == 127 {
			return fmt.Errorf("token 不能包含控制字符")
		}
	}
	return nil
}

func validateHostPort(value string) error {
	return netaddr.ValidateHostPort(value)
}

func validateListenHostPort(value string) error {
	return netaddr.ValidateListenHostPort(value)
}

func validateMetricsListenHostPort(value string) error {
	return netaddr.ValidateListenHostPortAllowZero(value)
}

func validateHostPortValue(value string, allowEmptyHost bool) error {
	return netaddr.ValidateHostPortValue(value, allowEmptyHost)
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
	return validateStartupConfigValues(currentRuntimeValues())
}

func validateStartupConfigValues(values runtimeValues) (*startupConfig, error) {
	if err := validateToken(values.Token); err != nil {
		return nil, fmt.Errorf("token 无效: %w", err)
	}
	if err := validateGlobalConfigValues(values.Global, values.MaxClientSessions, values.MaxStreamsPerClient); err != nil {
		return nil, fmt.Errorf("全局参数无效: %w", err)
	}
	if values.MetricsAddr != "" {
		if err := validateMetricsListenHostPort(values.MetricsAddr); err != nil {
			return nil, fmt.Errorf("metrics 地址无效: %w", err)
		}
	}
	targetIPs := splitCommaList(values.IPAddr)
	for _, targetIP := range targetIPs {
		if err := validateDialIPOverride(targetIP); err != nil {
			return nil, fmt.Errorf("-ip 参数无效 %q: %w", targetIP, err)
		}
	}
	ipStrategyValue, err := parseIPStrategyStrict(values.IPS)
	if err != nil {
		return nil, fmt.Errorf("-ips 参数无效: %w", err)
	}
	listeners, isServer, serverListen, serverScheme, err := classifyListeners(values.ListenAddr)
	if err != nil {
		return nil, err
	}
	if err := validateMTLSConfigValues(isServer, serverScheme, values); err != nil {
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
		sourceNets, err := parseSourceCIDRs(values.CIDRs)
		if err != nil {
			return nil, fmt.Errorf("source CIDR 配置无效: %w", err)
		}
		policy, socksConfig, err := validateServerStartupConfig(values.ForwardAddr, values.TargetAllowCIDRs, values.TargetDenyCIDRs, values.TargetAllowHosts, values.TargetDenyHosts)
		if err != nil {
			return nil, err
		}
		startup.SourceCIDRs = sourceNets
		startup.TargetPolicy = policy
		startup.SOCKS5Config = socksConfig
		return startup, nil
	}
	clientConfig, err := validateClientStartupConfig(values.ForwardAddr, values.ConnectionNum, values.ClientCertFile, values.ClientKeyFile, values.Insecure, values.Fallback, values.UDPBlockPortsStr)
	if err != nil {
		return nil, err
	}
	if clientConfig.ForwardScheme == "wss" && !clientConfig.Fallback {
		if err := validateECHLookupConfig(values.ECHDomain, values.DNSServer); err != nil {
			return nil, fmt.Errorf("ECH 查询配置无效: %w", err)
		}
	}
	if err := validateWebSocketFrontProxyConfig(values.WebSocketFrontProxy); err != nil {
		return nil, fmt.Errorf("WebSocket 前置代理配置无效: %w", err)
	}
	startup.Client = clientConfig
	return startup, nil
}
