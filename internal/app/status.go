package app

import (
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type runtimeListener struct {
	mu         sync.RWMutex
	Protocol   string `json:"protocol"`
	Configured string `json:"configured"`
	Actual     string `json:"actual"`
	State      string `json:"state"`
	LastError  string `json:"last_error,omitempty"`

	closeFn func() error
	done    chan struct{}
	once    sync.Once
}

type ListenerStatus struct {
	Protocol   string `json:"protocol"`
	Configured string `json:"configured"`
	Actual     string `json:"actual"`
	State      string `json:"state"`
	LastError  string `json:"last_error,omitempty"`
}

type ClientChannelStatus struct {
	Channel      int     `json:"channel"`
	Up           bool    `json:"up"`
	RTTSeconds   float64 `json:"rtt_seconds"`
	Capabilities uint64  `json:"capabilities"`
}

type ClientStatus struct {
	Forward      string                `json:"forward"`
	Channels     []ClientChannelStatus `json:"channels"`
	Fallback     bool                  `json:"fallback"`
	ECHEnabled   bool                  `json:"ech_enabled"`
	FrontProxy   bool                  `json:"front_proxy"`
	UDPBlockList []int                 `json:"udp_block_ports,omitempty"`
}

type ServerStatus struct {
	Sessions      int                 `json:"sessions"`
	Channels      int                 `json:"channels"`
	ActiveStreams int                 `json:"active_streams"`
	TargetPolicy  TargetPolicySummary `json:"target_policy"`
}

type TargetPolicySummary struct {
	AllowCIDRs int `json:"allow_cidrs"`
	DenyCIDRs  int `json:"deny_cidrs"`
	AllowHosts int `json:"allow_hosts"`
	DenyHosts  int `json:"deny_hosts"`
}

type Status struct {
	Mode          string           `json:"mode"`
	StartedAt     time.Time        `json:"started_at"`
	UptimeSeconds float64          `json:"uptime_seconds"`
	Version       string           `json:"version"`
	Commit        string           `json:"commit"`
	ConfigHash    string           `json:"config_hash"`
	Listeners     []ListenerStatus `json:"listeners"`
	Client        *ClientStatus    `json:"client,omitempty"`
	Server        *ServerStatus    `json:"server,omitempty"`
	MetricsAddr   string           `json:"metrics_addr,omitempty"`
	LastFatal     string           `json:"last_fatal_error,omitempty"`
}

func newRuntimeListener(protocol, configured, actual string, closeFn func() error) *runtimeListener {
	return &runtimeListener{
		Protocol:   protocol,
		Configured: configured,
		Actual:     actual,
		State:      "started",
		closeFn:    closeFn,
		done:       make(chan struct{}),
	}
}

func (l *runtimeListener) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	l.State = "stopping"
	l.mu.Unlock()
	if l.closeFn == nil {
		return nil
	}
	return l.closeFn()
}

func (l *runtimeListener) finish(err error) {
	l.once.Do(func() {
		l.mu.Lock()
		if err != nil {
			l.LastError = err.Error()
		}
		l.State = "stopped"
		l.mu.Unlock()
		close(l.done)
	})
}

func (l *runtimeListener) snapshot() ListenerStatus {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return ListenerStatus{
		Protocol:   l.Protocol,
		Configured: redactConfigValue(l.Configured),
		Actual:     redactConfigValue(l.Actual),
		State:      l.State,
		LastError:  redactConfigValue(l.LastError),
	}
}

func (e *Engine) status() Status {
	e.mu.Lock()
	listeners := append([]*runtimeListener(nil), e.listeners...)
	startedAt := e.startedAt
	fatalErr := e.fatalErr
	e.mu.Unlock()

	mode := "client"
	if e.config.startup != nil && e.config.startup.IsServer {
		mode = "server"
	}
	status := Status{
		Mode:        mode,
		StartedAt:   startedAt,
		Version:     e.options.Build.Version,
		Commit:      e.options.Build.Commit,
		ConfigHash:  e.config.ConfigHash,
		MetricsAddr: e.config.values.MetricsAddr,
	}
	if !startedAt.IsZero() {
		status.UptimeSeconds = time.Since(startedAt).Seconds()
	}
	if fatalErr != nil {
		status.LastFatal = redactConfigValue(fatalErr.Error())
	}
	for _, listener := range listeners {
		status.Listeners = append(status.Listeners, listener.snapshot())
	}
	if mode == "server" {
		status.Server = &ServerStatus{
			Sessions:      countServerSessions(),
			Channels:      countServerChannels(),
			ActiveStreams: countServerActiveStreams(),
			TargetPolicy:  summarizeTargetPolicy(e.config.startup.TargetPolicy),
		}
	} else {
		status.Client = &ClientStatus{
			Forward:    redactConfigValue(e.config.values.ForwardAddr),
			Channels:   snapshotClientChannels(echPool),
			Fallback:   e.config.startup.Client.Fallback,
			ECHEnabled: e.config.startup.Client.ForwardScheme == "wss" && !e.config.startup.Client.Fallback,
			FrontProxy: e.config.values.WebSocketFrontProxy.Enabled,
		}
		for port := range e.config.startup.Client.UDPBlockPorts {
			status.Client.UDPBlockList = append(status.Client.UDPBlockList, port)
		}
	}
	return status
}

func summarizeTargetPolicy(policy *TargetPolicy) TargetPolicySummary {
	if policy == nil {
		return TargetPolicySummary{}
	}
	return TargetPolicySummary{
		AllowCIDRs: len(policy.Allow),
		DenyCIDRs:  len(policy.Deny),
		AllowHosts: len(policy.AllowHosts),
		DenyHosts:  len(policy.DenyHosts),
	}
}

func snapshotClientChannels(pool *ECHPool) []ClientChannelStatus {
	if pool == nil {
		return nil
	}
	pool.wsConnsMu.RLock()
	defer pool.wsConnsMu.RUnlock()
	out := make([]ClientChannelStatus, 0, len(pool.channelRTT))
	for i := range pool.channelRTT {
		up := i < len(pool.smuxConns) && pool.smuxConns[i] != nil && !pool.smuxConns[i].IsClosed()
		var caps uint64
		if i < len(pool.channelCaps) {
			caps = pool.channelCaps[i]
		}
		out = append(out, ClientChannelStatus{
			Channel:      i + 1,
			Up:           up,
			RTTSeconds:   float64(atomic.LoadInt64(&pool.channelRTT[i])) / float64(time.Second),
			Capabilities: caps,
		})
	}
	return out
}

func redactConfigValue(value string) string {
	if value == "" {
		return value
	}
	parts := strings.Split(value, ",")
	for i, part := range parts {
		parts[i] = redactURLUserInfo(strings.TrimSpace(part))
	}
	return strings.Join(parts, ",")
}

func redactURLUserInfo(value string) string {
	u, err := url.Parse(value)
	if err != nil || u == nil || u.User == nil {
		return value
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		u.User = url.UserPassword("redacted", "redacted")
	} else {
		u.User = url.User("redacted")
	}
	return u.String()
}
