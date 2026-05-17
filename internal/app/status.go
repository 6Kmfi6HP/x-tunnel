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

type TrafficStats struct {
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
}

type CounterStats struct {
	ServerStreams                       uint64 `json:"server_streams_total"`
	UDPAssociations                     uint64 `json:"udp_associations_total"`
	UDPAssociationsActive               uint64 `json:"udp_associations_active"`
	ClientReconnects                    uint64 `json:"client_reconnects_total"`
	ServerSourceRejections              uint64 `json:"server_source_rejections_total"`
	ServerAuthRejections                uint64 `json:"server_auth_rejections_total"`
	ServerClientSessionRejections       uint64 `json:"server_client_session_rejections_total"`
	ServerStreamRejections              uint64 `json:"server_stream_rejections_total"`
	ServerTargetRejections              uint64 `json:"server_target_rejections_total"`
	ServerUnsupportedStreams            uint64 `json:"server_unsupported_streams_total"`
	ServerProtocolNegotiations          uint64 `json:"server_protocol_negotiations_total"`
	ServerProtocolNegotiationRejections uint64 `json:"server_protocol_negotiation_rejections_total"`
	ServerProtocolNegotiationFailures   uint64 `json:"server_protocol_negotiation_failures_total"`
	ServerProtocolReplayRejections      uint64 `json:"server_protocol_replay_rejections_total"`
	ClientProtocolNegotiations          uint64 `json:"client_protocol_negotiations_total"`
	ClientProtocolNegotiationFailures   uint64 `json:"client_protocol_negotiation_failures_total"`
	ClientRTTProbeFailures              uint64 `json:"client_rtt_probe_failures_total"`
}

type Stats struct {
	Timestamp     time.Time        `json:"timestamp"`
	Mode          string           `json:"mode"`
	StartedAt     time.Time        `json:"started_at"`
	UptimeSeconds float64          `json:"uptime_seconds"`
	Traffic       TrafficStats     `json:"traffic"`
	Counters      CounterStats     `json:"counters"`
	Listeners     []ListenerStatus `json:"listeners"`
	Client        *ClientStatus    `json:"client,omitempty"`
	Server        *ServerStatus    `json:"server,omitempty"`
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

func (e *Engine) Stats() Stats {
	status := e.status()
	return Stats{
		Timestamp:     time.Now().UTC(),
		Mode:          status.Mode,
		StartedAt:     status.StartedAt,
		UptimeSeconds: status.UptimeSeconds,
		Traffic: TrafficStats{
			BytesSent:     atomic.LoadUint64(&runtimeBytesSentSeq),
			BytesReceived: atomic.LoadUint64(&runtimeBytesReceivedSeq),
		},
		Counters: CounterStats{
			ServerStreams:                       atomic.LoadUint64(&serverStreamSeq),
			UDPAssociations:                     atomic.LoadUint64(&udpAssociationSeq),
			UDPAssociationsActive:               atomic.LoadUint64(&udpAssociationActiveSeq),
			ClientReconnects:                    atomic.LoadUint64(&clientReconnectSeq),
			ServerSourceRejections:              atomic.LoadUint64(&serverSourceRejectSeq),
			ServerAuthRejections:                atomic.LoadUint64(&serverAuthRejectSeq),
			ServerClientSessionRejections:       atomic.LoadUint64(&serverClientRejectSeq),
			ServerStreamRejections:              atomic.LoadUint64(&serverStreamRejectSeq),
			ServerTargetRejections:              atomic.LoadUint64(&serverTargetRejectSeq),
			ServerUnsupportedStreams:            atomic.LoadUint64(&serverUnsupportedStreamSeq),
			ServerProtocolNegotiations:          atomic.LoadUint64(&serverProtocolOKSeq),
			ServerProtocolNegotiationRejections: atomic.LoadUint64(&serverProtocolRejectSeq),
			ServerProtocolNegotiationFailures:   atomic.LoadUint64(&serverProtocolFailureSeq),
			ServerProtocolReplayRejections:      atomic.LoadUint64(&serverProtocolReplaySeq),
			ClientProtocolNegotiations:          atomic.LoadUint64(&clientProtocolOKSeq),
			ClientProtocolNegotiationFailures:   atomic.LoadUint64(&clientProtocolFailureSeq),
			ClientRTTProbeFailures:              atomic.LoadUint64(&clientRTTProbeFailureSeq),
		},
		Listeners: status.Listeners,
		Client:    status.Client,
		Server:    status.Server,
	}
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
