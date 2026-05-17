package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Logger interface {
	Printf(format string, args ...any)
}

type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

type RuntimeOptions struct {
	Logger           Logger
	Build            BuildInfo
	ControlAddr      string
	ReadyFile        string
	ControlTokenFile string
}

type Engine struct {
	config  RuntimeConfig
	options RuntimeOptions

	mu        sync.Mutex
	started   bool
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
	startedAt time.Time
	done      chan struct{}
	wg        sync.WaitGroup

	listeners []*runtimeListener
	control   *controlServer
	logs      *LogRing
	logUndo   func()
	fatalErr  error
}

func NewEngine(config RuntimeConfig, options RuntimeOptions) (*Engine, error) {
	if err := ValidateConfig(config); err != nil {
		return nil, err
	}
	if options.Build.Version == "" {
		options.Build = BuildInfo{Version: buildVersion, Commit: buildCommit, Date: buildDate}
	}
	if options.ControlAddr == "" && (options.ReadyFile != "" || options.ControlTokenFile != "") {
		return nil, fmt.Errorf("-ready-file and -control-token-file require -control")
	}
	return &Engine{
		config:  config,
		options: options,
		done:    make(chan struct{}),
		logs:    NewLogRing(512),
	}, nil
}

func (e *Engine) Start(parent context.Context) error {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return fmt.Errorf("runtime already started")
	}
	if e.closed {
		e.mu.Unlock()
		return fmt.Errorf("runtime already closed")
	}
	e.ctx, e.cancel = context.WithCancel(parent)
	e.started = true
	e.startedAt = time.Now()
	e.logUndo = installLogRing(e.logs, e.options.Logger)
	e.config.values.applyGlobals()
	e.mu.Unlock()

	if err := e.startRuntime(); err != nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), e.config.values.Global.ShutdownTimeout)
		defer cancel()
		e.abortStart(closeCtx)
		return err
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		<-e.ctx.Done()
	}()
	go e.finishWhenDone()
	return nil
}

func (e *Engine) abortStart(ctx context.Context) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	cancel := e.cancel
	listeners := append([]*runtimeListener(nil), e.listeners...)
	logUndo := e.logUndo
	e.logUndo = nil
	done := e.done
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	wait := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(wait)
	}()
	select {
	case <-wait:
	case <-ctx.Done():
	}
	if logUndo != nil {
		logUndo()
	}
	close(done)
}

func (e *Engine) startRuntime() error {
	startup := e.config.startup
	if startup == nil {
		return fmt.Errorf("runtime config is missing startup state")
	}

	if e.config.values.MetricsAddr != "" {
		metrics, err := startMetricsServer(e.ctx, e.config.values.MetricsAddr, e.config.values.Global.ShutdownTimeout)
		if err != nil {
			return fmt.Errorf("listen.bind_failed: metrics: %w", err)
		}
		e.trackListener(metrics)
	}

	if startup.IsServer {
		if e.config.values.Token == "" {
			log.Printf("[服务端] 警告: 未配置 token，v2 ChannelInit 不会校验 HMAC proof")
		}
		log.Printf("[服务端] protocol=v2-only")
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
		server, err := startWebSocketServer(e.ctx, startup.ServerListen, startup.SourceCIDRs, e.config.values.Global.ShutdownTimeout, e.reportFatal)
		if err != nil {
			return fmt.Errorf("listen.bind_failed: server: %w", err)
		}
		e.trackListener(server)
		return e.startControl()
	}

	if e.config.values.Token == "" {
		log.Printf("[客户端] 警告: 未配置 token，将发送空 token 的 v2 ChannelInit proof")
	}
	log.Printf("[客户端] protocol=v2-only")
	ipStrategy = startup.IPStrategy
	if e.config.values.IPS != "" {
		log.Printf("[客户端] IP 访问策略: %s (code: %d)", e.config.values.IPS, ipStrategy)
	}
	fallback = startup.Client.Fallback
	udpBlockPorts = startup.Client.UDPBlockPorts
	if frontProxyEnabled() {
		log.Printf("[客户端] WebSocket 前置代理已启用: type=%s server=%s", websocketFrontProxyConfig.Type, websocketFrontProxyConfig.Server)
		if startup.Client.ForwardScheme == "wss" && !fallback {
			log.Printf("[客户端] 警告: WebSocket 前置代理只代理隧道 TCP 连接，ECH DNS 查询仍会直连；如前置代理要求完整链路，请启用 fallback")
		}
	}

	if startup.Client.ForwardScheme == "wss" {
		if e.config.values.Insecure {
			if startup.Client.AutoFallback {
				log.Printf("[客户端] wss 模式且启用不校验证书（insecure）：已自动禁用 ECH（fallback）")
			} else {
				log.Printf("[客户端] wss 模式且启用不校验证书（insecure）")
			}
		}
		if !fallback {
			if err := prepareECHContext(e.ctx); err != nil {
				if errors.Is(err, context.Canceled) {
					return err
				}
				return fmt.Errorf("transport.ech_lookup_failed: %w", err)
			}
		} else {
			log.Printf("[客户端] fallback 模式已启用：禁用 ECH，使用标准 TLS 1.3")
		}
	} else {
		if e.config.values.Insecure {
			log.Printf("[客户端] ws 模式已忽略 insecure 参数")
		}
		if fallback {
			log.Printf("[客户端] ws 模式已忽略 fallback/ECH 参数")
		}
	}

	clientID = uuid.NewString()
	log.Printf("[客户端] 客户端ID: %s", clientID)

	echPool = NewECHPool(e.config.values.ForwardAddr, e.config.values.ConnectionNum, startup.TargetIPs, clientID)
	echPool.Start(e.ctx)

	for _, listenerRule := range startup.Listeners {
		var (
			listener *runtimeListener
			err      error
		)
		switch listenerRule.Scheme {
		case "tcp":
			listener, err = startTCPListener(e.ctx, listenerRule.Raw)
		case "socks5":
			listener, err = startSOCKS5Listener(e.ctx, listenerRule.Raw)
		case "http":
			listener, err = startHTTPListener(e.ctx, listenerRule.Raw)
		default:
			log.Printf("[客户端] 忽略未知协议的监听地址: %s", listenerRule.Raw)
			continue
		}
		if err != nil {
			return fmt.Errorf("listen.bind_failed: %s: %w", listenerRule.Scheme, err)
		}
		e.trackListener(listener)
	}

	return e.startControl()
}

func (e *Engine) startControl() error {
	if e.options.ControlAddr == "" {
		return nil
	}
	control, err := startControlServer(e.ctx, e, e.options.ControlAddr, e.options.ControlTokenFile)
	if err != nil {
		return fmt.Errorf("listen.bind_failed: control: %w", err)
	}
	e.control = control
	e.trackListener(control.listener)
	if e.options.ReadyFile != "" {
		if err := writeReadyFile(e.options.ReadyFile, control.readyInfo(e.options.Build)); err != nil {
			return fmt.Errorf("ready_file.write_failed: %w", err)
		}
	}
	return nil
}

func (e *Engine) trackListener(listener *runtimeListener) {
	if listener == nil {
		return
	}
	e.mu.Lock()
	e.listeners = append(e.listeners, listener)
	e.mu.Unlock()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		<-listener.done
	}()
}

func (e *Engine) reportFatal(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	if e.fatalErr == nil {
		e.fatalErr = err
	}
	cancel := e.cancel
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (e *Engine) finishWhenDone() {
	e.wg.Wait()
	e.mu.Lock()
	if e.logUndo != nil {
		e.logUndo()
		e.logUndo = nil
	}
	e.mu.Unlock()
	close(e.done)
}

func (e *Engine) Close(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		done := e.done
		e.mu.Unlock()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !e.started {
		e.closed = true
		close(e.done)
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	cancel := e.cancel
	listeners := append([]*runtimeListener(nil), e.listeners...)
	done := e.done
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) Wait() error {
	<-e.done
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fatalErr
}

func (e *Engine) Status() Status {
	return e.status()
}
