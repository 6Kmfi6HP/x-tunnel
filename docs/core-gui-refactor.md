# Core / GUI Refactor Plan

这份文档记录如何把 x-tunnel 从 CLI-first 工具改造成未来 GUI 客户端可使用的内核。

结论先放前面：第一阶段不要直接做一个很大的 `pkg/core`、完整事件总线、全量热重载、跨平台 named pipe 和多实例运行时。更稳的路线是先把当前 CLI 背后的运行时收敛成一个可启动、可关闭、可检查状态的内部 `Engine`，然后让 GUI 通过 sidecar 进程和本地控制 API 使用它。等 sidecar 合同跑稳定以后，再决定是否公开 Go package API。

## 目标

- 保持现有 CLI 用法不变，`./x-tunnel -config ...` 继续可用。
- 让核心运行时不再直接拥有 flag parsing、OS signal、`os.Exit`、`log.Fatal`。
- GUI 可以启动一个 x-tunnel sidecar，读取 ready file，调用本地控制 API，展示状态和日志，并安全停止/重启。
- 配置验证必须可以在不启动网络监听器的情况下完成。
- 第一版 GUI 切换配置时优先走“验证新配置 -> 停止旧 sidecar -> 启动新 sidecar”，暂不承诺任意字段热重载。

## 暂不做

- 暂不公开稳定 `pkg/core`。当前 `docs/module-layout.md` 已明确不急着支持外部 Go imports；先把内部生命周期跑顺。
- 暂不支持一个进程里同时跑多个 x-tunnel Engine。Xray 自己也把 server lifecycle 做成实例，但注释里仍强调同一时间最多一个 server 实例运行。x-tunnel 第一阶段不需要比这些成熟项目更激进。
- 暂不做完整 hot reload / reload plan。GUI 切配置先重启 sidecar，更诚实，也更容易测试。
- 暂不做复杂事件总线。先做日志 ring buffer + 当前状态快照；以后 UI 需要时间线，再把日志事件化。
- 暂不做 Windows named pipe / Unix socket。先做 loopback HTTP；命名管道以后作为安全增强。
- 暂不把包拆成很多层。先加少量文件和接口，等边界稳定后再搬目录。

## 外部项目参考

以下结果在 2026-05-17 用 `gh` 查询过，目的是看它们的边界，而不是照搬实现。

### Xray-core

查询：

```bash
gh api -H "Accept: application/vnd.github.raw" \
  "/repos/XTLS/Xray-core/contents/core/xray.go?ref=main" |
  rg -n -C 4 "type Server|type Instance|func New|Start|Close"

gh api -H "Accept: application/vnd.github.raw" \
  "/repos/XTLS/Xray-core/contents/main/run.go?ref=main" |
  rg -n -C 5 "core.New|server.Start|server.Close|signal|startXray"
```

看到的模式：

- `core/xray.go` 暴露 `Server` / `Instance`，并提供 `New`、`Start`、`Close`。
- `main/run.go` 负责加载配置、调用 `core.New`、`server.Start()`、等待 OS signal、最后 `server.Close()`。
- CLI 是适配器，核心生命周期不依赖 flag 和 signal。

对 x-tunnel 的启发：

- 必须先有一个真实 lifecycle：`New` 创建但不启动，`Start` 启动并返回 bind/config 错误，`Close` 释放资源。
- 但不要先追求多实例。先保证一个 Engine 被 GUI 稳定托管。

### sing-box

查询：

```bash
gh api -H "Accept: application/vnd.github.raw" \
  "/repos/SagerNet/sing-box/contents/box.go?ref=testing" |
  rg -n -C 5 "type Box|type Options|func New|Start|Close|PlatformLogWriter"

gh api -H "Accept: application/vnd.github.raw" \
  "/repos/SagerNet/sing-box/contents/daemon/instance.go?ref=testing" |
  rg -n -C 5 "box.New|PlatformLogWriter|Start|Close"

gh api -H "Accept: application/vnd.github.raw" \
  "/repos/SagerNet/sing-box/contents/experimental/libbox/config.go?ref=testing" |
  rg -n -C 4 "CheckConfig|FormatConfig|parseConfig|box.New"
```

看到的模式：

- `box.New(box.Options{Context, Options, PlatformLogWriter})` 创建 core。
- CLI、daemon、libbox 都包装同一个 `box.Box`。
- `experimental/libbox/config.go` 有 `CheckConfig`、`FormatConfig`，GUI/mobile 可以先校验配置。

对 x-tunnel 的启发：

- `RuntimeOptions` 里至少要有 `context` 和日志 sink，GUI 不应该抓 stdout。
- 配置校验/格式化是 GUI 接入的刚需，而且应该比控制 API 更早做。
- sidecar 和未来 Go library 可以共用同一个内部 Engine。

### Clash / Clash.Meta

查询：

```bash
gh api -H "Accept: application/vnd.github.raw" \
  "/repos/fossabot/clash/contents/hub/server.go?ref=master" |
  rg -n -C 5 "traffic|logs|configs|ListenAndServe"

gh api -H "Accept: application/vnd.github.raw" \
  "/repos/backup-genius/Clash.Meta/contents/hub/route/server.go?ref=Alpha" |
  rg -n -C 5 "Start|Authorization|Bearer|token|logs|traffic"

gh api -H "Accept: application/vnd.github.raw" \
  "/repos/backup-genius/Clash.Meta/contents/hub/route/configs.go?ref=Alpha" |
  rg -n -C 5 "configRouter|Put|Patch|ParseWithBytes|ApplyConfig"
```

看到的模式：

- 老 Clash 暴露本地 external controller，包括 `/traffic`、`/logs`、`/configs`。
- Clash.Meta 风格加入 bearer token、`/configs` PUT/PATCH、日志/流量/代理组等 GUI 面向 API。
- 这些项目的控制面非常适合 GUI，但内部全局状态较多，不适合作为 x-tunnel 的目标架构。

对 x-tunnel 的启发：

- GUI 最好控制一个本地 core，而不是把 CLI stdout 当协议。
- 控制 API 必须从第一天就有本地绑定、token、敏感信息脱敏。
- 不要照搬 Clash 的全局 singleton。x-tunnel 当前已经有不少 globals，重构目标是减少它们，而不是把控制 API 套在 globals 外面就结束。

## 当前耦合点

现在 `cmd/x-tunnel/main.go` 很薄，只调用 `app.Main()`，这点是好的。

真正卡死 GUI 的地方在 `internal/app`：

- `internal/app/run.go` 同时做了 `flag.Parse()`、版本输出、配置文件加载、启动校验、OS signal、metrics、服务端/客户端模式分支、ECH 准备、listener goroutine 启动。
- `internal/app/config.go` 通过 package globals 保存运行参数，例如 `listenAddr`、`forwardAddr`、`token`、TLS/mTLS 文件、ECH、metrics、timeouts、`echPool`、server/client counters 等。
- `loadConfigFile` 会直接把 JSON 写回这些 package globals，配置加载不是纯函数。
- `init()` 里注册所有 flags，导致配置解析和包初始化绑在一起。
- `internal/app/server.go`、`internal/app/local_socks5.go`、`internal/app/local_http.go`、`internal/app/client.go` 的 listener 启动失败会 `log.Fatalf`，GUI 没法拿到错误对象，只会看到进程退出。
- 服务端会话、nonce cache、metrics counters、client ECH pool 都是包级状态，sidecar 单实例还能接受，但不适合作为未来公开 library API。
- 当前 metrics 已能提供部分状态，但 GUI 还需要更直接的 health/status/logs/stop 合同。

## 推荐形态

第一阶段只建立一个内部内核边界：

```text
cmd/x-tunnel
  main.go: 设置 build info，调用 internal/app 的 CLI adapter

internal/app
  cli.go: flag/config/signal/stdout/stderr/exit code 适配
  config.go: 现有 JSON schema、defaults、validate，逐步改成纯函数
  engine.go: Engine lifecycle，持有 context、cancel、wg、listeners、metrics、状态
  control.go: 本地 HTTP 控制 API，可选开启
  logring.go: stdout logger + bounded ring buffer
  status.go: GUI 需要的状态快照
  server/client/local listeners: 先少量改签名，后续再拆包

internal/wire
  继续只做协议帧，不碰 GUI/CLI

internal/netaddr
  继续做地址校验
```

先不要创建这些包：

```text
pkg/core
internal/runtime
internal/control
internal/events
internal/transport
internal/proxy
```

这些名字未来可能会出现，但第一阶段提前拆出来会让代码移动多于行为改善。

## Engine 合同

第一阶段的内部 API 可以很小：

```go
type Engine struct {
	// private fields
}

type RuntimeOptions struct {
	Logger Logger
	Build  BuildInfo
}

type Logger interface {
	Printf(format string, args ...any)
}

func LoadConfig(path string, overrides CLIOverrides) (RuntimeConfig, error)
func ValidateConfig(config RuntimeConfig) error
func CheckConfigJSON(raw []byte) error
func FormatConfigJSON(raw []byte) ([]byte, error)

func NewEngine(config RuntimeConfig, options RuntimeOptions) (*Engine, error)
func (e *Engine) Start(ctx context.Context) error
func (e *Engine) Close(ctx context.Context) error
func (e *Engine) Wait() error
func (e *Engine) Status() Status
```

语义：

- `NewEngine` 只做配置归一化、依赖准备，不监听端口。
- `Start` 必须在关键 listener 和 control API bind 成功后才返回 nil。
- `Start` 不能把 bind 错误藏在 goroutine 里。
- `Close` 可以重复调用，负责关闭 listener、metrics/control HTTP server、ECH pool、active sessions，并等待 goroutine 退出到 timeout。
- `Wait` 返回运行期 fatal error。CLI 用它阻塞，GUI sidecar 也可以用它决定退出码。
- `Status` 返回不可变快照，不暴露 live map/slice 指针。

第一版不承诺 `Reload`。原因很简单：当前 listener、TLS/mTLS、ECH、front proxy、连接池、token 都交织在 globals 和 goroutine 里，假装能热重载比直接重启更危险。

## CLI 适配器

CLI 继续负责：

- 解析 flags。
- 读取 config path。
- 合并显式 flags 和 JSON。
- 处理 `-version`。
- 安装 OS signal。
- 把日志写到终端。
- 把错误转换成 exit code。

核心不再做：

- `flag.Parse()`。
- `os.Exit()`。
- `log.Fatal` / `log.Fatalf`。
- `signal.NotifyContext`。
- 直接读写 stdout/stderr。

这样现有命令仍然长这样：

```bash
./x-tunnel -config ./client.json
```

未来 GUI sidecar 只是在原有命令上加控制参数，而不是马上引入子命令系统：

```bash
./x-tunnel \
  -config ./client.json \
  -control 127.0.0.1:0 \
  -ready-file ./x-tunnel-ready.json
```

不建议第一版做 `x-tunnel daemon ...`，因为当前项目还没有 cobra/subcommand 体系。强行引入子命令会把 CLI 迁移和 core 迁移混在一起。

## Sidecar 合同

GUI 启动 sidecar 后只依赖 ready file 和控制 API。

Ready file：

```json
{
  "pid": 12345,
  "version": "dev",
  "commit": "unknown",
  "control_url": "http://127.0.0.1:43125",
  "token_file": "/Users/me/Library/Application Support/x-tunnel/token",
  "started_at": "2026-05-17T00:00:00Z"
}
```

规则：

- `-control 127.0.0.1:0` 表示自动选择 loopback 空闲端口。
- ready file 只能在 control API 成功 bind 后写出。
- token 写入单独文件，权限尽量收紧到 owner-only。ready file 只引用 token 文件路径，不直接写 token。
- stdout/stderr 只给人看，不作为 GUI 协议。
- sidecar 收到 `/v1/runtime/stop` 或 OS signal 后优雅退出。
- 配置错误、端口占用、运行期异常使用不同 exit code，方便 GUI 展示原因。

## 最小控制 API

第一阶段实现这些：

```text
GET  /v1/version
GET  /v1/health
GET  /v1/status
GET  /v1/logs
GET  /v1/logs/stream
GET  /v1/metrics
GET  /v1/stats
POST /v1/config/check
POST /v1/config/format
POST /v1/runtime/stop
```

`/v1/version` 返回 build metadata、`control_api_version` 和 capabilities。错误响应使用稳定 JSON shape：

```json
{
  "ok": false,
  "error": {
    "code": "config.invalid",
    "message": "配置无效",
    "field": "listen"
  }
}
```

`/v1/logs/stream` 使用 SSE 输出 bounded log ring entries。`/v1/stats` 返回 UI dashboard 需要的 JSON counters、traffic、listeners 和 client/server 状态。

先不做：

```text
POST /v1/config/reload
POST /v1/config/reload-plan
GET  /v1/events/stream
```

理由：

- GUI 第一版已经可以用轮询 `status` + `logs`；SSE log stream 只作为更顺滑日志面板的可选能力。
- profile 切换可以重启 sidecar，暂不需要 reload。
- 如果一开始把 reload 做进 API，就会被迫处理 listener handoff、TLS 证书替换、ECH 刷新、连接池缩放、token 替换等高风险路径。

`/v1/status` 至少包含：

- mode: client/server。
- uptime、version、config hash。
- listeners: 配置地址、实际绑定地址、协议、状态、last error。
- client: forward URL 的脱敏版本、channel 数、RTT、capabilities、fallback/ECH 状态。
- server: sessions、channels、active streams、source/target policy 摘要。
- metrics address。
- last fatal error。

`/v1/logs` 返回最近 N 条 ring buffer 日志：

```json
{
  "entries": [
    {
      "time": "2026-05-17T00:00:00Z",
      "level": "info",
      "component": "client",
      "message": "SOCKS5 proxy started",
      "fields": {
        "addr": "127.0.0.1:11080"
      }
    }
  ]
}
```

第一版如果还没有结构化日志，也可以先把 `message` 作为主字段；关键是进入 bounded ring buffer，GUI 不再解析 stdout。

## 控制 API 安全

- 默认只允许 `127.0.0.1` / `::1`。
- 远程监听必须显式打开，例如未来的 `-control-allow-remote`，第一阶段可以先不提供。
- 所有非 health/version 请求都要求 `Authorization: Bearer <token>`。
- token 比较使用 constant-time compare。
- 不把 token 放进 URL query；如果以后要支持浏览器 WebSocket 限制，只允许 loopback query token，并且绝不记录完整 URL。
- CORS 默认关闭或只允许 GUI 指定 origin。不要默认 `*`。
- 控制 API 不接收“任意 path 并读取配置文件”。`config/check` 和 `config/format` 只接收 payload，避免 GUI/网页把 sidecar 变成本地文件读取器。
- status、logs、metrics 默认脱敏：`token`、proxy password、private key、mTLS key、front-proxy custom headers 不能出现。

## 配置策略

保持现有 JSON schema 作为第一版 GUI profile 格式，不急着发明一套全新的 nested schema。

当前 CLI 已经支持：

- `listen`
- `forward`
- `token`
- TLS/mTLS 文件
- target/source policy
- ECH/fallback/DNS
- timeouts
- metrics
- `websocket_front_proxy`

GUI 第一版可以直接编辑这些字段。代码侧要做的是把现有“加载 JSON 后写 globals”改成：

```text
raw JSON
  -> decode FileConfig
  -> apply defaults
  -> apply CLI overrides
  -> normalize aliases
  -> validate
  -> RuntimeConfig
```

兼容规则：

- 继续接受现有 hyphen/underscore alias。
- 显式 CLI flags 继续覆盖 config file。
- `CheckConfigJSON` 不启动 listener，不做网络 ECH 查询，不拨号。
- `FormatConfigJSON` 只做缩进和字段归一化；JSON 本身没有注释，因此不要承诺保留注释。
- 涉密字段在 status/logs 里统一 redacted。

## 迁移顺序

### 阶段 1：先切生命周期

目标：不改用户行为，只让运行时不再杀进程。

- 增加 `RuntimeConfig`，把 `validateStartupConfig` 的结果和运行参数集中起来。
- 把 `loadConfigFile` 改成返回配置对象，避免直接写 package globals。
- 把 `runWebSocketServer`、`runSOCKS5Listener`、`runHTTPListener`、`runTCPListener` 改成返回 error，启动成功后再进入 accept loop。
- 引入 `Engine.Start/Close/Wait/Status`。
- CLI adapter 捕获 error 并决定日志/exit code。

验收：

- 端口占用时 `Start` 返回 error，不 `log.Fatal`。
- `Close` 可重复调用并释放端口。
- 现有 CLI 集成测试仍通过。
- 本地 server/client smoke test 仍能走 SOCKS5 和 TCP forward。

### 阶段 2：加 sidecar 控制面

目标：GUI 可以可靠启动、检查、停止。

- 增加 `-control`、`-ready-file`、`-control-token-file`。
- 实现最小控制 API。
- 增加 bounded log ring。
- 写 ready file 前确保 control API 已 bind。
- `/v1/config/check` 和 `/v1/config/format` 接收 payload。

验收：

- GUI/脚本能启动 sidecar，读取 ready file，调用 `/v1/health`。
- bearer token 错误时返回 401。
- `/v1/status` 不泄露 token/password/private key/header value。
- `/v1/runtime/stop` 能优雅退出并释放监听端口。

### 阶段 3：清理 globals

目标：让内部 Engine 真正拥有状态。

- `echPool` 移到 Engine。
- server sessions、nonce cache 移到 Engine。
- metrics counters 移到 Engine 或显式 collector。
- target policy、SOCKS5 upstream、IP strategy、timeouts 从 package globals 改为 Engine fields。
- listener 对象持有自己的 `net.Listener` / `http.Server`。

验收：

- race test 覆盖 start/close/status/logs。
- metrics/status 来自同一份 Engine 状态。
- 核心代码路径不依赖 package-level mutable runtime state。

### 阶段 4：再决定公开 Go API

只有当确实要写 Go GUI 或被第三方 Go 程序 import 时，才新增 `pkg/core`。

那时公开的 API 也应该很小：

```go
package core

type Engine struct {
	// wrapper around internal/app engine
}

func CheckConfigJSON(raw []byte) error
func FormatConfigJSON(raw []byte) ([]byte, error)
func New(config Config, options Options) (*Engine, error)
func (e *Engine) Start(ctx context.Context) error
func (e *Engine) Close(ctx context.Context) error
func (e *Engine) Status() Status
func (e *Engine) Done() <-chan struct{}
```

不要公开 smux、websocket、listener 内部对象、mutable maps。公开 API 一旦发布就很难改，sidecar 合同更适合作为第一版 GUI 边界。

## 后续热重载原则

第一版没有热重载。以后如果要做，只从低风险字段开始：

可考虑 in-place：

- log level。
- source CIDR / target allow-deny policy。
- 部分软限制。
- GUI profile metadata。

继续 restart-required：

- listener 地址或协议。
- token/auth material。
- TLS/mTLS cert/key/CA。
- ws/wss 切换。
- ECH/fallback/DNS/front proxy。
- connection count / target IP list。
- metrics/control bind address。

规则：没有测试证明能安全迁移的字段，都当 restart-required。

## 接受标准

- `go test ./...` 通过。
- `go test -race ./internal/app` 至少覆盖 Engine start/close/control/status 的核心路径。
- 端口占用、配置错误、认证失败都返回结构化 error，而不是进程内部 `fatal`。
- 现有 CLI 参数和 JSON 兼容性保持。
- sidecar ready file 只在真正 ready 后写出。
- control API token、CORS、loopback 限制有测试。
- 日志和状态脱敏有测试。
- 真实本地连通性测试仍通过：server + client + SOCKS5 fetch + TCP forward。

## 为什么这个方案更适合现在

原方案方向没有错，但第一步拉得太满：`pkg/core`、`internal/runtime`、`internal/control`、`internal/events`、reload plan、named pipe、多实例语义都同时出现，会让重构看起来像架构升级，实际最难的 `log.Fatal`、globals、listener bind readiness、config pure functions 反而容易被淹没。

这版方案把顺序调回来：

1. 先让 core 能被启动和关闭。
2. 再让 GUI 能通过 sidecar 控制它。
3. 再逐步把 globals 收进 Engine。
4. 最后才公开 Go API 或做热重载。

它仍然借鉴 Xray 的 lifecycle、sing-box 的 sidecar/library 共用核心、Clash 的 GUI controller，但不会在 x-tunnel 还没脱离 CLI globals 前过早承诺一个很重的公共内核架构。
