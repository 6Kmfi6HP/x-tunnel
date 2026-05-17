# Windows GUI 客户端方案

日期：2026-05-17

这份文档把 `docs/core-gui-refactor.md` 里的 core/sidecar 方向，落成一个 Windows 桌面客户端方案。目标不是 MVP，而是一个能长期日常使用、可恢复、可升级、可诊断，并且以后能扩展到 TUN 模式的完整客户端。

## 结论

推荐形态：

```text
x-tunnel-client.exe        Windows GUI、托盘、profile 管理、sidecar supervisor
x-tunnel.exe               现有 Go core，作为 sidecar 进程运行
x-tunnel-helper.exe        可选高权限 helper/service，负责 TUN、路由、DNS、防火墙
```

推荐技术栈：

```text
C# / .NET 8 或 .NET 9
Avalonia UI
MVVM，优先 ReactiveUI 或 CommunityToolkit.Mvvm
SQLite 保存本地状态
DPAPI 保存 profile secret
签名安装器 + portable zip
```

第一版完整客户端不建议把 Go core 嵌入 GUI 进程。当前 `x-tunnel` 已经有适合 GUI 使用的 sidecar 合同：

```bat
x-tunnel.exe ^
  -config <runtime-profile.json> ^
  -control 127.0.0.1:0 ^
  -ready-file <runtime-dir>\ready.json ^
  -control-token-file <runtime-dir>\token
```

GUI 只依赖 ready file 和 loopback control API，不解析 stdout。

## 当前 Core 适配度

已经具备：

- `internal/app/engine.go` 已有 `NewEngine`、`Start`、`Close`、`Wait`、`Status`。
- 已有 sidecar flags：`-control`、`-ready-file`、`-control-token-file`。
- 已有 control API：`/v1/version`、`/v1/health`、`/v1/status`、`/v1/logs`、`/v1/logs/stream`、`/v1/metrics`、`/v1/stats`、`/v1/config/check`、`/v1/config/format`、`/v1/runtime/stop`。
- `/v1/version` 已暴露 `control_api_version` 和 capabilities。
- `/v1/stats` 已提供 dashboard 友好的 JSON counters、traffic、listeners 和 client/server 状态。
- control API 错误响应已有稳定 `error.code/message/field` shape。
- 已有离线 `-check-config` 和 `-format-config` 命令。
- control API 只允许 loopback，并且使用 bearer token。
- config check/format 接收 JSON payload，不读取任意本地路径。
- status/logs 已经做了 URL userinfo 脱敏。
- profile 切换天然适合用“停止旧 sidecar -> 启动新 sidecar”，不需要第一版热重载。

完整 Windows 客户端还缺：

- Windows helper/service，用于 TUN、路由、DNS、kill switch。
- 部分运行时状态仍依赖 package globals，所以一个 sidecar 进程里先只运行一个 Engine。

## 开源项目参考

以下结果在 2026-05-17 用 `gh` 查询过。

| 项目 | 技术栈 | 当前状态 | 参考点 |
| --- | --- | --- | --- |
| [2dust/v2rayN](https://github.com/2dust/v2rayN) | C# / Avalonia | 活跃，最新 release `7.21.3`，发布于 2026-05-10 | Windows 系统代理、托盘、profile 管理、多 core 监督 |
| [clash-verge-rev/clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev) | Tauri / TypeScript / Rust | 活跃，最新 release `v2.4.7`，发布于 2026-03-21 | 现代 sidecar 管理、TUN 设置、更新器、跨平台打包 |
| [chen08209/FlClash](https://github.com/chen08209/FlClash) | Flutter / Dart | 活跃，最新 release `v0.8.92`，发布于 2026-02-02 | 跨平台状态模型、托盘、TUN UX |
| [hiddify/hiddify-app](https://github.com/hiddify/hiddify-app) | Flutter / Dart | 活跃，最新 release `v4.1.1`，发布于 2026-03-05 | 多协议 profile UX、诊断、订阅工作流 |

旧项目例如 Qv2ray、nekoray、原 clash-verge 可以看历史设计，但不适合作为 2026 年新 Windows 客户端的主要参照。

注意 license：v2rayN、Clash Verge Rev、FlClash 是 GPL 系项目。除非 x-tunnel GUI 明确采用兼容 license，否则只能参考架构和产品边界，不应复制实现代码。

## 技术栈选择

### 推荐：C# + Avalonia

理由：

- Windows 集成直接：注册表、系统代理、named mutex、DPAPI、Windows Service、Task Scheduler、named pipe、安装器都顺手。
- 不引入浏览器运行时和 WebView2 行为。
- 适合托盘优先的桌面工具。
- 未来仍保留 Linux/macOS 可能性，但第一年可以 Windows-first。
- v2rayN 当前采用 Avalonia，说明这类代理客户端场景可行。

### 备选：Tauri 2 + React + Rust

适合团队前端/Rust 能力明显强于 C# 的情况。

优点：

- UI 开发现代。
- Tauri 插件和 updater 生态较完整。
- Clash Verge Rev 是强参考。

代价：

- 项目会同时包含 Go core、Rust host、Node/frontend 工具链。
- Windows 系统集成可做，但不如 C# 直接。
- 长期维护面更大。

### 备选：Flutter

适合明确要做多平台甚至移动端的情况。

优点：

- 跨平台 UI 一致。
- Hiddify 和 FlClash 证明代理客户端可行。

代价：

- Windows 桌面深度集成经常需要 native plugin。
- helper/service、系统代理、TUN 这类 Windows 专项工作会更绕。

### 不建议第一版用 WinUI 3

WinUI 3 做纯 Windows 原生应用没问题，但会锁死 Windows 路线，打包和运行时也有自己的复杂度。除非明确只做 Windows 且 Fluent 原生体验优先，否则不如 Avalonia 稳。

## 产品范围

这个应用应该是 client-first。core 虽然支持 server mode，但 Windows 桌面客户端的主要工作流应假设用户连接到已有 x-tunnel server。

第一版完整 release 应包含：

- 单实例桌面应用。
- 托盘优先：连接、断开、切换 profile、打开主页、打开日志、退出。
- Profile 管理：新建、编辑、复制、删除、导入、导出。
- 结构化表单编辑 + JSON 高级编辑。
- 通过 core 做配置校验和格式化。
- 启动、停止、监控 sidecar。
- System Proxy 模式。
- PAC 模式。
- 状态、日志、metrics、诊断。
- 开机启动和可选自动连接。
- GUI 与 bundled core 的更新流程。
- 崩溃恢复和系统代理恢复。

后续高级 release：

- TUN 模式。
- Kill switch。
- PAC 之外的 split routing。
- 远程订阅和分享链接。
- Deep link 导入。
- 签名 profile/subscription。
- named pipe control channel。

## 进程架构

### GUI 进程

职责：

- 管理 app settings、profiles、subscriptions 和用户交互。
- 从选中 profile 生成 runtime JSON config。
- 启动 `x-tunnel.exe`。
- 等待 ready file。
- 读取 token file 并调用 control API。
- 轮询或订阅 status/logs/stats。
- 设置和恢复 Windows 系统代理。
- 需要特权操作时协调 helper/service。

不做：

- 不在 C# 里实现 tunnel 协议。
- 不复制 Go core 的配置校验规则。
- 不持有长期 tunnel 网络状态。
- 不把 stdout 当作 GUI 协议。

### Core sidecar

职责：

- 每个进程运行一个 x-tunnel runtime。
- 拥有本地 SOCKS5/HTTP/TCP listeners。
- 拥有 WebSocket/WSS、smux、ECH/fallback、mTLS、front proxy、target policy、metrics。
- 通过 loopback control API 暴露 status/logs/config check/stop。

规则：

- GUI 同一时间只管理一个 active sidecar。
- 切换 profile 走 restart，不走 hot reload。
- 等 core 有字段级 reload 测试后再讨论热重载。

### Helper/service

职责：

- 安装和管理 Wintun 或其他 TUN adapter。
- 修改路由和 DNS。
- 配置 kill switch 防火墙规则。
- 只在用户明确要求时处理 WinHTTP proxy 这类管理员操作。

规则：

- helper API 必须窄。
- helper 不应接触 profile secret，除非无法避免。
- 正常 system proxy 模式不需要提权。
- 安装 helper/service 必须有清晰提示和卸载清理。

## Runtime 状态机

GUI supervisor 应显式建模状态：

```text
Stopped
Starting
Running
Degraded
Stopping
Faulted
Recovering
```

转换：

- `Stopped -> Starting`：用户连接或 auto-connect。
- `Starting -> Running`：ready file 存在、token 可用、`/v1/health` OK、预期 listeners started。
- `Starting -> Faulted`：core 退出、ready timeout、配置错误、端口占用、token 读取失败。
- `Running -> Degraded`：sidecar 仍可响应，但 channel down 或 status 里有 fatal。
- `Running -> Stopping`：用户断开、切 profile、app 退出。
- `Stopping -> Stopped`：`/v1/runtime/stop` 成功且进程退出。
- `Running -> Faulted`：sidecar 异常退出。
- `Faulted -> Recovering`：满足自动重启策略。

崩溃恢复：

- GUI 启动时读取上次 runtime marker。
- 如果上次 GUI 退出时系统代理处于启用状态，且当前代理仍指向 x-tunnel 端口但 sidecar 不健康，则自动恢复或提示恢复。
- 如果存在旧 sidecar PID，必须校验 PID 和 exe 路径，不要只按进程名杀。
- 不要杀用户手动启动的其他 `x-tunnel.exe`。

## 文件布局

推荐 per-user 路径：

```text
%LOCALAPPDATA%\x-tunnel-client\
  app.db
  settings.json
  profiles\
  subscriptions\
  runtime\
    active.json
    ready.json
    token
    supervisor.lock
  logs\
    gui.log
    core-YYYYMMDD.log
  core\
    x-tunnel.exe
    version.json
  updates\

%APPDATA%\x-tunnel-client\
  exportable user preferences if needed
```

规则：

- runtime 文件是临时文件，clean shutdown 后可删除。
- profile metadata 存 SQLite。
- 导出 profile 默认不包含明文 secret，除非用户明确选择 encrypted export。
- token、ready、runtime config 所在目录设置 current-user ACL。
- core exe 更新时不要原地替换正在运行的文件，应 staging 后切换。

## 数据模型

GUI metadata 和 core runtime JSON 分开。

### Profile

示例：

```json
{
  "id": "uuid",
  "name": "Home",
  "kind": "client",
  "enabled": true,
  "source": "local",
  "created_at": "2026-05-17T00:00:00Z",
  "updated_at": "2026-05-17T00:00:00Z",
  "core_config": {
    "listen": "socks5://127.0.0.1:10808,http://127.0.0.1:10809",
    "forward": "wss://example.com/tunnel",
    "token_ref": "secret:profile-token",
    "connections": 3,
    "fallback": false
  },
  "ui": {
    "color": "blue",
    "sort_order": 100
  }
}
```

运行时写给 `x-tunnel.exe` 的 JSON 必须把 `token_ref` 替换成解密后的 `token`，并且只写入 runtime 目录。

### App settings

与 profile 分开保存：

- 语言。
- 主题。
- 开机启动。
- 自动连接 profile ID。
- 默认代理模式：off、system、PAC、TUN。
- 默认本地端口。
- 更新 channel。
- 日志保留策略。
- 诊断隐私设置。

### Subscription

如果支持订阅，保存：

- URL。
- 显示名。
- ETag / Last-Modified。
- 更新间隔。
- 最近更新结果。
- 导入出的 profile IDs。
- 信任策略：普通导入、签名导入、每次确认。

不要静默用远程订阅覆盖正在连接的 profile。应先 fetch、validate、diff，再由用户或策略决定 apply。

## Profile 格式策略

第一版继续使用现有 x-tunnel JSON schema 作为 runtime profile 格式，不发明第二套完整 tunnel schema。

GUI 可以包一层 metadata 和 secret reference，但生成给 core 的 runtime JSON 应接近现有配置文件：

```json
{
  "listen": "socks5://127.0.0.1:10808,http://127.0.0.1:10809",
  "forward": "wss://example.com/tunnel",
  "token": "runtime-secret",
  "connections": 3,
  "fallback": false,
  "metrics": "127.0.0.1:0"
}
```

规则：

- 表单编辑器只写已知字段。
- 高级 JSON 编辑器允许直接编辑 core config。
- 保存前调用 config format/check。
- 连接前生成 runtime JSON 后再次校验。
- 当前 core 使用 `DisallowUnknownFields`，所以 GUI 也应拒绝未知字段。
- JSON format 不承诺保留注释。

## 系统代理模式

System proxy 应作为第一个完整流量入口模式。

模式：

```text
Off
System Proxy
PAC
TUN
```

System Proxy 行为：

- 修改当前用户 WinINET proxy 设置。
- HTTP/HTTPS 指向本地 HTTP listener，例如 `127.0.0.1:10809`。
- 需要时 SOCKS 指向本地 SOCKS5 listener，例如 `127.0.0.1:10808`。
- 断开时恢复之前完整设置。
- 如果运行期间用户或其他软件改了代理设置，不要盲目覆盖，应提示或保留用户变更。

默认不要修改 WinHTTP proxy。WinHTTP 影响服务和系统组件，通常带管理员预期，不适合作为普通桌面代理默认行为。可以以后作为高级选项。

PAC 模式：

- GUI 或轻量组件提供本地 PAC server。
- 设置 `AutoConfigURL` 到 `http://127.0.0.1:<pac-port>/proxy.pac`。
- 支持 LAN bypass、domain bypass、自定义规则片段、direct/proxy 模式。
- PAC 文件应可检查、可复制、可诊断。

必须恢复系统代理的场景：

- 用户断开。
- 正常退出 app。
- sidecar 崩溃。
- GUI 崩溃后下次启动发现代理仍指向 x-tunnel。
- 卸载客户端。

## TUN 模式

TUN 是单独阶段，不只是 UI 上多一个开关。

原因：

- 需要管理员权限或 Windows service。
- 会改路由和 DNS。
- 可能涉及 Wintun driver 生命周期。
- 清理失败会影响网络。
- 需要 kill switch 策略。

推荐路径：

1. 第一版完整 release 不带 TUN，但 UI 和数据模型预留。
2. 增加 `x-tunnel-helper.exe` Windows service，负责 adapter、route、DNS、firewall。
3. 初期用成熟 tun2socks 层把 TUN 流量转给现有本地 SOCKS5/HTTP listener。
4. 长期考虑在 Go core 增加原生 `tun://` listener，让 helper 只负责 OS 特权操作。

TUN UX 应包含：

- 明确标注需要管理员权限。
- 路由模式：global 或 split。
- DNS 模式：system DNS、remote DNS、自定义 DNS。
- LAN bypass。
- Kill switch。
- Adapter repair。
- Route/DNS restore。
- 诊断用 last known route snapshot。

## 安全模型

主要风险：

- 本地低权限进程尝试控制 sidecar。
- 导入的 profile 可能包含 secret 或恶意本地端口。
- 日志和诊断包可能泄露 token、代理密码、header、private key path。
- update 如果没有签名或校验，可能被篡改。

必须做：

- control API 保持 loopback-only。
- bearer token 放 current-user-only runtime file。
- GUI 不把 control token 放 URL query。
- profile secret 用 DPAPI。
- 带明文 secret 的 runtime JSON 只在连接时写入，clean shutdown 后删除。
- 日志展示和导出都经过脱敏。
- 导入 profile 保存前和连接前都校验。
- 自动更新使用签名 manifest 或可信 checksum。
- 面向用户分发前，安装器和二进制应 code signing。

后续增强：

- current-user ACL 的 named pipe control channel。
- 每次启动生成新 control token。
- 可选 signed profile/subscription。
- helper/service 使用最小命令集。

## GUI 信息架构

推荐顶层：

```text
Overview
Profiles
Logs
Diagnostics
Settings
```

Overview：

- 连接开关。
- 当前 profile。
- core 状态。
- 本地代理地址。
- channel 健康和 RTT。
- 上传/下载计数。
- 最近错误。
- 快捷操作：restart core、复制代理地址、打开诊断。

Profiles：

- profile 表格：状态、endpoint、模式、来源、最近更新、最近校验。
- 常用字段向导。
- 高级 JSON 编辑器。
- 从文件、剪贴板、QR、deep link 导入。
- 导出选中 profile。
- 测试配置、测试连接。

Logs：

- GUI/core 合并日志。
- component 和 level 过滤。
- follow mode。
- 复制选中行。
- 导出脱敏日志包。

Diagnostics：

- core 版本和 GUI 版本。
- control API health。
- 端口占用检查。
- 系统代理状态。
- DNS/ECH 检查。
- server reachability 检查。
- channel 状态。
- 最近 crash。
- 生成脱敏诊断包。

Settings：

- 开机启动和自动连接。
- 默认代理模式。
- 本地端口。
- 更新 channel。
- 语言/主题。
- 日志保留。
- helper/TUN 高级设置。

设计方向：

- 这是运维型桌面工具，不是 landing page。
- 第一屏要密集、可扫描、能直接操作。
- 关键状态不要藏在装饰 UI 里。
- 危险操作必须有明确状态和可恢复路径。

## Sidecar 监督细节

启动流程：

1. 从 profile 生成 runtime config。
2. 调用 config check/format，或者未来的 offline config check。
3. 尽量提前检查本地端口占用。
4. 删除 stale ready/token files。
5. 启动 sidecar，并把 stdout/stderr 重定向到 core log file。
6. 等 ready file，建议 timeout 10 秒左右。
7. 读取 token file。
8. 调 `/v1/health`。
9. 调 `/v1/status` 并检查预期 listeners。
10. 如用户开启，启用 system proxy/PAC。
11. 进入 monitor loop。

停止流程：

1. 先禁用 system proxy/PAC/TUN，或标记 cleanup pending。
2. 调 `/v1/runtime/stop`。
3. 等进程退出，timeout 为 core shutdown timeout 加余量。
4. 只在 PID 和 exe path 都匹配时 kill tracked sidecar。
5. 删除 runtime token 和 ready file。
6. 写 clean shutdown marker。

Monitor loop：

- Overview 可见时每 1-2 秒 poll `/v1/status`。
- 最小化到托盘时可降到每 5 秒。
- 支持 SSE 时用 `/v1/logs/stream` 跟随日志；不可用时降级轮询 `/v1/logs?limit=N`。
- 独立监听 sidecar process exit，不只依赖 HTTP health。
- UI 根据状态机更新，不直接散落 boolean。

## 已补充的 Core API

当前 API 已经补齐第一版 GUI 的核心 sidecar 合同。

### Version/capability discovery

`/v1/version` 返回：

```json
{
  "version": "0.4.1",
  "commit": "abc123",
  "build": "2026-05-17T00:00:00Z",
  "control_api_version": 1,
  "capabilities": [
    "status",
    "logs",
    "metrics",
    "config_check",
    "config_format",
    "runtime_stop"
  ]
}
```

### JSON stats endpoint

```text
GET /v1/stats
```

返回适合 UI 图表的 JSON：

- 上传/下载 bytes。
- active streams。
- total streams。
- per-listener connection counts。
- per-channel RTT、up/down、capabilities。
- reconnect count。
- target/source/auth rejection counts。

### Events/log stream

已新增：

```text
GET /v1/logs/stream
```

SSE 足够，不需要第一版上 WebSocket。

### 离线 config check

```bat
x-tunnel.exe -check-config <path>
x-tunnel.exe -format-config <path>
```

这样 GUI 在 sidecar 未启动时也能校验 profile。

### 结构化错误

control API 和 sidecar exit 应尽量提供稳定机器可读错误：

```json
{
  "ok": false,
  "error": {
    "code": "listen.bind_failed",
    "message": "listen tcp 127.0.0.1:10809: bind: address already in use",
    "field": "listen"
  }
}
```

GUI 不应解析中文或英文错误文本来判断错误类型。

## Windows 集成细节

### 单实例

- 使用 named mutex。
- 第二次启动应激活已有窗口，并可传递 import/deep-link payload。
- 单实例 IPC 只允许当前用户。

### 托盘

托盘菜单：

- Connect / Disconnect。
- Active profile submenu。
- Proxy mode submenu。
- Open dashboard。
- Open logs。
- Diagnostics。
- Quit。

托盘状态：

- Disconnected。
- Connecting。
- Connected。
- Degraded。
- Error。

### 开机启动

默认使用 per-user startup。

选项：

- 登录时启动。
- 启动后最小化。
- 自动连接上次 profile。
- 登录后延迟自动连接，例如 5-15 秒。

普通 auto-start 不应要求管理员权限。

### Deep links

可选但有价值：

```text
xtunnel://import?url=...
xtunnel://profile/<encoded>
```

deep link 导入必须先显示确认页，不能直接保存或连接。

### 通知

只在必要时通知：

- 已连接。
- 意外断开。
- 系统代理已恢复。
- 有可用更新。
- 订阅更新失败。
- TUN/helper 需要修复。

避免每次 reconnect 都弹通知。

## 打包和更新

推荐分发：

- 普通用户使用签名安装器。
- 高级用户提供 portable zip。
- bundled `x-tunnel.exe` 与 GUI release 匹配。
- GUI 和 core 都有 checksum。

安装器职责：

- 安装 GUI 和 bundled core。
- 创建 Start Menu shortcut。
- 可选注册 `xtunnel://` protocol。
- 注册卸载清理。
- 不默认安装 helper/service，除非用户启用 TUN 或高级功能。

更新器：

- GUI 和 bundled core 一起更新。
- 校验下载文件 checksum/signature。
- 不原地替换正在运行的 core exe，应下载到 staging，下次重启切换。
- 保留上一个 core 用于 rollback。
- 如果 GUI 需要更高 control API version，要显示兼容性错误。

Channel：

- Stable。
- Beta/preview。
- 禁用自动更新。

## 诊断和支持

诊断包应包含：

- GUI version。
- Core version。
- OS version 和 architecture。
- 安装模式。
- 不含 secret 的 active profile metadata。
- 脱敏 runtime config。
- 当前 `/v1/status`。
- 最近 `/v1/logs`。
- `/v1/metrics` 或 JSON stats。
- 当前系统代理设置和保存的 previous settings。
- 端口检查结果。
- 最近 crash report。

脱敏规则：

- runtime token。
- control token。
- 代理密码。
- mTLS private key path，除非用户选择低隐私级别。
- `websocket_front_proxy.headers` 的 header values。
- 带 secret 的 subscription URL。

诊断动作：

- 检查本地端口占用。
- 测试 core config。
- 测试 server TCP 连接。
- 测试 WebSocket handshake。
- 测试 ECH DNS lookup。
- 通过本地 proxy 访问一个已知 HTTP target。
- 修复系统代理。
- 修复 TUN adapter。

## 测试策略

### GUI unit tests

- Profile validation wrapper。
- Runtime config generation。
- Secret reference replacement。
- Redaction。
- Supervisor state machine。
- 通过抽象层测试系统代理 diff/restore。
- Update manifest parsing。
- Subscription diffing。

### GUI integration tests

- fake core HTTP server 覆盖 control API 成功/失败路径。
- real `x-tunnel.exe` 覆盖 sidecar smoke。
- ready file timeout。
- token mismatch。
- port conflict。
- config error。
- runtime stop。
- 模拟 core crash 后系统代理恢复。

### Windows manual matrix

- Windows 10 x64。
- Windows 11 x64。
- Windows 11 ARM64，如果发布 ARM64。
- 标准用户安装。
- Portable zip。
- 连接前已有系统代理设置。
- 已有 VPN 或企业代理。
- IPv4-only 和 IPv6-enabled 网络。
- 睡眠/唤醒。
- 连接中网络变化。
- 如有必要，测试 fast user switching。

### Core contract tests

保留或补充：

- control API loopback restriction。
- token auth。
- ready file timing。
- config check/format。
- status redaction。
- logs redaction。
- start/stop 释放端口。
- Windows path handling。

## 路线图

### Phase 0：Core 合同补强

目标：避免 GUI 依赖模糊行为。

- [x] 增加 control API version/capabilities。
- [x] 增加稳定 JSON error shape。
- [x] 增加 offline config check/format。
- [x] 增加 JSON stats endpoint，支撑 dashboard。
- [x] 增加 SSE log stream，支撑更顺滑日志面板。
- [ ] 明确 Windows release artifact 命名和 bundled core 路径。

验收：

- GUI 不启动 tunnel 也能判断 core 是否兼容。
- GUI 不解析自由文本日志来判断正常状态。

### Phase 1：Windows supervisor shell

目标：GUI 能可靠连接/断开。

- Avalonia app skeleton。
- Single instance。
- Profile storage。
- Runtime config generation。
- Sidecar start/stop。
- Ready/token handling。
- Status/log view。
- Basic settings。

验收：

- 用户能创建 profile、连接、看状态、断开。
- sidecar crash 后 UI 进入 faulted state。
- 除非用户明确开启，否则不修改系统设置。

### Phase 2：System proxy 和 PAC

目标：可日常使用。

- System proxy mode。
- PAC mode。
- Proxy restoration。
- Auto-start 和 auto-connect。
- Tray menu 和 tray state。
- Port conflict detection。

验收：

- 浏览器流量能通过 system proxy。
- 正常退出、core crash、GUI 重启后都能恢复之前代理设置。

### Phase 3：产品完整性

目标：能管理真实 profile 和支持排障。

- Subscription support。
- Import/export。
- Advanced JSON editor。
- Diagnostics bundle。
- Update flow。
- Log retention。
- 可选 deep link import。

验收：

- 用户不手写 JSON 也能更新 profile。
- 诊断包足够定位常见故障，并且默认脱敏。

### Phase 4：Helper 和 TUN

目标：覆盖不遵守系统代理的应用。

- Helper/service install。
- Wintun adapter management。
- Route and DNS management。
- Kill switch。
- TUN diagnostics and repair。

验收：

- TUN 启停不会留下坏路由或坏 DNS。
- helper 命令集窄且可审计。

### Phase 5：Hardening 和 release

目标：安全公开发布。

- Code signing。
- Installer/uninstaller cleanup。
- Update signature/checksum verification。
- Crash reporting policy。
- 完整 Windows test matrix。
- local IPC 和 secret storage 安全审查。

验收：

- 签名安装器和 portable release 可复现。
- 升级和 rollback 路径经过测试。

## 这次补上的遗漏点

如果只看 sidecar，很容易漏掉这些：

- core 崩溃、GUI 崩溃、卸载时恢复系统代理。
- 区分 WinINET system proxy 和 WinHTTP proxy。
- 处理已有企业代理/VPN 的用户。
- 远程订阅更新前先 validate 和 diff。
- profile secret 不应明文保存在普通 JSON。
- runtime JSON 含解密 secret，需要 ACL、生命周期和清理策略。
- 杀旧 sidecar 前必须验证 PID 和 exe path。
- GUI/core 需要 control API 兼容性，不只是 app semver。
- token/runtime 目录要 current-user ACL。
- TUN 前先设计 helper/service 权限边界。
- 诊断包导出前必须有明确脱敏规则。
- 不要复制 GPL 参考客户端代码，除非 license 决策明确。
- portable mode 不能假设安装器已写 registry。
- server-mode profile 是否属于这个 Windows 客户端，需要产品上拍板。

## 需要确认的问题

这些问题不会阻塞方案推进，但实现前应确认。

| 问题 | 推荐默认值 |
| --- | --- |
| GUI 是一年内 Windows-only，还是 Windows-first 但未来跨平台？ | Windows-first，保留 Avalonia 跨平台余地。 |
| TUN 是否必须进第一版 public release？ | 不进。先发 system proxy/PAC，TUN 放 helper 阶段。 |
| 分发方式？ | GitHub Releases 提供签名安装器 + portable zip。 |
| server mode 是否放进同一个 GUI？ | 作为 advanced profile type，不作为主流程。 |
| profile/subscription 格式？ | 原生 x-tunnel JSON + GUI metadata wrapper。 |
| 是否兼容 v2rayN/Clash 订阅？ | 默认不兼容，除非产品定位要求导入既有生态。 |
| UI 语言？ | 中文优先；如果准备公开发布，从第一天保留 i18n key。 |
| GUI license？ | 实现前明确，避免误用 GPL 项目代码。 |
| 更新 channel？ | 第一版 stable only，release 流程稳定后再加 beta。 |
| Telemetry/crash reporting？ | 默认关闭；如加入，必须 opt-in。 |

## 推荐下一步

Phase 0 的核心合同已经落地。下一步应继续推进 Avalonia GUI 的可用体验：

1. 把 Overview 从原始 JSON 文本改成可扫描的运行状态、流量、监听地址和最近错误。
2. 补 Profile 表单的错误提示、连接前校验和端口占用提示。
3. 增强 Logs/Diagnostics 的过滤、导出和脱敏确认。
4. 用 fake-core integration tests 覆盖 GUI 状态机，再用 real-core smoke tests 验证 sidecar 合同。
