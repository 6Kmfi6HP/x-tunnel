# Core / GUI Refactor Plan

This note records how to turn x-tunnel from a CLI-first program into a reusable
runtime core that can be embedded by future GUI clients or controlled as a
background daemon.

## References

- Xray keeps the CLI in `main/run.go`: it loads config, creates a core server
  with `core.New`, then calls `Start` and `Close`. The core package exposes an
  instance lifecycle that is independent from flag parsing and signal handling.
  See <https://github.com/XTLS/Xray-core/blob/main/core/xray.go> and
  <https://github.com/XTLS/Xray-core/blob/main/main/run.go>.
- sing-box exposes `box.New(options)`, `Start`, `Close`, managers, context, and
  platform log hooks. Its CLI wraps that API, while `daemon` and `libbox` wrap
  the same core for service/mobile use. See
  <https://github.com/SagerNet/sing-box/blob/testing/box.go>,
  <https://github.com/SagerNet/sing-box/blob/testing/cmd/sing-box/cmd_run.go>,
  <https://github.com/SagerNet/sing-box/blob/testing/daemon/instance.go>, and
  <https://github.com/SagerNet/sing-box/blob/testing/experimental/libbox/config.go>.
- Clash-style clients commonly control a running core through a local external
  controller API. The older Clash code also has a central tunnel object with
  config reload and observable logs, but it relies on globals/singletons more
  than x-tunnel should. See
  <https://github.com/fossabot/clash/blob/master/tunnel/tunnel.go> and
  <https://github.com/fossabot/clash/blob/master/hub/configs.go>.
  For a newer Clash.Meta-style controller shape, see
  <https://github.com/backup-genius/Clash.Meta/blob/Alpha/hub/route/server.go>,
  <https://github.com/backup-genius/Clash.Meta/blob/Alpha/hub/route/configs.go>,
  and
  <https://github.com/backup-genius/Clash.Meta/blob/Alpha/hub/executor/executor.go>.

Notes checked with `gh`:

- Xray `core/xray.go` has a `Server`/`Instance` lifecycle and `New`,
  `Start`, `Close`. `main/run.go` is only an adapter around config loading,
  `server.Start()`, signal waiting, and `server.Close()`.
- sing-box `box.go` exposes `box.New(options)`, `Start`, and `Close`, and its
  `Options` carries `Context` plus platform log hooks. Its CLI recreates the
  instance on `SIGHUP`, `daemon/instance.go` wraps the same `box.Box`, and
  `experimental/libbox/config.go` exposes `CheckConfig` and `FormatConfig`.
- Clash/Clash.Meta exposes a local external controller with `/logs`,
  `/traffic`, `/configs`, bearer-token authentication, and config patch/reload.
  This is useful for GUI UX, but its heavy use of package globals is exactly
  what x-tunnel should avoid before becoming a reusable core.

The lesson is not to copy any one project. For x-tunnel, Xray gives the clean
instance lifecycle, sing-box gives the best sidecar/library split, and Clash
gives the GUI control surface. The risky part to avoid is a global singleton
runtime that works for one process but cannot be embedded safely.

The most useful reproducible `gh` lookups were:

```powershell
gh api -H "Accept: application/vnd.github.raw" /repos/XTLS/Xray-core/contents/core/xray.go?ref=main |
  Select-String -Pattern "type Instance|func New|Start|Close" -Context 3,8

gh api -H "Accept: application/vnd.github.raw" /repos/SagerNet/sing-box/contents/box.go?ref=testing |
  Select-String -Pattern "type Box|func New|Start|Close|Platform" -Context 3,8

gh api -H "Accept: application/vnd.github.raw" /repos/backup-genius/Clash.Meta/contents/hub/route/server.go?ref=Alpha |
  Select-String -Pattern "secret|Authorization|Bearer|Start" -Context 2,8
```

## Current Coupling

The current x-tunnel entrypoint is thin, but `internal/app` still owns too much:

- `run.go` parses CLI flags, prints version output, reads config files, installs
  OS signal handlers, starts metrics, and starts client/server runtime.
- `config.go` stores runtime state as package-level variables such as listener
  addresses, token, TLS paths, ECH options, limits, metrics address, and global
  timeout config.
- `front_proxy.go` adds a client-side WebSocket front proxy, but it is currently
  also driven by package-level config (`websocketFrontProxyConfig`) and read
  directly from the WebSocket dial path.
- Runtime components use process-level behavior such as `log.Fatalf`, package
  globals like `echPool`, `ipStrategy`, `targetPolicy`, and global counters.
- The package lives under `internal`, so a separate GUI module cannot import it.
- Startup has no readiness contract. Some listeners call `log.Fatalf`, some
  run in goroutines, and the caller cannot reliably know which listener bound
  successfully before the runtime is considered started.
- Shutdown is context-driven but not owned by a runtime object. There is no
  single `Close` path that closes listeners, channels, ECH pools, metrics,
  background DNS/ECH refresh, and control API, then reports the final error.
- Metrics and observable state are process-global. Running two engines in the
  same process would mix counters, sessions, nonce replay cache, and channel
  state.

These are fine for a single binary, but poor for GUI integration. A GUI needs to
start, stop, validate, reload, display logs, inspect status, and handle errors
without the core exiting the process.

## Questions To Close Blind Spots

These are the questions the design must answer before code is moved into
`pkg/core`:

1. Will one process ever host multiple x-tunnel engines?
   - Default answer: yes, at least for tests and future multi-profile GUIs.
     Therefore no mutable runtime state should live in package globals except
     immutable constants and reusable pools.

2. Is the first GUI expected to link Go code or launch a sidecar process?
   - Default answer: support both surfaces, but ship the sidecar/control API
     first because it works for Tauri, Electron, Flutter, C#, Python, and mobile
     wrappers without binding to Go ABI stability.

3. What does `Start` mean?
   - It must mean all configured critical listeners and control endpoints are
     bound, background workers are launched, and startup errors have been
     returned to the caller. `Start` must not hide bind errors in goroutines.

4. What does `Close` guarantee?
   - It cancels the engine context, closes listeners and active transports,
     stops metrics/control servers, waits for owned goroutines up to the
     configured shutdown timeout, and returns an aggregated error.

5. What can be reloaded without restart?
   - Policy, logging level, selected profile metadata, and some limits can be
     swapped in place. Listener addresses, transport type, TLS/mTLS material,
     ECH/fallback behavior, token, connection count, and metrics/control bind
     addresses should be treated as restart-required until each has a tested
     in-place migration path.

6. How should a GUI receive logs?
   - Through structured events plus an optional text log stream. The GUI should
     not scrape stdout. Events need levels, timestamps, component names, stable
     error codes, and redacted fields.

7. How are secrets protected?
   - Config validation and snapshot APIs must mark secret fields. Logs, status,
     metrics labels, and control API responses must never emit `token`, proxy
     passwords, mTLS private keys, or custom front-proxy header values such as
     `X-T5-Auth`.

8. How will a GUI know the core is alive?
   - The sidecar should print or write one machine-readable ready message after
     control bind succeeds, and the control API should expose health, version,
     uptime, config hash, and last error.

9. What error shape does UI code consume?
   - Use typed errors with stable codes such as `config.invalid`,
     `listen.bind_failed`, `transport.ech_lookup_failed`, `auth.failed`, and
     `runtime.closed`, plus human text for display.

10. How do we avoid locking in a bad public Go API?
    - Put the first instantiable runtime behind `internal/runtime.Engine`.
      Promote a small, documented `pkg/core` facade only after the sidecar API
      and tests prove the lifecycle shape.

## Target Shape

Use two integration surfaces:

1. A Go package API for Go-based GUIs and tests.
2. A local control API for Tauri, Electron, Flutter, mobile, or any GUI that is
   better off running the core as a sidecar process.

The Go API should look roughly like this:

```go
package core

type Engine struct {
	// private runtime state
}

type Config struct {
	Mode      Mode
	Listeners []Listener
	Server    ServerConfig
	Client    ClientConfig
	Transport TransportConfig
	Network   NetworkConfig
	TLS       TLSConfig
	Metrics   MetricsConfig
	Limits    LimitsConfig
}

type TransportConfig struct {
	WebSocketFrontProxy *WebSocketFrontProxyConfig
}

type RuntimeOptions struct {
	Logger Logger
	Events EventSink
	Clock  Clock
	Dialer DialerFactory
}

func LoadJSON(r io.Reader) (Config, error)
func Validate(config Config) error
func New(config Config, options RuntimeOptions) (*Engine, error)

func (e *Engine) Start(ctx context.Context) error
func (e *Engine) Close() error
func (e *Engine) Done() <-chan struct{}
func (e *Engine) Err() error
func (e *Engine) Snapshot() Snapshot
func (e *Engine) ReloadPlan(config Config) (ReloadPlan, error)
func (e *Engine) Reload(config Config) error
```

`Start` should return after bind/readiness succeeds, not when the engine exits.
`Done` should close after shutdown. `Err` should report the terminal runtime
error if a background component failed after startup.

The CLI should become an adapter:

```text
cmd/x-tunnel
  parse flags
  load config file
  call core.New(...)
  install OS signal handler
  print logs/errors
```

The core must not parse flags, read process signals, call `os.Exit`, or call
`log.Fatal`.

## Package Layout

Recommended end state:

```text
cmd/x-tunnel
  CLI adapter only

pkg/core
  public lifecycle API for GUI clients

internal/runtime
  client/server orchestration, listener lifecycle, ECH pool, metrics collectors

internal/config
  JSON config schema, defaults, validation, CLI-to-config merge helpers

internal/proxy
  local SOCKS5, HTTP, and TCP forward listeners

internal/transport
  WebSocket, TLS, ECH, smux pool, WebSocket front proxy dialers

internal/wire
  protocol frames, unchanged unless protocol changes

internal/netaddr
  address validation, unchanged

internal/control
  local HTTP/named-pipe control API, auth middleware, log streaming, reload

internal/events
  event model, ring buffer, redaction helpers, subscriber fanout
```

If the GUI is definitely not written in Go, `pkg/core` can initially be delayed,
but the same lifecycle must still exist internally so a daemon/control API can
use it cleanly.

## Migration Order

1. Freeze the current CLI behavior with tests before moving code.
   - Add focused tests for config parsing, bind failures, metrics output,
     server/client startup validation, and log redaction for secret fields.
   - These tests protect existing CLI users while internals are made
     instantiable.

2. Add a lifecycle boundary before moving files.
   - Introduce `Engine`, `Config`, `RuntimeOptions`, `Start`, `Close`,
     `Snapshot`, and `Validate`.
   - Keep implementation inside `internal/app` first if needed, then move once
     tests are stable.

3. Split CLI parsing from pure config loading.
   - Move flag definitions out of package `init`.
   - Add `LoadJSON`, `ApplyDefaults`, `Validate`, and `MergeCLI`.
   - `loadConfigFile` should return a config object; it should not mutate
     package variables.
   - Preserve existing JSON aliases, but mark the canonical field names in docs.

4. Replace global config with runtime-owned fields.
   - Move values such as token, fallback, IP strategy, timeout config, SOCKS5
     upstream, target policy, WebSocket front proxy config, and listener list
     into `Config` / `Engine`.
   - Keep process-wide counters only if they are truly process-wide; otherwise
     make them engine metrics.
   - Move `serverSessions`, `serverNonceCache`, `echPool`, channel RTT/caps,
     and UDP association counters under the engine.

5. Make all listener/server start functions return errors.
   - Replace `log.Fatalf` in server, SOCKS5, HTTP, and TCP listener startup with
     returned errors.
   - `Start` should fail if a configured listener cannot bind.
   - Use explicit listener objects with `Start`, `Close`, `Addr`, and `Snapshot`.

6. Separate logs and events from the standard logger.
   - Define a small logger/event interface.
   - CLI can adapt it to `log.Printf`.
   - GUI can subscribe and render logs without scraping stdout.
   - Sensitive front-proxy headers such as `X-T5-Auth` must never be emitted in
     logs or GUI events.

7. Add config validation and formatting APIs.
   - Mirror sing-box style: `CheckConfig`, `FormatConfig`, and `LoadJSON`.
   - GUI can validate profiles before applying them.

8. Add a control API for non-Go GUIs.
   - Prefer a local-only HTTP API on loopback for portability.
   - Prefer Unix domain sockets / Windows named pipes when the GUI framework can
     use them.
   - Guard every mutating endpoint with a random token.
   - Expose status, logs, metrics, config check, reload, stop, and version.
   - Do not expose it remotely by default.

9. Add sidecar mode.
   - Add `x-tunnel daemon --config <path> --control 127.0.0.1:0`.
   - Emit a single ready JSON line to stdout or a `--ready-file` after the
     control API is listening.
   - Keep normal CLI mode unchanged for existing users.

10. Only then split packages.
   - Moving code before lifecycle cleanup will mostly move globals around.
   - First make the runtime instantiable; package movement becomes mechanical.

11. Promote a public Go package.
   - Export only stable lifecycle/config/status types.
   - Do not export `smux`, `websocket`, listener internals, or mutable maps.
   - Add examples that start an engine, subscribe to events, validate config,
     and close cleanly.

## GUI Control API Draft

Minimum endpoints for a sidecar core:

```text
GET  /v1/version
GET  /v1/health
GET  /v1/status
GET  /v1/metrics
GET  /v1/events/stream
GET  /v1/logs/stream
POST /v1/config/check
POST /v1/config/format
POST /v1/config/reload-plan
POST /v1/config/reload
POST /v1/runtime/stop
```

Status should include:

- mode: client or server
- local listeners and actual bound addresses
- tunnel channel count and per-channel RTT
- WebSocket front proxy enabled/type/server, without custom header values
- active streams and UDP associations
- last error per listener/channel
- uptime and version metadata
- config hash and whether the running config differs from the pending profile

Control API security rules:

- Bind to `127.0.0.1` by default. Remote bind requires an explicit
  `--control-allow-remote` style option.
- Generate a high-entropy token by default and pass it to the GUI through a
  protected ready file, environment variable, or parent process pipe.
- Use `Authorization: Bearer <token>` for HTTP. If browser WebSocket/EventSource
  limitations force a query token, allow it only on loopback and never log the
  URL query.
- Use constant-time token comparison.
- Restrict CORS by default. `*` is convenient for dashboards but unsafe when the
  token is available to browser code.
- Do not add an API that reads arbitrary config paths from user input unless it
  is restricted to explicit profile directories. Prefer payload-based
  validation/reload.
- Return redacted config/status by default; add an explicit local-only debug
  mode for raw diagnostics.

## Reload Strategy

Start with an honest reload model:

```text
In-place reload:
  log level
  target allow/deny policy
  source CIDR policy
  selected profile metadata
  soft numeric limits that do not resize existing pools

Restart-required reload:
  listener address or protocol changes
  token/auth material
  TLS/mTLS cert/key/CA changes
  ws vs wss changes
  fallback/ECH/DNS lookup changes
  WebSocket front proxy changes
  connection count / target IP list
  metrics/control API bind address
```

`ReloadPlan` should tell the GUI whether applying a profile will be in-place,
restart-required, or invalid. For restart-required changes, sidecar GUIs can
validate the config, stop the old engine, then start a new engine. Later,
x-tunnel can add listener handoff or per-component restarts where the tests
prove it is safe.

## Event And Snapshot Model

Events are for timelines; snapshots are for current state.

Event examples:

```text
runtime.started
runtime.stopped
listener.started
listener.failed
channel.connected
channel.disconnected
stream.opened
stream.closed
config.reload_started
config.reload_finished
security.auth_failed
```

Each event should include:

- timestamp
- level
- component
- stable event name
- engine id
- optional listener/channel/stream id
- message
- redacted fields map
- error code and error text, when applicable

Snapshots should be immutable value objects assembled on demand. They must not
return pointers to live runtime maps or slices.

## Sidecar Contract

A GUI that does not link Go code should treat x-tunnel like a supervised core:

```text
x-tunnel daemon \
  --config C:\path\profile.json \
  --control 127.0.0.1:0 \
  --ready-file C:\path\x-tunnel-ready.json
```

Ready file shape:

```json
{
  "pid": 12345,
  "version": "dev",
  "control_url": "http://127.0.0.1:43125",
  "token_file": "C:\\path\\x-tunnel-token",
  "started_at": "2026-05-17T00:00:00Z"
}
```

Sidecar rules:

- stdout/stderr remain diagnostic only. GUI automation should use the ready
  file and control API.
- Exit code `0` means clean stop. Startup config errors and bind failures get
  distinct non-zero exit codes.
- The sidecar should handle parent-process death where the platform supports it.
- On Windows, named pipe control should be considered after loopback HTTP works.

## Test And Acceptance Checklist

- `Start` returns an error on occupied ports and never calls `os.Exit` or
  `log.Fatal`.
- `Close` is idempotent and releases listeners, metrics, and control API ports.
- Two client engines can run in the same process with different listeners and do
  not share counters, sessions, logs, or config.
- Config load/validate/format functions are pure and can run without starting
  network listeners.
- CLI flags override config files exactly as they do today.
- Control API rejects missing or wrong bearer tokens.
- Log and status APIs redact token, password, private key material, and
  front-proxy header values.
- `ReloadPlan` correctly marks restart-required changes.
- Event subscribers cannot block the runtime; slow subscribers drop or backfill
  from a bounded ring buffer.
- Race tests pass around start/close/reload/event subscription.
- Existing integration tests still pass through the CLI adapter.

## Design Rules

- CLI owns flags, terminal output, exit codes, and OS signals.
- Core owns listeners, sessions, tunnel channels, metrics, and validation.
- Core returns errors; it does not terminate the process.
- Runtime state belongs to an `Engine`, not package globals.
- Logs are events; stdout/stderr is only one possible sink.
- Config input should be structured. CLI shorthand can compile into the same
  structured config used by GUI profiles.
- Client transport features such as ECH, fallback TLS, IP override, and
  WebSocket front proxy should compose below the x-tunnel v2/smux protocol layer.
- Public APIs should expose stable concepts, not implementation packages.
- GUI-facing APIs must be conservative about secrets, paths, and remote access.
- Prefer an explicit `RestartRequired` result over pretending every setting can
  be safely hot-reloaded.

This gives x-tunnel the same basic shape as Xray and sing-box, while keeping a
Clash-like control API available for GUI clients that should not link Go code
directly.
