# x-tunnel

x-tunnel is a Go tunneling tool that carries local SOCKS5, HTTP proxy, and TCP forwarding traffic over WebSocket/WSS with smux multiplexing. Server-side egress can be direct or through an upstream SOCKS5 proxy.

The local HTTP proxy listener supports `CONNECT`, ordinary `http://` absolute-form proxy requests, and origin-form requests with a valid `Host` header. Non-CONNECT absolute-form requests with other schemes, URL userinfo, malformed authorities, or mismatched `Host`/URL authorities are rejected with `400 Bad Request`.

## Build

```bash
go build -o x-tunnel ./cmd/x-tunnel
./x-tunnel -version
```

Build metadata can be injected with `-ldflags`:

```bash
go build -ldflags "\
  -X main.buildVersion=0.4.1 \
  -X main.buildCommit=$(git rev-parse --short HEAD) \
  -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o x-tunnel ./cmd/x-tunnel
```

Or use the build script:

```bash
VERSION=0.4.1 OUT=./x-tunnel ./scripts/build.sh
./x-tunnel -version
```

Create cross-platform release artifacts:

```bash
VERSION=0.4.1 ./scripts/release.sh
cat dist/SHA256SUMS
```

## Container Image

Build locally:

```bash
docker build -t x-tunnel:local .
docker run --rm x-tunnel:local -version
```

Tagged releases publish multi-architecture images to GHCR:

```bash
docker pull ghcr.io/6kmfi6hp/x-tunnel:v0.4.1
docker run --rm ghcr.io/6kmfi6hp/x-tunnel:v0.4.1 -version
```

Run a loopback-only server in a container:

```bash
docker run --rm -p 127.0.0.1:18080:18080 ghcr.io/6kmfi6hp/x-tunnel:v0.4.1 \
  -l ws://0.0.0.0:18080/tunnel \
  -token local-test-token \
  -cidr 127.0.0.1/32
```

## Release Automation

Push a version tag to publish GitHub Release assets and GHCR images:

```bash
git tag v0.4.1
git push origin v0.4.1
```

The release workflow verifies formatting, `go vet`, tests, race tests, and a
release-script smoke build before publishing. It uploads cross-platform
binaries from `dist/` to GitHub Releases and pushes `linux/amd64` plus
`linux/arm64` images to `ghcr.io/6kmfi6hp/x-tunnel`. See
[docs/release.md](docs/release.md) for tags, permissions, and rollback notes.

## Local WS Example

Server:

```bash
./x-tunnel \
  -l ws://127.0.0.1:18080/tunnel \
  -token local-test-token \
  -cidr 127.0.0.1/32
```

Client with SOCKS5 and TCP forward listeners:

```bash
./x-tunnel \
  -l socks5://127.0.0.1:11080,tcp://127.0.0.1:12000/127.0.0.1:19090 \
  -f ws://127.0.0.1:18080/tunnel \
  -token local-test-token \
  -n 1
```

Use the SOCKS5 listener:

```bash
curl --noproxy '' --proxy socks5h://127.0.0.1:11080 http://127.0.0.1:19090/
```

Use the TCP forward listener:

```bash
curl http://127.0.0.1:12000/
```

## Hardened Server Example

```bash
./x-tunnel \
  -l wss://0.0.0.0:443/tunnel \
  -cert /path/fullchain.pem \
  -key /path/privkey.pem \
  -token "$TOKEN" \
  -cidr 203.0.113.0/24 \
  -allow-target 10.0.0.0/8 \
  -deny-target 10.0.9.0/24 \
  -allow-host api.internal.example.com \
  -max-clients 64 \
  -max-streams 256
```

See [docs/deployment.md](docs/deployment.md) for v2 token authentication, source filtering, target filtering, and TLS/ECH notes.
For a Linux one-click server installer with interactive and non-interactive modes, temporary Cloudflare tunnels, direct public listeners, and generated client configs, see [docs/server-installer.md](docs/server-installer.md).

Require client certificates with mTLS:

```bash
./x-tunnel \
  -l wss://0.0.0.0:443/tunnel \
  -cert /path/server.pem \
  -key /path/server-key.pem \
  -client-ca /path/client-ca.pem \
  -token "$TOKEN"

./x-tunnel \
  -l socks5://127.0.0.1:11080 \
  -f wss://example.com/tunnel \
  -client-cert /path/client.pem \
  -client-key /path/client-key.pem \
  -token "$TOKEN"
```

## Metrics

Expose lightweight Prometheus-style counters with `-metrics`:

```bash
./x-tunnel -l ws://127.0.0.1:18080/tunnel -token local-test-token -metrics 127.0.0.1:9090
curl http://127.0.0.1:9090/metrics
```

Metrics include:

- Server gauges: `x_tunnel_server_sessions`, `x_tunnel_server_channels`, `x_tunnel_server_active_streams`.
- Server counters: source CIDR, v2 auth, client-limit, stream-limit, target-policy, unsupported-stream, and protocol-negotiation outcomes.
- UDP counters/gauges: total and active SOCKS5 UDP associations.
- Client counters: reconnects, protocol negotiation outcomes, and RTT probe failures.
- Client channel gauges: `x_tunnel_client_channel_up{channel="N"}`, `x_tunnel_client_channel_rtt_seconds{channel="N"}`, and `x_tunnel_client_channel_capabilities{channel="N"}`.
- Runtime counters: `x_tunnel_runtime_bytes_sent_total` and `x_tunnel_runtime_bytes_received_total`.

## Sidecar Control API

GUI or supervisor clients can start x-tunnel as a sidecar and use a loopback-only
control API instead of parsing stdout:

```bash
./x-tunnel \
  -config ./examples/local-client.json \
  -control 127.0.0.1:0 \
  -ready-file ./x-tunnel-ready.json \
  -control-token-file ./x-tunnel-token
```

The ready file is written only after the control API is bound. It contains the
process id, build metadata, control URL, token file path, and start time. The
token value is stored only in the token file. `-ready-file` and
`-control-token-file` require `-control`.

Unauthenticated endpoints:

- `GET /v1/version`
- `GET /v1/health`

`/v1/version` includes build metadata, `control_api_version`, and a capability
list so GUI clients can check compatibility before connecting user workflows to
the sidecar.

Authenticated endpoints use `Authorization: Bearer <token>`:

- `GET /v1/status`
- `GET /v1/logs`
- `GET /v1/logs/stream`
- `GET /v1/metrics`
- `GET /v1/stats`
- `POST /v1/config/check`
- `POST /v1/config/format`
- `POST /v1/runtime/stop`

`/v1/logs/stream` is an SSE stream of log-ring entries. `/v1/stats` returns JSON
traffic counters, listener status, client/server state, and machine-readable
counters for dashboards. Control API errors use a stable JSON shape:

```json
{
  "ok": false,
  "error": {
    "code": "config.invalid",
    "message": "invalid config",
    "field": "listen"
  }
}
```

`/v1/config/check` and `/v1/config/format` accept JSON payloads; they do not read
arbitrary local file paths. Status and logs redact URL userinfo and do not include
the runtime token or control token.

## Config File

Use `-config` with JSON when command lines get long. Explicit flags override config file values.
Most keys mirror flag names; `-n` is `connections`, and target filter keys accept either
hyphen or underscore forms, for example `allow-target` or `allow_target`.
See [examples](examples) for local, hardened server, WSS mTLS, and WebSocket front-proxy templates.

```json
{
  "listen": "socks5://127.0.0.1:11080",
  "forward": "ws://127.0.0.1:18080/tunnel",
  "token": "local-test-token",
  "allow-target": "10.0.0.0/8",
  "deny_target": "10.0.9.0/24",
  "allow-host": "api.internal.example.com,*.svc.example.com",
  "connections": 1,
  "max_clients": 64,
  "max_streams": 128,
  "dial_timeout": "5s",
  "reconnect_max_delay": "30s",
  "auth_skew": "5m",
  "preauth_timeout": "5s",
  "metrics": "127.0.0.1:9090"
}
```

```bash
./x-tunnel -config ./client.json
```

For GUI clients and CI checks that need validation before starting a listener,
the same config parser is available offline:

```bash
./x-tunnel -check-config ./client.json
./x-tunnel -format-config ./client.json
```

Use `-` as the path to read JSON from stdin.

Operational timeouts can be tuned with duration flags such as `-dial-timeout`,
`-ws-handshake-timeout`, `-reconnect-delay`, `-auth-skew`,
`-preauth-timeout`, and `-shutdown-timeout`. JSON config uses underscore keys,
for example `"dial_timeout": "5s"`.

UDP block ports from `-block` must be comma-separated integers in `1-65535`; invalid entries fail startup instead of being ignored.

### WebSocket Front Proxy

Client configs can optionally wrap only the client-to-server WebSocket TCP connection in an HTTP CONNECT front proxy:

```json
{
  "listen": "socks5://127.0.0.1:11080",
  "forward": "wss://x-tunnel.example.com/tunnel",
  "token": "replace-with-server-token",
  "fallback": true,
  "websocket_front_proxy": {
    "enabled": true,
    "type": "http_connect",
    "server": "cloudnproxy.baidu.com:443",
    "connect_host": "sptest.baidu.com",
    "headers": {
      "X-T5-Auth": "replace-with-auth-token",
      "User-Agent": "okhttp/3.11.0 Dalvik/2.1.0 (Linux; Build/RKQ1.200826.002)"
    }
  }
}
```

This does not change the x-tunnel v2 protocol, smux framing, local SOCKS5/HTTP/TCP listeners, or server-side SOCKS5 egress proxy. `headers` must not contain `Host`; use `connect_host` when the CONNECT request needs a custom Host header. Header values are never logged.

## Troubleshooting

- `认证失败`: client and server `-token` values differ, the v2 HMAC proof is invalid, or the ChannelInit timestamp is outside the configured skew.
- `DNS 查询失败` or `未找到 ECH 参数`: the configured `-dns` resolver could not return HTTPS/ECH records for `-ech`. Use `-fallback` only when standard TLS without ECH is acceptable.
- `无可用 smux 通道`: the local listener accepted a connection before any WebSocket/smux channel was ready, or every channel is reconnecting.
- `TCP 拒绝` or `UDP 拒绝`: the target was malformed or blocked by `-allow-target`, `-deny-target`, `-allow-host`, or `-deny-host`.
- `拒绝客户端会话`: the server-side `-max-clients` limit is already reached for new client IDs.
- `拒绝新 stream`: the server-side `-max-streams` limit for that client session is already reached.
- `ws 模式已忽略 insecure 参数`: `-insecure` only applies to `wss://`.

## Test

```bash
go test ./...
go test -cover ./...
```

## Code Organization

The binary entrypoint lives under `cmd/x-tunnel`, with implementation packages
under `internal`. See [docs/module-layout.md](docs/module-layout.md) for the
current package boundaries and dependency rules.
