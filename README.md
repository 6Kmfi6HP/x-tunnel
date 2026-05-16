# x-tunnel

x-tunnel is a Go tunneling tool that carries local SOCKS5, HTTP proxy, and TCP forwarding traffic over WebSocket/WSS with smux multiplexing. Server-side egress can be direct or through an upstream SOCKS5 proxy.

The local HTTP proxy listener supports `CONNECT`, ordinary `http://` absolute-form proxy requests, and origin-form requests with a valid `Host` header. Non-CONNECT absolute-form requests with other schemes, URL userinfo, malformed authorities, or mismatched `Host`/URL authorities are rejected with `400 Bad Request`.

## Build

```bash
go build -o x-tunnel .
./x-tunnel -version
```

Build metadata can be injected with `-ldflags`:

```bash
go build -ldflags "\
  -X main.buildVersion=0.1.0 \
  -X main.buildCommit=$(git rev-parse --short HEAD) \
  -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o x-tunnel .
```

Or use the build script:

```bash
VERSION=0.1.0 OUT=./x-tunnel ./scripts/build.sh
./x-tunnel -version
```

Create cross-platform release artifacts:

```bash
VERSION=0.1.0 ./scripts/release.sh
cat dist/SHA256SUMS
```

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

See [docs/deployment.md](docs/deployment.md) for token limits, source filtering, target filtering, and TLS/ECH notes.

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
- Server counters: source CIDR, token auth, client-limit, stream-limit, target-policy, unsupported-stream, and protocol-negotiation outcomes.
- UDP counters/gauges: total and active SOCKS5 UDP associations.
- Client counters: reconnects, protocol negotiation outcomes, and RTT probe failures.
- Client channel gauges: `x_tunnel_client_channel_up{channel="N"}`, `x_tunnel_client_channel_rtt_seconds{channel="N"}`, and `x_tunnel_client_channel_capabilities{channel="N"}`.

## Config File

Use `-config` with JSON when command lines get long. Explicit flags override config file values.
Most keys mirror flag names; `-n` is `connections`, and target filter keys accept either
hyphen or underscore forms, for example `allow-target` or `allow_target`.
See [examples](examples) for local, hardened server, and WSS mTLS templates.

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
  "metrics": "127.0.0.1:9090"
}
```

```bash
./x-tunnel -config ./client.json
```

Operational timeouts can be tuned with duration flags such as `-dial-timeout`,
`-ws-handshake-timeout`, `-reconnect-delay`, and `-shutdown-timeout`. JSON config
uses underscore keys, for example `"dial_timeout": "5s"`.

UDP block ports from `-block` must be comma-separated integers in `1-65535`; invalid entries fail startup instead of being ignored.

## Troubleshooting

- `认证失败：Token 不匹配或未提供`: client and server `-token` values differ, or the token contains characters that are not valid WebSocket subprotocol token characters.
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
