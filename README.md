# x-tunnel

x-tunnel is a Go tunneling tool that carries local SOCKS5, HTTP proxy, and TCP forwarding traffic over WebSocket/WSS with smux multiplexing. Server-side egress can be direct or through an upstream SOCKS5 proxy.

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
  -deny-target 10.0.9.0/24
```

See [docs/deployment.md](docs/deployment.md) for token limits, source filtering, target filtering, and TLS/ECH notes.

## Metrics

Expose lightweight Prometheus-style counters with `-metrics`:

```bash
./x-tunnel -l ws://127.0.0.1:18080/tunnel -token local-test-token -metrics 127.0.0.1:9090
curl http://127.0.0.1:9090/metrics
```

## Config File

Use `-config` with JSON when command lines get long. Explicit flags override config file values.
Most keys mirror flag names; `-n` is `connections`, and target filter keys accept either
`allow-target`/`deny-target` or `allow_target`/`deny_target`.

```json
{
  "listen": "socks5://127.0.0.1:11080",
  "forward": "ws://127.0.0.1:18080/tunnel",
  "token": "local-test-token",
  "allow-target": "10.0.0.0/8",
  "deny_target": "10.0.9.0/24",
  "connections": 1,
  "metrics": "127.0.0.1:9090"
}
```

```bash
./x-tunnel -config ./client.json
```

## Troubleshooting

- `认证失败：Token 不匹配或未提供`: client and server `-token` values differ, or the token contains characters that are not valid WebSocket subprotocol token characters.
- `DNS 查询失败` or `未找到 ECH 参数`: the configured `-dns` resolver could not return HTTPS/ECH records for `-ech`. Use `-fallback` only when standard TLS without ECH is acceptable.
- `无可用 smux 通道`: the local listener accepted a connection before any WebSocket/smux channel was ready, or every channel is reconnecting.
- `TCP 拒绝` or `UDP 拒绝`: the target was blocked by `-allow-target` or `-deny-target`.
- `ws 模式已忽略 insecure 参数`: `-insecure` only applies to `wss://`.

## Test

```bash
go test ./...
go test -cover ./...
```
