# x-tunnel Deployment Notes

## Authentication

Use `-token` on both client and server whenever the WebSocket listener is reachable by anything outside a trusted test environment.

The token is sent as a WebSocket subprotocol value, so it must be a valid HTTP token: ASCII letters, digits, and token-safe punctuation such as `-`, `_`, `.`, and `~`. Whitespace, commas, slashes, control characters, and non-ASCII characters are rejected at startup.

This is bearer-token authentication. Anyone who has the token can connect unless source CIDR filtering also blocks them.

## Source Filtering

Use `-cidr` on the server to restrict which client source IPs may connect:

```bash
./x-tunnel -l ws://0.0.0.0:18080/tunnel -token "$TOKEN" -cidr 203.0.113.0/24
```

`-cidr` protects the WebSocket entrypoint. It does not restrict where the tunnel may dial after a client is accepted.

## Target Filtering

Use `-allow-target` and `-deny-target` on the server to restrict target IP CIDRs:

```bash
./x-tunnel \
  -l ws://0.0.0.0:18080/tunnel \
  -token "$TOKEN" \
  -allow-target 10.0.0.0/8,192.168.0.0/16 \
  -deny-target 10.0.9.0/24
```

Policy order:

1. `-deny-target` wins first.
2. If `-allow-target` is set, the target IP must match at least one allowed CIDR.
3. Domain targets are rejected when `-allow-target` is set because the server cannot prove the pre-dial domain belongs to an allowed CIDR.
4. Domain targets are allowed under deny-only policy unless the client sends a literal denied IP.

## TLS, ECH, and `-insecure`

Prefer `wss://` with a real certificate for exposed deployments.

`-insecure` disables certificate verification in fallback TLS mode and automatically disables ECH. Treat it as a local debugging option, not a production mode.

If ECH DNS lookup fails, the client keeps retrying until it can load an ECH config or until you explicitly use `-fallback`.

## Recommended Server Baseline

```bash
./x-tunnel \
  -l wss://0.0.0.0:443/tunnel \
  -cert /path/fullchain.pem \
  -key /path/privkey.pem \
  -token "$TOKEN" \
  -cidr 203.0.113.0/24 \
  -allow-target 10.0.0.0/8
```

For local development, keep the listener on loopback:

```bash
./x-tunnel -l ws://127.0.0.1:18080/tunnel -token local-test-token -cidr 127.0.0.1/32
```
