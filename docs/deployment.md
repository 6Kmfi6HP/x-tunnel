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

Use `-allow-target` and `-deny-target` on the server to restrict target IP CIDRs.
Use `-allow-host` and `-deny-host` to restrict domain targets before DNS resolution:

```bash
./x-tunnel \
  -l ws://0.0.0.0:18080/tunnel \
  -token "$TOKEN" \
  -allow-target 10.0.0.0/8,192.168.0.0/16 \
  -deny-target 10.0.9.0/24 \
  -allow-host api.internal.example.com,*.svc.example.com \
  -deny-host bad.internal.example.com
```

Policy order:

1. `-deny-target` wins first for IP targets; `-deny-host` wins first for domain targets.
2. If any allow policy is set, the target must match the allow policy for its type: CIDR for IPs, host pattern for domains.
3. Host wildcards only support the `*.example.com` form and match subdomains, not the apex `example.com`.
4. Domain targets are still rejected when only CIDR allow rules exist because the server cannot prove the pre-dial domain belongs to an allowed CIDR.
5. Domain targets are allowed under deny-only policy unless the hostname matches `-deny-host`.

## Resource Limits

Use `-max-streams` on the server to cap active smux streams per client session:

```bash
./x-tunnel \
  -l ws://0.0.0.0:18080/tunnel \
  -token "$TOKEN" \
  -max-streams 256
```

The default `0` preserves legacy behavior and means unlimited. The limit counts all active streams for the same `client_id` across that client's WebSocket channels, including short-lived hello and ping streams. JSON config accepts `max_streams` or `max-streams`.

## TLS, ECH, and `-insecure`

Prefer `wss://` with a real certificate for exposed deployments.

`-insecure` disables certificate verification in fallback TLS mode and automatically disables ECH. Treat it as a local debugging option, not a production mode.

If ECH DNS lookup fails, the client keeps retrying until it can load an ECH config or until you explicitly use `-fallback`.

## Runtime Timeouts

Default timeouts are conservative for local and small remote deployments, but exposed deployments can tune them explicitly:

- `-dial-timeout`: target TCP/DNS dialing timeout.
- `-ws-handshake-timeout`: WebSocket handshake timeout.
- `-reconnect-delay`, `-reconnect-max-delay`, `-reconnect-jitter`: client reconnect backoff. Set `-reconnect-jitter 0s` to disable jitter.
- `-rtt-timeout`: channel RTT probe timeout.
- `-dns-timeout` and `-ech-retry-delay`: ECH lookup timeout/retry behavior.
- `-udp-read-timeout`: server UDP relay read polling timeout.
- `-shutdown-timeout`: graceful HTTP server shutdown timeout.

JSON config uses underscore keys such as `dial_timeout`, `ws_handshake_timeout`, and `shutdown_timeout`.

## mTLS Client Authentication

For stronger client authentication, use `-client-ca` on the WSS server and `-client-cert` / `-client-key` on the client.

Server:

```bash
./x-tunnel \
  -l wss://0.0.0.0:443/tunnel \
  -cert /path/server.pem \
  -key /path/server-key.pem \
  -client-ca /path/client-ca.pem \
  -token "$TOKEN"
```

Client:

```bash
./x-tunnel \
  -l socks5://127.0.0.1:11080 \
  -f wss://example.com/tunnel \
  -client-cert /path/client.pem \
  -client-key /path/client-key.pem \
  -token "$TOKEN"
```

`-client-ca` only works on `wss://` server listeners. `-client-cert` and `-client-key` only work with `wss://` client forwards.

## Recommended Server Baseline

```bash
./x-tunnel \
  -l wss://0.0.0.0:443/tunnel \
  -cert /path/fullchain.pem \
  -key /path/privkey.pem \
  -token "$TOKEN" \
  -cidr 203.0.113.0/24 \
  -allow-target 10.0.0.0/8 \
  -max-streams 256
```

For local development, keep the listener on loopback:

```bash
./x-tunnel -l ws://127.0.0.1:18080/tunnel -token local-test-token -cidr 127.0.0.1/32
```
