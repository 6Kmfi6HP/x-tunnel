# x-tunnel Troubleshooting

## Token Mismatch

Symptoms:

- Client logs `认证失败：Token 不匹配或未提供`.
- Server logs `Token 认证失败`.

Checks:

- Ensure client and server use the same `-token`.
- Ensure the token has no spaces, commas, slashes, quotes, non-ASCII characters, or shell-expanded characters.
- Re-run `x-tunnel -version` to confirm both sides are the expected build.

## No Available smux Channel

Symptoms:

- Local proxy accepts a connection, but traffic fails.
- Client may log `无可用 smux 通道`.

Checks:

- Confirm the client logs `协议协商成功`.
- Check reconnect logs for repeated `连接失败`, `smux 初始化失败`, or `协议协商失败`.
- Verify the server URL, token, and source CIDR.
- Increase `-n` only after basic single-channel connectivity works.

## ECH or DNS Lookup Failure

Symptoms:

- Client repeatedly logs DNS query failures or missing ECH config.

Checks:

- Use `-fallback` to intentionally disable ECH and use ordinary TLS 1.3.
- Verify `-dns` is reachable from the client.
- Verify `-ech` points to a domain with an HTTPS record carrying ECH config.
- Do not use `-insecure` in production; with `wss://`, it disables ECH and uses fallback TLS behavior.

## Target Policy Rejection

Symptoms:

- Server logs `TCP 拒绝` or `UDP 拒绝`.
- Client side may see an empty reply or closed stream.

Checks:

- Review server `-allow-target` and `-deny-target`.
- `-deny-target` wins before `-allow-target`.
- Domain targets are rejected when `-allow-target` is set because the server cannot prove the pre-dial domain belongs to an allowed CIDR.

## Source CIDR Rejection

Symptoms:

- WebSocket upgrade fails with HTTP 403.

Checks:

- Confirm the server process sees the real client IP.
- If behind a reverse proxy, enforce source filtering at the proxy or ensure the tunnel process receives the true remote address.
- Update `-cidr` only after confirming the observed remote address in server logs.
