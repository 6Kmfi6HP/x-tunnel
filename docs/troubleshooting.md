# x-tunnel Troubleshooting

## Token Mismatch

Symptoms:

- Client logs `认证失败：Token 不匹配或未提供`.
- Server logs `Token 认证失败`.

Checks:

- Ensure client and server use the same `-token`.
- Ensure the token has no spaces, commas, slashes, quotes, non-ASCII characters, or shell-expanded characters.
- Re-run `x-tunnel -version` to confirm both sides are the expected build.
- If `-metrics` is enabled, check `x_tunnel_server_auth_rejections_total`.

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
- New clients with negotiated TCPStatus map TCP target failures to local SOCKS5 failure replies, HTTP `502 Bad Gateway`, or a closed TCP-forward connection.
- Legacy channels may still show an empty reply or closed stream.

Checks:

- Review server `-allow-target`, `-deny-target`, `-allow-host`, and `-deny-host`.
- Confirm the requested target is a valid `host:port` authority with no whitespace and a port in `1-65535`.
- `-deny-target` wins before `-allow-target` for IP targets; `-deny-host` wins before `-allow-host` for domain targets.
- Domain targets are rejected when CIDR allow rules exist without a matching `-allow-host`.
- If `-metrics` is enabled, check `x_tunnel_server_target_rejections_total`.

## Source CIDR Rejection

Symptoms:

- WebSocket upgrade fails with HTTP 403.

Checks:

- Confirm the server process sees the real client IP.
- If behind a reverse proxy, enforce source filtering at the proxy or ensure the tunnel process receives the true remote address.
- Update `-cidr` only after confirming the observed remote address in server logs.
- If `-metrics` is enabled, check `x_tunnel_server_source_rejections_total`.

## Client or Stream Limit Rejection

Symptoms:

- Server logs `拒绝客户端会话`.
- Server logs `拒绝新 stream`.
- New client requests fail while existing streams continue running.

Checks:

- Review server `-max-clients`; `0` means unlimited.
- Review server `-max-streams`; `0` means unlimited.
- Raise the limit if expected concurrency is higher than the configured cap.
- Check whether many clients, WebSocket channels, or long-lived TCP/UDP streams are stuck open.
- If `-metrics` is enabled, check `x_tunnel_server_client_session_rejections_total`, `x_tunnel_server_stream_rejections_total`, `x_tunnel_server_channels`, `x_tunnel_server_active_streams`, and `x_tunnel_udp_associations_active`.

## Unsupported Stream Kind

Symptoms:

- Server logs `不支持的 stream kind`.
- The affected smux stream closes without forwarding traffic.

Checks:

- Confirm both client and server are expected builds with `x-tunnel -version`.
- Check for incompatible forks or experimental clients before raising protocol capabilities.
- If `-metrics` is enabled, check `x_tunnel_server_unsupported_streams_total`.

## mTLS Failure

Symptoms:

- Client repeatedly logs TLS or connection failures when connecting to `wss://`.
- Server has `-client-ca` configured and the client never reaches `协议协商成功`.

Checks:

- Ensure the server listener uses `wss://`; `-client-ca` is rejected on `ws://`.
- Ensure the client uses `wss://` with both `-client-cert` and `-client-key`.
- Ensure the client certificate is signed by the CA configured with `-client-ca`.
- If using a self-signed server certificate for local testing, use `-insecure`; this only disables server certificate verification on the client and does not bypass server-side client certificate verification.
