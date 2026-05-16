# x-tunnel Protocol Specification

Status: current implementation snapshot.

This document describes the wire behavior implemented in `x-tunnel.go` before any protocol evolution. It is intentionally conservative: any future change to these bytes must either remain backward-compatible or introduce explicit version/capability negotiation.

## 1. Topology

x-tunnel has two runtime roles:

- Client mode: starts local listeners and dials a remote WebSocket server.
- Server mode: accepts WebSocket connections, opens smux streams, and dials target TCP/UDP endpoints directly or through an upstream SOCKS5 proxy.

The transport stack is:

```text
local app
  -> local SOCKS5 / HTTP / TCP listener
  -> smux stream
  -> WebSocket binary messages
  -> TCP or TLS 1.3 WebSocket connection
  -> remote server
  -> target TCP/UDP endpoint
```

## 2. WebSocket Transport

Supported schemes:

- `ws://`
- `wss://`

For `wss://`, the client uses TLS 1.3. ECH can be enabled by default and disabled with fallback mode. `-insecure` disables certificate verification for standard TLS fallback behavior.

Authentication, when configured, uses the `Sec-WebSocket-Protocol` header:

```text
Sec-WebSocket-Protocol: <token>
```

Current limitations:

- The token is a bearer secret and is not a full authentication protocol.
- The token is compared as an exact subprotocol value.
- There is no separate session-auth frame after WebSocket upgrade.

## 3. Client Session and Channels

Each client process generates one `client_id` UUID. Each WebSocket channel is dialed with query parameters:

```text
client_id=<uuid>
channel_id=<1-based integer>
```

The server groups channels by `client_id`. If a channel connects with an existing `channel_id`, the old WebSocket connection for that channel is closed and replaced.

Each WebSocket channel carries one smux session.

On new builds, the client opens one hello control stream immediately after smux session creation. If the server responds, the session has explicit version and capability negotiation. If an old server closes or times out the hello stream, the client logs legacy mode and keeps the existing data path available.

## 4. smux Stream Open Header

Every new smux stream starts with a fixed 4-byte header followed by an optional target string:

```text
0                   1                   2                   3
+-------------------+-------------------+-------------------+
| kind              | ip_strategy       | target_len (BE16) |
+-------------------+-------------------+-------------------+
| target bytes ...                                      |
+-------------------------------------------------------+
```

Fields:

- `kind`: stream type.
- `ip_strategy`: requested target IP selection strategy.
- `target_len`: big-endian uint16 length of the following target string.
- `target`: UTF-8 string, usually `host:port`.

Stream kinds:

| Value | Name | Meaning |
| --- | --- | --- |
| `1` | TCP | Open a TCP proxy stream to `target`. |
| `2` | UDP | Open a UDP relay stream to `target`. |
| `3` | Ping | Echo an 8-byte ping payload. |
| `4` | Hello | Negotiate protocol version and capabilities for the smux session. |

IP strategies:

| Value | CLI | Meaning |
| --- | --- | --- |
| `0` | default | Use default resolver/dialer behavior. |
| `1` | `4` | IPv4 only. |
| `2` | `6` | IPv6 only. |
| `3` | `4,6` | Prefer IPv4, fall back to IPv6. |
| `4` | `6,4` | Prefer IPv6, fall back to IPv4. |

Limits:

- `target_len <= 65535`.
- The current TCP/UDP/Ping stream open header remains unchanged for compatibility.
- TCP and UDP streams reject `ip_strategy` values outside `0..4` before dialing or opening a relay.
- Unknown stream kinds are treated as unsupported: the server logs the kind, increments `x_tunnel_server_unsupported_streams_total`, and closes the stream.

## 5. Protocol Hello Stream

The hello stream uses `streamKindHello` (`4`) with an empty target in the existing smux open header. After that header, the client writes a protocol hello frame:

```text
0                   1                   2                   3
+-------------------+-------------------+-------------------+
| magic "XTUN"                                          |
+-------------------+-------------------+-------------------+
| version           | status            | msg_len (BE16)    |
+-------------------+-------------------+-------------------+
| capabilities (BE32)                                  |
+-------------------------------------------------------+
| message bytes ...                                    |
+-------------------------------------------------------+
```

Fields:

- `magic`: fixed ASCII string `XTUN`.
- `version`: current protocol version, currently `1`.
- `status`: `0` for OK, non-zero for rejection responses.
- `msg_len`: big-endian uint16 message length.
- `capabilities`: big-endian uint32 capability flags.
- `message`: optional UTF-8 diagnostic message.

Status values:

| Value | Name | Meaning |
| --- | --- | --- |
| `0` | OK | Version/capabilities accepted. |
| `1` | UnsupportedVersion | Peer does not support the requested version. |
| `2` | NoCommonCapabilities | Peer is missing required capabilities for this protocol version. |

Capability flags:

| Bit | Name | Meaning |
| --- | --- | --- |
| `1 << 0` | TCP | TCP streams are supported. |
| `1 << 1` | UDP | UDP streams are supported. |
| `1 << 2` | Ping | Ping streams are supported. |
| `1 << 3` | IPStrategy | IP strategy byte is understood. |
| `1 << 4` | TCPStatus | TCP streams begin with an open-status frame before proxied bytes. |

Current client behavior:

- Requires negotiated TCP and Ping capabilities.
- Advertises UDP, IPStrategy, and TCPStatus support. TCPStatus changes the TCP stream handshake when both peers negotiate it; UDP and IPStrategy are currently declared capabilities for compatibility visibility rather than per-stream gates.
- Treats EOF, unexpected EOF, or timeout while waiting for hello as legacy server behavior.
- Fails the channel cleanly on explicit rejection or insufficient capabilities.

## 6. TCP Stream

After a TCP stream open header, legacy peers proxy raw bytes until either direction exits. The implementation then closes both the target connection and the smux stream.

When both peers negotiate `TCPStatus`, the server first writes a TCP open-status frame:

```text
----------------+------------------+----------------------+
| status (u8)   | msg_len (BE16)   | message bytes ...    |
+----------------+------------------+----------------------+
```

Status values:

| Value | Name | Meaning |
| --- | --- | --- |
| `0` | OK | Target policy and remote TCP dial succeeded. Proxied bytes follow. |
| `1` | Error | Target policy or remote TCP dial failed. The message is diagnostic text and the stream closes. |

New clients wait for this status before returning local SOCKS5 or HTTP CONNECT success. Legacy channels do not wait for a status frame and keep the older best-effort behavior.

Local failure mapping with TCPStatus:

- SOCKS5 CONNECT returns a non-success SOCKS5 reply when the remote server rejects the target or cannot dial it.
- HTTP proxy and CONNECT requests return `502 Bad Gateway` after a remote target-policy or dial failure.
- TCP forward listeners close the local connection when the remote open status is an error.
- Malformed TCP stream targets are rejected before target-policy checks and use the same TCPStatus error path when available.

## 7. Ping Stream

A ping stream has:

```text
stream open header(kind=3, ip_strategy=0, target="")
8-byte payload
```

The server echoes the exact 8-byte payload. The client measures RTT around write/read completion.

## 8. UDP Stream

A UDP stream is opened for one current target. The local SOCKS5 UDP association binds to the first requested `DST.ADDR:DST.PORT`; later packets for a different target are dropped instead of being sent over the already-bound stream. Client-to-server datagrams are sent as chunks:

```text
0                   1
+-------------------+
| chunk_len (BE16)  |
+-------------------+
| payload bytes ... |
+-------------------+
```

Limits:

- `chunk_len <= 65535`.
- Zero-length chunks are ignored.

Server-to-client UDP replies include the source address string and payload:

```text
0                   1                   2                   3
+-------------------+-------------------+-------------------+
| addr_len (BE16)   | payload_len (BE16)|
+-------------------+-------------------+-------------------+
| addr bytes ...                                        |
+-------------------------------------------------------+
| payload bytes ...                                     |
+-------------------------------------------------------+
```

Limits:

- `addr_len <= 65535`.
- `payload_len <= 65535`.

## 9. SOCKS5 UDP Packet Format

The local SOCKS5 UDP association accepts standard SOCKS5 UDP request packets:

```text
RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2) | DATA
```

Current behavior:

- `RSV` must be `0x0000`.
- `FRAG` must be `0`.
- `ATYP` supports IPv4, domain, and IPv6.
- IPv6 targets are formatted as `[host]:port` after parsing.
- UDP destination ports listed in `-block` are silently dropped.

## 10. Local HTTP Proxy Behavior

The local HTTP listener accepts three proxy forms:

- `CONNECT host:port HTTP/1.1` for HTTPS or other TCP tunnels. A missing port defaults to `443`.
- Absolute-form HTTP requests such as `GET http://host[:port]/path HTTP/1.1`. A missing port defaults to `80`.
- Origin-form requests such as `GET /path HTTP/1.1` with a valid `Host` header. A missing port defaults to `80`.

Non-CONNECT absolute-form requests are accepted only with the `http` scheme. Absolute-form `https://`, `ftp://`, URL userinfo, malformed authorities, and mismatched `Host` versus URL authorities are rejected with `400 Bad Request` before any smux stream opens. `Proxy-Authorization` is consumed locally before forwarding ordinary HTTP requests. Hop-by-hop request headers are stripped before forwarding, including fields named by `Connection` plus common proxy/connection-only fields such as `Proxy-Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, and `Upgrade`.

## 11. Current Risk Map

### Compatibility Risks

- Protocol version/capability negotiation now exists on a hello control stream, but TCP/UDP/Ping stream headers are still unversioned for compatibility.
- Optional future features such as compression, metrics, stronger auth, or status replies must be gated behind capability flags.
- Unknown stream kinds are explicitly rejected and counted, but future structured status replies still require negotiated framing.

### Reliability Risks

- TCP open status is negotiated, but UDP errors and mid-stream TCP failures are still not structured.
- Reconnect timing and major network timeouts are configurable, but future paths should keep using `GlobalConfig` rather than reintroducing literals.
- Graceful shutdown and listener lifecycle are not centralized.

### Security Risks

- WebSocket token auth is a bearer-token subprotocol check only.
- `-insecure` and ECH fallback behavior must stay explicit in logs because misuse weakens TLS validation.
- Server-side egress policy is pre-dial only: CIDR rules apply to literal IP targets, and host rules apply to literal domain targets before DNS resolution. `allow-host` does not allow literal IP targets, `deny-host` alone does not block literal IP targets, and host matches do not prove the final resolved IP for a domain.

### Testability Risks

- The project has unit coverage for protocol helpers and automated local integration coverage, but broader load, failure-injection, and cross-platform tests are still future work.
- Protocol encoders/decoders are extracted into `protocol.go`; SOCKS5 parsing remains in the main file.

## 12. Evolution Rules

- Do not change existing wire bytes until unit tests cover current encoders/decoders.
- Add negotiation before introducing incompatible stream framing.
- Keep current WS/WSS + smux behavior working while adding tests and docs.
- Prefer explicit errors over silent fallthrough for future protocol versions.
