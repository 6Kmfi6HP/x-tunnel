# Proxy Protocol Research Notes

This note records protocol research used to steer x-tunnel development. It is intentionally practical: each section maps a public proxy protocol standard to the current implementation and to low-risk future work.

## SOCKS5

Primary references:

- SOCKS Protocol Version 5: RFC 1928, <https://www.rfc-editor.org/rfc/rfc1928>
- Username/Password Authentication for SOCKS V5: RFC 1929, <https://www.rfc-editor.org/rfc/rfc1929>

Current alignment:

- Local TCP CONNECT follows the SOCKS5 method negotiation, request header, address type, and reply-shape model used by RFC 1928.
- Local username/password authentication follows the RFC 1929 sub-negotiation shape and enforces one-byte username/password lengths.
- Local UDP ASSOCIATE accepts standard SOCKS5 UDP request packets:

```text
RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2) | DATA
```

- x-tunnel does not support SOCKS5 UDP fragmentation. Packets with `FRAG != 0` are rejected/dropped rather than reassembled.
- UDP request and response address parsing is now centralized so request and response paths share the same RSV/FRAG/ATYP handling.

Good next work:

- Keep SOCKS5 error mapping conservative. Remote TCP open failures default to general failure (`0x05`), but structured `policy_denied` open errors map to "connection not allowed by ruleset" (`0x02`).
- Keep UDP fragmentation unsupported unless there is a real user need; supporting it would require buffering, timeout, and resource-limit design.

## HTTP CONNECT And Local HTTP Proxying

Primary reference:

- HTTP Semantics: RFC 9110, <https://www.rfc-editor.org/rfc/rfc9110>

Current alignment:

- `CONNECT host:port HTTP/1.1` opens an opaque TCP tunnel through smux.
- A successful CONNECT response is `HTTP/1.1 200 Connection Established`, with no `Content-Length` and no `Transfer-Encoding`, before switching to tunnel bytes.
- Failed remote TCP opens return `502 Bad Gateway` locally instead of starting a tunnel.
- Non-CONNECT proxy requests accept `http://` absolute-form requests and origin-form requests with a `Host` header.
- Hop-by-hop headers, including headers named by `Connection`, are stripped before forwarding ordinary HTTP requests.
- Forwarded non-CONNECT requests append `Via: 1.1 x-tunnel`.

Good next work:

- Add more exact failure mapping only when the remote protocol carries structured error categories; avoid parsing human log strings.
- Keep CONNECT tunnel bytes opaque. Do not add HTTP headers or body processing after a successful CONNECT response.

## CONNECT-UDP And MASQUE

Primary reference:

- Proxying UDP in HTTP: RFC 9298, <https://www.rfc-editor.org/rfc/rfc9298>

Current position:

- x-tunnel does not implement HTTP CONNECT-UDP or MASQUE. UDP support today is local SOCKS5 UDP ASSOCIATE translated into x-tunnel smux UDP streams.
- x-tunnel's UDP smux stream format is internal and target-bound. It should not be presented as CONNECT-UDP wire compatibility.
- This separation is useful: current UDP relay behavior remains compatible with SOCKS5 clients without taking on HTTP/3, capsules, or MASQUE proxy semantics.

Good next work:

- If CONNECT-UDP is added later, implement it as a separate local listener mode or explicit feature flag, not as an implicit change to existing HTTP CONNECT handling.
- Reuse target validation, UDP read timeouts, metrics, and stream limits from the current UDP path.
- Keep the internal smux UDP stream protocol versioned through the hello/capability mechanism before adding any new UDP error/status frames.

## Development Heuristics

- Preserve legacy smux stream behavior unless a capability bit proves both sides understand a new frame.
- Prefer fixed byte-level golden tests for protocol frame writers and real loopback tests for proxy behavior.
- Treat public proxy protocols as compatibility boundaries. Internal smux framing can evolve, but local SOCKS5 and HTTP behavior should stay boring and predictable.
