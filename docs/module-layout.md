# Module Layout

This document records the current module boundaries and the intended dependency
direction for future x-tunnel changes.

## Packages

- `cmd/x-tunnel`: binary entrypoint only. It owns build metadata variables so
  existing `-ldflags -X main.buildVersion=...` release commands keep working.
- `internal/app`: runtime orchestration for client and server modes. This layer
  owns flags, JSON config loading, signal handling, local listeners, server
  session registry, smux lifecycle, metrics wiring, TLS/ECH setup, WebSocket
  front proxy dialing, and logging.
- `internal/wire`: byte-level x-tunnel protocol encoding and decoding. This
  includes smux open headers, v2 ChannelInit/Accept/Reject control frames,
  TCP/UDP open status frames, UDP chunks, and full-write helpers.
- `internal/netaddr`: shared host, hostname, and host:port validation helpers.

## Dependency Direction

```text
cmd/x-tunnel
  -> internal/app
       -> internal/wire
       -> internal/netaddr
  -> no other internal package

internal/wire
  -> internal/netaddr
```

`internal/wire` must not import `internal/app`. Wire behavior should remain
testable without starting listeners, parsing CLI flags, or touching global
runtime state.

## Refactor Rules

- Protocol byte changes require direct tests in `internal/wire` plus existing
  app/integration tests.
- Address validation changes require direct tests in `internal/netaddr` plus
  existing local proxy tests.
- New command behavior belongs in `internal/app`; `cmd/x-tunnel/main.go` should
  stay a thin entrypoint.
- Avoid adding public `pkg/*` packages until this repository intentionally
  supports external Go imports as a stable API.
