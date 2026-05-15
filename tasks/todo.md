# x-tunnel Development Plan Until 2026-05-16 19:00 +07

Assumption: "today 7 o'clock" means 19:00 on 2026-05-16 in the current local timezone (+07). Current planning time: about 03:33, leaving roughly 15.5 hours.

## Objective

Improve x-tunnel from a working single-file prototype into a protocol that is easier to evolve, verify, debug, and harden without breaking current WS/WSS + smux + SOCKS5/HTTP/TCP forwarding behavior.

## Current Baseline

- Single Go binary in `x-tunnel.go` with client/server modes.
- Transports: `ws://`, `wss://`, optional ECH, smux multiplexing.
- Local client listeners: SOCKS5, HTTP proxy, TCP forward.
- Remote egress: direct TCP/UDP or upstream SOCKS5.
- Existing manual verification previously passed local SOCKS5 and TCP forwarding.
- Main gap: no automated test files, no protocol spec, and protocol messages are implicit in code.

## Time-Boxed Plan

### Phase 1: Protocol Spec and Risk Map, 03:35-05:00

- [x] Document current wire protocol in `docs/protocol.md`.
- [x] Define frame/header formats for stream open, TCP, UDP chunk, UDP reply, and ping.
- [x] Record current limits: target length <= 65535, chunk length <= 65535, TLS 1.3, token via WebSocket subprotocol.
- [x] Identify backward-compatibility constraints before changing bytes on the wire.
- [x] List concrete risks: missing version negotiation, weak error propagation, no automated parser fuzz tests, large single-file maintenance cost, limited graceful shutdown.

Verification:

- [x] `go test ./...`
- [x] Manual review that spec matches existing parser/writer functions.

### Phase 2: Test Harness First, 05:00-07:00

- [x] Add unit tests for `parseIPStrategy`.
- [x] Add unit tests for SOCKS5 auth/address parsing.
- [x] Add round-trip tests for `writeSmuxOpenHeader` and `readSmuxOpenHeader`.
- [x] Add round-trip tests for `writeChunk` and `readChunk`.
- [x] Add round-trip tests for `writeUDPReply` and `readUDPReply`.
- [x] Add round-trip and malformed-input tests for SOCKS5 UDP packet parsing/building.

Verification:

- [x] `go test ./...`
- [x] Add coverage around protocol parser edge cases.

### Phase 3: Protocol Evolution Foundation, 07:00-09:30

- [x] Add a versioned client/server hello on each smux session or stream without breaking current data paths.
- [x] Define capability flags for TCP, UDP, ping, IP strategy, and future compression/metrics.
- [x] Fail cleanly on unsupported versions/capabilities.
- [x] Keep compatibility path for existing behavior if possible; otherwise document the breaking point clearly.

Verification:

- [x] Unit tests for supported and unsupported version negotiation.
- [x] Local WS server/client tunnel smoke test.

### Phase 4: Reliability and Lifecycle, 09:30-12:00

- [x] Replace repeated magic timeout literals with config fields where practical.
- [x] Add listener/server context plumbing where it can be done without a large rewrite.
- [x] Improve reconnect backoff to avoid fixed retry storms.
- [x] Ensure goroutines exit on stream/session close in TCP and UDP paths.
- [x] Add clearer error logs for failed TCP/UDP target dial/open.

Verification:

- [x] `go test ./...`
- [x] Local connectivity smoke test for SOCKS5 and TCP forward.
- [x] Short reconnect test by killing/restarting local server.

### Phase 5: Security Hardening, 12:00-14:00

- [x] Add explicit config validation for listener and forward URLs.
- [x] Add safer token validation semantics and document token limitations.
- [x] Add optional target allow/deny CIDR or host rules if the scope stays small.
- [x] Review `-insecure`, fallback, and ECH interactions; make user-facing logs unambiguous.
- [x] Document recommended deployment modes.

Verification:

- [x] Tests for config validation and auth failure behavior where practical.
- [x] Manual unauthorized token test.

### Phase 6: Observability and Operator UX, 14:00-15:30

- [ ] Add structured-ish log prefixes or counters for sessions, channels, streams, reconnects, and UDP associations.
- [ ] Add a `-version` flag if build metadata can be added simply.
- [ ] Improve help text and README examples for common modes.
- [ ] Add a troubleshooting section for token mismatch, ECH failure, DNS failure, and no smux channel available.

Verification:

- [ ] `go run x-tunnel.go -h`
- [ ] README/docs examples checked against actual flags.

### Phase 7: Refactor Only Where It Pays, 15:30-17:30

- [ ] Extract pure protocol encoding/decoding into a small file/package if tests show a clean boundary.
- [ ] Extract SOCKS5 parsing/building helpers if it reduces single-file risk without broad churn.
- [ ] Avoid broad architectural rewrites unless current changes become hard to verify.

Verification:

- [ ] `go test ./...`
- [ ] `go run x-tunnel.go -h`
- [ ] Local WS server/client tunnel smoke test.

### Phase 8: Final Verification and Review, 17:30-19:00

- [ ] Run complete local test matrix:
  - [ ] server `ws://127.0.0.1`
  - [ ] client SOCKS5 listener
  - [ ] client TCP forward listener
  - [ ] HTTP proxy CONNECT if feasible in time
  - [ ] token mismatch rejection
- [ ] Record exact commands and results in this file.
- [ ] Review diff for unnecessary churn.
- [ ] Confirm docs match current behavior.
- [ ] Prepare final summary with remaining risks and next development backlog.

## Scope Control Rules

- Do not change wire bytes before tests exist for the current format.
- Prefer compatibility and explicit negotiation over silent behavior changes.
- Keep changes minimal and reversible; no broad rewrite unless a narrower fix is blocked.
- If tests fail or protocol behavior is ambiguous, stop and re-plan before continuing.

## Candidate Backlog After 19:00

- QUIC/WebTransport transport option.
- Metrics endpoint or Prometheus counters.
- Config file support.
- mTLS or stronger client authentication.
- Benchmark suite and load testing.
- Windows/Linux/macOS release packaging.
- CI workflow.

## Review

Phase 1:

- Added `docs/protocol.md` as the current protocol snapshot and risk map.
- Verified with `go test ./...`: pass, package reports `[no test files]`.

Phase 2:

- Added `x_tunnel_test.go` unit tests for IP strategy parsing, SOCKS5 auth/address parsing, smux open headers, UDP chunks, UDP replies, SOCKS5 UDP packet round-trips, and malformed SOCKS5 UDP inputs.
- Added bounds checks for oversized UDP reply payloads and oversized SOCKS5 UDP domain names to prevent length-field truncation.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 10.0% of statements`.

Phase 3:

- Added `streamKindHello` protocol negotiation over a smux control stream.
- Added protocol version `1`, status codes, and capability flags for TCP, UDP, Ping, and IPStrategy.
- New clients fail explicit unsupported-version/capability responses and fall back to legacy mode only when the peer does not answer the hello stream.
- Updated `docs/protocol.md` with the hello frame format.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 11.5% of statements`.
- Verified local WS smoke test with server `ws://127.0.0.1:18080/tunnel`, client SOCKS5 `127.0.0.1:11080`, TCP forward `127.0.0.1:12000`, and local HTTP target `127.0.0.1:19090`.
- Smoke result: `phase3_smoke=pass`, source/SOCKS/TCP hash all `8f099f7578ffd733cbd2dbb20acd572448feefd2c104c887253829aa302223f7`.
- Negotiation evidence: client log contained `协议协商成功: version=1 caps=0xf`; server log contained `协议协商成功: version=1 caps=0xf`.

Pending for later phases: reliability/security changes, integration smoke tests, and final review.

Phase 4:

- Added config fields for reconnect max delay/jitter, DNS query timeout, ECH retry delay, UDP read timeout, and shutdown timeout.
- Replaced practical hard-coded DNS/ECH/UDP time literals with config values.
- Added exponential reconnect backoff with crypto-random jitter and unit coverage for base delay and jitter bounds.
- Added clearer logs for failed client stream opens, server TCP/UDP target failures, and UDP response write failures.
- Added SIGINT/SIGTERM context plumbing for the WebSocket server, client listeners, and channel reconnect loops.
- Added graceful HTTP server shutdown with `cfg.ShutdownTimeout`.
- Updated UDP stream lifecycle so the relay is closed as soon as the stream reader exits, unblocking the reply loop without waiting for the read timeout.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 12.3% of statements`.
- Verified reconnect smoke test by starting the client before the WS server, observing a connection failure/backoff, then starting the server and fetching through SOCKS5 and TCP.
- Reconnect smoke result: `phase4_reconnect_smoke=pass hash=3db3ab0c56d7ea82789a83e33a7cf7634e95421e2b7c014e82b639d847c0acb8 socks_size=69297 tcp_size=69297`.
- Backoff evidence: first failure logged `连接失败: dial tcp 127.0.0.1:18082: connect: connection refused，1.044365433s 后重试 (attempt=1)`.
- Negotiation evidence after reconnect: client and server logs both contained `协议协商成功`, `version=1`, and `caps=0xf`.
- Verified lifecycle smoke test with a temporary `go build` binary: server/client handled SIGTERM and exited after SOCKS5/TCP hash checks.
- Lifecycle smoke result: `phase4_lifecycle_smoke=pass hash=2f7fb3bf5a5ef93f224c5a14ee54ed9112f54b07a152a37ac43cb640352aa45e socks_size=71153 tcp_size=71153 graceful_sigterm=pass`.

Remaining Phase 4 work: complete.

Phase 5:

- Added startup validation for listener rules, token syntax, and `-ip` overrides.
- Added `-allow-target` and `-deny-target` server CIDR policies for TCP/UDP target access.
- Added `docs/deployment.md` covering token limits, source CIDR filtering, target filtering, TLS/ECH/`-insecure`, and recommended deployment commands.
- Added unit tests for config validation and target policy behavior.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 15.7% of statements`.
- Verified wrong-token rejection with a real server/client: `phase5_token_reject=pass`.
- Wrong-token evidence: client logged `认证失败：Token 不匹配或未提供`; server logged `Token 认证失败，来源 IP: 127.0.0.1`.
- Verified target policy rejection with server `-allow-target 10.0.0.0/8` and client request to `127.0.0.1:19095`: `phase5_target_policy=pass curl_code=52`.
- Target policy evidence: server logged `TCP 拒绝: 127.0.0.1:19095, reason=目标 127.0.0.1 未命中 allow-target`.

Pending for later phases: observability/operator UX, integration smoke tests, and final review.
