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

- [ ] Document current wire protocol in `docs/protocol.md`.
- [ ] Define frame/header formats for stream open, TCP, UDP chunk, UDP reply, and ping.
- [ ] Record current limits: target length <= 65535, chunk length <= 65535, TLS 1.3, token via WebSocket subprotocol.
- [ ] Identify backward-compatibility constraints before changing bytes on the wire.
- [ ] List concrete risks: missing version negotiation, weak error propagation, no automated parser fuzz tests, large single-file maintenance cost, limited graceful shutdown.

Verification:

- [ ] `go test ./...`
- [ ] Manual review that spec matches existing parser/writer functions.

### Phase 2: Test Harness First, 05:00-07:00

- [ ] Add unit tests for `parseIPStrategy`.
- [ ] Add unit tests for SOCKS5 auth/address parsing.
- [ ] Add round-trip tests for `writeSmuxOpenHeader` and `readSmuxOpenHeader`.
- [ ] Add round-trip tests for `writeChunk` and `readChunk`.
- [ ] Add round-trip tests for `writeUDPReply` and `readUDPReply`.
- [ ] Add round-trip and malformed-input tests for SOCKS5 UDP packet parsing/building.

Verification:

- [ ] `go test ./...`
- [ ] Add coverage around protocol parser edge cases.

### Phase 3: Protocol Evolution Foundation, 07:00-09:30

- [ ] Add a versioned client/server hello on each smux session or stream without breaking current data paths.
- [ ] Define capability flags for TCP, UDP, ping, IP strategy, and future compression/metrics.
- [ ] Fail cleanly on unsupported versions/capabilities.
- [ ] Keep compatibility path for existing behavior if possible; otherwise document the breaking point clearly.

Verification:

- [ ] Unit tests for supported and unsupported version negotiation.
- [ ] Local WS server/client tunnel smoke test.

### Phase 4: Reliability and Lifecycle, 09:30-12:00

- [ ] Replace repeated magic timeout literals with config fields where practical.
- [ ] Add listener/server context plumbing where it can be done without a large rewrite.
- [ ] Improve reconnect backoff to avoid fixed retry storms.
- [ ] Ensure goroutines exit on stream/session close in TCP and UDP paths.
- [ ] Add clearer error logs for failed TCP/UDP target dial/open.

Verification:

- [ ] `go test ./...`
- [ ] Local connectivity smoke test for SOCKS5 and TCP forward.
- [ ] Short reconnect test by killing/restarting local server.

### Phase 5: Security Hardening, 12:00-14:00

- [ ] Add explicit config validation for listener and forward URLs.
- [ ] Add safer token validation semantics and document token limitations.
- [ ] Add optional target allow/deny CIDR or host rules if the scope stays small.
- [ ] Review `-insecure`, fallback, and ECH interactions; make user-facing logs unambiguous.
- [ ] Document recommended deployment modes.

Verification:

- [ ] Tests for config validation and auth failure behavior where practical.
- [ ] Manual unauthorized token test.

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

Pending. Add exact commands, test outputs, behavior evidence, and known residual risks after implementation.
