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

- [x] Add structured-ish log prefixes or counters for sessions, channels, streams, reconnects, and UDP associations.
- [x] Add a `-version` flag if build metadata can be added simply.
- [x] Improve help text and README examples for common modes.
- [x] Add a troubleshooting section for token mismatch, ECH failure, DNS failure, and no smux channel available.

Verification:

- [x] `go run . -h`
- [x] README/docs examples checked against actual flags.

### Phase 7: Refactor Only Where It Pays, 15:30-17:30

- [x] Extract pure protocol encoding/decoding into a small file/package if tests show a clean boundary.
- [ ] Extract SOCKS5 parsing/building helpers if it reduces single-file risk without broad churn.
- [x] Avoid broad architectural rewrites unless current changes become hard to verify.

Verification:

- [x] `go test ./...`
- [x] `go run . -h`
- [x] Local WS server/client tunnel smoke test.

### Phase 8: Final Verification and Review, 17:30-19:00

- [x] Run complete local test matrix:
  - [x] server `ws://127.0.0.1`
  - [x] client SOCKS5 listener
  - [x] client TCP forward listener
  - [x] HTTP proxy CONNECT if feasible in time
  - [x] token mismatch rejection
- [x] Record exact commands and results in this file.
- [x] Review diff for unnecessary churn.
- [x] Confirm docs match current behavior.
- [x] Prepare final summary with remaining risks and next development backlog.

## Scope Control Rules

- Do not change wire bytes before tests exist for the current format.
- Prefer compatibility and explicit negotiation over silent behavior changes.
- Keep changes minimal and reversible; no broad rewrite unless a narrower fix is blocked.
- If tests fail or protocol behavior is ambiguous, stop and re-plan before continuing.

## Candidate Backlog After 19:00

- QUIC/WebTransport transport option.
- [x] Metrics endpoint or Prometheus counters.
- [x] Config file support.
- [x] mTLS or stronger client authentication.
- Benchmark suite and load testing.
- [x] Windows/Linux/macOS release packaging.
- [x] CI workflow.
- [x] Automated local integration test.
- [x] Release build metadata script.
- [x] Protocol helper benchmarks.

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
- Verified with `go test -cover ./...`: pass, `coverage: 16.3% of statements`.
- Verified wrong-token rejection with a real server/client: `phase5_unauthorized_token=pass`.
- Wrong-token evidence: client logged `认证失败：Token 不匹配或未提供`; server logged `Token 认证失败，来源 IP: 127.0.0.1`.
- Verified allowed target policy smoke with server `-allow-target 127.0.0.0/8`: `phase5_policy_smoke=pass hash=4eecc23f5206ec6b4e30afb974965f817b156ec67ae9ad17fe6dd76c443c28d0`.
- Verified target policy rejection with server `-allow-target 10.0.0.0/8` and client request to `127.0.0.1:19096`: `phase5_target_policy=pass curl_code=52`.
- Target policy evidence: server logged `TCP 拒绝: 127.0.0.1:19096, reason=目标 127.0.0.1 未命中 allow-target`.

Pending for later phases: observability/operator UX, integration smoke tests, and final review.

Phase 6:

- Added `-version` with build metadata fields `buildVersion`, `buildCommit`, and `buildDate`.
- Added structured-ish stream logs with server stream IDs and UDP association IDs.
- Added `README.md` with build, local WS, hardened server, troubleshooting, and test examples.
- Added `docs/troubleshooting.md` for token mismatch, ECH/DNS lookup failures, no smux channel, target policy rejection, and source CIDR rejection.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 15.8% of statements`.
- Verified `go run . -version`: `x-tunnel version=dev commit=unknown build=unknown`.
- Verified `go run . -h`: pass and includes `-allow-target`, `-deny-target`, `-version`, and `socks5://`.
- Verified real TCP log smoke: `phase6_log_smoke=pass hash=09d9c57acdfa0bacb95eb1b4854ea293fa27b5671ed8142f9db9c4995437a05a tcp_size=78465`.
- Log evidence: server emitted `stream=4 client=240e1179 channel=1 kind=1 target=127.0.0.1:19096`.

Phase 7:

- Extracted protocol constants and pure protocol encoders/decoders into `protocol.go`.
- Kept SOCKS5 helpers in `x-tunnel.go` for now because they are still interleaved with listener and UDP relay behavior; extracting them now would be churn without a cleaner boundary.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 15.7% of statements`.
- Verified `go run . -h` and `go run x-tunnel.go protocol.go -h`: pass and includes `-version` and `socks5://`.
- Verified local WS/SOCKS5/TCP smoke after refactor: `phase7_refactor_smoke=pass hash=9fbf747126281a01d9be3b3712502fb005e4441a5832baf68eb10df609470bfb socks_size=73026 tcp_size=73026`.
- Log evidence after refactor: server emitted `stream=4 client=bd1b5253 channel=1 kind=1 target=127.0.0.1:19097`.

Pending for later phases: final integration smoke tests and final review.

Phase 8:

- Ran final local integration matrix with a temporary `go build` binary.
- Covered WS server, SOCKS5 listener, TCP forward listener, HTTP proxy CONNECT through a local self-signed TLS service, and wrong-token rejection.
- Matrix result: `phase8_matrix=pass hash=9fbf747126281a01d9be3b3712502fb005e4441a5832baf68eb10df609470bfb socks_size=73026 tcp_size=73026 connect_size=4919`.
- CONNECT evidence: response contained `s_server -quiet -accept 19443`.
- Token rejection evidence: client logged `认证失败：Token 不匹配或未提供`; server logged `Token 认证失败，来源 IP: 127.0.0.1`.
- Diff review: protocol extraction is isolated to `protocol.go`; no wire-format changes were made in Phase 7/8.
- Docs checked: `README.md`, `docs/protocol.md`, `docs/deployment.md`, and `docs/troubleshooting.md` match the current flags and observed behavior.

Remaining risks/backlog:

- Add CI so `go test ./...` runs automatically on push/PR.
- [x] Expand automated integration tests to cover WSS/fallback modes.
- Add release build metadata defaults in a documented build script.
- Consider mTLS or signed client auth beyond bearer-token subprotocol auth.

Post Phase 8 backlog:

- Added GitHub Actions CI workflow at `.github/workflows/ci.yml`.
- CI runs on push and pull request with Go `1.24.4`.
- CI steps: module download, `go test ./...`, `go test -cover ./...`, and `go build -o x-tunnel .`.
- CI also smoke-tests `scripts/build.sh` and `scripts/release.sh`.
- Verified CI build-script smoke locally with `OUT=/tmp/x-tunnel-ci VERSION=ci COMMIT=local BUILD_DATE=ci ./scripts/build.sh`.
- Verified CI release-script smoke locally with `TARGETS=linux/amd64 DIST=/tmp/x-tunnel-dist VERSION=ci COMMIT=local BUILD_DATE=ci ./scripts/release.sh`.
- Added `integration_test.go` to automate the local tunnel matrix inside `go test ./...`.
- Integration test builds a temporary binary and covers WS server, metrics endpoint, SOCKS5 TCP, SOCKS5 UDP relay, TCP forward, HTTP proxy GET, HTTP CONNECT, and wrong-token rejection.
- Added WSS fallback integration coverage with auto self-signed server cert and client `-insecure`.
- Verified WSS fallback integration with `go test ./...`: pass.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 16.3% of statements`.
- Added `integration_test.go`, which builds a temporary x-tunnel binary, starts a real local WS server/client pair, and verifies TCP forward plus HTTP proxy traffic against an `httptest` server.
- Verified with `go test ./...`: pass, including integration test.
- Verified with `go test -cover ./...`: pass, `coverage: 15.7% of statements`.
- Added `scripts/build.sh` to inject `buildVersion`, `buildCommit`, and `buildDate` via `-ldflags`.
- Documented the build script in `README.md`.
- Verified build script with `OUT=$(mktemp) VERSION=0.1.0 COMMIT=testcommit BUILD_DATE=2026-05-16T00:00:00Z ./scripts/build.sh`.
- Verified generated binary output: `x-tunnel version=0.1.0 commit=testcommit build=2026-05-16T00:00:00Z`.
- Added protocol helper benchmarks for smux open headers, chunks, and UDP replies.
- Verified short benchmark run:
  - `BenchmarkSmuxOpenHeaderRoundTrip-8`: `93.25 ns/op`
  - `BenchmarkChunkRoundTrip-8`: `292.3 ns/op`
  - `BenchmarkUDPReplyRoundTrip-8`: `329.8 ns/op`

Post Phase 8 metrics:

- Added optional `-metrics` HTTP endpoint exposing Prometheus-style text at `/metrics`.
- Metrics include server stream count, UDP association count, client reconnect count, and active server session count.
- Documented `-metrics` in `README.md`.
- Added unit coverage for metrics rendering and integration coverage for the `/metrics` endpoint.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 16.3% of statements`.
- Verified real metrics endpoint: `metrics_smoke=pass`, with all four metric names present.

Post Phase 8 config:

- Added `-config` JSON config support.
- Explicit CLI flags override config file values.
- Unknown config fields are rejected with `DisallowUnknownFields`.
- Config rejects trailing JSON values and duplicate `allow_target`/`allow-target` aliases.
- Supported both `allow-target`/`deny-target` and `allow_target`/`deny_target` in JSON config.
- Documented config usage in `README.md`.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 18.1% of statements`.
- Verified CLI help includes `-config` with `go run . -h`.
- Verified real config smoke: `config_smoke=pass hash=9ca571ad702f4922cc9f5d5a07bf231c53298b0bfea8a7e7fed8ef0ac23f2b56 tcp_size=77336`.

Post Phase 8 release packaging:

- Added `scripts/release.sh` for Linux, macOS, and Windows builds across amd64/arm64.
- Release script injects version metadata and writes `SHA256SUMS`.
- Documented release script in `README.md`.
- Verified release script with `TARGETS=linux/amd64`, producing `x-tunnel_0.1.0_linux_amd64` and `SHA256SUMS`.
- Verified release script with `TARGETS=darwin/arm64`, producing `x-tunnel_0.1.0_darwin_arm64`, `SHA256SUMS`, and version output `x-tunnel version=0.1.0 commit=testcommit build=2026-05-16T00:00:00Z`.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 18.1% of statements`.

Post Phase 8 mTLS:

- Added WSS mTLS support.
- Server flag: `-client-ca` requires and verifies client certificates against a CA PEM file.
- Client flags: `-client-cert` and `-client-key` present a client certificate for WSS connections.
- Added JSON config fields `client_ca`, `client_cert`, and `client_key`.
- Added startup validation so `-client-ca` only works on WSS server listeners and client cert/key are only used in WSS client mode.
- Documented mTLS usage in `README.md` and `docs/deployment.md`.
- Added integration test coverage that generates a temporary CA/client cert, verifies no-cert WSS client failure, then verifies certified WSS client TCP forwarding.
- Verified `go run . -h` includes `-client-ca`, `-client-cert`, and `-client-key`.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 19.0% of statements`.

Post Phase 8 runtime tunables:

- Added CLI duration flags for dial timeout, WebSocket handshake timeout, reconnect delay/max/jitter, RTT probe timeout, DNS timeout, ECH retry delay, UDP read timeout, and shutdown timeout.
- Added matching JSON config keys such as `dial_timeout` and `reconnect_max_delay`.
- Added config validation for positive durations, non-negative reconnect jitter, and reconnect max-delay ordering.
- Documented duration config examples in `README.md` and `docs/deployment.md`.
- Verified focused duration/config tests with `go test -run 'Test(LoadConfigFile|ValidateGlobalConfig|ReconnectDelay)' -count=1 ./...`: pass.
- Verified `go run . -h` includes `-dial-timeout`, `-reconnect-max-delay`, and the other duration flags.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 20.7% of statements`.

Post Phase 8 integration stability:

- Added explicit 5s HTTP/client/connection deadlines to integration test helpers.
- This prevents proxy, SOCKS5, and HTTP fetch assertions from hanging indefinitely if a listener is open but the relay path stalls.
- Verified focused integration tests with `go test -run 'TestIntegrationLocal' -count=1 ./...`: pass.
- Verified with `go test ./...`: pass.

Post Phase 8 host target policies:

- Added server `-allow-host` and `-deny-host` target hostname policies with exact and `*.example.com` wildcard matching.
- Host deny rules win before host allow rules; CIDR policies remain authoritative for IP targets.
- Added JSON config aliases `allow_host`/`allow-host` and `deny_host`/`deny-host`.
- Documented host target filtering in `README.md`, `docs/deployment.md`, `docs/troubleshooting.md`, and `docs/protocol.md`.
- Added unit coverage for host policy parsing, wildcard matching, deny precedence, and invalid host patterns.
- Added real integration coverage by proxying an allowed `localhost` target through the HTTP listener.
- Verified focused policy tests with `go test -run 'Test(TargetPolicy|ParseTargetPolicy|LoadConfigFile)' -count=1 ./...`: pass.
- Verified focused real integration with `go test -run TestLocalTunnelIntegration -count=1 ./...`: pass.
- Verified `go run . -h` includes `-allow-host` and `-deny-host`.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 23.1% of statements`.
- Verified external process smoke with HTTP proxy and server `-allow-host localhost`: `host_policy_smoke=pass allow_host=localhost blocked_ip_exit=52`; the `localhost` target succeeded and the `127.0.0.1` target was rejected with server log `TCP 拒绝`.

Post Phase 8 DNS query hardening:

- Hardened DNS query construction for ECH lookups so invalid domains, empty labels, illegal label characters, labels over 63 bytes, and domains over 253 bytes are rejected before encoding.
- DNS query construction now normalizes names to lowercase and rejects labels with leading/trailing hyphens, spaces, underscores, and non-ASCII characters.
- Limited DoH response reads to one DNS message (`65535` bytes) and reject oversized responses.
- Updated UDP DNS and DoH paths to return query construction errors instead of silently truncating label lengths.
- Added unit coverage for valid trailing-dot normalization and invalid DNS names.
- Verified focused DNS tests with `go test -run 'Test(BuildDNSQueryValidatesDomain|QueryDoHRejectsOversizedResponse)' -count=1 ./...`: pass.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 25.2% of statements`.

Post Phase 8 per-client stream limits:

- Added optional server-side `-max-streams` limit for active smux streams per client session.
- Kept default behavior compatible with `0` meaning unlimited.
- Added JSON config aliases `max_streams` and `max-streams`.
- Reject negative values in startup/config validation.
- Added unit coverage for stream accounting, config parsing, duplicate aliases, and validation.
- Documented the limit in `README.md`, `docs/deployment.md`, and `docs/troubleshooting.md`.
- Verified focused stream/config tests with `go test -run 'Test(ClientSessionStreamLimitAccounting|ValidateGlobalConfig|LoadConfigFile)' -count=1 ./...`: pass.
- Verified `go run . -h` includes `-max-streams`.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 26.4% of statements`.
- Verified real process stream-limit smoke with server `-max-streams 1`: `stream_limit_smoke=pass max_streams=1 blocked_exit=52`; one long-lived CONNECT stream stayed open and the next HTTP proxy request was rejected with server log `拒绝新 stream`.

Post Phase 8 SOCKS5 short-read hardening:

- Replaced ignored `io.ReadFull` results in SOCKS5 CONNECT response draining, local SOCKS5 request parsing, and username/password auth parsing.
- Added unit coverage for truncated upstream SOCKS5 bound-address responses and short username/password auth requests.
- Verified focused SOCKS5 tests and the local integration path with `go test -run 'Test(Socks5ConnectRejectsTruncatedBoundAddress|HandleSOCKS5UserPassAuthRejectsShortRequest|LocalTunnelIntegration)' -count=1 ./...`: pass.
- Verified with `go test ./...`: pass.
- Verified with `go test -cover ./...`: pass, `coverage: 27.3% of statements`.

Post Phase 8 client session limits:

- [x] Add an optional server-side `-max-clients` limit for active client sessions.
- [x] Keep default behavior compatible with `0` meaning unlimited.
- [x] Let existing client sessions open additional WebSocket channels even when the limit is reached.
- [x] Reject invalid negative config values at startup/config-load time.
- [x] Add unit coverage, docs, real process smoke, and verification evidence before committing.

Verification:

- `go test -run 'Test(ClientSessionLimitAllowsExistingClient|ClientSessionStreamLimitAccounting|LoadConfigFile|ValidateGlobalConfig)' -count=1 ./...`: pass.
- `go test -run TestIntegrationMaxClientsRejectsNewClient -count=1 ./...`: pass.
- `go run . -h` includes `-max-clients` and `-max-streams`.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 28.1% of statements`.
- Real process smoke with server `-max-clients 1`: `client_limit_smoke=pass max_clients=1 rejected_second_client=1`; the first client negotiated successfully and the second client ID was rejected with server log `拒绝客户端会话`.

Post Phase 8 rejection metrics:

- [x] Add metrics counters for source CIDR, token auth, client-session limit, stream limit, and target-policy rejections.
- [x] Increment counters on the same paths that currently emit rejection logs or HTTP errors.
- [x] Extend metrics unit coverage and docs.
- [x] Run focused metrics tests, full tests, coverage, and commit.

Verification:

- `go test -run TestWriteMetrics -count=1 ./...`: pass.
- `go test -run 'Test(LocalTunnelIntegration|IntegrationMaxClientsRejectsNewClient|WriteMetrics)' -count=1 ./...`: pass; integration assertions verify token and client-session rejection counters through `/metrics`.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 28.4% of statements`.

Post Phase 8 TCP open status:

- [x] Add a negotiated `TCPStatus` capability without changing legacy TCP stream behavior.
- [x] Have new servers send TCP open success/failure status before proxy bytes.
- [x] Have new clients wait for TCP status before returning local SOCKS5/HTTP CONNECT success.
- [x] Add protocol/unit/integration coverage for blocked or failed remote TCP opens.
- [x] Update `docs/protocol.md`, run verification, and commit.

Verification:

- `go test -run 'Test(TCPOpenStatus|ProtocolHello|NegotiateProtocolHello|IntegrationTCPStatusRejectsBlockedTarget)' -count=1 ./...`: pass.
- `go test -run 'Test(TCPOpenStatus|IntegrationTCPStatusRejectsBlockedTarget|HandleSmuxStreamRejectsUnsupportedKind|WriteMetrics|IsSupportedStreamKind)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 29.3% of statements`.

Post Phase 8 unknown stream kinds:

- [x] Add explicit server handling for unsupported smux stream kinds.
- [x] Close unsupported streams without changing existing wire framing.
- [x] Expose an unsupported-stream counter in metrics.
- [x] Update protocol docs and tests, then run focused/full/coverage verification before commit.

Verification:

- `go test -run 'Test(WriteMetrics|IsSupportedStreamKind|HandleSmuxStreamRejectsUnsupportedKind|LocalTunnelIntegration)' -count=1 ./...`: pass.
- `go test -run TestProtocolConstants -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 29.3% of statements`.

Post Phase 8 HTTP proxy TCP failure responses:

- [x] Return an explicit HTTP 502 for ordinary HTTP proxy requests when remote TCP open fails.
- [x] Keep HTTP CONNECT failure behavior returning 502 and SOCKS5 CONNECT returning a SOCKS5 error code.
- [x] Add integration coverage for a target-policy-blocked HTTP proxy request.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `go test -run TestIntegrationTCPStatusRejectsBlockedTarget -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 29.3% of statements`.

Post Phase 8 protocol parser fuzz seeds:

- [x] Add Go fuzz seed tests for smux open headers, protocol hello frames, TCP open status frames, chunks, and UDP replies.
- [x] Keep fuzz tests side-effect free so normal `go test` runs only seed corpora quickly.
- [x] Run focused fuzz seed tests, full tests, coverage, and commit.

Verification:

- `go test -run 'FuzzRead' -count=1 ./...`: pass.
- `go test -run 'Test(SmuxOpenHeader|ProtocolHello|TCPOpenStatus|Chunk|UDPReply)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 29.6% of statements`.

Post Phase 8 config examples:

- [x] Add example JSON configs for local server/client, hardened WSS server, and WSS mTLS client.
- [x] Document how to use examples with `-config`.
- [x] Add test coverage that every example JSON loads and validates common config constraints.
- [x] Run focused example tests, full tests, coverage, and commit.

Verification:

- `go test -run TestExampleConfigFilesLoad -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 30.4% of statements`.

Post Phase 8 UDP block port validation:

- [x] Replace silent `-block` parsing with strict comma-separated port validation.
- [x] Reject non-numeric, partial numeric, zero, and out-of-range ports at startup.
- [x] Preserve empty `-block ""` behavior as no UDP port block list.
- [x] Add unit coverage, docs, full verification, and commit.

Verification:

- `go test -run 'Test(ParseUDPBlockPorts|LoadConfigFileAppliesUnsetFlags)' -count=1 ./...`: pass.
- `go run . -h`: pass and includes `-block`.
- `go run . -l socks5://127.0.0.1:12345 -f ws://127.0.0.1:1/tunnel -block 443abc`: exits non-zero with `-block 参数无效`.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 30.4% of statements`.

Post Phase 8 benchmark expansion:

- [x] Add stable microbenchmarks for target policy checks, DNS query construction, and TCP open-status frames.
- [x] Run a short benchmark pass plus full tests and coverage.
- [x] Record benchmark evidence and commit.

Verification:

- `go test -run '^$' -bench 'Benchmark(TCPOpenStatus|TargetPolicy|BuildDNSQuery)' -benchtime=100ms ./...`: pass.
  - `BenchmarkTCPOpenStatusRoundTrip-8`: `112.2 ns/op`.
  - `BenchmarkTargetPolicyAllowsCIDR-8`: `66.66 ns/op`.
  - `BenchmarkTargetPolicyAllowsHost-8`: `79.98 ns/op`.
- `BenchmarkBuildDNSQuery-8`: `110.9 ns/op`.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 30.4% of statements`.

Post Phase 8 local proxy auth parsing:

- [x] Require local SOCKS5/HTTP listener auth to use complete `user:pass@host:port` syntax.
- [x] Reject incomplete auth instead of silently running without auth.
- [x] Make HTTP listener handle auth parse errors like SOCKS5 listener.
- [x] Add unit coverage, startup smoke, full verification, and commit.

Verification:

- `go test -run 'TestParseAuthAndAddr' -count=1 ./...`: pass.
- `go run . -l http://user@127.0.0.1:12346 -f ws://127.0.0.1:1/tunnel`: exits non-zero with `HTTP地址解析失败`.
- `go run . -l socks5://user@127.0.0.1:12347 -f ws://127.0.0.1:1/tunnel`: exits non-zero with `SOCKS5地址解析失败`.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 30.5% of statements`.

Post Phase 8 listener auth prevalidation:

- [x] Validate SOCKS5/HTTP listener `user:pass@host:port` syntax during global listen-rule validation.
- [x] Reject missing passwords or empty username/password before client pool startup.
- [x] Add unit coverage, focused validation, full tests, coverage, and commit.

Verification:

- `go test -run 'Test(ValidateListenRule|ParseAuthAndAddr)' -count=1 ./...`: pass.
- `go run . -l http://user@127.0.0.1:12346 -f ws://127.0.0.1:1/tunnel`: exits non-zero during listen-rule validation with `监听地址无效`.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 30.7% of statements`.

Post Phase 8 source CIDR metrics integration:

- [x] Add real process integration coverage for source CIDR WebSocket rejection.
- [x] Verify rejected requests return HTTP 403 and increment `x_tunnel_server_source_rejections_total`.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `go test -run TestIntegrationSourceCIDRRejectionMetrics -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 30.4% of statements`.

Post Phase 8 startup validation extraction:

- [x] Extract listener classification and client/server startup validation out of `main`.
- [x] Preserve existing server/client behavior while failing invalid config before metrics, pool, ECH, or listener startup.
- [x] Classify listener schemes from parsed lowercase URLs instead of string prefixes.
- [x] Add unit coverage for TCP forward parsing, listener classification, valid server/client startup config, common invalid startup configs, and example config validation.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `go test -run 'Test(ParseTCPForwardRule|ClassifyListeners|ValidateClientStartupConfig|ValidateServerStartupConfig|ValidateStartupConfig|ValidateListenRule|ExampleConfigFilesLoad|IntegrationSourceCIDRRejectionMetrics)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 34.0% of statements`.

Post Phase 8 source CIDR startup validation:

- [x] Parse and validate server source CIDR filters during startup validation.
- [x] Pass parsed source CIDR networks into the WebSocket server instead of reparsing after startup side effects.
- [x] Reject empty or malformed `-cidr` values with unit coverage.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `go test -run 'Test(ParseSourceCIDRs|ValidateStartupConfig|IntegrationSourceCIDRRejectionMetrics)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 34.6% of statements`.

Post Phase 8 IP strategy startup validation:

- [x] Add strict `-ips` parsing for startup validation while preserving permissive `parseIPStrategy` fallback behavior for legacy callers.
- [x] Store the parsed IP strategy in startup config and reuse it in `main`.
- [x] Reject invalid non-empty `-ips` values with unit coverage.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `go test -run 'Test(ParseIPStrategy|ValidateStartupConfig|ExampleConfigFilesLoad)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 34.8% of statements`.
