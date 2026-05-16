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
- [x] Extract SOCKS5 parsing/building helpers if it reduces single-file risk without broad churn.
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

Post Phase 8 SOCKS5 and DNS parser fuzz seeds:

- [x] Add fuzz seeds for client SOCKS5 UDP request parsing.
- [x] Add fuzz seeds for SOCKS5 UDP response parsing.
- [x] Add fuzz seeds for DNS HTTPS response parsing.
- [x] Add fuzz seeds for HTTPS record parameter parsing.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `go test -run 'Fuzz(ParseSOCKS5UDP|ParseDNSResponse|ParseHTTPSRecord)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 38.2% of statements`.

Post Phase 8 ECH DNS startup validation:

- [x] Validate `-ech` DNS names and `-dns` DoH/UDP endpoints before ECH network lookup.
- [x] Only require ECH DNS validation for `wss://` clients when fallback is disabled.
- [x] Add unit coverage for valid and invalid ECH lookup config plus startup rejection.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `go test -run 'Test(BuildDNSQuery|ValidateECHLookupConfig|ValidateStartupConfig|ExampleConfigFilesLoad)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 38.2% of statements`.

Post Phase 8 protocol negotiation metrics:

- [x] Add server counters for protocol negotiation success, rejection, and failure.
- [x] Add client counters for protocol negotiation success, legacy fallback, and failure.
- [x] Extend metrics unit and integration assertions.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `go test -run 'Test(WriteMetrics|LocalTunnelIntegration|IntegrationMaxClientsRejectsNewClient|IntegrationTCPStatusRejectsBlockedTarget|NegotiateProtocolHello)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 38.4% of statements`.

Post Phase 8 protocol metrics integration values:

- [x] Expose metrics on the client side during local tunnel integration.
- [x] Assert server protocol negotiation success counter increments after a real client hello.
- [x] Assert client protocol negotiation success counter increments after a real server response.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `go test -run TestLocalTunnelIntegration -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 38.4% of statements`.

Post Phase 8 upstream SOCKS5 auth validation:

- [x] Require upstream SOCKS5 proxy auth to use complete `user:pass@host:port` syntax.
- [x] Reject missing password, empty username/password, and empty proxy host during server startup validation.
- [x] Add unit coverage for parser and server startup validation.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `go test -run 'Test(ParseSOCKS5Addr|ValidateServerStartupConfig|ValidateStartupConfig|ExampleConfigFilesLoad)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 38.5% of statements`.

Post Phase 8 CI race testing:

- [x] Add Go race detector test to GitHub Actions.
- [x] Verify `go test -race ./...` locally.
- [x] Run full tests and coverage after workflow change.
- [x] Commit workflow and task log.

Verification:

- `go test -race ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 38.6% of statements`.

Post Phase 8 SOCKS5 UDP port validation:

- [x] Reject SOCKS5 UDP request packets with destination port 0.
- [x] Reject upstream SOCKS5 UDP responses with source port 0.
- [x] Reject SOCKS5 UDP packet construction when port is outside 1-65535.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestSOCKS5UDP(Packet|Resp)Malformed|TestBuildSOCKS5UDPPacketRejects(InvalidPort|OversizedDomain)|FuzzParseSOCKS5UDP' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 38.7% of statements`.

Post Phase 8 server hello deadline:

- [x] Set a read/write deadline while handling protocol hello streams on the server.
- [x] Clear the hello stream deadline after the negotiation branch finishes.
- [x] Add a half-open hello stream unit test that verifies the handler returns and increments failure metrics.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestHandleSmuxStreamHelloDeadline|TestHandleSmuxStreamRejectsUnsupportedKind|Test(ReadProtocolHelloMalformed|NegotiateProtocolHello)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 39.0% of statements`.

Post Phase 8 SOCKS5 UDP header strict validation:

- [x] Require SOCKS5 UDP request packets to have zero RSV and FRAG fields.
- [x] Require upstream SOCKS5 UDP response packets to have zero RSV and FRAG fields.
- [x] Add malformed packet coverage and protocol documentation.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `go test -run 'Test(SOCKS5UDPPacket|SOCKS5UDPResp|BuildSOCKS5UDPPacket|ParseSOCKS5Addr|ValidateServerStartupConfig)' -count=1 ./...`: pass.
- `go test -race ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 38.6% of statements`.

Post Phase 8 local proxy auth integration:

- [x] Add integration helpers for authenticated HTTP proxy requests, HTTP CONNECT, and SOCKS5 username/password handshakes.
- [x] Assert local HTTP proxy auth rejects missing and wrong credentials.
- [x] Assert local SOCKS5 auth rejects missing and wrong credentials.
- [x] Assert correct HTTP and SOCKS5 credentials can fetch through a real WS tunnel.
- [x] Ensure HTTP proxy auth headers are not forwarded to the origin server.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run TestIntegrationLocalProxyAuth -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 39.0% of statements`.

Post Phase 8 protocol hello rejection handler coverage:

- [x] Send an unsupported protocol version hello through the smux handler.
- [x] Assert the server writes an unsupported-version protocol response.
- [x] Assert the server protocol rejection counter increments without recording a failure.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestHandleSmuxStreamRejectsUnsupportedProtocolHello|TestHandleSmuxStreamHelloDeadline|Test(NegotiateProtocolHello|ProtocolHello)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 39.3% of statements`.

Post Phase 8 upstream SOCKS5 auth integration:

- [x] Add a real fake upstream SOCKS5 proxy that requires username/password auth.
- [x] Verify server `-f socks5://user:pass@proxy` can proxy TCP through that upstream to an origin.
- [x] Verify wrong upstream SOCKS5 credentials fail as an HTTP 502 through the local client proxy.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run TestIntegrationUpstreamSOCKS5Auth -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 39.3% of statements`.

Post Phase 8 local SOCKS5 method negotiation:

- [x] Reject authenticated listeners when the client does not offer username/password method.
- [x] Reject unauthenticated listeners when the client does not offer no-auth method.
- [x] Add unit coverage for method rejection and update integration assertions.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(HandleSOCKS5RejectsMissing|HandleSOCKS5UserPassAuthRejectsShortRequest|IntegrationLocalProxyAuth)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 39.7% of statements`.

Post Phase 8 SOCKS5 TCP port validation:

- [x] Reject upstream SOCKS5 CONNECT targets with non-numeric, zero, or out-of-range ports before writing a request.
- [x] Reject local SOCKS5 CONNECT requests with destination port 0 while preserving UDP ASSOCIATE behavior.
- [x] Add focused unit coverage for both paths.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(Socks5ConnectRejects|HandleSOCKS5Rejects|HandleSOCKS5UserPassAuthRejectsShortRequest)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 40.3% of statements`.

Post Phase 8 upstream SOCKS5 auth method enforcement:

- [x] Offer only username/password auth to upstream SOCKS5 proxies when credentials are configured.
- [x] Reject upstream proxies that select a method the client did not offer.
- [x] Add unit coverage for forced user/pass and invalid no-auth selection.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(Socks5Handshake|IntegrationUpstreamSOCKS5Auth)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 41.4% of statements`.

Post Phase 8 SOCKS5 auth credential length validation:

- [x] Reject upstream SOCKS5 usernames/passwords over 255 bytes before encoding RFC1929 auth.
- [x] Reject local SOCKS5 listener auth over 255 bytes during listener validation.
- [x] Keep HTTP proxy auth parsing behavior unchanged.
- [x] Add focused unit coverage and run full verification before commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(ValidateListenRule|ParseSOCKS5Addr|Socks5UserPassAuthSrv|Socks5Handshake)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 41.7% of statements`.

Post Phase 8 startup validation subprocess smoke:

- [x] Build the real binary once for invalid startup cases.
- [x] Verify bad metrics, bad listener auth, bad CIDR, bad IP strategy, and bad upstream SOCKS auth exit non-zero.
- [x] Assert each failure is emitted from startup validation with `[配置]` in logs.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run TestIntegrationStartupValidationFailures -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 41.7% of statements`.

Post Phase 8 UDP strict port parsing:

- [x] Reject UDP target addresses with non-numeric, zero, or out-of-range ports in IP strategy resolution.
- [x] Avoid emitting SOCKS5 UDP response packets when the remote reply address has an invalid port.
- [x] Replace remaining UDP `fmt.Sscanf` port parsing with checked parsing.
- [x] Add focused unit coverage and run full verification before commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(ResolveUDPWithStrategyRejectsInvalidPort|UDPAssociationHandleUDPResponseRejectsInvalidPort|SOCKS5UDPPacket|SOCKS5UDPResp)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 42.1% of statements`.

Post Phase 8 SOCKS5 UDP associate relay validation:

- [x] Reject upstream SOCKS5 UDP ASSOCIATE responses with unknown address types.
- [x] Reject upstream SOCKS5 UDP ASSOCIATE responses with relay port 0.
- [x] Resolve relay hosts with `net.JoinHostPort` so IPv6 relay addresses are handled correctly.
- [x] Add focused unit coverage and run full verification before commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestNewSOCKS5UDPRelay' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 44.5% of statements`.

Post Phase 8 HTTP proxy auth rejection unit coverage:

- [x] Add direct `handleHTTP` coverage for missing proxy auth.
- [x] Add direct `handleHTTP` coverage for wrong Basic proxy auth.
- [x] Assert both responses are HTTP 407 with `Proxy-Authenticate`.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(HandleHTTPRejectsProxyAuth|ParseAuthAndAddr)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 44.5% of statements`.

Post Phase 8 SOCKS5 unsupported command response:

- [x] Return SOCKS5 status `0x07` for unsupported local SOCKS5 commands.
- [x] Preserve CONNECT and UDP ASSOCIATE behavior.
- [x] Add focused unit coverage for BIND/unsupported command handling.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(HandleSOCKS5RejectsZeroConnectPort|HandleSOCKS5RejectsUnsupportedCommand|HandleSOCKS5RejectsMissing)' -count=1 ./...`: pass.
- `go test ./...`: pass.
- `go test -cover ./...`: pass, `coverage: 44.7% of statements`.

Post Phase 8 SOCKS5 unsupported address response:

- [x] Return SOCKS5 status `0x08` for unsupported local SOCKS5 address types.
- [x] Preserve existing IPv4/domain/IPv6 parsing behavior.
- [x] Add focused unit coverage for unknown ATYP handling.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestHandleSOCKS5Rejects(UnsupportedAddressType|UnsupportedCommand|ZeroConnectPort|Missing)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 44.8% of statements`.

Post Phase 8 HTTP proxy target validation:

- [x] Extract HTTP proxy target authority normalization.
- [x] Reject empty, malformed, or Host/absolute-URL mismatch targets before opening a tunnel.
- [x] Preserve CONNECT default port 443 and HTTP default port 80 behavior.
- [x] Add focused unit coverage and run full verification before commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(HTTPProxyTarget|HandleHTTPRejectsMalformedProxyTarget)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 45.7% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 SOCKS5 UDP empty domain validation:

- [x] Reject SOCKS5 UDP request packets with empty domain names.
- [x] Reject upstream SOCKS5 UDP responses with empty domain names.
- [x] Reject SOCKS5 UDP packet construction with an empty host.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(SOCKS5UDPPacket|SOCKS5UDPResp|BuildSOCKS5UDPPacket)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 45.7% of statements`.

Post Phase 8 CI test timeout hardening:

- [x] Add explicit Go test timeouts to CI test, coverage, and race steps.
- [x] Disable Go test cache in CI with `-count=1`.
- [x] Keep existing build and release smoke steps unchanged.
- [x] Run local equivalents before commit.

Verification:

- `go test -count=1 -timeout=2m ./...`: pass.
- `go test -cover -count=1 -timeout=2m ./...`: pass, `coverage: 45.7% of statements`.
- `go test -race -count=1 -timeout=3m ./...`: pass.
- `go build -o /tmp/x-tunnel-ci-local .`: pass.
- `OUT=/tmp/x-tunnel-ci VERSION=ci COMMIT=local BUILD_DATE=ci ./scripts/build.sh`: pass.
- `/tmp/x-tunnel-ci -version`: pass, `x-tunnel version=ci commit=local build=ci`.
- `TARGETS=linux/amd64 DIST=/tmp/x-tunnel-dist VERSION=ci COMMIT=local BUILD_DATE=ci ./scripts/release.sh`: pass.
- `test -s /tmp/x-tunnel-dist/SHA256SUMS`: pass.

Post Phase 8 protocol writer short-write hardening:

- [x] Add a shared write-all helper for protocol frame writers.
- [x] Use it for protocol hello, TCP open status, smux open header, chunks, and UDP replies.
- [x] Add focused tests that fail on short writes without errors.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(ProtocolWritersRejectShortWritesWithoutError|WriteAllHandlesProgressiveShortWrites|ProtocolHelloRoundTrip|TCPOpenStatusRoundTrip|SmuxOpenHeaderRoundTrip|ChunkRoundTrip|UDPReplyRoundTrip)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 46.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 smux stream target validation:

- [x] Reject TCP/UDP smux streams with empty or malformed target addresses before dial/relay setup.
- [x] Preserve ping/hello streams without targets.
- [x] Return TCP open-status errors when the client negotiated TCP status capability.
- [x] Add focused unit coverage and run full verification before commit.

Post Phase 8 HTTP proxy absolute-form scheme validation:

- [x] Reject non-CONNECT absolute-form URLs unless the scheme is `http`.
- [x] Preserve CONNECT and origin-form behavior.
- [x] Add focused target parser and handler coverage.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(HTTPProxyTarget|HandleHTTPRejectsMalformedProxyTarget|HandleHTTPRejectsUnsupportedAbsoluteFormScheme|ValidateSmuxStreamTarget|HandleSmuxStreamRejectsMalformedTCPTargetWithStatus)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 46.3% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 host:port whitespace validation:

- [x] Reject host:port values containing spaces, tabs, or line breaks.
- [x] Preserve empty-host listen addresses such as `:8080`.
- [x] Add focused coverage for direct host:port, listen rules, and smux targets.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(ValidateHostPortRejectsWhitespace|ValidateListenRule|ValidateSmuxStreamTarget)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 46.4% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 SOCKS5 UDP short domain and IPv6 response parsing:

- [x] Accept valid SOCKS5 UDP packets with one-byte domains and no payload.
- [x] Parse IPv6 SOCKS5 UDP responses using bracketed host:port formatting.
- [x] Preserve malformed packet rejection for short headers, empty domains, missing ports, and zero ports.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestSOCKS5UDP(Resp|Packet)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 46.6% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 HTTP/TCPStatus documentation alignment:

- [x] Document supported HTTP proxy request forms and rejected absolute-form schemes.
- [x] Clarify TCPStatus local client failure mapping for target policy and dial failures.
- [x] Keep protocol capability wording aligned with implementation behavior.
- [x] Run focused documentation-relevant tests and full test verification before commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(HTTPProxyTarget|HandleHTTPRejectsUnsupportedAbsoluteFormScheme|HandleSmuxStreamRejectsMalformedTCPTargetWithStatus|IntegrationTCPStatusRejectsBlockedTarget)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 46.6% of statements`.

Post Phase 8 local SOCKS5 request header validation:

- [x] Reject local SOCKS5 requests whose request header RSV byte is non-zero.
- [x] Reject username/password auth sub-negotiation when the auth version is not `0x01`.
- [x] Add focused tests for malformed RSV and auth version.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestHandleSOCKS5(UserPassAuthRejectsInvalidVersion|UserPassAuthRejectsShortRequest|RejectsNonzeroRequestReservedByte|RejectsZeroConnectPort|RejectsUnsupportedCommand|RejectsUnsupportedAddressType)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 46.7% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 upstream SOCKS5 response header validation:

- [x] Validate upstream SOCKS5 username/password auth response version.
- [x] Validate upstream SOCKS5 CONNECT response `VER` and `RSV` bytes.
- [x] Validate upstream SOCKS5 UDP ASSOCIATE response `VER` and `RSV` bytes.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(Socks5UserPassAuthSrv|Socks5Connect|NewSOCKS5UDPRelay)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 47.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 integration metrics assertion precision:

- [x] Replace substring-based metric value assertions with exact metric-name/value matching.
- [x] Keep broad metrics presence checks unchanged.
- [x] Update integration assertions for protocol, auth, source, client limit, and target rejection counters.
- [x] Run focused integration/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(LocalTunnelIntegration|IntegrationMaxClientsRejectsNewClient|IntegrationSourceCIDRRejectionMetrics|IntegrationTCPStatusRejectsBlockedTarget)$' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 46.7% of statements`.

Post Phase 8 UDP reply malformed frame tests:

- [x] Add explicit `readUDPReply` coverage for short headers.
- [x] Add explicit coverage for truncated address and payload fields.
- [x] Preserve existing round-trip and fuzz coverage.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(UDPReplyRoundTrip|ReadUDPReplyMalformed|UDPReplyRejectsOversizedFields)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 47.1% of statements`.

Post Phase 8 max-clients existing session regression:

- [x] Add a real forwarded request through the first client after a second client is rejected.
- [x] Keep existing rejection log and metric assertions intact.
- [x] Run focused/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run TestIntegrationMaxClientsRejectsNewClient -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 47.3% of statements`.

Post Phase 8 smux ping stream deadline:

- [x] Apply `RTTProbeTimeout` while the server reads ping payloads.
- [x] Preserve normal ping echo behavior.
- [x] Add focused tests for ping echo and half-open ping streams.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(HandleSmuxStreamPing|IntegrationMaxClientsRejectsNewClient)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 47.3% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 target policy documentation truth table:

- [x] Add a target policy decision table for IP/domain targets across CIDR and host rules.
- [x] Clarify host wildcard and pre-DNS security boundary semantics.
- [x] Run focused policy tests plus full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(TargetPolicy|ParseTargetPolicy|ValidateServerStartupConfig|IntegrationTCPStatusRejectsBlockedTarget)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 47.3% of statements`.

Post Phase 8 SOCKS5 method preference regression tests:

- [x] Confirm existing method rejection logic covers missing no-auth and missing user/pass methods.
- [x] Add regression coverage for multi-method greetings selecting the configured method.
- [x] Run focused SOCKS5/full/coverage verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestHandleSOCKS5(RejectsMissingUserPassMethod|RejectsMissingNoAuthMethod|SelectsConfiguredMethod|UserPassAuthRejectsInvalidVersion|UserPassAuthRejectsShortRequest)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 47.3% of statements`.

Post Phase 8 smux IP strategy validation:

- [x] Reject TCP smux streams with unknown `ip_strategy` values and return TCPStatus errors when negotiated.
- [x] Reject UDP smux streams with unknown `ip_strategy` values before relay setup.
- [x] Document the invalid strategy behavior in the protocol notes.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(ParseIPStrategy|ValidateIPStrategyValue|HandleSmuxStreamRejectsInvalid.*IPStrategy|HandleSmuxStreamRejectsMalformedTCPTargetWithStatus)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 47.8% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 smux open header deadline:

- [x] Apply `RTTProbeTimeout` while the server reads smux open headers and target bytes.
- [x] Preserve normal stream behavior by clearing the deadline after a complete header.
- [x] Add focused tests for half-open headers and truncated target bytes.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestHandleSmuxStream(OpenHeaderDeadline|TruncatedOpenHeaderTargetDeadline|PingDeadline|HelloDeadline|RejectsInvalid.*IPStrategy)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 47.9% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 SOCKS5 UDP association target binding:

- [x] Drop packets whose SOCKS5 UDP target differs from the association's bound target.
- [x] Add unit coverage that same-target packets still write and changed-target packets do not.
- [x] Document the single-target association behavior.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(UDPAssociationSendWritesBoundTarget|UDPAssociationSendDropsChangedTarget|UDPAssociationHandleUDPResponseRejectsInvalidPort|SOCKS5UDPPacket|SOCKS5UDPResp)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 50.8% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 HTTP CONNECT buffered early data:

- [x] Forward bytes already buffered by `http.ReadRequest` after a successful CONNECT response.
- [x] Preserve existing CONNECT and non-CONNECT proxy behavior.
- [x] Add focused handleHTTP coverage for CONNECT headers and first tunnel bytes in one write.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(UDPAssociationSend|HandleHTTPConnectForwardsBufferedClientBytes|HandleHTTPRejectsMalformedProxyTarget|HandleHTTPRejectsUnsupportedAbsoluteFormScheme|HTTPProxyTarget|LocalTunnelIntegration)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 50.8% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 integration process diagnostics:

- [x] Wrap started x-tunnel subprocesses with log path and exit status.
- [x] Let `waitTCP` fail fast with subprocess logs when a watched process exits before the port opens.
- [x] Pass watched processes to key server/client listener waits.
- [x] Run focused integration/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(LocalTunnelIntegration|IntegrationLocalProxyAuth|IntegrationMaxClientsRejectsNewClient|IntegrationTCPStatusRejectsBlockedTarget)$' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 51.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 active runtime metrics:

- [x] Expose active server channels as a gauge.
- [x] Expose active server streams as a gauge, including unlimited `max-streams=0` mode.
- [x] Expose active SOCKS5 UDP associations as a gauge.
- [x] Document active runtime gauges in README and troubleshooting guidance.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(WriteMetrics|ClientSessionStreamLimitAccounting|LocalTunnelIntegration|IntegrationMaxClientsRejectsNewClient|IntegrationTCPStatusRejectsBlockedTarget)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 51.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 integration binary reuse:

- [x] Build the x-tunnel integration test binary once per test process.
- [x] Reuse the binary across integration tests instead of rebuilding per case.
- [x] Clean the shared integration build directory from `TestMain`.
- [x] Run focused integration/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(LocalTunnelIntegration|IntegrationLocalProxyAuth|IntegrationLocalWSSFallback|IntegrationLocalWSSMTLS|IntegrationMaxClientsRejectsNewClient|IntegrationTCPStatusRejectsBlockedTarget|IntegrationStartupValidationFailures)$' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 51.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 integration log wait diagnostics:

- [x] Let `waitLogContains` fail fast when a watched x-tunnel process exits before the expected log appears.
- [x] Pass watched processes to key client/server log waits.
- [x] Run focused integration/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(LocalTunnelIntegration|IntegrationLocalProxyAuth|IntegrationUpstreamSOCKS5Auth|IntegrationLocalWSSMTLS|IntegrationMaxClientsRejectsNewClient|IntegrationTCPStatusRejectsBlockedTarget)$' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 51.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Post Phase 8 SOCKS5 upstream short-write handling:

- [x] Use `writeAll` for upstream SOCKS5 method greeting writes.
- [x] Use `writeAll` for upstream username/password auth and CONNECT request writes.
- [x] Use `writeAll` for upstream SOCKS5 UDP ASSOCIATE request writes.
- [x] Add focused net.Conn short-write regression tests and commit after full verification.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(Socks5HandshakeHandlesProgressiveShortWrites|UpstreamSOCKS5WritersRejectShortWrites|Socks5UserPassAuthSrvHandlesProgressiveShortWrites|Socks5ConnectHandlesProgressiveShortWrites|ProtocolWritersRejectShortWritesWithoutError|WriteAllHandlesProgressiveShortWrites)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 51.2% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Upstream SOCKS5 request writers now use `writeAll`, so progressive short writes are completed and silent short writes fail with `io.ErrShortWrite`.
- Focused short-write regressions plus full, coverage, and race suites passed.

Post Phase 8 local proxy response short-write handling:

- [x] Add local SOCKS5 response writer helpers for method selection, auth replies, fixed command replies, and UDP ASSOCIATE replies.
- [x] Use `writeAll` for local SOCKS5 method selection, auth, CONNECT failure/success, unsupported command, and UDP ASSOCIATE responses.
- [x] Use `writeAll` for local SOCKS5 UDP ASSOCIATE replies.
- [x] Use `writeAll` for local HTTP proxy status responses and buffered first request writes.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(LocalProxyResponseWriters|WriteSOCKS5UDPAssociateReplyRejectsInvalidAddress|HandleSOCKS5|HandleHTTP|HTTPProxyTarget|WriteAllHandlesProgressiveShortWrites|ProtocolWritersRejectShortWritesWithoutError)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 53.4% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Local SOCKS5 and HTTP proxy responses now complete progressive short writes and expose silent short writes as `io.ErrShortWrite` through shared helpers.
- UDP ASSOCIATE replies now validate the response address and port before writing the protocol frame.

Post Phase 8 SOCKS5 UDP target-policy integration:

- [x] Reuse the SOCKS5 UDP integration setup so success and no-response cases share the same handshake path.
- [x] Assert a blocked SOCKS5 UDP target produces no UDP response.
- [x] Assert blocked UDP increments `x_tunnel_server_target_rejections_total` and logs `UDP 拒绝`.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestIntegrationTCPStatusRejectsBlockedTarget$' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 53.4% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- The target-policy integration now proves blocked SOCKS5 UDP targets do not receive relay responses.
- The same test asserts UDP rejections are observable through both server logs and `x_tunnel_server_target_rejections_total`.

Post Phase 8 UDP datagram short-write checks:

- [x] Add a shared UDP datagram writer that rejects silent short writes.
- [x] Use the helper for direct UDP relays, upstream SOCKS5 UDP relays, and local SOCKS5 UDP responses.
- [x] Add focused tests for short writes, impossible over-writes, normal writes, and error propagation.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(WriteUDPDatagram|UDPAssociationHandleUDPResponseRejectsInvalidPort|UDPAssociationSendWritesBoundTarget|UDPAssociationSendDropsChangedTarget|WriteAllCount|WriteAllHandlesProgressiveShortWrites)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 53.7% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- UDP datagram writes now treat silent short writes and impossible byte counts as `io.ErrShortWrite`.
- Direct UDP relay writes, upstream SOCKS5 UDP relay writes, and SOCKS5 UDP client response writes share the same guard.

Post Phase 8 WebSocket frame short-write handling:

- [x] Add a counted `writeAll` helper so `net.Conn`-style writers can preserve bytes-written semantics.
- [x] Use the counted helper in `wsNetConn.Write` to complete progressive WebSocket frame short writes.
- [x] Return `io.ErrShortWrite` from WebSocket frame writes that stop making progress.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(WriteUDPDatagram|UDPAssociationHandleUDPResponseRejectsInvalidPort|UDPAssociationSendWritesBoundTarget|UDPAssociationSendDropsChangedTarget|WriteAllCount|WriteAllHandlesProgressiveShortWrites)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 53.7% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- `wsNetConn.Write` now uses counted full-write behavior while preserving the `net.Conn` byte-count return contract.
- The shared counted writer keeps the original `writeAll` API simple for protocol encoders.

Post Phase 8 SOCKS5 CONNECT target validation:

- [x] Reject invalid upstream SOCKS5 CONNECT `host:port` targets before writing a request.
- [x] Reject local SOCKS5 CONNECT empty or malformed domain targets before opening a remote stream.
- [x] Add focused tests for empty domain and invalid host targets.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(Socks5ConnectRejectsInvalidTargetPort|ReadLocalSOCKS5RequestMalformedReplyStatus|ReadLocalSOCKS5Request|HandleSOCKS5RejectsZeroConnectPort)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 54.2% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Upstream SOCKS5 CONNECT now rejects malformed `host:port` targets before writing any request bytes.
- Local SOCKS5 CONNECT parsing maps empty or invalid domain-style targets to a failed SOCKS5 reply instead of opening a stream.

Post Phase 8 local SOCKS5 request parser extraction:

- [x] Extract local SOCKS5 command/address/port parsing from `handleSOCKS5`.
- [x] Preserve existing SOCKS5 reply codes for bad RSV, unsupported ATYP, zero CONNECT port, and unsupported command.
- [x] Add focused parser tests for valid IPv4/domain/IPv6 requests and malformed request statuses.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(ReadLocalSOCKS5Request|HandleSOCKS5Rejects|HandleSOCKS5MethodSelection|HandleSOCKS5UserPassAuth|HandleSOCKS5UDPAssociate)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 54.2% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- `handleSOCKS5` now delegates command/address/port parsing to `readLocalSOCKS5Request`, keeping policy and dispatch logic separate from byte parsing.
- Parser tests cover IPv4, domain, IPv6, bad RSV, unsupported ATYP, zero CONNECT port, and truncated input.

Post Phase 8 wsNetConn adapter coverage:

- [x] Add a real `httptest` WebSocket pair helper for wsNetConn tests.
- [x] Cover binary frame writes and partial reads through `wsNetConn`.
- [x] Cover local/remote addresses, deadline forwarding, close signaling, and recorded dead errors.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestWSNetConn' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 56.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- wsNetConn now has real WebSocket adapter coverage for binary frame writes, buffered partial reads, deadline forwarding, address accessors, and close/dead signaling.
- The test uses `httptest` plus gorilla/websocket rather than mocks, so it exercises the same frame APIs used by smux channels.

Post Phase 8 CI parser fuzz smoke:

- [x] Add short CI fuzz smoke for the protocol hello parser.
- [x] Add short CI fuzz smoke for the SOCKS5 UDP packet parser.
- [x] Run both fuzz smoke commands locally plus full test verification.
- [x] Commit the workflow update with verification notes.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestWSNetConn' -count=1 ./...`: pass.
- `go test -run '^$' -fuzz FuzzReadProtocolHello -fuzztime=2s -parallel=1 ./...`: pass.
- `go test -run '^$' -fuzz FuzzParseSOCKS5UDPPacket -fuzztime=2s -parallel=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 56.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- CI now runs bounded fuzz smoke for protocol hello and SOCKS5 UDP packet parsing after the normal race test.
- The local run did not create repository fuzz corpus files; generated interesting inputs stayed in Go's fuzz cache.

Post Phase 8 HTTP proxy hop-by-hop header stripping:

- [x] Strip `Proxy-Connection` before forwarding ordinary HTTP proxy requests.
- [x] Keep local consumption/removal of `Proxy-Authorization` in the same helper.
- [x] Update protocol docs for forwarded HTTP proxy headers.
- [x] Add focused unit coverage and run full verification before commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(StripHTTPProxyHeaders|HandleHTTP|HTTPProxyTarget)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 56.1% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Ordinary HTTP proxy requests now remove locally consumed `Proxy-Authorization`, proxy-only `Proxy-Connection`, fields named by `Connection`, and common hop-by-hop headers before forwarding.
- `docs/protocol.md` now documents the forwarded-header boundary for HTTP proxy requests.

Post Phase 8 HTTP proxy header integration:

- [x] Extend local proxy auth integration to capture headers seen by the origin server.
- [x] Send a raw authenticated HTTP proxy request with `Proxy-Authorization`, `Proxy-Connection`, `Connection`, and a connection-named header.
- [x] Assert proxy-only and hop-by-hop headers are absent at the origin while end-to-end headers survive.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestIntegrationLocalProxyAuth$' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 56.1% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- The authenticated HTTP proxy integration now verifies the origin never sees `Proxy-Authorization`, `Proxy-Connection`, `Connection`, or a connection-named header.
- The same real request verifies an end-to-end header survives forwarding, so the cleanup is scoped rather than blanket-stripping request metadata.

Post Phase 8 protocol standards references:

- [x] Add stable standards references for SOCKS5, SOCKS5 username/password auth, and HTTP semantics.
- [x] Clarify that x-tunnel's documented local proxy behavior is derived from those references plus project-specific target-policy rules.
- [x] Run docs-focused verification and full tests before commit.

Verification:

- `git diff --check`: pass.
- `rg -n "RFC 1928|RFC 1929|RFC 9110|target-policy|hop-by-hop" docs/protocol.md`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 56.1% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- `docs/protocol.md` now links the SOCKS5, username/password auth, and HTTP semantics RFCs used as external protocol baselines.
- The local proxy sections now separate standards-derived parsing from x-tunnel-specific target validation and policy checks.

Post Phase 8 ClientSession channel lifecycle tests:

- [x] Add a lightweight real `*websocket.Conn` helper for channel lifecycle tests.
- [x] Cover `addChannel` auto IDs, preferred IDs, and replacement closing the old channel.
- [x] Cover `removeChannel` ignoring stale channel pointers and cleaning `serverSessions` when the last current channel is removed.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestClientSession(ChannelLifecycle|StreamLimitAccounting|LimitAllowsExistingClient)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 57.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Client session channel lifecycle now has unit coverage for auto IDs, preferred IDs, replacement close behavior, stale remove protection, and final session cleanup.
- The test uses real websocket connections from the existing adapter helper, avoiding unsafe fake `*websocket.Conn` construction.

Post Phase 8 benchmark coverage refresh:

- [x] Add microbenchmarks for SOCKS5 UDP packet round-trips, HTTP proxy header stripping, and counted full writes.
- [x] Run a short benchmark pass plus full/coverage/race verification.
- [x] Record benchmark evidence and commit.

Verification:

- `git diff --check`: pass.
- `go test -run '^$' -bench 'Benchmark(SOCKS5UDPPacketRoundTrip|StripHTTPProxyHeaders|WriteAllCount)' -benchtime=100ms ./...`: pass.
  - `BenchmarkSOCKS5UDPPacketRoundTrip-8`: `245.4 ns/op`.
  - `BenchmarkStripHTTPProxyHeaders-8`: `459.4 ns/op`.
  - `BenchmarkWriteAllCount-8`: `2.962 ns/op`.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 57.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Benchmark coverage now includes today's SOCKS5 UDP packet, HTTP header cleanup, and counted full-write paths.

Post Phase 8 HTTP proxy Via header:

- [x] Add local HTTP proxy handling that appends `Via: 1.1 x-tunnel` to forwarded non-CONNECT requests.
- [x] Preserve existing `Via` values using standard header append semantics.
- [x] Prove CONNECT tunnel payload bytes remain opaque and do not get proxy-added request headers.
- [x] Add unit and real integration coverage for the forwarded `Via` behavior.
- [x] Update protocol documentation, run focused/full/coverage/race verification, and commit.

Verification:

- `git diff --check`: pass.
- `rg -n "Via: 1\\.1 x-tunnel|CONNECT tunnel payload" docs/protocol.md integration_test.go x-tunnel.go x_tunnel_test.go`: pass.
- `go test -run 'Test(AddHTTPProxyViaHeader|StripHTTPProxyHeaders)$' -count=1 ./...`: pass.
- `go test -run 'TestIntegrationLocalProxyAuth$' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 57.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Ordinary HTTP proxy forwarding now appends `Via: 1.1 x-tunnel` while preserving upstream `Via` values.
- The authenticated proxy integration proves the origin sees both upstream and x-tunnel `Via` values on ordinary HTTP, while CONNECT-originated request bytes stay free of proxy-added `Via`.

Post Phase 8 HTTP/WebSocket auth interop:

- [x] Accept WebSocket token authentication when the client offers the token inside a subprotocol list.
- [x] Parse local HTTP proxy Basic auth case-insensitively and tolerate normal optional whitespace.
- [x] Clear request close state so stripped `Connection: close` is not regenerated on forwarded HTTP proxy requests.
- [x] Add focused unit coverage and run full/coverage/race verification before commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(WebSocketRequestHasToken|ValidHTTPProxyBasicAuth|SanitizeHTTPProxyRequestClearsCloseState|HandleHTTPRejectsProxyAuth)$' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 57.2% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- WebSocket token auth now accepts a valid token anywhere in the offered `Sec-WebSocket-Protocol` list while still rejecting partial or missing tokens.
- Local HTTP proxy auth now accepts normal Basic auth casing/whitespace variants, and sanitized ordinary HTTP forwarding no longer regenerates `Connection: close` after stripping hop-by-hop headers.

Post Phase 8 target hostname validation:

- [x] Reject non-IP target hosts that are not valid DNS hostnames before opening TCP/UDP tunnel streams.
- [x] Apply the same hostname validation to HTTP proxy authorities and local SOCKS5 CONNECT domain targets.
- [x] Add focused boundary tests and update protocol documentation.
- [x] Run full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(ValidateHostPort|ValidateListenRule|HTTPProxyTarget|HandleHTTPRejectsMalformedProxyTarget|ReadLocalSOCKS5RequestMalformedReplyStatus|ReadLocalSOCKS5Request|EnsureTargetAllowed)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 57.6% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Target `host:port` validation now rejects non-IP hosts that are not valid DNS hostnames before smux stream creation.
- HTTP proxy authorities and local SOCKS5 CONNECT domain targets now fail locally instead of reaching remote DNS/dial paths.

Post Phase 8 target policy wrapper coverage:

- [x] Add direct `ensureTargetAllowed` coverage for nil policy, allowed target, and denied target errors.
- [x] Verify global `targetPolicy` is restored after tests.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- Covered by the focused/full/coverage/race verification in the target hostname validation batch.

Review:

- `ensureTargetAllowed` now has direct coverage for nil policy, allowed CIDR target, outside-allow CIDR rejection, and denied host rejection.

Post Phase 8 UDP relayer method coverage:

- [x] Add loopback coverage for `DirectUDPRelayer` read/write/deadline/close behavior.
- [x] Add loopback coverage for `SOCKS5UDPRelay` packet-wrapped read/write behavior and idempotent close.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(DirectUDPRelayerRoundTrip|SOCKS5UDPRelayRoundTripAndClose|HandleHTTPPostOpensStreamBeforeBodyComplete|HandleHTTPConnectForwardsBufferedClientBytes)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 59.2% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Direct UDP relay and SOCKS5 UDP relay methods now have loopback coverage for datagram wrapping, reads, writes, deadlines, and close behavior.

Post Phase 8 HTTP proxy request body streaming:

- [x] Forward ordinary HTTP proxy requests directly to the smux stream instead of buffering the full request in memory.
- [x] Preserve forwarded request headers, `Via`, body framing, and CONNECT behavior.
- [x] Add a focused test proving the smux stream opens before a POST body is fully sent.
- [x] Run full/coverage/race verification and commit.

Verification:

- Covered by the focused/full/coverage/race verification in the UDP relayer method coverage batch.

Review:

- Ordinary HTTP proxy requests now open the smux stream before waiting for the full request body, then stream `Request.Write` directly to the tunnel.
- The focused POST test proves forwarded headers reach the smux stream before the delayed body is sent, while existing CONNECT buffered-byte coverage remains intact.

Post Phase 8 client protocol negotiation coverage:

- [x] Add smux-level coverage for successful client hello negotiation.
- [x] Add coverage for legacy hello close/error classification.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(NegotiateClientProtocol|IsLegacyProtocolHelloError)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 60.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Client-side protocol negotiation now has smux-level coverage for successful hello request/response handling.
- Legacy hello close and timeout/EOF classification now have direct regression tests.

Post Phase 8 SOCKS5 UDP relay read bounds:

- [x] Return an error when an upstream SOCKS5 UDP response payload exceeds the caller buffer.
- [x] Add focused unit coverage so `SOCKS5UDPRelay.Read` never returns `n > len(buffer)`.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestSOCKS5UDPRelay(ReadRejectsOversizedPayload|RoundTripAndClose)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 60.0% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- `SOCKS5UDPRelay.Read` now returns an explicit oversize error instead of returning a length larger than the caller buffer.

Post Phase 8 SOCKS5 UDP relay close/read race:

- [x] Synchronize `SOCKS5UDPRelay.Read` access to the relay closed state.
- [x] Add focused coverage proving `Close` unblocks a pending `Read`.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestSOCKS5UDPRelay(ReadUnblocksOnClose|ReadRejectsOversizedPayload|RoundTripAndClose)' -count=1 ./...`: pass.
- `go test -race -run 'TestSOCKS5UDPRelayReadUnblocksOnClose' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 60.1% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- `SOCKS5UDPRelay.Read` now snapshots `closed` under the relay mutex, matching `Write` and `Close`.
- The close/unblock regression covers pending UDP reads during relay shutdown.

Post Phase 8 SOCKS5 UDP hostname strictness:

- [x] Reject invalid DNS hostname fields while parsing SOCKS5 UDP request and response packets.
- [x] Reject invalid non-IP hostnames when building SOCKS5 UDP packets.
- [x] Add focused malformed packet and builder coverage.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(SOCKS5UDPPacketMalformed|SOCKS5UDPRespMalformed|BuildSOCKS5UDPPacketRejectsInvalidDomain|SOCKS5UDPPacketRoundTrip|SOCKS5UDPResp|ResolveUDPWithStrategy(LiteralIPs|LocalhostFamilies|RejectsInvalidPort))' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 61.3% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- SOCKS5 UDP request and response packet parsing now rejects invalid DNS hostname fields after packet decoding.
- SOCKS5 UDP packet building now rejects invalid non-IP hostnames before emitting a domain-form packet.

Post Phase 8 hostname trailing-dot compatibility:

- [x] Preserve valid trailing-dot DNS hostnames while rejecting malformed hostnames.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestValidateHostPortRejectsWhitespace' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 59.2% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Hostname validation now trims one trailing root dot before validating labels, matching the existing target-policy normalization behavior.

Post Phase 8 UDP resolve strategy coverage:

- [x] Cover literal IPv4/IPv6 UDP targets resolving without DNS regardless of strategy.
- [x] Cover localhost IPv4-only, IPv6-only, and preferred-family resolution when the address family exists locally.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- Covered by the focused SOCKS5 UDP verification command above.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 61.3% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Literal IP UDP resolution now has regression coverage proving strategy selection only affects DNS names.
- Localhost family tests adapt to the address families present on the host, keeping the coverage portable.

Post Phase 8 UDP reply frame address validation:

- [x] Reject empty or malformed source addresses when writing internal UDP reply frames.
- [x] Reject empty or malformed source addresses when reading internal UDP reply frames.
- [x] Document the UDP reply frame address validity requirement.
- [x] Add focused malformed read/write coverage.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'Test(UDPReply|ReadUDPReplyMalformed|DialViaSocks5AuthProxy)' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 61.6% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- Internal UDP reply frame write/read paths now reject empty or malformed source addresses before the payload is accepted.
- The protocol doc now records that UDP reply `addr bytes` must be a valid non-empty `host:port` source address.

Post Phase 8 upstream SOCKS5 dial coverage:

- [x] Add direct `dialViaSocks5` coverage through an authenticated local SOCKS5 proxy.
- [x] Verify the returned connection can exchange bytes with a TCP echo target.
- [x] Run focused/full/coverage/race verification and commit.

Verification:

- `git diff --check`: pass.
- `go test -run 'TestDialViaSocks5AuthProxy' -count=1 ./...`: pass.
- `go test -count=1 ./...`: pass.
- `go test -cover -count=1 ./...`: pass, `coverage: 61.6% of statements`.
- `go test -race -count=1 ./...`: pass.

Review:

- `dialViaSocks5` now has direct coverage through an authenticated local SOCKS5 proxy.
- The returned proxied TCP connection is verified with a real byte exchange against a one-shot TCP echo target.
