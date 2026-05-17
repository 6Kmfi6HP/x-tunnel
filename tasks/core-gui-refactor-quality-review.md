# Core / GUI Refactor Quality Review

Date: 2026-05-17
Scope: current working tree against `docs/core-gui-refactor.md`

## Summary

- Verdict: Ready for release after commit, push, and tag.
- Release version planned: `v0.4.0`.
- Triage:
  - Docs-only: no.
  - React/Next perf review: no.
  - UI guidelines audit: no.
  - Reason: Go runtime, control API, CLI, docs, and CI workflow changes.

## Requirements Checklist

- Existing CLI stays usable: `RunCLI` still accepts existing flags and config files; integration tests pass.
- Core lifecycle exists: `NewEngine`, `Start`, `Close`, `Wait`, and `Status` implemented in `internal/app/engine.go`.
- Startup errors return errors: local listeners, WS/WSS server, metrics, and control API pre-bind before reporting success.
- Config check/format does not start tunnel listeners: `CheckConfigJSON` and `FormatConfigJSON` use in-memory JSON payloads.
- Sidecar contract exists: `-control`, `-ready-file`, and `-control-token-file`; ready file is written after control bind.
- Control API exists: version, health, status, logs, metrics, config check, config format, runtime stop.
- Security basics covered: loopback-only control bind, bearer token auth, constant-time token compare, no default CORS, no file-path config API.
- Redaction basics covered: status/logs avoid token fields and redact URL userinfo.
- GUI profile switching model remains restart-based: no reload API was added.
- Public Go API remains deferred: no `pkg/core` was added.

## Issues Found And Fixed During Review

- `FormatConfigJSON` only indented JSON and did not normalize alias keys. It now canonicalizes aliases such as `allow-target` to `allow_target`.
- `Engine.Close` before `Start` could wait for context timeout because `done` was never closed. It now closes immediately.
- `-ready-file` / `-control-token-file` without `-control` silently did nothing. `NewEngine` now rejects that option combination.
- `RuntimeOptions.Logger` was defined but unused. The log ring now also forwards complete log lines to the supplied logger.
- CI fuzz smoke referenced non-existent `FuzzReadProtocolHello`. It now uses existing `FuzzReadSmuxOpenHeader`.
- README did not document the sidecar control API. It now documents sidecar flags, ready/token behavior, and endpoints.

## Residual Deferrals

- Stage 3 global-state cleanup remains intentionally deferred by the plan. The current release targets the sidecar/lifecycle milestone and still treats x-tunnel as one Engine per process.
- Hot reload, reload-plan endpoints, events/log streaming, named pipes, and public `pkg/core` remain out of scope for this release.

## Verification Evidence

- `git diff --check`: passed.
- `test -z "$(gofmt -l ./cmd ./internal)"`: passed.
- `go vet ./...`: passed.
- `go test -count=1 -timeout=2m ./...`: passed.
- `go test -race -count=1 -timeout=3m ./...`: passed.
- `go test -cover -count=1 -timeout=2m ./...`: passed.
- `go test -run '^$' -fuzz FuzzReadSmuxOpenHeader -fuzztime=2s -parallel=1 ./internal/app`: passed.
- `go test -run '^$' -fuzz FuzzParseSOCKS5UDPPacket -fuzztime=2s -parallel=1 ./internal/app`: passed.
- `OUT=/tmp/x-tunnel-core-gui-build VERSION=v0.4.0 ... ./scripts/build.sh && /tmp/x-tunnel-core-gui-build -version`: passed.
- `TARGETS='linux/amd64' DIST=/tmp/x-tunnel-release-v040-smoke VERSION=v0.4.0 ... ./scripts/release.sh`: passed and wrote `SHA256SUMS`.
- Real local smoke: server + client sidecars, ready files, token auth, status/logs, SOCKS5 payload, TCP-forward payload, runtime stop, and external `https://example.com/` through SOCKS5 returned `HTTP/2 200`.
- Docker local smoke: skipped because Docker daemon was not running locally.
