# Release Process

This repository publishes two release surfaces from the same tag:

- GitHub Release assets: cross-platform `x-tunnel` binaries plus `SHA256SUMS`.
- GHCR container images: multi-architecture Linux images for `linux/amd64` and
  `linux/arm64`.

## Release Trigger

Create and push a semantic version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Tags must match `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-prerelease`, for
example `v0.1.0` or `v0.1.0-rc.1`. The workflow can also be run manually with
an existing tag through `workflow_dispatch`.

## CI Gates

`.github/workflows/release.yml` verifies the tag before publishing:

1. Check out the exact tag.
2. Validate the tag format and that the tag exists.
3. Run `gofmt`, `go vet`, `go test ./...`, and `go test -race ./...`.
4. Smoke-test `scripts/release.sh` for `linux/amd64`.

Publishing only starts after these gates pass.

## GitHub Release Assets

The `github-release` job runs:

```bash
VERSION="$RELEASE_TAG" COMMIT="$(git rev-parse --short=12 HEAD)" ./scripts/release.sh
```

The release uploads every file under `dist/`. Current default targets are:

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`
- `windows/arm64`

The job is idempotent: if the GitHub Release already exists, it re-uploads the
assets with `--clobber`; otherwise it creates a release for the verified tag and
generates release notes.

## GHCR Images

The `container` job builds `Dockerfile` with Buildx and pushes to:

```text
ghcr.io/<owner>/<repo>
```

The workflow lowercases the image name because OCI image references are
lowercase. A stable tag such as `v0.1.0` publishes:

- `ghcr.io/<owner>/<repo>:v0.1.0`
- `ghcr.io/<owner>/<repo>:0.1.0`
- `ghcr.io/<owner>/<repo>:0.1`
- `ghcr.io/<owner>/<repo>:0`
- `ghcr.io/<owner>/<repo>:latest`
- `ghcr.io/<owner>/<repo>:sha-<commit>`

A prerelease tag such as `v0.1.0-rc.1` publishes only the version and commit
tags, not `latest`, major, or minor tags.

## Required Permissions

The workflow uses the built-in `GITHUB_TOKEN`:

- `contents: write` creates or updates the GitHub Release.
- `packages: write` pushes the GHCR image.

No personal access token is required for releases and packages in the same
repository.

## Rollback Notes

Do not move an already-published tag unless the release has never been consumed.
For a bad release, create a new patch tag and publish it through the same
workflow. If a GHCR tag was published incorrectly, delete or retag the package in
GitHub Packages and make the GitHub Release notes point to the corrected patch
version.

## Local Release Checks

Before tagging, run:

```bash
go test ./...
go test -race ./...
VERSION=v0.1.0 TARGETS="linux/amd64" DIST=/tmp/x-tunnel-dist ./scripts/release.sh
cat /tmp/x-tunnel-dist/SHA256SUMS
```

If Docker is available locally, smoke-test the image:

```bash
docker build -t x-tunnel:local .
docker run --rm x-tunnel:local -version
```
