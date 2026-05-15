#!/usr/bin/env sh
set -eu

version="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
commit="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
build_date="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
dist="${DIST:-dist}"
targets="${TARGETS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}"

mkdir -p "${dist}"
: >"${dist}/SHA256SUMS"

for target in ${targets}; do
  goos="${target%/*}"
  goarch="${target#*/}"
  ext=""
  if [ "${goos}" = "windows" ]; then
    ext=".exe"
  fi
  out="${dist}/x-tunnel_${version}_${goos}_${goarch}${ext}"
  printf 'building %s/%s -> %s\n' "${goos}" "${goarch}" "${out}"
  GOOS="${goos}" GOARCH="${goarch}" go build \
    -ldflags "-s -w -X main.buildVersion=${version} -X main.buildCommit=${commit} -X main.buildDate=${build_date}" \
    -o "${out}" \
    .
  (cd "${dist}" && shasum -a 256 "$(basename "${out}")" >>SHA256SUMS)
done

printf 'release artifacts written to %s\n' "${dist}"
