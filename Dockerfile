# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.24.4

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" go build \
    -trimpath \
    -ldflags "-s -w -X main.buildVersion=${VERSION} -X main.buildCommit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/x-tunnel \
    ./cmd/x-tunnel

FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG SOURCE_REPOSITORY=https://github.com/6Kmfi6HP/x-tunnel

LABEL org.opencontainers.image.title="x-tunnel" \
      org.opencontainers.image.description="WebSocket tunnel with SOCKS5, HTTP proxy, and TCP forwarding listeners." \
      org.opencontainers.image.source="${SOURCE_REPOSITORY}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=build /out/x-tunnel /usr/local/bin/x-tunnel

USER nonroot:nonroot
EXPOSE 11080 18080

ENTRYPOINT ["/usr/local/bin/x-tunnel"]
