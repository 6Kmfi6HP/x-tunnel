# x-tunnel config examples

These JSON files are starting points for `./x-tunnel -config <file>`.

- `local-server.json`: loopback WS server for local development.
- `local-client.json`: local SOCKS5, HTTP proxy, and TCP forward listeners.
- `hardened-server.json`: exposed WSS server with source CIDR, target policy, resource limits, metrics, and runtime timeouts.
- `wss-mtls-client.json`: WSS client with mTLS credentials and conservative reconnect settings.

Replace placeholder tokens, hostnames, CIDRs, ports, and certificate paths before use.
