# Server One-Click Installer

`scripts/install/server.sh` installs a persistent x-tunnel server on a Linux
host, writes `/etc/x-tunnel/server.json`, creates systemd services, starts the
server, and prints client JSON configs.

The installer supports two exposure modes:

- `cloudflared`: x-tunnel listens on `127.0.0.1`, and a temporary
  `trycloudflare.com` URL forwards public WebSocket traffic to it.
- `direct`: x-tunnel listens on `0.0.0.0`, and clients connect directly to the
  server public IP or DNS name.

## Interactive install

Run as root on the server:

```bash
curl -fsSL https://raw.githubusercontent.com/6Kmfi6HP/x-tunnel/main/scripts/install/server.sh | sh
```

When stdin is a terminal, the script prompts for the exposure mode, listen port,
WebSocket path, token, and metrics address. Press Enter to keep the defaults.

## Non-interactive cloudflared mode

```bash
curl -fsSL https://raw.githubusercontent.com/6Kmfi6HP/x-tunnel/main/scripts/install/server.sh | \
  sh -s -- \
    --non-interactive \
    --mode cloudflared \
    --version v0.2.0 \
    --token 'replace-with-a-long-random-token'
```

This creates:

- `/usr/local/bin/x-tunnel`
- `/etc/x-tunnel/server.json`
- `/etc/systemd/system/x-tunnel.service`
- `/etc/systemd/system/x-tunnel-cloudflared.service`

The output includes a `wss://...trycloudflare.com/tunnel` client `forward`
value. Quick Tunnel domains are temporary and can change after restarting
`x-tunnel-cloudflared.service`.

## Non-interactive direct mode

```bash
curl -fsSL https://raw.githubusercontent.com/6Kmfi6HP/x-tunnel/main/scripts/install/server.sh | \
  sh -s -- \
    --non-interactive \
    --mode direct \
    --version v0.2.0 \
    --public-host 203.0.113.10 \
    --listen-port 18080 \
    --token 'replace-with-a-long-random-token'
```

Direct mode outputs a client `forward` value like:

```text
ws://203.0.113.10:18080/tunnel
```

Open the selected TCP port in the cloud firewall and host firewall before using
direct mode from another machine.

## Server egress proxy and target policy

The installer can configure server-side SOCKS5 egress and target restrictions:

```bash
./scripts/install/server.sh \
  --non-interactive \
  --mode direct \
  --public-host x-tunnel.example.com \
  --upstream-socks5 socks5://user:pass@127.0.0.1:1080 \
  --allow-target 10.0.0.0/8,192.168.0.0/16 \
  --deny-target 10.0.9.0/24 \
  --allow-host api.internal.example.com,*.svc.internal.example.com \
  --max-clients 64 \
  --max-streams 256
```

## Generated client configs

At the end of a successful install, the script prints:

- a standard client config with SOCKS5 and HTTP proxy listeners;
- a client config that includes `websocket_front_proxy` for Baidu-style
  HTTP CONNECT front proxying.

To include a Baidu front-proxy auth header in the printed config:

```bash
./scripts/install/server.sh \
  --non-interactive \
  --mode cloudflared \
  --front-proxy-auth 'replace-with-auth-token'
```

Relevant client output:

```json
{
  "websocket_front_proxy": {
    "enabled": true,
    "type": "http_connect",
    "server": "cloudnproxy.baidu.com:443",
    "connect_host": "sptest.baidu.com",
    "headers": {
      "X-T5-Auth": "replace-with-auth-token"
    }
  }
}
```

The front proxy only wraps the client-to-server WebSocket TCP connection. It
does not change the x-tunnel v2 protocol, token authentication, smux framing, or
server-side egress behavior.

## Useful checks

```bash
systemctl status x-tunnel.service --no-pager
systemctl status x-tunnel-cloudflared.service --no-pager
journalctl -u x-tunnel.service -n 80 --no-pager
journalctl -u x-tunnel-cloudflared.service -n 80 --no-pager
curl -fsS http://127.0.0.1:18081/metrics
```
