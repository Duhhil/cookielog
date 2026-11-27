"""cklog/log.py — structured JSON logging for cookielog.

Writes one JSON object per line to a .jsonl file. Each entry has a timestamp,
level, and arbitrary key-value pairs. Used by listen.py and auto.py for
observability without changing the human-readable console output.
"""
import json
import os
import time


class JsonLogger:
    """Append-only JSON Lines logger."""

    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def log(self, level="info", **kwargs):
        entry = {"ts": time.time(), "level": level}
        entry.update(kwargs)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def info(self, **kwargs):
        self.log("info", **kwargs)

    def warn(self, **kwargs):
        self.log("warn", **kwargs)

    def error(self, **kwargs):
        self.log("error", **kwargs)

    def metric(self, name, value, **kwargs):
        self.log("metric", metric=name, value=value, **kwargs)
