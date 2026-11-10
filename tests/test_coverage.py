import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from cklog import coverage as cov


def src(**kw):
    base = dict(kind="chromium", browser="chrome", profile="Default",
                path=r"C:\Users\x\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies",
                rows=100, decrypted=95, failed=5, skipped="", note="")
    base.update(kw)
    return base


class TestManifest(unittest.TestCase):
    def test_totals(self):
        m = cov.manifest({"host": "V", "sources": [src(), src(browser="firefox", rows=50,
                                                               decrypted=50, failed=0)]})
        self.assertEqual(m["totals"]["sources"], 2)
        self.assertEqual(m["totals"]["rows"], 150)
        self.assertEqual(m["totals"]["decrypted"], 145)
        self.assertEqual(m["totals"]["failed"], 5)
        self.assertAlmostEqual(m["totals"]["yield"], round(145 / 150, 4))

    def test_skip_reason_whitelist(self):
        m = cov.manifest({"sources": [src(skipped="v10-fail"), src(skipped="whatever")]})
        self.assertEqual(m["sources"][0]["skipped"], "v10-fail")
        self.assertEqual(m["sources"][1]["skipped"], "")

    def test_bad_input_never_raises(self):
        self.assertEqual(cov.manifest(None)["sources"], [])
        self.assertEqual(cov.manifest({"sources": "nope"})["sources"], [])
        self.assertEqual(cov.manifest({"sources": [1, "x", None]})["sources"], [])

    def test_decrypted_clamped(self):
        m = cov.manifest({"sources": [src(rows=10, decrypted=50, failed=50)]})
        s = m["sources"][0]
        self.assertEqual(s["decrypted"], 10)
        self.assertEqual(s["failed"], 0)


class TestStore(unittest.TestCase):
    def test_append_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            m1 = cov.manifest({"host": "A", "sources": [src()]})
            m2 = cov.manifest({"host": "B", "sources": [src()]})
            p = cov.append(tmp, m1)
            cov.append(tmp, m2)
            self.assertTrue(os.path.isfile(p))
            rows = cov.load_all(tmp)
            self.assertEqual([r["host"] for r in rows], ["A", "B"])
            self.assertIn("A/", cov.summarize(rows[0]))

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(cov.load_all(tmp), [])

    def test_envelope_shape(self):
        env = cov.envelope([{"name": "sid"}], host="V", run="r1", sources=[src()])
        self.assertIn("records", env)
        self.assertIn("coverage", env)
        self.assertEqual(env["coverage"]["totals"]["rows"], 100)


if __name__ == "__main__":
    unittest.main()
