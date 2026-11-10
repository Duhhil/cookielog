import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from cklog import loot


def c(**kw):
    base = dict(_host="V", browser="chrome", profile="Default",
                domain=".example.com", name="sid", path="/", value="a")
    base.update(kw)
    return base


class TestMerge(unittest.TestCase):
    def test_replace_wins(self):
        old = [c(value="old")]
        new = [c(value="new")]
        out = loot.merge(old, new)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["value"], "new")

    def test_profile_does_not_collapse(self):
        out = loot.merge([c(profile="Default")], [c(profile="Profile 1")])
        self.assertEqual(len(out), 2)

    def test_partition_does_not_collapse(self):
        out = loot.merge([c(_partition="a")], [c(_partition="b")])
        self.assertEqual(len(out), 2)

    def test_token_identity_uses_value(self):
        out = loot.merge([c(name="token", value="t1")],
                         [c(name="token", value="t2")])
        self.assertEqual(len(out), 2)

    def test_passwords_do_not_collapse(self):
        out = loot.merge([c(name="password", value="p1", _username="a")],
                         [c(name="password", value="p2", _username="b")])
        self.assertEqual(len(out), 2)

    def test_sink_mode_keeps_first(self):
        out = loot.merge([c(value="old")], [c(value="new")], replace=False)
        self.assertEqual(out[0]["value"], "old")


class TestFilters(unittest.TestCase):
    def test_split(self):
        rows = [c(name="a"), c(name="password"), c(name="b", expires=0)]
        self.assertEqual(len(loot.filter_cookies(rows)), 2)
        self.assertEqual(len(loot.filter_passwords(rows)), 1)
        self.assertEqual(len(loot.filter_session(rows)), 2)   # both non-password rows have no expiry

    def test_expiry_tolerates_junk(self):
        self.assertEqual(loot.expiry({"expires": "nope"}), 0)
        self.assertEqual(loot.expiry({"expirationDate": 123}), 123)


class TestWriters(unittest.TestCase):
    def test_netscape(self):
        body = loot.netscape([c(name="sid", value="v", secure=True, expires=0)])
        line = body.splitlines()[1]
        fields = line.split("\t")
        self.assertEqual(fields[0], ".example.com")
        self.assertEqual(fields[3], "TRUE")
        self.assertEqual(fields[4], "0")
        self.assertEqual(fields[5], "sid")

    def test_json_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "x.json")
            loot.write_json(p, [c()])
            self.assertEqual(len(loot.load_json(p)), 1)
            self.assertEqual(loot.load_json(os.path.join(tmp, "absent.json")), [])


if __name__ == "__main__":
    unittest.main()
