import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from cklog import build as B
from cklog import pe


class TestSections(unittest.TestCase):
    def test_non_pe(self):
        self.assertEqual(pe.sections(b"not a pe"), [])
        self.assertEqual(pe.sections(b"MZ" + b"\0" * 10), [])

    def test_loader_sections(self):
        p = os.path.join(ROOT, "bin", "loader.exe")
        if not os.path.isfile(p):
            self.skipTest("bin/loader.exe not built")
        secs = pe.sections(B.read(p))
        names = [s[0] for s in secs]
        self.assertIn(".data", names)
        self.assertIn(".text", names)


class TestSentinel(unittest.TestCase):
    def setUp(self):
        p = os.path.join(ROOT, "bin", "loader.exe")
        if not os.path.isfile(p):
            self.skipTest("bin/loader.exe not built")
        self.blob = B.read(p)

    def test_c2_slot_is_writable(self):
        idx = pe.find_sentinel(self.blob, b"CKC2_DEADBEEF_", 256)
        self.assertGreater(idx, 0)
        # clang-cl may place the array in .rdata (read-only at runtime, patched
        # on disk); what must never happen is picking the .text immediate.
        self.assertIn(pe.section_of(self.blob, idx), (".data", ".rdata"))
        self.assertEqual(pe.patch_ready(self.blob, b"CKC2_DEADBEEF_", 256), idx)
        # the 256-byte slot is the only hit followed by that much zero padding
        self.assertEqual(self.blob[idx + 14:idx + 256], b"\0" * (256 - 14))

    def test_eight_byte_slots(self):
        for s in (b"CKPR____", b"CKAV0000"):
            idx = pe.patch_ready(self.blob, s, 8)
            self.assertGreaterEqual(idx, 0, s)
            self.assertNotEqual(pe.section_of(self.blob, idx), ".text")

    def test_patch_c2_roundtrip(self):
        sentinel = b"CKC2_DEADBEEF_"
        idx = pe.patch_ready(self.blob, sentinel, 256)
        url = b"http://example.invalid:9415/"
        blob = self.blob[:idx] + url + b"\0" * (256 - len(url)) + self.blob[idx + 256:]
        # the global is overwritten; the memcmp literal elsewhere may survive
        self.assertNotIn(sentinel, blob[idx:idx + 256])
        self.assertIn(url, blob)

    def test_already_patched_slot(self):
        blob = b"CKPR____" + b"ABCDEFGH"
        self.assertEqual(pe.patch_ready(blob, b"CKPR____", 16), -2)


if __name__ == "__main__":
    unittest.main()
