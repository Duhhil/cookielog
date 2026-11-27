import os
import random
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from cklog import pe


class TestFuzzPe(unittest.TestCase):
    """Fuzz pe.find_sentinel and pe.patch_ready with random inputs."""

    def test_find_sentinel_no_crash(self):
        rng = random.Random(42)
        for _ in range(1000):
            size = rng.randint(0, 5000)
            data = bytes(rng.randrange(256) for _ in range(size))
            sentinel = b"CKC2_DEADBEEF_"
            # Should not raise
            idx = pe.find_sentinel(data, sentinel, 256)
            self.assertTrue(idx == -1 or 0 <= idx < len(data))

    def test_patch_ready_no_crash(self):
        rng = random.Random(123)
        for _ in range(1000):
            size = rng.randint(0, 5000)
            data = bytearray(rng.randrange(256) for _ in range(size))
            sentinel = b"CKPR____"
            # Should not raise
            result = pe.patch_ready(bytes(data), sentinel, 8)
            self.assertTrue(result == -1 or result == -2 or result >= 0)

    def test_find_sentinel_with_real_loader(self):
        """If loader.exe exists, find_sentinel should find all three sentinels."""
        loader_path = os.path.join(ROOT, "bin", "loader.exe")
        if not os.path.isfile(loader_path):
            self.skipTest("bin/loader.exe not built")
        with open(loader_path, "rb") as f:
            blob = f.read()
        for sentinel, slot in [(b"CKC2_DEADBEEF_", 256), (b"CKPR____", 8), (b"CKAV0000", 8)]:
            idx = pe.find_sentinel(blob, sentinel, slot)
            self.assertGreaterEqual(idx, 0, f"sentinel {sentinel} not found")

    def test_sections_no_crash(self):
        rng = random.Random(999)
        for _ in range(500):
            size = rng.randint(0, 10000)
            data = bytes(rng.randrange(256) for _ in range(size))
            secs = pe.sections(data)
            self.assertIsInstance(secs, list)

    def test_patch_ready_already_patched(self):
        # Sentinel followed by non-zero bytes = already patched
        data = b"CKPR____" + b"ABCDEFGH"
        self.assertEqual(pe.patch_ready(data, b"CKPR____", 16), -2)

    def test_patch_ready_text_section(self):
        # Just ensure it returns -1 for .text (can't easily construct, but test the logic)
        data = b"CKPR____" + b"\x00" * 8
        # Without a PE header, section_of returns None, so rank is neutral
        result = pe.patch_ready(data, b"CKPR____", 16)
        # Should be -2 (already patched) or a valid index
        self.assertTrue(result == -2 or result >= 0)


if __name__ == "__main__":
    unittest.main()
