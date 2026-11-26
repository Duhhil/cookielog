import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from cklog import dllproxy


def make_pe(machine=0x8664, magic=0x20B, dotnet=False, with_exports=True,
            eat=(0x1400, 0x1404, 0x1100), names=None, base=5):
    """Small PE32+ image with one file-backed section at RVA 0x1000."""
    blob = bytearray(0xA00)
    blob[:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x80)
    blob[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", blob, 0x84, machine)
    struct.pack_into("<H", blob, 0x86, 1)       # NumberOfSections
    struct.pack_into("<H", blob, 0x94, 0xF0)    # SizeOfOptionalHeader
    struct.pack_into("<H", blob, 0x96, 0x2022)  # executable, DLL, large-address-aware
    opt = 0x98
    struct.pack_into("<H", blob, opt, magic)
    struct.pack_into("<I", blob, opt + 60, 0x200)
    struct.pack_into("<I", blob, opt + 108, 16)
    if with_exports:
        struct.pack_into("<II", blob, opt + 112, 0x1000, 0x200)
    if dotnet:
        struct.pack_into("<II", blob, opt + 112 + 14 * 8, 0x1500, 72)

    sec = opt + 0xF0
    blob[sec:sec + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", blob, sec + 8, 0x800, 0x1000, 0x800, 0x200)
    if not with_exports:
        return bytes(blob)

    names = {0: (b"Alpha",), 2: (b"Beta",)} if names is None else names
    nfuncs = len(eat)
    nnames = sum(len(rows) for rows in names.values())
    # Characteristics, timestamp, versions, Name, Base, counts, and three RVAs.
    struct.pack_into("<IIHHIIIIIII", blob, 0x200,
                     0, 0, 0, 0, 0, base, nfuncs, nnames,
                     0x1040, 0x1080, 0x1060)  # functions, names, name ordinals
    for i, rva in enumerate(eat):
        struct.pack_into("<I", blob, 0x240 + i * 4, rva)
    flat_names = []
    for index in sorted(names):
        for name in names[index]:
            flat_names.append((index, name))
    next_name = 0x1300
    for i, (index, name) in enumerate(flat_names):
        struct.pack_into("<H", blob, 0x260 + i * 2, index)
        struct.pack_into("<I", blob, 0x280 + i * 4, next_name)
        raw = next_name - 0x1000 + 0x200
        blob[raw:raw + len(name) + 1] = name + b"\0"
        next_name += len(name) + 1
    if 0x1100 in eat:
        blob[0x300:0x300 + 13] = b"OTHER.Target\0"
    return bytes(blob)


def put_u32(blob, offset, value):
    mutable = bytearray(blob)
    struct.pack_into("<I", mutable, offset, value)
    return bytes(mutable)


class TestExports(unittest.TestCase):
    def test_named_ordinal_only_alias_and_forwarded_exports(self):
        blob = make_pe(names={0: (b"Alpha",), 2: (b"Beta", b"Alias")})
        rows = dllproxy.parse_exports(blob)
        self.assertEqual([row.ordinal for row in rows], [5, 6, 7])
        self.assertEqual(rows[0].names, ("Alpha",))
        self.assertEqual(rows[1].names, ())
        self.assertEqual(rows[2].names, ("Alias", "Beta"))
        self.assertIsNone(rows[0].forwarder)
        self.assertEqual(rows[2].forwarder, "OTHER.Target")

    def test_no_export_directory_and_null_eat_slots(self):
        self.assertEqual(dllproxy.parse_exports(make_pe(with_exports=False)), [])
        rows = dllproxy.parse_exports(make_pe(eat=(0, 0x1400), names={}))
        self.assertEqual([(row.ordinal, row.rva) for row in rows], [(6, 0x1400)])

    def test_rejects_non_x64_and_dotnet(self):
        with self.assertRaisesRegex(dllproxy.PEError, "x64"):
            dllproxy.parse_exports(make_pe(machine=0x14C))
        with self.assertRaisesRegex(dllproxy.PEError, "PE32+"):
            dllproxy.parse_exports(make_pe(magic=0x10B))
        with self.assertRaisesRegex(dllproxy.PEError, ".NET"):
            dllproxy.parse_exports(make_pe(dotnet=True))

    def test_rejects_malformed_headers_and_ranges(self):
        cases = [
            b"not a PE",
            make_pe()[:100],
            put_u32(make_pe(), 0x3C, 0xFFFFFF00),
            put_u32(make_pe(), 0x98 + 60, 0x10000),
            put_u32(make_pe(), 0x200 + 16, 0xFFFFFF00),  # ordinal base overflows
            put_u32(make_pe(), 0x200 + 28, 0x17FC),       # EAT crosses raw data
            put_u32(make_pe(), 0x200 + 32, 0x17FC),       # names table crosses raw data
            put_u32(make_pe(), 0x200 + 36, 0x17FE),       # ordinal table crosses raw data
        ]
        for blob in cases:
            with self.subTest(blob=blob[:16]), self.assertRaises(dllproxy.PEError):
                dllproxy.parse_exports(blob)

    def test_rejects_bad_name_ordinal_and_unterminated_string(self):
        bad_ordinal = bytearray(make_pe())
        struct.pack_into("<H", bad_ordinal, 0x260, 9)
        with self.assertRaisesRegex(dllproxy.PEError, "ordinal"):
            dllproxy.parse_exports(bytes(bad_ordinal))
        unterminated = bytearray(make_pe())
        unterminated[0x500:0xA00] = b"A" * 0x500
        with self.assertRaisesRegex(dllproxy.PEError, "unterminated"):
            dllproxy.parse_exports(bytes(unterminated))


class TestDef(unittest.TestCase):
    def test_forwarding_preserves_names_ordinals_and_noname(self):
        text = dllproxy.generate_def(make_pe(), r"C:\vendor\original.dll")
        self.assertIn("    Alpha=original_ck.#5 @5\r\n", text)
        self.assertIn("    __ck_ordinal_6=original_ck.#6 @6 NONAME\r\n", text)
        self.assertIn("    Beta=original_ck.#7 @7\r\n", text)
        self.assertNotIn("OTHER.Target=", text)  # Forward through the sibling instead.

    def test_custom_sibling_must_be_a_plain_dll_name(self):
        text = dllproxy.generate_def(make_pe(), "original.dll", "renamed.dll")
        self.assertIn("Alpha=renamed.#5", text)
        with self.assertRaises(dllproxy.PEError):
            dllproxy.generate_def(make_pe(), "original.dll", r"folder\renamed.dll")
        with self.assertRaises(dllproxy.PEError):
            dllproxy.generate_def(make_pe(), "original.dll", "ORIGINAL.DLL")
        with self.assertRaises(dllproxy.PEError):
            dllproxy.generate_def(make_pe(), "original.exe")

    def test_payload_export_conflict_is_rejected(self):
        for name in ("payload_entry", "noop", "entry_stub"):
            blob = make_pe(names={0: (name.encode(),), 2: ()})
            with self.subTest(name=name), self.assertRaisesRegex(dllproxy.PEError, "conflict"):
                dllproxy.generate_def(blob, "original.dll")

    def test_executable_is_not_a_dll_proxy_target(self):
        blob = bytearray(make_pe())
        characteristics = struct.unpack_from("<H", blob, 0x96)[0]
        struct.pack_into("<H", blob, 0x96, characteristics & ~0x2000)
        with self.assertRaisesRegex(dllproxy.PEError, "DLL"):
            dllproxy.parse_exports(bytes(blob))


class TestProxyPatch(unittest.TestCase):
    def test_patches_only_explicit_proxy_slot(self):
        blob = bytearray(make_pe(with_exports=False))
        blob[0x188:0x190] = b".data\0\0"
        blob[0x300:0x300 + len(dllproxy.C2_SENTINEL)] = dllproxy.C2_SENTINEL
        fd, path = tempfile.mkstemp(suffix=".dll")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
            offset = dllproxy.patch_proxy_c2(path, "http://127.0.0.1:9000/")
            self.assertEqual(offset, 0x300)
            with open(path, "rb") as f:
                patched = f.read()
            self.assertEqual(patched[:0x300], blob[:0x300])
            self.assertEqual(patched[0x400:], blob[0x400:])
            self.assertTrue(patched[0x300:0x400].startswith(b"http://127.0.0.1:9000/\0"))
            self.assertEqual(patched[0x300 + 23:0x400], b"\0" * (256 - 23))
            with self.assertRaises(dllproxy.PEError):
                dllproxy.patch_proxy_c2(path, "http://127.0.0.1:9000/")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
