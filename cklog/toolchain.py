# cklog/toolchain.py -- locate the Windows C++ toolchain and run the build
# scripts. The detection mirrors what auto.py grew over time; auto.py keeps its
# own copy until stage 2 replaces it, this module is the authoritative one for
# build.py.
import os
import shutil
import subprocess
import sys


def find_vcvars():
    """Locate vcvars64.bat: vswhere first, then the common install roots."""
    candidates = []
    vswhere = os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                           "Microsoft Visual Studio", "Installer", "vswhere.exe")
    if os.path.isfile(vswhere):
        try:
            r = subprocess.run([vswhere, "-latest", "-products", "*",
                                "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                                "-property", "installationPath"],
                               capture_output=True, text=True, timeout=15)
            root = (r.stdout or "").strip().splitlines()
            if root:
                candidates.append(os.path.join(root[0], r"VC\Auxiliary\Build\vcvars64.bat"))
        except Exception:
            pass
    for root in (os.environ.get("VSINSTALLDIR", ""),
                 r"C:\Program Files\Microsoft Visual Studio\2022\Community",
                 r"C:\Program Files\Microsoft Visual Studio\2022\Professional",
                 r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise",
                 r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"):
        if root:
            candidates.append(os.path.join(root, r"VC\Auxiliary\Build\vcvars64.bat"))
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def msvc_toolset():
    """Newest MSVC toolset directory, or None."""
    vc = find_vcvars()
    if not vc:
        return None
    vc_dir = os.path.dirname(os.path.dirname(os.path.dirname(vc)))   # <install>\VC
    msvc = os.path.join(vc_dir, "Tools", "MSVC")
    if not os.path.isdir(msvc):
        return None
    for ver in sorted(os.listdir(msvc), reverse=True):
        if os.path.isdir(os.path.join(msvc, ver)):
            return os.path.join(msvc, ver)
    return None


def clang_bin():
    """clang-cl.exe's directory: the unpacked LLVM first, then PATH."""
    local = os.path.join(os.environ.get("USERPROFILE", ""), "toolchain",
                         "clang+llvm-19.1.7-x86_64-pc-windows-msvc", "bin")
    if os.path.isfile(os.path.join(local, "clang-cl.exe")):
        return local
    found = shutil.which("clang-cl")
    return os.path.dirname(found) if found else None


def sdk_version():
    """Newest Windows 10/11 SDK that actually ships um headers and x64 libs."""
    base = os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                        "Windows Kits", "10")
    inc = os.path.join(base, "Include")
    if not os.path.isdir(inc):
        return None
    vers = [d for d in os.listdir(inc)
            if d.startswith("10.") and os.path.isfile(os.path.join(inc, d, "um", "windows.h"))]
    vers.sort(key=lambda v: [int(x) for x in v.split(".") if x.isdigit()], reverse=True)
    for v in vers:
        if os.path.isfile(os.path.join(base, "Lib", v, "um", "x64", "kernel32.lib")):
            return v
    return None


def rc_exe(sdk_ver):
    """rc.exe from the unpacked SDK BuildTools package, then the SDK bin tree."""
    bt = os.path.join(os.environ.get("USERPROFILE", ""), "toolchain", "sdkbt", "bin")
    if os.path.isdir(bt):
        for ver in sorted(os.listdir(bt), reverse=True):
            c = os.path.join(bt, ver, "x64", "rc.exe")
            if os.path.isfile(c):
                return c
    if sdk_ver:
        c = os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                         "Windows Kits", "10", "bin", sdk_ver, "x64", "rc.exe")
        if os.path.isfile(c):
            return c
    return None


def clang_ready(root):
    """clang-cl + lld-link + llvm-ml + MSVC headers/libs + SDK libs + rc.exe."""
    if not os.path.isfile(os.path.join(root, "build_clang.bat")):
        return False, "build_clang.bat missing"
    cbin = clang_bin()
    if not cbin:
        return False, "clang-cl.exe not found (unpack LLVM into %USERPROFILE%\\toolchain)"
    for exe in ("clang-cl.exe", "lld-link.exe", "llvm-ml.exe"):
        if not os.path.isfile(os.path.join(cbin, exe)):
            return False, "%s missing next to clang-cl.exe" % exe
    msvc = msvc_toolset()
    if not msvc or not os.path.isfile(os.path.join(msvc, "include", "vcruntime.h")):
        return False, "MSVC headers/libs not found (clang-cl still needs them)"
    if not os.path.isdir(os.path.join(msvc, "lib", "x64")):
        return False, "MSVC x64 libs missing under %s" % msvc
    sdk = sdk_version()
    if not sdk:
        return False, "Windows SDK 10 headers/libs not found"
    um = os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                      "Windows Kits", "10", "Lib", sdk, "um", "x64", "kernel32.lib")
    if not os.path.isfile(um):
        return False, "Windows SDK %s x64 libs missing" % sdk
    if not rc_exe(sdk):
        return False, "rc.exe not found (SDK bin tree or toolchain\\sdkbt)"
    return True, "clang-cl (%s)" % os.path.basename(msvc)


def compiler_ready(root):
    """MSVC first; fall back to clang-cl when the install has headers but no .exe."""
    msvc = msvc_toolset()
    if msvc:
        ver = os.path.basename(msvc)
        cl = os.path.join(msvc, "bin", "Hostx64", "x64", "cl.exe")
        ml = os.path.join(msvc, "bin", "Hostx64", "x64", "ml64.exe")
        if os.path.isfile(cl) and os.path.isfile(ml):
            return True, "MSVC %s" % ver
    ok, info = clang_ready(root)
    if ok:
        return True, info
    if msvc:
        return False, ("cl.exe/ml64.exe missing and no clang fallback: %s -- repair "
                       "'Desktop development with C++' in the Visual Studio Installer"
                       % info)
    return False, info


def run_script(root, name, timeout=600):
    """Run a build .bat with cmd/c. Returns (ok, combined_output)."""
    script = os.path.join(root, name)
    if not os.path.isfile(script):
        return False, "missing %s" % name
    if sys.platform != "win32":
        return False, "build scripts are Windows-only; ship prebuilt bin/ on Linux"
    try:
        r = subprocess.run(["cmd", "/c", script], cwd=root,
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "%s timed out after %ss" % (name, timeout)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    return r.returncode == 0, out
