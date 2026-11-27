"""auto/network.py — IP detection, port scanning, C2 reachability.

Extracted from auto.py to keep the orchestrator thin. All public names are
re-exported by auto.py so existing imports and tests keep working.
"""
import socket
import urllib.parse
import urllib.request


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
    """Check if IP is a private/LAN address (RFC 1918)."""
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
        parts = ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return ip
        return None
    except Exception:
        return None


def find_best_port(start=9400, end=9500, preferred=None):
    """Scan a range of ports and return the first one that is free."""
    if preferred:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("0.0.0.0", preferred))
            s.close()
            return preferred
        except (OSError, socket.error):
            pass

    for p in range(start, end + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("0.0.0.0", p))
            s.close()
            return p
        except (OSError, socket.error):
            continue
    return None


def check_c2_reachable(c2_url, timeout=4):
    """Best-effort TCP connect to the C2 host:port."""
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


def find_port_owner_pid(port):
    """Return (pid, cmdline) of whatever is LISTENing on port, or (None, None)."""
    import subprocess
    import re
    try:
        if __import__("sys").platform == "win32":
            out = subprocess.run(["netstat", "-ano", "-p", "tcp"],
                                  capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[3].upper() == "LISTENING" and parts[1].endswith(":%d" % port):
                    pid = int(parts[4])
                    cl = subprocess.run(["powershell", "-NoProfile", "-Command",
                                          "(Get-CimInstance Win32_Process -Filter 'ProcessId=%d').CommandLine" % pid],
                                         capture_output=True, text=True, timeout=10)
                    return pid, (cl.stdout or "").strip()
        else:
            out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                if ":%d " % port not in line and not line.rstrip().endswith(":%d" % port):
                    continue
                m = re.search(r'pid=(\d+)', line)
                if not m:
                    continue
                pid = int(m.group(1))
                try:
                    with open("/proc/%d/cmdline" % pid, "rb") as f:
                        cl = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
                except Exception:
                    cl = ""
                return pid, cl
    except Exception:
        pass
    return None, None
