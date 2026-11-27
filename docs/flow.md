# Infection Flow

## Overview

```
ATTACKER                                    VICTIM (Windows)
+---------------------------+              +---------------------------+
| 1. Build (build.py all)   |              |                           |
|    ckdll.dll + loader.exe |              |                           |
|                           |              |                           |
| 2. Infect (auto.py)       |  send ifec/  | 3. Victim runs infected   |
|    patch C2 URL into      | -----------> |    .exe                   |
|    loader, append host     |              |                           |
|                           |              | 4. Loader extracts host   |
| 3. Start listener         |              |    from trailer, launches  |
|    (listen.py)            |              |    it normally (game/GUI) |
|                           |              |                           |
|                           |  HTTP POST   | 5. Payload maps into      |
| 4. Receive cookies        | <----------- |    loader process,        |
|    (Cookie-Editor JSON)   |              |    extracts cookies       |
|                           |              |                           |
| 5. Relay (optional)       |              | 6. Payload POSTs to C2    |
|    Telegram / Discord     |              |    or falls back to pipe  |
+---------------------------+              +---------------------------+
```

## Infection Format

The infected `.exe` has this binary layout:

```
[loader.exe (patched)][original host bytes][host_len: 4 bytes LE]["CKLG": 4 bytes]
```

- `loader.exe`: the payload loader, with C2 URL patched into a 256-byte slot
- `original host bytes`: the legitimate host `.exe` content
- `host_len`: little-endian 32-bit length of the host
- `CKLG`: magic sentinel marking the end of the trailer

## Extraction (victim side)

1. Loader opens itself and checks for the `CKLG` magic at the end
2. Reads `host_len` from the 4 bytes before the magic
3. Extracts the host bytes to a temp file (`~ck_tmp.exe`)
4. Launches the host normally (game/installer/GUI appears)
5. Maps the payload DLL into its own process
6. Payload runs as a thread of the loader process

## Loader Sentinels

The loader contains three patchable sentinels:

| Sentinel | Size | Patched to | Purpose |
|----------|------|------------|---------|
| `CKC2_DEADBEEF_` | 256 bytes | C2 URL | Where to POST cookies |
| `CKPR____` | 8 bytes | `CKPR0001` | Enable persistence (registry Run key) |
| `CKAV0000` | 8 bytes | `CKAV0001` | Disable anti-VM checks |

## Payload Extraction Pipeline

1. **Chromium browsers** (Chrome, Edge, Brave, etc.): reads `Cookies` SQLite DB, decrypts v10/v11 (DPAPI) and v20 (app-bound) cookies
2. **Firefox**: reads `cookies.sqlite` (plaintext)
3. **Passwords**: extracts from `Login Data` SQLite DB
4. **Discord tokens**: reads `Local State` JSON
5. **Coverage manifest**: reports what was scanned and what was missed

## C2 Reception

The listener (`listen.py`) receives POSTs on the configured port:
- Bare JSON list → cookies only
- `{"records": [...], "coverage": {...}}` → cookies + coverage manifest

Output files in `loot/`:
- `all_cookies.json` — Cookie-Editor format
- `all_cookies.txt` — Netscape format
- `passwords.json` / `passwords.txt` — extracted credentials
- `session_cookies.json` / `session_cookies.txt` — session-only cookies
- `coverage.jsonl` — per-run coverage manifests

## Troubleshooting

### No cookies received
- Check: is the listener running? (`python listen.py <port>`)
- Check: is the C2 URL correct? (must match the listener's bind address)
- Check: Windows Firewall (direct listeners need inbound rule)
- Fallback: payload dumps to `C:\ProgramData\MediaCache\cache.json` on the victim

### Port already in use
- Use `--find-port` in auto.py to scan for a free port
- Or kill the existing listener: `taskkill /F /PID <pid>`

### Build fails
- Ensure Visual Studio Build Tools with "Desktop development with C++" are installed
- Or use `build_clang.bat` if only headers/libs are available
- On Linux: use prebuilt binaries from `bin/`

### Anti-VM false positives
- Use `--no-anti-vm` flag for testing in VMs
- The payload checks MAC addresses, debugger presence, and process names

### v20 (app-bound) cookies missing
- Run stage 1 as SYSTEM: `python cookielog.py --v20-sys`
- Run stage 2 as user: `python cookielog.py --v20-usr`
- Or use `ckkey.exe` (one-shot, elevated)

### Handle hijacking fails
- Browser must be running (handle hijacking needs an open file handle)
- Some browsers (Chrome) use 0-sharing locks — handle hijacking is the fallback
- Firefox doesn't hold exclusive locks — direct copy works
