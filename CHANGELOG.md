## What's New

### v15 -- tunnel C2, installers that actually verify (current)

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