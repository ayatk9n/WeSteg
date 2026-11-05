#!/usr/bin/env bash
# WeSteg - Linux Setup Script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo -e "${CYAN}[*] Starting WeSteg Environment Setup for Linux (Debian / Ubuntu / Kali)...${NC}"

echo -e "${CYAN}[*] Updating apt package lists...${NC}"
$SUDO apt-get update

CORE_PKGS=(
    python3
    python3-venv
    python3-pip
    python3-pyqt6
    ruby-full
    build-essential
    file
    binutils
    fonts-dejavu-core
    libimage-exiftool-perl
    foremost
    steghide
    pngcheck
    libxcb-cursor0
)

echo -e "${CYAN}[*] Installing core system packages...${NC}"
$SUDO apt-get install -y "${CORE_PKGS[@]}" || {
    echo -e "${YELLOW}[!] Batch install encountered an issue; attempting individual package install...${NC}"
    for pkg in "${CORE_PKGS[@]}"; do
        $SUDO apt-get install -y "$pkg" || echo -e "${YELLOW}[!] Skipping unavailable package: $pkg${NC}"
    done
}

for pkg in binwalk binwalk3 stegseek openstego; do
    if apt-cache policy "$pkg" 2>/dev/null | grep -qE 'Candidate:\s+[^(\s]'; then
        echo -e "${GREEN}[+] Installing $pkg...${NC}"
        $SUDO apt-get install -y "$pkg" || echo -e "${YELLOW}[!] Could not install $pkg via apt, skipping.${NC}"
    else
        echo -e "${YELLOW}[!] Package $pkg has no install candidate in current apt mirror, skipping.${NC}"
    fi
done

if ! command -v zsteg >/dev/null 2>&1; then
    echo -e "${CYAN}[*] Installing zsteg via RubyGems...${NC}"
    $SUDO gem install zsteg || echo -e "${YELLOW}[!] Could not install zsteg gem; native Python LSB scanner will be used.${NC}"
else
    echo -e "${GREEN}[+] zsteg is already installed.${NC}"
fi

echo -e "${CYAN}[*] Setting up Python virtual environment (.venv)...${NC}"
python3 -m venv --system-site-packages .venv
source .venv/bin/activate

echo -e "${CYAN}[*] Installing Python requirements...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

echo -e ""
echo -e "${GREEN}==============================================================================${NC}"
echo -e "${GREEN}[+] WeSteg installation complete!${NC}"
echo -e "${GREEN}[+] Run the application with:${NC}"
echo -e "    source .venv/bin/activate && python3 main.py"
echo -e "${GREEN}==============================================================================${NC}"
