#!/usr/bin/env bash
# WeSteg - AppImage Build Script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

python3 -m pip install --upgrade pyinstaller

python3 -m PyInstaller --noconfirm --onedir --windowed --name WeSteg main.py

rm -rf AppDir
mkdir -p AppDir/usr/bin
mkdir -p AppDir/usr/share/applications
mkdir -p AppDir/usr/share/icons/hicolor/256x256/apps

cp -r dist/WeSteg/* AppDir/usr/bin/

if [ -f "westeg.png" ]; then
    cp westeg.png AppDir/westeg.png
    cp westeg.png AppDir/usr/share/icons/hicolor/256x256/apps/westeg.png
fi

cat <<'EOF' > AppDir/westeg.desktop
[Desktop Entry]
Type=Application
Name=WeSteg
Exec=WeSteg %F
Icon=westeg
Categories=Utility;Security;
Comment=Steganalysis and Steganography Suite
Terminal=false
EOF

cp AppDir/westeg.desktop AppDir/usr/share/applications/westeg.desktop

cat <<'EOF' > AppDir/AppRun
#!/bin/sh
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin:${PATH}"
export LD_LIBRARY_PATH="${HERE}/usr/lib:${HERE}/usr/bin:${LD_LIBRARY_PATH}"
exec "${HERE}/usr/bin/WeSteg" "$@"
EOF

chmod +x AppDir/AppRun

if ! command -v appimagetool >/dev/null 2>&1; then
    if [ ! -f "appimagetool-x86_64.AppImage" ]; then
        echo "[*] Downloading appimagetool..."
        curl -sSL -o appimagetool-x86_64.AppImage "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" || wget -qO appimagetool-x86_64.AppImage "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
        chmod +x appimagetool-x86_64.AppImage
    fi
    APPIMAGETOOL="./appimagetool-x86_64.AppImage"
else
    APPIMAGETOOL="appimagetool"
fi

echo "[*] Packing AppImage..."
if [ "$APPIMAGETOOL" = "./appimagetool-x86_64.AppImage" ]; then
    ARCH=x86_64 "$APPIMAGETOOL" --appimage-extract-and-run AppDir WeSteg-x86_64.AppImage
else
    ARCH=x86_64 "$APPIMAGETOOL" AppDir WeSteg-x86_64.AppImage
fi

chmod +x WeSteg-x86_64.AppImage
echo "[+] Build complete: WeSteg-x86_64.AppImage"
