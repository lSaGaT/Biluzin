#!/usr/bin/env bash
# install.sh - instala a Biluzim no Linux/Kali
#
#   sudo ./install.sh            -> /usr/local/bin/biluzim
#   sudo PREFIX=/usr ./install.sh
#   ./install.sh                 -> ~/.local/bin/biluzim (sem root)
#
# Nenhuma dependencia Python: so a stdlib (Python 3.9+, padrao no Kali).
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"

if [ ! -w "$BIN_DIR" ] 2>/dev/null; then
    if [ "$(id -u)" != "0" ]; then
        BIN_DIR="$HOME/.local/bin"
        mkdir -p "$BIN_DIR"
        echo "[*] sem permissao em $PREFIX/bin - instalando em $BIN_DIR"
        case ":$PATH:" in
            *":$BIN_DIR:"*) ;;
            *)
                echo "[!] adicione ao PATH (uma vez):"
                echo "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
                ;;
        esac
    fi
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

chmod +x "$HERE/bin/biluzim"
ln -sf "$HERE/bin/biluzim" "$BIN_DIR/biluzim"

echo "[*] instalado: $BIN_DIR/biluzim"
"$BIN_DIR/biluzim" --version
echo "[*] pronto. comece com: biluzim --help"
