#!/usr/bin/env bash
# install.sh - instala a Biluzim com um comando, direto do GitHub
#
#   curl -sSL https://raw.githubusercontent.com/lSaGaT/Biluzin/main/install.sh | bash
#   wget -qO- https://raw.githubusercontent.com/lSaGaT/Biluzin/main/install.sh | bash
#
# Ou do jeito classico (dentro de um clone):
#   git clone https://github.com/lSaGaT/Biluzin.git && cd Biluzin && sudo ./install.sh
#
# Variaveis opcionais:
#   BILUZIM_HOME=/caminho   onde o clone fica (padrao: ~/.local/share/biluzim,
#                           ou /opt/biluzim se root)
#   PREFIX=/caminho         onde cria o binario (padrao: ~/.local/bin,
#                           ou /usr/local/bin se root)
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/lSaGaT/Biluzin.git}"

if [ "$(id -u)" = "0" ]; then
    DEST="${BILUZIM_HOME:-/opt/biluzim}"
    BIN_DIR="${PREFIX:-/usr/local}/bin"
else
    DEST="${BILUZIM_HOME:-$HOME/.local/share/biluzim}"
    BIN_DIR="${PREFIX:-$HOME/.local}/bin"
fi

# ---------------------------------------------------------------- dependencia unica
if ! command -v python3 >/dev/null 2>&1; then
    echo "[-] python3 nao encontrado - no Kali/Debian: sudo apt install python3" >&2
    exit 1
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
    echo "[-] Python 3.9+ e necessario (encontrado: $(python3 --version 2>&1))" >&2
    exit 1
fi

# ---------------------------------------------------------------- codigo
if [ -f "./biluzim.py" ] && [ -f "./install.sh" ]; then
    echo "[*] instalando a partir do clone local: $PWD"
    SRC="$PWD"
else
    if ! command -v git >/dev/null 2>&1; then
        echo "[-] git nao encontrado - no Kali/Debian: sudo apt install git" >&2
        exit 1
    fi
    if [ -d "$DEST/.git" ]; then
        echo "[*] atualizando clone existente em $DEST"
        git -C "$DEST" pull --ff-only
    else
        echo "[*] clonando $REPO_URL -> $DEST"
        mkdir -p "$(dirname "$DEST")"
        git clone --depth 1 "$REPO_URL" "$DEST"
    fi
    SRC="$DEST"
fi

# ---------------------------------------------------------------- binario
# launcher fino com o caminho do pacote gravado (sem depender de symlink)
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/biluzim" << EOF
#!/usr/bin/env bash
# gerado por install.sh - pacote em: $SRC
set -euo pipefail
export PYTHONUNBUFFERED=1
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys' 2>/dev/null; then
    exec python3 "$SRC/biluzim.py" "\$@"
fi
exec python "$SRC/biluzim.py" "\$@"
EOF
chmod +x "$BIN_DIR/biluzim"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo "[!] '$BIN_DIR' nao esta no seu PATH. Adicione uma vez:"
        echo "    echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
        ;;
esac

echo "[+] instalado: $BIN_DIR/biluzim (pacote em $SRC)"
"$BIN_DIR/biluzim" --version
echo "[+] pronto: 'biluzim' abre o wizard; 'biluzim --help' lista os modos"
echo "[+] para atualizar depois: git -C $SRC pull"
