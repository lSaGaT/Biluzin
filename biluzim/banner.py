# -*- coding: utf-8 -*-
"""Banner ASCII e paleta de cores da Biluzim."""

import os
import sys

from . import __version__

# Mark: "BILUZIM" (5 linhas, figlet standard com espacamento)
WORD = [
    r" ____    ___   _       _   _   _____   ___   __  __ ",
    r"| __ )  |_ _| | |     | | | | |__  / |_ _| |  \/  |",
    r"|  _ \   | |  | |     | | | |   / /   | |  | |\/| |",
    r"| |_) |  | |  | |___  | |_| |  / /_   | |  | |  | |",
    r"|____/  |___| |_____|  \___/  /____| |___| |_|  |_|",
]

TAGLINE = "Recon passivo + enumeracao ativa   v" + __version__
CREDIT = "juncao de lunatic + koffuster (lunalully) - porte Python"


class Palette:
    """Cores ANSI. Ativas quando stderr e TTY (ou --color força)."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return "\033[" + code + "m" + text + "\033[0m"

    def red(self, t: str) -> str: return self._wrap("1;31", t)
    def green(self, t: str) -> str: return self._wrap("1;32", t)
    def yellow(self, t: str) -> str: return self._wrap("1;33", t)
    def blue(self, t: str) -> str: return self._wrap("1;34", t)
    def magenta(self, t: str) -> str: return self._wrap("1;35", t)
    def cyan(self, t: str) -> str: return self._wrap("1;36", t)
    def gray(self, t: str) -> str: return self._wrap("90", t)
    def bold(self, t: str) -> str: return self._wrap("1", t)


def colors_enabled(force_color: bool, force_nocolor: bool) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if force_nocolor:
        return False
    if force_color:
        return True
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


def render(pal: Palette) -> str:
    """Banner colorido, uma string multi-linha (destino: stderr)."""
    lines = []
    art_color = pal.cyan
    for row in WORD:
        lines.append(art_color(row))
    lines.append(pal.bold(TAGLINE))
    lines.append(pal.gray(CREDIT))
    lines.append(pal.gray("uso autorizado apenas - pente fino, zero exploracao"))
    return "\n".join(lines)


def print_banner(pal: Palette, quiet: bool, fmt: str, stream=sys.stderr) -> None:
    """Imprime o banner no stream de diagnostico (stderr por padrao).

    Silencioso quando -q/--quiet ou formato jsonl (para nao sujar pipes).
    """
    if quiet or fmt == "jsonl":
        return
    try:
        stream.write(render(pal) + "\n\n")
        stream.flush()
    except Exception:
        pass
