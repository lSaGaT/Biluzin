# -*- coding: utf-8 -*-
"""Utilidades comuns: log, saida, escopo de dominio, wordlists, tokens."""

import json
import os
import random
import re
import string
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Log de diagnostico (stderr) - resultados de dados vão para stdout, nunca aqui.
# ---------------------------------------------------------------------------

_log_lock = threading.Lock()


class Log:
    def __init__(self, pal, quiet=False, verbose=False):
        self.pal = pal
        self.quiet = quiet
        self.verbose = verbose

    def _emit(self, text):
        with _log_lock:
            try:
                sys.stderr.write(text + "\n")
                sys.stderr.flush()
            except Exception:
                pass

    def info(self, msg):
        if not self.quiet:
            self._emit(self.pal.gray("[*] " + msg))

    def ok(self, msg):
        if not self.quiet:
            self._emit(self.pal.green("[+] " + msg))

    def warn(self, msg):
        if not self.quiet:
            self._emit(self.pal.yellow("[!] " + msg))

    def error(self, msg):
        self._emit(self.pal.red("[-] " + msg))

    def debug(self, msg):
        if self.verbose:
            self._emit(self.pal.gray("[v] " + msg))


# ---------------------------------------------------------------------------
# Escrita de resultados: stdout + arquivo opcional (append + flush por linha).
# ---------------------------------------------------------------------------

class Emitter:
    """Recebe resultados de qualquer modo e distribui para stdout/arquivo.

    fmt: 'text' (uma linha por resultado) ou 'jsonl' (JSON por linha).
    """

    def __init__(self, fmt="text", output_path=None, show_sources=False):
        self.fmt = fmt
        self.output_path = output_path
        self.show_sources = show_sources
        self._file = None
        self._lock = threading.Lock()
        if output_path:
            self._file = open(output_path, "a", encoding="utf-8", errors="replace")

    def emit(self, record):
        """record: dict com pelo menos 'type'; em text, usamos record['line']."""
        if self.fmt == "jsonl":
            line = json.dumps(record, ensure_ascii=False, sort_keys=False)
        else:
            line = record.get("line", "")
        with self._lock:
            try:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
            except Exception:
                pass
            if self._file:
                try:
                    self._file.write(line + "\n")
                    self._file.flush()
                except Exception:
                    pass

    def close(self):
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None


# ---------------------------------------------------------------------------
# Escopo: validacao de dominio alvo e normalizacao de nomes candidatos.
# Porte do internal/scope do lunatic (regras LDH + underscore em candidatos).
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_CAND_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_NAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.?$"
)


class ScopeError(ValueError):
    pass


def parse_domain(input_str: str) -> str:
    """Valida o dominio alvo (mais estrito: sem underscore) e normaliza."""
    s = (input_str or "").strip().rstrip(".").lower()
    if not s:
        raise ScopeError("dominio vazio")
    if "://" in s or "/" in s:
        raise ScopeError("'%s' parece uma URL; informe um dominio puro, ex.: exemplo.com" % input_str)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
        raise ScopeError("'%s' e um IP; os modos passivos esperam um dominio" % input_str)
    if not _NAME_RE.match(s + "."):
        raise ScopeError("'%s' nao e um nome de dominio valido" % input_str)
    for label in s.split("."):
        if not _LABEL_RE.match(label):
            raise ScopeError("rotulo invalido no dominio: '%s'" % label)
    return s


_SUB_RE = re.compile(
    r"(?<![a-z0-9_.-])"
    r"([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
    r"(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?![a-z0-9_.-])"
)


def find_in_text(text: str, domain: str):
    """Extrai nomes de host dentro do sufixo .domain de um texto livre
    (porte do scope.FindInText do lunatic). Retorna em ordem de aparicao."""
    domain = domain.lower()
    out, seen = [], set()
    for m in _SUB_RE.finditer(text.lower()):
        name = m.group(1).strip(".")
        if name.endswith("." + domain) and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def in_scope(name: str, domain: str) -> bool:
    """True se name e igual ou subdominio de domain (comparacao exata)."""
    name = name.strip().rstrip(".").lower()
    return name == domain or name.endswith("." + domain)


def normalize_candidate(raw: str, domain: str):
    """Normaliza um nome candidato vindo de fonte OSINT; None se fora de escopo."""
    s = (raw or "").strip().strip(".").lower()
    s = s.split("@")[-1] if "@" in s else s  # e-mails: mantem so a parte direita
    s = re.sub(r"\*\.", "", s)
    if not s or not in_scope(s, domain):
        return None
    if len(s) > 253:
        return None
    for label in s.split("."):
        if not _CAND_LABEL_RE.match(label):
            return None
    return s


# ---------------------------------------------------------------------------
# Wordlists (arquivo ou '-' para stdin); dedupe, ignora comentarios/vazios.
# ---------------------------------------------------------------------------

def load_wordlist(path: str):
    if path == "-":
        words = [ln.strip() for ln in sys.stdin.read().splitlines()]
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            words = [ln.strip() for ln in fh]
    out, seen = [], set()
    for w in words:
        if not w or w.startswith("#"):
            continue
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


# ---------------------------------------------------------------------------
# Tokens de controle (sondas "nao-dicionario") - porte do classify.kf.
# ---------------------------------------------------------------------------

def control_token(salt: int, prefix: str = "blzctl") -> str:
    n = random.randint(10_000_000, 99_999_999)
    mixed = (n + salt * 7919) % 100_000_000
    return "%s%d" % (prefix, mixed)


def parse_int_list(spec: str):
    """'200,301,500-502' -> {200,301,500,501,502}; None se vazio."""
    if not spec:
        return None
    out = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                lo_i, hi_i = int(lo), int(hi)
            except ValueError:
                raise ScopeError("faixa invalida em '%s': %r" % (spec, part))
            if lo_i > hi_i:
                lo_i, hi_i = hi_i, lo_i
            out.update(range(lo_i, hi_i + 1))
        else:
            try:
                out.add(int(part))
            except ValueError:
                raise ScopeError("numero invalido em '%s': %r" % (spec, part))
    return out


def parse_extensions(spec: str):
    exts = []
    for e in (spec or "").split(","):
        e = e.strip().lstrip(".")
        if e and re.match(r"^[A-Za-z0-9]{1,10}$", e):
            exts.append(e)
    return exts


def expand_extensions(words, exts):
    if not exts:
        return list(words)
    out = []
    for w in words:
        out.append(w)
        for e in exts:
            out.append("%s.%s" % (w, e))
    return out


def bucket_url(endpoint: str, name: str) -> str:
    try:
        return endpoint % name
    except TypeError:
        return endpoint + name


def redact_url(u: str) -> str:
    """Mascara credenciais embutidas na URL antes de logar."""
    return re.sub(r"(://[^/@\s:]+:)[^@\s]+@", r"\1***@", u)


class Throttle:
    """Limitador simples por intervalo minimo entre chamadas (1/RPS)."""

    def __init__(self, rps: float):
        self.min_interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delay = self._next - now
            if delay > 0:
                time.sleep(delay)
                self._next = time.monotonic() + self.min_interval
            else:
                self._next = now + self.min_interval


class Progress:
    """Barra de progresso simples em stderr (nao suja pipes)."""

    def __init__(self, log, total: int, label: str, enabled: bool):
        self.log = log
        self.total = max(total, 1)
        self.label = label
        self.enabled = enabled
        self.done = 0
        self.found = 0
        self._last_pct = -10

    def tick(self, found_hit=False):
        if found_hit:
            self.found += 1
        self.done += 1
        if not self.enabled:
            return
        pct = int(self.done * 100 / self.total)
        if pct >= self._last_pct + 5 or self.done == self.total:
            self._last_pct = pct
            with _log_lock:
                bar = "#" * min(int(pct // 5), 20) + "." * max(20 - int(pct // 5), 0)
                sys.stderr.write(
                    "\r[%s] %s %3d%%  achados=%d" % (self.log.pal.cyan(bar), self.label, pct, self.found)
                )
                sys.stderr.flush()
            if self.done == self.total:
                with _log_lock:
                    sys.stderr.write("\n")
                    sys.stderr.flush()

    def found_one(self):
        """Conta um achado sem avancar o progresso (o tick do candidato ja foi dado)."""
        self.found += 1

    def finish(self):
        if self.enabled:
            with _log_lock:
                sys.stderr.write("\n")
                sys.stderr.flush()


def json_dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=False)


def default_wordlist(name):
    """Wordlist embutida: fica ao lado do pacote biluzim/wordlists/."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", name)
