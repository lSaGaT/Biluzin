# -*- coding: utf-8 -*-
"""Modo `tftp`: checagem read-only de arquivos via RRQ (modes_tftp.kf).

Sonda com RRQ (opcode 1); se o servidor manda DATA (opcode 3), o arquivo
existe (manda ACK para parar retransmissao); ERROR codigo 1 = nao existe,
codigo 2 = acesso negado. Le no maximo o primeiro bloco de ~512 bytes.
"""

import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from ..util import load_wordlist, Progress

OP_RRQ = 1
OP_DATA = 3
OP_ERROR = 5
ERR_NOT_FOUND = 1
ERR_ACCESS = 2


def _rrq(file_name: str) -> bytes:
    return struct.pack("!H", OP_RRQ) + file_name.encode("utf-8", "replace") + b"\x00octet\x00"


def _ack(block: int) -> bytes:
    return struct.pack("!HH", 4, block)


def probe_file(host, port, file_name, timeout_ms, family=socket.AF_INET, attempts=2):
    """Um candidato -> (estado, detalhe). Estados: existe|negado|nao_existe|timeout|erro.

    UDP pode perder pacotes: tenta de novo ate `attempts` vezes.
    """
    result = ("timeout", "")
    for attempt in range(max(1, attempts)):
        result = _probe_once(host, port, file_name, timeout_ms, family)
        if result[0] != "timeout":
            return result
    return result


def _probe_once(host, port, file_name, timeout_ms, family):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(max(timeout_ms / 1000.0, 0.5))
    try:
        s.sendto(_rrq(file_name), (host, port))
        data, addr = s.recvfrom(1500)
        if len(data) >= 4 and data[0] == 0 and data[1] == OP_DATA:
            try:  # ACK do bloco 1, para o servidor (educacao, igual ao koffuster)
                s.sendto(_ack(struct.unpack("!H", data[2:4])[0]), addr)
            except Exception:
                pass
            return ("existe", "primeiro bloco: %d bytes" % (len(data) - 4))
        if len(data) >= 4 and data[0] == 0 and data[1] == OP_ERROR:
            code = data[3]
            if code == ERR_NOT_FOUND:
                return ("nao_existe", "")
            if code == ERR_ACCESS:
                return ("negado", "servidor negou acesso ao arquivo")
            return ("erro", "ERROR %d" % code)
        return ("erro", "opcode inesperado")
    except socket.timeout:
        return ("timeout", "")
    except ConnectionRefusedError:
        return ("erro", "porta inalcancavel")
    except socket.gaierror:
        return ("erro", "dns")
    except OSError as e:
        return ("erro", "rede: %s" % (e.errno or str(e)[:60]))
    finally:
        try:
            s.close()
        except Exception:
            pass


def parse_tftp_target(url_value: str, port: int):
    """'host[:porta]' ou 'tftp://host[:porta]' -> (host, porta)."""
    s = (url_value or "").strip()
    if "://" in s:
        p = urlparse(s)
        host = p.hostname or ""
        if p.port:
            port = p.port
    else:
        host, _, p = s.partition(":")
        if p.isdigit():
            port = int(p)
    if not host:
        sys.stderr.write("biluzim tftp: alvo invalido: %r\n" % url_value)
        raise SystemExit(2)
    return host, int(port)


def run_tftp_mode(cfg, log, emitter):
    host, port = parse_tftp_target(cfg.url, cfg.port)
    timeout_ms = max(int(cfg.timeout * 1000), 500)
    files = load_wordlist(cfg.wordlist)
    log.info("tftp: %d candidatos, servidor %s:%d (somente leitura, primeiro bloco)"
             % (len(files), host, port))

    found = errors = 0
    progress = Progress(log, len(files), "tftp", enabled=not cfg.quiet and len(files) >= 50)
    width = max(1, cfg.threads)

    with ThreadPoolExecutor(max_workers=width) as pool:
        for file_name, (state, detail) in pool.map(
                lambda f: (f, probe_file(host, port, f, timeout_ms)), files):
            progress.tick()
            if state in ("nao_existe", "timeout"):
                if state == "timeout":
                    errors += 1
                continue
            if state == "erro":
                errors += 1
                log.debug("erro: %s -> %s" % (file_name, detail))
                continue
            found += 1
            progress.found_one()
            emitter.emit({
                "type": "tftp", "host": "%s:%d" % (host, port), "file": file_name,
                "state": state, "detail": detail,
                "line": "%-7s  %-24s  %s:%d/%s" % (state, detail, host, port, file_name),
            })

    progress.finish()
    return found, errors
