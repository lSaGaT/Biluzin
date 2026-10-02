# -*- coding: utf-8 -*-
"""Modo `dir`: forca bruta de diretorios/arquivos (porte do modes_dir.kf).

Tres fases por batch, como no koffuster:
  1. sondagem de status em paralelo (largura = threads);
  2. classificacao: erro, excluido, ou candidato que precisa de corpo;
  3. corpos dos candidatos relevantes -> decisao de filtro -> emissao.
"""

from concurrent.futures import ThreadPoolExecutor

from ..util import (expand_extensions, load_wordlist, parse_extensions,
                    parse_int_list, Progress, control_token)
from .classify import Baseline, join_dir_url


def _probe_status(http, url):
    try:
        resp = http.get(url)
        return resp.status, len(resp.body)
    except Exception as e:
        return None, str(e)


def run_dir_mode(cfg, log, emitter):
    http = cfg.http
    words = load_wordlist(cfg.wordlist)
    exts = parse_extensions(cfg.extensions)
    words = expand_extensions(words, exts)
    include_status = parse_int_list(cfg.status_include) if cfg.status_include else None
    exclude_status = parse_int_list(cfg.exclude_status) if cfg.exclude_status else None
    exclude_length = parse_int_list(cfg.exclude_length) if cfg.exclude_length else None

    log.info("dir: %d candidatos, alvo %s" % (len(words), cfg.url))

    baseline = _build(cfg, log)

    found = errors = 0
    total = len(words)
    progress = Progress(log, total, "dir", enabled=not cfg.quiet and total >= 50)
    width = max(1, cfg.threads)

    def batch(start, count):
        nonlocal found, errors
        chunk = words[start:start + count]
        urls = [join_dir_url(cfg.url, w) for w in chunk]
        with ThreadPoolExecutor(max_workers=min(width, count)) as pool:
            probes = list(pool.map(lambda u: _probe_status(http, u), urls))
        for word, url, (status, info) in zip(chunk, urls, probes):
            progress.tick()
            if status is None:
                errors += 1
                log.debug("erro: %s -> %s" % (url, info))
                continue
            if status == 404 and include_status is None:
                continue
            # fase 2: corpo so para quem pode virar resultado
            if include_status is not None and status not in include_status:
                continue
            if exclude_status is not None and status in exclude_status:
                continue
            if baseline.soft_detected and status == baseline.status:
                try:
                    resp = http.get(url)
                    length = len(resp.body)
                except Exception:
                    continue
                if baseline.length < 0 or length == baseline.length:
                    continue
            else:
                try:
                    length = len(http.get(url).body)
                except Exception:
                    length = -1
            if exclude_length is not None and length in exclude_length:
                continue
            found += 1
            progress.tick(found_hit=True)
            emitter.emit({
                "type": "dir", "url": url, "status": status,
                "length": length if length >= 0 else None,
                "line": "%d  %8s  %s" % (status, length if length >= 0 else "-", url),
            })

    bsz = width * 4
    for start in range(0, total, bsz):
        batch(start, min(bsz, total - start))
    progress.finish()
    return found, errors


def _build(cfg, log) -> Baseline:
    """Baseline de soft-404 com o mesmo token de controle do classify."""
    from .classify import build_baseline
    b = build_baseline(cfg.http, cfg.url, need_length=True, log=log)
    if b.soft_detected and log and not cfg.quiet:
        if b.status != 404:
            if b.length >= 0:
                log.warn("soft-404: alvo responde %d com corpo de %d bytes para paths "
                         "inexistentes; candidatos iguais sao filtrados (use -s <status> para ve-los)"
                         % (b.status, b.length))
            else:
                log.warn("soft-404: alvo responde %d para paths inexistentes; "
                         "candidatos iguais sao filtrados" % b.status)
        else:
            log.debug("baseline: 404 consistente (status=%d, length=%s)" % (b.status, b.length))
    return b
