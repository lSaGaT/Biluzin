# -*- coding: utf-8 -*-
"""Modo `fuzz`: substitui FUZZ em URL, cabecalho ou corpo (modes_fuzz.kf).

Achado = resposta cujo status/tamanho difere do baseline de resposta
"vazia" (payload aleatorio no lugar do FUZZ).
"""

from concurrent.futures import ThreadPoolExecutor

from ..util import load_wordlist, control_token, Progress


def _find_fuzz(cfg):
    spots = []
    if "FUZZ" in (cfg.url or ""):
        spots.append("url")
    for h in cfg.header or []:
        if "FUZZ" in h:
            spots.append("header")
    if "FUZZ" in (cfg.body or ""):
        spots.append("body")
    return spots


def run_fuzz_mode(cfg, log, emitter):
    http = cfg.http
    spots = _find_fuzz(cfg)
    if not spots:
        log.error("fuzz: nenhum FUZZ na linha de comando - nada para substituir.")
        log.error("Coloque FUZZ onde o payload deve entrar. Exemplos:")
        log.error('  biluzim fuzz "alvo.com/busca?q=FUZZ" payloads.txt')
        log.error("  biluzim fuzz alvo.com/FUZZ payloads.txt")
        log.error('  biluzim fuzz alvo.com/api payloads.txt -X POST --body "user=FUZZ"')
        log.error('  biluzim fuzz alvo.com payloads.txt -H "X-Token: FUZZ"')
        raise SystemExit(2)

    words = load_wordlist(cfg.wordlist)
    log.info("fuzz: %d candidatos, FUZZ em %s, alvo %s"
             % (len(words), ",".join(spots), cfg.url))

    # baseline: payload aleatorio - resposta "sem achado"
    b_status, b_len = -1, -1
    try:
        r = _send(http, cfg, spots, control_token(31337))
        b_status, b_len = r
        log.info("fuzz baseline: status=%d, corpo=%d bytes (payload de controle)" % (b_status, b_len))
    except Exception as e:
        log.warn("fuzz: baseline falhou (%s) - reportando tudo que nao for erro" % str(e)[:80])

    found = errors = 0
    progress = Progress(log, len(words), "fuzz", enabled=not cfg.quiet and len(words) >= 50)
    width = max(1, cfg.threads)
    include_status = cfg.status_include

    def probe(word):
        try:
            status, length = _send(http, cfg, spots, word)
            return (word, status, length, "")
        except Exception as e:
            return (word, None, None, str(e)[:100])

    with ThreadPoolExecutor(max_workers=width) as pool:
        for word, status, length, err in pool.map(probe, words):
            progress.tick()
            if status is None:
                errors += 1
                log.debug("erro: %s -> %s" % (word, err))
                continue
            if include_status and status not in include_status:
                continue
            hit = status != b_status or length != b_len
            if not hit:
                continue
            found += 1
            progress.found_one()
            emitter.emit({
                "type": "fuzz", "payload": word, "status": status, "length": length,
                "url": cfg.url.replace("FUZZ", word),
                "line": "%d  %8d  %s" % (status, length if length is not None else -1, word),
            })

    progress.finish()
    return found, errors


def _send(http, cfg, spots, payload):
    url = cfg.url.replace("FUZZ", payload) if "url" in spots else cfg.url
    headers = []
    for h in cfg.header or []:
        headers.append(h.replace("FUZZ", payload))
    http.extra_headers = {}
    for h in headers:
        if ":" in h:
            k, _, v = h.partition(":")
            http.extra_headers[k.strip()] = v.strip()
    body = cfg.body.replace("FUZZ", payload) if cfg.body else None
    method = (cfg.method or "GET").upper()
    if body is not None:
        if "Content-Type" not in {k.lower() for k in http.extra_headers}:
            http.extra_headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = http.request(url, method, data=body.encode("utf-8"))
    else:
        r = http.request(url, method)
    return r.status, len(r.body)
