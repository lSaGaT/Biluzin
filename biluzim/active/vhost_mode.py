# -*- coding: utf-8 -*-
"""Modo `vhost`: enumera virtual hosts variando o header Host (modes_vhost.kf).

Baseline: dois Hosts aleatorios; se status+corpo coincidirem, e a
assinatura "nao achado" (mesma filosofia do soft-404 do dir).
"""

from concurrent.futures import ThreadPoolExecutor

from ..util import load_wordlist, control_token, Progress


def run_vhost_mode(cfg, log, emitter):
    http = cfg.http
    words = load_wordlist(cfg.wordlist)
    log.info("vhost: %d candidatos, alvo %s" % (len(words), cfg.url))

    # baseline com dois hosts aleatorios
    base_len = -1
    base_status = -1
    consistent = True
    probes = []
    for salt in (71, 73):
        http.force_host = control_token(salt)
        try:
            r = http.get(cfg.url)
            probes.append((r.status, len(r.body)))
        except Exception:
            probes.append(None)
        finally:
            http.force_host = None
    good = [p for p in probes if p]
    if len(good) == 2 and good[0][0] == good[1][0] and good[0][1] == good[1][1]:
        base_status, base_len = good[0]
    else:
        consistent = False
    if consistent and not cfg.quiet:
        log.info("vhost baseline: status=%d, corpo=%d bytes" % (base_status, base_len))
    elif not cfg.quiet:
        log.warn("vhost: baseline inconsistente (status/corpo variam entre Hosts aleatorios) "
                 "- comparando por diferenca de tamanho")
    cfg.stage_info = {"baseline": {"consistent": consistent,
                                   "status": base_status if consistent else None,
                                   "length": base_len if consistent else None}}

    found = errors = 0
    progress = Progress(log, len(words), "vhost", enabled=not cfg.quiet and len(words) >= 50)
    width = max(1, cfg.threads)

    def probe(word):
        host = word.strip().rstrip(".")
        if cfg.domain:
            host = host + "." + cfg.domain
        http.force_host = host
        try:
            r = http.get(cfg.url)
            return (host, r.status, len(r.body), "")
        except Exception as e:
            return (host, None, None, str(e)[:100])
        finally:
            http.force_host = None

    with ThreadPoolExecutor(max_workers=width) as pool:
        for host, status, length, err in pool.map(probe, words):
            progress.tick()
            if status is None:
                errors += 1
                log.debug("erro: %s -> %s" % (host, err))
                continue
            hit = False
            if 200 <= status < 300:
                hit = not consistent or length != base_len
            elif status >= 500:
                # 5xx real: o Host existe mas o alvo responde erro (igual ao koffuster)
                hit = True
            if not hit:
                continue
            found += 1
            progress.found_one()
            emitter.emit({
                "type": "vhost", "host": host, "status": status,
                "length": length,
                "line": "%d  %8d  %s" % (status, length or -1, host),
            })

    progress.finish()
    return found, errors
