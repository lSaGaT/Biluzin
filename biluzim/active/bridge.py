# -*- coding: utf-8 -*-
"""Ponte passivo->ativo: e aqui que a Biluzim junta lunatic e koffuster.

`biluzim recon -d alvo.com --resolve`  resolve DNS dos nomes achados.
`biluzim recon -d alvo.com --probe`    alem de resolver, faz uma sonda
                                       HTTP e reporta status/titulo.
Ambos sao PASSOS ATIVOS e ficam marcados como tal na saida.
"""

import re
from concurrent.futures import ThreadPoolExecutor

from .dns_mode import resolve_names

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def probe_alive(http, names, workers=16, schemes=("https", "http"), timeout_note=""):
    """Sonda HTTP leve: GET / em https e http; reporta status+titulo.

    Retorna lista de dicts na ordem de entrada. Nunca segue redirects
    (status exato, mesma regra dos outros modos).
    """

    def one(name):
        for scheme in schemes:
            url = "%s://%s/" % (scheme, name)
            try:
                r = http.get(url)
                m = _TITLE_RE.search(r.text()[:20000])
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
                return {
                    "subdomain": name, "url": url, "status": r.status,
                    "length": len(r.body), "title": title,
                }
            except Exception:
                continue
        return {"subdomain": name, "url": None, "status": None,
                "length": None, "title": ""}

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(one, names))


def run_recon_bridge(cfg, log, emitter, names):
    """Executa --resolve e/ou --probe sobre os nomes do recon."""
    if not (cfg.resolve or cfg.probe):
        return
    log.info("ponte ativa: %d nomes para verificar (%s%s)"
             % (len(names),
                "resolve" if cfg.resolve else "",
                "+probe" if cfg.resolve and cfg.probe else "probe" if cfg.probe else ""))

    if cfg.resolve:
        resolved = resolve_names(names, workers=max(1, cfg.threads))
        alive = []
        for name, ips in resolved:
            if ips:
                alive.append(name)
                emitter.emit({
                    "type": "resolve", "subdomain": name, "ips": ips,
                    "line": "%s  [%s]" % (name, ", ".join(ips)),
                })
        if not alive:
            log.warn("nenhum nome resolveu em DNS; probe HTTP sera pulado")
            return
        names = alive

    if cfg.probe:
        rows = probe_alive(cfg.http, names, workers=max(1, cfg.threads))
        for r in rows:
            if r["status"] is None:
                continue
            line = "%d  %8d  %s" % (r["status"], r["length"] or -1, r["url"])
            if r["title"]:
                line += "  | " + r["title"]
            emitter.emit({
                "type": "probe", "subdomain": r["subdomain"], "url": r["url"],
                "status": r["status"], "length": r["length"], "title": r["title"],
                "line": line,
            })
