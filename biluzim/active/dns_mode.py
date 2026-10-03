# -*- coding: utf-8 -*-
"""Modo `dns`: forca bruta de subdominios via DoH JSON (modes_dns.kf).

Wildcard: 3 tokens aleatorios; se todos resolverem para o mesmo IP, esse
IP e a assinatura e candidatos com ele sao descartados.
"""

import json
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from ..util import load_wordlist, control_token, Progress

DEFAULT_RESOLVER = "https://dns.google/resolve"


def _doh_url(resolver: str, name: str) -> str:
    sep = "&" if "?" in resolver else "?"
    return "%s%sname=%s&type=A" % (resolver, sep, urllib.parse.quote(name, safe=""))


def _query(http, name, resolver):
    """Retorna (status_doh, [ips]) ou levanta excecao operacional."""
    u = _doh_url(resolver, name)
    try:
        data = http.get_json(u, {"Accept": "application/dns-json"})
    except Exception as e:
        raise RuntimeError("doh: %s" % (str(e)[:80] or type(e).__name__))
    if not isinstance(data, dict):
        raise RuntimeError("doh: resposta nao-JSON")
    status = int(data.get("Status", -1))
    ips = []
    if status == 0:
        for ans in data.get("Answer") or []:
            if ans.get("type") in (1, 28) and ans.get("data"):
                ips.append(str(ans["data"]))
    return status, ips


def detect_wildcard(http, domain, resolver, log):
    tokens = [control_token(i, "blzwild") + "." + domain for i in range(3)]
    first_ip, all_same, all_resolved = "", True, True
    for t in tokens:
        try:
            status, ips = _query(http, t, resolver)
        except RuntimeError:
            all_resolved = False
            continue
        if status != 0 or not ips:
            all_resolved = False
            continue
        if not first_ip:
            first_ip = ips[0]
        elif ips[0] != first_ip:
            all_same = False
    if all_resolved and all_same and first_ip:
        return True, first_ip
    return False, ""


def run_dns_mode(cfg, log, emitter):
    http = cfg.http
    resolver = cfg.resolver or DEFAULT_RESOLVER
    words = load_wordlist(cfg.wordlist)
    log.info("dns: %d candidatos, dominio %s, resolver %s" % (len(words), cfg.domain, resolver))

    wildcard_ip, detected = "", False
    try:
        detected, wildcard_ip = detect_wildcard(http, cfg.domain, resolver, log)
    except Exception as e:
        log.warn("nao foi possivel testar wildcard: %s" % e)
    if detected:
        log.warn("wildcard detectado, IP=%s (candidatos com esse IP descartados)" % wildcard_ip)
    else:
        log.info("sem wildcard detectado")
    cfg.stage_info = {"wildcard": {"detected": detected, "ip": wildcard_ip if detected else None}}

    found = errors = 0
    progress = Progress(log, len(words), "dns", enabled=not cfg.quiet and len(words) >= 50)
    width = max(1, cfg.threads)

    def probe(word):
        name = word.strip().rstrip(".")
        if "." not in name:
            name = name + "." + cfg.domain
        try:
            status, ips = _query(http, name, resolver)
        except RuntimeError as e:
            return (name, None, [], str(e))
        return (name, status, ips, "")

    with ThreadPoolExecutor(max_workers=width) as pool:
        for name, status, ips, err in pool.map(probe, words):
            progress.tick()
            if status is None:
                errors += 1
                log.debug("erro: %s -> %s" % (name, err))
                continue
            if status != 0 or not ips:
                continue
            if detected and wildcard_ip in ips:
                continue
            found += 1
            progress.found_one()
            emitter.emit({
                "type": "dns", "subdomain": name, "ips": ips,
                "line": name + "  [" + ", ".join(ips) + "]",
            })

    progress.finish()
    return found, errors


# ---------------------------------------------------------------------------
# ponte: resolucao ativa dos nomes achados no modo passivo (recon --resolve)
# ---------------------------------------------------------------------------


def resolve_names(names, workers=16):
    """Resolve uma lista de nomes localmente (socket) -> [(nome, ips|None)]."""
    out = []

    def one(n):
        try:
            infos = socket.getaddrinfo(n, None, proto=socket.IPPROTO_TCP)
            ips = sorted({i[4][0] for i in infos})
            return (n, ips)
        except OSError:
            return (n, None)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for r in pool.map(one, names):
            out.append(r)
    return out
