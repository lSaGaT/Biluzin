# -*- coding: utf-8 -*-
"""Modos `s3` e `gcs`: checagem read-only de buckets (modes_store.kf).

So status probe: 404=ausente, 403=existe (negado), 200=publico.
Nunca GET de conteudo, nunca escrita.

Nome de bucket e namespace GLOBAL: um hit em nome generico ("backup",
"videos") quase sempre e bucket de TERCEIRO. Quando o alvo e conhecido
(-D/--target, ou o wizard passa o dominio):
  * deriva candidatos do alvo (marca + sufixos: -backup, -exports...);
  * classifica cada hit: "target" (nome contem a marca) ou "third_party";
  * hits de terceiro ficam ocultos por padrao (contados no resumo);
    --all-buckets os emite rotulados [terceiro].
Sem alvo informado, comporta-se como antes (emite tudo).
"""

import re
import sys
from concurrent.futures import ThreadPoolExecutor

from ..util import load_wordlist, bucket_url, Progress

S3_ENDPOINT = "http://%s.s3.amazonaws.com/"
GCS_ENDPOINT = "https://storage.googleapis.com/%s/"

_STATE = {200: "public", 403: "exists_denied", 301: "exists_redirect", 404: "absent"}

# derivacao de candidatos a partir da marca do alvo
_SUFFIXES = (
    "", "-backup", "-backups", "-bak", "-prod", "-production", "-dev",
    "-development", "-test", "-testing", "-staging", "-stage", "-qa", "-uat",
    "-export", "-exports", "-data", "-logs", "-log", "-media", "-static",
    "-assets", "-files", "-file", "-docs", "-documents", "-img", "-images",
    "-db", "-database", "-dump", "-sql", "-archive", "-private", "-public",
    "-secret", "-secrets", "-internal", "-web", "-app", "-api", "-cdn",
    "-download", "-downloads", "-upload", "-uploads", "-video", "-videos",
    "-audio", "-photo", "-photos", "-user", "-users", "-client", "-clients",
    "-invoice", "-invoices", "-payment", "-payments", "-hr", "-erp", "-crm",
    "-config", "-conf", "-old", "-new", "-tmp", "-temp",
)
_PREFIXES = ("backup-", "bak-", "dev-", "test-", "staging-", "prod-", "data-")


def _brand_of(target: str) -> str:
    """'nodoprime.com.br' -> 'nodoprime'; marca pura passa como esta."""
    t = (target or "").strip().lower().rstrip(".")
    if not t:
        return ""
    return t.split(".")[0]


def _sanitize(name: str) -> str:
    """Ajusta ao formato de nome de bucket (minusculo, [a-z0-9.-], 3+ chars)."""
    name = re.sub(r"[^a-z0-9.-]", "-", name.lower())
    name = re.sub(r"-{2,}", "-", name).strip("-.")
    return name if len(name) >= 3 else ""


def derive_candidates(brand: str):
    """Nomes de bucket derivados da marca: marca+sufixo e prefixo+marca."""
    out = []
    for suf in _SUFFIXES:
        n = _sanitize(brand + suf)
        if n:
            out.append(n)
    for pre in _PREFIXES:
        n = _sanitize(pre + brand)
        if n:
            out.append(n)
    return list(dict.fromkeys(out))


def run_store_mode(cfg, log, emitter, mode_name):
    http = cfg.http
    endpoint = cfg.endpoint or (S3_ENDPOINT if mode_name == "s3" else GCS_ENDPOINT)
    if "%s" not in endpoint:
        sys.stderr.write("biluzim %s: endpoint precisa de %%s no lugar do nome "
                         "do bucket (ex.: http://%%s.s3.amazonaws.com/)\n" % mode_name)
        raise SystemExit(2)

    brand = _brand_of(getattr(cfg, "target", ""))
    show_third = getattr(cfg, "all_buckets", False)

    buckets = load_wordlist(cfg.wordlist)
    if brand:
        buckets = list(dict.fromkeys(buckets + derive_candidates(brand)))
        log.info("%s: alvo %s (marca '%s') - candidatos derivados incluidos; "
                 "hits de terceiros ficam ocultos (use --all-buckets para ver)"
                 % (mode_name, cfg.target, brand))
    log.info("%s: %d candidatos, endpoint %s" % (mode_name, len(buckets), endpoint))

    found = errors = third_party = 0
    progress = Progress(log, len(buckets), mode_name, enabled=not cfg.quiet and len(buckets) >= 50)
    width = max(1, cfg.threads)

    def probe(bucket):
        url = bucket_url(endpoint, bucket)
        try:
            r = http.get(url)
            return (bucket, url, r.status, "")
        except Exception as e:
            return (bucket, url, None, str(e)[:100])

    with ThreadPoolExecutor(max_workers=width) as pool:
        for bucket, url, status, err in pool.map(probe, buckets):
            progress.tick()
            if status is None:
                errors += 1
                log.debug("erro: %s -> %s" % (bucket, err))
                continue
            state = _STATE.get(status, "inconclusive")
            if state == "absent":
                continue
            owner = "unknown"
            if brand:
                owner = "target" if brand in bucket else "third_party"
            if owner == "third_party" and not show_third:
                third_party += 1
                continue
            found += 1
            progress.found_one()
            line = "%d  %-14s  %s" % (status, state, url)
            if owner == "third_party":
                line = "[terceiro] " + line
            emitter.emit({
                "type": mode_name, "bucket": bucket, "url": url,
                "status": status, "state": state, "owner": owner,
                "line": line,
            })

    progress.finish()
    if brand:
        log.info("%s: %d com vinculo ao alvo; %d de terceiros ocultados%s; %d erros"
                 % (mode_name, found, third_party,
                    " (visiveis com --all-buckets)" if not show_third else "", errors))
    return found, errors
