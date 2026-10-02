# -*- coding: utf-8 -*-
"""Modos `s3` e `gcs`: checagem read-only de buckets (modes_store.kf).

So status probe: 404=ausente, 403=existe (negado), 200=publico.
Nunca GET de conteudo, nunca escrita.
"""

import sys
from concurrent.futures import ThreadPoolExecutor

from ..util import load_wordlist, bucket_url, Progress

S3_ENDPOINT = "http://%s.s3.amazonaws.com/"
GCS_ENDPOINT = "https://storage.googleapis.com/%s/"

_STATE = {200: "public", 403: "exists_denied", 301: "exists_redirect", 404: "absent"}


def run_store_mode(cfg, log, emitter, mode_name):
    http = cfg.http
    endpoint = cfg.endpoint or (S3_ENDPOINT if mode_name == "s3" else GCS_ENDPOINT)
    if "%s" not in endpoint:
        sys.stderr.write("biluzim %s: endpoint precisa de %%s no lugar do nome "
                         "do bucket (ex.: http://%%s.s3.amazonaws.com/)\n" % mode_name)
        raise SystemExit(2)
    buckets = load_wordlist(cfg.wordlist)
    log.info("%s: %d candidatos, endpoint %s" % (mode_name, len(buckets), endpoint))

    found = errors = 0
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
            found += 1
            progress.tick(found_hit=True)
            emitter.emit({
                "type": mode_name, "bucket": bucket, "url": url,
                "status": status, "state": state,
                "line": "%d  %-14s  %s" % (status, state, url),
            })

    progress.finish()
    return found, errors
