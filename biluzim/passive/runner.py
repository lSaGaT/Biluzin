# -*- coding: utf-8 -*-
"""Runner do modo passivo: orquestra fontes em paralelo com rate-limit.

Garantias passiveis herdadas do lunatic:
  * nenhuma fonte resolve DNS do alvo nem faz requisicao HTTP a ele;
  * nomes crus sao normalizados e filtrados pelo escopo do dominio alvo;
  * credenciais nunca sao logadas.
"""

import threading

from .base import all_sources, get_source, Session, SourceError
from . import sources  # noqa: F401  (garante o registro dos adapters)

from ..util import normalize_candidate, Throttle


def _load_creds(config, source_info, log):
    """Credenciais de uma fonte: config JSON > variaveis de ambiente.

    config: {'sources': {fonte: {campo: valor}}}
    env:    BILUZIM_<FONTE>_<CAMPO>
    """
    creds = {}
    fields = list(source_info.cred_fields)
    if not fields:
        return creds
    src_cfg = (config or {}).get("sources", {}).get(source_info.name, {})
    for f in fields:
        v = str(src_cfg.get(f, "") or "").strip()
        env = "%s_%s" % (source_info.env_prefix, f.upper())
        if not v:
            import os
            v = str(os.environ.get(env, "") or "").strip()
        placeholders = ("<", "your_", "changeme", "todo", "none", "null")
        if v and v.lower() not in placeholders and not v.startswith("<"):
            creds[f] = v
    return creds


def _usable(source_info, creds):
    if source_info.disabled:
        return False, "desabilitada"
    if source_info.auth == "required":
        for f in source_info.cred_fields:
            if not creds.get(f):
                return False, "sem chave (%s)" % "/".join(source_info.cred_fields)
    return True, ""


def list_sources_table(config=None):
    """Linhas para --list-sources: (nome, auth, default, chave?, url)."""
    rows = []
    for cls in all_sources():
        info = cls.INFO
        creds = _load_creds(config, info, None)
        usable, why = _usable(info, creds)
        has_key = "sim" if any(creds.get(f) for f in info.cred_fields) else (
            "-" if info.auth == "none" else "nao")
        rows.append({
            "name": info.name,
            "url": info.url,
            "auth": info.auth,
            "default": bool(info.default and usable),
            "phase2": info.phase2,
            "has_key": has_key,
            "status": "ok" if usable else why,
        })
    return rows


class _ThrottledHttp:
    """Proxy do HttpClient que aplica o rate-limit da fonte a cada REQUISICAO
    (nao a cada nome emitido - uma resposta pode trazer milhares de nomes)."""

    def __init__(self, http, throttle):
        self._http = http
        self._throttle = throttle

    def _gate(self):
        self._throttle.wait()

    def get(self, url, headers=None):
        self._gate()
        return self._http.get(url, headers)

    def head(self, url, headers=None):
        self._gate()
        return self._http.head(url, headers)

    def get_json(self, url, headers=None):
        self._gate()
        return self._http.get_json(url, headers)

    def post_json(self, url, headers=None, payload=None):
        self._gate()
        return self._http.post_json(url, headers, payload)

    def request(self, url, method="GET", headers=None, data=None):
        self._gate()
        return self._http.request(url, method, headers, data)


class ReconRunner:
    """Executa fontes passivas e emite subdominios dedupados."""

    def __init__(self, domain, http, log, emitter, config=None,
                 selected=None, excluded=None, use_all=False,
                 max_pages=10, workers=8):
        self.domain = domain
        self.http = http
        self.log = log
        self.emitter = emitter
        self.config = config or {}
        self.selected = selected or []
        self.excluded = set(excluded or [])
        self.use_all = use_all
        self.max_pages = max_pages
        self.workers = max(1, workers)
        self.results = set()
        self.name_sources = {}
        self.ips = set()
        self.summary = []  # (nome, status, detalhe)
        self._lock = threading.Lock()
        self._interrupt = threading.Event()

    def interrupt(self):
        self._interrupt.set()

    # ------------------------------------------------------------------
    def _plan(self):
        plan = []
        for cls in all_sources():
            info = cls.INFO
            if info.name in self.excluded:
                continue
            if self.selected:
                if info.name in self.selected:
                    plan.append((cls, info))
                continue
            if self.use_all or info.default:
                plan.append((cls, info))
        return plan

    def _emit_name(self, raw, source_name):
        if self._interrupt.is_set():
            return
        name = normalize_candidate(str(raw), self.domain)
        if not name:
            return
        with self._lock:
            self.name_sources.setdefault(name, set()).add(source_name)
            if name in self.results:
                return
            self.results.add(name)
        rec = {"type": "subdomain", "domain": self.domain, "subdomain": name}
        if self.emitter.fmt == "jsonl" and self.emitter.show_sources:
            rec["sources"] = sorted(self.name_sources[name])
        self.emitter.emit(rec)

    def _run_source(self, cls, info):
        creds = _load_creds(self.config, info, self.log)
        usable, why = _usable(info, creds)
        if not usable:
            self.summary.append((info.name, "skipped", why))
            return
        # rate-limit da fonte vale por REQUISICAO HTTP ao provedor
        throttled_http = _ThrottledHttp(self.http, Throttle(info.rps))

        def emit(raw):
            self._emit_name(raw, info.name)

        sess = Session(throttled_http, creds, self.log, max_pages=self.max_pages,
                       report_ip=lambda ip: self.ips.add(ip) if _is_public(ip) else None)
        try:
            if self._interrupt.is_set():
                raise SourceError("canceled", "interrompido")
            cls().enumerate(self.domain, sess, emit)
            self.summary.append((info.name, "ok", ""))
        except SourceError as e:
            self.summary.append((info.name, "failed", e.label()))
        except KeyboardInterrupt:
            self.summary.append((info.name, "failed", "interrompido"))
        except Exception as e:
            self.summary.append((info.name, "failed",
                                 "inesperado: %s" % (str(e)[:120] or type(e).__name__)))

    # ------------------------------------------------------------------
    def run(self):
        plan = self._plan()
        if not plan:
            return []
        from concurrent.futures import ThreadPoolExecutor
        # fase 1: fontes normais
        normal = [(c, i) for c, i in plan if not i.phase2]
        phase2 = [(c, i) for c, i in plan if i.phase2]
        with ThreadPoolExecutor(max_workers=min(self.workers, max(1, len(normal)))) as pool:
            futures = [pool.submit(self._run_source, c, i) for c, i in normal]
            for f in futures:
                f.result()
        # fase 2: fontes que so usam IPs ja coletados (internetdb)
        for cls, info in phase2:
            ips = sorted(self.ips)
            if not ips:
                self.summary.append((info.name, "skipped", "nenhum IP reportado na fase 1"))
                continue
            creds = _load_creds(self.config, info, self.log)
            sess = Session(_ThrottledHttp(self.http, Throttle(info.rps)), creds, self.log,
                           max_pages=self.max_pages, ips=ips)

            def emit(raw):
                self._emit_name(raw, info.name)

            try:
                cls().enumerate(self.domain, sess, emit)
                self.summary.append((info.name, "ok", ""))
            except SourceError as e:
                self.summary.append((info.name, "failed", e.label()))
            except Exception as e:
                self.summary.append((info.name, "failed", "inesperado: %s" % str(e)[:120]))
        return sorted(self.results)


def _is_public(ip: str) -> bool:
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved or a.is_unspecified)
    except ValueError:
        return False
