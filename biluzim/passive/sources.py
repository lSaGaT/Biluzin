# -*- coding: utf-8 -*-
"""Fontes OSINT passivas - porte dos adapters do lunatic (Go) para Python.

Cada classe consulta apenas o endpoint de busca do provedor e emite nomes
cruas. Detalhes de endpoint/parse/rate-limit copiados do repositorio de
origem (lunatic, internal/sources/*.go, revisado em 2026-09-29).

Tipos de credencial: "none", "optional" (funciona sem), "required".
"""

import ipaddress
import json
import re
import urllib.parse

from .base import (
    Info, Source, SourceError, register,
    AUTH, RATE_LIMITED, UNEXPECTED, UNAVAILABLE,
)

# --------------------------------------------------------------------------
# helpers compartilhados
# --------------------------------------------------------------------------


def _host_from_url(raw: str) -> str:
    """Hostname de uma URL indexada (porte de waybackarchiveHost)."""
    s = (raw or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    for ch in "/?#":
        i = s.find(ch)
        if i >= 0:
            s = s[:i]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    for _ in range(2):
        dec = urllib.parse.unquote(s)
        s = dec
    for ch in "/?#:":
        i = s.find(ch)
        if i >= 0:
            s = s[:i]
    return s.strip(". *").strip().lower()


# --------------------------------------------------------------------------
# gratuitas, executadas por padrao (Default: true)
# --------------------------------------------------------------------------


@register
class Crtsh(Source):
    """crt.sh - Certificate Transparency (Sectigo)."""
    INFO = Info("crtsh", "https://crt.sh", rps=0.2)

    def enumerate(self, domain, session, emit):
        u = "https://crt.sh/?q=%s&output=json" % urllib.parse.quote("%." + domain, safe="")
        rows = session.http.get_json(u, {"Accept": "application/json"})
        if not isinstance(rows, list):
            raise SourceError(UNEXPECTED, "crt.sh nao devolveu uma lista JSON")
        for r in rows:
            for n in str(r.get("name_value", "")).split("\n"):
                n = n.strip()
                if n and "@" not in n:  # pula SANs de e-mail (dados pessoais)
                    emit(n)


@register
class Alienvault(Source):
    """AlienVault OTX - passive DNS. Chave opcional (cota maior)."""
    INFO = Info("alienvault", "https://otx.alienvault.com", auth="optional",
                cred_fields=["api_key"], rps=2)

    def enumerate(self, domain, session, emit):
        headers = {"Accept": "application/json"}
        try:
            from .base import pick_key
            headers["X-OTX-API-KEY"] = pick_key(session.creds, "api_key")
        except SourceError:
            pass
        u = "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns" % urllib.parse.quote(domain)
        r = session.http.get_json(u, headers)
        msg = (r.get("error") or r.get("detail") or "").strip() if isinstance(r, dict) else ""
        if msg:
            low = msg.lower()
            if "api key" in low or "unauthor" in low or "forbidden" in low:
                raise SourceError(AUTH, msg)
            if "throttl" in low or "rate limit" in low or "too many" in low:
                raise SourceError(RATE_LIMITED, msg)
            raise SourceError(UNEXPECTED, msg)
        for e in (r.get("passive_dns") or []) if isinstance(r, dict) else []:
            h = e.get("hostname")
            if h:
                emit(h)


@register
class Waybackarchive(Source):
    """Wayback Machine (Internet Archive) - indice CDX, nunca paginas."""
    INFO = Info("waybackarchive", "https://web.archive.org", rps=0.5)

    def enumerate(self, domain, session, emit):
        suffix = "." + domain
        seen = set()
        resume = ""
        base = ("https://web.archive.org/cdx/search/cdx?url=%s"
                "&output=txt&fl=original&collapse=urlkey&limit=50000&showResumeKey=true"
                % urllib.parse.quote("*." + domain, safe=""))
        for _page in range(max(1, session.max_pages)):
            u = base + ("&resumeKey=" + urllib.parse.quote(resume) if resume else "")
            resp = session.http.get(u)
            body = resp.text().replace("\r\n", "\n")
            rows, tail = body, ""
            if "\n\n" in body:
                rows, tail = body.split("\n\n", 1)
                tail = tail.strip()
            for line in rows.split("\n"):
                h = _host_from_url(line)
                if h and h.endswith(suffix) and h not in seen:
                    seen.add(h)
                    emit(h)
            if not tail or tail == resume or any(c in tail for c in " \n"):
                return
            resume = tail


@register
class Anubis(Source):
    """Anubis DB - base colaborativa de subdominios."""
    INFO = Info("anubis", "https://anubisdb.com", rps=1)

    def enumerate(self, domain, session, emit):
        u = "https://anubisdb.com/anubis/subdomains/" + urllib.parse.quote(domain)
        names = session.http.get_json(u, {"Accept": "application/json"})
        for n in names or []:
            if n:
                emit(n)


@register
class Shodanct(Source):
    """Shodan Certificate Transparency (ctl.shodan.io) - sem chave."""
    INFO = Info("shodanct", "https://ctl.shodan.io", rps=1)

    def enumerate(self, domain, session, emit):
        u = "https://ctl.shodan.io/api/v1/domain/%s/hostnames" % urllib.parse.quote(domain)
        resp = session.http.get(u)
        try:
            raw = json.loads(resp.text())
        except json.JSONDecodeError as e:
            raise SourceError(UNEXPECTED, "shodanct: JSON invalido: %s" % e)
        if isinstance(raw, list):
            for h in raw:
                emit(h)
        elif isinstance(raw, dict):
            if raw.get("error"):
                raise SourceError(UNEXPECTED, "shodanct: %s" % raw["error"])
            for h in raw.get("hostnames") or []:
                emit(h)
        else:
            raise SourceError(UNEXPECTED, "shodanct: formato inesperado")


@register
class Subdomaincenter(Source):
    """Subdomain Center - API gratuita."""
    INFO = Info("subdomaincenter", "https://www.subdomain.center", rps=0.5)

    def enumerate(self, domain, session, emit):
        u = "https://api.subdomain.center/?domain=" + urllib.parse.quote(domain)
        lst = session.http.get_json(u)
        for h in lst or []:
            emit(h)


@register
class Threatminer(Source):
    """ThreatMiner rt=5 (subdominios). 10 consultas/minuto."""
    INFO = Info("threatminer", "https://www.threatminer.org", rps=0.1)

    def enumerate(self, domain, session, emit):
        u = ("https://api.threatminer.org/v2/domain.php?q=%s&rt=5"
             % urllib.parse.quote(domain))
        r = session.http.get_json(u)
        code = str(r.get("status_code", "")).strip().strip('"')
        if code == "404":
            return
        if code == "429":
            raise SourceError(RATE_LIMITED, str(r.get("status_message", "")))
        if code != "200":
            raise SourceError(UNEXPECTED, "threatminer status_code=%s: %s"
                              % (code or "?", r.get("status_message", "")))
        for h in r.get("results") or []:
            emit(h)


@register
class Hackertarget(Source):
    """HackerTarget hostsearch. Cota gratuita por IP; chave opcional."""
    INFO = Info("hackertarget", "https://api.hackertarget.com",
                auth="optional", cred_fields=["api_key"], rps=1)

    def enumerate(self, domain, session, emit):
        headers = {}
        from .base import pick_key
        try:
            headers["X-API-Key"] = pick_key(session.creds, "api_key")
        except SourceError:
            pass
        u = "https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(domain)
        body = session.http.get(u, headers).text().strip()
        if not body:
            return
        low = body.lower()
        if low.startswith("api count exceeded") or "quota exceeded" in low or "increase quota" in low:
            raise SourceError(RATE_LIMITED, "hackertarget: cota esgotada")
        if low.startswith("no records found"):
            return
        if low.startswith("error"):
            if "api key" in low:
                raise SourceError(AUTH, "hackertarget rejeitou a chave")
            raise SourceError(UNEXPECTED, "hackertarget: %s" % body[:120])
        for line in body.split("\n"):
            line = line.strip()
            if not line:
                continue
            name = line.split(",")[0].strip()
            if name:
                session.report_ip(line.split(",")[1].strip() if "," in line else "")
                emit(name)


@register
class Scanmalware(Source):
    """scanmalware.com - CT/DNS agregado, endpoint unico permitido."""
    INFO = Info("scanmalware", "https://scanmalware.com", rps=2)

    def enumerate(self, domain, session, emit):
        u = ("https://scanmalware.com/api/v1/ct/dns/%s?subdomain_limit=5000"
             % urllib.parse.quote(domain))
        v = session.http.get_json(u, {"Accept": "application/json"})
        if isinstance(v, dict):
            for k in ("error", "message", "detail"):
                m = v.get(k)
                if isinstance(m, str) and m and len(v) <= 3:
                    raise SourceError(UNEXPECTED, m)
        elif not isinstance(v, list):
            raise SourceError(UNEXPECTED, "scanmalware: tipo de JSON inesperado")

        def walk(node):
            if isinstance(node, dict):
                for val in node.values():
                    walk(val)
            elif isinstance(node, list):
                for val in node:
                    walk(val)
            elif isinstance(node, str):
                if node.endswith("." + domain) or node == domain:
                    emit(node)

        walk(v)


@register
class Thc(Source):
    """THC org - lookup de subdominios (POST paginado)."""
    INFO = Info("thc", "https://ip.thc.org", rps=1)

    def enumerate(self, domain, session, emit):
        state = ""
        for _page in range(max(1, session.max_pages)):
            r = session.http.post_json(
                "https://ip.thc.org/api/v1/lookup/subdomains",
                payload={"domain": domain, "page_state": state, "limit": 1000},
            )
            err = (r.get("error") or "").strip()
            if err:
                low = err.lower()
                if "rate" in low or "too many" in low:
                    raise SourceError(RATE_LIMITED, err)
                raise SourceError(UNEXPECTED, err)
            for d in r.get("domains") or []:
                name = d if isinstance(d, str) else str(d)
                session.report_ip(d.get("ip", "") if isinstance(d, dict) else "")
                emit(name)
            state = (r.get("next_page_state") or "").strip()
            if not state:
                return


@register
class Urlscan(Source):
    """urlscan.io - SOMENTE a API de busca (nunca submete scan)."""
    INFO = Info("urlscan", "https://urlscan.io", auth="optional",
                cred_fields=["api_key"], rps=1)

    def enumerate(self, domain, session, emit):
        headers = {}
        from .base import pick_key
        try:
            headers["API-Key"] = pick_key(session.creds, "api_key")
        except SourceError:
            pass
        after = ""
        for _page in range(max(1, session.max_pages)):
            u = ("https://urlscan.io/api/v1/search/?q=%s&size=100"
                 % urllib.parse.quote("domain:" + domain))
            if after:
                u += "&search_after=" + urllib.parse.quote(after)
            r = session.http.get_json(u, headers)
            results = r.get("results") or []
            for row in results:
                page = row.get("page") or {}
                task = row.get("task") or {}
                for h in (page.get("domain"), task.get("domain")):
                    if h:
                        emit(h)
                for u_ in (page.get("url"), task.get("url")):
                    host = _host_from_url(u_)
                    if host:
                        emit(host)
                sort = row.get("sort") or []
                if sort:
                    after = ",".join(str(s) for s in sort)
            if not r.get("has_more") or not after:
                return


@register
class Internetdb(Source):
    """Shodan InternetDB - fase 2: consulta so IPs ja reportados (fase 1)."""
    INFO = Info("internetdb", "https://internetdb.shodan.io", rps=1, phase2=True)
    MAX_IPS = 100

    def enumerate(self, domain, session, emit):
        n = 0
        for ip in session.ips:
            if n >= self.MAX_IPS:
                break
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            n += 1
            u = "https://internetdb.shodan.io/" + urllib.parse.quote(ip)
            try:
                r = session.http.get_json(u)
            except Exception as e:
                from .base import TIMEOUT
                if getattr(e, "status", None) == 404:
                    continue
                if isinstance(e, SourceError) and e.kind == TIMEOUT:
                    raise
                continue
            for h in r.get("hostnames") or []:
                emit(h)


# --------------------------------------------------------------------------
# gratuitas, fora do conjunto padrao (pesadas/instaveis)
# --------------------------------------------------------------------------


@register
class Rapiddns(Source):
    """RapidDNS - raspagem HTML das paginas de subdominio."""
    INFO = Info("rapiddns", "https://rapiddns.io", default=False, rps=0.2)

    @staticmethod
    def _is_challenge(body: str) -> bool:
        low = body.lower()
        return ("captcha" in low or "just a moment" in low
                or "challenge-platform" in low)

    def enumerate(self, domain, session, emit):
        seen = set()
        from ..util import find_in_text
        for page in range(1, max(1, session.max_pages) + 1):
            u = "https://rapiddns.io/subdomain/%s?page=%d&full=1" % (domain, page)
            resp = session.http.get(u, {"Accept": "text/html"})
            if resp.status == 404:
                return
            if resp.status == 403:
                raise SourceError(UNAVAILABLE, "rapiddns bloqueou o pedido (HTTP 403)")
            body = resp.text()
            if self._is_challenge(body):
                raise SourceError(UNAVAILABLE, "rapiddns serviu pagina de challenge; nao contornada")
            fresh = 0
            for n in find_in_text(body, domain):
                if n not in seen:
                    seen.add(n)
                    fresh += 1
                    emit(n)
            if fresh == 0:
                return


@register
class Digitorus(Source):
    """certificatedetails.com - paginas publicas de CT (raspagem)."""
    INFO = Info("digitorus", "https://certificatedetails.com", default=False, rps=0.5)

    def enumerate(self, domain, session, emit):
        u = "https://certificatedetails.com/" + urllib.parse.quote(domain)
        resp = session.http.get(u, {"Accept": "text/html"})
        if resp.status in (403, 503):
            raise SourceError(UNAVAILABLE,
                              "certificatedetails.com recusou o pedido (HTTP %d)" % resp.status)
        body = resp.text()
        if "just a moment" in body.lower() or "captcha" in body.lower():
            raise SourceError(UNAVAILABLE, "certificatedetails.com serviu challenge; nao contornado")
        from ..util import find_in_text
        for n in find_in_text(body, domain):
            emit(n)


@register
class Commoncrawl(Source):
    """Common Crawl - ultimos 3 indices, NDJSON de URLs."""
    INFO = Info("commoncrawl", "https://commoncrawl.org", default=False, rps=0.5)
    INDEXES = 3
    _ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

    def enumerate(self, domain, session, emit):
        info = session.http.get_json("https://index.commoncrawl.org/collinfo.json")
        ids = sorted((i.get("id") for i in info if self._ID_RE.match(i.get("id", ""))),
                     reverse=True)[:self.INDEXES]
        if not ids:
            raise SourceError(UNEXPECTED, "commoncrawl: collinfo.json sem indice utilizavel")
        seen = set()
        for cid in ids:
            base = ("https://index.commoncrawl.org/%s-index?url=%s&output=json&fl=url"
                    % (cid, urllib.parse.quote("*." + domain, safe="")))
            try:
                np = session.http.get_json(base + "&showNumPages=true")
            except Exception as e:
                if getattr(e, "status", None) == 404:
                    continue
                raise
            pages = min(int(np.get("pages") or 0), max(1, session.max_pages))
            for p in range(pages):
                resp = session.http.get(base + "&page=%d" % p)
                if resp.status == 404:
                    return
                for line in resp.text().split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        raise SourceError(UNEXPECTED, "commoncrawl: linha NDJSON invalida")
                    if rec.get("error"):
                        raise SourceError(UNEXPECTED, "commoncrawl: %s" % rec["error"])
                    h = _host_from_url(rec.get("url", ""))
                    if h and h.endswith("." + domain) and h not in seen:
                        seen.add(h)
                        emit(h)


@register
class Arquivopt(Source):
    """Arquivo.pt (arquivo web portugues) - indice CDX."""
    INFO = Info("arquivopt", "https://arquivo.pt", default=False, rps=0.5)

    def enumerate(self, domain, session, emit):
        u = ("https://arquivo.pt/wayback/cdx?url=%s&output=json&fields=url&limit=100000"
             % urllib.parse.quote("*." + domain, safe=""))
        resp = session.http.get(u)
        seen = set()
        for line in resp.text().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            h = _host_from_url(row.get("url", ""))
            if h and h.endswith("." + domain) and h not in seen:
                seen.add(h)
                emit(h)


@register
class Sitedossier(Source):
    """SiteDossier - parentdomain com paginacao por link 'next'."""
    INFO = Info("sitedossier", "http://www.sitedossier.com", default=False, rps=0.2)
    _NEXT_RE = re.compile(r'<a href="(/parentdomain/[A-Za-z0-9./_-]+)"><b>')

    def enumerate(self, domain, session, emit):
        from ..util import find_in_text
        path = "/parentdomain/" + urllib.parse.quote(domain)
        visited = set()
        for _page in range(max(1, session.max_pages)):
            if not path or path in visited:
                return
            visited.add(path)
            resp = session.http.get("http://www.sitedossier.com" + path)
            body = resp.text()
            low = body.lower()
            if any(m in low for m in ("captcha", "unusual traffic", "automated queries",
                                      "you have been blocked", "access denied")):
                raise SourceError(UNAVAILABLE, "sitedossier: anti-bot; nao contornado")
            for h in find_in_text(body, domain):
                emit(h)
            path = ""
            for m in self._NEXT_RE.finditer(body):
                if m.group(1) not in visited:
                    path = m.group(1)
                    break


# --------------------------------------------------------------------------
# com chave obrigatoria ( entram quando credenciadas no config )
# --------------------------------------------------------------------------


@register
class Virustotal(Source):
    """VirusTotal v3 - 4 req/min na chave gratuita."""
    INFO = Info("virustotal", "https://www.virustotal.com", auth="required",
                cred_fields=["api_key"], rps=0.25)

    def enumerate(self, domain, session, emit):
        from .base import pick_key
        key = pick_key(session.creds, "api_key")
        cursor = ""
        for _page in range(max(1, session.max_pages)):
            u = ("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40"
                 % urllib.parse.quote(domain))
            if cursor:
                u += "&cursor=" + urllib.parse.quote(cursor)
            r = session.http.get_json(u, {"x-apikey": key})
            err = r.get("error") or {}
            code = err.get("code", "")
            if code == "NotFoundError":
                return
            if code in ("AuthenticationRequiredError", "WrongCredentialsError"):
                raise SourceError(AUTH, err.get("message", "credencial invalida"))
            if code == "RateLimitError":
                raise SourceError(RATE_LIMITED, err.get("message", "cota esgotada"))
            if code:
                raise SourceError(UNEXPECTED, "%s: %s" % (code, err.get("message", "")))
            for item in r.get("data") or []:
                if item.get("id"):
                    emit(item["id"])
            cursor = ((r.get("meta") or {}).get("cursor") or "").strip()
            if not cursor:
                return


@register
class Shodan(Source):
    """Shodan DNS /dns/domain (costuma exigir plano pago)."""
    INFO = Info("shodan", "https://api.shodan.io", auth="required",
                cred_fields=["api_key"], rps=1)

    def enumerate(self, domain, session, emit):
        from .base import pick_key
        key = pick_key(session.creds, "api_key")
        for page in range(1, max(1, session.max_pages) + 1):
            u = ("https://api.shodan.io/dns/domain/%s?key=%s&page=%d"
                 % (urllib.parse.quote(domain), urllib.parse.quote(key), page))
            r = session.http.get_json(u)
            if r.get("error"):
                msg = str(r["error"])
                low = msg.lower()
                if "not found" in low or "no information" in low:
                    return
                if "access denied" in low or "membership" in low or "upgrade" in low:
                    raise SourceError(AUTH, msg)
                if "rate" in low or "limit" in low:
                    raise SourceError(RATE_LIMITED, msg)
                raise SourceError(UNEXPECTED, msg)
            labels = list(r.get("subdomains") or [])
            for d in r.get("data") or []:
                if isinstance(d, dict) and d.get("subdomain"):
                    labels.append(d["subdomain"])
            if not labels:
                return
            for l in labels:
                l = str(l).strip()
                if not l or l == "@":
                    continue
                emit(l if l.endswith("." + domain) else l + "." + domain)


@register
class Chaos(Source):
    """ProjectDiscovery Chaos - requer chave."""
    INFO = Info("chaos", "https://dns.projectdiscovery.io", auth="required",
                cred_fields=["api_key"], rps=1)

    def enumerate(self, domain, session, emit):
        from .base import pick_key
        key = pick_key(session.creds, "api_key")
        u = "https://dns.projectdiscovery.io/dns/%s/subdomains" % urllib.parse.quote(domain)
        r = session.http.get_json(u, {"Authorization": key, "Accept": "application/json"})
        subs = r.get("subdomains") or []
        if not subs and not r.get("domain") and (r.get("error") or r.get("message")):
            raise SourceError(UNEXPECTED, str(r.get("error") or r.get("message")))
        for label in subs:
            label = str(label).strip().strip(". ")
            if label and label != "*":
                emit(label + "." + domain)


@register
class Fullhunt(Source):
    """FullHunt - requer chave (X-API-KEY)."""
    INFO = Info("fullhunt", "https://fullhunt.io", auth="required",
                cred_fields=["api_key"], rps=0.05)

    def enumerate(self, domain, session, emit):
        from .base import pick_key
        key = pick_key(session.creds, "api_key")
        u = "https://fullhunt.io/api/v1/domain/%s/subdomains" % urllib.parse.quote(domain)
        r = session.http.get_json(u, {"X-API-KEY": key})
        status = int(r.get("status") or 0)
        msg = str(r.get("message") or "")
        if status in (0, 200):
            for h in r.get("hosts") or []:
                emit(h)
            return
        if status in (401, 403):
            raise SourceError(AUTH, msg or "credencial invalida")
        if status in (402, 429):
            raise SourceError(RATE_LIMITED, msg or "cota esgotada")
        raise SourceError(UNEXPECTED, "fullhunt status %d: %s" % (status, msg))


@register
class Leakix(Source):
    """LeakIX - requer chave; resultados atrasados no plano gratuito."""
    INFO = Info("leakix", "https://leakix.net", auth="required",
                cred_fields=["api_key"], rps=0.5)

    def enumerate(self, domain, session, emit):
        from .base import pick_key
        key = pick_key(session.creds, "api_key")
        u = "https://leakix.net/api/subdomains/" + urllib.parse.quote(domain)
        body = session.http.get(u, {"api-key": key, "Accept": "application/json"}).text().strip()
        if not body or body == "null":
            return
        try:
            rows = json.loads(body)
        except json.JSONDecodeError as e:
            raise SourceError(UNEXPECTED, "leakix: JSON invalido: %s" % e)
        for r in rows if isinstance(rows, list) else []:
            if r.get("subdomain"):
                emit(r["subdomain"])


@register
class Bufferover(Source):
    """BufferOver tls.bufferover.run - requer chave."""
    INFO = Info("bufferover", "https://tls.bufferover.run", auth="required",
                cred_fields=["api_key"], rps=1)

    def enumerate(self, domain, session, emit):
        from .base import pick_key
        key = pick_key(session.creds, "api_key")
        u = "https://tls.bufferover.run/dns?q=" + urllib.parse.quote("." + domain)
        r = session.http.get_json(u, {"x-api-key": key, "Accept": "application/json"})
        meta_err = ((r.get("Meta") or {}).get("Errors") or [])
        if meta_err or r.get("error"):
            msg = r.get("error") or json.dumps(meta_err[0])
            low = str(msg).lower()
            if "unauthor" in low or "forbidden" in low or "api key" in low:
                raise SourceError(AUTH, str(msg))
            if "rate" in low or "too many" in low or "throttl" in low:
                raise SourceError(RATE_LIMITED, str(msg))
            raise SourceError(UNEXPECTED, str(msg))
        rows = list(r.get("FDNS_A") or []) + list(r.get("RDNS") or []) + list(r.get("Results") or [])
        if not rows and r.get("message"):
            raise SourceError(UNEXPECTED, str(r["message"]))
        for e in rows:
            row = e if isinstance(e, str) else json.dumps(e)
            # FDNS_A vem como "ip,host"
            parts = row.split(",")
            if len(parts) == 2:
                session.report_ip(parts[0].strip())
                emit(parts[1].strip())
            else:
                emit(row.strip())


@register
class Github(Source):
    """GitHub code search por fragmentos com o dominio (requer token)."""
    INFO = Info("github", "https://github.com", auth="required",
                cred_fields=["token"], rps=0.15)

    def enumerate(self, domain, session, emit):
        from .base import pick_key
        from ..util import find_in_text
        token = pick_key(session.creds, "token")
        headers = {
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github.text-match+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        for page in range(1, min(max(1, session.max_pages), 10) + 1):
            u = ("https://api.github.com/search/code?q=%s&per_page=100&page=%d"
                 % (urllib.parse.quote('"%s"' % domain), page))
            try:
                resp = session.http.get(u, headers)
            except Exception as e:
                status = getattr(e, "status", None)
                if status == 403 or status == 429:
                    raise SourceError(RATE_LIMITED, "github: limite de busca de codigo")
                raise
            if resp.status == 422 and page > 1:
                return
            if resp.status in (403, 429):
                raise SourceError(RATE_LIMITED, "github: limite de busca de codigo")
            try:
                out = json.loads(resp.text())
            except json.JSONDecodeError as e:
                raise SourceError(UNEXPECTED, "github: JSON invalido: %s" % e)
            items = out.get("items") or []
            for item in items:
                for tm in item.get("text_matches") or []:
                    for h in find_in_text(tm.get("fragment", ""), domain):
                        emit(h)
            if len(items) < 100:
                return


@register
class Dnsdumpster(Source):
    """DNSDumpster API - requer chave gratuita (50 req/dia)."""
    INFO = Info("dnsdumpster", "https://dnsdumpster.com", auth="required",
                cred_fields=["api_key"], rps=0.5)

    def enumerate(self, domain, session, emit):
        from .base import pick_key
        key = pick_key(session.creds, "api_key")
        u = "https://api.dnsdumpster.com/domain/" + urllib.parse.quote(domain)
        r = session.http.get_json(u, {"X-API-Key": key})
        if r.get("error"):
            msg = str(r["error"])
            low = msg.lower()
            if "rate limit" in low or "quota" in low:
                raise SourceError(RATE_LIMITED, msg)
            if "api key" in low or "unauthor" in low or "forbidden" in low:
                raise SourceError(AUTH, msg)
            raise SourceError(UNEXPECTED, msg)
        for set_key in ("a", "cname", "mx", "ns"):
            for rec in r.get(set_key) or []:
                host = rec.get("host")
                if host:
                    emit(str(host).rstrip("."))
                for iprec in rec.get("ips") or []:
                    ip = iprec.get("ip") if isinstance(iprec, dict) else iprec
                    session.report_ip(ip or "")


@register
class Certspotter(Source):
    """SSLMate Cert Spotter v1 - sem chave tem cota horaria pequena."""
    INFO = Info("certspotter", "https://api.certspotter.com", auth="optional",
                cred_fields=["api_key"], default=False, rps=1)

    def enumerate(self, domain, session, emit):
        from .base import pick_key
        headers = {"Accept": "application/json"}
        try:
            headers["Authorization"] = "Bearer " + pick_key(session.creds, "api_key")
        except SourceError:
            pass
        after = ""
        for _page in range(max(1, session.max_pages)):
            q = ("domain=%s&include_subdomains=true&expand=dns_names" % urllib.parse.quote(domain))
            if after:
                q += "&after=" + urllib.parse.quote(after)
            rows = session.http.get_json("https://api.certspotter.com/v1/issuances?" + q, headers)
            if not rows:
                return
            last = str(rows[-1].get("id", ""))
            for r in rows:
                for n in r.get("dns_names") or []:
                    emit(n)
            if not last or last == after:
                raise SourceError(UNEXPECTED, "certspotter: nao foi possivel paginar")
            after = last
