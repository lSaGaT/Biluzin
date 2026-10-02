# -*- coding: utf-8 -*-
"""Modo `explore`: o time explorador. Vasculha o site POR DENTRO.

O que ele faz (tudo GET, tudo reportado, nada destrutivo):
  * crawler de verdade: segue links/forms/iframes/scripts por profundidade,
    respeita escopo (host ou subdominios do dominio da semente);
  * robots.txt: vira mapa (Disallow/Allow/Sitemap entram na fila);
  * sitemap.xml: <loc> entram na fila;
  * JS: extrai endpoints (LinkFinder-style) e segredos (AKIA, AIza, JWT,
    private key, xox, generic api_key/secret/token/password);
  * caca arquivos classicos vazados com assinatura (.git/HEAD, .env,
    .DS_Store, dump.sql, server-status, actuator...);
  * detecta directory listing ("Index of /");
  * extrai comentarios de HTML e e-mails;
  * enumera forms (action/metodo/campos) - NUNCA submete;
  * fingerprint por cabecalho (Server, X-Powered-By, generator);
  * mineracao de parametros (Arjun-lite): canario aleatorio, detecta
    reflexao/mudanca de status/tamanho - sem payload de ataque.

`--out-urls` grava todas as URLs descobertas para alimentar dir/fuzz.
"""

import json
import random
import re
import string
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode

from ..util import load_wordlist, Progress, find_in_text

FETCHABLE = ("text/html", "application/xhtml", "application/javascript",
             "text/javascript", "application/json", "text/plain",
             "application/xml", "text/xml")

# ---------------------------------------------------------------- sensíveis
SENSITIVE = {
    "/.git/HEAD": (b"ref: refs/", "repositorio .git exposto"),
    "/.git/config": (b"[core]", "config do .git exposto"),
    "/.svn/entries": (None, "repositorio .svn exposto"),
    "/.env": (None, "arquivo .env exposto"),
    "/.DS_Store": (b"Bud1", ".DS_Store da Apple exposto"),
    "/web.config": (b"<configuration", "web.config exposto"),
    "/server-status": (b"Apache Server Status", "server-status do Apache aberto"),
    "/server-info": (b"Apache Server Information", "server-info do Apache aberto"),
    "/phpinfo.php": (b"phpinfo()", "phpinfo exposto"),
    "/info.php": (b"phpinfo()", "info.php exposto"),
    "/actuator/health": (b'"status"', "Spring Boot actuator aberto"),
    "/actuator/env": (None, "Spring Boot actuator/env aberto"),
    "/debug/vars": (b"cmdline", "expvar do Go aberto"),
    "/backup.zip": (b"PK\x03\x04", "backup .zip no ar"),
    "/backup.tar.gz": (b"\x1f\x8b", "backup .tar.gz no ar"),
    "/site.tar.gz": (b"\x1f\x8b", "backup .tar.gz no ar"),
    "/dump.sql": (b"CREATE TABLE", "dump SQL exposto"),
    "/db.sql": (b"CREATE TABLE", "dump SQL exposto"),
    "/database.sql": (b"CREATE TABLE", "dump SQL exposto"),
    "/backup.sql": (b"CREATE TABLE", "dump SQL exposto"),
    "/console": (None, "console de debug (werkzeug/django)"),
    "/.well-known/security.txt": (None, "security.txt (contato do time de seguranca)"),
}
_robots_disallow = re.compile(r"^\s*(?:dis)?allow:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_robots_sitemap = re.compile(r"^\s*sitemap:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_sitemap_loc = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)

# ---------------------------------------------------------------- JS
_JS_PATH_RE = re.compile(
    r"""["']((?:/[A-Za-z0-9_.\-]{1,80}){1,15}(?:\?[A-Za-z0-9_=&%.\-]{0,80})?)["']"""
)
_JS_URL_RE = re.compile(r"""["'](https?://[^"'\s]{4,200})["']""")
_SECRET_SIGS = [
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]\-[A-Za-z0-9\-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("generic_secret", re.compile(
        r"""(?:api[_\-]?key|apikey|secret|passwd|password|token|auth)["'`\s:=]{1,4}["']?([A-Za-z0-9_\-\.]{16,64})["']?""",
        re.IGNORECASE)),
]
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_LISTING_RE = re.compile(r"<title>[^<]*Index of[^<]*</title>", re.IGNORECASE)
_TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator",
                 "x-drupal-cache", "x-runtime", "via")


def _canary():
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))


def _mask(secret: str) -> str:
    if len(secret) <= 8:
        return secret[:2] + "***"
    return secret[:6] + "..." + secret[-3:]


class _HTML(HTMLParser):
    """Extrai links, forms, comentarios, meta-refresh, generator e titulo."""

    LINK_TAGS = {"a": "href", "form": "action", "iframe": "src",
                 "script": "src", "link": "href", "area": "href"}

    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.links = []
        self.forms = []
        self.comments = []
        self.title = ""
        self.generator = ""
        self.emails = []
        self._in_title = False
        self._cur_form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in self.LINK_TAGS and a.get(self.LINK_TAGS[tag]):
            self.links.append((self.LINK_TAGS[tag], urljoin(self.base, a[self.LINK_TAGS[tag]])))
        if tag == "form":
            self._cur_form = {"action": urljoin(self.base, a.get("action") or self.base),
                              "method": (a.get("method") or "get").upper(),
                              "fields": []}
        if tag == "input" and self._cur_form is not None:
            name = a.get("name")
            if name:
                self._cur_form["fields"].append(name)
        if tag == "textarea" and self._cur_form is not None and a.get("name"):
            self._cur_form["fields"].append(a["name"])
        if tag == "select" and self._cur_form is not None and a.get("name"):
            self._cur_form["fields"].append(a["name"])
        if tag == "meta":
            if (a.get("http-equiv") or "").lower() == "refresh" and a.get("content"):
                m = re.search(r"url=(.+)", a["content"], re.IGNORECASE)
                if m:
                    self.links.append(("meta-refresh", urljoin(self.base, m.group(1).strip())))
            if (a.get("name") or "").lower() == "generator" and a.get("content"):
                self.generator = a["content"]

    def handle_endtag(self, tag):
        if tag == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None

    def handle_startendtag(self, tag, attrs):
        if tag == "form":  # form self-closing raro: fecha na hora
            a = dict(attrs)
            self.forms.append({"action": urljoin(self.base, a.get("action") or self.base),
                               "method": (a.get("method") or "get").upper(),
                               "fields": [x.get("name") for x in ()]})
        else:
            self.handle_starttag(tag, attrs)

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        for m in _EMAIL_RE.finditer(data):
            self.emails.append(m.group(0))

    def handle_starttag_title(self):  # pragma: no cover
        pass

    def handle_comment(self, data):
        data = data.strip()
        if data and not data.startswith(("[if", "<!")):
            self.comments.append(data[:300])


class Explorer:
    def __init__(self, cfg, log, emitter):
        self.cfg = cfg
        self.http = cfg.http
        self.log = log
        self.emitter = emitter
        self.seeds = list(cfg.urls)
        first = urlparse(self.seeds[0])
        self.base_netloc = first.netloc
        self.base_domain = first.hostname or ""
        self.scope = cfg.scope
        self.depth = max(1, cfg.depth)
        self.max_pages = max(1, cfg.max_pages)
        self.visited = set()
        self.discovered = set()   # toda URL em-escopo vista (para --out-urls)
        self.page_seen = set()    # paginas realmente baixadas/parseadas
        self.tech_done = set()
        self.found = 0
        self.errors = 0
        self.param_budget = max(0, getattr(cfg, "max_param_probes", 50)) * 60
        self.out_urls = open(cfg.out_urls, "a", encoding="utf-8") if cfg.out_urls else None

    # ---------------------------------------------------------------- helpers
    def emit(self, rec):
        self.found += 1
        self.emitter.emit(rec)

    def note_url(self, url):
        if url in self.discovered:
            return
        self.discovered.add(url)
        if self.out_urls:
            try:
                self.out_urls.write(url + "\n")
                self.out_urls.flush()
            except Exception:
                pass

    def in_scope(self, url):
        try:
            p = urlparse(url)
        except Exception:
            return False
        if p.scheme not in ("http", "https"):
            return False
        if self.scope == "host":
            return p.netloc == self.base_netloc
        host = (p.hostname or "").lower()
        return host == self.base_domain or host.endswith("." + self.base_domain)

    @staticmethod
    def normalize(url):
        p = urlparse(url)
        host = (p.hostname or "").lower()
        netloc = host
        if p.port and not ((p.scheme == "http" and p.port == 80) or
                           (p.scheme == "https" and p.port == 443)):
            netloc = "%s:%d" % (host, p.port)
        return "%s://%s%s" % (p.scheme, netloc, p.path or "/") + \
               (("?" + p.query) if p.query else "")

    def emit_tech(self, url, resp):
        host = urlparse(url).netloc
        if host in self.tech_done:
            return
        self.tech_done.add(host)
        items = []
        for h in _TECH_HEADERS:
            v = resp.header(h)
            if v:
                items.append("%s: %s" % (h, v))
        cookies = [c.split("=")[0] for c in (resp.header("Set-Cookie") or "").split(";")
                   if "=" in c]
        if cookies:
            items.append("cookies: " + ",".join(cookies))
        if items:
            self.emit({"type": "tech", "host": host, "detail": items,
                       "line": "[tech] %s  %s" % (host, " | ".join(items))})

    # ---------------------------------------------------------------- fetch
    def fetch(self, url):
        try:
            return self.http.get(url)
        except Exception as e:
            self.errors += 1
            self.log.debug("erro: %s -> %s" % (url, str(e)[:90]))
            return None

    def fetch_many(self, urls):
        with ThreadPoolExecutor(max_workers=max(1, self.cfg.threads)) as pool:
            return list(pool.map(self.fetch, urls))

    # ---------------------------------------------------------------- parse
    @staticmethod
    def is_js(url, ctype):
        if "javascript" in ctype:
            return True
        return urlparse(url).path.lower().endswith(".js") and ctype.startswith("text/")

    def parse_page(self, url, resp):
        ctype = (resp.header("Content-Type") or "").split(";")[0].strip().lower()
        text = resp.text()
        self.emit_tech(url, resp)

        if self.is_js(url, ctype):
            # javascript: endpoints + segredos
            for m in _JS_PATH_RE.finditer(text):
                path = m.group(1)
                if len(path) > 3 and not path.endswith((".png", ".jpg", ".gif", ".css", ".woff", ".svg")):
                    absu = urljoin(url, path)
                    if self.in_scope(absu):
                        self.note_url(absu)
                        self.emit({"type": "endpoint", "source": url, "endpoint": absu,
                                   "line": "[js-endpoint] %s  (%s)" % (absu, url)})
            self.scan_secrets(url, text)
            return []

        if "json" in ctype or "xml" in ctype or "text/plain" in ctype:
            for m in _JS_URL_RE.finditer(text):
                self._add_link(url, m.group(1))
            self.scan_secrets(url, text)
            return []

        if not ctype.startswith(("text/", "application/")):
            return []  # binario (imagem, pdf): so anota a URL, nao parseia

        hp = _HTML(url)
        try:
            hp.feed(text)
        except Exception:
            pass
        title = " ".join(hp.title.split())[:120]
        listing = bool(_LISTING_RE.search(text)) or text.lower().startswith("<h1>index of")
        self.emit({"type": "page", "url": url, "status": resp.status,
                   "length": len(resp.body), "title": title,
                   "listing": listing,
                   "line": "%d  %8d  %s%s" % (resp.status, len(resp.body), url,
                                              ("  | " + title) if title else "")})
        if listing:
            self.emit({"type": "listing", "url": url,
                       "line": "[listing aberto] %s" % url})
        for c in hp.comments:
            self.emit({"type": "comment", "url": url, "comment": c,
                       "line": "[comentario] %s  %s" % (url, c[:120])})
        for email in sorted(set(hp.emails)):
            if not email.lower().endswith((".png", ".jpg", ".gif")):
                self.emit({"type": "email", "url": url, "email": email,
                           "line": "[email] %s  (%s)" % (email, url)})
        for f in hp.forms:
            if f["fields"] or f["action"] != url:
                self.emit({"type": "form", "url": url, "action": f["action"],
                           "method": f["method"], "fields": f["fields"],
                           "line": "[form %s] %s  campos: %s"
                                   % (f["method"], f["action"], ",".join(f["fields"]) or "-")})
        if hp.generator:
            self.emit({"type": "tech", "host": urlparse(url).netloc,
                       "detail": ["generator: " + hp.generator],
                       "line": "[tech] generator: %s (%s)" % (hp.generator, url)})
        return hp.links

    def _add_link(self, base, raw):
        u = self.normalize(urljoin(base, raw))
        if self.in_scope(u):
            self.note_url(u)
            return u
        return None

    def scan_secrets(self, url, text):
        for kind, rx in _SECRET_SIGS:
            for m in rx.finditer(text):
                secret = m.group(1) if m.groups() else m.group(0)
                self.emit({"type": "js_secret", "url": url, "kind": kind,
                           "preview": _mask(secret),
                           "line": "[SEGREDO %s] %s  %s" % (kind.upper(), _mask(secret), url)})

    # ---------------------------------------------------------------- robots/sitemap
    def seed_extras(self, seed):
        """robots.txt e sitemap da semente; devolve URLs extras para a fila."""
        extra = []
        p = urlparse(seed)
        robots = p.scheme + "://" + p.netloc + "/robots.txt"
        resp = self.fetch(robots)
        if resp and resp.status == 200:
            body = resp.text()
            self.emit({"type": "robots", "url": robots, "line": "[robots.txt] %s" % robots})
            for m in _robots_sitemap.finditer(body):
                sm = self.normalize(m.group(1))
                if self.in_scope(sm):
                    extra.append(sm)
            for m in _robots_disallow.finditer(body):
                path = m.group(1)
                if path.startswith("/"):
                    u = self.normalize(p.scheme + "://" + p.netloc + path)
                    if self.in_scope(u):
                        self.note_url(u)
                        extra.append(u)
                        self.emit({"type": "robots_entry", "url": u,
                                   "line": "[robots] %s  %s" % (m.group(0).strip(), u)})
            # sitemap.xml padrao
            sm = self.normalize(p.scheme + "://" + p.netloc + "/sitemap.xml")
            extra.append(sm)
        return extra

    def parse_sitemap(self, url, resp):
        locs = _sitemap_loc.findall(resp.text())
        out = []
        for loc in locs:
            u = self.normalize(loc)
            if self.in_scope(u):
                self.note_url(u)
                out.append(u)
        if out:
            self.emit({"type": "sitemap", "url": url, "count": len(out),
                       "line": "[sitemap] %d URLs em %s" % (len(out), url)})
        return out

    # ---------------------------------------------------------------- leaks
    def probe_sensitive(self):
        from .classify import build_baseline
        for seed in dict.fromkeys(
                [urlparse(s).scheme + "://" + urlparse(s).netloc for s in self.seeds]):
            # baseline de soft-404: respota generica do site para o que nao existe
            baseline = build_baseline(self.http, seed, need_length=True)
            paths = list(SENSITIVE.keys())
            if self.cfg.sensitive_list:
                try:
                    extra = load_wordlist(self.cfg.sensitive_list)
                    paths += [e if e.startswith("/") else "/" + e for e in extra]
                except OSError:
                    self.log.warn("sensitive-list nao abriu: %s" % self.cfg.sensitive_list)

            def one(path):
                sig, label = SENSITIVE.get(path, (None, path.strip("/") or path))
                r = self.fetch(seed + path)
                if r is None:
                    return None
                if r.status in (404, 410):
                    return None
                # soft-404: resposta identica a pagina generica de nao-achado
                if (baseline.soft_detected and r.status == baseline.status
                        and (baseline.length < 0 or len(r.body) == baseline.length)):
                    return None
                if sig and sig not in r.body:
                    return None
                if not sig and r.status in (400, 401, 403, 405):
                    return None  # sem assinatura, so interessa se responder de boa
                return (seed + path, r, label)

            with ThreadPoolExecutor(max_workers=max(1, self.cfg.threads)) as pool:
                for hit in pool.map(one, paths):
                    if hit:
                        url, r, label = hit
                        self.emit({"type": "leak", "url": url, "label": label,
                                   "status": r.status, "length": len(r.body),
                                   "line": "[LEAK] %d  %8d  %s  %s"
                                           % (r.status, len(r.body), url, label)})

    # ---------------------------------------------------------------- params
    def mine_params(self, targets):
        words = load_wordlist(self.cfg.param_wordlist)
        seen = set()
        queue = deque()
        for t in targets:
            u = self.normalize(t)
            if u not in seen and self.in_scope(u):
                seen.add(u)
                queue.append(u)
        probes = 0
        targets_done = 0
        while queue and targets_done < self.cfg.max_param_probes and self.param_budget > 0:
            target = queue.popleft()
            base = self.fetch(target)
            targets_done += 1
            if base is None or base.status >= 500:
                continue
            b_status, b_len, b_body = base.status, len(base.body), base.text()
            jobs = []
            for w in words:
                if self.param_budget <= 0:
                    break
                sep = "&" if "?" in target else "?"
                jobs.append((w, target + sep + w + "=" + _canary()))
                self.param_budget -= 1
            with ThreadPoolExecutor(max_workers=max(1, self.cfg.threads)) as pool:
                results = list(pool.map(lambda j: (j[0], self.fetch(j[1])), jobs))
            for w, r in results:
                probes += 1
                if r is None:
                    continue
                body = r.text()
                if _canary_marker(jobs, w, body):
                    kind = "refletido"
                elif r.status != b_status:
                    kind = "mudou-status (%d -> %d)" % (b_status, r.status)
                elif abs(len(r.body) - b_len) > 30:
                    kind = "mudou-corpo (%d -> %d)" % (b_len, len(r.body))
                else:
                    continue
                url = target + ("&" if "?" in target else "?") + w + "=CANARIO"
                self.emit({"type": "param", "url": url, "param": w, "effect": kind,
                           "line": "[param] %-12s %-28s %s" % (w, kind, url)})

    # ---------------------------------------------------------------- main
    def run(self):
        self.log.info("explore: %d semente(s), profundidade %d, orcamento %d paginas, escopo %s"
                      % (len(self.seeds), self.depth, self.max_pages, self.scope))

        frontier = deque()
        for s in self.seeds:
            frontier.append((self.normalize(s), 1))
        for seed in self.seeds:
            for u in self.seed_extras(seed):
                frontier.append((u, 2))

        pages = 0
        progress = Progress(self.log, self.max_pages, "explore",
                            enabled=not self.cfg.quiet)
        visited_links = set()

        while frontier and pages < self.max_pages:
            wave = []
            while frontier and len(wave) < self.cfg.threads * 4 and pages + len(wave) < self.max_pages:
                url, depth = frontier.popleft()
                if url in self.visited:
                    continue
                self.visited.add(url)
                wave.append((url, depth))
            if not wave:
                break
            results = self.fetch_many([u for u, _ in wave])
            next_links = []
            for (url, depth), resp in zip(wave, results):
                pages += 1
                progress.tick()
                if resp is None:
                    continue
                ctype = (resp.header("Content-Type") or "").split(";")[0].strip().lower()
                if "xml" in ctype and url.endswith(".xml"):
                    for u in self.parse_sitemap(url, resp):
                        if u not in self.visited:
                            next_links.append((u, depth + 1))
                    continue
                if "html" not in ctype and not self.is_js(url, ctype) and \
                        not ctype.startswith(("text/", "application/json", "application/xml")):
                    continue  # binario/asset: anotado, nao parseado
                self.page_seen.add(url)
                links = self.parse_page(url, resp)
                if depth >= self.depth:
                    continue
                for _attr, raw in links:
                    u = self._add_link(url, raw)
                    if u and u not in self.visited and u not in visited_links:
                        visited_links.add(u)
                        next_links.append((u, depth + 1))
            frontier.extend(next_links)
        progress.finish()

        if not self.cfg.no_sensitive:
            self.log.info("explore: cacando arquivos classicos vazados...")
            self.probe_sensitive()
        if not self.cfg.no_params:
            self.log.info("explore: minerando parametros (sondagem GET com canario)...")
            # alvos: sementes + paginas sem query ja vistas + descobertas com query
            targets = list(self.seeds)
            for u in sorted(self.page_seen):
                targets.append(u)
            for u in sorted(self.discovered):
                if urlparse(u).query:
                    targets.append(u)
            cap = max(1, self.cfg.max_param_probes)
            self.mine_params(targets[:cap])

        if self.out_urls:
            self.out_urls.close()
        self.log.info("explore concluido: %d achados, %d paginas, %d erros"
                      % (self.found, pages, self.errors))
        return self.found


def _canary_marker(jobs, word, body):
    for w, u in jobs:
        if w == word:
            canary = u.split("=", 1)[1]
            return canary in body
    return False
