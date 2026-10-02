# -*- coding: utf-8 -*-
"""Cliente HTTP unico da Biluzim (porte do internal/httpx dos dois projetos).

Regras herdadas dos projetos de origem:
  * statuses 3xx NUNCA sao seguidos - o status exato e reportado
    (o koffuster nem le headers de resposta; aqui lemos, mas seguimos
    a mesma filosofia de "sonda, nao navega");
  * erros sao tipados (auth / rate-limit / timeout / http-status);
  * um unico cliente configura timeout, proxy, UA, cookie, auth basic.
"""

import base64
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
import gzip
import io
import ssl

DEFAULT_UA = "biluzim/0.1"

# Contexto TLS permissivo: sondas de enumeracao precisam alcancar hosts com
# certificados quebrados/self-signed (equivalente ao -k de ferramentas classicas).
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class HttpError(Exception):
    """Erro operacional tipado. .kind: auth|rate_limited|timeout|dns|conn|status|unexpected"""

    def __init__(self, kind, message, status=None):
        super().__init__(message)
        self.kind = kind
        self.status = status


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers  # email.message.Message
        self.body = body        # bytes

    def text(self):
        for enc in ("utf-8", "latin-1"):
            try:
                return self.body.decode(enc)
            except UnicodeDecodeError:
                continue
        return self.body.decode("utf-8", "replace")

    def header(self, name, default=""):
        try:
            return self.headers.get(name, default)
        except Exception:
            return default


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # nao segue: 3xx chega como HTTPError com status exato


class HttpClient:
    """Cliente unico compartilhado por todos os modos/fontes."""

    def __init__(self, timeout=10.0, retries=1, user_agent=None, cookie=None,
                 auth=None, extra_headers=None, proxy=None, verify_tls=False):
        self.timeout = timeout
        self.retries = max(0, int(retries))
        self.user_agent = user_agent or DEFAULT_UA
        self.cookie = cookie
        self.auth = auth
        self.extra_headers = dict(extra_headers or {})
        self.force_host = None  # modo vhost: sobrescreve o header Host
        handlers = [_NoRedirect(), urllib.request.HTTPSHandler(context=_CTX)]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({
                "http": proxy,
                "https": proxy,
            }))
        else:
            handlers.append(urllib.request.ProxyHandler({}))  # ignora env, sonda direto
        self.opener = urllib.request.build_opener(*handlers)

    # ------------------------------------------------------------------
    def _headers_for(self, url, headers):
        hdrs = {"User-Agent": self.user_agent}
        host = urllib.parse.urlparse(url).hostname or ""
        # urllib reescreve Host pelo host da URL; para sondas de vhost o
        # chamador seta self.force_host e nos injetamos o header na mao.
        if self.force_host:
            hdrs["Host"] = self.force_host
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        if self.auth:
            token = base64.b64encode(self.auth.encode("utf-8")).decode("ascii")
            hdrs["Authorization"] = "Basic " + token
        for k, v in self.extra_headers.items():
            hdrs[k.lower()] = v
        for k, v in (headers or {}).items():
            hdrs[k.lower()] = v
        return hdrs

    def request(self, url, method="GET", headers=None, data=None):
        """Faz uma requisicao; 3xx/4xx chegam como Response normal.

        Levanta HttpError tipado para timeout/dns/conexao/5xx-quando-corpo-indisponivel.
        """
        hdrs = self._headers_for(url, headers)
        last_exc = None
        attempts = self.retries + 1
        for attempt in range(attempts):
            try:
                req = urllib.request.Request(url, data=data, method=method)
                for k, v in hdrs.items():
                    req.add_header(k, v)
                # add_header capitaliza; Host precisa do nome exato:
                if "Host" in hdrs:
                    req.add_unredirected_header("Host", hdrs["Host"])
                with self.opener.open(req, timeout=self.timeout) as resp:
                    body = self._read_body(resp)
                    return Response(resp.status, resp.headers, body)
            except urllib.error.HTTPError as e:
                # 3xx (nao seguidos) e 4xx: e uma resposta valida para sondas.
                if e.code < 500:
                    try:
                        body = e.read()
                    except Exception:
                        body = b""
                    return Response(e.code, e.headers, body)
                last_exc = HttpError("status", "HTTP %d" % e.code, status=e.code)
                if attempt + 1 >= attempts:
                    # 5xx: tenta ler corpo mesmo assim (koffuster vhost usa isso)
                    try:
                        body = e.read()
                        return Response(e.code, e.headers, body)
                    except Exception:
                        raise last_exc
            except urllib.error.URLError as e:
                reason = getattr(e, "reason", e)
                last_exc = self._classify_conn(reason, url)
                if attempt + 1 >= attempts:
                    raise last_exc
            except socket.timeout:
                last_exc = HttpError("timeout", "timeout apos %ss" % self.timeout)
                if attempt + 1 >= attempts:
                    raise last_exc
            except ConnectionError as e:
                last_exc = HttpError("conn", "conexao: %s" % e)
                if attempt + 1 >= attempts:
                    raise last_exc
            except OSError as e:
                last_exc = self._classify_conn(e, url)
                if attempt + 1 >= attempts:
                    raise last_exc
        raise last_exc or HttpError("unexpected", "falha desconhecida")

    @staticmethod
    def _read_body(resp):
        raw = resp.read()
        if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
            try:
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
            except Exception:
                pass
        return raw

    @staticmethod
    def _classify_conn(reason, url):
        text = str(reason).lower()
        if "certificate" in text or "ssl" in text:
            return HttpError("conn", "tls: %s" % reason)
        if "name or service not known" in text or "nodename" in text or "getaddrinfo" in text:
            host = urllib.parse.urlparse(url).hostname or url
            return HttpError("dns", "dns: nao resolve '%s'" % host)
        if "timed out" in text or "timeout" in text:
            return HttpError("timeout", "timeout: %s" % reason)
        if "refused" in text:
            return HttpError("conn", "conexao recusada por %s" % (urllib.parse.urlparse(url).hostname or url))
        return HttpError("conn", "rede: %s" % reason)

    # ------------------------------------------------------------------
    def get(self, url, headers=None):
        return self.request(url, "GET", headers)

    def head(self, url, headers=None):
        return self.request(url, "HEAD", headers)

    def get_json(self, url, headers=None):
        resp = self.get(url, headers)
        try:
            return json.loads(resp.text())
        except json.JSONDecodeError as e:
            raise HttpError("unexpected", "JSON invalido de %s: %s" % (urllib.parse.urlparse(url).netloc, e))

    def post_json(self, url, headers=None, payload=None):
        data = json.dumps(payload or {}).encode("utf-8")
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        hdrs.update(headers or {})
        resp = self.request(url, "POST", hdrs, data=data)
        try:
            return json.loads(resp.text())
        except json.JSONDecodeError as e:
            raise HttpError("unexpected", "JSON invalido (POST %s): %s" % (url, e))
