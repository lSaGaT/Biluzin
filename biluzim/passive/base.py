# -*- coding: utf-8 -*-
"""Contrato das fontes passivas - porte fiel do internal/sources do lunatic.

Cada fonte:
  * consulta SOMENTE endpoints de busca do provedor (nunca o alvo);
  * emite nomes crus via emit(); o runner normaliza e filtra escopo;
  * devolve lista de erros tipados ou None no sucesso.
"""

NO_KEY = "no_key"
AUTH = "auth"
RATE_LIMITED = "rate_limited"
TIMEOUT = "timeout"
UNEXPECTED = "unexpected"
UNAVAILABLE = "unavailable"
BLOCKED = "blocked"
CANCELED = "canceled"

_ERR_TEXT = {
    NO_KEY: "sem chave de API configurada",
    AUTH: "credencial rejeitada",
    RATE_LIMITED: "limite de requisicoes",
    TIMEOUT: "tempo esgotado",
    UNEXPECTED: "resposta inesperada",
    UNAVAILABLE: "provedor indisponivel",
    BLOCKED: "pedido bloqueado pelo provedor",
    CANCELED: "interrompido",
}


class SourceError(Exception):
    """Erro tipado de fonte; .kind e uma das constantes acima."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind

    def label(self):
        base = _ERR_TEXT.get(self.kind, self.kind)
        return "%s: %s" % (base, self) if str(self) else base


def pick_key(creds, field):
    v = (creds or {}).get(field, "")
    if v:
        return v
    raise SourceError(NO_KEY, field)


class Info:
    """Metadados da fonte (espelho de sources.Info do lunatic)."""

    def __init__(self, name, url, auth="none", cred_fields=(), default=True,
                 disabled=False, disabled_reason="", rps=0.0, phase2=False,
                 env_prefix=None):
        self.name = name
        self.url = url
        self.auth = auth  # "none" | "optional" | "required"
        self.cred_fields = list(cred_fields)
        self.default = default
        self.disabled = disabled
        self.disabled_reason = disabled_reason
        self.rps = rps
        self.phase2 = phase2
        self.env_prefix = env_prefix or ("BILUZIM_" + name.upper())


class Session:
    """O que o runner entrega a cada fonte (espelho de sources.Session)."""

    def __init__(self, http, creds, log, max_pages=10, report_ip=None, ips=None):
        self.http = http
        self.creds = creds or {}
        self.log = log
        self.max_pages = max_pages
        self._report_ip = report_ip
        self.ips = ips or []

    def report_ip(self, ip):
        if self._report_ip and ip:
            try:
                self._report_ip(str(ip).strip())
            except Exception:
                pass


REGISTRY = {}


def register(source_cls):
    """Decorador de registro; key = Info.name."""
    REGISTRY[source_cls.INFO.name] = source_cls
    return source_cls


def all_sources():
    return sorted(REGISTRY.values(), key=lambda c: c.INFO.name)


def get_source(name):
    return REGISTRY.get(name)


class Source:
    """Classe base: subclasses implementam enumerate(domain, session, emit)."""

    INFO = None  # Info

    def enumerate(self, domain, session, emit):
        raise NotImplementedError
