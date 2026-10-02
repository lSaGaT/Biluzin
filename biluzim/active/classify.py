# -*- coding: utf-8 -*-
"""Classificacao de candidatos - porte do classify.kf do koffuster.

Baseline de soft-404: sonda dois paths aleatorios; se status e tamanho
do corpo coincidirem, isso vira a assinatura "nao achado" e candidatos
iguais sao descartados.
"""

from urllib.parse import urlparse

from ..util import control_token


def join_dir_url(base_url: str, word: str) -> str:
    """Junta a base (com path e/ou query) com a palavra como novo segmento."""
    path, _, query = base_url.partition("?")
    joined = path + (word if path.endswith("/") else "/" + word)
    return joined + ("?" + query if query else "")


class Baseline:
    def __init__(self, soft_detected=False, status=-1, length=-1):
        self.soft_detected = soft_detected
        self.status = status
        self.length = length


def build_baseline(http, base_url, need_length=True, log=None):
    """Sonda 2 tokens de controle e deriva o baseline de soft-404."""
    u1 = join_dir_url(base_url, control_token(17))
    u2 = join_dir_url(base_url, control_token(9001))
    try:
        r1 = http.get(u1)
        r2 = http.get(u2)
    except Exception:
        return Baseline(False, -1, -1)
    if r1.status != r2.status:
        return Baseline(False, -1, -1)
    if not need_length:
        return Baseline(True, r1.status, -1)
    try:
        l1, l2 = len(r1.body), len(r2.body)
        if l1 == l2:
            return Baseline(True, r1.status, l1)
        return Baseline(True, r1.status, -1)
    except Exception:
        return Baseline(True, r1.status, -1)


def candidate_included(status, length, baseline, include_status, exclude_status, exclude_length):
    """Decision do filtro; retorna (incluir: bool, motivo: str).

    Precedencia (igual ao koffuster): -s desliga exclusao padrao de 404;
    -b aplica depois; --exclude-length por ultimo; baseline sempre filtra.
    """
    if include_status is not None:
        if status not in include_status:
            return False, "status fora de -s"
    else:
        if status == 404:
            return False, "404"
    if baseline.soft_detected and status == baseline.status:
        if baseline.length >= 0 and length == baseline.length:
            return False, "soft-404 (status+corpo identicos ao baseline)"
        if baseline.length < 0:
            return False, "soft-404 (status identico ao baseline)"
    if exclude_status is not None and status in exclude_status:
        return False, "status em -b"
    if exclude_length is not None and length in exclude_length:
        return False, "tamanho em --exclude-length"
    return True, ""


def status_class(status: int) -> str:
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if status >= 500:
        return "5xx"
    return "1xx"


def ensure_scheme(url: str) -> str:
    if "://" not in url:
        return "https://" + url
    return url


def host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""
