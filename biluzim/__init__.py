"""
Biluzim - reconhecimento passivo + enumeracao ativa em uma ferramenta so.

Juncao das ideias de dois projetos do lunalully:
  * lunatic    - reconhecimento PASSIVO de subdominios via fontes OSINT
                 (nunca toca no alvo; so consulta bases de terceiros).
  * koffuster  - enumeracao ATIVA de terminal (dir, dns, vhost, fuzz,
                 s3/gcs, tftp) - so sonda e reporta, nunca explora.

Uso autorizado apenas. Sem dependencias externas: Python 3.9+ puro.
"""

__version__ = "0.1.0"
__tool__ = "biluzim"
__license__ = "GPL-3.0-or-later"
