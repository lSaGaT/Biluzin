# -*- coding: utf-8 -*-
"""Modo wizard: o maestro que comanda os tres times numa conversa so.

`biluzim` (sem argumentos) ou `biluzim run`:

  1. pergunta o alvo UMA vez (dominio e/ou URL base);
  2. roda o TIME PASSIVO (recon) e entrega o resumo por fonte;
  3. resolve e sonda os subdominios achados (ponte passivo->ativo);
  4. pergunta: entrar no MODO ATIVO? [s/N] - executa a fila
     (dns, dir, vhost, fuzz, s3, gcs, tftp) nos alvos vivos;
  5. pergunta: rodar o EXPLORADOR? [s/N] - explore nos URLs vivos;
  6. tudo consolida num arquivo so (texto ou JSONL).

Respostas podem vir pipeadas (scriptavel): EOF = resposta padrao.
`--yes` roda todas as etapas sem perguntar. Mesmos codigos de saida.
"""

import sys
from argparse import Namespace

from .banner import Palette, colors_enabled, print_banner
from .httpx import HttpClient
from .util import Emitter, Log, ScopeError, default_wordlist, parse_domain
from .active.classify import ensure_scheme

ACTIVE_DEFAULT = ["dns", "dir", "vhost", "s3", "gcs", "tftp"]
NO_ANSWERS = ("n", "nao", "no", "0", "false")


def _ask(prompt, default=""):
    """Pergunta no stderr; EOF (stdin fechado) devolve o padrao."""
    sys.stderr.write(prompt)
    sys.stderr.flush()
    line = sys.stdin.readline()
    if not line:  # EOF
        return default
    return line.strip() or default


def _ask_yes(prompt, default=False):
    suffix = " [S/n]: " if default else " [s/N]: "
    ans = _ask(prompt + suffix).lower()
    if not ans:
        return default
    return ans not in NO_ANSWERS


def _stage_cfg(args, http, **over):
    """Namespace com todos os campos que os runners dos modos tocam."""
    d = dict(
        quiet=args.quiet, verbose=args.verbose, threads=args.threads,
        timeout=args.timeout, retries=args.retries, format=args.format,
        header=[], cookie=getattr(args, "cookie", None),
        auth=getattr(args, "auth", None), user_agent=getattr(args, "user_agent", None),
        proxy=args.proxy,
        wordlist="", url="", domain="", extensions="", status_include="",
        exclude_status="", exclude_length="", resolver="https://dns.google/resolve",
        method="GET", body="", endpoint="", port=69,
        no_sensitive=False, sensitive_list="", no_js=False, no_params=False,
        param_wordlist=default_wordlist("params.txt"), max_param_probes=50,
        out_urls="", scope="host", depth=3, max_pages=200, urls=[],
    )
    d.update(over)
    ns = Namespace(**d)
    ns.http = http
    return ns


def _header(log, title):
    log.info("")
    log.info("========== %s ==========" % title)


def run_wizard(args, config):
    from .passive.runner import ReconRunner
    from .active.dns_mode import run_dns_mode, resolve_names
    from .active.dir_mode import run_dir_mode
    from .active.vhost_mode import run_vhost_mode
    from .active.fuzz_mode import run_fuzz_mode
    from .active.store_mode import run_store_mode
    from .active.tftp_mode import run_tftp_mode
    from .active.explore_mode import Explorer

    pal = Palette(colors_enabled(getattr(args, "color", False),
                                 getattr(args, "no_color", False)))
    log = Log(pal, quiet=args.quiet, verbose=getattr(args, "verbose", False))
    print_banner(pal, args.quiet, args.format)

    counts = {}

    # ------------------------------------------------------------------ alvo
    domain = (getattr(args, "domain", "") or "").strip()
    if not domain:
        domain = _ask("Alvo - dominio (ex.: alvo.com): ")
    try:
        domain = parse_domain(domain)
    except ScopeError as e:
        from .cli import usage_error
        usage_error("biluzim wizard: %s" % e)

    base_url = (getattr(args, "url", "") or "").strip()
    if not base_url:
        base_url = _ask("URL base [enter = https://%s/]: " % domain)
    base_url = ensure_scheme(base_url or ("https://" + domain + "/"))
    if not base_url.startswith(("http://", "https://")):
        from .cli import usage_error
        usage_error("biluzim wizard: URL base invalida: %r" % base_url)

    output = getattr(args, "output", None) or ""
    if not output:
        output = _ask("Arquivo consolidado [enter = biluzim_%s.txt]: " % domain)
    output = output or ("biluzim_%s.txt" % domain)

    emitter = Emitter(args.format, output)
    http = HttpClient(timeout=args.timeout, retries=args.retries,
                      user_agent=getattr(args, "user_agent", None),
                      cookie=getattr(args, "cookie", None),
                      auth=getattr(args, "auth", None), proxy=args.proxy)
    log.info("alvo: %s | base: %s | consolidado em: %s" % (domain, base_url, output))

    # ------------------------------------------------- time 1: recon passivo
    _header(log, "TIME 1: RECON PASSIVO (nunca toca no alvo)")
    selected = [s.strip() for s in (getattr(args, "sources", "") or "").split(",") if s.strip()]
    runner = ReconRunner(domain, http, log, emitter, config=config,
                         selected=selected, use_all=getattr(args, "all", False),
                         max_pages=getattr(args, "max_pages", 10),
                         workers=args.threads)
    names = runner.run()
    counts["recon_fontes"] = runner.summary
    counts["recon"] = len(names)
    ok_src = sum(1 for s in runner.summary if s[1] == "ok")
    fail_src = sum(1 for s in runner.summary if s[1] == "failed")
    if not args.quiet:
        for name, status, detail in runner.summary:
            mark = {"ok": pal.green("ok"), "skipped": pal.gray("skip"),
                    "failed": pal.red("fail")}.get(status, status)
            log.info("%-16s %-5s %s" % (name, mark, detail))
    log.info("recon: %d subdominios unicos (%d fontes ok, %d falhas)"
             % (len(names), ok_src, fail_src))

    # ------------------------------------- ponte: resolver + sondar vivos
    alive_urls = []
    if names:
        _header(log, "PONTE: RESOLVER + SONDAR OS ACHADOS (passo ativo)")
        resolved = resolve_names(names, workers=args.threads)
        alive_names = []
        for name, ips in resolved:
            if ips:
                alive_names.append(name)
                emitter.emit({"type": "resolve", "subdomain": name, "ips": ips,
                              "line": "%s  [%s]" % (name, ", ".join(ips))})
        log.info("%d de %d nomes resolveram" % (len(alive_names), len(names)))
        if alive_names:
            from .active.bridge import probe_alive
            rows = probe_alive(http, alive_names, workers=args.threads)
            for r in rows:
                if r["status"] is None:
                    continue
                alive_urls.append(r["url"])
                line = "%d  %8d  %s" % (r["status"], r["length"] or -1, r["url"])
                if r["title"]:
                    line += "  | " + r["title"]
                emitter.emit({"type": "probe", "subdomain": r["subdomain"],
                              "url": r["url"], "status": r["status"],
                              "length": r["length"], "title": r["title"], "line": line})
            log.info("%d alvos vivos respondendo HTTP" % len(alive_urls))
        counts["vivos"] = len(alive_urls)
    else:
        log.warn("recon nao achou nada; os times seguintes usam a URL base")

    # --------------------------------------------------- time 2: modo ativo
    if args.yes or _ask_yes("Entrar no modo ativo?"):
        _header(log, "TIME 2: MODO ATIVO (fila de enumeracao)")
        queue_in = (getattr(args, "active", "") or "").strip()
        if not queue_in:
            queue_in = _ask("Modos [enter = %s | lista por virgula | n]: "
                            % ",".join(ACTIVE_DEFAULT), "")
        if queue_in.lower() in NO_ANSWERS:
            log.info("modo ativo pulado")
            queue = []
        elif not queue_in:
            queue = list(ACTIVE_DEFAULT)
        else:
            queue = [m.strip().lower() for m in queue_in.split(",") if m.strip()]

        fuzz_url = ""
        if "fuzz" in queue:
            fuzz_url = _ask('URL com FUZZ para o modo fuzz [enter = pula fuzz]: ')
            fuzz_url = ensure_scheme(fuzz_url) if fuzz_url else ""

        unknown = [m for m in queue if m not in ACTIVE_DEFAULT + ["fuzz"]]
        if unknown:
            log.warn("modos desconhecidos ignorados: %s" % ", ".join(unknown))

        for mode in queue:
            if mode not in ACTIVE_DEFAULT + ["fuzz"]:
                continue
            if mode == "fuzz":
                if not fuzz_url:
                    log.warn("fuzz pulado (sem URL com FUZZ)")
                    continue
                if "FUZZ" not in fuzz_url:
                    log.warn("fuzz pulado (a URL nao contem FUZZ)")
                    continue
                _header(log, "ativo: fuzz")
                c = _stage_cfg(args, http, url=fuzz_url,
                               wordlist=default_wordlist("fuzz.txt"))
                f, e = run_fuzz_mode(c, log, emitter)
                counts["fuzz"] = f
                continue

            _header(log, "ativo: %s" % mode)
            if mode == "dns":
                c = _stage_cfg(args, http, domain=domain,
                               wordlist=default_wordlist("subdomains.txt"))
                f, e = run_dns_mode(c, log, emitter)
            elif mode == "dir":
                c = _stage_cfg(args, http, url=base_url,
                               wordlist=default_wordlist("directories.txt"))
                f, e = run_dir_mode(c, log, emitter)
            elif mode == "vhost":
                c = _stage_cfg(args, http, url=base_url, domain=domain,
                               wordlist=default_wordlist("vhosts.txt"))
                f, e = run_vhost_mode(c, log, emitter)
            elif mode in ("s3", "gcs"):
                c = _stage_cfg(args, http, wordlist=default_wordlist("buckets.txt"))
                f, e = run_store_mode(c, log, emitter, mode)
            elif mode == "tftp":
                c = _stage_cfg(args, http, url=domain,
                               wordlist=default_wordlist("tftp-files.txt"))
                f, e = run_tftp_mode(c, log, emitter)
            else:
                continue
            counts[mode] = f
            log.info("%s: %d achados, %d erros" % (mode, f, e))
    else:
        log.info("modo ativo pulado")

    # ------------------------------------------------- time 3: explorador
    run_explore = (args.yes and not getattr(args, "no_explore", False)) or \
                  (not args.yes and _ask_yes("Rodar o explorador (explore)?"))
    if run_explore:
        _header(log, "TIME 3: EXPLORADOR (vasculha por dentro)")
        seeds = alive_urls or [base_url]
        log.info("sementes: %d URL(s) viva(s)" % len(seeds))
        c = _stage_cfg(args, http, urls=seeds,
                       scope=getattr(args, "scope", "host"),
                       depth=getattr(args, "depth", 3),
                       max_pages=getattr(args, "explore_pages", 200))
        explorer = Explorer(c, log, emitter)
        explorer.run()
        counts["explore"] = explorer.found
    else:
        log.info("explorador pulado")

    # ------------------------------------------------------------- resumo
    _header(log, "RESUMO DA OPERACAO")
    log.info("alvo: %s  |  arquivo: %s  |  formato: %s" % (domain, output, args.format))
    log.info("time 1 (passivo): %d subdominios, %d vivos" %
             (counts.get("recon", 0), counts.get("vivos", 0)))
    ativo = {k: v for k, v in counts.items()
             if k in ("dns", "dir", "vhost", "fuzz", "s3", "gcs", "tftp")}
    if ativo:
        log.info("time 2 (ativo):   %s" %
                 ", ".join("%s=%d" % (k, v) for k, v in ativo.items()))
    else:
        log.info("time 2 (ativo):   pulado")
    log.info("time 3 (explorer): %s" %
             ("%d achados" % counts["explore"] if "explore" in counts else "pulado"))
    emitter.close()
    log.info("fim - use autorizado apenas")
    return 0
