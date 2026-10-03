# -*- coding: utf-8 -*-
"""Modo wizard: o maestro que comanda os tres times numa conversa so.

`biluzim` (sem argumentos) ou `biluzim run`:

  1. pergunta o alvo UMA vez (dominio e/ou URL base);
  2. roda o TIME PASSIVO (recon) e entrega o resumo por fonte;
  3. resolve e sonda os subdominios achados (ponte passivo->ativo);
  4. pergunta: entrar no MODO ATIVO? [s/N] - executa a fila
     (dns, dir, vhost, fuzz, s3, gcs, tftp) nos alvos vivos;
  5. pergunta: rodar o EXPLORADOR? [s/N] - explore nos URLs vivos;
  6. tudo consolida num arquivo so (jsonl por padrao, text com -f text).

Arquivo autodescrito (schema biluzim/1) para consumo por agentes/SDK:
  {"type":"run", ...}         envelope da execucao (quem, quando, config)
  {"type":"stage", ...}       um por etapa: config, resumo, o que ficou de fora
  {"type":"<achado>", ...}    cada achado estruturado (subdomain, leak, ...)
  {"type":"run_summary", ...} cauda: duracao, exit, contagens por tipo
Respostas podem vir pipeadas (scriptavel): EOF = resposta padrao.
`--yes` roda todas as etapas sem perguntar. Mesmos codigos de saida.
"""

import sys
from argparse import Namespace
from datetime import datetime

from . import __version__
from .banner import Palette, colors_enabled, print_banner
from .httpx import HttpClient
from .util import Emitter, Log, ScopeError, default_wordlist, parse_domain
from .active.classify import ensure_scheme

ACTIVE_DEFAULT = ["dns", "dir", "vhost", "s3", "gcs", "tftp"]
NO_ANSWERS = ("n", "nao", "no", "0", "false")

# mapeamento leve de estagios para taticas ATT&CK (dica para o ecossistema)
ATTACK = {
    "recon": "Reconnaissance",
    "bridge": "Discovery",
    "dns": "Discovery", "dir": "Discovery", "vhost": "Discovery",
    "fuzz": "Discovery", "s3": "Discovery", "gcs": "Discovery",
    "tftp": "Discovery", "explore": "Discovery",
}


def _now():
    return datetime.now().isoformat(timespec="seconds")


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
        auth=getattr(args, "auth", None),
        user_agent=getattr(args, "user_agent", None), proxy=args.proxy,
        wordlist="", url="", domain="", extensions="", status_include="",
        exclude_status="", exclude_length="",
        resolver="https://dns.google/resolve",
        method="GET", body="", endpoint="", port=69,
        no_sensitive=False, sensitive_list="", no_js=False, no_params=False,
        param_wordlist=default_wordlist("params.txt"), max_param_probes=50,
        out_urls="", scope="host", depth=3, max_pages=200, urls=[],
        target="", all_buckets=False,
    )
    d.update(over)
    ns = Namespace(**d)
    ns.http = http
    return ns


class _Stage:
    """Um registro {"type":"stage"} no arquivo: config + resumo + contexto."""

    def __init__(self, emitter, name, config=None):
        self.emitter = emitter
        self.name = name
        self.config = config
        self.started = _now()
        self.status = "done"
        self.summary = {}
        self.context = {}

    def skip(self, reason):
        self.status = "skipped"
        self.summary = {"reason": reason}
        self._emit()

    def fail(self, detail):
        self.status = "failed"
        self.summary = {"detail": detail}
        self._emit()

    def finish(self, **summary):
        self.summary.update(summary)
        self._emit()

    def _emit(self):
        rec = {
            "type": "stage", "stage": self.name,
            "attack": ATTACK.get(self.name), "status": self.status,
            "started_at": self.started, "finished_at": _now(),
            "summary": self.summary,
        }
        if self.config:
            rec["config"] = self.config
        if self.context:
            rec["context"] = self.context
        self.emitter.emit(rec)


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
    from .cli import usage_error

    pal = Palette(colors_enabled(getattr(args, "color", False),
                                 getattr(args, "no_color", False)))
    log = Log(pal, quiet=args.quiet, verbose=getattr(args, "verbose", False))
    print_banner(pal, args.quiet, args.format)

    counts = {}
    interrupted = {"flag": False}

    # ------------------------------------------------------------------ alvo
    domain = (getattr(args, "domain", "") or "").strip()
    if not domain:
        domain = _ask("Alvo - dominio (ex.: alvo.com): ")
    try:
        domain = parse_domain(domain)
    except ScopeError as e:
        usage_error("biluzim wizard: %s" % e)

    base_url = (getattr(args, "url", "") or "").strip()
    if not base_url:
        base_url = _ask("URL base [enter = https://%s/]: " % domain)
    base_url = ensure_scheme(base_url or ("https://" + domain + "/"))
    if not base_url.startswith(("http://", "https://")):
        usage_error("biluzim wizard: URL base invalida: %r" % base_url)

    ext = "jsonl" if args.format == "jsonl" else "txt"
    output = getattr(args, "output", None) or ""
    if not output and not args.yes:
        output = _ask("Arquivo consolidado [enter = biluzim_%s.%s]: " % (domain, ext))
    output = output or ("biluzim_%s.%s" % (domain, ext))

    emitter = Emitter(args.format, output)
    http = HttpClient(timeout=args.timeout, retries=args.retries,
                      user_agent=getattr(args, "user_agent", None),
                      cookie=getattr(args, "cookie", None),
                      auth=getattr(args, "auth", None), proxy=args.proxy)
    log.info("alvo: %s | base: %s | consolidado em: %s" % (domain, base_url, output))

    # ------------------------------------------------- envelope: {"type":"run"}
    emitter.emit({
        "type": "run", "schema": "biluzim/1", "tool": "biluzim",
        "version": __version__, "domain": domain, "base_url": base_url,
        "started_at": _now(), "interactive": not args.yes,
        "output_file": output,
        "config": {
            "threads": args.threads, "timeout": args.timeout,
            "retries": args.retries, "proxy": args.proxy,
            "sources": [s.strip() for s in (getattr(args, "sources", "") or "").split(",") if s.strip()],
            "all_sources": getattr(args, "all", False),
            "max_pages_recon": getattr(args, "max_pages", 10),
            "scope_explore": getattr(args, "scope", "host"),
            "depth_explore": getattr(args, "depth", 3),
            "explore_pages": getattr(args, "explore_pages", 200),
            "wordlists": {
                "subdomains": default_wordlist("subdomains.txt"),
                "directories": default_wordlist("directories.txt"),
                "vhosts": default_wordlist("vhosts.txt"),
                "fuzz": default_wordlist("fuzz.txt"),
                "buckets": default_wordlist("buckets.txt"),
                "tftp_files": default_wordlist("tftp-files.txt"),
                "params": default_wordlist("params.txt"),
            },
        },
    })

    started_ts = datetime.now()
    run_status = "complete"

    try:
        # ------------------------------------------- time 1: recon passivo
        stage = _Stage(emitter, "recon",
                       config={"sources": getattr(args, "sources", ""),
                               "all": getattr(args, "all", False),
                               "max_pages": getattr(args, "max_pages", 10)})
        _header(log, "TIME 1: RECON PASSIVO (nunca toca no alvo)")
        selected = [s.strip() for s in (getattr(args, "sources", "") or "").split(",") if s.strip()]
        runner = ReconRunner(domain, http, log, emitter, config=config,
                             selected=selected, use_all=getattr(args, "all", False),
                             max_pages=getattr(args, "max_pages", 10),
                             workers=args.threads)
        names = runner.run()
        counts["recon"] = len(names)
        ok_src = sum(1 for s in runner.summary if s[1] == "ok")
        fail_src = sum(1 for s in runner.summary if s[1] == "failed")
        stage.context["sources"] = [
            {"name": n, "status": st, "detail": dt} for n, st, dt in runner.summary
        ]
        stage.finish(unique_subdomains=len(names), sources_ok=ok_src,
                     sources_failed=fail_src)
        if not args.quiet:
            for name, status, detail in runner.summary:
                mark = {"ok": pal.green("ok"), "skipped": pal.gray("skip"),
                        "failed": pal.red("fail")}.get(status, status)
                log.info("%-16s %-5s %s" % (name, mark, detail))
        log.info("recon: %d subdominios unicos (%d fontes ok, %d falhas)"
                 % (len(names), ok_src, fail_src))

        # --------------------------------- ponte: resolver + sondar vivos
        stage = _Stage(emitter, "bridge",
                       config={"workers": args.threads, "resolve": True,
                               "probe": True})
        _header(log, "PONTE: RESOLVER + SONDAR OS ACHADOS (passo ativo)")
        alive_urls = []
        if names:
            resolved = resolve_names(names, workers=args.threads)
            alive_names = []
            for name, ips in resolved:
                if ips:
                    alive_names.append(name)
                    emitter.emit({"type": "resolve", "subdomain": name,
                                  "ips": ips,
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
                    emitter.emit({
                        "type": "probe", "subdomain": r["subdomain"],
                        "url": r["url"], "status": r["status"],
                        "length": r["length"], "title": r["title"],
                        "server": r.get("server"), "powered_by": r.get("powered_by"),
                        "line": line,
                    })
            log.info("%d alvos vivos respondendo HTTP" % len(alive_urls))
            stage.finish(resolved=len(alive_names), alive_http=len(alive_urls))
        else:
            log.warn("recon nao achou nada; os times seguintes usam a URL base")
            stage.finish(resolved=0, alive_http=0)
        counts["vivos"] = len(alive_urls)

        # --------------------------------------------------- time 2: ativo
        if args.yes or _ask_yes("Entrar no modo ativo?"):
            _header(log, "TIME 2: MODO ATIVO (fila de enumeracao)")
            queue_in = (getattr(args, "active", "") or "").strip()
            if not queue_in and not args.yes:
                queue_in = _ask("Modos [enter = %s | lista por virgula | n]: "
                                % ",".join(ACTIVE_DEFAULT), "")
            if queue_in.lower() in NO_ANSWERS:
                _Stage(emitter, "active_queue").skip("operador respondeu n")
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
                    if not fuzz_url or "FUZZ" not in fuzz_url:
                        _Stage(emitter, "fuzz").skip("sem URL contendo FUZZ")
                        log.warn("fuzz pulado (sem URL com FUZZ)")
                        continue
                    _header(log, "ativo: fuzz")
                    stage = _Stage(emitter, "fuzz",
                                   config={"url": fuzz_url,
                                           "wordlist": default_wordlist("fuzz.txt")})
                    c = _stage_cfg(args, http, url=fuzz_url,
                                   wordlist=default_wordlist("fuzz.txt"))
                    f, e = run_fuzz_mode(c, log, emitter)
                    stage.context["baseline"] = getattr(c, "stage_info", {}).get("baseline")
                    stage.finish(found=f, errors=e)
                    counts["fuzz"] = f
                    continue

                _header(log, "ativo: %s" % mode)
                stage = _Stage(emitter, mode, config={})
                if mode == "dns":
                    stage.config = {"domain": domain,
                                    "resolver": "https://dns.google/resolve",
                                    "wordlist": default_wordlist("subdomains.txt")}
                    c = _stage_cfg(args, http, domain=domain,
                                   wordlist=default_wordlist("subdomains.txt"))
                    f, e = run_dns_mode(c, log, emitter)
                    stage.context["wildcard"] = getattr(c, "stage_info", {}).get("wildcard")
                elif mode == "dir":
                    stage.config = {"url": base_url,
                                    "wordlist": default_wordlist("directories.txt")}
                    c = _stage_cfg(args, http, url=base_url,
                                   wordlist=default_wordlist("directories.txt"))
                    f, e = run_dir_mode(c, log, emitter)
                    stage.context["baseline"] = getattr(c, "stage_info", {}).get("baseline")
                elif mode == "vhost":
                    stage.config = {"url": base_url, "domain_suffix": domain,
                                    "wordlist": default_wordlist("vhosts.txt")}
                    c = _stage_cfg(args, http, url=base_url, domain=domain,
                                   wordlist=default_wordlist("vhosts.txt"))
                    f, e = run_vhost_mode(c, log, emitter)
                    stage.context["baseline"] = getattr(c, "stage_info", {}).get("baseline")
                elif mode in ("s3", "gcs"):
                    stage.config = {"endpoint_default": True,
                                    "wordlist": default_wordlist("buckets.txt"),
                                    "target": domain}
                    c = _stage_cfg(args, http, wordlist=default_wordlist("buckets.txt"),
                                   target=domain)
                    f, e = run_store_mode(c, log, emitter, mode)
                    stage.context.update(getattr(c, "stage_info", {}))
                elif mode == "tftp":
                    stage.config = {"host": domain, "port": 69,
                                    "wordlist": default_wordlist("tftp-files.txt")}
                    c = _stage_cfg(args, http, url=domain,
                                   wordlist=default_wordlist("tftp-files.txt"))
                    f, e = run_tftp_mode(c, log, emitter)
                else:
                    continue
                stage.finish(found=f, errors=e)
                counts[mode] = f
                log.info("%s: %d achados, %d erros" % (mode, f, e))
        else:
            _Stage(emitter, "active_queue").skip("operador respondeu n")
            log.info("modo ativo pulado")

        # ------------------------------------------------- time 3: explorer
        run_explore = (args.yes and not getattr(args, "no_explore", False)) or \
                      (not args.yes and _ask_yes("Rodar o explorador (explore)?"))
        if run_explore:
            _header(log, "TIME 3: EXPLORADOR (vasculha por dentro)")
            seeds = alive_urls or [base_url]
            log.info("sementes: %d URL(s) viva(s)" % len(seeds))
            stage = _Stage(emitter, "explore",
                           config={"seeds": seeds,
                                   "scope": getattr(args, "scope", "host"),
                                   "depth": getattr(args, "depth", 3),
                                   "max_pages": getattr(args, "explore_pages", 200)})
            c = _stage_cfg(args, http, urls=seeds,
                           scope=getattr(args, "scope", "host"),
                           depth=getattr(args, "depth", 3),
                           max_pages=getattr(args, "explore_pages", 200))
            explorer = Explorer(c, log, emitter)
            explorer.run()
            stage.finish(found=explorer.found, pages=explorer.pages,
                         errors=explorer.errors)
            counts["explore"] = explorer.found
        else:
            _Stage(emitter, "explore").skip("operador respondeu n")
            log.info("explorador pulado")

    except KeyboardInterrupt:
        interrupted["flag"] = True
        run_status = "interrupted"
        sys.stderr.write("\nbiluzim: interrompido; gerando resumo do que deu tempo\n")

    # ------------------------------------------ cauda: {"type":"run_summary"}
    duration = (datetime.now() - started_ts).total_seconds()
    emitter.emit({
        "type": "run_summary", "finished_at": _now(),
        "duration_sec": round(duration, 1), "exit": run_status,
        "counts": dict(emitter.type_counts),
    })
    emitter.close()

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
    log.info("fim - use autorizado apenas")
    return 130 if interrupted["flag"] else 0
