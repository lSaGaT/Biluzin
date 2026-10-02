# -*- coding: utf-8 -*-
"""CLI da Biluzim: um binario, oito modos, zero exploracao.

Modos passivos (nunca tocam no alvo):
  recon               subdominios via fontes OSINT (lunatic)

Modos ativos (sondam o alvo, reportam, nao exploram):
  dir dns vhost fuzz s3 gcs tftp                (koffuster)

Ponte passivo->ativo:
  recon --resolve / --probe     (verifica os nomes achados)

Codigos de saida:
  0   sucesso
  1   erro operacional (alvo inalcancavel / nenhuma fonte respondeu)
  2   erro de uso (argumentos)
  3   sucesso parcial (algumas fontes falharam)
  130 interrompido (Ctrl+C), resultados parciais preservados
"""

import argparse
import json
import os
import signal
import sys
from urllib.parse import urlparse

from . import __version__
from .banner import Palette, colors_enabled, print_banner
from .httpx import HttpClient
from .util import Log, Emitter, parse_domain, ScopeError

DEFAULT_RESOLVER = "https://dns.google/resolve"

CONFIG_CANDIDATES = (
    os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")),
                 "biluzim", "config.json"),
    os.path.expanduser("~/.biluzim.json"),
)


def load_config(path=None):
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            usage_error("biluzim: config nao encontrada: %s" % path)
        except json.JSONDecodeError as e:
            usage_error("biluzim: config JSON invalida (%s): %s" % (path, e))
    for c in CONFIG_CANDIDATES:
        if os.path.isfile(c):
            try:
                with open(c, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except json.JSONDecodeError as e:
                usage_error("biluzim: config JSON invalida (%s): %s" % (c, e))
    return {}


def default_wordlist(name):
    """Wordlist embutida: fica ao lado do pacote biluzim/wordlists/."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "wordlists", name)


class Ctx:
    """Carrega opcoes comuns e monta os objetos compartilhados."""

    def __init__(self, args, mode):
        self.args = args
        self.mode = mode
        self.pal = Palette(colors_enabled(getattr(args, "color", False),
                                          getattr(args, "no_color", False)))
        self.log = Log(self.pal, quiet=getattr(args, "quiet", False),
                       verbose=getattr(args, "verbose", False))
        self.emitter = Emitter(getattr(args, "format", "text"),
                               getattr(args, "output", None),
                               show_sources=getattr(args, "show_sources", False))
        self.http = HttpClient(
            timeout=getattr(args, "timeout", 10.0),
            retries=getattr(args, "retries", 1),
            user_agent=getattr(args, "user_agent", None),
            cookie=getattr(args, "cookie", None),
            auth=getattr(args, "auth", None),
            extra_headers=parse_header_args(getattr(args, "header", None)),
            proxy=getattr(args, "proxy", None),
        )

    # atributos "mode-specific" expostos como propriedades de args
    def __getattr__(self, name):
        return getattr(self.args, name)

    def summary_line(self, found, errors):
        return ("concluido: %d achados, %d erros" % (found, errors))


def usage_error(msg):
    """Erro de uso: mensagem no stderr e codigo de saida 2."""
    sys.stderr.write(str(msg) + "\n")
    raise SystemExit(2)


def parse_header_args(headers):
    out = {}
    for h in headers or []:
        if ":" not in h:
            usage_error("biluzim: header invalido: %r (use \"Nome: valor\")" % h)
        k, _, v = h.partition(":")
        out[k.strip()] = v.strip()
    return out


def add_common_options(sp, need_output=True):
    sp.add_argument("-o", "--output", help="grava resultados tambem neste arquivo (append)")
    sp.add_argument("-f", "--format", choices=["text", "jsonl"], default="text",
                    help="formato de saida (padrao: text)")
    sp.add_argument("-t", "--threads", type=int, default=8, help="largura do paralelismo (padrao: 8)")
    sp.add_argument("--timeout", type=float, default=10.0, help="timeout por requisicao em s (padrao: 10)")
    sp.add_argument("-r", "--retries", type=int, default=1, help="retries por requisicao (padrao: 1)")
    sp.add_argument("-A", "--user-agent", default=None, help="User-Agent customizado")
    sp.add_argument("-H", "--header", action="append", default=[],
                    metavar='"Nome: valor"', help="cabecalho extra (replicavel)")
    sp.add_argument("--cookie", default=None, help='cookie, ex.: "sessao=abc"')
    sp.add_argument("-a", "--auth", default=None, metavar="USUARIO:SENHA",
                    help="autenticacao HTTP Basic")
    sp.add_argument("--proxy", default=None, metavar="URL", help="proxy http(s), ex.: http://127.0.0.1:8080")
    sp.add_argument("-q", "--quiet", action="store_true", help="so resultados, sem diagnostico")
    sp.add_argument("-v", "--verbose", action="store_true", help="diagnostico detalhado")
    sp.add_argument("--color", action="store_true", help="forca cores")
    sp.add_argument("--no-color", action="store_true", help="desliga cores")


def add_wordlist(sp, required=False, default=None, help_text="wordlist (arquivo) ou '-' para stdin"):
    if default:
        sp.add_argument("-w", "--wordlist", required=required, default=default,
                        help=help_text + "; padrao: embutida " + os.path.basename(default))
    else:
        sp.add_argument("-w", "--wordlist", required=required, help=help_text)


# ---------------------------------------------------------------------------
# subcomandos
# ---------------------------------------------------------------------------


def build_parser():
    ap = argparse.ArgumentParser(
        prog="biluzim",
        description="Biluzim - reconhecimento passivo + enumeracao ativa (lunatic + koffuster)",
        epilog="Uso autorizado apenas. Achados sao de ENUMERACAO, nunca vulnerabilidades.",
    )
    ap.add_argument("--version", action="version", version="biluzim " + __version__)
    sub = ap.add_subparsers(dest="mode", metavar="<modo>")

    # ---- recon (passivo, lunatic) ---------------------------------------
    p = sub.add_parser("recon", aliases=["passive", "osint"],
                       help="enumeracao passiva de subdominios via fontes OSINT")
    p.add_argument("-d", "--domain", action="append", default=[], metavar="DOMINIO",
                   help="dominio alvo (replicavel ou separado por virgula)")
    p.add_argument("-dL", "--domain-list", metavar="ARQUIVO",
                   help="arquivo com dominios (um por linha; '#' comenta)")
    p.add_argument("-S", "--sources", default="", metavar="LISTA",
                   help="somente estas fontes (crtsh,waybackarchive,...)")
    p.add_argument("--exclude-sources", default="", metavar="LISTA", help="exclui fontes")
    p.add_argument("--all", action="store_true",
                   help="todas as fontes nao desabilitadas (inclui as pesadas)")
    p.add_argument("--list-sources", action="store_true",
                   help="tabela de fontes e sai")
    p.add_argument("--show-sources", action="store_true",
                   help="no jsonl, inclui a fonte de cada achado")
    p.add_argument("--max-pages", type=int, default=10, help="paginas por fonte (padrao: 10)")
    p.add_argument("--resolve", action="store_true",
                   help="PONTE ATIVA: resolve DNS dos nomes achados")
    p.add_argument("--probe", action="store_true",
                   help="PONTE ATIVA: sonda HTTP dos nomes achados (implica resolve)")
    p.add_argument("--config", default=None, metavar="ARQUIVO", help="config JSON de credenciais")
    add_common_options(p)

    # ---- dir -------------------------------------------------------------
    p = sub.add_parser("dir", help="forca bruta de diretorios/arquivos")
    p.add_argument("target", nargs="?", default=None, help="URL base (posicional)")
    p.add_argument("listfile", nargs="?", default=None, help="wordlist (posicional)")
    p.add_argument("-u", "--url", default="", help="URL base; sem esquema assume https://")
    add_wordlist(p, default=default_wordlist("directories.txt"))
    p.add_argument("-x", "--extensions", default="", metavar="CSV", help="extensoes extras (php,html)")
    p.add_argument("-s", "--status", dest="status_include", default="", metavar="LISTA",
                   help="so estes status; desliga exclusao de 404 (200,301,500-502)")
    p.add_argument("-b", "--exclude-status", default="", metavar="LISTA", help="exclui status")
    p.add_argument("--exclude-length", default="", metavar="LISTA", help="exclui por tamanho (0,100-200)")
    add_common_options(p)

    # ---- dns ---------------------------------------------------------------
    p = sub.add_parser("dns", help="forca bruta de subdominios via DoH")
    p.add_argument("target", nargs="?", default=None, help="dominio (posicional)")
    p.add_argument("listfile", nargs="?", default=None, help="wordlist (posicional)")
    p.add_argument("-d", "--domain", default="", help="dominio alvo")
    add_wordlist(p, default=default_wordlist("subdomains.txt"))
    p.add_argument("--resolver", default=DEFAULT_RESOLVER,
                   help="resolver DoH JSON (padrao: %s)" % DEFAULT_RESOLVER)
    add_common_options(p)

    # ---- vhost -------------------------------------------------------------
    p = sub.add_parser("vhost", help="enumeracao de virtual hosts via header Host")
    p.add_argument("target", nargs="?", default=None, help="URL base (posicional)")
    p.add_argument("listfile", nargs="?", default=None, help="wordlist (posicional)")
    p.add_argument("-u", "--url", default="", help="URL base; sem esquema assume https://")
    add_wordlist(p, default=default_wordlist("vhosts.txt"))
    p.add_argument("-D", "--domain", default="", metavar="DOMINIO",
                   help="sufixo: Host = palavra.DOMINIO")
    add_common_options(p)

    # ---- fuzz --------------------------------------------------------------
    p = sub.add_parser("fuzz", help="substituicao de payloads com FUZZ em URL/header/corpo")
    p.add_argument("target", nargs="?", default=None, help='URL com FUZZ (posicional)')
    p.add_argument("listfile", nargs="?", default=None, help="wordlist (posicional)")
    p.add_argument("-u", "--url", default="", help='URL contendo FUZZ')
    add_wordlist(p, required=True)
    p.add_argument("-X", "--method", default="GET", help="metodo HTTP (padrao: GET)")
    p.add_argument("--body", default="", help='corpo contendo FUZZ (ex.: "user=FUZZ")')
    p.add_argument("-s", "--status", dest="status_include", default="", metavar="LISTA",
                   help="so estes status (200,301)")
    p.add_argument("-b", "--exclude-status", default="", metavar="LISTA", help="exclui status")
    add_common_options(p)

    # ---- s3 / gcs ------------------------------------------------------------
    for mode_name, ep_help in (("s3", "endpoint S3 custom (padrao: http://%%s.s3.amazonaws.com/)"),
                               ("gcs", "endpoint GCS custom (padrao: https://storage.googleapis.com/%%s/)")):
        p = sub.add_parser(mode_name, help="checagem read-only de buckets (%s)" % mode_name.upper())
        p.add_argument("listfile", nargs="?", default=None, help="wordlist de buckets (posicional)")
        add_wordlist(p, default=default_wordlist("buckets.txt"))
        p.add_argument("--endpoint", default="", help=ep_help)
        add_common_options(p)

    # ---- tftp -------------------------------------------------------------
    p = sub.add_parser("tftp", help="checagem de arquivos via TFTP RRQ (somente leitura)")
    p.add_argument("target", nargs="?", default=None, help="servidor[:porta] (posicional)")
    p.add_argument("listfile", nargs="?", default=None, help="wordlist (posicional)")
    p.add_argument("-u", "--url", default="", help="servidor[:porta] (equivalente ao posicional)")
    add_wordlist(p, default=default_wordlist("tftp-files.txt"))
    p.add_argument("--port", type=int, default=69, help="porta TFTP (padrao: 69)")
    add_common_options(p)

    # ---- explore ----------------------------------------------------------
    p = sub.add_parser("explore", aliases=["explorer", "deep"],
                       help="crawler profundo: links, JS, leaks, listings, forms, params")
    p.add_argument("target", nargs="?", default=None, help="URL semente (posicional)")
    p.add_argument("-u", "--url", action="append", default=[], metavar="URL",
                   help="URL semente (replicavel)")
    p.add_argument("--seeds-file", default="", metavar="ARQUIVO",
                   help="arquivo com URLs sementes (uma por linha)")
    p.add_argument("-d", "--depth", type=int, default=3,
                   help="profundidade do rastreio a partir da semente (padrao: 3)")
    p.add_argument("--max-pages", type=int, default=200,
                   help="orcamento de paginas baixadas (padrao: 200)")
    p.add_argument("--scope", choices=["host", "subdomains"], default="host",
                   help="host: so o host da semente; subdomains: todo *.dominio (padrao: host)")
    p.add_argument("--no-sensitive", action="store_true",
                   help="pula a cacada de arquivos classicos vazados")
    p.add_argument("--sensitive-list", default="", metavar="ARQUIVO",
                   help="paths extras para cacar vazamentos (uma rota por linha)")
    p.add_argument("--no-js", action="store_true", help="pula extracao de endpoints/segredos de JS")
    p.add_argument("--no-params", action="store_true",
                   help="pula mineracao de parametros (sondagem GET com canario)")
    p.add_argument("--param-wordlist", default=default_wordlist("params.txt"),
                   help="wordlist de nomes de parametro")
    p.add_argument("--max-param-probes", type=int, default=50,
                   help="maximo de URLs testadas na mineracao de parametros (padrao: 50)")
    p.add_argument("--out-urls", default="", metavar="ARQUIVO",
                   help="grava todas as URLs descobertas (alimenta dir/fuzz)")
    add_common_options(p)

    return ap


# ---------------------------------------------------------------------------
# handlers por modo
# ---------------------------------------------------------------------------


def _positional(ctx_args, flag_name):
    """Preenche flag a partir do posicional quando o flag ficou vazio."""
    v = getattr(ctx_args, flag_name, "")
    if not v and getattr(ctx_args, "target", None):
        v = ctx_args.target
    if not v and getattr(ctx_args, "listfile", None) and flag_name == "wordlist":
        v = ctx_args.listfile
    return v


def cmd_recon(args, config):
    from .passive.runner import ReconRunner, list_sources_table
    from .active.bridge import run_recon_bridge
    from .util import Emitter

    pal = Palette(colors_enabled(getattr(args, "color", False), getattr(args, "no_color", False)))
    log = Log(pal, quiet=args.quiet, verbose=args.verbose)

    if args.list_sources:
        emitter = Emitter(args.format, args.output)
        if args.format == "jsonl":
            for row in list_sources_table(config):
                emitter.emit(dict(row, type="source"))
        else:
            print("%-16s %-9s %-7s %-6s %-6s %s" % ("FONTE", "AUTH", "PADRAO", "CHAVE", "FASE", "STATUS"))
            for row in list_sources_table(config):
                print("%-16s %-9s %-7s %-6s %-6s %s" % (
                    row["name"], row["auth"], "sim" if row["default"] else "-",
                    row["has_key"], "2" if row["phase2"] else "1", row["status"]))
        return 0

    domains = []
    for d in args.domain:
        domains.extend(x.strip() for x in d.split(",") if x.strip())
    if args.domain_list:
        with open(args.domain_list, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
    if not domains:
        usage_error("biluzim recon: informe o dominio com -d ou -dL")
    clean = []
    for d in domains:
        try:
            clean.append(parse_domain(d))
        except ScopeError as e:
            usage_error("biluzim recon: %s" % e)

    print_banner(pal, args.quiet, args.format)
    emitter = Emitter(args.format, args.output, show_sources=args.show_sources)
    http = HttpClient(timeout=args.timeout, retries=args.retries,
                      user_agent=args.user_agent, proxy=args.proxy)
    runner = ReconRunner(clean[0], http, log, emitter, config=config,
                         selected=[s.strip() for s in args.sources.split(",") if s.strip()],
                         excluded=[s.strip() for s in args.exclude_sources.split(",") if s.strip()],
                         use_all=args.all, max_pages=args.max_pages, workers=args.threads)

    interrupted = {"flag": False}

    def on_sigint(signum, frame):
        interrupted["flag"] = True
        runner.interrupt()

    try:
        signal.signal(signal.SIGINT, on_sigint)
    except (ValueError, AttributeError):
        pass

    failed = 0
    for domain in clean:
        runner.domain = domain
        if not args.quiet:
            log.info("recon: dominio %s, fontes: %s" % (
                domain, "selecionadas" if args.sources else ("todas" if args.all else "padrao")))
        names = runner.run()
        if interrupted["flag"]:
            break
        failed += sum(1 for s in runner.summary if s[1] == "failed")
        # ponte passivo->ativo
        args_quiet_backup = args.quiet
        bridge_cfg = type("BC", (), {
            "resolve": args.resolve or args.probe,
            "probe": args.probe,
            "threads": args.threads,
            "http": http,
        })()
        run_recon_bridge(bridge_cfg, log, emitter, names)
        args.quiet = args_quiet_backup

    # resumo por fonte (stderr)
    if not args.quiet:
        ok = sum(1 for s in runner.summary if s[1] == "ok")
        skip = sum(1 for s in runner.summary if s[1] == "skipped")
        for name, status, detail in runner.summary:
            mark = {"ok": pal.green("ok"), "skipped": pal.gray("skip"),
                    "failed": pal.red("fail")}.get(status, status)
            log.info("%-16s %-5s %s" % (name, mark, detail))
        log.info("fontes: %d ok, %d ignoradas, %d falhas; %d subdominios unicos"
                 % (ok, skip, failed, len(runner.results)))

    emitter.close()
    if interrupted["flag"]:
        return 130
    if failed and not runner.results:
        return 1
    if failed:
        return 3
    return 0


def _require(args, field, msg, flag):
    v = _positional(args, field)
    if not v:
        usage_error("biluzim %s: %s (use %s)" % (args.mode, msg, flag))
    setattr(args, field, v)
    return v


def cmd_dir(args, config):
    from .active.dir_mode import run_dir_mode
    from .util import parse_int_list
    from .active.classify import ensure_scheme

    ctx = Ctx(args, "dir")
    print_banner(ctx.pal, args.quiet, args.format)
    _require(args, "url", "faltou a URL base", "-u <url>")
    args.url = ensure_scheme(args.url)
    _require(args, "wordlist", "faltou a wordlist", "-w <arquivo|->")
    if args.status_include:
        parse_int_list(args.status_include)  # valida cedo
    found, errors = run_dir_mode(ctx, ctx.log, ctx.emitter)
    ctx.log.info(ctx.summary_line(found, errors))
    ctx.emitter.close()
    return 1 if (found == 0 and errors > 0) else 0


def cmd_dns(args, config):
    from .active.dns_mode import run_dns_mode
    ctx = Ctx(args, "dns")
    print_banner(ctx.pal, args.quiet, args.format)
    _require(args, "domain", "faltou o dominio", "-d <dominio>")
    try:
        args.domain = parse_domain(args.domain)
    except ScopeError as e:
        usage_error("biluzim dns: %s" % e)
    _require(args, "wordlist", "faltou a wordlist", "-w <arquivo|->")
    found, errors = run_dns_mode(ctx, ctx.log, ctx.emitter)
    ctx.log.info(ctx.summary_line(found, errors))
    ctx.emitter.close()
    return 1 if (found == 0 and errors > 0) else 0


def cmd_vhost(args, config):
    from .active.vhost_mode import run_vhost_mode
    from .active.classify import ensure_scheme
    ctx = Ctx(args, "vhost")
    print_banner(ctx.pal, args.quiet, args.format)
    _require(args, "url", "faltou a URL base", "-u <url>")
    args.url = ensure_scheme(args.url)
    _require(args, "wordlist", "faltou a wordlist", "-w <arquivo|->")
    found, errors = run_vhost_mode(ctx, ctx.log, ctx.emitter)
    ctx.log.info(ctx.summary_line(found, errors))
    ctx.emitter.close()
    return 1 if (found == 0 and errors > 0) else 0


def cmd_fuzz(args, config):
    from .active.fuzz_mode import run_fuzz_mode
    from .active.classify import ensure_scheme
    from .util import parse_int_list
    ctx = Ctx(args, "fuzz")
    _require(args, "url", "faltou a URL com FUZZ", '-u "alvo.com/?q=FUZZ"')
    args.url = ensure_scheme(args.url)
    print_banner(ctx.pal, args.quiet, args.format)
    if args.status_include:
        parse_int_list(args.status_include)
    found, errors = run_fuzz_mode(ctx, ctx.log, ctx.emitter)
    ctx.log.info(ctx.summary_line(found, errors))
    ctx.emitter.close()
    return 1 if (found == 0 and errors > 0) else 0


def cmd_store(args, config, mode_name):
    from .active.store_mode import run_store_mode
    ctx = Ctx(args, mode_name)
    print_banner(ctx.pal, args.quiet, args.format)
    _require(args, "wordlist", "faltou a wordlist de buckets", "-w <arquivo|->")
    found, errors = run_store_mode(ctx, ctx.log, ctx.emitter, mode_name)
    ctx.log.info(ctx.summary_line(found, errors))
    ctx.emitter.close()
    return 1 if (found == 0 and errors > 0) else 0


def cmd_tftp(args, config):
    from .active.tftp_mode import run_tftp_mode
    ctx = Ctx(args, "tftp")
    print_banner(ctx.pal, args.quiet, args.format)
    _require(args, "url", "faltou o servidor", "-u <host[:porta]>")
    _require(args, "wordlist", "faltou a wordlist", "-w <arquivo|->")
    found, errors = run_tftp_mode(ctx, ctx.log, ctx.emitter)
    ctx.log.info(ctx.summary_line(found, errors))
    ctx.emitter.close()
    return 1 if (found == 0 and errors > 0) else 0


def cmd_explore(args, config):
    from .active.explore_mode import Explorer
    from .active.classify import ensure_scheme

    ctx = Ctx(args, "explore")
    print_banner(ctx.pal, args.quiet, args.format)

    seeds = [ensure_scheme(u) for u in (args.url or []) if u.strip()]
    if getattr(args, "target", None):
        seeds.insert(0, ensure_scheme(args.target))
    if args.seeds_file:
        with open(args.seeds_file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    seeds.append(ensure_scheme(line))
    seeds = list(dict.fromkeys(seeds))
    if not seeds:
        usage_error("biluzim explore: faltou a URL semente (use -u <url> ou --seeds-file)")
    bad = [s for s in seeds if urlparse(s).scheme not in ("http", "https")]
    if bad:
        usage_error("biluzim explore: semente invalida: %s" % ", ".join(bad))
    args.urls = seeds

    explorer = Explorer(ctx, ctx.log, ctx.emitter)
    explorer.run()
    ctx.emitter.close()
    return 1 if explorer.found == 0 and explorer.errors > 0 else 0


HANDLERS = {
    "recon": cmd_recon, "passive": cmd_recon, "osint": cmd_recon,
    "dir": cmd_dir, "dns": cmd_dns, "vhost": cmd_vhost, "fuzz": cmd_fuzz,
    "s3": lambda a, c: cmd_store(a, c, "s3"),
    "gcs": lambda a, c: cmd_store(a, c, "gcs"),
    "tftp": cmd_tftp,
    "explore": cmd_explore, "explorer": cmd_explore, "deep": cmd_explore,
}


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.mode:
        ap.print_help(sys.stderr)
        return 2
    config = load_config(getattr(args, "config", None))
    handler = HANDLERS.get(args.mode)
    if handler is None:
        ap.print_help(sys.stderr)
        return 2
    try:
        return handler(args, config)
    except KeyboardInterrupt:
        sys.stderr.write("\nbiluzim: interrompido; resultados parciais preservados\n")
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
