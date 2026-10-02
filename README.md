# Biluzim

```
 ____    ___   _       _   _   _____   ___   __  __
| __ )  |_ _| | |     | | | | |__  / |_ _| |  \/  |
|  _ \   | |  | |     | | | |   / /   | |  | |\/| |
| |_) |  | |  | |___  | |_| |  / /_   | |  | |  | |
|____/  |___| |_____|  \___/  /____| |___| |_|  |_|
Recon passivo + enumeracao ativa   v0.3.0
```

Biluzim é uma ferramenta de reconhecimento para terminal com três times: o passivo (subdomínios via fontes OSINT), o ativo (dir, dns, vhost, fuzz, s3/gcs, tftp) e o explorador (crawler que vasculha o site por dentro):

Escrita em **Python 3 puro (só stdlib)** — nada de `pip install` no Kali.
Todo achado é reportado como **achado de enumeração**, nunca como
vulnerabilidade.

> **Uso autorizado apenas.** Consultas passivas geram informação sobre um
> alvo; sondas ativas enviam pacotes a ele. Só rode contra sistemas que
> você tem permissão para testar.

---

## Instalação (Kali / Debian / Ubuntu)

Pré-requisito: **Python 3.9+** (padrão no Kali). Nenhuma biblioteca extra.

```bash
# clone este projeto (ou baixe o ZIP e extraia)
cd biluzim
sudo ./install.sh          # instala em /usr/local/bin/biluzim
```

Sem root? Instala em `~/.local/bin`:

```bash
./install.sh
```

Alternativa via pip (opcional):

```bash
sudo pip3 install .
```

Confirme:

```bash
biluzim --version
# biluzim 0.1.0
```

---

## Modos

```
biluzim                  sem argumentos: MODO WIZARD (alvo 1x, os 3 times em fila)
biluzim <modo> [opções]

PASSIVOS (nunca tocam no alvo)
  recon                subdominios via fontes OSINT (crt.sh, wayback, OTX...)

ATIVOS (sondam o alvo, so reportam, nao exploram)
  explore              crawler profundo: links, JS, leaks, forms, params
  dir                  forca bruta de diretorios/arquivos
  dns                  forca bruta de subdominios via DoH
  vhost                enumeracao de virtual hosts (header Host)
  fuzz                 substituicao de payloads com FUZZ
  s3 / gcs             checagem read-only de buckets
  tftp                 checagem de arquivos via TFTP RRQ (so o 1o bloco)
```

### `run` — o modo wizard (o maestro)

```bash
biluzim                       # abre a conversa: alvo 1x e os 3 times em fila
biluzim run --yes -d alvo.com # scriptado: roda tudo sem perguntar
biluzim run --yes -d alvo.com --active dir,dns --no-explore
```

O wizard pergunta o alvo uma vez so e vai comandando os times:

1. **recon passivo** roda e entrega o resumo por fonte;
2. resolve e sonda os subdominios achados (ponte passivo->ativo);
3. `Entrar no modo ativo? [s/N]` - executa a fila `dns,dir,vhost,fuzz,s3,gcs,tftp` (ou a lista que voce digitar) nos alvos vivos;
4. `Rodar o explorador? [s/N]` - o explore entra nos URLs que responderam;
5. tudo consolida num arquivo so (padrao: `biluzim_<dominio>.txt`; `-f jsonl` para JSONL).

Respostas podem ser pipeadas (EOF = padrao), entao o wizard tambem e scriptavel: `printf 'alvo.com


s
s
' | biluzim`.

### `recon` — passivo

```bash
biluzim recon -d exemplo.com                       # fontes gratuitas padrao
biluzim recon -d exemplo.com -o subs.txt           # tambem grava em arquivo
biluzim recon -dL dominios.txt -o resultados.txt   # lista de dominios
biluzim recon -d exemplo.com -S crtsh,waybackarchive   # so estas fontes
biluzim recon -d exemplo.com --all                 # todas as fontes (inclui as pesadas)
biluzim recon -d exemplo.com --exclude-sources scanmalware,thc
biluzim recon --list-sources                       # tabela de fontes/chaves
biluzim recon -d exemplo.com -f jsonl --show-sources   # JSONL com fonte de cada achado
```

- `-d` aceita repetição e vírgulas (`-d a.com,b.com`); `-dL` aceita arquivo
  (linhas com `#` são comentários).
- A lista é **ponto de partida**, não inventário fechado: registros passivos
  podem estar fora do ar, não resolver, ou nem pertencer à organização
  (curingas e certificados compartilhados geram ruído).

### A ponte: do passivo ao ativo

```bash
biluzim recon -d exemplo.com --resolve --probe
```

```
www.exemplo.com  [93.184.216.34]
200       713  https://www.exemplo.com/  | Example Domain
```

- `--resolve` — resolve DNS de cada subdomínio achado (**passo ativo**);
- `--probe` — faz `GET /` em https e http e reporta status, tamanho e título
  (**passo ativo**; não segue redirects, mesma regra dos outros modos).

Depois disso, aprofunde no que estiver vivo com os modos ativos:

```bash
biluzim explore -u https://www.exemplo.com            # vasculha o site por dentro
biluzim dir -u https://www.exemplo.com -w /usr/share/wordlists/dirb/common.txt
biluzim dns -d exemplo.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### `explore` — crawler profundo

```bash
biluzim explore -u https://alvo.com
biluzim explore -u https://alvo.com -d 5 --max-pages 500 -t 16
biluzim explore -u https://alvo.com --scope subdomains      # segue para *.alvo.com
biluzim explore -u https://alvo.com --out-urls urls.txt     # alimenta dir/fuzz depois
```

O que ele vasculha e reporta:

- **crawler** por profundidade (`-d`), com orcamento de paginas (`--max-pages`), so em-escopo;
- **robots.txt** e **sitemap.xml** viram mapa: `Disallow` e `<loc>` entram na fila (e sao reportados);
- **JS**: endpoints embutidos e **segredos** — chaves AWS (`AKIA...`), Google (`AIza...`), JWT, token Slack, private key e genericos `api_key/secret/token/password` (valor sempre mascarado);
- **vazamentos classicos** com assinatura de conteudo e filtro de soft-404: `/.git/HEAD`, `/.env`, `/.svn`, `/.DS_Store`, `dump.sql`, `backup.zip`, `server-status`, `actuator`... (lista extra via `--sensitive-list`);
- **directory listing** aberto ("Index of /");
- **formularios**: action, metodo e campos — enumera, **nunca submete**;
- **e-mails e comentarios** no HTML (comentario de dev e ouro);
- **fingerprint**: `Server`, `X-Powered-By`, `generator`, cookies;
- **mineracao de parametros**: canario aleatorio em ~100 nomes classicos; reporta parametro **refletido**, que **muda status** ou que **muda o corpo** — so sinal, sem payload de ataque.

Tudo e GET e reportado; a Biluzim nao submete formulario e nao injeta payload destrutivo. Os achados alimentam o proximo passo (`fuzz`, `dir` ou o exploit runner de sua preferencia).

### `dir` — força bruta de diretórios

```bash
biluzim dir alvo.com words.txt                     # forma posicional (assume https://)
biluzim dir -u https://alvo.com/app/ -w words.txt  # path/query preservados
biluzim dir alvo.com words.txt -x php,html -t 16 -s 200,301
biluzim dir alvo.com words.txt -b 302 --exclude-length 0
cat words.txt | biluzim dir alvo.com -             # wordlist pelo stdin
biluzim dir alvo.com words.txt -o hits.jsonl -f jsonl -q
```

- **Soft-404 automático**: sonda 2 paths aleatórios; se o alvo responde
  igual para o que não existe (mesmo status/corpo), candidatos idênticos
  são filtrados. Use `-s <status>` para desligar a exclusão de 404.

### `dns` — subdomínios via DoH

```bash
biluzim dns -d alvo.com -w subs.txt
biluzim dns alvo.com subs.txt --resolver https://dns.google/resolve
```

- Detecta **wildcard**: 3 nomes aleatórios resolvendo para o mesmo IP viram
  assinatura, e candidatos com esse IP são descartados.
- Resolvedor DoH JSON: `https://dns.google/resolve` (padrão),
  `https://cloudflare-dns.com/dns-query?ct=application/dns-json`, etc.

### `vhost` — virtual hosts

```bash
biluzim vhost -u https://alvo.com -w vhosts.txt
biluzim vhost -u https://alvo.com -D alvo.com -w vhosts.txt   # Host = palavra.alvo.com
```

- Baseline com 2 Hosts aleatórios: respostas com o mesmo status/tamanho do
  "não achado" são descartadas; 5xx com Host custom é reportado (o Host
  existe, o alvo responde erro).

### `fuzz` — payloads com FUZZ

```bash
biluzim fuzz "alvo.com/busca?q=FUZZ" payloads.txt
biluzim fuzz alvo.com/FUZZ payloads.txt
biluzim fuzz alvo.com/api payloads.txt -X POST --body "user=FUZZ"
biluzim fuzz alvo.com payloads.txt -H "X-Token: FUZZ"
```

- Baseline com um payload de controle aleatório: respostas iguais à
  "vazia" são filtradas.

### `s3` / `gcs` — buckets (read-only)

```bash
biluzim s3  -w buckets.txt
biluzim gcs -w buckets.txt
biluzim s3  -w buckets.txt --endpoint "http://%s.minha-s3-compativel/"
```

- Só status probe: `200 = público`, `403 = existe (negado)`,
  `404 = ausente`. Nunca lê conteúdo, nunca escreve.

### `tftp` — arquivos via TFTP

```bash
biluzim tftp 192.168.1.1 -w files.txt          # porta padrão 69
biluzim tftp -u 192.168.1.1:6969 -w files.txt
```

- Manda RRQ (opcode 1) e reporta: `existe` (DATA — baixa só o primeiro
  bloco de ~512 bytes), `negado` (ERROR 2), `nao_existe` (ERROR 1).
- IPv4, UDP, com retry para perda de pacote.

---

## Wordlists

Cada modo tem uma **wordlist embutida pequena** (em `biluzim/wordlists/`)
para você testar a ferramenta na hora. Para trabalho real, use as do Kali:

```bash
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt   # (apt install seclists)
```

---

## Credenciais das fontes (recon)

Roda sem nenhuma chave: as fontes gratuitas cobrem o essencial
(`crtsh`, `waybackarchive`, `alienvault`, `anubis`, `shodanct`,
`subdomaincenter`, `threatminer`, `hackertarget`, `scanmalware`, `thc`,
`urlscan`, `internetdb` + extras com `--all`).

Fontes pagas/chaveadas entram quando você credencia. Veja o estado com
`biluzim recon --list-sources` e configure por:

**Variáveis de ambiente:**

```bash
export BILUZIM_SHODAN_API_KEY="..."
export BILUZIM_VIRUSTOTAL_API_KEY="..."
```

**Arquivo de config** (`~/.config/biluzim/config.json`, ou `--config arquivo`):

```json
{ "sources": { "shodan": { "api_key": "..." }, "github": { "token": "..." } } }
```

Modelo completo em [`config.example.json`](config.example.json). Nunca
faça commit de chaves reais.

---

## Saída e códigos de saída

Resultados vão para o **stdout**; banner, progresso e diagnóstico para o
**stderr** (pipes limpos: `biluzim recon -d alvo.com -q | sort -u`).
`-o arquivo` espalda a saída (append + flush). `-f jsonl` emite JSON por
linha (`--show-sources` inclui a fonte de cada subdomínio).

| Código | Significado |
|---|---|
| `0` | sucesso |
| `1` | erro operacional (alvo inalcançável, todas as sondas falharam) |
| `2` | erro de uso (argumentos) |
| `3` | sucesso parcial (recon: algumas fontes falharam) |
| `130` | interrompido (Ctrl+C) — resultados parciais preservados |

---

## Laboratório local (teste sem tocar em ninguém)

O pacote traz um alvo de teste que emula soft-404, vhosts, DoH com
wildcard, buckets, TFTP e um mini-site para o modo explore:

```bash
python3 labs/lab.py          # http://127.0.0.1:8000, doh://:8005, tftp://:6969
```

Em outro terminal:

```bash
biluzim explore -u http://127.0.0.1:8000 -d 3 --max-pages 30
biluzim dir -u http://127.0.0.1:8000 -w biluzim/wordlists/directories.txt
biluzim dns -d lab.local -w biluzim/wordlists/subdomains.txt --resolver http://127.0.0.1:8005/resolve
biluzim vhost -u http://127.0.0.1:8000 -D lab.local -w biluzim/wordlists/vhosts.txt
biluzim fuzz "http://127.0.0.1:8000/search?q=FUZZ" -w biluzim/wordlists/fuzz.txt
biluzim tftp -u 127.0.0.1:6969 -w biluzim/wordlists/tftp-files.txt
```

---

## Arquitetura

```
biluzim.py              entry point
biluzim/
├── cli.py              parser de argumentos + handlers de cada modo
├── httpx.py            cliente HTTP único (sem redirect, erros tipados, TLS relaxado)
├── util.py             log/stdout-disciplina, escopo, wordlists, throttle, progresso
├── banner.py           banner + cores (respeita NO_COLOR; cores em stderr-tty)
├── passive/            porte do lunatic (Go -> Python)
│   ├── base.py         contrato de fonte, erros tipados, registry
│   ├── sources.py      ~26 fontes OSINT (endpoints/parse copiados do original)
│   └── runner.py       paralelismo, rate-limit por REQUISIÇÃO, fase 2 (internetdb)
└── active/             porte do koffuster (KOF -> Python)
    ├── explore_mode.py crawler profundo: links, robots/sitemap, JS, leaks,
    │                   listings, forms, e-mails, comentarios, params
    ├── classify.py     baseline soft-404 + filtros (-s/-b/--exclude-length)
    ├── dir_mode.py     3 fases por batch como no original
    ├── dns_mode.py     DoH JSON + detecção de wildcard + resolve_names (ponte)
    ├── vhost_mode.py   header Host + baseline de vhost
    ├── fuzz_mode.py    FUZZ em url/header/corpo + baseline de controle
    ├── store_mode.py   s3/gcs por status
    ├── tftp_mode.py    RRQ/UDP com retry
    └── bridge.py       ponte passivo->ativo (--resolve/--probe)
```

Fidelidade aos originais: mesmas flags, mesma semântica de filtros, mesma
detecção de soft-404/wildcard, mesma disciplina de saída (dados no stdout,
diagnóstico no stderr) e os mesmos códigos de saída.

---

Uso autorizado apenas. O que a Biluzim faz é **enumerar** — ela não
explora, não ataca e não quebra nada. Continue assim: pente fino, zero
exploração.
