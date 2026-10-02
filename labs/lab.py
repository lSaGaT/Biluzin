#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lab local da Biluzim - servidor unico que emula os alvos de teste.

Inspira-se nos labs/http_lab.py + tftp_lab.py do koffuster. Serve para
testar a ferramenta SEM tocar em alvos reais.

Emulacoes (tudo em 127.0.0.1):
  * HTTP :8000  - soft-404 (paths desconhecidos devolvem 200 com corpo
                  fixo), paths "reais" com corpo proprio, vhosts por
                  header Host, endpoint de fuzz, buckets s3/gcs-like;
  * DoH  :8005  - resolver JSON (dns.google/resolve shape) com wildcard:
                  qualquer nome resolve 203.0.113.9 exceto os reais;
  * TFTP :6969/udp - RRQ: arquivos conhecidos -> DATA; outros -> ERROR 1.

Uso:  python labs/lab.py  (Ctrl+C para sair)
"""

import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SOFT_BODY = b"<html><body>Not Found Page Template v1</body></html>"  # corpo fixo do soft-404

KNOWN_PATHS = {
    "/admin": ("admin panel - biluzim lab", 200),
    "/login": ("login page - biluzim lab", 200),
    "/backup.zip": ("PK\x03\x04 fake-zip", 200),
    "/secret": ("top secret area", 403),
    "/old": ("moved permanently", 301),
    # ===== lab do modo explore =====
    "/": ("<html><head><title>Biluzim Lab Home</title></head><body>"
          "<a href='/admin'>admin</a> <a href='/sobre'>sobre</a>"
          " <a href='/static/app.js'>app js</a> <a href='/blog/post1'>post</a>"
          " <a href='/files/'>arquivos</a> <a href='/busca'>busca</a>"
          " <a href='https://externo-fora-do-escopo.com/x'>fora</a>"
          " <form action='/login' method='post'><input name='user'><input name='pass'></form>"
          " </body></html>", 200),
    "/sobre": ("<html><title>Sobre</title><body>"
               "<a href='/contato'>contato</a><a href='/'>home</a></body></html>", 200),
    "/contato": ("<html><title>Contato</title><body>email: contato@lab.local "
                 "<!-- TODO: remover senha de teste antes do deploy --></body></html>", 200),
    "/blog/post1": ("<html><title>Post 1</title><body>"
                    "<a href='/blog/post2'>proximo</a><a href='/admin'>admin</a>"
                    "</body></html>", 200),
    "/blog/post2": ("<html><title>Post 2</title><body>fim</body></html>", 200),
    "/static/app.js": ("var api = '/api/v2/users';\n"
                       "var cfg = 'https://cdn.lab.local/lib.js';\n"
                       "var key = 'AKIAIOSFODNN7EXAMPLE';\n"
                       "var jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123def456ghi789';\n"
                       "fetch('/api/v2/orders?user=')", 200),
    "/api/v2/users": ('[{"id":1,"login":"adm"}]', 200),
    "/secret-area": ("area secreta via robots", 200),
    "/files/": ("<html><head><title>Index of /files/</title></head><body>"
                "<a href='/files/a.txt'>a.txt</a><a href='/files/backup.zip'>backup.zip</a>"
                "</body></html>", 200),
    "/files/a.txt": ("conteudo solto", 200),
    "/busca": (None, 200),  # corpo dinamico: reflete 'q' e 'debug' (ver _route)
}

KNOWN_VHOSTS = {
    "admin.lab.local": "vhost: ADMIN",
    "intranet.lab.local": "vhost: INTRANET",
}

KNOWN_FILES = {
    "passwd": b"root:x:0:0:root:/root:/bin/sh\n",
    "config.txt": b"hostname lab-router\n!\ninterface Vlan1\n",
    "running-config": b"version 15.2\nservice timestamps\n",
}

KNOWN_BUCKETS = {"biluzim-lab-public", "biluzim-lab-denied"}


class LabHTTP(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # silencia o log padrao
        pass

    # ------------------------------------------------------------------
    def _send(self, code, body: bytes, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _host(self):
        return (self.headers.get("Host") or "").split(":")[0].lower()

    def _route(self):
        host = self._host()
        path = self.path.split("?")[0]

        # arquivos especiais do lab (caçados pelo modo explore)
        special = self._special()
        if special:
            return special

        # vhost: so a raiz, so para hosts "virtuais"
        if host in KNOWN_VHOSTS and path == "/":
            return 200, KNOWN_VHOSTS[host].encode()
        if host not in ("127.0.0.1", "localhost") and path == "/":
            return 200, SOFT_BODY  # vhost desconhecido -> pagina padrao

        # buckets
        if path.startswith("/biluzim-lab-public"):
            return 200, "<ListBucketResult>public</ListBucketResult>".encode()
        if path.startswith("/biluzim-lab-denied"):
            return 403, "<Error>AccessDenied</Error>".encode()
        if path.startswith("/biluzim-"):
            return 404, "<Error>NoSuchBucket</Error>".encode()

        # fuzz: ecoa o parametro q (na URL ou no corpo do POST)
        if path == "/search":
            payload = self.path
            if self.command == "POST":
                length = int(self.headers.get("Content-Length") or 0)
                payload = self.rfile.read(length).decode("utf-8", "replace")
                if "q=" not in payload:
                    return 400, b"missing q"
            if "q=" not in payload:
                return 400, b"missing q"
            q = payload.split("q=", 1)[1]
            q = q.replace("+", " ")
            if "%" in q or "'" in q or '"' in q:
                return 500, b"search backend error"
            if q.isdigit():
                return 200, ("<result>id=%s</result>" % q).encode()
            return 200, ("<result>empty</result>").encode()

        # dir: caminhos conhecidos tem corpo proprio
        if path in KNOWN_PATHS:
            msg, code = KNOWN_PATHS[path]
            if path == "/busca":
                from urllib.parse import parse_qs, unquote
                qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                if "debug" in qs and qs["debug"][0]:
                    return 500, b"debug mode crashed"
                q = unquote(qs.get("q", [""])[0])
                return 200, ("resultado da busca por %s" % q).encode()
            return code, msg.encode()
        return 200, SOFT_BODY  # soft-404: 200 com corpo fixo

    def do_GET(self):
        code, body = self._route()
        ctype = "application/javascript" if self.path.split("?")[0].endswith(".js") else "text/html"
        self._send(code, body, ctype)

    do_HEAD = do_GET
    do_POST = do_GET

    # arquivos especiais do lab (explorados pelo modo explore)
    def _special(self):
        path = self.path.split("?")[0]
        if path == "/robots.txt":
            return 200, ("User-agent: *\nDisallow: /secret-area\n"
                         "Sitemap: http://127.0.0.1:8000/sitemap.xml\n").encode()
        if path == "/sitemap.xml":
            return 200, ('<?xml version="1.0"?><urlset>'
                         "<url><loc>http://127.0.0.1:8000/sobre</loc></url>"
                         "<url><loc>http://127.0.0.1:8000/blog/post1</loc></url>"
                         "</urlset>").encode()
        if path == "/.git/HEAD":
            return 200, b"ref: refs/heads/main\n"
        if path == "/.env":
            return 200, b"DB_HOST=localhost\nDB_PASSWORD=supersecret123\n"
        return None


class LabDoH(BaseHTTPRequestHandler):
    """Emula https://dns.google/resolve com wildcard: 203.0.113.9."""

    REAL = {"www.lab.local": "203.0.113.1", "mail.lab.local": "203.0.113.2",
            "dev.lab.local": "203.0.113.3"}

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs, unquote
        q = parse_qs(urlparse(self.path).query)
        name = unquote(q.get("name", [""])[0]).lower()
        if name in self.REAL:
            self._answer(0, self.REAL[name])
        elif name.endswith("lab.local"):
            # wildcard: qualquer coisa resolve para o mesmo IP
            self._answer(0, "203.0.113.9")
        else:
            self._answer(3, "")  # NXDOMAIN

    def _answer(self, status, ip):
        import json
        data = {"Status": status, "Answer": []}
        if ip:
            data["Answer"] = [{"name": ".", "type": 1, "data": ip}]
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def tftp_server(host="127.0.0.1", port=6969, stop_event=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, port))
    s.settimeout(0.5)
    while True:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            data, addr = s.recvfrom(1500)
        except socket.timeout:
            continue
        if len(data) < 4 or data[0] != 0:
            continue
        opcode = data[1]
        if opcode == 1:  # RRQ
            name = data[2:].split(b"\x00")[0].decode("utf-8", "replace")
            content = KNOWN_FILES.get(name)
            if content is None:
                err = struct.pack("!HH", 5, 1) + b"File not found\x00"
                s.sendto(err, addr)
            else:
                block = struct.pack("!HH", 3, 1) + content[:512]
                s.sendto(block, addr)
    s.close()


def main():
    stop = threading.Event()
    threading.Thread(target=tftp_server, kwargs={"stop_event": stop}, daemon=True).start()
    httpd = ThreadingHTTPServer(("127.0.0.1", 8000), LabHTTP)
    dohd = ThreadingHTTPServer(("127.0.0.1", 8005), LabDoH)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    threading.Thread(target=dohd.serve_forever, daemon=True).start()
    print("lab pronto: http://127.0.0.1:8000  doh://127.0.0.1:8005  tftp://127.0.0.1:6969")
    print("Ctrl+C para sair")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        stop.set()
        httpd.shutdown()
        dohd.shutdown()


if __name__ == "__main__":
    main()
