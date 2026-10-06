"""VulnLab hidden services - :8081 (catalogue) and :6379 (rabbit hole).

==========================================================================
  AUTHORIZED LAB ONLY - vulnerable on purpose.  Do not expose this host.
==========================================================================

These are the "1-3 hidden services" from the lab design.  Not every one of
them is useful - one is a deliberate dead end.

  :8081  internals   real content.  recon-02 (service matrix) lives here.
  :6379  cache       a rabbit hole.  It answers PING/PONG, stores the keys a
                     student sets, and leaks nothing: a deliberate trap for
                     students who see a listening Redis and assume it is the
                     prize.
"""
import os
import socket
import socketserver
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

HOST = config.BIND_HOST


def flag(cid):
    return config.resolve_flag(cid)


# ---------------------------------------------------------------------------
# :8081 - internal service catalogue
# ---------------------------------------------------------------------------
INDEX_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>VulnLab internal catalogue</title></head><body>
<h1>vulnlab-internals 0.8</h1>
<p>Internal service catalogue. Not linked from the portal.</p>
<ul>
  <li><a href="/services">/services</a> - the full service matrix</li>
  <li><a href="/matrix">/matrix</a> - ports, owners and exposure</li>
  <li><a href="/notes">/notes</a> - deployment notes</li>
</ul>
</body></html>
"""

MATRIX = {
    "generated": "2024-02-11",
    "target": config.TARGET_HOST,
    "services": [
        {"port": config.PORT_FTP, "proto": "ftp", "owner": "ops",
         "note": "anonymous read enabled since 2019"},
        {"port": config.PORT_TELNET, "proto": "telnet", "owner": "net",
         "note": "edge management console, plaintext"},
        {"port": config.PORT_SSH, "proto": "ssh", "owner": "ops",
         "note": "password and key auth"},
        {"port": config.PORT_SMB_SIM, "proto": "smb", "owner": "net",
         "note": "share simulator"},
        {"port": config.PORT_WEB, "proto": "http", "owner": "web",
         "note": "portal + API"},
        {"port": config.PORT_WAF, "proto": "http", "owner": "sec",
         "note": "filter in front of the portal"},
        {"port": config.PORT_CTF, "proto": "http", "owner": "edu",
         "note": "scoreboard"},
        {"port": config.PORT_DEBUG, "proto": "http", "owner": "web",
         "note": "development instance, not advertised"},
        {"port": config.PORT_RABBIT1, "proto": "redis", "owner": "web",
         "note": "cache"},
        {"port": config.PORT_RABBIT2, "proto": "http", "owner": "platform",
         "note": "this catalogue"},
    ],
}

NOTES = """Deployment notes
=================
2024-02-11  the internals catalogue was moved off the portal after the
            last penetration test; it still answers on its own port.
2024-02-09  debug-lab came back up. Someone needs to take it down.
2024-02-02  rotate svc_web before the external audit.
2024-01-28  the cache service on {p} has never had a client attached.
"""


class InternalsHandler(socketserver.StreamRequestHandler):
    """A tiny HTTP server so students can browse the catalogue."""

    timeout = 30

    def handle(self):
        # readline, not read(n): a socket file blocks until n bytes arrive.
        raw = self.rfile.readline()
        if not raw:
            return
        line = raw.decode("utf-8", "replace").strip()
        try:
            method, path, _ = line.split(" ", 2)
        except ValueError:
            return
        # Drain the headers so the client is not left writing into a full buffer.
        while True:
            h = self.rfile.readline()
            if not h or h in (b"\r\n", b"\n"):
                break
        path = path.split("?")[0]
        if len(path) > 1:
            path = path.rstrip("/")
        body, ctype = self.route(path)
        payload = body.encode("utf-8")
        self.wfile.write(
            ("HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n"
             "Connection: close\r\n\r\n".format(ctype, len(payload))).encode())
        self.wfile.write(payload)

    def route(self, path):
        import json
        if path == "/":
            return INDEX_HTML, "text/html; charset=utf-8"
        if path == "/services":
            return (json.dumps(MATRIX, indent=2) +
                    "\n// recon-02: {}\n".format(flag("recon-02"))), \
                "application/json"
        if path == "/matrix":
            rows = ["{:<6} {:<8} {:<10} {}".format(
                s["port"], s["proto"], s["owner"], s["note"])
                for s in MATRIX["services"]]
            return ("<h1>service matrix</h1><pre>" + "\n".join(rows) +
                    "\nrecon-02: " + flag("recon-02") + "</pre>"), \
                "text/html; charset=utf-8"
        if path == "/notes":
            return ("<h1>notes</h1><pre>" +
                    NOTES.format(p=config.PORT_RABBIT1) + "</pre>"), \
                "text/html; charset=utf-8"
        return ("404 - no such catalogue entry: " + path), "text/plain"


# ---------------------------------------------------------------------------
# :6379 - deliberate rabbit hole
# ---------------------------------------------------------------------------
class CacheHandler(socketserver.StreamRequestHandler):
    """Answers like a key/value cache service and reveals nothing useful."""

    timeout = 30

    def setup(self):
        self.store = {}
        # Build rfile/wfile first: if the greeting below raises, BaseRequestHandler
        # still calls finish(), which needs wfile to exist.
        super().setup()
        try:
            self.request.sendall(
                b"*1\r\n$4\r\nINFO\r\n:6144\r\n# VulnLab cache service\r\n"
                b"# 0 keys, 0 expires, 0 already expired\r\n"
                b"# nothing interesting in here, keep looking\r\n")
        except OSError:
            # Client hung up between connect and greeting; nothing to serve.
            self.close_connection = True

    def handle(self):
        while True:
            try:
                data = self.request.recv(4096)
            except (socket.timeout, TimeoutError):
                return          # idle client, clean shutdown
            if not data:
                return
            for line in data.decode("utf-8", "replace").split("\r\n"):
                line = line.strip()
                if not line:
                    continue
                verb = line[1:].split()[0].upper() if line.startswith("$") else line.split()[0].upper()
                if verb == "PING":
                    self.request.sendall(b"+PONG\r\n")
                elif verb in ("GET", "GETRANGE"):
                    parts = line.split()
                    key = parts[-1].lstrip("$")
                    val = self.store.get(key)
                    if val is None:
                        self.request.sendall(b"$-1\r\n")
                    else:
                        self.request.sendall(
                            "${}\r\n{}\r\n".format(len(val), val).encode())
                elif verb == "SET":
                    parts = line.split()
                    if len(parts) >= 3:
                        self.store[parts[-2].lstrip("$")] = parts[-1]
                        self.request.sendall(b"+OK\r\n")
                    else:
                        self.request.sendall(b"-ERR wrong number of arguments\r\n")
                elif verb == "KEYS":
                    self.request.sendall(
                        ("*{}\r\n".format(len(self.store)) +
                         "".join("${}\r\n{}\r\n".format(k, k)
                                 for k in self.store)).encode())
                elif verb == "INFO":
                    self.request.sendall(
                        (":6144\r\n# {} keys, 0 expires, 0 already expired\r\n"
                         .format(len(self.store))).encode())
                elif verb == "QUIT":
                    return
                else:
                    self.request.sendall(b"-ERR unknown command\r\n")


class ThreadedTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        """Stay quiet when a scanner probes a service and hangs up.

        Windows raises ConnectionAbortedError/ConnectionResetError for every
        client that closes mid-handshake, and the stock handler then trips
        over the missing `wfile` (setup() raised before the stream was built).
        Neither is interesting to a student, so keep genuine bugs on stderr
        but drop the disconnect noise.  socketserver dispatches this on the
        *server*, not on the request handler.
        """
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionAbortedError, ConnectionResetError,
                            BrokenPipeError, socket.timeout, TimeoutError,
                            OSError)):
            return
        socketserver.BaseServer.handle_error(self, request, client_address)


def serve_internals():
    srv = ThreadedTCP((HOST, config.PORT_RABBIT2), InternalsHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def serve_cache():
    srv = ThreadedTCP((HOST, config.PORT_RABBIT1), CacheHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    serve_internals()
    serve_cache()
    print("hidden services up on {} and {}".format(config.PORT_RABBIT1,
                                                  config.PORT_RABBIT2))
    threading.Event().wait()