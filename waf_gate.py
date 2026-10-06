"""VulnLab WAF gate - a deliberately broken filtering layer on 127.0.0.1:5050.

==========================================================================
  AUTHORIZED LAB ONLY
  This service is intentionally vulnerable for cybersecurity education.
  Do not expose this machine directly to the public Internet.
==========================================================================

The "protected" application sits behind this gate.  Every protection here is
wrong in a different, instructive way:

  waf-01  exact-match deny rule vs normalising router   (CWE-863)
  waf-02  trusts a spoofable X-Forwarded-For identity   (CWE-290)
  waf-03  authorization checked for GET only            (CWE-863)
  waf-04  raw-body keyword filter vs decoded backend    (CWE-116)
  waf-05  one decode in the filter, two in the backend  (CWE-22)
  recon-03  /diag/ports describes the shadow services
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

from flask import Flask, Response, jsonify, request

import config

app = Flask(__name__)
app.secret_key = config.WEB_SECRET_KEY

# A bind address is not a dial address.  With BIND_HOST=0.0.0.0 the upstream
# URL became http://0.0.0.0:5000, and connecting to 0.0.0.0 fails outright on
# Windows (OSError 10049) - every proxied page answered 502.  Dial loopback.
_UPSTREAM_HOST = "127.0.0.1" if config.BIND_HOST == "0.0.0.0" else config.BIND_HOST
UPSTREAM = "http://{}:{}".format(_UPSTREAM_HOST, config.PORT_WEB)


@app.after_request
def _never_stale(resp):
    """The gate rebuilds proxied responses from scratch, so it must re-apply
    the upstream no-cache policy or it drops it and the preview goes stale."""
    if resp.mimetype == "text/html" or request.path.startswith("/static"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp

# The WAF's idea of "dangerous".  Compared against the RAW request only.
KEYWORDS = ["union", "select", "../", "etc/passwd", "cmd.exe", "<script"]

WAF_BANNER = "vulnlab-waf/2.2 (filter mode: strict)"


def flag(cid):
    return config.resolve_flag(cid)


# ---------------------------------------------------------------------------
# recon-03  shadow service diagnostics
# ---------------------------------------------------------------------------
@app.get("/diag/ports")
def diag_ports():
    body = ("VulnLab WAF diagnostics\n"
            "=========================\n"
            "protected upstream : {up}\n"
            "waf port           : {waf}\n"
            "ctf portal         : {ctf}\n"
            "shadow services (not advertised in the docs):\n"
            "  {d1}  debug-lab   - development instance, debugger enabled\n"
            "  {r1}  redis-like  - cache service, lab data only\n"
            "  {r2}  internals   - internal service catalogue\n"
            "filter mode        : strict\n"
            "rules              : exact-match deny list\n"
            "recon-03: {f}\n").format(
        up=UPSTREAM, waf=config.PORT_WAF, ctf=config.PORT_CTF,
        d1=config.PORT_DEBUG, r1=config.PORT_RABBIT1, r2=config.PORT_RABBIT2,
        f=flag("recon-03"))
    return Response(body, mimetype="text/plain")


@app.get("/diag/rules")
def diag_rules():
    return jsonify({
        "deny_rules": ["/admin", "/internal-panel"],
        "method_rules": {"GET": "deny", "POST": "allow"},
        "keyword_filter": KEYWORDS,
        "body_encoding": "raw, single decode",
        "upstream_body_encoding": "double decode",
    })


@app.get("/health")
@app.get("/")
def health():
    return Response(WAF_BANNER + "\n", mimetype="text/plain")


# ---------------------------------------------------------------------------
# waf-01  exact-match deny rule vs a normalising router
# ---------------------------------------------------------------------------
@app.route("/admin", methods=["GET", "POST", "PUT", "PATCH"])
def admin_gate():
    raw_path = request.environ.get("RAW_URI", request.path) or request.path
    # CWE-863: the deny list compares the raw path for EQUALITY, so a
    # trailing slash, a doubled slash or a dot segment never matches while the
    # router still resolves it to the same handler.
    if raw_path.rstrip("/") == "/admin" and request.method == "GET":
        return Response("403 Forbidden - path denied by filter\n",
                        status=403, mimetype="text/plain")

    body = ("<h1>Admin (behind WAF)</h1>"
            "<p>Reached through the gate. Filter saw "
            "<code>{raw}</code> which did not equal the deny rule.</p>"
            "<p>waf-01: {f}</p>").format(raw=raw_path, f=flag("waf-01"))
    return Response(body, mimetype="text/html")


@app.route("/admin/", methods=["GET", "POST", "PUT", "PATCH"])
@app.route("/admin/..;/admin", methods=["GET", "POST", "PUT", "PATCH"])
def admin_gate_bypass():
    return Response(
        "<h1>Admin (behind WAF)</h1><p>Normalised path reached the handler "
        "while the deny list never matched.</p><p>waf-01: {}</p>".format(
            flag("waf-01")), mimetype="text/html")


# ---------------------------------------------------------------------------
# waf-03  authorization depends on the HTTP method
# ---------------------------------------------------------------------------
@app.route("/admin/action", methods=["GET", "POST", "PUT", "PATCH"])
def admin_action():
    if request.method == "GET":
        return Response("403 Forbidden - action denied for GET\n",
                        status=403, mimetype="text/plain")
    # CWE-863: only one method is checked, so the same authorization decision
    # can be skipped entirely by changing the verb.
    return Response(
        "<h1>Admin action</h1><p>Executed via {m}. The deny rule only covers "
        "GET.</p><p>waf-03: {f}</p>".format(m=request.method, f=flag("waf-03")),
        mimetype="text/html")


# ---------------------------------------------------------------------------
# waf-02  spoofed proxy identity
# ---------------------------------------------------------------------------
@app.get("/internal-panel")
def internal_panel():
    """CWE-290: 'internal only' is decided by a header any client can set."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded.split(",")[0].strip() not in ("127.0.0.1", "::1", "localhost"):
        return Response("403 Forbidden - internal clients only\n",
                        status=403, mimetype="text/plain")
    return Response(
        "<h1>Internal panel</h1><p>Client identity taken from "
        "<code>X-Forwarded-For: {}</code>.</p><p>waf-02: {}</p>".format(
            forwarded, flag("waf-02")), mimetype="text/html")


# ---------------------------------------------------------------------------
# waf-04  filter/backend parser mismatch  (CWE-116)
# ---------------------------------------------------------------------------
@app.route("/api/query", methods=["GET", "POST"])
def api_query():
    raw_body = request.get_data(as_text=True)
    # The filter scans the RAW bytes only, so \uXXXX escapes sail past it...
    lowered = raw_body.lower()
    for kw in KEYWORDS:
        if kw in lowered:
            return Response(
                "406 Not Acceptable - filter rejected keyword: {}\n".format(kw),
                status=406, mimetype="text/plain")
    # ...while the backend decodes the JSON, turning them back into real text.
    try:
        decoded = json.loads(raw_body) if raw_body else {}
    except ValueError:
        decoded = {"raw": raw_body}
    text = json.dumps(decoded)
    hit = [kw for kw in KEYWORDS if kw in text.lower()]
    return jsonify({
        "backend_saw": decoded,
        "backend_keywords": hit,
        "filter_keywords": [],
        "waf-04": flag("waf-04") if hit else None,
    })


# ---------------------------------------------------------------------------
# waf-05  double-decode traversal  (CWE-22)
# ---------------------------------------------------------------------------
@app.get("/download")
def download():
    """The filter decodes once and blocks a literal '..'; the backend decodes
    twice.  `%252e%252e%252f` survives the filter and reaches the backend as
    `../` (CWE-22)."""
    # The raw query string is used deliberately: request.args would already
    # have decoded once, hiding the mismatch the challenge is about.
    raw_value = ""
    for part in (request.environ.get("QUERY_STRING") or "").split("&"):
        if part.startswith("file="):
            raw_value = part[len("file="):]
    once = urllib.parse.unquote(raw_value)          # what the filter inspects
    if ".." in once:
        return Response("403 Forbidden - traversal blocked by filter\n",
                        status=403, mimetype="text/plain")
    twice = urllib.parse.unquote(once)             # what the backend resolves
    if ".." in twice:
        # Reached /secret/flag.txt on the host filesystem.
        return Response(
            "<h1>secret/flag.txt</h1><p>backend decoded twice and served the "
            "file: <code>{}</code></p><p>waf-05: {}</p>".format(
                twice, flag("waf-05")), mimetype="text/html")
    return Response("<p>download {}</p>".format(twice), mimetype="text/html")


# ---------------------------------------------------------------------------
# Proxy everything else to the real application on :5000
# ---------------------------------------------------------------------------
@app.route("/", defaults={"rest": ""},
           methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
@app.route("/<path:rest>",
           methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def proxy(rest):
    target = "{}/{}".format(UPSTREAM, rest)
    data = request.get_data() or None
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "content-length")}
    req = urllib.request.Request(target, data=data, headers=headers,
                                 method=request.method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type", "text/html")
            out = Response(body, status=resp.status,
                           mimetype=ctype.split(";")[0])
            for h in ("X-Lab-First-Contact", "X-Lab-Flag"):
                if h in resp.headers:
                    out.headers[h] = resp.headers[h]
            return out
    except urllib.error.HTTPError as e:
        return Response(e.read(), status=e.code, mimetype="text/plain")
    except Exception as exc:  # noqa: BLE001
        return Response("upstream error: {}".format(exc), status=502,
                        mimetype="text/plain")


if __name__ == "__main__":
    print("=" * 62)
    print("  VulnLab WAF gate")
    print("  AUTHORIZED LAB ONLY - the filter is broken on purpose")
    print("  http://{}:{}/".format(config.BIND_HOST, config.PORT_WAF))
    print("=" * 62)
    app.run(host=config.BIND_HOST, port=config.PORT_WAF, debug=False,
            threaded=True)