"""VulnLab debug-lab - 127.0.0.1:8000 (hidden development instance).

==========================================================================
  AUTHORIZED LAB ONLY - vulnerable on purpose.  Do not expose this host.
==========================================================================

This is the "development instance with debugging enabled" that flask-04
points at.  It is a separate listener so the main target on :5000 can stay in
normal production mode while students research the debugger separately.

  flask-04  the page itself announces debug mode
  flask-05  /debug-lab/info lists the machine identity attributes that feed
            the documented md5 grouping, and the deterministic lab PIN
  flask-06  /debug-lab/console is PIN protected; with the PIN it evaluates an
            expression, which is how <flagdir>/debugger.flag gets read

The PIN is computed from the fake identity attributes in
config.DEBUG_PIN_MATERIAL, so every student gets the same stable answer and
the result matches config.compute_debug_pin() used by the scoreboard.
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

from flask import Flask, Response, jsonify, request  # noqa: E402

app = Flask(__name__)
app.secret_key = config.WEB_SECRET_KEY


def flag(cid):
    return config.resolve_flag(cid)


TRACEBACK_FOOTER = (
    "  File \"{fl}\", line {n}, in _wsgi_app\n"
    "    return response(environ, start_response)\n"
)


@app.get("/")
def index():
    """flask-04: the traceback-style footer betrays debug mode."""
    return Response(
        "<h1>vulnlab-debug-lab</h1>\n"
        "<p>Development instance. Do not deploy.</p>\n"
        "<pre>Traceback (most recent call last):\n"
        "  File \"{fl}\", line 42, in index\n"
        "    return render(name)\n"
        "jinja2.exceptions.TemplateNotFound: nope.html\n</pre>\n"
        "<!-- FLASK-04: {f} -->\n".format(fl=config.DEBUG_PIN_MATERIAL["filepath"],
                                           f=flag("flask-04")),
        mimetype="text/html")


@app.get("/debug-lab/info")
def info():
    """flask-05: the attributes a debugger PIN is derived from."""
    m = config.DEBUG_PIN_MATERIAL
    return jsonify({
        "username": m["username"],
        "modname": m["modname"],
        "appname": m["appname"],
        "filepath": m["filepath"],
        "mac": m["mac"],
        "machine_id": m["machine_id"],
        "pin_derivation": "md5 of ':'-joined attributes, hex digits reduced "
                          "mod 10, grouped 6-3",
        "pin": config.compute_debug_pin(),
        "note": "these are fixed lab values so the PIN is stable and "
                "verifiable - see instructor/answer_key.md",
    })


@app.get("/debug-lab/console")
def console():
    """flask-06: PIN protected expression evaluation."""
    pin = (request.args.get("pin") or "").strip()
    expected = config.compute_debug_pin()
    if pin.replace("-", "") != expected.replace("-", ""):
        return Response(
            "<h1>Debugger console</h1>"
            "<p>Console is protected. Enter the debugger PIN.</p>"
            "<form><input name='pin' placeholder='123-456'>"
            "<input name='code' placeholder='expression'>"
            "<button>run</button></form>"
            "<p>tip: the PIN comes from machine identity, not from a secret "
            "file - /debug-lab/info lists the inputs.</p>",
            status=401, mimetype="text/html")

    code = request.args.get("code", "1+1")
    captured = io.StringIO()
    old = sys.stdout
    sys.stdout = captured
    try:
        value = eval(code)  # noqa: S307 - the entire point of the lab
        err = None
    except Exception as exc:  # noqa: BLE001
        value, err = None, "{}: {}".format(exc.__class__.__name__, exc)
    finally:
        sys.stdout = old
    if err is None:
        # Correct PIN plus an evaluated expression: door two of three.
        config.mark_door("flask-06")
    return jsonify({
        "pin_accepted": True,
        "code": code,
        "result": repr(value),
        "error": err,
        "printed": captured.getvalue(),
    })


@app.get("/debug-lab/flagdir")
def flagdir():
    return jsonify({"flag_dir": config.FLAG_DIR,
                    "target_file": "debugger.flag"})


@app.get("/health")
def health():
    return Response("debug-lab up\n", mimetype="text/plain")


def serve():
    print("=" * 62)
    print("  VulnLab debug-lab  (debugger research instance)")
    print("  http://{}:{}/".format(config.BIND_HOST, config.PORT_DEBUG))
    print("=" * 62)
    app.run(host=config.BIND_HOST, port=config.PORT_DEBUG, debug=False,
            threaded=True)


if __name__ == "__main__":
    serve()
