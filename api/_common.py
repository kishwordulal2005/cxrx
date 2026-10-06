"""Shared helpers for the VulnLab API blueprints.

Everything in here is intentionally unsafe in specific, documented ways.
Each vulnerability is annotated with its CWE so the instructor answer key and
the on-page source leaks stay consistent.

INTENTIONALLY VULNERABLE - AUTHORIZED LAB ONLY.
"""
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time

import config


# ---------------------------------------------------------------------------
# Flag delivery
# ---------------------------------------------------------------------------
def flag(cid):
    """Server-side flag string for a challenge id (never sent to a client
    unless the student has actually earned it through the intended action)."""
    return config.resolve_flag(cid)


def seeded(row):
    """Expand {{FLAG:id}} placeholders in a database row."""
    return config.render_placeholders(row)


def db():
    return database_target()


def database_target():
    import database
    return database.target_db()


# ---------------------------------------------------------------------------
# Minimal HS256 JWT (no third-party dependency)
# ---------------------------------------------------------------------------
def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def b64u_dec(seg):
    if isinstance(seg, str):
        seg = seg.encode()
    pad = b"=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def jwt_encode(payload, secret=None, header=None):
    """Sign a payload with the weak lab secret (CWE-321)."""
    secret = config.JWT_SECRET if secret is None else secret
    head = {"alg": "HS256", "typ": "JWT"} if header is None else header
    h = b64u(json.dumps(head, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    signing = h + b"." + p
    sig = b64u(hmac.new(secret.encode(), signing, hashlib.sha256).digest())
    return (signing + b"." + sig).decode()


def jwt_peek(token):
    """Return (header, payload, signature_bytes) without verifying."""
    try:
        h, p, s = token.split(".")
        return json.loads(b64u_dec(h)), json.loads(b64u_dec(p)), b64u_dec(s)
    except Exception:
        return None, None, None


def jwt_verify(token, secret=None):
    """INTENTIONALLY FLAWED (CWE-347).

    The verifier trusts the token's own `alg` header and has a fallback path
    for unsigned tokens, so `{"alg": "none"}` is accepted.
    """
    head, payload, sig = jwt_peek(token)
    if head is None:
        return None, "malformed"
    alg = head.get("alg", "HS256")
    secret = config.JWT_SECRET if secret is None else secret
    if alg.lower() == "none":
        # Vulnerable fallback path.
        return payload, None
    signing = token.rsplit(".", 1)[0].encode()
    expected = hmac.new(secret.encode(), signing, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig or b""):
        return None, "bad_signature"
    return payload, None


def current_user(req):
    """Return the caller dict from the Authorization header, or None."""
    auth = req.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    payload, err = jwt_verify(auth.split(None, 1)[1].strip())
    if payload is None:
        return None
    return payload


def username_of(who):
    """The identity claim a token carries (`sub`, or `username` if minted so)."""
    if not who:
        return None
    return who.get("username") or who.get("sub")


# ---------------------------------------------------------------------------
# Pickle-backed cache (FLASK-09..FLASK-12, CVE-2021-33026)
# ---------------------------------------------------------------------------
def cache_path(key):
    """INTENTIONALLY VULNERABLE: key is joined into a path (CWE-22).

    Only the colon is percent-encoded.  Seeded keys such as
    'session:svc_web' would otherwise be truncated on Windows, where ':'
    opens an alternate data stream: the seed silently became a file called
    'session' and 'rate:otp' read back as a cache miss.  Path traversal is
    left completely untouched - `../` walking out of the cache directory is
    the vulnerability this endpoint exists to teach.
    """
    os.makedirs(config.CACHE_DIR, exist_ok=True)
    return os.path.join(config.CACHE_DIR, "{}.pkl".format(key.replace(":", "%3A")))


def cache_set(key, value):
    import pickle
    with open(cache_path(key), "wb") as fh:
        pickle.dump(value, fh)


def cache_get(key):
    import pickle
    p = cache_path(key)
    if not os.path.exists(p):
        return None, None
    with open(p, "rb") as fh:
        return pickle.load(fh), p


APP_CACHE_KEYS = set()


def warm_cache():
    """Pre-warm a few cache entries (FLASK-09/11, BONUS-08 stale entry)."""
    os.makedirs(config.CACHE_DIR, exist_ok=True)
    cache_set("demo", {
        "cache_component": "Flask-Caching",
        "backend": "FileSystemCache",
        "serializer": "pickle",
        "version": "1.10.1",
        "stale_payload": "pre-warmed 2019-04-02 by deploy user, never invalidated",
        "stale_flag": config.resolve_flag("bonus-08"),
        "note": "objects are serialized with pickle and written to ./data/cache",
    })
    cache_set("session:svc_web", {"user": "svc_web", "role": "service",
                                 "legacy": True, "stale": True})
    cache_set("rate:otp", {"sent": 0, "window": 60})
    APP_CACHE_KEYS.update({"demo", "session:svc_web", "rate:otp"})


def is_app_seed(key):
    """True when the application itself wrote this cache entry.

    Anything else on disk was planted by somebody else, which is precisely
    the condition that turns a cache read into CWE-502.
    """
    return key in APP_CACHE_KEYS


def stream_executes_code(path):
    """True when a pickle opcode stream invokes a callable on load.

    The application only ever dumps plain dicts, strings and lists, so a
    REDUCE/STACK_GLOBAL opcode in the stream means the payload will execute
    attacker-chosen code the moment it is loaded (classic __reduce__ gadget).
    """
    import pickletools
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        for op, _arg, _pos in pickletools.genops(data):
            if op.name in ("REDUCE", "STACK_GLOBAL", "GLOBAL", "INST", "OBJ"):
                return True
    except Exception:  # noqa: BLE001
        return False
    return False


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def client_ip(req):
    # INTENTIONALLY VULNERABLE (CWE-290): trusts a spoofable proxy header.
    return (req.headers.get("X-Forwarded-For")
            or req.headers.get("X-Real-IP")
            or req.remote_addr or "unknown")


def now():
    return int(time.time())


def md5(text):
    return hashlib.md5(text.encode()).hexdigest()