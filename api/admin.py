"""Admin + cache + business-logic endpoints.

INTENTIONALLY VULNERABLE - AUTHORIZED LAB ONLY.

  CWE-862  shared-secret-only authorization            (api-06)
  CWE-1059 undocumented shadow API                      (api-13)
  CWE-502  unsafe pickle deserialization in the cache    (flask-09..12, flask-14)
  CWE-841  negative quantity in the shop                (biz-01)
  CWE-362  race condition on coupon redemption          (biz-02)
  CWE-472  client-controlled price                      (biz-03)
"""
import io
import os
import pickle
import sys
import threading
import time

from flask import Blueprint, jsonify, request

import config
from api._common import (cache_get, cache_path, cache_set, current_user, db, flag,
                         is_app_seed, jwt_encode, md5, now, stream_executes_code,
                         username_of)

admin_bp = Blueprint("api_admin", __name__)

# api-13 shadow API (undocumented version prefix)
SHADOW_BANNER = "vulnlab-shadow-api/9.9 (undocumented)"

_redeems = {}
_lock = threading.Lock()


def safe_unpickle(path):
    """INTENTIONALLY VULNERABLE (CWE-502, CVE-2021-33026).

    Unpickles an attacker-controllable file.  This is the lab's *controlled*
    RCE: output is captured and returned so students can see the effect, and
    no real system state is modified.
    """
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        with open(path, "rb") as fh:
            obj = pickle.load(fh)
        out = buf.getvalue()
    except Exception as exc:  # noqa: BLE001 - lab wants the message visible
        out = buf.getvalue()
        result = {"error": "deserialization failed: {}".format(exc.__class__.__name__),
                  "detail": str(exc)[:200]}
        sys.stdout = old
        return None, out, result
    finally:
        sys.stdout = old
    return obj, out, None


# ---------------------------------------------------------------------------
# api-06  Admin export   (CWE-862)
# ---------------------------------------------------------------------------
@admin_bp.get("/api/v1/admin/export")
def admin_export():
    """VULNERABILITY (CWE-862): authorization is a single shared header value
    shipped to every browser in static/js/app.js.  Possession of the key is
    the entire access-control model."""
    key = request.headers.get("X-Internal-Key", "")
    if key != config.INTERNAL_API_KEY:
        return jsonify({"error": "forbidden", "need": "X-Internal-Key"}), 403
    con = db()
    rows = con.execute("SELECT username, email, role, department, note FROM users").fetchall()
    con.close()
    users = []
    for r in rows:
        d = dict(r)
        d["note"] = config.render_placeholders(d.get("note") or "")
        users.append(d)
    return jsonify({
        "export": "all-accounts",
        "rows": users,
        "lab_flag": flag("api-06"),
    })


@admin_bp.get("/api/v1/admin/users")
def admin_users():
    who = current_user(request)
    if not who:
        return jsonify({"error": "login required"}), 401
    if who.get("role") != "admin":
        return jsonify({"error": "admin role required"}), 403
    con = db()
    rows = con.execute("SELECT username, email, role FROM users").fetchall()
    con.close()
    return jsonify({"users": [dict(r) for r in rows]})


# ---------------------------------------------------------------------------
# api-13  Shadow API inventory   (CWE-1059)
# ---------------------------------------------------------------------------
@admin_bp.get("/api/v2/<path:rest>")
@admin_bp.get("/api/internal/<path:rest>")
def shadow_api(rest):
    """Undocumented API version not listed anywhere in the docs."""
    return jsonify({
        "api": SHADOW_BANNER,
        "path": request.path,
        "deprecated": False,
        "note": "this version is not in the published inventory",
        "lab_flag": flag("api-13"),
    })


# ---------------------------------------------------------------------------
# flask-09..flask-12 / flask-14  pickle cache
# ---------------------------------------------------------------------------
@admin_bp.get("/api/v1/cache/info")
def cache_info():
    """Identifies the cache component and serialization format."""
    return jsonify({
        "component": "Flask-Caching",
        "version": "1.10.1",
        "backend": "FileSystemCache",
        "cache_dir": config.CACHE_DIR,
        "serializer": "pickle",
        "cve_2021_33026_prerequisites": "attacker control of the cache backend",
        "lab_flag": flag("flask-09"),
    })


@admin_bp.get("/api/v1/cache/stats")
def cache_stats():
    """Where cache objects physically live."""
    d = config.CACHE_DIR
    entries = []
    if os.path.isdir(d):
        entries = sorted(os.listdir(d))
    total = 0
    for name in entries:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            total += os.path.getsize(p)
    return jsonify({
        "cache_dir": d,
        "entry_count": len(entries),
        "entries": entries,
        "bytes_on_disk": total,
        "persistence": "objects are pickled to <cache_dir>/<key>.pkl on local disk",
        "lab_flag": flag("flask-11"),
    })


@admin_bp.get("/api/v1/cache/get")
def cache_get_route():
    """INTENTIONALLY VULNERABLE (CWE-502, CVE-2021-33026): reads <key>.pkl
    from the cache directory and unpickles it.  Combine with an upload
    path-traversal write to plant an attacker-controlled pickle."""
    key = request.args.get("key", "demo")
    path = cache_path(key)
    if not os.path.exists(path):
        return jsonify({"error": "cache miss", "key": key, "path": path}), 404

    planted = not is_app_seed(key)
    executes = planted and stream_executes_code(path)
    if executes:
        # An attacker-planted pickle that reaches a callable on load: door
        # three of three (flask-boss).
        config.mark_door("flask-12")
    obj, out, err = safe_unpickle(path)
    if err:
        return jsonify(dict(err, key=key, path=path,
                            planted_by_attacker=planted), 500)

    resp = {"key": key, "path": path, "value": _jsonable(obj)}
    if out.strip():
        resp["command_output"] = out.strip()

    if planted:
        # flask-12: the application just deserialized an object it did not write.
        resp["lab_flag"] = flag("flask-12")
        resp["note"] = ("this cache entry was not written by the application - "
                        "it was deserialized from disk anyway")
    if executes:
        # flask-14: the pickle stream invoked a callable on load, so this is
        # code execution, not just an unsafe read.  The chain continues in SSH.
        resp["rce"] = "pickle opcode stream executed a callable on load"
        resp["controlled_rce_flag"] = flag("flask-14")
        resp["credential_hint"] = (
            "a lab service credential lives in {} - read it with the same "
            "primitive, then use it for SSH on port {}".format(
                os.path.join(config.DATA_DIR, "secrets", "svc_flask.creds"),
                config.PORT_SSH))
    return jsonify(resp)


@admin_bp.post("/api/v1/cache/set")
def cache_set_route():
    """Convenience setter used by the app itself."""
    key = request.args.get("key", "")
    value = (request.get_json(silent=True) or {}).get("value", "")
    cache_set(key, value)
    return jsonify({"stored": key})


def _jsonable(obj):
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    return repr(obj)


# ---------------------------------------------------------------------------
# biz-01 / biz-03  shop   (CWE-841, CWE-472)
# ---------------------------------------------------------------------------
CATALOG = {
    "sticker": {"price": 25, "desc": "VulnLab sticker"},
    "hoodie": {"price": 1500, "desc": "VulnLab hoodie"},
    "ROOT_ACCESS_TOKEN": {"price": 100000, "desc": "internal root token (do not sell)"},
}


@admin_bp.post("/api/v1/shop/order")
def shop_order():
    """VULNERABILITIES: quantity sign is never validated (CWE-841) and the
    price is taken from the client (CWE-472)."""
    body = request.get_json(silent=True) or {}
    who = current_user(request) or {"sub": "anonymous"}
    username = body.get("username") or username_of(who) or "anonymous"
    item = body.get("item", "sticker")
    qty = body.get("qty", 1)
    try:
        qty = int(qty)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid qty"}), 400
    price = body.get("price")          # client-controlled price (CWE-472)
    entry = CATALOG.get(item)
    if not entry:
        return jsonify({"error": "unknown item", "catalog": list(CATALOG)}), 404
    unit = price if price is not None else entry["price"]
    from api.users import add_balance, balance_for
    before = balance_for(username)
    delta = -unit * qty
    after = add_balance(username, delta)

    out = {
        "item": item,
        "qty": qty,
        "unit_price_used": unit,
        "balance_before": before,
        "balance_after": after,
    }
    if qty < 0:
        out["note"] = "negative quantity credited instead of debited"
        out["lab_flag"] = flag("biz-01")
    if item == "ROOT_ACCESS_TOKEN" and price is not None and int(price) < entry["price"]:
        out["note"] = "client-supplied price accepted for a high-value item"
        out["lab_flag"] = flag("biz-03")
        out["purchased"] = {"token": "VL_root_tk_" + md5(username + str(now()))[:12]}
    return jsonify(out)


# ---------------------------------------------------------------------------
# biz-02  coupon race   (CWE-362)
# ---------------------------------------------------------------------------
@admin_bp.post("/api/v1/redeem")
def redeem():
    """VULNERABILITY (CWE-362): the balance check and the write are separate,
    non-atomic steps, so concurrent requests redeem the same coupon twice."""
    body = request.get_json(silent=True) or {}
    who = current_user(request) or {"sub": "anonymous"}
    username = body.get("username") or username_of(who) or "anonymous"
    coupon = body.get("coupon", "")
    from api.users import balance_for, add_balance
    balance = balance_for(username)
    time.sleep(0.05)  # widen the check/write window on purpose
    if balance < 0:
        return jsonify({"error": "not eligible", "balance": balance}), 400
    add_balance(username, 100)
    with _lock:
        count = _redeems.get(coupon, 0) + 1
        _redeems[coupon] = count
    out = {"coupon": coupon, "redeemed": True, "times_redeemed": count,
           "balance": balance_for(username)}
    if count >= 2:
        out["note"] = "coupon accepted more than once - check/write race"
        out["lab_flag"] = flag("biz-02")
    return jsonify(out)