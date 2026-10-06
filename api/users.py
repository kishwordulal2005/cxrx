"""User / profile endpoints.

INTENTIONALLY VULNERABLE - AUTHORIZED LAB ONLY.

  CWE-200  excessive data exposure / user enumeration   (api-01, api-04)
  CWE-639  BOLA - object id is used as authorization    (api-02)
  CWE-862  missing authorization on admin lookup         (api-03)
  CWE-915  mass assignment on PATCH /profile             (api-07)
  CWE-285  missing function-level authorization          (api-16)
  CWE-20   improper input validation (fuzz lab)          (api-17)
"""
import threading
import time

from flask import Blueprint, jsonify, request

import config
from api._common import (cache_get, cache_set, current_user, db, flag, jwt_encode,
                         md5, username_of)

users_bp = Blueprint("api_users", __name__)

# In-memory balances for the business-logic track (biz-01..03).
_balances = {}
_redeems = {}
_lock = threading.Lock()


def balance_for(username):
    with _lock:
        if username not in _balances:
            _balances[username] = 500
        return _balances[username]


def add_balance(username, delta):
    with _lock:
        if username not in _balances:
            _balances[username] = 500
        _balances[username] += delta
        return _balances[username]


# ---------------------------------------------------------------------------
# api-01  Who Is Here?   (CWE-200)
# ---------------------------------------------------------------------------
@users_bp.get("/api/v1/users")
def list_users():
    """Public user listing.

    VULNERABILITY (CWE-200): returns internal fields the UI never shows -
    role, department, internal ids, password reset hint, api key fragment and
    free-text notes.  No authentication required.
    """
    con = db()
    rows = con.execute(
        "SELECT id, username, email, role, department, internal_id, profile_id,"
        " password_reset_hint, api_key_fragment, note, verified"
        " FROM users ORDER BY id"
    ).fetchall()
    con.close()
    users = []
    for r in rows:
        d = dict(r)
        d["note"] = config.render_placeholders(d.get("note") or "")
        d["password_reset_hint"] = config.render_placeholders(d.get("password_reset_hint") or "")
        users.append(d)
    return jsonify({
        "count": len(users),
        "users": users,
        # Chatty metadata - the enumeration marker lives here.
        "meta": {
            "generator": "vulnlab-user-directory/2.4",
            "pagination": {"page": 1, "per_page": 100, "total": len(users)},
            "leak_note": flag("api-01"),
        },
    })


# ---------------------------------------------------------------------------
# api-03  Admin Enumeration   (CWE-862)
# ---------------------------------------------------------------------------
@users_bp.get("/api/v1/user")
def get_user():
    """VULNERABILITY (CWE-862): anyone may look up any account by name and
    learn its profile_id, which then feeds the BOLA in /profile/<id>."""
    username = request.args.get("username", "")
    if not username:
        return jsonify({"error": "username required"}), 400
    con = db()
    row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    con.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    d = dict(row)
    # Password hashes are supposed to be omitted here.
    d.pop("password", None)
    d["note"] = config.render_placeholders(d.get("note") or "")
    d["password_reset_hint"] = config.render_placeholders(d.get("password_reset_hint") or "")
    return jsonify({"user": d})


# ---------------------------------------------------------------------------
# api-02 / api-04  BOLA + Excessive Data Exposure   (CWE-639 / CWE-200)
# ---------------------------------------------------------------------------
@users_bp.get("/api/v1/profile")
def own_profile():
    who = current_user(request)
    if not who:
        return jsonify({"error": "login required"}), 401
    return _profile_response(username_of(who))


@users_bp.get("/api/v1/profile/<int:pid>")
def profile_by_id(pid):
    """VULNERABILITY (CWE-639 BOLA): the numeric id is treated as
    authorization.  Ids are sequential and guessable; no ownership check."""
    con = db()
    row = con.execute("SELECT username FROM users WHERE profile_id = ?", (pid,)).fetchone()
    con.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return _profile_response(row["username"])


def _profile_response(username):
    con = db()
    row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    con.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    d = dict(row)
    d.pop("password", None)
    # CWE-200: the raw object carries internal fields the UI hides.
    d["note"] = config.render_placeholders(d.get("note") or "")
    d["password_reset_hint"] = config.render_placeholders(d.get("password_reset_hint") or "")
    return jsonify({"profile": d})


# ---------------------------------------------------------------------------
# api-07  Mass Assignment   (CWE-915)
# ---------------------------------------------------------------------------
@users_bp.patch("/api/v1/profile")
@users_bp.put("/api/v1/profile")
def patch_profile():
    """VULNERABILITY (CWE-915): every JSON key is written straight into the
    users row, so `role`, `verified` or `internal_id` can be set by the client.
    A form whitelist would have blocked this."""
    who = current_user(request)
    if not who:
        return jsonify({"error": "login required"}), 401
    body = request.get_json(silent=True) or {}
    allowed = ["email", "department", "note"]
    con = db()
    username = username_of(who)
    row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        con.close()
        return jsonify({"error": "not found"}), 404

    updated, escalated = {}, False
    for key, value in body.items():
        updated[key] = value  # no allow-list: mass assignment
        if key in ("role", "is_admin", "verified", "internal_id") and value not in (None, 0, False):
            escalated = True

    if updated:
        cols = ", ".join("{}=?".format(k) for k in updated)
        con.execute("UPDATE users SET {} WHERE username=?".format(cols),
                    tuple(updated.values()) + (username,))
        con.commit()
    fresh = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    con.close()

    out = dict(fresh)
    out.pop("password", None)
    out["note"] = config.render_placeholders(out.get("note") or "")
    payload = {"profile": out, "accepted_fields": list(updated.keys())}
    if escalated:
        payload["escalation"] = "server accepted privileged fields from the client"
        payload["lab_flag"] = flag("api-07")
    return jsonify(payload)


# ---------------------------------------------------------------------------
# api-16  Function-Level Authorization   (CWE-285)
# ---------------------------------------------------------------------------
@users_bp.post("/api/v1/user/export")
def user_export():
    """VULNERABILITY (CWE-285): this is an admin-only bulk export, but the
    handler never checks the caller's role - any valid token is accepted."""
    who = current_user(request)
    if not who:
        return jsonify({"error": "login required"}), 401
    con = db()
    rows = con.execute(
        "SELECT username, email, role, department FROM users ORDER BY id").fetchall()
    con.close()
    users = []
    for r in rows:
        d = dict(r)
        d["note"] = config.render_placeholders(d.get("note") or "")
        users.append(d)
    return jsonify({
        "exported_as": username_of(who),
        "caller_role": who.get("role", "user"),
        "authorization_checked": False,
        "rows": users,
        "lab_flag": flag("api-16"),
    })


# ---------------------------------------------------------------------------
# api-17  Fuzzing lab   (CWE-20)
# ---------------------------------------------------------------------------
@users_bp.get("/api/v1/fuzz")
@users_bp.post("/api/v1/fuzz")
def fuzz():
    """Type-confusion target.  `x` is expected to be a string; an object or
    array raises an unhandled exception and the debug handler leaks a trace
    containing the lab marker."""
    body = request.get_json(silent=True) if request.method == "POST" else request.args
    x = body.get("x", "")
    if isinstance(x, (dict, list)):
        # Unhandled type confusion -> the error page carries the marker.
        raise ValueError(
            "fuzz: expected str for 'x', got {} (len {})".format(
                type(x).__name__, len(x))
        )
    if not isinstance(x, str):
        return jsonify({"echo": str(x), "type": type(x).__name__}), 200
    if len(x) > 512:
        return jsonify({"error": "too long"}), 400
    if x.startswith("'"):
        return jsonify({"error": "sql-ish input rejected"}), 400
    return jsonify({"echo": x, "type": "str", "length": len(x)})