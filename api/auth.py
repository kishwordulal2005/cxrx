"""Authentication endpoints.

INTENTIONALLY VULNERABLE - AUTHORIZED LAB ONLY.

  CWE-321  weak hard-coded JWT signing secret              (api-08)
  CWE-347  algorithm confusion / trusting the alg header    (api-09)
  CWE-330  predictable password-reset token derivation      (api-10)
  CWE-307  insufficient rate limiting on the OTP            (api-14)
  CWE-942  CORS reflects any Origin with credentials        (api-15)
"""
import random

from flask import Blueprint, jsonify, make_response, request

import config
from api._common import (current_user, db, flag, jwt_encode, jwt_peek,
                         jwt_verify, md5, now)

auth_bp = Blueprint("api_auth", __name__)

RESET_SALT = "1234"  # leaked in static/leaks/flask_settings.py

_otp_state = {"code": None, "issued": 0, "attempts": 0}
_otp_bruteforced = False


# ---------------------------------------------------------------------------
# api-08  Weak JWT secret   (CWE-321)
# ---------------------------------------------------------------------------
@auth_bp.post("/api/v1/auth/login")
def login():
    con = db()
    row = con.execute("SELECT * FROM users WHERE username = ?",
                      (request.args.get("username") or
                       (request.get_json(silent=True) or {}).get("username", ""),)).fetchone()
    con.close()
    username = request.args.get("username") or \
        (request.get_json(silent=True) or {}).get("username", "")
    password = request.args.get("password") or \
        (request.get_json(silent=True) or {}).get("password", "")
    if not row or row["password"] != password:
        return jsonify({"error": "invalid credentials"}), 401
    token = jwt_encode({
        "sub": row["username"],
        "uid": row["id"],
        "role": row["role"],
        "iat": now(),
        # Custom claim: readable only once the signing secret is cracked.
        "lab_flag": flag("api-08"),
    })
    return jsonify({
        "token": token,
        "token_type": "Bearer",
        "algorithm": "HS256",
        "hint": "the signing secret is also used as the Flask session key",
    })


@auth_bp.post("/api/v1/auth/token")
def token_endpoint():
    """Mint a token for any username with only the weak secret - the secret
    leak in static/leaks/flask_settings.py turns this into admin access."""
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    role = body.get("role", "user")
    token = jwt_encode({"sub": username, "role": role, "iat": now()})
    return jsonify({"token": token, "role": role})


@auth_bp.get("/api/v1/auth/inspect")
def inspect_token():
    """Decode a token without verifying it (useful for the algorithm-confusion
    track).  Also shows whether the signature matches the lab secret."""
    token = request.args.get("token", "")
    head, payload, sig = jwt_peek(token)
    if head is None:
        return jsonify({"error": "malformed token"}), 400
    import hashlib
    import hmac
    signing = token.rsplit(".", 1)[0].encode()
    expected = hmac.new(config.JWT_SECRET.encode(), signing, hashlib.sha256).digest()
    return jsonify({
        "header": head,
        "payload": payload,
        "signature_matches_lab_secret": hmac.compare_digest(expected, sig or b""),
    })


def bearer(req):
    auth = req.headers.get("Authorization", "")
    parts = auth.split(None, 1)
    return parts[1].strip() if len(parts) > 1 else ""


@auth_bp.get("/api/v1/auth/me")
def me():
    """Reads the role straight out of the token claim."""
    token = bearer(request)
    payload, err = jwt_verify(token)
    if payload is None:
        return jsonify({"error": err or "login required"}), 401
    head, _, _ = jwt_peek(token)
    return jsonify({
        "sub": payload.get("sub"),
        # INTENTIONALLY FLAWED (CWE-347): the role is trusted from the token.
        "role": payload.get("role"),
        "alg_accepted": (head or {}).get("alg"),
    })


@auth_bp.get("/api/v1/admin/status")
def admin_status():
    """Admin-only view.  Authorization is whatever the token claims (CWE-347),
    so a forged `{"alg":"none","role":"admin"}` token passes."""
    payload, err = jwt_verify(bearer(request))
    if payload is None:
        return jsonify({"error": err or "login required"}), 401
    if payload.get("role") != "admin":
        return jsonify({"error": "admin role required"}), 403
    return jsonify({
        "panel": "admin status",
        "role": "admin",
        "authorized_by": "token claim only",
        "lab_flag": flag("api-09"),
    })


# ---------------------------------------------------------------------------
# api-10  Predictable reset   (CWE-330)
# ---------------------------------------------------------------------------
@auth_bp.post("/api/v1/reset")
def request_reset():
    """VULNERABILITY (CWE-330): the reset token is md5(username + salt), not a
    random value.  With the salt from the leaked settings file the token is
    computable offline."""
    body = request.get_json(silent=True) or {}
    username = body.get("username") or request.args.get("username", "")
    if not username:
        return jsonify({"error": "username required"}), 400
    token = md5(username + RESET_SALT)
    con = db()
    con.execute("DELETE FROM reset_tokens WHERE username = ?", (username,))
    con.execute("INSERT INTO reset_tokens (username, token, used) VALUES (?,?,0)",
                (username, token))
    con.commit()
    con.close()
    return jsonify({
        "message": "reset token generated",
        "username": username,
        "algorithm": "md5",
        "input_template": "<username><salt>",
        "token_preview": token[:8] + "...",
    })


@auth_bp.post("/api/v1/reset/confirm")
def confirm_reset():
    """Confirms a reset token and sets a new password for the account."""
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    token = body.get("token", "")
    new_password = body.get("password", "pwned123")
    expected = md5(username + RESET_SALT)
    if token != expected:
        return jsonify({"error": "invalid token"}), 400
    con = db()
    con.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
    con.commit()
    con.close()
    return jsonify({
        "message": "password updated",
        "username": username,
        "note": "login with the new password",
        "lab_flag": flag("api-10"),
    })


# ---------------------------------------------------------------------------
# api-14  OTP brute force   (CWE-307)
# ---------------------------------------------------------------------------
@auth_bp.post("/api/v1/otp")
def otp_request():
    global _otp_state
    code = random.randint(0, 9999)
    _otp_state["code"] = code
    _otp_state["issued"] = now()
    return jsonify({
        "message": "verification code sent",
        "expires_in": 300,
        # Hint: only 4 digits, no lockout.
        "code_length": 4,
        "rate_limit": "none",
    })


@auth_bp.post("/api/v1/otp/verify")
def otp_verify():
    """VULNERABILITY (CWE-307): unlimited attempts, 4-digit space."""
    global _otp_bruteforced
    body = request.get_json(silent=True) or {}
    guess = str(body.get("code", ""))
    _otp_state["attempts"] += 1
    if _otp_state["code"] is not None and guess == str(_otp_state["code"]):
        out = {"verified": True, "attempts_used": _otp_state["attempts"],
               "lab_flag": flag("api-14")}
        _otp_bruteforced = True
        return jsonify(out)
    return jsonify({
        "verified": False,
        "attempts_used": _otp_state["attempts"],
        "remaining_space": 10000 - _otp_state["attempts"],
        "lockout": False,
    }), 401


# ---------------------------------------------------------------------------
# api-15  CORS misconfiguration   (CWE-942)
# ---------------------------------------------------------------------------
@auth_bp.get("/api/v1/cors-demo")
def cors_demo():
    """VULNERABILITY (CWE-942): reflects any Origin and allows credentials."""
    origin = request.headers.get("Origin", "")
    resp = make_response(jsonify({
        "message": "user profile data",
        "profile": {"username": "student", "email": "student@vulnlab.test"},
    }))
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Vary"] = "Origin"
    if origin:
        # Lab marker rides along so the misconfiguration is unambiguous.
        resp.headers["X-Lab-Note"] = "reflected origin: " + origin
        resp.headers["X-Lab-Flag"] = flag("api-15")
    return resp


@auth_bp.route("/api/v1/cors-demo", methods=["OPTIONS"])
def cors_preflight():
    resp = make_response("", 204)
    origin = request.headers.get("Origin", "")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Headers"] = "Authorization,Content-Type,X-Internal-Key"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    return resp