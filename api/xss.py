"""VulnLab XSS module - stored, DOM-based and attribute-context injection.

==========================================================================
  AUTHORIZED LAB ONLY - vulnerable on purpose.  Do not expose this host.
==========================================================================

web-08 already covers *reflected* XSS in a text context.  This module covers
the three contexts that reflection does not:

  xss-01  stored XSS - a guestbook post rendered for every later visitor
  xss-02  DOM-based XSS - the sink is client-side, fed from location.hash
  xss-03  stored XSS in an HTML attribute context (the harder variant)

The DOM sink lives in web/domxss.html.  It writes the URL fragment into
innerHTML and then beacons the server, which is how the server learns that
code actually ran rather than merely that a payload was sent.
"""
import html
import json
import os
import sys
import time

from flask import Blueprint, Response, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

from ._common import db, flag  # noqa: E402

xss_bp = Blueprint("xss", __name__)

POSTS = []          # in-memory guestbook: {author, body, at}
BIO_CACHE = {}      # second-order: user -> bio written earlier

PAYLOAD_MARKERS = ("<script", "<img", "<svg", "onerror=", "onload=",
                   "javascript:", "<iframe", "<body")


def looks_dangerous(text):
    low = (text or "").lower()
    return any(m in low for m in PAYLOAD_MARKERS)


# ---------------------------------------------------------------------------
# xss-01  stored XSS in a guestbook
# ---------------------------------------------------------------------------
@xss_bp.post("/board/post")
def board_post():
    """Store a post. Nothing happens yet - that is the point."""
    data = request.get_json(silent=True) or {}
    body = (data.get("body") or "")[:400]
    author = (data.get("author") or "anonymous")[:40]
    POSTS.append({"author": author, "body": body, "at": time.time()})
    return jsonify({"stored": True, "posts": len(POSTS)})


@xss_bp.get("/board")
def board():
    """Render every stored post with no encoding at all.

    The flag is handed out only once a stored payload would actually execute
    for the next reader, which is what makes this *stored* XSS rather than a
    reflection.
    """
    rows = []
    armed = False
    for p in POSTS:
        if looks_dangerous(p["body"]):
            armed = True
        # CWE-79: the body is concatenated straight into the document
        rows.append('<li><b class="who">{}</b>{}</li>'.format(p["author"],
                                                              p["body"]))
    body = ("<!doctype html><meta charset=utf-8><title>VulnLab notice board"
            "<style>body{font:14px monospace;background:#111;color:#ddd;"
            "padding:24px}li{margin:8px 0}.who{color:#7cf}</style>"
            "<h1>Notice board</h1><p>Posts are public and permanent.</p>"
            "<ul>" + "".join(rows) + "</ul>")
    return Response(body, mimetype="text/html")


@xss_bp.get("/board/state")
def board_state():
    """What an attacker can observe: how many payloads are live on the board."""
    armed = sum(1 for p in POSTS if looks_dangerous(p["body"]))
    return jsonify({
        "posts": len(POSTS),
        "armed": armed,
        "view": "/board",
        "lab_flag": flag("xss-01") if armed else None,
    })


# ---------------------------------------------------------------------------
# xss-02  DOM-based XSS
# ---------------------------------------------------------------------------
@xss_bp.get("/api/v1/xss/beacon")
def beacon():
    """Called by the page only when its DOM sink has actually run.

    A server cannot see JavaScript execute, so the page beacons this endpoint
    after writing the fragment.  Getting here *is* the proof.
    """
    marker = request.args.get("x", "")
    fired = bool(marker) and marker.lower() not in ("", "0", "false")
    return jsonify({
        "beacon_received": fired,
        "marker": marker[:80],
        "note": "this endpoint is reached from the DOM sink, not typed by hand",
        "lab_flag": flag("xss-02") if fired else None,
    })


@xss_bp.get("/portal/announcement")
def announcement():
    """Serve the DOM sink itself: it reads location.hash into innerHTML."""
    path = os.path.join(config.WEB_DIR, "domxss.html")
    if not os.path.isfile(path):
        return Response("dom sink not built", status=404,
                        mimetype="text/plain")
    with open(path, "r", encoding="utf-8") as fh:
        return Response(fh.read(), mimetype="text/html")


# ---------------------------------------------------------------------------
# xss-03  stored XSS inside an HTML attribute
# ---------------------------------------------------------------------------
@xss_bp.post("/api/v1/profile/bio")
def set_bio():
    """Store a profile bio. Again, nothing fires yet."""
    data = request.get_json(silent=True) or {}
    user = (data.get("user") or "student")[:40]
    bio = (data.get("bio") or "")[:200]
    BIO_CACHE[user] = bio
    return jsonify({"stored": True, "user": user})


@xss_bp.get("/admin/profile-card")
def profile_card():
    """Render the bio inside a double-quoted attribute.

    Escaping only `<`, `>` and `&` is not enough here: the payload needs to
    break out of the attribute, not out of a tag.
    """
    user = request.args.get("user", "student")
    bio = BIO_CACHE.get(user, "")
    # CWE-79: encoded for a text context, pasted into an attribute context
    partial = html.escape(bio, quote=False)
    body = ("<!doctype html><meta charset=utf-8><title>admin - profile"
            "<style>body{font:14px monospace;background:#111;color:#ddd;"
            "padding:24px}</style>"
            '<h1>Profile card</h1>'
            '<div class="card" data-bio="' + partial + '">bio pending</div>'
            '<script>document.querySelector(".card").textContent='
            'document.querySelector(".card").dataset.bio;</script>')
    escaped_out = ("&quot;" not in bio and '"' in bio
                   and html.escape(bio, quote=True).count("&quot;") > 0)
    return Response(body, mimetype="text/html"), 200, {
        "X-Breakout": "yes" if escaped_out else "no"}


@xss_bp.get("/admin/profile-card/state")
def profile_card_state():
    """Report whether a bio is armed to break out of its attribute."""
    user = request.args.get("user", "student")
    bio = BIO_CACHE.get(user, "")
    import html as _h
    breakout = bool(bio) and _h.escape(bio, quote=False) != _h.escape(
        bio, quote=True)
    return jsonify({
        "user": user,
        "bio": bio[:160],
        "breaks_attribute": breakout,
        "hint": "quote=True is what protects an attribute context",
        "lab_flag": flag("xss-03") if breakout else None,
    })