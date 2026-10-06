"""File upload / retrieval and SSRF endpoints.

INTENTIONALLY VULNERABLE - AUTHORIZED LAB ONLY.

  CWE-434  case-sensitive extension denylist              (upload-01)
  CWE-434  trusts client-supplied Content-Type             (upload-02)
  CWE-22   unsanitised filename join (path traversal)      (upload-03)
  CWE-434  uploads served inline with their own type       (upload-04)
  CWE-918  server-side fetch to an arbitrary URL           (api-11, api-12)
"""
import os
import urllib.error
import urllib.request

from flask import Blueprint, jsonify, request, send_from_directory

import config
from api._common import flag

files_bp = Blueprint("api_files", __name__)

DENYLIST = [".php", ".phtml", ".sh", ".exe", ".asp", ".aspx", ".jsp"]


@files_bp.post("/upload")
@files_bp.post("/api/v1/upload")
def upload():
    """Four independent upload flaws in one handler."""
    if "file" not in request.files:
        return jsonify({"error": "no file part"}), 400
    fh = request.files["file"]
    filename = fh.filename or "unnamed"
    ext = os.path.splitext(filename)[1].lower()

    # CWE-434 #1: the denylist is compared in lower case but the *original*
    # name is kept, so .pHp / .PHP variants slip through.
    blocked = ext in DENYLIST

    # CWE-434 #2: the declared Content-Type is trusted for storage metadata.
    declared = fh.content_type or "application/octet-stream"

    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    # CWE-22: filename is joined without sanitising ../ sequences.
    dest = os.path.join(config.UPLOAD_DIR, filename)
    try:
        fh.save(dest)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": "save failed: {}".format(exc)}), 500

    # upload-01: mixed-case extension bypasses the denylist.
    real_ext = os.path.splitext(filename)[1]
    mixed_case = ext in DENYLIST and real_ext != ext
    lab_flag = None
    if mixed_case:
        lab_flag = flag("upload-01")

    # upload-03: traversal wrote outside the upload directory.
    outside = not os.path.abspath(dest).startswith(
        os.path.abspath(config.UPLOAD_DIR) + os.sep)
    if outside and lab_flag is None:
        lab_flag = flag("upload-03")

    # upload-02: the declared Content-Type is believed without inspecting the
    # bytes, so a non-image body sails through as image/png.
    if declared.startswith("image/") and lab_flag is None:
        with open(dest, "rb") as fh:
            head = fh.read(64)
        real_image = (head.startswith(b"\x89PNG\r\n\x1a\n")
                      or head.startswith(b"\xff\xd8\xff")
                      or head.startswith(b"GIF87a") or head.startswith(b"GIF89a")
                      or head.lstrip()[:5] == b"<?xml")
        if not real_image:
            # Markup documents are the upload-04 track (stored XSS), not the
            # content-type track, so leave them alone here.
            if real_ext not in (".svg", ".html", ".htm"):
                lab_flag = flag("upload-02")

    # upload-04: html/svg served back inline.
    if real_ext in (".html", ".htm", ".svg") and lab_flag is None:
        lab_flag = flag("upload-04")

    resp = {
        "stored": True,
        "filename": filename,
        "extension": real_ext,
        "declared_content_type": declared,
        "blocked_by_denylist": blocked,
        "bytes": os.path.getsize(dest) if os.path.exists(dest) else 0,
        "serve_url": "/files/" + filename.lstrip("/"),
    }
    if outside:
        resp["traversal"] = "wrote outside the upload directory"
        resp["resolved_path"] = os.path.abspath(dest)
    if lab_flag:
        resp["lab_flag"] = lab_flag
    return jsonify(resp)


@files_bp.get("/files/<path:name>")
def serve_upload(name):
    """CWE-434: stored files are returned inline with their stored type, so an
    uploaded .svg or .html executes in the origin of this host."""
    for base in (config.UPLOAD_DIR,):
        candidate = os.path.join(base, name)
        if os.path.isfile(candidate):
            resp = send_from_directory(base, name, as_attachment=False)
            resp.headers["Content-Disposition"] = "inline"
            resp.headers["X-Upload-Served-Inline"] = "true"
            return resp
    return jsonify({"error": "not found", "name": name}), 404


# ---------------------------------------------------------------------------
# api-11 / api-12  SSRF   (CWE-918)
# ---------------------------------------------------------------------------
@files_bp.get("/api/v1/fetch")
def fetch_url():
    """VULNERABILITY (CWE-918): the URL-preview helper fetches whatever it is
    given from the server side.  Loopback is reachable, which is exactly the
    point of the challenge."""
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url required"}), 400
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "only http/https"}), 400
    try:
        with urllib.request.urlopen(url, timeout=4) as r:
            body = r.read(20000).decode("utf-8", "replace")
            status = r.status
            ctype = r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        body = e.read(2000).decode("utf-8", "replace")
        status, ctype = e.code, e.headers.get("Content-Type", "")
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": "fetch failed: {}".format(exc), "url": url}), 502

    out = {"url": url, "status": status, "content_type": ctype, "body": body}

    # Internal-only targets award their flag when fetched from the server side.
    if "/internal/secret" in url:
        out["lab_flag"] = flag("api-11")
        out["note"] = "server-side request reached a loopback-only endpoint"
    if "/internal/metadata" in url:
        out["lab_flag"] = flag("api-12")
        out["note"] = "fake cloud metadata reached through the fetch endpoint"
    return jsonify(out)