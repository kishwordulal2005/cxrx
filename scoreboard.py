"""VulnLab Scoreboard + CTF portal.

Run:  python scoreboard.py     ->  http://127.0.0.1:9090/ctf.html

Safety: binds 127.0.0.1 by default (VULNLAB_BIND to override on isolated labs).

Never exposes flags, answer keys or instructor data through its API:
only SHA-256 hashes of flags are held for verification.
"""
import csv
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import time

from flask import Flask, jsonify, request, send_from_directory

import config
import database

app = Flask(__name__, static_folder=config.STATIC_DIR, static_url_path="/static")


@app.after_request
def _never_stale(resp):
    """Students and the instructor both reload this portal mid-session; make
    sure the browser cannot hand back a frame from before the change."""
    if resp.mimetype == "text/html" or request.path.startswith("/static"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp

CHALLENGES = json.load(open(config.CHALLENGES_PATH))
CH_BY_ID = {c["id"]: c for c in CHALLENGES}

# Server-side verification material (hashes only)
FLAG_HASHES = {}
FLAG_PLAIN_LENGTH = {}
for _cid in CH_BY_ID:
    # A challenge may accept several equally correct answers (research
    # questions), so hold the full set of digests.
    _answers = [a for a in config.flag_answers(_cid) if a]
    FLAG_HASHES[_cid] = {
        hashlib.sha256(_a.encode()).hexdigest() for _a in _answers}
    FLAG_PLAIN_LENGTH[_cid] = max(len(_a) for _a in _answers) if _answers else 0

# Decoy / rabbit-hole strings: submitting them awards a badge but no points.

# Handles created by the verification suites.  They are real rows in the
# database, but a classroom leaderboard should only show students, and a
# half-finished run must never be visible to players.  config owns the
# prefix list so the public queries and reset_player_state() cannot drift.
BOT_HANDLE_PATTERNS = config.bot_handle_patterns()
# One NOT LIKE per known prefix, with a single bound parameter each.
BOT_NOT_BOT_CLAUSE = " AND ".join(
    "p.handle NOT LIKE ? ESCAPE '" + chr(92) + "'" for _ in BOT_HANDLE_PATTERNS
)


DECOYS = {
    "VULNLAB{fake_root_flag}",
    "VULNLAB{decoy_api_key}",
    "VULNLAB{admin_password_is_admin}",
    "VULNLAB{totally_real_secret}",
    "VULNLAB{this_is_not_the_flag}",
    "CVE-2099-0001",
}

# Gating: only the final boss and the Flask boss are locked (per design doc).
PREREQS = {
    "boot-02": {"all": ["linux-01"]},
    "flask-boss": {"any": ["flask-02", "flask-06", "flask-12"], "count": 2},
}

FIRST_BLOOD_PCT = 0.20
FIRST_BLOOD_CAP = 50
HINT_COST = {1: 0.10, 2: 0.20, 3: 0.30}
MODE_HINTS = {"BEGINNER": 3, "INTERMEDIATE": 3, "HARD": 2, "INSANE": 1}
SUBMIT_COOLDOWN = 3

ACHIEVEMENTS = [
    ("first_blood", "First Blood"),
    ("port_scanner", "Port Scanner"),
    ("ftp_hunter", "FTP Hunter"),
    ("telnet_survivor", "Telnet Survivor"),
    ("smb_explorer", "SMB Explorer"),
    ("api_hunter", "API Hunter"),
    ("jwt_breaker", "JWT Breaker"),
    ("cve_hunter", "CVE Hunter"),
    ("rabbit_hole_survivor", "Rabbit Hole Survivor"),
    ("root_access", "Root Access"),
    ("speed_demon", "Speed Demon"),
    ("no_hint_solver", "No-Hint Solver"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _db():
    return database.scoreboard_db()


def _player_by_token(token):
    if not token:
        return None
    c = _db()
    row = c.execute("SELECT * FROM players WHERE student_token=?", (token,)).fetchone()
    c.close()
    return row


def _solved_ids(player_id):
    c = _db()
    rows = c.execute("SELECT challenge_id FROM solves WHERE player_id=?", (player_id,)).fetchall()
    c.close()
    return {r["challenge_id"] for r in rows}


def _hints_used(player_id, cid):
    c = _db()
    rows = c.execute(
        "SELECT level FROM hints_used WHERE player_id=? AND challenge_id=?", (player_id, cid)
    ).fetchall()
    c.close()
    return {r["level"] for r in rows}


def _score_of(player_id):
    c = _db()
    row = c.execute("SELECT COALESCE(SUM(points),0) AS s FROM solves WHERE player_id=?", (player_id,)).fetchone()
    c.close()
    return int(row["s"])


def _rank_of(player_id):
    c = _db()
    rows = c.execute(
        "SELECT player_id, COALESCE(SUM(points),0) AS s FROM solves GROUP BY player_id ORDER BY s DESC, MIN(solved_at) ASC"
    ).fetchall()
    c.close()
    for i, r in enumerate(rows, 1):
        if r["player_id"] == player_id:
            return i
    return None


def _leaderboard_rows(limit=100):
    c = _db()
    rows = c.execute(
        """SELECT p.id, p.handle,
                  COALESCE(SUM(s.points),0) AS score,
                  COUNT(s.id) AS flags,
                  MAX(s.solved_at) AS last_solve
           FROM players p LEFT JOIN solves s ON s.player_id=p.id
           WHERE """ + BOT_NOT_BOT_CLAUSE + """
           GROUP BY p.id ORDER BY score DESC, MIN(s.solved_at) ASC LIMIT ?""",
        tuple(BOT_HANDLE_PATTERNS) + (limit,),
    ).fetchall()
    out = []
    for i, r in enumerate(rows, 1):
        out.append({
            "rank": i,
            "handle": r["handle"],
            "score": int(r["score"]),
            "flags": int(r["flags"]),
            "last_solve": (r["last_solve"] or "")[11:16] if r["last_solve"] else "",
        })
    c.close()
    return out


def _grant_achievement(c, player_id, key):
    try:
        c.execute("INSERT INTO achievements (player_id, key) VALUES (?,?)", (player_id, key))
        return True
    except Exception:
        return False


def _prereq_ok(cid, solved):
    rule = PREREQS.get(cid)
    if not rule:
        return True, None
    if "all" in rule:
        missing = [m for m in rule["all"] if m not in solved]
        if missing:
            return False, "Locked: requires '{}'".format("', '".join(missing))
    if "any" in rule:
        hits = len([x for x in rule["any"] if x in solved])
        if hits < rule["count"]:
            return False, "Locked: solve {} of {} Python RCE doors first".format(
                rule["count"], len(rule["any"]))
    return True, None


def _target_status():
    checks = {
        "web": config.PORT_WEB, "waf": config.PORT_WAF, "ftp": config.PORT_FTP,
        "telnet": config.PORT_TELNET, "ssh": config.PORT_SSH, "debug": config.PORT_DEBUG,
        "rabbit1": config.PORT_RABBIT1, "rabbit2": config.PORT_RABBIT2,
        "smb": config.PORT_SMB_SIM,
    }
    state = {}
    for name, port in checks.items():
        s = socket.socket()
        s.settimeout(0.25)
        try:
            s.connect((config.BIND_HOST if config.BIND_HOST != "0.0.0.0" else "127.0.0.1", port))
            state[name] = True
        except Exception:
            state[name] = False
        finally:
            s.close()
    return state


def _effective_points(cid, player_id):
    """Base points minus hint deductions for hints this player unlocked."""
    base = CH_BY_ID[cid]["points"]
    used = _hints_used(player_id, cid) if player_id else set()
    if config.DIFFICULTY == "BEGINNER":
        return base
    penalty = sum(HINT_COST.get(lv, 0) for lv in used)
    return max(int(round(base * (1 - penalty))), 10)


# ---------------------------------------------------------------------------
# Static portal
# ---------------------------------------------------------------------------
@app.route("/")
@app.route("/ctf.html")
def ctf():
    """Serve the portal with the LAN address baked in.

    Students reach this page over the Wi-Fi, so the address they have to type
    is the one thing the page should never have to guess.  Substituted here
    rather than in a template engine - it is a single placeholder.
    """
    with open(os.path.join(config.WEB_DIR, "ctf.html"),
              "r", encoding="utf-8") as fh:
        page = fh.read()
    page = (page.replace("{{LAN_IP}}", config.PUBLIC_IP)
                .replace("{{JOIN_URL}}", config.join_url("/ctf.html"))
                .replace("{{TARGET_URL}}",
                         "http://{}:{}".format(config.PUBLIC_IP, config.PORT_WEB)))
    return page


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
@app.route("/api/status")
def api_status():
    c = _db()
    n_players = c.execute("SELECT COUNT(*) AS n FROM players").fetchone()["n"]
    n_solves = c.execute("SELECT COUNT(*) AS n FROM solves").fetchone()["n"]
    c.close()
    return jsonify({
        "target": config.TARGET_HOST,
        "mode": config.DIFFICULTY,
        "difficulty": "HARD",
        "players": n_players,
        "flags_solved": n_solves,
        "flags_total": len(CHALLENGES),
        "services": _target_status(),
    })


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    handle = (data.get("handle") or "").strip()
    if not handle or len(handle) > 24:
        return jsonify({"error": "handle required (max 24 chars)"}), 400
    token = hashlib.sha256("{}:{}:{}".format(handle, time.time(), os.urandom(8).hex()).encode()).hexdigest()[:32]
    c = _db()
    try:
        c.execute(
            "INSERT INTO players (handle, student_token, last_ip) VALUES (?,?,?)",
            (handle, token, request.remote_addr or ""),
        )
        c.commit()
    except Exception:
        # The handle already exists, so this player is resuming rather than
        # registering: hand back a fresh token for the same player id so their
        # score, rank and badges survive a cleared browser.  Refusing here
        # locked anyone out of their own progress permanently.
        row = c.execute("SELECT id FROM players WHERE handle=?",
                        (handle,)).fetchone()
        if not row:
            c.close()
            return jsonify({"error": "could not register"}), 409
        c.execute("UPDATE players SET student_token=?, last_ip=? WHERE id=?",
                  (token, request.remote_addr or "", row["id"]))
        c.commit()
        c.close()
        return jsonify({"student_token": token, "handle": handle,
                        "resumed": True})
    row = c.execute("SELECT id FROM players WHERE student_token=?", (token,)).fetchone()
    _grant_achievement(c, row["id"], "registered")
    c.commit()
    c.close()
    return jsonify({"student_token": token, "handle": handle})


@app.route("/api/challenges")
def api_challenges():
    token = request.args.get("student_token", "")
    player = _player_by_token(token)
    solved = _solved_ids(player["id"]) if player else set()
    out = []
    for ch in CHALLENGES:
        used = _hints_used(player["id"], ch["id"]) if player else set()
        max_hints = MODE_HINTS[config.DIFFICULTY]
        locked, why = _prereq_ok(ch["id"], solved)
        entry = {
            "id": ch["id"],
            "name": ch["name"],
            "category": ch["category"],
            "difficulty": ch["difficulty"],
            "points": ch["points"],
            "effective_points": _effective_points(ch["id"], player["id"]) if player else ch["points"],
            "cwe": ch.get("cwe", ""),
            "cve": ch.get("cve", ""),
            "description": ch["description"],
            "solved": ch["id"] in solved,
            "locked": not locked,
            "lock_reason": why,
            "hints_released": sorted(used),
            "hints_available": max_hints,
        }
        # BEGINNER mode shows hint text up front (more guidance).
        if config.DIFFICULTY == "BEGINNER" and not player:
            entry["hints"] = ch["hints"]
        out.append(entry)
    return jsonify({"challenges": out, "mode": config.DIFFICULTY})


@app.route("/api/hint", methods=["POST"])
def api_hint():
    data = request.get_json(silent=True) or {}
    player = _player_by_token(data.get("student_token"))
    if not player:
        return jsonify({"error": "invalid student_token"}), 401
    cid = data.get("challenge_id", "")
    level = int(data.get("level", 0))
    ch = CH_BY_ID.get(cid)
    if not ch:
        return jsonify({"error": "unknown challenge"}), 404
    if level < 1 or level > 3:
        return jsonify({"error": "level must be 1..3"}), 400
    if level > MODE_HINTS[config.DIFFICULTY]:
        return jsonify({"error": "hints beyond level {} are disabled in {} mode".format(
            MODE_HINTS[config.DIFFICULTY], config.DIFFICULTY)}), 403
    c = _db()
    try:
        c.execute("INSERT INTO hints_used (player_id, challenge_id, level) VALUES (?,?,?)",
                  (player["id"], cid, level))
        c.commit()
    except Exception:
        pass  # already unlocked
    c.close()
    cost = 0 if config.DIFFICULTY == "BEGINNER" else int(ch["points"] * HINT_COST[level])
    return jsonify({
        "hint": ch["hints"][level - 1],
        "cost": cost,
        "effective_points": _effective_points(cid, player["id"]),
    })


@app.route("/api/submit", methods=["POST"])
def api_submit():
    data = request.get_json(silent=True) or {}
    player = _player_by_token(data.get("student_token"))
    if not player:
        return jsonify({"result": "error", "message": "invalid student_token"}), 401
    cid = data.get("challenge_id", "")
    submission = (data.get("flag") or "").strip()
    ch = CH_BY_ID.get(cid)
    if not ch:
        return jsonify({"result": "error", "message": "unknown challenge"}), 404

    c = _db()
    now = time.time()
    last = c.execute("SELECT last_submit FROM players WHERE id=?", (player["id"],)).fetchone()
    last_ts = 0
    if last and last["last_submit"]:
        try:
            row = c.execute(
                "SELECT strftime('%s', ?) AS t", (last["last_submit"],)).fetchone()
            last_ts = int(row["t"])
        except Exception:
            last_ts = 0
    if last_ts and now - last_ts < SUBMIT_COOLDOWN:
        c.close()
        return jsonify({
            "result": "cooldown",
            "message": "submission cooldown: wait {}s".format(int(SUBMIT_COOLDOWN - (now - last_ts))),
        }), 429

    c.execute("UPDATE players SET last_submit=datetime('now'), last_ip=? WHERE id=?",
              (request.remote_addr or "", player["id"]))

    def record(result):
        c.execute(
            "INSERT INTO submissions (player_id, challenge_id, submitted, result, ip) VALUES (?,?,?,?,?)",
            (player["id"], cid, submission[:80], result, request.remote_addr or ""),
        )
        c.commit()

    solved = _solved_ids(player["id"])

    if cid in solved:
        record("duplicate")
        c.close()
        return jsonify({"result": "duplicate", "message": "already solved - no double dipping"})

    if submission in DECOYS:
        new_badge = _grant_achievement(c, player["id"], "rabbit_hole_survivor")
        record("decoy")
        c.close()
        return jsonify({
            "result": "decoy",
            "message": "DECOY - rabbit hole. It teaches you something, but it is not the flag.",
            "achievement": "Rabbit Hole Survivor" if new_badge else None,
        })

    ok, why = _prereq_ok(cid, solved)
    if not ok:
        record("locked")
        c.close()
        return jsonify({"result": "locked", "message": why}), 403

    digest = hashlib.sha256(submission.encode()).hexdigest()
    if digest not in FLAG_HASHES.get(cid, ()):
        record("incorrect")
        c.close()
        return jsonify({"result": "incorrect", "message": "no match - no penalty"})

    # ---- correct ----
    first_blood = c.execute(
        "SELECT COUNT(*) AS n FROM solves WHERE challenge_id=?", (cid,)).fetchone()["n"] == 0
    points = _effective_points(cid, player["id"])
    bonus = 0
    if first_blood:
        bonus = min(int(ch["points"] * FIRST_BLOOD_PCT), FIRST_BLOOD_CAP)
    try:
        c.execute(
            "INSERT INTO solves (player_id, challenge_id, points, first_blood) VALUES (?,?,?,?)",
            (player["id"], cid, points + bonus, 1 if first_blood else 0),
        )
    except Exception:
        record("duplicate")
        c.close()
        return jsonify({"result": "duplicate", "message": "already solved"}), 409

    # achievements
    badges = []
    def A(key, label):
        if _grant_achievement(c, player["id"], key):
            badges.append(label)

    if first_blood:
        A("first_blood", "First Blood")
    cat = ch["category"]
    s = solved | {cid}
    if cat == "Recon":
        A("port_scanner", "Port Scanner")
    if s >= {"ftp-01", "ftp-02", "ftp-03", "ftp-04"}:
        A("ftp_hunter", "FTP Hunter")
    if s >= {"telnet-01", "telnet-02", "telnet-03", "telnet-04"}:
        A("telnet_survivor", "Telnet Survivor")
    if len([x for x in s if x.startswith("smb-")]) >= 3:
        A("smb_explorer", "SMB Explorer")
    if len([x for x in s if x.startswith("api-")]) >= 5:
        A("api_hunter", "API Hunter")
    if {"api-08", "api-09"} <= s:
        A("jwt_breaker", "JWT Breaker")
    if len([x for x in s if x.startswith("cve-") or x == "flask-13"]) >= 5:
        A("cve_hunter", "CVE Hunter")
    if cid == "boot-02":
        A("root_access", "Root Access")
    fast = c.execute(
        "SELECT (strftime('%s','now') - strftime('%s', (SELECT created_at FROM players WHERE id=?))) < 600 AS fast",
        (player["id"],)).fetchone()["fast"]
    if fast:
        A("speed_demon", "Speed Demon")
    if len(s) >= 5 and c.execute(
        "SELECT COUNT(*) AS n FROM hints_used WHERE player_id=?", (player["id"],)).fetchone()["n"] == 0:
        A("no_hint_solver", "No-Hint Solver")

    c.commit()
    c.close()

    new_total = _score_of(player["id"])
    new_rank = _rank_of(player["id"])
    return jsonify({
        "result": "correct",
        "message": "ACCESS GRANTED",
        "points": points + bonus,
        "base_points": points,
        "first_blood": first_blood,
        "first_blood_bonus": bonus,
        "new_total": new_total,
        "rank": new_rank,
        "category": cat,
        "challenge": ch["name"],
        "achievements": badges,
        "cwe": ch.get("cwe", ""),
    })


@app.route("/api/leaderboard")
def api_leaderboard():
    return jsonify({"leaderboard": _leaderboard_rows()})


@app.route("/api/feed")
def api_feed():
    """Recent solves: who solved what, and what it was worth.

    Backs the live activity feed on the CTF page.  Only handles, challenge
    ids and points are exposed - never the flags themselves.
    """
    c = _db()
    try:
        rows = c.execute(
            """SELECT p.handle, s.challenge_id, s.points, s.solved_at
               FROM solves s JOIN players p ON p.id = s.player_id
           WHERE """ + BOT_NOT_BOT_CLAUSE + """
               ORDER BY s.solved_at DESC, s.id DESC LIMIT ?""",
            tuple(BOT_HANDLE_PATTERNS) + (40,),
        ).fetchall()
    finally:
        c.close()
    out = []
    for r in rows:
        cid = r["challenge_id"]
        ch = CH_BY_ID.get(cid)
        out.append({
            "handle": r["handle"],
            "challenge_id": cid,
            "challenge": (ch["name"] if ch else cid),
            "category": (ch.get("category") if ch else ""),
            "points": int(r["points"]),
            "at": (r["solved_at"] or "")[11:19],
        })
    return jsonify({"feed": out, "server_time": time.strftime("%H:%M:%S")})


@app.route("/api/me")
def api_me():
    player = _player_by_token(request.args.get("student_token", ""))
    if not player:
        return jsonify({"error": "invalid student_token"}), 401
    c = _db()
    solves = c.execute(
        "SELECT challenge_id, points, first_blood, solved_at FROM solves"
        " WHERE player_id=? ORDER BY solved_at ASC",
        (player["id"],)).fetchall()
    badges = [r["key"] for r in c.execute(
        "SELECT key FROM achievements WHERE player_id=?", (player["id"],)).fetchall()]
    c.close()
    solved = {r["challenge_id"] for r in solves}
    graph = {}
    for cid in ["recon-01", "ftp-01", "smb-01", "telnet-01", "web-01", "api-01",
                "waf-01", "flask-01", "ssh-01", "linux-01", "boot-01", "boot-02"]:
        graph[cid] = "done" if cid in solved else ("locked" if not _prereq_ok(cid, solved)[0] else "todo")
    return jsonify({
        "handle": player["handle"],
        "score": _score_of(player["id"]),
        "rank": _rank_of(player["id"]),
        "flags": len(solved),
        "total_flags": len(CHALLENGES),
        "solved": sorted(solved),
        "achievements": badges,
        "all_achievements": [{"key": k, "name": n} for k, n in ACHIEVEMENTS],
        "graph": graph,
        "solves": [dict(r) for r in solves],
    })


# ---------------------------------------------------------------------------
# Instructor panel (never public: requires VULNLAB_INSTRUCTOR_KEY)
# ---------------------------------------------------------------------------
INSTRUCTOR_HTML = """<!doctype html><html><head><title>VulnLab Instructor</title>
<style>body{{background:#0a0e12;color:#9ef;font:14px monospace;padding:24px}}
table{{border-collapse:collapse}}td,th{{border:1px solid #234;padding:4px 10px}}
input,button{{background:#111;color:#0f8;border:1px solid #0f8;padding:6px;font:inherit}}
a{{color:#0fc}}</style></head><body>
<h1>VULNLAB - INSTRUCTOR PANEL</h1>
<form method=get><input name=key value="{key}"> <button>refresh</button></form>
{body}
<p><a href="/instructor?key={key}&action=export">export scores (csv)</a> |
<a href="/instructor?key={key}&action=reset_scoreboard">RESET SCOREBOARD</a> |
<a href="/instructor?key={key}&action=reset_lab">FULL LAB RESET (runs reset_lab.py)</a></p>
<p>Run reset any time: <code>python instructor/reset_lab.py</code></p>
</body></html>"""


@app.route("/instructor")
def instructor():
    key = request.args.get("key", "")
    if key != config.INSTRUCTOR_SECRET:
        return jsonify({"error": "missing or invalid instructor key"}), 403
    action = request.args.get("action", "")
    if action == "reset_scoreboard":
        c = _db()
        c.execute("DELETE FROM solves"); c.execute("DELETE FROM players")
        c.execute("DELETE FROM submissions"); c.execute("DELETE FROM hints_used")
        c.execute("DELETE FROM achievements")
        c.commit(); c.close()
    elif action == "reset_lab":
        subprocess.Popen([sys.executable, os.path.join(config.BASE_DIR, "instructor", "reset_lab.py")])
    elif action == "export":
        c = _db()
        rows = c.execute(
            "SELECT p.handle, COALESCE(SUM(s.points),0) score, COUNT(s.id) flags"
            " FROM players p LEFT JOIN solves s ON s.player_id=p.id GROUP BY p.id ORDER BY score DESC").fetchall()
        c.close()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["handle", "score", "flags"])
        for r in rows:
            w.writerow([r["handle"], r["score"], r["flags"]])
        resp = app.response_class(buf.getvalue(), mimetype="text/csv")
        resp.headers["Content-Disposition"] = "attachment; filename=scores.csv"
        return resp

    c = _db()
    players = c.execute(
        "SELECT p.handle, p.created_at, COALESCE(SUM(s.points),0) score, COUNT(s.id) flags"
        " FROM players p LEFT JOIN solves s ON s.player_id=p.id GROUP BY p.id ORDER BY score DESC").fetchall()
    recent = c.execute(
        "SELECT player_id, challenge_id, result, ip, at FROM submissions ORDER BY id DESC LIMIT 25").fetchall()
    c.close()
    body = ["<h2>Students ({})</h2><table><tr><th>handle</th><th>score</th><th>flags</th><th>joined</th></tr>".format(len(players))]
    for p in players:
        body.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            p["handle"], p["score"], p["flags"], p["created_at"]))
    body.append("</table><h2>Recent submissions</h2><table><tr><th>who</th><th>challenge</th><th>result</th><th>ip</th><th>at</th></tr>")
    for r in recent:
        body.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            r["player_id"], r["challenge_id"], r["result"], r["ip"], r["at"]))
    body.append("</table>")
    return INSTRUCTOR_HTML.format(key=key, body="\n".join(body))


if __name__ == "__main__":
    database.init_scoreboard()
    database.init_target()
    print("[scoreboard] http://{}:{}/ctf.html  (mode: {})".format(
        config.BIND_HOST, config.PORT_CTF, config.DIFFICULTY))
    app.run(host=config.BIND_HOST, port=config.PORT_CTF, threaded=True)
