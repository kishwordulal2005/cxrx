"""Build instructor/answer_key.md and instructor/scoring.md from the catalogs.

The answer key and the scoring tables are generated from flags/flags.json and
hints/challenges.json so they can never drift from what the scoreboard
actually accepts.

    python instructor/build_answer_key.py
"""
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

# Where the flag actually lives once a student has earned it.
LOCATION = {
    "recon-01": "HTTP response header X-Lab-First-Contact on http://127.0.0.1:5000/",
    "recon-02": "GET http://127.0.0.1:8081/services (hidden service catalogue)",
    "recon-03": "GET http://127.0.0.1:5050/diag/ports",
    "recon-04": "multi-line FTP 220 banner on :2121",
    "recon-05": "X-Lab-Flag header on /sitemap.xml",
    "ftp-01": "LIST after anonymous login on :2121",
    "ftp-02": "backup.zip in the FTP home directory",
    "ftp-03": "credentials.old -> svc_web -> SSH on :2222",
    "ftp-04": "CWD .backup then RETR ftp_history.log (hidden from LIST)",
    "telnet-01": "banner on :2323",
    "telnet-02": "admin / S3cureSwitch! (from FTP employee_notes.txt)",
    "telnet-03": "'show config' in the management console",
    "telnet-04": "300+ byte username crashes the console",
    "ssh-01": "any valid SSH login prints the MOTD flag",
    "ssh-02": "svc_backup / BackupSmb1! from the SMB backup share",
    "ssh-03": "'backup' account, key-only auth (id_rsa inside backup.zip)",
    "smb-01": "SMB session banner on :4450",
    "smb-02": "guest read of the public share",
    "smb-03": "svc_backup credentials -> backup share -> old_backup.txt",
    "smb-04": "engineering / EngBuild2020! (telnet show config) -> engineering share",
    "smb-05": "unadvertised dev$ share",
    "web-01": "/robots.txt -> /admin-old",
    "web-02": "HTML comment in the homepage source",
    "web-03": "/.git/logs/refs/heads/main",
    "web-04": "/config.bak",
    "web-05": "/search?q=' OR 1=1-- (secret=1 row)",
    "web-06": "/debug diagnostic block",
    "web-07": "/logs/app.log",
    "web-08": "/search?q=<script>alert(1)</script>",
    "api-01": "GET /api/v1/users -> meta.leak_note",
    "api-02": "GET /api/v1/profile/1002 (alice's note)",
    "api-03": "GET /api/v1/user?username=admin -> profile_id 1009 -> /profile/1009",
    "api-04": "GET /api/v1/profile/1001 (own profile's internal note)",
    "api-05": "/static/js/app.js -> VL_INTERNAL_KEY",
    "api-06": "GET /api/v1/admin/export with X-Internal-Key",
    "api-07": "PATCH /api/v1/profile {\"role\":\"admin\"}",
    "api-08": "crack the HS256 secret, read the lab_flag JWT claim",
    "api-09": "forge {\"alg\":\"none\"} token -> GET /api/v1/admin/status",
    "api-10": "md5('admin'+'1234') -> POST /api/v1/reset/confirm",
    "api-11": "/api/v1/fetch?url=http://127.0.0.1:5000/internal/secret",
    "api-12": "/api/v1/fetch?url=http://127.0.0.1:5000/internal/metadata",
    "api-13": "GET /api/v2/users or /api/internal/anything",
    "api-14": "brute-force 4 digits against /api/v1/otp/verify",
    "api-15": "GET /api/v1/cors-demo with an Origin header",
    "api-16": "POST /api/v1/user/export with any valid token",
    "api-17": "/api/v1/fuzz with x as an object -> unhandled path",
    "gql-01": "POST /graphql {__schema{types{name fields{name}}}}",
    "gql-02": "POST /graphql { leaked: internalSecret }",
    "gql-03": "POST /graphql with a batch of 9+ queries",
    "waf-01": "GET :5050/admin/ (trailing slash)",
    "waf-02": ":5050/internal-panel with X-Forwarded-For: 127.0.0.1",
    "waf-03": "POST :5050/admin/action",
    "waf-04": ":5050/api/query with the keyword as \\uXXXX escapes",
    "waf-05": ":5050/download?file=%252e%252e%252fsecret%252fflag.txt",
    "upload-01": "upload flag.pHp (mixed-case extension)",
    "upload-02": "upload a non-image body as image/png",
    "upload-03": "upload with filename ../cache/<key>.pkl",
    "upload-04": "upload an .svg, then GET /files/<name> and read the headers",
    "crypto-01": "/crypto/ecb?mode=ECB",
    "crypto-02": "/crypto/token, reproduce random.Random(seed), /crypto/token/claim",
    "crypto-03": "/crypto/token/issue-cbc, flip ct[0][4:8] with 07 1c 0a 06, /crypto/verify",
    "crypto-04": "sha256 length extension against /crypto/forge",
    "flask-01": "/profile?name={{7*7}}",
    "flask-02": "SSTI -> read <flagdir>/ssti.flag (/internal/config reveals flag_dir)",
    "flask-03": "/safe-profile -> reach <flagdir>/ssti_filter.flag",
    "flask-04": "http://127.0.0.1:8000/ carries the FLASK-04 comment",
    "flask-05": ":8000/debug-lab/info lists the attributes; PIN is 6-3 digits",
    "flask-06": ":8000/debug-lab/console with the PIN -> read debugger.flag",
    "flask-07": "/static/leaks/flask_settings.py -> SECRET_KEY",
    "flask-08": "forge the Flask session cookie with the leaked SECRET_KEY -> /admin",
    "flask-09": "GET /api/v1/cache/info -> serializer field",
    "flask-10": "/static/leaks/cache_backend.py -> FLASK-10 comment",
    "flask-11": "GET /api/v1/cache/stats -> cache_dir",
    "flask-12": "upload traversal writes data/cache/<key>.pkl, then /api/v1/cache/get",
    "flask-13": "research: the answer is the CVE id, not a VULNLAB flag",
    "flask-14": "pickle RCE reads <flagdir>/rce.flag and data/secrets/svc_flask.creds",
    "flask-boss": "solve any 2 of flask-02 / flask-06 / flask-12, then resubmit",
    "linux-01": "SSH -> cat /opt/vulnlab/README.local",
    "linux-02": "find / -perm -4000 -> /usr/local/share/vulnlab/suid.flag",
    "linux-03": "vulnhelper --read /root/suid.flag (SUID helper)",
    "linux-04": "sudo -l -> sudo /opt/vulnlab/maintenance.sh (world-writable cron script)",
    "linux-05": "plant /opt/vulnlab/bin/log-cleaner, then run lab-tick",
    "linux-06": "env -> VULNLAB_BACKUP_KEY -> vulnlab-decrypt /var/backups/creds.enc",
    "linux-07": "cat /etc/vulnlab/app.conf",
    "linux-08": "cat /etc/cron.d/vulnlab",
    "bonus-01": "cat /var/backups/.hidden",
    "bonus-02": "/static/js/app.js.map -> sourceMappingURL comment",
    "bonus-03": "FTP employee_notes.txt",
    "bonus-04": "cat /proc/self/environ -> VULNLAB_BONUS_ENV",
    "bonus-05": "X-Lab-Flag header on /debug-old",
    "bonus-06": "/private",
    "bonus-07": "/logs/app.log, the internal traceback line",
    "bonus-08": "/api/v1/cache/get?key=demo -> stale_payload",
    "boot-01": "SSH as svc_flask with the Flask-RCE credential -> MOTD",
    "boot-02": "root, then cat /root/root.txt (requires linux-01)",
    "cve-01": "answer is a CVE id from NVD, not a VULNLAB flag",
    "cve-02": "answer is a CVE id from NVD, not a VULNLAB flag",
    "cve-03": "answer is a CVE id from NVD, not a VULNLAB flag",
    "cve-04": "answer is a CVE id from NVD, not a VULNLAB flag",
    "cve-05": "answer is a CVE id from NVD, not a VULNLAB flag",
    "cve-06": "answer is a CVE id from NVD, not a VULNLAB flag",
    "cve-07": "answer is a CVE id from NVD, not a VULNLAB flag",
    "cve-08": "answer is a CVE id from NVD, not a VULNLAB flag",
    "cve-09": "answer is a CWE id, format CWE-NNN",
    "cve-10": "answer is a CWE id, format CWE-NNN",
    "biz-01": "POST /api/v1/shop/order {\"qty\":-1}",
    "biz-02": "concurrent POST /api/v1/redeem with the same coupon",
    "biz-03": "POST /api/v1/shop/order with price=1 for ROOT_ACCESS_TOKEN",
}

ATTACK_PATH = {
    "recon": "Route 0 - nmap / port scan / banner grabbing",
    "ftp": "Route 1a - FTP anonymous -> backup.zip -> credentials -> services",
    "web": "Route 1b - HTTP recon -> source leaks -> API -> session forge",
    "flask": "Route 1c - Flask RCE (SSTI / debugger / pickle) -> svc_flask -> SSH",
    "linux": "Final - SSH shell -> local enumeration -> privilege escalation -> root",
}

EXTRA = """
## Why the debugger PIN is stable

`config.compute_debug_pin()` builds the PIN from the fake identity attributes
in `config.DEBUG_PIN_MATERIAL` (username `vulnlab`, modname `flask.app`,
appname `VulnLabDebug`, filepath `/opt/vulnlab/debug-lab.py`, mac
`02:42:ac:11:00:02`, machine-id `vlabs0000000000000000000000000002`).

The material is joined with `:`, hashed with md5, each hex digit is reduced
mod 10, and the first nine digits are grouped 6-3.  Those attributes are the
published research inputs for Werkzeug debugger PIN generation
(`username`, `modname`, `appname`, `modname`'s file path, the network MAC and
`/etc/machine-id`), which is exactly what `:8000/debug-lab/info` exposes.

This is a lab stand-in, not the real algorithm: the real PIN also folds in
the cgroup id and the machine-id path.  Because the attributes are fixed, every
student computes the same value and the scoreboard's `computed:debug_pin`
answer always matches.

## The three independent initial-access routes

1. **Network / service route** - nmap finds 2121/2222/2323/4450/5000/5050/9090,
   anonymous FTP hands over `backup.zip`, `credentials.old` and
   `employee_notes.txt`, whose passwords are reused by the telnet console and
   SSH.
2. **Web / API route** - `robots.txt`, an HTML comment, `/.git/`, `/config.bak`
   and `/static/leaks/*` leak the weak Flask secret, the internal API key and
   the reset salt.  The weak secret forges a session and an admin token.
3. **Flask RCE route** - Jinja2 SSTI, the Werkzeug debugger console on :8000,
   or the pickle-backed cache give code execution, which reads
   `data/secrets/svc_flask.creds` and logs into SSH as `svc_flask`.

## The privilege-escalation routes

A. **SUID** - `find / -perm -4000` -> `/usr/local/bin/vulnhelper --read
   /root/suid.flag`.  (linux-02 -> linux-03)
B. **Writable cron script** - `sudo -l` reveals a NOPASSWD rule for
   `/opt/vulnlab/maintenance.sh`, which is world writable and run as root from
   `/etc/cron.d/vulnlab`.  (linux-08 -> linux-04)
C. **PATH hijack** - `/etc/cron.d/vulnlab` runs `lab-tick`, which resolves
   `log-cleaner` without an absolute path, and `/opt/vulnlab/bin` is on that
   job's PATH.  (linux-08 -> linux-05)

All three end at the same place, and `cat /root/root.txt` additionally
requires `linux-01` (the scoreboard enforces this as well as the shell).

## Safety

Every service binds 127.0.0.1 by default.  Set `VULNLAB_BIND=0.0.0.0` only on
an isolated classroom or CTF network, and never on a host reachable from the
Internet.  The SSH service never touches the real filesystem: it presents an
in-memory model of the machine, so no SUID bit, cron entry or root-owned file
is ever created on the host running VulnLab.
"""


def main():
    challenges = json.load(open(config.CHALLENGES_PATH, "r"))
    flags = config.load_flags()

    by_cat = defaultdict(list)
    for c in challenges:
        by_cat[c["category"]].append(c)

    # ---- answer key ----
    lines = [
        "# VulnLab instructor answer key",
        "",
        "Generated by `instructor/build_answer_key.py` from",
        "`flags/flags.json` and `hints/challenges.json` - do not edit by hand.",
        "",
        "%d challenges, %d flags, %d points." % (
            len(challenges), len(flags),
            sum(c.get("points", 0) for c in challenges)),
        "",
        "Submit answers at http://127.0.0.1:9090/ctf.html",
        "",
    ]
    for cat in sorted(by_cat):
        lines.append("## %s" % cat)
        lines.append("")
        lines.append("| id | challenge | CWE | pts | answer | where |")
        lines.append("| --- | --- | --- | ---: | --- | --- |")
        for c in sorted(by_cat[cat], key=lambda x: x["id"]):
            cid = c["id"]
            # Research questions can accept several answers; show them all so
            # an instructor knows what the scoreboard will mark correct.
            answers = config.flag_answers(cid)
            answer = " or ".join(answers) if answers else "(none)"
            loc = LOCATION.get(cid, "")
            lines.append("| `%s` | %s | %s | %d | `%s` | %s |" % (
                cid, c["name"], c.get("cwe", "-"), c.get("points", 0),
                answer, loc))
        lines.append("")
    lines.append(EXTRA.strip())
    lines.append("")
    lines.append("## Service credential sheet")
    lines.append("")
    lines.append("| service | account | password | source |")
    lines.append("| --- | --- | --- | --- |")
    for row in (
        ("portal login", "student", "Student2019!", "training account, admin hint"),
        ("API login", "admin", "Admin!2019", "api-10 predictable reset"),
        ("FTP", "anonymous", "any", "guest login"),
        ("telnet console", "admin", "S3cureSwitch!", "FTP employee_notes.txt"),
        ("telnet console", "root", "toor", "console guess"),
        ("SSH", "student", "Student2019!", "training account"),
        ("SSH", "svc_web", "WebOld2019!", "FTP backup.zip / credentials.old"),
        ("SSH", "svc_backup", "BackupSmb1!", "SMB backup share, telnet config"),
        ("SSH", "svc_flask", "VLsvc_flask_2019!", "Flask RCE -> data/secrets/"),
        ("SSH", "backup", "(key only)", "backup.zip contains id_rsa"),
        ("SMB", "engineering", "EngBuild2020!", "telnet show config"),
        ("admin API", "(header)", "VL_internal_9f3a7c2e_deadbeef_0001", "/static/leaks/app.js"),
        ("Flask secret", "(key)", "vulnlab-secret", "/config.bak, /static/leaks/"),
        ("JWT secret", "(key)", "vulnlab-jwt-secret", "/config.bak, /static/leaks/"),
        ("reset salt", "(value)", "1234", "flask_settings.py"),
        ("debug PIN", "(value)", config.compute_debug_pin(), ":8000/debug-lab/info"),
    ):
        lines.append("| {} | `{}` | `{}` | {} |".format(*row))
    lines.append("")
    key_path = os.path.join(HERE, "answer_key.md")
    with open(key_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print("wrote", key_path)

    # ---- scoring ----
    total_points = sum(c.get("points", 0) for c in challenges)
    diff = defaultdict(list)
    for c in challenges:
        diff[c.get("difficulty", "Medium")].append(c)
    cats = sorted(by_cat)

    s = [
        "# VulnLab scoring",
        "",
        "Generated by `instructor/build_answer_key.py`.",
        "",
        "## Model",
        "",
        "- Flags are stored as SHA-256 hashes only. A database dump never",
        "  reveals a flag, and submissions are compared in constant time.",
        "- A handle plus a browser token is all a student needs; no personal",
        "  data is collected.",
        "- Hint level 1 costs 10%, level 2 costs 20%, level 3 costs 30% of the",
        "  challenge points. Hints are per player and per level, so buying",
        "  level 1 twice is free but never refunds.",
        "- First blood awards +20%, capped at +50 points per challenge.",
        "- A 3 second cooldown sits between submissions.",
        "- Each handle gets the `Speed Demon` achievement for three solves in",
        "  under five minutes, and `Rabbit Hole Survivor` for submitting a",
        "  decoy flag.",
        "",
        "## Gating",
        "",
        "- `boot-02` (ROOT) unlocks only after `linux-01`, in both the",
        "  scoreboard and the simulated shell.",
        "- `flask-boss` unlocks after any 2 of `flask-02`, `flask-06`,",
        "  `flask-12` - the point is that three different primitives reach the",
        "  same Python runtime.",
        "",
        "## Totals",
        "",
        "| measure | value |",
        "| --- | ---: |",
        "| challenges | {} |".format(len(challenges)),
        "| flags | {} |".format(len(flags)),
        "| total points | {} |".format(total_points),
        "| categories | {} |".format(len(cats)),
        "",
        "## By difficulty",
        "",
        "| difficulty | challenges | points |",
        "| --- | ---: | ---: |",
    ]
    for d in ("Easy", "Medium", "Hard", "Expert"):
        if diff.get(d):
            s.append("| {} | {} | {} |".format(
                d, len(diff[d]), sum(c.get("points", 0) for c in diff[d])))
    s += ["", "## By category", "", "| category | challenges | points |",
          "| --- | ---: | ---: |"]
    for cat in cats:
        s.append("| {} | {} | {} |".format(
            cat, len(by_cat[cat]), sum(c.get("points", 0) for c in by_cat[cat])))
    s += ["", "## Routes", "", "| stage | challenges |", "| --- | --- |"]
    for name, text in ATTACK_PATH.items():
        s.append("| {} | {} |".format(text.split(" - ")[1], text.split(" - ")[0]))
    s += [
        "",
        "## Suggested thresholds",
        "",
        "| band | points | meaning |",
        "| --- | ---: | --- |",
        "| novice | 0 | found the scan, nothing exploited |",
        "| competent | %d | one full route to a user shell |" % round(total_points * 0.30),
        "| proficient | %d | user shell plus one privesc route |" % round(total_points * 0.55),
        "| advanced | %d | rooted, most of the API and Flask material |" % round(total_points * 0.80),
        "| complete | %d | everything except the research-only entries |" % total_points,
        "",
    ]
    scoring_path = os.path.join(HERE, "scoring.md")
    with open(scoring_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(s))
    print("wrote", scoring_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())