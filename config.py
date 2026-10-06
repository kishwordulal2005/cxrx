"""VulnLab central configuration.

SHARING MODEL: this lab is meant for a classroom.  Every service binds
0.0.0.0 by default so students on the same Wi-Fi/LAN can reach the portal
at http://<your-ip>:9090/ctf.html and register themselves.  Set

    VULNLAB_BIND=127.0.0.1   (solo practice, nothing shared)

The target is intentionally vulnerable, so only ever run it on a trusted
classroom network.  Never port-forward or expose this machine to the
public Internet.
"""
import json
import os
import pathlib
import socket
import time
import hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
BIND_HOST = os.environ.get("VULNLAB_BIND", "0.0.0.0")


def lan_ip():
    """This machine's address on the local network, for the join link.

    Picks the interface the OS would actually route through, so students are
    pointed at the Wi-Fi address rather than a VirtualBox/WSL adapter.
    Returns 127.0.0.1 when there is no route (offline or standalone).
    """
    override = os.environ.get("VULNLAB_IP")
    if override:
        return override
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packet is actually sent; this just asks the routing table which
        # local address would be used to leave the machine.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


PUBLIC_IP = lan_ip()

# Where the local tools should *dial*.  0.0.0.0 is a valid listen address but
# a poor destination, so checks connect to the real LAN address instead.
CONNECT_HOST = os.environ.get("VULNLAB_CONNECT", PUBLIC_IP)


def join_url(path="/", port=None):
    """The address a student should actually open."""
    return "http://{}:{}{}".format(PUBLIC_IP, port or PORT_CTF, path)


PORT_WEB = int(os.environ.get("VULNLAB_PORT_WEB", "5000"))       # Flask target
PORT_WAF = int(os.environ.get("VULNLAB_PORT_WAF", "5050"))       # WAF gate
PORT_CTF = int(os.environ.get("VULNLAB_PORT_CTF", "9090"))       # scoreboard
PORT_FTP = int(os.environ.get("VULNLAB_PORT_FTP", "2121"))
PORT_TELNET = int(os.environ.get("VULNLAB_PORT_TELNET", "2323"))
PORT_SSH = int(os.environ.get("VULNLAB_PORT_SSH", "2222"))
PORT_SMB = int(os.environ.get("VULNLAB_PORT_SMB", "445"))       # real port; sim falls back
PORT_SMB_SIM = int(os.environ.get("VULNLAB_PORT_SMB_SIM", "4450"))  # portable sim default
PORT_DEBUG = int(os.environ.get("VULNLAB_PORT_DEBUG", "8000"))   # debug-lab
PORT_RABBIT1 = int(os.environ.get("VULNLAB_PORT_R1", "6379"))    # rabbit hole
PORT_RABBIT2 = int(os.environ.get("VULNLAB_PORT_R2", "8081"))    # hidden svc

TARGET_HOST = os.environ.get("VULNLAB_TARGET", PUBLIC_IP)

PORT_WEB = int(os.environ.get("VULNLAB_PORT_WEB", "5000"))       # Flask target
PORT_WAF = int(os.environ.get("VULNLAB_PORT_WAF", "5050"))       # WAF gate
PORT_CTF = int(os.environ.get("VULNLAB_PORT_CTF", "9090"))       # scoreboard
PORT_FTP = int(os.environ.get("VULNLAB_PORT_FTP", "2121"))
PORT_TELNET = int(os.environ.get("VULNLAB_PORT_TELNET", "2323"))
PORT_SSH = int(os.environ.get("VULNLAB_PORT_SSH", "2222"))
PORT_SMB = int(os.environ.get("VULNLAB_PORT_SMB", "445"))       # real port; sim falls back
PORT_SMB_SIM = int(os.environ.get("VULNLAB_PORT_SMB_SIM", "4450"))  # portable sim default
PORT_DEBUG = int(os.environ.get("VULNLAB_PORT_DEBUG", "8000"))   # debug-lab
PORT_RABBIT1 = int(os.environ.get("VULNLAB_PORT_R1", "6379"))    # rabbit hole
PORT_RABBIT2 = int(os.environ.get("VULNLAB_PORT_R2", "8081"))    # hidden svc

TARGET_HOST = os.environ.get("VULNLAB_TARGET", PUBLIC_IP)

# ---------------------------------------------------------------------------
# Modes / secrets  (all values below are FAKE lab values, never real secrets)
# ---------------------------------------------------------------------------
DIFFICULTY = os.environ.get("VULNLAB_MODE", "INTERMEDIATE").upper()
if DIFFICULTY not in ("BEGINNER", "INTERMEDIATE", "HARD", "INSANE"):
    DIFFICULTY = "INTERMEDIATE"

INSTRUCTOR_SECRET = os.environ.get("VULNLAB_INSTRUCTOR_KEY", "vl-instructor-9090")
WEB_SECRET_KEY = os.environ.get("VULNLAB_WEB_SECRET", "vulnlab-secret")  # FLASK-07: intentionally weak FAKE secret
JWT_SECRET = os.environ.get("VULNLAB_JWT_SECRET", "vulnlab-jwt-secret")  # intentionally weak FAKE secret

# Intentionally weak fake API key (leaked in static/js/app.js)
INTERNAL_API_KEY = "VL_internal_9f3a7c2e_deadbeef_0001"

# crypto-04: the token oracle signs sha256(secret || message).  A secret-prefix
# MAC is the shape that makes length extension possible (CWE-354).
MAC_SECRET = b"vulnlab-mac-secret-2019"
MAC_MESSAGE = b"msg=user=alice&role=user"

# Fake debugger identity attributes (FLASK-05 research uses these)
DEBUG_PIN_MATERIAL = {
    "username": "vulnlab",
    "modname": "flask.app",
    "appname": "VulnLabDebug",
    "filepath": "/opt/vulnlab/debug-lab.py",
    "mac": "02:42:ac:11:00:02",
    "machine_id": "vlabs0000000000000000000000000002",
}

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
WEB_DIR = os.path.join(BASE_DIR, "web")
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
SECRETS_DIR = os.path.join(DATA_DIR, "secrets")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
# FLASK-BOSS tracks which of the three Python-RCE doors have been opened.
# Every lab process has to agree on the tally, and the debug lab runs in a
# different process from app.py, so it lives on disk.
DOORS_DIR = os.path.join(DATA_DIR, "doors")
LAB_KEY_PATH = os.path.join(DATA_DIR, ".lab_id_rsa")
_LAB_KEY_CACHE = None
FLASK_DOORS = ["flask-02", "flask-06", "flask-12"]


def lab_private_key():
    """The one RSA key the lab uses for key-only SSH auth (ssh-03).

    Generated once and cached on disk.  The copy inside backup.zip has to be
    the *same* key the SSH service accepts, so both sides read this instead of
    each inventing their own.  paramiko's writer emits text while its reader
    wants bytes, so the round-trip goes through a temporary file.
    """
    global _LAB_KEY_CACHE
    if _LAB_KEY_CACHE is not None:
        return _LAB_KEY_CACHE
    os.makedirs(SECRETS_DIR, exist_ok=True)
    if os.path.isfile(LAB_KEY_PATH):
        with open(LAB_KEY_PATH, "r", encoding="utf-8") as fh:
            _LAB_KEY_CACHE = fh.read()
            return _LAB_KEY_CACHE
    from paramiko import RSAKey
    key = RSAKey.generate(2048)
    tmp = "{}.{}.tmp".format(LAB_KEY_PATH, os.getpid())
    # paramiko 5 writes text through f.write(), so it needs a real text-mode
    # handle - not a path and not a StringIO.
    with open(tmp, "w", encoding="utf-8") as fh:
        key.write_private_key(fh)
    try:
        # Claim the path atomically.  app.py and the SSH service start at the
        # same time and both ask for the key; the claim fails if another
        # process won the race, so every process converges on the same
        # material.  os.link is atomic but is not available everywhere
        # (some filesystems, some Windows configurations), so fall back to
        # O_CREAT|O_EXCL, which is the same guarantee.
        try:
            os.link(tmp, LAB_KEY_PATH)
        except (AttributeError, NotImplementedError, OSError):
            try:
                fd = os.open(LAB_KEY_PATH,
                             os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "w", encoding="utf-8") as win:
                    with open(tmp, "r", encoding="utf-8") as rfh:
                        win.write(rfh.read())
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    with open(LAB_KEY_PATH, "r", encoding="utf-8") as fh:
        _LAB_KEY_CACHE = fh.read()
    return _LAB_KEY_CACHE


# ---------------------------------------------------------------------------
# Automated verification players
# ---------------------------------------------------------------------------
# The verification suites register players and solve challenges, so they are
# real rows in the score database.  A classroom leaderboard should only ever
# show people, and a half-finished run must never look like a busy class.
# Both the public queries and the reset teardown read this list, so a bot
# cannot surface on the board under any name listed here.
BOT_HANDLE_PREFIXES = ("verifier_", "verify_")

_BACKSLASH = chr(92)


def bot_handle_patterns():
    """LIKE patterns matching automated players, already escaped.

    ``_`` is a wildcard inside LIKE, so it has to be escaped or ``verify_``
    would also match unrelated handles such as ``verifyX_``.
    """
    return [
        prefix.replace("_", _BACKSLASH + "_") + "%"
        for prefix in BOT_HANDLE_PREFIXES
    ]


XXE_PROBE_MARKER = "VULNLAB-XXE-PROBE-8f2c1d"
XXE_PROBE_FILE = "xxe_probe.txt"


def xxe_probe_file():
    """A real file the XXE challenge can be pointed at, on any platform.

    Earlier revisions used C:/Windows/win.ini, which only exists on Windows
    and would make the check unverifiable anywhere else.  The lab now plants
    its own probe with a known marker, so the check is deterministic and
    portable - and it asserts on the marker rather than on the absence of an
    error.
    """
    path = os.path.join(DATA_DIR, XXE_PROBE_FILE)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            # The import endpoint tells a filesystem read from request text by
            # looking for a newline or a bracketed section, so the probe has to
            # look like a real ini file - and keep an INTERNAL newline, since
            # the response strips leading/trailing whitespace.
            fh.write("[lab-probe]\n" + XXE_PROBE_MARKER + "\n")
    except OSError:
        return None
    return path


def xxe_probe_uri():
    """file:// URI for the probe, or None if it cannot be planted."""
    path = xxe_probe_file()
    if not path:
        return None
    try:
        return pathlib.Path(path).resolve().as_uri()
    except (ValueError, OSError):
        return None


def remove_player(handle):
    """Delete one player and everything they earned.  Returns True if gone.

    Useful for a mistaken registration, and for verification runs that need a
    human-looking control player that must not linger on the board.  Child
    tables are discovered from the schema rather than hardcoded.
    """
    import sqlite3
    if not os.path.isfile(SCORE_DB_PATH):
        return False
    try:
        con = sqlite3.connect(SCORE_DB_PATH)
        rows = con.execute(
            "SELECT id FROM players WHERE handle = ?", (handle,)
        ).fetchall()
        if not rows:
            con.close()
            return False
        children = []
        for (name,) in con.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ):
            cols = [r[1] for r in con.execute("PRAGMA table_info(" + name + ")")]
            if "player_id" in cols:
                children.append(name)
        for (pid,) in rows:
            for name in children:
                con.execute("DELETE FROM " + name + " WHERE player_id=?", (pid,))
            con.execute("DELETE FROM players WHERE id=?", (pid,))
        con.commit()
        con.close()
        return True
    except sqlite3.Error:
        return False


def reset_player_state():
    """Remove the artefacts a verification run plants, for all tools to share.

    The suites deliberately open the FLASK-BOSS doors, upload files and drop a
    pickle into the cache in order to prove those paths work.  Left behind,
    they hand the next player a pre-solved boss and a named exploit artefact,
    so every tool that runs an exploit clears up after itself.  Leaderboard
    scores are kept on purpose - they are evidence - use
    `instructor/reset_lab.py --scores` to drop those.
    """
    import shutil
    removed = []
    if os.path.isdir(DOORS_DIR):
        shutil.rmtree(DOORS_DIR, ignore_errors=True)
        removed.append("flask-boss doors")
    if os.path.isdir(UPLOAD_DIR):
        for name in os.listdir(UPLOAD_DIR):
            target = os.path.join(UPLOAD_DIR, name)
            if os.path.isfile(target):
                os.remove(target)
        removed.append("uploads")
    # Verification runs register bot players; leaving them behind fills the
    # leaderboard with machine rows and inflates the player count.
    import sqlite3
    if os.path.isfile(SCORE_DB_PATH):
        try:
            con = sqlite3.connect(SCORE_DB_PATH)
            where = " OR ".join(
                "handle LIKE ? ESCAPE '" + _BACKSLASH + "'"
                for _ in BOT_HANDLE_PREFIXES
            )
            rows = con.execute(
                "SELECT id FROM players WHERE " + where, bot_handle_patterns()
            ).fetchall()
            # Ask the schema which tables reference a player instead of naming
            # them: a typo here used to raise, and the swallowed exception left
            # the whole cleanup uncommitted while looking like it had worked.
            children = []
            for (name,) in con.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ):
                cols = [r[1] for r in con.execute("PRAGMA table_info(" + name + ")")]
                if "player_id" in cols:
                    children.append(name)
            for (pid,) in rows:
                for name in children:
                    con.execute(
                        "DELETE FROM " + name + " WHERE player_id=?", (pid,)
                    )
                con.execute("DELETE FROM players WHERE id=?", (pid,))
            con.commit()
            con.close()
            if rows:
                removed.append("{} verifier player(s)".format(len(rows)))
        except sqlite3.Error:
            pass

    seeds = {"demo", "session%3Asvc_web", "rate%3Aotp"}
    if os.path.isdir(CACHE_DIR):
        for name in os.listdir(CACHE_DIR):
            path = os.path.join(CACHE_DIR, name)
            if os.path.isfile(path) and name[:-4] not in seeds:
                os.remove(path)
                removed.append("planted cache:{}".format(name[:-4]))
    return removed


def mark_door(challenge_id):
    """Record that a Flask RCE door was opened by a successful exploit."""
    try:
        os.makedirs(DOORS_DIR, exist_ok=True)
        with open(os.path.join(DOORS_DIR, "{}.door".format(challenge_id)),
                  "w", encoding="utf-8") as fh:
            fh.write("{}\n".format(int(time.time())))
    except OSError:
        pass


def doors_opened():
    """Which FLASK-BOSS doors are open, in canonical order."""
    try:
        have = {n[:-5] for n in os.listdir(DOORS_DIR) if n.endswith(".door")}
    except OSError:
        have = set()
    return [d for d in FLASK_DOORS if d in have]
SMB_DIR = os.path.join(DATA_DIR, "smb")
DB_PATH = os.path.join(DATA_DIR, "users.db")            # target web app DB
SCORE_DB_PATH = os.path.join(DATA_DIR, "scoreboard.db")  # scoreboard DB
FLAGS_PATH = os.path.join(BASE_DIR, "flags", "flags.json")
CHALLENGES_PATH = os.path.join(BASE_DIR, "hints", "challenges.json")

# Flag files read by SSTI / debugger / pickle challenges.
# Tries /opt/vulnlab/flags (lab VM), falls back to ./data/flagfiles.
_flag_candidates = [
    os.environ.get("VULNLAB_FLAG_DIR", ""),
]
if os.name != "nt":
    # On a real lab VM the flags live in the Linux root filesystem.
    _flag_candidates.append("/opt/vulnlab/flags")
_flag_candidates.append(os.path.join(DATA_DIR, "flagfiles"))
FLAG_DIR = None


def _ensure_flag_dir():
    global FLAG_DIR
    for p in _flag_candidates:
        if not p:
            continue
        try:
            os.makedirs(p, exist_ok=True)
            probe = os.path.join(p, ".probe")
            with open(probe, "w") as fh:
                fh.write("ok")
            os.remove(probe)
            FLAG_DIR = p
            return p
        except OSError:
            continue
    FLAG_DIR = os.path.join(DATA_DIR, "flagfiles")
    os.makedirs(FLAG_DIR, exist_ok=True)
    return FLAG_DIR


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
_FLAG_MAP = None


def load_flags():
    global _FLAG_MAP
    if _FLAG_MAP is None:
        with open(FLAGS_PATH, "r") as fh:
            _FLAG_MAP = json.load(fh)
    return _FLAG_MAP


def get_flag(challenge_id):
    """Return the flag/answer string for a challenge (server-side only).

    A value may also be a list of equally correct answers (see
    flag_answers) - in that case the primary/first entry is returned so every
    caller that expects a plain string keeps working.
    """
    raw = load_flags().get(challenge_id)
    if isinstance(raw, list):
        return raw[0] if raw else None
    return raw


def flag_answers(challenge_id):
    """Every answer the grader will accept for a challenge.

    Most challenges have exactly one.  Research questions ("identify the CVE")
    can legitimately have several - CVE-2015-3306 and CVE-2019-12815 are both
    real ProFTPD mod_copy arbitrary-file-copy bugs - so flags.json may list
    them all and the scoreboard hashes each one.
    """
    raw = load_flags().get(challenge_id)
    if raw is None:
        return []
    if isinstance(raw, list):
        return [_resolve_raw(r) for r in raw if isinstance(r, str)]
    return [_resolve_raw(raw)]


def resolve_flag(challenge_id):
    """Resolve entries that are computed rather than static."""
    raw = get_flag(challenge_id)
    if raw is None:
        return None
    return _resolve_raw(raw)


def _resolve_raw(raw):
    """Expand a 'computed:...' marker to the value it stands for."""
    if raw == "computed:debug_pin":
        return compute_debug_pin()
    return raw


def compute_debug_pin():
    """Deterministic lab debugger PIN derived from the fake machine identity.

    (Educational stand-in for public research on Werkzeug debugger PIN
    generation - see instructor/answer_key.md.  Uses fixed fake attributes so
    the PIN is stable and verifiable.)
    """
    m = DEBUG_PIN_MATERIAL
    material = "{}:{}:{}:{}:{}:{}".format(
        m["username"], m["modname"], m["appname"], m["filepath"], m["mac"], m["machine_id"]
    )
    digest = hashlib.md5(material.encode()).hexdigest()
    # 9 digits, grouped 6-3 like real debugger PINs
    digits = "".join(str(int(c, 16) % 10) for c in digest)[:9]
    return "{}-{}".format(digits[:6], digits[6:])


def hash_flag(flag):
    return hashlib.sha256(flag.encode()).hexdigest()


# Flag files consumed by the SSTI / debugger / pickle challenge chains.
FLAG_FILES = {
    "ssti.flag": "flask-02",
    "ssti_filter.flag": "flask-03",
    "debugger.flag": "flask-06",
    "cache.flag": "flask-12",
    "rce.flag": "flask-14",
}


def write_flag_files():
    d = _ensure_flag_dir()
    for name, cid in FLAG_FILES.items():
        with open(os.path.join(d, name), "w") as fh:
            fh.write(str(resolve_flag(cid)) + "\n")
    return d


def render_placeholders(text):
    """Replace {{FLAG:challenge-id}} placeholders with real flag strings."""
    import re
    def _sub(m):
        return resolve_flag(m.group(1)) or m.group(0)
    return re.sub(r"\{\{FLAG:([a-z0-9\-]+)\}\}", _sub, text or "")
