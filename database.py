"""VulnLab database helpers.

Two databases live under ./data:

  * scoreboard.db  - handles, tokens, scores, hints, achievements (scoreboard.py)
  * users.db       - intentionally vulnerable target application data (app.py)

Neither database ever stores plaintext flags: the scoreboard stores SHA-256
hashes only, so flags cannot be recovered from a database dump.
"""
import os
import sqlite3
import threading

import config

_lock = threading.Lock()


def _conn(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = sqlite3.connect(path, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


# ---------------------------------------------------------------------------
# Scoreboard database
# ---------------------------------------------------------------------------
def scoreboard_db():
    return _conn(config.SCORE_DB_PATH)


def init_scoreboard():
    with _lock:
        c = scoreboard_db()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS players (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                handle TEXT UNIQUE NOT NULL,
                student_token TEXT UNIQUE NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                last_ip TEXT DEFAULT '',
                last_submit TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS solves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player_id INTEGER NOT NULL,
                challenge_id TEXT NOT NULL,
                points INTEGER NOT NULL,
                first_blood INTEGER DEFAULT 0,
                solved_at TEXT DEFAULT (datetime('now')),
                UNIQUE(player_id, challenge_id)
            );
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player_id INTEGER,
                challenge_id TEXT,
                submitted TEXT,
                result TEXT,
                ip TEXT,
                at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS hints_used (
                player_id INTEGER NOT NULL,
                challenge_id TEXT NOT NULL,
                level INTEGER NOT NULL,
                at TEXT DEFAULT (datetime('now')),
                UNIQUE(player_id, challenge_id, level)
            );
            CREATE TABLE IF NOT EXISTS achievements (
                player_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                at TEXT DEFAULT (datetime('now')),
                UNIQUE(player_id, key)
            );
            CREATE TABLE IF NOT EXISTS disabled_challenges (
                challenge_id TEXT PRIMARY KEY,
                disabled INTEGER DEFAULT 1
            );
            """
        )
        c.commit()
        c.close()


# ---------------------------------------------------------------------------
# Target application database (intentionally vulnerable data set)
# ---------------------------------------------------------------------------
def target_db():
    return _conn(config.DB_PATH)


def init_target():
    """Create the fake employee/user dataset used by the vulnerable API."""
    with _lock:
        c = target_db()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT,
                role TEXT,
                department TEXT,
                internal_id INTEGER,
                profile_id INTEGER,
                password_reset_hint TEXT,
                api_key_fragment TEXT,
                note TEXT,
                verified INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS search_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                body TEXT,
                secret INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS reset_tokens (
                username TEXT,
                token TEXT,
                used INTEGER DEFAULT 0
            );
            """
        )
        # The lab dataset is canonical: re-seed it on every start so a stale
        # database can never diverge from the notes/flags declared here.
        rows = [
            (1000, "student", "Student2019!", "student@vulnlab.test", "user",
             "Training", 1000, 1001, "first pet name", "VLfrag_0001",
             "{{FLAG:api-04}}", 1),
            (1001, "alice", "Wonderland1!", "alice@vulnlab.test", "user",
             "Engineering", 1001, 1002, "mother maiden name", "VLfrag_0002",
             "{{FLAG:api-02}} - also: engineering on-call rotation lives in the SMB engineering share", 1),
            (1002, "bob", "bob123", "bob@vulnlab.test", "user",
             "Support", 1002, 1003, "first school", "VLfrag_0003",
             "bob still uses the password from credentials.old", 1),
            (1003, "svc_web", "WebOld2019!", "svcweb@vulnlab.test", "service",
             "Web Tier", 1003, 1004, "n/a", "VLfrag_0004",
             "service account - password reused from an old FTP backup", 1),
            (1004, "svc_backup", "BackupSmb1!", "svcbackup@vulnlab.test", "service",
             "Backup Tier", 1004, 1005, "n/a", "VLfrag_0005",
             "service account - reachable over SSH and SMB", 1),
            (1005, "developer", "DevNotes2020!", "dev@vulnlab.test", "user",
             "Engineering", 1005, 1006, "project codename", "VLfrag_0006",
             "coupon RACE2020 still works in the shop - do not deploy", 1),
            (1006, "backup", "Winter2021!", "backup@vulnlab.test", "service",
             "Backup Tier", 1006, 1007, "n/a", "VLfrag_0007",
             "key-based login preferred; password disabled", 0),
            (1007, "old_employee", "Legacy2018!", "old.employee@vulnlab.test", "user",
             "Retired", 1007, 1008, "decoy - account disabled", "VLfrag_0008",
             "RABBIT HOLE: account disabled in 2019, password is a decoy", 0),
            (1008, "admin", "Admin!2019", "admin@vulnlab.test", "admin",
             "IT Operations", 1008, 1009,                 "hint: the backup zip has an old config; training account student / Student2019!", "VLfrag_0009", "{{FLAG:api-03}}", 1),
            (1009, "rootish", "root", "rootish@vulnlab.test", "user",
             "Security", 1009, 1010, "RABBIT HOLE: not a real root account", "VLfrag_0010",
             "decoy - web account named like root, no privileges", 1),
        ]
        c.executemany(
            "INSERT OR REPLACE INTO users (id, username, password, email, role, department,"
            " internal_id, profile_id, password_reset_hint, api_key_fragment, note, verified)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        c.execute("DELETE FROM reset_tokens")
        docs = [
            ("Welcome", "VulnLab Internal Portal - intranet search", 0),
            ("VPN Setup", "Connect with the standard corporate VPN client.", 0),
            ("Office Map", "Second floor, desks near the window.", 0),
            ("Onboarding", "New hires get an account in the training domain.", 0),
            ("Security Bulletin", "Rotate service account passwords quarterly.", 0),
            ("Buried Record", "{{FLAG:web-05}}", 1),
        ]
        c.execute("DELETE FROM search_index")
        c.executemany("INSERT INTO search_index (title, body, secret) VALUES (?,?,?)", docs)
        c.commit()
        c.close()
