"""VulnLab reset tool - restore the lab to a known-good state.

    python instructor/reset_lab.py                 # reset lab data, keep scores
    python instructor/reset_lab.py --scores        # also wipe the scoreboard
    python instructor/reset_lab.py --uploads       # also clear uploads
    python instructor/reset_lab.py --cache         # also clear planted pickles
    python instructor/reset_lab.py --everything    # full clean slate
    python instructor/reset_lab.py --check         # report only, change nothing

What gets rebuilt:
  data/flagfiles/   the challenge flag files read by SSTI / debugger / pickle
  data/users.db     the fake employee directory
  data/backups/     backup.zip served over FTP
  data/smb/         the share trees
  data/secrets/     svc_flask credentials (the boot-01 chain)
  data/cache/       the pre-warmed cache entries
  static/leaks/     the developer source leaks

Scores live in data/scoreboard.db and are only touched with --scores.
"""
import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
import database  # noqa: E402

RESETTABLE_DIRS = ("uploads", "backups", "secrets", "cache", "smb", "flagfiles")


def log(msg):
    print("  " + msg)


def clear_dir(name):
    d = os.path.join(config.DATA_DIR, name)
    if os.path.isdir(d):
        shutil.rmtree(d, ignore_errors=True)
        return True
    return False


def clear_leaks():
    d = os.path.join(config.STATIC_DIR, "leaks")
    if os.path.isdir(d):
        shutil.rmtree(d, ignore_errors=True)
        return True
    return False


def wipe_scores():
    p = config.SCORE_DB_PATH
    if os.path.exists(p):
        os.remove(p)
        return True
    return False


def build(check_only=False):
    if check_only:
        log("check mode - nothing will be modified")
    for name in RESETTABLE_DIRS:
        if clear_dir(name):
            log("cleared data/{}".format(name))
    if clear_leaks():
        log("cleared static/leaks/")

    os.makedirs(config.DATA_DIR, exist_ok=True)
    database.init_scoreboard()
    log("scoreboard schema ready")
    database.init_target()
    log("users.db reseeded (10 accounts, 6 search documents)")

    import app as target_app
    flag_dir = target_app.bootstrap()
    log("flag files written to {}".format(flag_dir))
    log("backup archive, share trees, secrets and source leaks rebuilt")
    log("cache pre-warmed: {}".format(", ".join(sorted(
        __import__("api._common", fromlist=["x"]).APP_CACHE_KEYS))))


def status():
    print("=" * 64)
    print(" VulnLab state")
    print("=" * 64)
    for name in RESETTABLE_DIRS:
        d = os.path.join(config.DATA_DIR, name)
        n = len(os.listdir(d)) if os.path.isdir(d) else 0
        print("  data/{:<10} {:>4} item(s)".format(name, n))
    print("  data/users.db       {}".format(
        "present" if os.path.exists(config.DB_PATH) else "MISSING"))
    print("  data/scoreboard.db  {}".format(
        "present" if os.path.exists(config.SCORE_DB_PATH) else "MISSING"))
    fd = config._ensure_flag_dir()
    print("  flag dir            {}".format(fd))
    print("  flags registered    {}".format(len(config.load_flags())))
    try:
        challenges = __import__("json").load(open(config.CHALLENGES_PATH))
    except Exception:  # noqa: BLE001
        challenges = []
    print("  challenges          {}".format(len(challenges)))
    print("=" * 64)


def main():
    ap = argparse.ArgumentParser(description="Reset the VulnLab environment")
    ap.add_argument("--scores", action="store_true",
                    help="also wipe player scores and handles")
    ap.add_argument("--uploads", action="store_true",
                    help="clear student uploads")
    ap.add_argument("--cache", action="store_true",
                    help="clear cache entries (removes planted pickles)")
    ap.add_argument("--doors", action="store_true",
                    help="clear the FLASK-BOSS door tally")
    ap.add_argument("--everything", action="store_true",
                    help="uploads + cache + doors + scores")
    ap.add_argument("--check", action="store_true",
                    help="print state and exit without changing anything")
    args = ap.parse_args()

    print("=" * 64)
    print(" VulnLab reset")
    print("=" * 64)

    if args.check:
        status()
        return 0

    scores = args.scores or args.everything
    uploads = args.uploads or args.everything
    cache = args.cache or args.everything
    doors = args.doors or args.everything

    if scores and wipe_scores():
        log("scoreboard database removed")
    if uploads:
        clear_dir("uploads")
        log("uploads cleared")
    if cache:
        clear_dir("cache")
        log("cache cleared")
    if doors:
        # FLASK-BOSS door markers: a leftover tally would hand the boss flag
        # to the next cohort for free.
        clear_dir("doors")
        log("flask-boss door tally cleared")

    build()
    print("=" * 64)
    status()
    return 0


if __name__ == "__main__":
    sys.exit(main())