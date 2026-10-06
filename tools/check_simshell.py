"""Offline smoke test for the simulated VulnLab SSH shell.

Runs the command handlers directly, without opening a socket, so the
enumeration and privilege-escalation chains can be checked fast.

    python tools/check_simshell.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

SRC = os.path.join(config.BASE_DIR, "services", "ssh_service.py")


def load():
    ns = {"__name__": "ssh_sim", "__file__": SRC}
    with open(SRC, "r", encoding="utf-8") as fh:
        exec(compile(fh.read(), SRC, "exec"), ns)
    return ns


def show(title, value, keep=None):
    print("--- {}".format(title))
    lines = value.splitlines() if isinstance(value, str) else list(value)
    for ln in (lines[-keep:] if keep else lines):
        print("   " + ln)


def main():
    ns = load()
    SimShell = ns["SimShell"]

    print("=" * 60)
    print(" enumeration (linux-01/02/07/08, bonus-01/04)")
    print("=" * 60)
    sh = SimShell("student")
    show("id", sh.run("id"))
    show("sudo -l", sh.run("sudo -l"), keep=3)
    show("README.local", sh.run("cat /opt/vulnlab/README.local"))
    show("root before escalation", sh.run("cat /root/root.txt"))
    show("find suid", sh.run("find / -perm -4000"))
    show("cron", sh.run("cat /etc/cron.d/vulnlab"), keep=2)
    show("env", [l for l in sh.run("env").splitlines() if "BONUS" in l])
    show("bonus-01", sh.run("cat /var/backups/.hidden"))
    show("linux-07", sh.run("cat /etc/vulnlab/app.conf"), keep=1)
    show("linux-06 decrypt", sh.run("vulnlab-decrypt /var/backups/creds.enc"), keep=1)

    print("=" * 60)
    print(" route A - SUID (linux-02 -> linux-03)")
    print("=" * 60)
    show("suid.flag", sh.run("cat /usr/local/share/vulnlab/suid.flag"))
    show("vulnhelper", sh.run("/usr/local/bin/vulnhelper --read /root/suid.flag"))
    show("root.txt", sh.run("cat /root/root.txt"))
    show("id", sh.run("id"))

    print("=" * 60)
    print(" route B - writable cron script (linux-04)")
    print("=" * 60)
    sh2 = SimShell("svc_backup")
    show("cat README", sh2.run("cat /opt/vulnlab/README.local"))
    show("maintenance.sh", sh2.run("sudo /opt/vulnlab/maintenance.sh"))
    show("root.txt", sh2.run("cat /root/root.txt"))

    print("=" * 60)
    print(" route C - PATH hijack (linux-05)")
    print("=" * 60)
    sh3 = SimShell("svc_flask")
    show("lab-tick clean", sh3.run("sudo /usr/bin/env lab-tick"))
    show("plant log-cleaner", sh3.run("chmod +w /opt/vulnlab/bin/log-cleaner"))
    sh3.run("chmod +w /opt/vulnlab/bin/log-cleaner")
    ns["VFS"].files["/opt/vulnlab/bin/log-cleaner"] = "#!/bin/sh\nid\n"
    show("lab-tick hijacked", sh3.run("sudo /usr/bin/env lab-tick"))
    sh3.run("cat /opt/vulnlab/README.local")
    show("root.txt", sh3.run("cat /root/root.txt"))

    print("=" * 60)
    print(" ssh-01/02/03 MOTD + auth")
    print("=" * 60)
    for user, pw in (("student", "Student2019!"), ("svc_backup", "BackupSmb1!")):
        ok = ns["_auth_ok"](user, pw, None)
        print("   password auth {}: {}".format(user, ok))
    print("   key-only backup (key):", ns["_auth_ok"]("backup", None, b"any"))
    print("   key-only backup (pw):", ns["_auth_ok"]("backup", "Winter2021!", None))
    print("   svc_flask chain login:", ns["_auth_ok"](
        "svc_flask", config.get_flag("flask-14b"), None))
    print("=" * 60)


if __name__ == "__main__":
    main()