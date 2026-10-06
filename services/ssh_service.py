"""VulnLab SSH service - 127.0.0.1:2222 (Paramiko), simulated Linux host.

==========================================================================
  AUTHORIZED LAB ONLY - vulnerable on purpose.  Do not expose this host.
==========================================================================

WHY THIS IS SIMULATED
  The privilege-escalation track (linux-01 .. linux-08, boot-02) needs a
  machine with SUID binaries, a root cron spool and a root-only flag file.
  VulnLab must also run on a student workstation, so the lab does NOT create
  real SUID files, real cron jobs or real root-owned paths on the host.

  Instead this service presents a *virtual* Linux filesystem over a genuine
  Paramiko SSH channel.  `find / -perm -4000`, `sudo -l`, `crontab -l`,
  `vulnhelper --read /root/root.txt` and friends are answered from that model,
  so nothing here can damage the machine VulnLab runs on.

INTENTIONALLY VULNERABLE
  ssh-01  a real SSH banner on a non-standard port
  ssh-02  credentials harvested from SMB/FTP work here too (CWE-522)
  ssh-03  the backup account accepts the key from backup.zip
  boot-01 the svc_flask login MOTD carries the Flask-chain flag
  linux-01..08  enumeration, SUID, writable cron, PATH hijack, secrets
  boot-02  root requires a completed privilege-escalation step

Two independent privesc routes:
  A  linux-02 -> linux-03   SUID helper reads a root-owned flag
  B  linux-08 -> linux-04   writable root cron script (sudo -l reveals it)
  C  linux-08 -> linux-05   PATH hijack in /opt/vulnlab/bin
"""
import os
import socket
import socketserver
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

HOST = config.BIND_HOST
PORT = config.PORT_SSH
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 VulnLab-lab"

HOST_KEY = None  # generated once at start-up


def flag(cid):
    return config.resolve_flag(cid)


# ---------------------------------------------------------------------------
# Accounts.  Passwords are deliberately reused across services (CWE-522).
# ---------------------------------------------------------------------------
ACCOUNTS = {
    "student":      {"pw": "Student2019!", "role": "user", "home": "/home/student"},
    "svc_web":      {"pw": "WebOld2019!", "role": "user", "home": "/home/svc_web"},
    "svc_backup":   {"pw": "BackupSmb1!", "role": "user", "home": "/home/svc_backup"},
    "developer":    {"pw": "DevNotes2020!", "role": "user", "home": "/home/developer"},
    "old.employee": {"pw": "Legacy2018!", "role": "user", "home": "/home/old.employee"},
    "engineering":  {"pw": "EngBuild2020!", "role": "user", "home": "/home/engineering"},
    # ssh-03: key-only account.
    "backup":       {"pw": None, "role": "user", "home": "/home/backup",
                     "key": "lab-backup-key"},
    # Reached only from the Flask RCE chain (boot-01).
    "svc_flask":    {"pw": config.get_flag("flask-14b") or "VLsvc_flask_2019!",
                     "role": "user", "home": "/home/svc_flask"},
    "root":         {"pw": None, "role": "root", "home": "/root"},
}

LAB_PRIVATE_KEY = None


def load_private_key():
    """The lab key pair, shared with the copy inside backup.zip (ssh-03).

    config.lab_private_key() owns the material so the key a student finds in
    the backup archive is the key this service actually accepts.
    """
    global LAB_PRIVATE_KEY, HOST_KEY
    import io
    from paramiko import RSAKey
    if LAB_PRIVATE_KEY is None:
        LAB_PRIVATE_KEY = config.lab_private_key()
        HOST_KEY = RSAKey.from_private_key(io.StringIO(LAB_PRIVATE_KEY))
    return LAB_PRIVATE_KEY


# ---------------------------------------------------------------------------
# The virtual machine
# ---------------------------------------------------------------------------
class FakeFS:
    """An in-memory Linux filesystem for the simulated host."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.files = {
            "/etc/hostname": "vulnlab\n",
            "/etc/os-release": 'PRETTY_NAME="Ubuntu 20.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="20.04"\n',
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "student:x:1000:1000:Training User:/home/student:/bin/bash\n"
                "svc_web:x:1003:1003:Web Service:/home/svc_web:/bin/bash\n"
                "svc_backup:x:1004:1004:Backup Service:/home/svc_backup:/bin/bash\n"
                "svc_flask:x:1011:1011:Flask Service:/home/svc_flask:/bin/bash\n"
                "developer:x:1005:1005:Developer:/home/developer:/bin/bash\n"
                "backup:x:1006:1006:Backup:/home/backup:/bin/bash\n"
                "engineering:x:1012:1012:Engineering:/home/engineering:/bin/bash\n"
            ),
            "/etc/group": ("root:x:0:\nsudo:x:27:student,svc_backup,svc_flask\n"
                           "engineering:x:1012:developer,engineering\n"),
            # linux-07: configuration secrets.
            "/etc/vulnlab/app.conf": (
                "; VulnLab application configuration\n"
                "[database]\n"
                "host = 127.0.0.1\n"
                "name = vulnlab\n"
                "password = dbpw-2019\n"
                "[services]\n"
                "ftp_password = WebOld2019!\n"
                "backup_password = BackupSmb1!\n"
                "# ops left the Flask service key here as well (CWE-798)\n"
                "flask_secret = vulnlab-secret\n"
                "linux-07: {f7}\n".format(f7=flag("linux-07"))),
            # linux-08: cron discovery.
            "/etc/cron.d/vulnlab": (
                "# VulnLab scheduled tasks\n"
                "SHELL=/bin/bash\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/vulnlab/bin\n"
                "17 * * * * root /opt/vulnlab/maintenance.sh\n"
                "*/5 * * * * root lab-tick\n"
                "# linux-08: {f8}\n".format(f8=flag("linux-08"))),
            "/etc/crontab": ("# m h dom mon dow user command\n"
                             "17 * * * * root /opt/vulnlab/maintenance.sh\n"),
            # linux-02 / linux-03: SUID helper and its notes.
            "/usr/local/share/vulnlab/suid.flag": "linux-02: {f2}\n".format(f2=flag("linux-02")),
            "/usr/local/bin/vulnhelper": "#!C\nplaceholder suid helper\n",
            # linux-01: the local enumeration breadcrumb.
            "/opt/vulnlab/README.local": (
                "VulnLab host notes\n"
                "==================\n"
                "This machine is a training target. Enumerate before you attack:\n"
                "  id / uname / sudo -l / crontab -l / env / find\n"
                "Start here: /opt/vulnlab\n"
                "linux-01: {f1}\n".format(f1=flag("linux-01"))),
            "/opt/vulnlab/maintenance.sh": (
                "#!/bin/bash\n"
                "# weekly maintenance - runs as root from /etc/cron.d/vulnlab\n"
                "echo \"maintenance starting\"\n"
                "rm -f /tmp/vulnlab-*.log\n"),
            "/var/backups/creds.enc": (
                "VLNB1:4a1f9c2d8e7b6a5f3d0c9b8a7f6e5d4c3b2a1908f7e6d5c4b3a29180f7e6d5c4\n"),
            # bonus-01
            "/var/backups/.hidden": "bonus-01: {fb}\n".format(fb=flag("bonus-01")),
        }
        self.dirs = {
            "/": ["bin", "boot", "etc", "home", "opt", "proc", "root",
                  "srv", "tmp", "usr", "var"],
            "/etc": ["cron.d", "vulnlab", "passwd", "group", "hostname",
                     "os-release", "crontab"],
            "/etc/cron.d": ["vulnlab"],
            "/etc/vulnlab": ["app.conf"],
            "/opt": ["vulnlab"],
            "/opt/vulnlab": ["README.local", "maintenance.sh", "bin"],
            "/opt/vulnlab/bin": [],          # linux-05: writable, on the cron PATH
            "/usr": ["local", "share"],
            "/usr/local": ["bin", "share"],
            "/usr/local/bin": ["vulnhelper", "sudo", "less", "vi", "find"],
            "/usr/local/share": ["vulnlab"],
            "/usr/local/share/vulnlab": ["suid.flag"],
            "/var": ["backups", "log"],
            "/var/backups": ["creds.enc", ".hidden"],
            "/var/log": ["auth.log", "syslog"],
            "/root": ["root.txt", "suid.flag", "bash_history"],
            "/home": ["student", "svc_web", "svc_backup", "svc_flask",
                      "developer", "backup", "engineering", "old.employee"],
            "/tmp": [],
            "/proc": ["self"],
            "/bin": ["bash", "ls", "cat"],
            "/srv": [],
            "/boot": [],
        }
        for u in ("student", "svc_web", "svc_backup", "svc_flask", "developer",
                  "backup", "engineering", "old.employee"):
            home = "/home/{}".format(u)
            self.dirs.setdefault(home, [])
            self.dirs["/home/" + u] = ["notes.txt"] if u == "student" else []
            self.files[home + "/notes.txt"] = (
                "read-only mount, session log kept in /opt/vulnlab\n") if u == "student" else ""
        # root-only files
        self.files["/root/root.txt"] = "boot-02: {f}\n".format(f=flag("boot-02"))
        self.files["/root/suid.flag"] = "linux-03: {f}\n".format(f=flag("linux-03"))
        self.files["/root/bash_history"] = (
            "cd /opt/vulnlab\n./maintenance.sh\ncat /root/root.txt\n")
        self.perms = {
            "/root/root.txt": "root only",
            "/root/suid.flag": "root only",
            "/etc/vulnlab/app.conf": "root:root 644",
            "/etc/cron.d/vulnlab": "root:root 644",
            "/opt/vulnlab/maintenance.sh": "root:root 777",   # linux-04: world writable
            "/opt/vulnlab/bin": "student:student 777",         # linux-05: writable
            "/usr/local/bin/vulnhelper": "-rwsr-xr-x 1 root root 8.4K Jul  2  2019",
            "/var/backups/creds.enc": "root:root 600",
        }
        self.suid = ["/usr/local/bin/vulnhelper", "/usr/bin/passwd", "/bin/mount"]
        self.owned_writable = ["/opt/vulnlab/maintenance.sh", "/opt/vulnlab/bin/log-cleaner"]


VFS = FakeFS()


def _readable(path, user, is_root):
    """Root-only paths are hidden from unprivileged sessions."""
    if path in ("/root/root.txt", "/root/suid.flag", "/root/bash_history") \
            and not is_root:
        return None
    return VFS.files.get(path)


def _stat_line(path):
    perms = VFS.perms.get(path)
    if perms and not perms.startswith("-"):
        return "{} 2 root root 4096 Jan  1  2019 {}".format(perms, path)
    if path in VFS.dirs:
        return "drwxr-xr-x 2 root root 4096 Jan  1  2019 {}".format(path)
    if perms:
        return "{} 1 root root {} Jan  1  2019 {}".format(perms.split()[0], perms, path)
    size = len(VFS.files.get(path, ""))
    return "-rw-r--r-- 1 root root {:>6} Jan  1  2019 {}".format(size, path)


# ---------------------------------------------------------------------------
# The simulated shell
# ---------------------------------------------------------------------------
class SimShell:
    def __init__(self, username, is_root=False):
        self.user = username
        self.home = ACCOUNTS.get(username, {}).get("home", "/home/" + username)
        self.is_root = is_root
        self.cwd = self.home
        self.env = {
            "USER": username,
            "HOME": self.home,
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            # linux-06 / bonus-04
            "VULNLAB_BACKUP_KEY": "4a1f9c2d8e7b6a5f3d0c9b8a7f6e5d4c3b2a1908f7e6d5c4b3a29180f7e6d5c4",
            "VULNLAB_BONUS_ENV": flag("bonus-04"),
            "LANG": "C.UTF-8",
        }
        self.escalated = set()
        # boot-02 mirrors the scoreboard gate: root is only reachable after the
        # local enumeration step, so students cannot skip straight to it.
        self.enumerated = False

    # -- prompt ------------------------------------------------------------
    def prompt(self):
        return "{}@vulnlab:{}# ".format(self.user, self.cwd)

    # -- helpers -----------------------------------------------------------
    def resolve(self, arg):
        if not arg:
            return self.cwd
        arg = arg.strip()
        if arg.startswith("~"):
            arg = self.home + arg[1:]
        if not arg.startswith("/"):
            arg = self.cwd.rstrip("/") + "/" + arg
        parts = []
        for seg in arg.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(seg)
        return "/" + "/".join(parts)

    def run(self, line):
        line = line.strip()
        if not line:
            return ""
        parts = line.split()
        cmd, args = parts[0], parts[1:]
        if "/" in cmd:
            # A qualified path is resolved against the command table by its
            # base name, the way a shell resolves it through PATH.
            cmd = cmd.rsplit("/", 1)[-1]

        table = {
            "id": self.c_id, "whoami": lambda a: self.user,
            "uname": self.c_uname, "hostname": lambda a: "vulnlab",
            "pwd": lambda a: self.cwd,
            "cd": self.c_cd, "ls": self.c_ls, "cat": self.c_cat,
            "echo": lambda a: " ".join(a),
            "env": self.c_env, "printenv": self.c_env,
            "sudo": self.c_sudo, "find": self.c_find, "crontab": self.c_crontab,
            "which": self.c_which, "stat": self.c_stat, "file": self.c_file,
            "grep": self.c_grep, "head": self.c_head, "tail": self.c_tail,
            "wc": lambda a: "", "less": self.c_cat, "more": self.c_cat,
            "ps": self.c_ps, "ss": self.c_ps, "netstat": self.c_ps,
            "history": lambda a: "  1  cd /opt/vulnlab\n  2  ls -la\n  3  cat README.local",
            "clear": lambda a: "",
            "who": lambda a: "root     tty1  2024-02-11 08:00\nstudent  pts/0  2024-02-11 09:14",
            "help": lambda a: "simulated shell: id uname ls cat sudo find crontab env ...",
            "vulnhelper": self.c_vulnhelper,
            "vulnlab-decrypt": self.c_decrypt,
            "lab-tick": self.c_lab_tick,
            "chmod": self.c_chmod, "echo_out": lambda a: "",
        }
        fn = table.get(cmd)
        if fn is None:
            return "{}: command not found".format(cmd)
        try:
            return fn(args)
        except Exception as exc:  # noqa: BLE001
            return "{}: {}".format(cmd, exc)

    # -- individual commands ----------------------------------------------
    def c_id(self, args):
        uid = 0 if self.is_root else {"student": 1000, "svc_web": 1003,
                                      "svc_backup": 1004, "svc_flask": 1011,
                                      "developer": 1005, "backup": 1006,
                                      "engineering": 1012}.get(self.user, 1000)
        out = "uid={}({}) gid={}({}) groups={}({})".format(
            uid, self.user, uid, self.user, uid, self.user)
        if self.escalated:
            out += "\n[root privileges acquired via {}]".format(", ".join(sorted(self.escalated)))
        return out

    def c_uname(self, args):
        if "-a" in args:
            return "Linux vulnlab 5.4.0-190-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        return "Linux"

    def c_cd(self, args):
        target = self.resolve(args[0] if args else self.home)
        if target not in VFS.dirs:
            return "cd: {}: No such file or directory".format(target)
        self.cwd = target
        return ""

    def c_ls(self, args):
        long = "-l" in args or "-la" in args or "-al" in args
        paths = [a for a in args if not a.startswith("-")] or [self.cwd]
        out = []
        for p in paths:
            target = self.resolve(p)
            entries = []
            if target in VFS.dirs:
                for name in sorted(VFS.dirs[target]):
                    entries.append(target.rstrip("/") + "/" + name)
            for key in sorted(VFS.files):
                if os.path.dirname(key) == target:
                    entries.append(key)
            hidden = [e for e in entries if os.path.basename(e).startswith(".")]
            show = entries if "-a" in args or long else [e for e in entries
                                                         if not os.path.basename(e).startswith(".")]
            for e in show:
                if long:
                    out.append(_stat_line(e))
                else:
                    out.append(os.path.basename(e))
        return "\n".join(out)

    def c_cat(self, args):
        if not args:
            return "cat: missing operand"
        out = []
        for a in args:
            if a == "/proc/self/environ":
                out.append("\0".join("{}={}".format(k, v)
                                     for k, v in sorted(self.env.items())))
                continue
            p = self.resolve(a)
            if p == "/root/root.txt":
                # boot-02 gate: the scoreboard also requires linux-01.
                if not self.is_root:
                    out.append("cat: /root/root.txt: Permission denied")
                elif not self.enumerated:
                    out.append("cat: /root/root.txt: Permission denied")
                else:
                    out.append(VFS.files["/root/root.txt"].rstrip("\n"))
                continue
            data = _readable(p, self.user, self.is_root)
            if data is None:
                out.append("cat: {}: Permission denied".format(a))
            elif p in VFS.dirs:
                out.append("cat: {}: Is a directory".format(a))
            else:
                out.append(data.rstrip("\n"))
                if p == "/opt/vulnlab/README.local":
                    self.enumerated = True
        return "\n".join(out)

    def c_env(self, args):
        return "\n".join("{}={}".format(k, v) for k, v in sorted(self.env.items()))

    def c_which(self, args):
        return "\n".join(a for a in args
                         if any(os.path.basename(x) == a
                                for x in VFS.dirs.get("/usr/local/bin", []) + ["ls", "cat", "bash"]))

    def c_stat(self, args):
        return "\n".join(_stat_line(self.resolve(a)) for a in args if not a.startswith("-"))

    def c_file(self, args):
        out = []
        for a in args:
            if a.startswith("/usr/local/bin/vulnhelper"):
                out.append("{}: ELF 64-bit LSB pie executable, "
                           "setuid, dynamically linked".format(a))
            else:
                out.append("{}: ASCII text".format(self.resolve(a)))
        return "\n".join(out)

    def c_grep(self, args):
        pattern = args[0] if args else ""
        targets = [self.resolve(a) for a in args[1:] if not a.startswith("-")]
        out = []
        for t in targets:
            data = _readable(t, self.user, self.is_root)
            if data:
                for i, ln in enumerate(data.splitlines(), 1):
                    if pattern in ln:
                        out.append("{}:{}:{}".format(t, i, ln))
        return "\n".join(out)

    def c_head(self, args):
        n = 10
        files = []
        for a in args:
            if a.startswith("-") and a[1:].isdigit():
                n = int(a[1:])
            else:
                files.append(self.resolve(a))
        out = []
        for f in files:
            data = _readable(f, self.user, self.is_root)
            if data:
                out.extend(data.splitlines()[:n])
        return "\n".join(out)

    def c_tail(self, args):
        n = 10
        files = []
        for a in args:
            if a.startswith("-") and a[1:].isdigit():
                n = int(a[1:])
            else:
                files.append(self.resolve(a))
        out = []
        for f in files:
            data = _readable(f, self.user, self.is_root)
            if data:
                out.extend(data.splitlines()[-n:])
        return "\n".join(out)

    def c_ps(self, args):
        return ("USER  PID  COMMAND\n"
                "root  1  /sbin/init\n"
                "root  812  /usr/sbin/cron -f\n"
                "{u}  {pid}  sshd: {u}@pts/0\n"
                "{u}  {pid2}  bash\n".format(u=self.user, pid=1200 + hash(self.user) % 500,
                                             pid2=1201 + hash(self.user) % 500))

    def c_sudo(self, args):
        if not args:
            return "usage: sudo -l"
        if "-l" in args:
            if self.user in ("student", "svc_backup", "svc_flask"):
                return ("Matching Defaults entries for {} on vulnlab:\n"
                        "    env_reset, secure_path=/usr/local/sbin\\:/usr/local/bin\\:"
                        "/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n"
                        "\n"
                        "User {} may run the following commands on vulnlab:\n"
                        "    (ALL) NOPASSWD: /usr/local/bin/vulnhelper\n"
                        "    (ALL) NOPASSWD: /opt/vulnlab/maintenance.sh\n"
                        "    (ALL) NOPASSWD: /usr/bin/env lab-tick\n").format(self.user, self.user)
            return "User {} is not in the sudoers file.".format(self.user)
        return self._privileged(args[0], args[1:])

    def _privileged(self, target, args):
        """Run a command 'as root' when this user is allowed to."""
        allowed = self.user in ("student", "svc_backup", "svc_flask")
        if not allowed:
            return ("{} is not in the sudoers file. "
                    "This incident has been reported.").format(self.user)

        if target.endswith("vulnhelper"):
            return self.c_vulnhelper(args)
        if target.endswith("maintenance.sh"):
            # linux-04: /etc/cron.d/vulnlab runs this world-writable script as
            # root, and sudo -l says so explicitly.
            self.escalated.add("writable-cron-script")
            self.is_root = True
            return ("maintenance starting\n"
                    "removed /tmp/vulnlab-week.log\n"
                    "[root] /opt/vulnlab/maintenance.sh executed as root\n"
                    "linux-04: {}".format(flag("linux-04")))
        if "lab-tick" in (target + " " + " ".join(args)):
            return self.c_lab_tick([])
        if target == "/usr/bin/env":
            return self.c_env([])
        return "sudo: unable to execute {}: No such file or directory".format(target)

    def c_vulnhelper(self, args):
        """linux-03: the SUID helper takes any path with no validation."""
        if "--read" in args:
            i = args.index("--read")
            path = self.resolve(args[i + 1]) if i + 1 < len(args) else ""
            if path == "/root/suid.flag":
                # Running the setuid binary IS the escalation.
                self.escalated.add("suid-vulnhelper")
                self.is_root = True
                return VFS.files["/root/suid.flag"].strip()
            data = _readable(path, self.user, self.is_root)
            if data is None:
                return "vulnhelper: cannot open {}: Permission denied".format(path)
            return data.rstrip("\n")
        return ("vulnhelper 1.0 - maintenance helper\n"
                "usage: vulnhelper --read <path>\n"
                "note: runs as root (setuid), trusts its argument completely")

    def c_decrypt(self, args):
        """linux-06: uses VULNLAB_BACKUP_KEY from the environment."""
        path = self.resolve(args[0]) if args else ""
        key = self.env.get("VULNLAB_BACKUP_KEY", "")
        if path == "/var/backups/creds.enc" and key:
            data = _readable(path, self.user, self.is_root)
            if data:
                return ("decrypted with VULNLAB_BACKUP_KEY:\n"
                        "root:Toor-Root-2021\n"
                        "svc_backup:BackupSmb1!\n"
                        "engineering:EngBuild2020!\n"
                        "linux-06: {}".format(flag("linux-06")))
        return "vulnlab-decrypt: no key in environment (VULNLAB_BACKUP_KEY)"

    def c_lab_tick(self, args):
        """linux-05: a root task that resolves a bare command name via PATH."""
        hijack = "/opt/vulnlab/bin/log-cleaner"
        present = hijack in VFS.files
        if present:
            self.escalated.add("path-hijack")
            self.is_root = True
            return ("lab-tick: running log-cleaner (resolved from /opt/vulnlab/bin)\n"
                    "[root] log-cleaner executed as root\n"
                    "linux-05: {}".format(flag("linux-05")))
        return ("lab-tick: log-cleaner: command not found\n"
                "(cron resolves bare command names through PATH, and "
                "/opt/vulnlab/bin is on it)")

    def c_chmod(self, args):
        files = [a for a in args if not a.startswith("-")]
        if files:
            VFS.owned_writable.extend(f for f in files if f not in VFS.owned_writable)
        return ""

    def c_crontab(self, args):
        if "-l" in args:
            if self.user in ("student", "svc_backup", "svc_flask"):
                return "# no crontab for {}\n".format(self.user)
            return "# no crontab for {}\n".format(self.user)
        return "no crontab for {}".format(self.user)

    def c_find(self, args):
        out = []
        want_suid = "-perm" in args and "4000" in "".join(args)
        base = "/"
        for i, a in enumerate(args):
            if a == "/":
                base = "/"
        if want_suid:
            out.extend(VFS.suid)
        else:
            for path in sorted(VFS.files):
                if path.startswith("/") and not self._hidden(path):
                    out.append(path)
            for d in sorted(VFS.dirs):
                if not self._hidden(d):
                    out.append(d)
        return "\n".join(out)

    def _hidden(self, path):
        """Unprivileged sessions cannot see the inside of /root."""
        if self.is_root:
            return False
        return path.startswith("/root/") or path == "/root"

    # -- extras ------------------------------------------------------------
    def cat_root(self):
        if self.is_root:
            return VFS.files["/root/root.txt"]
        return None


# ---------------------------------------------------------------------------
# Paramiko plumbing
# ---------------------------------------------------------------------------
import paramiko  # noqa: E402

MOTD = """Welcome to VulnLab 20.04 (GNU/Linux 5.4.0-190-generic x86_64)
 * Documentation:  https://lab.internal/vulnlab
 * Lab target: training only, no production data.

Last login: Mon Feb 12 09:14:03 2024 from 10.0.0.42
"""

MOTD_FLAASK = MOTD + """
Flask service account detected.
This account exists only because the portal's Python runtime was
compromised.  boot-01: {f}
""".format(f=flag("boot-01"))

# ftp-03: this password was read out of credentials.old on the anonymous FTP
# server, so reusing it here proves the reuse.
MOTD_SVC_WEB = MOTD + """
Password accepted for a service account whose credentials were recovered
from the anonymous FTP backup.  ftp-03: {f}
""".format(f=flag("ftp-03"))

# ssh-02: these credentials came out of the SMB backup share.
MOTD_SVC_BACKUP = MOTD + """
Password accepted for a service account whose credentials were lifted
from the SMB backup share.  ssh-02: {f}
""".format(f=flag("ssh-02"))

# ssh-03: this account accepted the key found inside backup.zip.
MOTD_BACKUP_KEY = MOTD + """
Public key accepted for a key-only account.  The private half came out
of an old backup archive.  ssh-03: {f}
""".format(f=flag("ssh-03"))

MOTD_BY_USER = {
    "svc_flask": MOTD_FLAASK,
    "svc_web": MOTD_SVC_WEB,
    "svc_backup": MOTD_SVC_BACKUP,
    "backup": MOTD_BACKUP_KEY,
}


def _lab_public_blob():
    """SSH wire encoding of the lab public key (see config.lab_private_key)."""
    import io
    from paramiko import RSAKey
    return RSAKey.from_private_key(io.StringIO(load_private_key())).asbytes()


def _auth_ok(username, password, public_key_blob):
    acct = ACCOUNTS.get(username)
    if not acct:
        return False
    if acct.get("key"):
        # key-only account (ssh-03): the offered key must be the lab key
        return public_key_blob == _lab_public_blob()
    return bool(password) and acct["pw"] == password


def handle_channel(chan, username):
    shell = SimShell(username)
    motd = MOTD_BY_USER.get(username, MOTD)

    def on_data(data):
        if data.strip() in ("exit", "logout", "quit"):
            chan.send("logout\r\n")
            chan.close()
            return
        out = shell.run(data)
        if out:
            chan.send(out.rstrip("\n") + "\r\n" + shell.prompt())
        else:
            chan.send(shell.prompt())

    chan.send(motd)
    shell.env["VULNLAB_BONUS_ENV"] = flag("bonus-04")
    chan.send(shell.prompt())
    while True:
        data = chan.recv(4096)
        if not data:
            break
        for line in data.decode("utf-8", "replace").splitlines():
            on_data(line)
    return


class VulnLabServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.username = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if _auth_ok(username, password, None):
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # ssh-03: password auth is disabled for this account, and only the key
        # that ships inside backup.zip is accepted - so finding the right key
        # is the whole challenge.
        if not ACCOUNTS.get(username, {}).get("key"):
            return paramiko.AUTH_FAILED
        if key is None:
            return paramiko.AUTH_FAILED
        try:
            if key.asbytes() == _lab_public_blob():
                self.username = username
                return paramiko.AUTH_SUCCESSFUL
        except Exception:  # noqa: BLE001 - a malformed key is simply refused
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        acct = ACCOUNTS.get(username, {})
        if acct.get("key"):
            return "publickey"
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        threading.Thread(target=handle_channel,
                         args=(channel, self.username), daemon=True).start()
        return True

    def check_channel_pty_request(self, *args, **kwargs):
        return True


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve():
    load_private_key()
    import io
    host_key = paramiko.RSAKey.from_private_key(io.StringIO(LAB_PRIVATE_KEY))

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            transport = paramiko.Transport(self.request)
            transport.add_server_key(host_key)
            srv_iface = VulnLabServer()
            try:
                transport.start_server(server=srv_iface)
                chan = transport.accept(30)
                if chan is None:
                    return
            except Exception:
                return
            chan.settimeout(300)
            try:
                while transport.is_active():
                    time.sleep(0.5)
            except Exception:
                pass
            transport.close()

    srv = ThreadedTCPServer((HOST, PORT), Handler)
    print("=" * 62)
    print("  VulnLab SSH  (simulated Linux host, root never touches this disk)")
    print("  ssh -p {} {}@{}".format(PORT, "student", HOST))
    print("=" * 62)
    srv.serve_forever()


if __name__ == "__main__":
    serve()