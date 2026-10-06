"""VulnLab FTP service - 127.0.0.1:2121 (raw sockets, no external server).

==========================================================================
  AUTHORIZED LAB ONLY - vulnerable on purpose.  Do not expose this host.
==========================================================================

INTENTIONALLY VULNERABLE
  ftp-01  anonymous / guest login is allowed        (CWE-287)
  ftp-02  a developer backup archive sits in the home directory (CWE-530)
  ftp-03  credentials.old reuses passwords elsewhere (CWE-522)
  ftp-04  a dot-directory is hidden from LIST but reachable with CWD (CWE-284)
  recon-04  the multi-line 220 banner carries extra commentary

Implemented with the standard library only: python sockets, the FTP command
subset students actually use (USER/PASS/SYST/PWD/CWD/TYPE/PASV/LIST/RETR/
SIZE/QUIT/NOOP/FEAT) and an in-memory virtual filesystem backed by real
files under data/backups.
"""
import os
import socket
import socketserver
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

HOST = config.BIND_HOST
PORT = config.PORT_FTP
BANNER = "220 VulnLab FTP server ready.\r\n220 Lab build 2.3.4 - anonymous upload area enabled.\r\n"

BANNER_NOTE = (
    "220 VulnLab FTP server ready.\r\n"
    "220 Lab build 2.3.4 - anonymous upload area enabled.\r\n"
    "220 NOTE FROM OPS: do not sync the home directory to the web root.\r\n"
    "220-recon-04: {f}\r\n"
    "220 Please log in.\r\n"
)

USERS = {
    "anonymous": "",           # guest login, anything (or nothing) as password
    "ftp": "",
    "svc_web": "WebOld2019!",
    "svc_backup": "BackupSmb1!",
}

# Accounts that authenticate with any password at all.
GUEST_USERS = ("anonymous", "ftp")

# Virtual filesystem: client path -> file on disk (or an inline literal).
FILES = {}
DIRS = {"/": ["/", "/.backup"]}

GUEST_HOME = "/"
AUTH_HOME = "/home/{user}"


def flag(cid):
    return config.resolve_flag(cid)


def _join(base, name):
    """Join FTP paths without producing a doubled slash at the root."""
    if base.endswith("/"):
        return base + name
    return base + "/" + name


def build_filesystem():
    """Populate the FTP tree from the same material app.py writes."""
    import app as target_app  # reuse one source of truth for the lab data
    target_app.bootstrap()
    backup = os.path.join(config.BACKUP_DIR, "backup.zip")

    def add(base):
        FILES[_join(base, "welcome.txt")] = (
            "VulnLab FTP - anonymous area\n"
            "backup.zip is the nightly developer backup.\n")
        FILES[_join(base, "employee_notes.txt")] = target_app.employee_notes()
        FILES[_join(base, "credentials.old")] = target_app.CREDENTIALS_OLD
        FILES[_join(base, "old_config.txt")] = target_app.OLD_CONFIG_TXT
        FILES[_join(base, "backup.zip")] = ("@FILE:" + backup)

    add(GUEST_HOME)
    for u in ("svc_web", "svc_backup"):
        add(AUTH_HOME.format(user=u))

    # ftp-04: deliberately excluded from LIST, still reachable by CWD.
    FILES["/.backup/ftp_history.log"] = (
        "2019-04-02 anonymous session from 10.0.0.17\n"
        "2019-04-02 svc_web login ok, 3 files retrieved\n"
        "2019-05-11 maintenance: rotated svc_backup\n"
        "ftp-04: {f}\n".format(f=flag("ftp-04")))


class FTPHandler(socketserver.BaseRequestHandler):
    timeout = 30

    # -- plumbing ---------------------------------------------------------
    def reply(self, text):
        try:
            self.request.sendall((text + "\r\n").encode("utf-8", "replace"))
        except OSError:
            # The client hung up first; nothing useful left to say.
            raise ConnectionResetError

    def multi(self, lines):
        out = []
        for i, ln in enumerate(lines):
            prefix = "{}-".format(220) if i < len(lines) - 1 else "220 "
            out.append(prefix + ln)
        self.reply("\r\n".join(out))

    def setup(self):
        self.cwd = "/"
        self.user = None
        self.authed = False
        self.type = "A"
        self.data_sock = None
        self.multi([
            "VulnLab FTP server ready.",
            "Lab build 2.3.4 - anonymous upload area enabled.",
            "NOTE FROM OPS: do not sync the home directory to the web root.",
            "recon-04: {}".format(flag("recon-04")),
            "Please log in.",
        ])

    def open_data(self):
        """PASV: hand out a passive port and wait for the data connection."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((HOST, 0))
        s.listen(1)
        s.settimeout(10)
        self.data_sock = s
        port = s.getsockname()[1]
        self.reply("227 Entering Passive Mode (127,0,0,1,{},{})".format(
            port >> 8, port & 0xFF))

    def _accept_data(self):
        if not self.data_sock:
            self.reply("425 Use PASV first")
            return None
        try:
            conn, _ = self.data_sock.accept()
            return conn
        except socket.timeout:
            self.reply("425 Connection timed out")
            return None
        finally:
            try:
                self.data_sock.close()
            except OSError:
                pass
            self.data_sock = None

    # -- commands ---------------------------------------------------------
    def handle(self):
        while True:
            try:
                raw = self.request.recv(2048)
            except socket.timeout:
                return
            if not raw:
                return
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()
            fn = getattr(self, "cmd_" + cmd.lower(), None)
            if fn is None:
                self.reply("502 Command not implemented")
                continue
            if not self.authed and cmd not in ("USER", "PASS", "QUIT", "FEAT",
                                               "SYST", "NOOP"):
                self.reply("530 Please login with USER and PASS")
                continue
            try:
                if fn(arg.strip()):
                    return
            except (ConnectionResetError, BrokenPipeError):
                return
            except Exception as exc:  # noqa: BLE001
                self.reply("550 {}".format(exc))

    def cmd_user(self, arg):
        self.user = arg
        if arg in GUEST_USERS:
            self.reply("230 Anonymous access granted, send your e-mail address as password.")
            self.authed = True
            self.cwd = GUEST_HOME
            return False
        self.reply("331 Please specify the password.")

    def cmd_pass(self, arg):
        # CWE-287: anonymous/ftp are guest accounts - any password (or none).
        if self.user in GUEST_USERS:
            self.authed = True
            self.cwd = GUEST_HOME
            self.reply("230 Login successful.")
            return False
        if self.user in USERS and USERS[self.user] == arg:
            self.authed = True
            self.cwd = AUTH_HOME.format(user=self.user)
            self.reply("230 Login successful.")
            return False
        self.reply("530 Login incorrect.")

    def cmd_syst(self, arg):
        self.reply("215 UNIX Type: L8")

    def cmd_feat(self, arg):
        self.reply("211-Features:\r\n SIZE\r\n PASV\r\n211 End")

    def cmd_noop(self, arg):
        self.reply("200 OK")

    def cmd_type(self, arg):
        self.type = arg.upper()[:1] or "A"
        self.reply("200 Type set to {}".format(self.type))

    def cmd_pwd(self, arg):
        self.reply('257 "{}" is the current directory'.format(self.cwd))

    def cmd_cwd(self, arg):
        target = self._resolve(arg)
        if target is None:
            self.reply("550 No such directory")
            return False
        if target not in DIRS and not any(k.startswith(target + "/")
                                          for k in FILES):
            self.reply("550 No such directory")
            return False
        self.cwd = target
        self.reply("250 Directory changed to {}".format(target))
        return False

    def _resolve(self, arg):
        arg = (arg or "").strip()
        if not arg:
            return self.cwd
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

    def cmd_size(self, arg):
        p = self._resolve(arg)
        if p not in FILES:
            self.reply("550 Could not get file size")
            return False
        body = self._content(p)
        self.reply("213 {}".format(len(body)))
        return False

    def cmd_list(self, arg):
        target = self._resolve(arg)
        names = sorted(os.path.basename(k) for k in FILES
                       if os.path.dirname(k) == target)
        # CWE-284: dot-directories are skipped, exactly like a default LIST.
        listing = "".join(
            "-rw-r--r-- 1 ftp ftp {:>6} Jan  1  2019 {}\r\n".format(
                len(self._content(_join(target, n))), n)
            for n in names)
        self.open_data()
        conn = self._accept_data()
        if conn:
            conn.sendall(listing.encode())
            conn.close()
        self.reply("150 Here comes the directory listing.")
        self.reply("226 Directory send OK.")
        return False

    def cmd_nlst(self, arg):
        return self.cmd_list(arg)

    def cmd_retr(self, arg):
        p = self._resolve(arg)
        if p not in FILES:
            self.reply("550 Failed to open file")
            return False
        body = self._content(p)
        self.open_data()
        conn = self._accept_data()
        if conn:
            conn.sendall(body)
            conn.close()
        self.reply("150 Opening BINARY mode data connection.")
        self.reply("226 Transfer complete.")
        return False

    def cmd_quit(self, arg):
        self.reply("221 Goodbye.")
        return True

    def _content(self, path):
        raw = FILES.get(path, "")
        if raw.startswith("@FILE:"):
            try:
                with open(raw[6:], "rb") as fh:
                    return fh.read()
            except OSError:
                return b""
        return raw.encode("utf-8")


class ThreadedTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve():
    build_filesystem()
    srv = ThreadedTCP((HOST, PORT), FTPHandler)
    print("=" * 62)
    print("  VulnLab FTP  (anonymous login allowed, on purpose)")
    print("  ftp://{}:{}".format(HOST, PORT))
    print("=" * 62)
    srv.serve_forever()


if __name__ == "__main__":
    serve()