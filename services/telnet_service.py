"""VulnLab Telnet service - 127.0.0.1:2323 (raw sockets).

==========================================================================
  AUTHORIZED LAB ONLY - vulnerable on purpose.  Do not expose this host.
==========================================================================

INTENTIONALLY VULNERABLE
  telnet-01  banner identifies the embedded management console (CWE-200)
  telnet-02  weak console credentials reused from an FTP file (CWE-798)
  telnet-03  'show config' discloses credentials for other services (CWE-200)
  telnet-04  unbounded username length crashes the console (CWE-119)

Plaintext protocol on a non-standard port, as students should expect.
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
PORT = config.PORT_TELNET

# telnet-02: the console password is documented in employee_notes.txt.
USERS = {"admin": "S3cureSwitch!", "root": "toor", "guest": "guest"}

CONFIG_DUMP = """switch# show config
!
hostname vulnlab-edge
!
username admin password 7 S3cureSwitch!
username svc_backup password 7 BackupSmb1!
!
! SMB shares reachable from this host
smb share //public  path data/smb/public   guest      = allowed
smb share //backup  path data/smb/backup   svc_backup = required
smb share //engineering path data/smb/engineering  engineering = required
smb share //dev$    path data/smb/dev$     hidden     = not advertised
!
! service inventory cached from the scanner
service ftp    0.0.0.0:{ftp}
service telnet 0.0.0.0:{telnet}
service ssh    0.0.0.0:{ssh}
service http   0.0.0.0:{web}
!
telnet-03: {f}
switch#
"""  # formatted per request in do_show()


def flag(cid):
    return config.resolve_flag(cid)


CONSOLE_HELP = """Available commands:
  show config        device configuration
  show users         console accounts
  show version       firmware banner
  show services      listening service inventory
  help               this list
  logout             end session
"""


class TelnetHandler(socketserver.BaseRequestHandler):
    timeout = 60
    _skip_lf = False

    def send(self, text):
        try:
            self.request.sendall(text.encode("utf-8", "replace"))
        except OSError:
            raise ConnectionError

    def prompt(self):
        self.send("switch# ")

    def handle(self):
        try:
            # telnet-01: banner first, before any credential is requested.
            self.send(
                "VulnLab management console v4.2.1 (Model VL-EDGE)\r\n"
                "Copyright (c) 2019 VulnLab Networks\r\n"
                "Warning: unauthenticated console access is restricted\r\n"
                "telnet-01: {f}\r\n\r\n".format(f=flag("telnet-01")))
            user = self.ask("Username: ")
            if user is None:
                return
            # telnet-04: no length validation on the username field.
            if len(user) > 256:
                self.send(
                    "\r\n*** console fault: username field overflow "
                    "(length {}) ***\r\n"
                    "*** telnet service restarting, session dropped ***\r\n"
                    "telnet-04: {f}\r\n".format(len(user), f=flag("telnet-04")))
                return
            pw = self.ask("Password: ")
            if pw is None:
                return
            if USERS.get(user) == pw:
                self.send("\r\nAuthentication accepted.\r\n\r\n")
                self.console(user)
            else:
                self.send("\r\nLogin invalid\r\n")
        except (ConnectionError, OSError):
            return

    def ask(self, prompt):
        self.send(prompt)
        buf = b""
        if getattr(self, "_skip_lf", False):
            # The LF half of the previous CRLF is still in the socket buffer;
            # swallow it so it is not read as this prompt's answer.
            self._skip_lf = False
            try:
                self.request.recv(1)
            except OSError:
                return None
        while True:
            try:
                ch = self.request.recv(1)
            except socket.timeout:
                return None
            except OSError:
                return None
            if not ch:
                return None
            if ch in (b"\r", b"\n"):
                self._skip_lf = (ch == b"\r")
                self.send("\r\n")
                return buf.decode("utf-8", "replace")
            if ch == b"\x7f" or ch == b"\x08":
                buf = buf[:-1]
                continue
            if ch == b"\x03":      # IAC - malformed option negotiation
                continue
            buf += ch

    def console(self, user):
        self.send(CONSOLE_HELP)
        self.prompt()
        while True:
            line = self.ask("")
            if line is None:
                return
            cmd = line.strip()
            if not cmd:
                self.prompt()
                continue
            parts = cmd.split()
            if parts[0] == "show":
                self.do_show(parts[1:])
            elif parts[0] in ("help", "?"):
                self.send(CONSOLE_HELP)
            elif parts[0] in ("logout", "exit", "quit"):
                self.send("Session ended.\r\n")
                return
            else:
                self.send("% Unknown command.\r\n" % parts[0])
            self.prompt()

    def do_show(self, args):
        what = args[0] if args else ""
        if what == "config":
            self.send(CONFIG_DUMP.format(
                ftp=config.PORT_FTP, telnet=config.PORT_TELNET,
                ssh=config.PORT_SSH, web=config.PORT_WEB,
                f=flag("telnet-03")))
        elif what == "users":
            self.send("\r\n".join(
                "username {}  role {}".format(u, "admin" if u == "admin" else "user")
                for u in USERS) + "\r\n")
        elif what == "version":
            self.send("VulnLab VL-EDGE, firmware 4.2.1, build 20190402\r\n")
        elif what == "services":
            self.send(
                "ftp {p1}  telnet {p2}  ssh {p3}  http {p4}\r\n".format(
                    p1=config.PORT_FTP, p2=config.PORT_TELNET,
                    p3=config.PORT_SSH, p4=config.PORT_WEB))
        else:
            self.send("% Incomplete command.\r\n")


class ThreadedTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve():
    srv = ThreadedTCP((HOST, PORT), TelnetHandler)
    print("=" * 62)
    print("  VulnLab Telnet management console (plaintext, on purpose)")
    print("  telnet {}:{}".format(HOST, PORT))
    print("=" * 62)
    srv.serve_forever()


if __name__ == "__main__":
    serve()