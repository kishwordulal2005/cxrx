"""VulnLab SMB service - 127.0.0.1:445 (or 4450 when 445 is taken).

==========================================================================
  AUTHORIZED LAB ONLY - vulnerable on purpose.  Do not expose this host.
==========================================================================

WHY THIS IS SIMULATED
  smbclient / enum4linux speak the real SMB2 dialect, and binding the real
  port 445 also collides with the host's own Windows file sharing on a
  classroom laptop.  VulnLab therefore models the shares over a small
  line protocol on the SMB port and teaches the same concepts:

    negprot  ->  session setup (guest or authenticated)
    treeconn ->  attach a share, including the unadvertised dev$ share
    readdir  ->  list files
    read     ->  fetch a file

  See smb/README.md for how to point a real Samba at the same share trees
  when an instructor wants genuine SMB on a Linux lab VM.

INTENTIONALLY VULNERABLE
  smb-01  share enumeration leaks the workgroup banner
  smb-02  the public share allows anonymous read
  smb-03  the backup share needs svc_backup's credentials
  smb-04  the engineering share needs the telnet-leaked credentials
  smb-05  dev$ is not advertised but is reachable
"""
import os
import socket
import socketserver
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

HOST = config.BIND_HOST
PORT = config.PORT_SMB_SIM

BANNER = ("\\x5cx\\x5cx\\x5cx\\x5cx\\x5cx\\x5cx\\x5cx\\x5cx\\x5cx\\x5cx\\x5cx\\x5cx"
          "SMB 3.1.1 - VulnLab file server (workgroup: VULNLAB)\n")

# share -> (advertised?, credential or None for guest, description)
SHARES = {
    "public": (True, None, "guest allowed"),
    "backup": (True, "svc_backup", "svc_backup"),
    "engineering": (True, "engineering", "engineering"),
    "dev$": (False, None, "hidden share, guest allowed"),
}

CREDS = {
    "svc_backup": "BackupSmb1!",
    "engineering": "EngBuild2020!",
    "svc_web": "WebOld2019!",
    "student": "Student2019!",
}


def flag(cid):
    return config.resolve_flag(cid)


def ensure_shares():
    import app as target_app
    target_app.bootstrap()


class SMBHandler(socketserver.StreamRequestHandler):
    timeout = 60

    def send(self, text):
        self.wfile.write((text + "\r\n").encode("utf-8", "replace"))
        self.wfile.flush()

    def handle(self):
        ensure_shares()
        self.send("SMB 3.1.1 VulnLab server - workgroup VULNLAB")
        self.send("smb-01: " + flag("smb-01"))
        user, authed = "guest", False
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            parts = line.split()
            verb = parts[0].lower()

            if verb in ("help", "?"):
                self.send("commands: negprot [user pass] | treeconn <share> | "
                          "readdir | read <file> | quit")
            elif verb == "negprot":
                if len(parts) >= 3 and CREDS.get(parts[1]) == parts[2]:
                    user, authed = parts[1], True
                    self.send("session setup ok for {}".format(user))
                else:
                    user, authed = "guest", False
                    self.send("session setup ok as guest (null session)")
            elif verb == "treeconn":
                name = parts[1] if len(parts) > 1 else ""
                key = name.split("\\\\")[-1].split("/")[-1]
                if key not in SHARES:
                    self.send("NT_STATUS_BAD_NETWORK_NAME")
                    continue
                advertised, needed, _ = SHARES[key]
                if needed and not (authed and user == needed):
                    self.send("NT_STATUS_ACCESS_DENIED - {} required".format(needed))
                    continue
                self.share = key
                self.send("connected to \\\\{}\\{}{}".format(
                    config.TARGET_HOST, key,
                    "" if advertised else "  (not in the share list)"))
                if key == "public":
                    self.send("smb-02: " + flag("smb-02"))
                if key == "dev$":
                    self.send("smb-05: " + flag("smb-05"))
            elif verb == "readdir":
                d = os.path.join(config.SMB_DIR, getattr(self, "share", ""))
                if not d or not os.path.isdir(d):
                    self.send("NT_STATUS_NO_SUCH_DEVICE")
                    continue
                for n in sorted(os.listdir(d)):
                    self.send("  " + n)
            elif verb == "read":
                fname = parts[1] if len(parts) > 1 else ""
                d = os.path.join(config.SMB_DIR, getattr(self, "share", ""))
                p = os.path.join(d, os.path.basename(fname))
                if not os.path.isfile(p):
                    self.send("NT_STATUS_OBJECT_NAME_NOT_FOUND")
                    continue
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    self.send(fh.read())
            elif verb in ("quit", "logout"):
                self.send("goodbye")
                return
            else:
                self.send("NT_STATUS_INVALID_COMMAND")


class ThreadedTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve():
    port = PORT
    try:
        ThreadedTCP((HOST, port), SMBHandler).server_close()
    except OSError:
        # 445 is often taken by the host's own file sharing; step aside.
        port = port + 1
    srv = ThreadedTCP((HOST, port), SMBHandler)
    print("=" * 62)
    print("  VulnLab SMB simulator (real SMB needs Linux - see smb/README.md)")
    print("  tcp://{}:{}".format(HOST, port))
    print("=" * 62)
    srv.serve_forever()


if __name__ == "__main__":
    serve()