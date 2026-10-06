"""Prove the lab is actually shared, not just running.

`verify_all` proves the lab works from this machine.  It cannot prove that a
phone on the same Wi-Fi can reach it, because that needs a second device.
This checks everything about sharing that CAN be checked from one machine,
and is explicit about the one thing that cannot.

    python tools/check_network.py          # report, exit 0 if shareable
    python tools/check_network.py --quiet  # summary line only

What it proves:
  * every service binds 0.0.0.0, not just loopback
  * every service answers on the LAN address AND on loopback
  * a full HTTP request/response completes against the LAN address (a TCP
    handshake alone would pass even when the server never answers)
  * pages come back with no-store, so a browser or preview pane cannot show
    a frame from before the current request
  * the LAN address is really assigned to this machine right now
  * the inbound firewall has an enabled Allow rule covering python
    (Windows) / is not blocking the ports (POSIX)

What it cannot prove, and says so:
  * that a second device can connect.  Only a real client on the network can.
    It prints the URL to open on a phone so that test takes five seconds.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

PORTS = [
    ("web target", config.PORT_WEB),
    ("waf gate", config.PORT_WAF),
    ("ctf portal", config.PORT_CTF),
    ("ftp", config.PORT_FTP),
    ("telnet", config.PORT_TELNET),
    ("ssh", config.PORT_SSH),
    ("smb sim", config.PORT_SMB_SIM),
    ("debug-lab", config.PORT_DEBUG),
    ("internals", config.PORT_RABBIT2),
    ("cache", config.PORT_RABBIT1),
]

# The ports a phone actually loads a page from, with a path that really
# returns HTML on each.  These get an HTTP-level probe as well as the raw
# TCP one every port gets.  (The WAF's "/" is a plain-text banner, so it
# probes the proxied /login instead.)
PAGE_PORTS = [
    ("web target", config.PORT_WEB, "/"),
    ("waf gate", config.PORT_WAF, "/login"),
    ("ctf portal", config.PORT_CTF, "/"),
]

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  {} {:<34} {}".format("PASS" if ok else "FAIL", name, detail))
    return ok


def can_connect(host, port, timeout=2.0):
    import socket
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def http_probe(host, port, path="/", timeout=3.0):
    """Send a real request and parse the status line.

    Connecting proves the socket was accepted; this proves something answered
    it, and returns the response headers so callers can inspect them.
    """
    import socket
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(("GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n"
                   .format(path, host)).encode())
        data = b""
        while len(data) < 8192:
            chunk = s.recv(2048)
            if not chunk:
                break
            data += chunk
    except OSError:
        return None, ""
    finally:
        s.close()
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    status = head.split("\r\n", 1)[0]
    return status, head


def local_ips():
    """Addresses actually assigned to this machine, no traffic sent."""
    import socket
    found = set()
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass
    # getaddrinfo often misses the primary; the routing probe catches it.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        found.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    found.discard("127.0.0.1")
    return sorted(found)


def _netsh_inbound_rules():
    """Parse `netsh advfirewall ... dir=in` into a list of field dicts.

    Rules are separated by blank lines, but netsh emits CRLF, so splitting on
    "\\n\\n" silently finds nothing.  Splitting on the "Rule Name:" marker
    instead is independent of line endings.
    """
    import re
    try:
        raw = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             "name=all", "dir=in"],
            capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "netsh failed: {}".format(exc)

    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    rules, current = [], []
    for line in raw.split("\n"):
        if line.startswith("Rule Name:"):
            if current:
                rules.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        rules.append("\n".join(current))

    def field(block, name):
        m = re.search(name + r":\s*(.*)", block)
        return m.group(1).strip() if m else ""

    return [dict((k, field(r, k)) for k in
                 ("Rule Name", "Enabled", "Action", "Protocol",
                  "LocalPort", "Profiles")) for r in rules], None


def firewall_state():
    """(verdict, detail) for inbound TCP traffic to this interpreter.

    Every VulnLab service is TCP, so a UDP-only Allow rule is not enough -
    that exact rule set exists on this machine alongside the TCP one, and
    checking only for the string "python" would wave both through.
    """
    if os.name != "nt":
        if subprocess.call(["which", "ufw"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) == 0:
            out = subprocess.run(["sudo", "-n", "ufw", "status"],
                                 capture_output=True, text=True).stdout
            return ("inactive" in out), "ufw " + (
                out.strip().splitlines()[0][:40] if out.strip() else "?")
        return True, "no ufw"

    rules, err = _netsh_inbound_rules()
    if err:
        return False, err

    tcp_allow = [r for r in rules
                 if "python" in r["Rule Name"].lower()
                 and r["Enabled"].lower() == "yes"
                 and r["Action"].lower() == "allow"
                 and r["Protocol"].upper() == "TCP"
                 and r["LocalPort"].lower() == "any"]
    if not tcp_allow:
        return False, "no enabled TCP Allow rule for python inbound"
    profiles = sorted(set(r["Profiles"] for r in tcp_allow))
    return True, "python TCP inbound Allow x{}, profiles={}".format(
        len(tcp_allow), "/".join(profiles))


def main():
    quiet = "--quiet" in sys.argv
    if not quiet:
        print("=" * 72)
        print(" VulnLab network share check")
        print("=" * 72)
        print()
        print("  bind     : {}".format(config.BIND_HOST))
        print("  lan      : {}".format(config.PUBLIC_IP))
        print()

    check("services bind all interfaces",
          config.BIND_HOST == "0.0.0.0",
          config.BIND_HOST)

    lan = config.PUBLIC_IP
    ips = local_ips()
    if not quiet:
        print("  this machine holds: {}".format(", ".join(ips) or "(none found)"))
        print()

    check("lan address is assigned here", lan in ips, lan)

    # The real test of multi-homing: does each service answer on the LAN
    # address as well as on loopback?
    lan_bad, loop_bad = [], []
    for name, port in PORTS:
        if not can_connect(lan, port):
            lan_bad.append("{} :{}".format(name, port))
        if not can_connect("127.0.0.1", port):
            loop_bad.append("{} :{}".format(name, port))
    check("all ports answer on the LAN address", not lan_bad,
          ", ".join(lan_bad) if lan_bad else "{} ports".format(len(PORTS)))
    check("all ports answer on loopback", not loop_bad, ", ".join(loop_bad))

    # A TCP handshake can succeed while nothing ever replies.  Ask each page
    # server for a real page over the LAN address and read the headers back -
    # this is the closest view one machine can get of what a phone sees.
    no_page, stale = [], []
    for name, port, path in PAGE_PORTS:
        status, head = http_probe(lan, port, path)
        if not status.startswith("HTTP/") or " 200" not in status:
            no_page.append("{} {}".format(name, status or "no reply"))
        elif "no-store" not in head.lower():
            stale.append(name)
    check("http pages answer on the LAN address", not no_page,
          ", ".join(no_page) if no_page
          else "{} pages".format(len(PAGE_PORTS)))
    check("pages ship no-store (no stale frames)", not stale,
          ", ".join(stale) if stale else "Cache-Control: no-store present")

    fw_ok, fw_detail = firewall_state()
    check("inbound firewall permits python", fw_ok, fw_detail)

    if not quiet:
        print()
        print("=" * 72)
        print("  EVERYTHING CHECKABLE FROM ONE MACHINE IS CHECKED ABOVE:")
        print("  bind address, LAN address ownership, TCP on 10 ports, real")
        print("  HTTP page loads, no-store headers, inbound firewall rule.")
        print()
        print("  ONE STEP CANNOT BE PROVED FROM HERE: a second device.")
        print()
        print("  Open this on a phone or laptop joined to the same network:")
        print()
        print("      " + config.join_url("/ctf.html"))
        print()
        print("  If that page loads and you can pick a handle, the class can")
        print("  join.  If it times out, the network - not VulnLab - is")
        print("  blocking inbound, and that is a router/AP setting.")
        print("=" * 72)

    print(" {} passed, {} failed".format(len(PASS), len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())