"""One command to bring the whole lab up and hand out the join URL.

Every Freebuff restart kills the background servers, which is the single most
annoying thing about this lab.  This does the boring part: start everything,
wait until every port actually answers, then print the address to give the
class.

    python start_lab.py              # start (no-op if already running)
    python start_lab.py --status     # report what is up, start nothing
    python start_lab.py --stop       # stop everything it started
    python start_lab.py --restart    # stop, then start
    python start_lab.py --wait-only  # wait for an already-running lab

Exit code is 0 only when every service came up, so it is safe to chain.
"""
import argparse
import os
import socket
import subprocess
import sys
import time

import config

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(HERE, "logs")

SERVICES = ("recon_services", "app", "waf_gate", "scoreboard")

# Everything a student can touch, and the two rabbit holes.
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


def port_open(port, host=None, timeout=1.5):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host or config.CONNECT_HOST, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def wait_ready(ports=PORTS, deadline=45.0, host=None):
    """Block until every port answers.  Returns the ones that never came up."""
    end = time.time() + deadline
    pending = list(ports)
    while pending and time.time() < end:
        pending = [p for p in pending if not port_open(p[1], host)]
        if pending:
            time.sleep(0.4)
    return pending


def _tail(path, lines=12):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return "".join(fh.readlines()[-lines:]).strip()
    except OSError:
        return ""


def start():
    os.makedirs(LOG_DIR, exist_ok=True)
    running = [name for name, port in PORTS if port_open(port)]
    if len(running) == len(PORTS):
        print(" lab already running ({}/{} ports up)".format(len(running), len(PORTS)))
        return []
    started = []
    for name in SERVICES:
        script = os.path.join(HERE, name + ".py")
        if not os.path.isfile(script):
            continue
        log = open(os.path.join(LOG_DIR, name + ".log"), "a", encoding="utf-8")
        subprocess.Popen(
            [sys.executable, script],
            cwd=HERE,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            # Own process group: stopping the lab stops the children too, and a
            # Freebuff restart does not leave orphans holding the ports.
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        log.close()
        started.append(name)
        print("  started {:<16} -> logs/{}.log".format(name, name))
    return started


def _lab_pids():
    """PIDs of python processes running scripts from this directory.

    Built on psutil rather than shelling out to `wmic`, because `wmic` no
    longer ships with Windows and its absence used to crash `--stop` and
    `--restart` with FileNotFoundError.  psutil also avoids parsing command
    output, which is the same class of bug as reading `netsh` on CRLF.
    """
    me = os.getpid()
    here = os.path.abspath(HERE).lower()
    pids = []
    try:
        import psutil
    except ImportError:
        return None  # caller falls back to tasklist
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if proc.info["pid"] == me:
                continue
            name = (proc.info.get("name") or "").lower()
            if name not in ("python.exe", "pythonw.exe", "python", "python3"):
                continue
            cmd = " ".join(proc.info.get("cmdline") or [])
            if not cmd:
                continue
            if here not in os.path.abspath(cmd.split()[0]).lower():
                if here not in cmd.lower():
                    continue
            if "start_lab" in cmd.lower():
                continue  # never kill the launcher itself
            pids.append(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return pids


def _lab_pids_tasklist():
    """Fallback when psutil is unavailable: parse `tasklist` CSV."""
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq python.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True,
        ).stdout
    except OSError:
        return []
    pids = []
    for line in out.splitlines():
        parts = line.strip().strip('"').split('","')
        if len(parts) >= 2 and parts[1].isdigit():
            pids.append(int(parts[1]))
    return pids


def stop():
    """Kill python processes running this lab, leaving other work alone."""
    pids = _lab_pids()
    if pids is None:
        if os.name != "nt":
            subprocess.call(["pkill", "-f", os.path.join(HERE, "")])
            return
        pids = _lab_pids_tasklist()
    killed = 0
    for pid in pids:
        if os.name == "nt":
            argv = ["taskkill", "/F", "/PID", str(pid)]
        else:
            argv = ["kill", "-9", str(pid)]
        # subprocess.run, not .call: .call has no capture_output, which is why
        # the original line raised TypeError once wmic stopped masking it.
        try:
            rc = subprocess.run(argv, capture_output=True).returncode
        except OSError:
            continue
        if rc == 0:
            killed += 1
    print("  stopped {} process(es)".format(killed))


def banner(ok):
    line = "=" * 62
    print(line)
    if ok:
        print("  VulnLab is up.")
        print()
        print("  Give the class this:")
        print()
        print("      " + config.join_url("/ctf.html"))
        print()
        print("  Target they attack:")
        print()
        print("      http://{}:{}".format(config.PUBLIC_IP, config.PORT_WEB))
        print()
        print("  bind {}   lan {}   mode {}".format(
            config.BIND_HOST, config.PUBLIC_IP, config.DIFFICULTY))
    else:
        print("  VulnLab did NOT fully start.  See logs/*.log")
    print(line)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stop", action="store_true")
    ap.add_argument("--restart", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--wait-only", action="store_true")
    ap.add_argument("--timeout", type=float, default=45.0)
    args = ap.parse_args()

    if args.stop:
        stop()
        return 0

    if args.restart:
        stop()
        time.sleep(1.5)

    if args.status or args.wait_only:
        pending = wait_ready(deadline=1.0 if args.status else args.timeout)
        for name, port in PORTS:
            print("  {:<12} :{:<6} {}".format(
                name, port, "up" if not any(p[1] == port for p in pending) else "DOWN"))
        banner(not pending)
        return 0 if not pending else 1

    started = start()
    pending = wait_ready(deadline=args.timeout)
    if pending:
        print()
        print(" these never came up:")
        for name, port in pending:
            log = os.path.join(LOG_DIR, name + ".py".join(("", ".log")))
            tail = _tail(log)
            print("   :{} {}\n{}".format(port, name, tail))
    banner(not pending)
    return 0 if not pending else 1


if __name__ == "__main__":
    sys.exit(main())