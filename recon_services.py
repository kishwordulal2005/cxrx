"""VulnLab service launcher - starts every non-web service in one process.

==========================================================================
  AUTHORIZED LAB ONLY - vulnerable on purpose.  Do not expose this host.
==========================================================================

    python recon_services.py            # start everything except the web/ctf apps
    python recon_services.py --list     # show the service map and exit
    python recon_services.py --only ftp ssh

Starts, each on 127.0.0.1 unless VULNLAB_BIND says otherwise:

    ftp        :2121   anonymous login, backup archive, hidden directory
    telnet     :2323   management console, weak credentials, config leak
    ssh        :2222   simulated Linux host, SUID / cron / PATH escalation
    smb        :4450   share simulator (see smb/README.md for real Samba)
    debug-lab  :8000   development instance, debugger console
    internals  :8081   hidden service catalogue (recon-02)
    cache      :6379   rabbit hole, deliberately useless
"""
import argparse
import os
import signal
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: E402

SERVICES = {
    "ftp": ("FTP service", config.PORT_FTP),
    "telnet": ("Telnet management console", config.PORT_TELNET),
    "ssh": ("SSH service (simulated Linux host)", config.PORT_SSH),
    "smb": ("SMB share simulator", config.PORT_SMB_SIM),
    "debug-lab": ("Debug-lab (Werkzeug debugger research)", config.PORT_DEBUG),
    "internals": ("Hidden service catalogue", config.PORT_RABBIT2),
    "cache": ("Cache service (rabbit hole)", config.PORT_RABBIT1),
}

ALL = tuple(SERVICES)


def banner():
    print("=" * 66)
    print("  VulnLab services")
    print("  AUTHORIZED LAB ONLY - every service here is vulnerable on purpose")
    print("  bind: {}".format(config.BIND_HOST))
    print("=" * 66)
    for name, (desc, port) in SERVICES.items():
        print("  {:<10} {:<6} {}".format(name, port, desc))
    print("=" * 66)


def start(name):
    """Start one service in a background thread; return the thread or None."""
    if name == "ftp":
        from services import ftp_service
        target = ftp_service.serve
    elif name == "telnet":
        from services import telnet_service
        target = telnet_service.serve
    elif name == "ssh":
        from services import ssh_service
        target = ssh_service.serve
    elif name == "smb":
        from services import smb_service
        target = smb_service.serve
    elif name == "debug-lab":
        from services import debug_lab
        target = debug_lab.serve
    elif name == "internals":
        from services import hidden_services
        target = hidden_services.serve_internals
    elif name == "cache":
        from services import hidden_services
        target = hidden_services.serve_cache
    else:
        raise ValueError("unknown service: " + name)

    def runner():
        try:
            target()
        except Exception as exc:  # noqa: BLE001
            print("  [{}] failed to start: {}".format(name, exc))

    t = threading.Thread(target=runner, name=name, daemon=True)
    t.start()
    time.sleep(0.4)
    print("  [{}] started".format(name))
    return t


def main():
    ap = argparse.ArgumentParser(description="VulnLab service launcher")
    ap.add_argument("--list", action="store_true", help="show the service map")
    ap.add_argument("--only", nargs="*", choices=ALL, help="start a subset")
    args = ap.parse_args()

    banner()
    if args.list:
        return 0

    # One-time bootstrap so every service shares the same lab data on disk.
    import app as target_app
    target_app.bootstrap()
    print("  lab data prepared under {}".format(config.DATA_DIR))
    print("  press Ctrl+C to stop")

    for name in (args.only or ALL):
        start(name)

    stop = threading.Event()

    def shutdown(*_):
        print("\n  stopping services ...")
        stop.set()

    signal.signal(signal.SIGINT, shutdown)
    try:
        signal.signal(signal.SIGTERM, shutdown)
    except (AttributeError, ValueError):
        pass
    while not stop.is_set():
        stop.wait(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())