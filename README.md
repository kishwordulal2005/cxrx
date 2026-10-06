# VulnLab — Boot-to-Root CTF Lab

> **AUTHORIZED LAB ONLY**
>
> This system intentionally contains vulnerable services and applications for
> cybersecurity education. Do not expose this machine directly to the public
> Internet.

A self-contained, deliberately vulnerable Boot-to-Root machine for teaching the
full path:

```
Recon → Enumeration → Service ID → Vulnerability Discovery → Exploitation
      → Credential Discovery → API Attacks → Web Attacks → Lateral Movement
      → Privilege Escalation → Root
```

**123 challenges · 15,375 points · 26 categories · 3 independent initial-access
routes · 3 privilege-escalation routes · 1 root objective.**

No Docker, no Kubernetes, no Node. Python 3, Flask, SQLite, vanilla JS, Python
sockets and Paramiko.

---

## Quick start

```bash
python -m pip install -r requirements.txt

python start_lab.py       # starts every service, waits for all 10 ports, prints the join URL
```

`start_lab.py` launches `app.py`, `waf_gate.py`, `scoreboard.py` and
`recon_services.py` for you and does not return until all ten ports actually
answer. Each service is detached, so it **survives a restart of whatever
terminal or editor started it** — you will not come back to a dead lab.

```bash
python start_lab.py --status    # is it up?
python start_lab.py --restart   # bounce it
python start_lab.py --stop      # stop only VulnLab, not other python processes
```

Then open the URL it prints, enter a handle, and start. On a classroom
network that is your LAN address, not `127.0.0.1`:

```
http://192.168.1.x:9090/ctf.html     <- students join here
http://192.168.1.x:5000              <- the machine they attack
```

The address is detected at runtime and changes with DHCP, so read it off the
screen rather than typing it from memory. Students can register and sign up
from any device on the same network.

Reset the lab at any time with:

```bash
python instructor/reset_lab.py --everything
```

---

## Service map

| port | service | what it teaches |
| ---: | --- | --- |
| 5000 | Flask web + API | web, API, GraphQL, upload, crypto, Flask RCE |
| 5050 | WAF gate | 403 bypass, header trust, method confusion, parser mismatch, double decode |
| 9090 | CTF scoreboard | challenges, hints, leaderboard, achievements |
| 2121 | FTP | anonymous login, backup archive, hidden directory |
| 2323 | Telnet | weak console credentials, config disclosure, length crash |
| 2222 | SSH | simulated Linux host, SUID / cron / PATH escalation |
| 4450 | SMB simulator | share enumeration, null session, hidden share |
| 8000 | debug-lab | Werkzeug debugger exposure and PIN console |
| 8081 | internals | hidden service catalogue (`recon-02`) |
| 6379 | cache | rabbit hole — deliberately yields nothing |

Ports 2121 / 2323 / 2224 / 4450 are deliberately non-standard so the lab never
fights with services already on an instructor's workstation. Note that **22 is
not SSH, 21 is not FTP, 23 is not Telnet** here — identifying the real service
is part of the exercise.

---

## The three ways in

### Route 1 — Network and services

```
nmap  →  :2121 FTP anonymous  →  backup.zip
      →  credentials.old + employee_notes.txt
      →  telnet console :2323 (admin / S3cureSwitch!)
      →  show config  →  SMB :4450 + SSH :2222 credentials
```

### Route 2 — Web and API

```
/robots.txt  →  /admin-old, /private, /debug-old
/            →  HTML comment (view source)
/.git/       →  reflog with the removed DEBUG commit
/config.bak  →  SECRET_KEY, JWT_SECRET, RESET_SALT, INTERNAL_API_KEY
/static/leaks/*  →  flask_settings.py, cache_backend.py, app.js
      →  forge the Flask session  →  /admin
      →  forge an admin JWT       →  /api/v1/admin/export
```

### Route 3 — Flask RCE (the mandatory module)

Three primitives reach the same Python runtime:

| door | technique | CWE |
| --- | --- | --- |
| `/profile?name=` | Jinja2 server-side template injection | CWE-1336 |
| `:8000/debug-lab/console` | Werkzeug debugger with a derived PIN | CWE-489 |
| `/api/v1/cache/get?key=` | pickle deserialization (CVE-2021-33026) | CWE-502 |

Any of them yields code execution, which reads
`data/secrets/svc_flask.creds` and logs into SSH:

```
Flask RCE  →  svc_flask:VLsvc_flask_2019!  →  ssh -p 2222 svc_flask@<lab-ip>
                                                (MOTD carries boot-01)
```

`flask-boss` unlocks after solving **two** of `flask-02`, `flask-06`,
`flask-12`. Each successful exploit records a door on disk, and
`GET /flask-boss` reports the tally and discloses the boss flag at two doors,
so the challenge is solvable from lab interaction alone rather than by guessing.
The point of the three doors is that they are different bugs but the runtime
behind them is the same.

### Getting to root

```
SSH shell  →  id / uname / sudo -l / crontab -l / env / find
          →  /opt/vulnlab/README.local          (linux-01, gates ROOT)
```

Then pick any of three routes:

| route | how |
| --- | --- |
| **SUID** | `find / -perm -4000` → `vulnhelper --read /root/suid.flag` |
| **Writable cron script** | `sudo -l` → `sudo /opt/vulnlab/maintenance.sh` (world-writable, run as root) |
| **PATH hijack** | `/etc/cron.d/vulnlab` runs `lab-tick`, which calls bare `log-cleaner` with `/opt/vulnlab/bin` on PATH |

`cat /root/root.txt` requires `linux-01` first, enforced by both the shell and
the scoreboard.

---

## Flask RCE module in detail

| id | challenge | pts |
| --- | --- | ---: |
| flask-01 | SSTI detection — `{{7*7}}` returns 49 | 75 |
| flask-02 | Jinja runtime escape — read `ssti.flag` | 150 |
| flask-03 | SSTI filter failure — a blacklist is not a sandbox | 125 |
| flask-04 | Debug mode exposed on `:8000` | 75 |
| flask-05 | Debugger PIN investigation | 150 |
| flask-06 | Debug console — read `debugger.flag` | 200 |
| flask-07 | Weak application secret | 100 |
| flask-08 | Session integrity — forge the admin cookie | 175 |
| flask-09 | Cache identification | 75 |
| flask-10 | Pickle discovery | 125 |
| flask-11 | Cache architecture | 100 |
| flask-12 | Unsafe deserialization | 175 |
| flask-13 | CVE-2021-33026 (research answer) | 100 |
| flask-14 | Controlled RCE — read `rce.flag` | 250 |
| flask-boss | Three doors — solve two | 500 |

The defense half is in `instructor/answer_key.md`: never build templates from
attacker-controlled strings, never ship a development debugger, never
deserialize untrusted pickle, and use a strong unpredictable secret.

## Web exploit module — request forgery, header abuse, injection

Most of the lab is about what the *application* does with input. This module
([api/webexploits.py](api/webexploits.py)) is about what the *transport* lets
an attacker control: who is asking, which host they claim to be, and what ends
up in a response header.

| id | challenge | CWE | pts |
| --- | --- | --- | ---: |
| csrf-01 | Forged role change — no CSRF token | CWE-352 | 100 |
| csrf-02 | Origin check that only runs when present | CWE-346 | 100 |
| host-01 | Password-reset link poisoned via Host | CWE-644 | 125 |
| host-02 | X-Forwarded-Host wins over the real host | CWE-441 | 100 |
| resp-01 | CRLF response splitting (`/legacy/go`) | CWE-113 | 150 |
| redir-01 | Protocol-relative open redirect | CWE-601 | 75 |
| sqli-01 | Blind injection via the X-Rows header | CWE-89 | 150 |
| sqli-02 | Second-order injection (store, then trigger) | CWE-89 | 200 |
| cmdi-01 | Command injection in the ping diagnostic | CWE-78 | 175 |
| xxe-01 | XML external entity file read | CWE-611 | 150 |
| race-01 | Single-use token pays out twice | CWE-362 | 150 |
| admin-01 | Admin console trusts X-Forwarded-For | CWE-290 | 125 |

`resp-01` is served by `RawRedirectMiddleware` in [app.py](app.py) rather than
a view. That is deliberate: Werkzeug rejects newline characters in header
values, so the only way to reproduce a real split is the way it happens in the
wild — a legacy handler that writes its own HTTP response and hands the headers
straight to the socket. The verification reads the response over a raw socket
to confirm the smuggled `X-Injected` header is really on the wire.

---

## Layout

```
vulnlab/
├── start_lab.py         start / status / restart / stop for every service
├── app.py               vulnerable Flask web + API target   :5000
├── waf_gate.py          broken filtering layer             :5050
├── scoreboard.py        CTF portal + scoreboard           :9090
├── recon_services.py    launcher for every other service
├── config.py            ports, bind/LAN detection, mode, secrets, flag helpers
├── database.py          scoreboard schema + target dataset
├── api/                 users / auth / admin / files blueprints
├── services/            ftp / telnet / ssh / smb / debug-lab / hidden
├── web/                 index, login, admin, api, upload, ctf, domxss
├── static/              css, js, leaks/ (developer source leaks)
├── data/                users.db, scoreboard.db, uploads, backups, smb, ...
├── flags/flags.json     124 flags and research answers
├── hints/challenges.json 123 challenges, 3 hints each
├── instructor/          answer_key.md, scoring.md, reset_lab.py
├── logs/                one log per service, written by start_lab.py
├── smb/README.md        how to run real Samba instead of the simulator
└── tools/               verify_all.py, verify_challenges.py, check_services.py,
                         check_simshell.py, check_network.py
```

---

## Safety

- Services bind `0.0.0.0` by default so a class can join, which means the
  lab **is** reachable from your network. Set `VULNLAB_BIND=127.0.0.1` to put
  it back behind loopback when you are working alone. Only share it on a
  network you trust; never port-forward it.
- **The SSH service never touches the real filesystem.** SUID binaries, a cron
  spool and root-owned files exist only in an in-memory model, so running the
  lab can never create privilege escalation material on the host machine.
- The pickle challenge is *controlled*: the payload's output is captured and
  returned in the response so the effect is visible.
- All credentials, keys and flags are fake lab values.

| variable | default | meaning |
| --- | --- | --- |
| `VULNLAB_BIND` | `0.0.0.0` | bind address; set `127.0.0.1` for solo work |
| `VULNLAB_MODE` | `INTERMEDIATE` | `BEGINNER` / `INTERMEDIATE` / `HARD` / `INSANE` |
| `VULNLAB_TARGET` | detected LAN address | host advertised in banners and the portal |
| `VULNLAB_INSTRUCTOR_KEY` | `vl-instructor-9090` | `/instructor` key |
| `VULNLAB_FLAG_DIR` | `data/flagfiles` | where flag files live |

---

## Instructor tools

```bash
python instructor/reset_lab.py --check        # report state
python instructor/reset_lab.py                # rebuild lab data, keep scores
python instructor/reset_lab.py --everything   # full clean slate
python instructor/build_answer_key.py          # regenerate answer key + scoring
python instructor/reset_lab.py --check        # then read instructor/answer_key.md
```

Instructor panel: <http://<your-lan-ip>:9090/instructor?key=vl-instructor-9090>

## Verifying the lab

```bash
python tools/verify_all.py        # web + API + Flask + WAF + services + scoreboard + real browser
python tools/check_services.py    # services only, over real sockets
python tools/verify_challenges.py # CVE answers + flag delivery paths + coverage gate
python tools/check_simshell.py    # simulated SSH shell, offline
python tools/check_network.py     # before class: can devices actually reach it?
```

`verify_all.py` drives real Chrome via selenium to prove the DOM-XSS payload
actually executes, rather than only that the sink is present. It needs
`pip install selenium`; without it that check skips loudly instead of passing
quietly.

`check_network.py` is the one to run on the day. It checks that every port
answers on your LAN address *and* on loopback, and that Windows has an enabled
inbound **TCP** Allow rule for python — then prints the URL to open on a phone
for the final step it cannot prove alone.

## Notes

- `data/users.db` is re-seeded on every start, so a stale database can never
  drift from `database.py`.
- Flag files live in `data/flagfiles` (or `/opt/vulnlab/flags` on a Linux lab
  VM) and are what the SSTI, debugger and pickle challenges read.
- FTP `backup.zip` is a real zip — download it and extract it.

## XSS module — stored, DOM-based and attribute contexts

[api/xss.py](api/xss.py) covers the contexts reflection cannot. `web-08` is
still the reflected case in a text context.

| id | challenge | CWE | pts |
| --- | --- | --- | ---: |
| xss-01 | Stored XSS in a public notice board | CWE-79 | 150 |
| xss-02 | DOM-based XSS — the sink is client-side | CWE-79 | 175 |
| xss-03 | Stored XSS in an HTML attribute context | CWE-79 | 200 |

`xss-02`'s sink lives in [web/domxss.html](web/domxss.html): it decodes
`location.hash` and writes it to `innerHTML`, then beacons
`/api/v1/xss/beacon`. A server cannot see JavaScript execute, so the beacon is
the proof that the sink ran — reaching it *means* the script executed. The
verification suite goes one step better and drives headless Chrome, asserting
that the payload really changed the page title.

## Student portal

[web/ctf.html](web/ctf.html) requires a handle before anything else is
available. Registration is a **resume, not a one-shot**: entering an existing
handle re-issues a token for the same player, so clearing cookies or switching
browsers never costs a student their score, rank or badges.

The dashboard polls the portal every few seconds and shows, live:

- **YOUR STANDING** — rank, score, flags, and whether you moved up or down
- **LIVE SOLVE FEED** — who solved what and for how many points, newest first
- the full leaderboard and per-category completion

`GET /api/feed` backs the feed. It exposes handles, challenge names and
points only — never a flag.
