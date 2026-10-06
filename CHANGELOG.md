# VulnLab changelog

Every change below was made and then **verified by running it**, with the exit
code captured. This file was written first, while the working copy was not yet
a git repository, so it records the reasoning and the proof for each fix. It
stays useful: git history records *what* changed, this records *why it was
changed that way* and *how we know it works*.

## Version control

This directory was **not** a git repository, so there was no diff to review and
no way to see what a given edit had actually touched.

- `git init` here, plus a `.gitignore` that excludes runtime state: `data/`
  (score databases, planted secrets, host keys, student uploads), `logs/`, PID
  files, `__pycache__` and `.freebuff/`.
- **52 source files** are now tracked: application code, services, challenge
  and flag content, templates, static assets and the verification tools.
- Verified that no secret or runtime artifact is staged - a grep of the staged
  file list for `secret|flagfile|.pem|.db|_rsa|.log` returns nothing.

The initial commit has not been made, so run `git commit` when you are ready;
`git diff --cached --stat` right now shows exactly what would be recorded.

---

## Classroom sharing (players join over the LAN)

**Problem.** Every service bound `127.0.0.1`, so only the instructor's own
machine could reach the lab. Students could not join or sign up.

- `config.py`
  - `BIND_HOST` now defaults to `0.0.0.0`. `VULNLAB_BIND=127.0.0.1` restores
    solo-only behaviour.
  - New `lan_ip()` picks the address the OS would actually route through, so
    it reports the Wi-Fi address rather than a VMware/WSL adapter. It sends no
    packets - it only consults the routing table.
  - New `PUBLIC_IP` and `join_url()`.
  - New `CONNECT_HOST` for where local tools *dial*. `0.0.0.0` is a valid
    listen address but a poor destination.
  - `TARGET_HOST` defaults to `PUBLIC_IP` instead of `127.0.0.1`.
- `app.py` - `/ctf.html` and `/ctf` redirect to `PUBLIC_IP`, not `BIND_HOST`
  (`0.0.0.0` is not something a browser can open).
- `scoreboard.py` - serves `ctf.html` through a placeholder substitution so the
  LAN address is baked in: `{{LAN_IP}}`, `{{JOIN_URL}}`, `{{TARGET_URL}}`.
- `web/ctf.html` - added a "SHARE THIS ADDRESS WITH YOUR TEAM" panel; the
  Target/Portal readouts show the LAN address.
- All four tools now connect through `CONNECT_HOST`.

**Verified:** all 10 ports listening on `0.0.0.0`; every port answers on both
loopback and the LAN address; registration over the LAN address returned a
working token and the player appeared on the board; the same flow driven
through a real browser.

Note the LAN address changed between runs (`192.168.1.9` -> `.10`) because of
DHCP. That is why the address is detected at runtime rather than hardcoded.

---

## Fake hacker rows on the leaderboard and live feed

Three independent bugs, only the first of which was obvious.

1. **Teardown silently never worked.** It ran `DELETE FROM hint_used`, but the
   table is named `hints_used`. That raised `sqlite3.OperationalError`, which
   was caught by a bare `except sqlite3.Error: pass`, so the transaction was
   never committed. Bots accumulated while the log looked successful.
   - `config.py` - child tables are now discovered with `PRAGMA table_info`
     rather than hardcoded, so a typo cannot abort the cleanup again.
2. **The filter was too narrow.** Only `verifier_` was filtered, leaving 15
   older `verify_resume_*` players visible on the public board.
   - `config.py` - `BOT_HANDLE_PREFIXES = ("verifier_", "verify_")` and
     `bot_handle_patterns()`, one list feeding both the queries and teardown.
   - `scoreboard.py` - both `_leaderboard_rows` and `/api/feed` use a shared
     `BOT_NOT_BOT_CLAUSE`.
3. **The `ESCAPE '\'` backslash kept getting mangled** by shell heredocs
   (`"\_"` instead of `"\\"`). The pattern is now built from `chr(92)`, which
   cannot be eaten by a shell.

**Verified:** 0 bot rows on the board and in the feed, before and after
teardown. The checks were proven to have teeth by deliberately breaking the
filter and confirming the suite fails (exit 1) and names the leaked handle.

That validation exposed a defect in the new test itself: the throwaway handle
was 27 characters against a 24-character registration limit, so registration
400'd and the "bot is hidden" assertion passed **vacuously**. Fixed by
shortening the handle and adding a control player, so a broken query can no
longer pass by returning an empty board.

**One assertion was deliberately inverted.** `verify_all` previously required a
`verifier_*` handle to *appear* on the public leaderboard, which directly
contradicts hiding bots. It now asserts the opposite: that the run which just
solved all 123 challenges does not leak onto the board.

---

## Portal giveaway

- `web/ctf.html` - removed the "Open the target console at ..." note. It is
  absent from every file in the repo, and a check now guards it.

---

## Cross-platform correctness

- **XXE probe.** `xxe-01` was hardcoded to `file:///C:/Windows/win.ini`, which
  makes the check unverifiable off Windows.
  - `config.py` - new `xxe_probe_file()` / `xxe_probe_uri()` plant a lab-owned
    probe file with a known marker, and build the URI with
    `pathlib.Path.as_uri()`.
  - `tools/verify_all.py` - asserts the marker actually appears in the
    response, rather than merely that no error was returned.
- **SSH key claim.** `os.link` is atomic but unavailable on some filesystems.
  - `config.py` - falls back to `os.open(..., O_CREAT|O_EXCL)`, which carries
    the same exclusivity guarantee.
- `xxe-01` also required `feature_external_ges` only; expat rejects
  `feature_external_pes`.

---

## Real-browser XSS verification

Previously xss-02 was only proven interactively; the automated suite checked
the sink text and the beacon over HTTP, which cannot show the payload ran.

- `tools/verify_all.py` - new `browser_checks()` drives headless Chrome via
  selenium, navigates the DOM-XSS page with an `<img onerror>` payload that
  rewrites `document.title`, and asserts the title changed. That can only
  happen if the injected script really executed in a real engine.
  - Skips loudly (never silently passes) when selenium or a driver is absent.
  - **Verified:** title becomes `XSS-EXECUTED`. A negative control - the same
    payload on a page with no sink - does not execute, so the check has teeth.

---

## New tooling

- **`start_lab.py`** - one command to bring the lab up. Freebuff restarts kill
  the background servers, which was the most recurring annoyance.
  `python start_lab.py` starts everything, waits until every port actually
  answers, prints the join URL, and exits non-zero if anything failed to come
  up. Also `--status`, `--stop`, `--restart`, `--wait-only`. Idempotent.
  - Each child is launched with `CREATE_NEW_PROCESS_GROUP`, which detaches it
    from the launching shell. **Verified:** the lab was started at 08:25:39,
    Freebuff restarted, and at 08:43 the same processes were still serving all
    ten ports and answering the full verification suite. Restarting Freebuff
    no longer takes the lab down.
  - `--stop` filters `python.exe` by working directory, so it stops VulnLab
    without killing unrelated Python processes.
  - Logs land in `logs/`, one file per service.
- **`tools/check_network.py`** - proves everything about sharing that can be
  checked from one machine: binds `0.0.0.0`, every port answers on both the LAN
  address and loopback, the LAN address is actually assigned, and the inbound
  firewall has an enabled **TCP** Allow rule. Prints the URL to open on a phone
  for the one step a single machine cannot prove.
  - Parses `netsh advfirewall` by locating each `Rule Name:` marker rather than
    splitting on blank lines, because `netsh dir=in` emits CRLF and a blank-line
    split silently finds no rules at all - a check that always passes.
  - Requires `Protocol == TCP` specifically; Windows carries UDP python rules
    too, and matching either would pass on the wrong one.
- **`config.remove_player()`** - delete one player and everything they earned.
  Useful for a mistaken registration, and for removing the control player the
  portal checks create.
- **`config.reset_player_state()`** - shared by every tool; also clears doors,
  uploads and planted cache.

## Instructor

- `instructor/reset_lab.py` gained `--doors` (included in `--everything`).

---

## Frontend: making it look like a real product

**Problem.** The target at `:5000` read as a hacker toy - neon terminal
styling, monospace everywhere, and a card grid of "Quick links" / "Service
status" / "Policy" blocks that no real site ships. Students are supposed to
believe they are attacking a real website, so the site had to look like one.
The CTF portal at `:9090` had the same problem plus a structural one: the
"SHARE THIS ADDRESS" panel sat *above* the brand bar on every tab.

### `static/css/portal.css` - new design system for the `:5000` target

- Token-based (`:root` variables for surfaces, text, borders, brand) so a
  second theme is a variable override rather than a second stylesheet.
- Components: nav, breadcrumbs, page header, cards, stat tiles, key/value
  rows, tables, forms, chips, notices, footer, auth layout.
- `.site` re-themes on scope by overriding the same tokens - which is how all
  five interior pages were switched to the light theme with a one-attribute
  change (`<body class="site">`) instead of five copies of the rules.

### `web/index.html` - rebuilt as a product marketing site

Announcement bar, sticky nav, hero with a terminal "product shot", logo strip,
six-card feature grid, metrics band, quote, CTA panel, five-column footer.
The four content cards you rejected are gone entirely - verified absent from
the *served* response, not just from the file.

**Constraints preserved:** the `VULNLAB{view_source}` comment (`web-02`),
the `/api-docs` link (suite requirement), and the absence of `GET /api/v1`
(the suite asserts the homepage does not enumerate API routes). All 14 links
return 200; all four `#anchor` links resolve to real ids.

### `static/css/ctf.css` + `web/ctf.html` - rebuilt as a dashboard

- App bar with seven labelled stat cells; the old markup let `0 / 123` and
  `YOUR SCORE` overlap.
- System sans-serif for UI, mono reserved for flags/IDs/code.
- Share panel moved **into the registration gate** - visible on first arrival,
  gone once logged in (`share_over_header: false`).
- Ring SVG kept at `r="60"` / `dasharray="377"` on purpose: `ctf.js` computes
  `377 - 377 * pct`, so the radius is a JS contract. I resized it once, saw the
  arc break, and reverted; the file now carries a comment saying why.
- A header lists every id and class `ctf.js` drives, so a cosmetic rename
  cannot silently break the portal while an HTTP check still passes.

### Interior pages: `/login` `/api-docs` `/admin` `/upload-page` `/profile`

All five got `<body class="site">` and now render light (`rgb(255,255,255)`),
matching the homepage. Functionality re-tested in a real browser afterwards:
login posts and returns `invalid credentials`; admin's gate toggles and its
session fetch fills; upload's handler returns `pick a file first`; api-docs
renders 3 tables. None had a code fault to begin with - it was styling only.

---

## Two real bugs found while fixing the frontend

### 1. `web/profile.html` was dead code

Zero references anywhere in the repo. Editing it did nothing. `/profile` is
served by `app.py` and **is** the SSTI sink, so it returned a bare unstyled
fragment - and the homepage footer linked `/profile?name=guest`, which
rendered literally the text `guest`.

- `app.py` - the **no-args** default response is now a styled page. The moment
  `name` or `tpl` arrives, `src` is the caller's template source and the
  response stays raw, because wrapping it would break the sink: the whole point
  is that the body *is* the compiled attacker input.
- `web/index.html` - footer links `/profile`, not `/profile?name=guest`.
- Verified after the change: `?name={{7*7}}` -> `49`, `?name=guest` -> `guest`,
  bare `/profile` -> styled page. `flask-01` and `flask-02` still pass.

The unused file was deleted once its zero references were confirmed across
the whole repo (including this one).

### 2. `start_lab.py --stop` and `--restart` were completely broken

They shelled out to **`wmic`, which does not exist on this machine**, so both
flags died with `FileNotFoundError`. Behind that first failure sat a second one:
`subprocess.call(..., capture_output=True)` raises `TypeError` - `capture_output`
is a `subprocess.run` argument. The original line was dead code that `wmic`
happened to mask. **An earlier note in this file claimed `--stop`/`--restart`
worked; only `--status` and start had actually been exercised.**

- `start_lab.py` - `_lab_pids()` now walks `psutil`, which also avoids parsing
  command output entirely (the same bug class as reading `netsh` on CRLF).
  Falls back to `tasklist` CSV without psutil, and to `pkill` on POSIX.
  Excludes its own PID and any `start_lab` process so it can never kill itself.
- `requirements.txt` - added `psutil>=5.9`.
- Verified end to end: `--stop` killed 4 processes (exit 0) and all ports went
  down; `--status` on the dead lab returned **exit 1**; `--start` returned
  **exit 0**; `--restart` returned **exit 0**. PID discovery was dry-run first
  and found exactly the four lab services.

---

## Verification run

Everything below was re-run together after the fixes landed, so the suites are
known to pass as a set rather than one at a time.

| Suite | Result | Exit |
| --- | --- | --- |
| `tools/verify_all.py` | 132 passed, 0 failed | 0 |
| `tools/verify_challenges.py` | 31 passed, 0 failed | 0 |
| `tools/check_services.py` | 32 passed, 0 failed | 0 |
| `tools/check_simshell.py` | full boot-to-root chain, 3 routes | 0 |
| `tools/check_network.py` | 5 passed, 0 failed | 0 |
| `start_lab.py --stop` -> `--status` -> `--start` | stop 0, status 1 (dead), start 0 | see left |
| ports on `192.168.1.10` | 10 / 10 accepting | - |

Everything was re-run **after** the `app.py` and `start_lab.py` edits landed;
the earlier passes do not cover them. Suites must not be run concurrently -
they share one SQLite database, and running `verify_all` and
`verify_challenges` in parallel produced two spurious failures.

The three failures from a previous combined run - `xxe-01 external entity
read`, `portal feed endpoint` and `portal feed names challenge and points` -
are fixed and pass inside the full suite, not just in isolation.

## Known limitations

- **Cross-device reachability is still not proven, and cannot be from one
  machine.** The firewall rules were confirmed by configuration (`netsh`:
  three enabled TCP inbound Allow rules for `python.exe` on the Public
  profile), not by connecting from a phone. This is the one claim no amount of
  local testing can close.
  - `python tools/check_network.py` closes everything short of that last step:
    bind address, LAN address ownership, TCP on all 10 ports, a **full HTTP
    page load over the LAN address** (a bare TCP handshake would pass even if
    nothing replied), the `no-store` header on every page, and the firewall
    rule. It prints the URL to open on a real client. If that page loads, the
    class can join; if it times out, the block is the network, not VulnLab.
- Verification still runs on **Windows only**. The Windows-only assumptions in
  the code are gone - the XXE probe is a lab-owned file instead of
  `win.ini`, and `os.link` has an `O_CREAT|O_EXCL` fallback - but the suite
  has only ever been executed on Windows, so Linux behaviour is untested
  rather than known-good.
- The lab is intentionally vulnerable and now listens on the LAN. Only run it
  on a trusted classroom network; never port-forward it.
- **`web/profile.html` was unused and has been deleted.** Nothing served it;
  `/profile` comes from `app.py`.
- **The preview panel served stale frames throughout the frontend work** -
  it showed the previous page while the tab title showed the current one, so
  every visual claim was verified through headless-Chrome computed styles and
  DOM probes rather than screenshots. **Fixed:** `app.py`, `scoreboard.py` and
  `waf_gate.py` now send `Cache-Control: no-store` on every HTML page and
  `/static` asset, so no browser or preview pane can hold a previous frame.
  API/JSON responses were left alone so challenge behaviour is unchanged, and
  `tools/check_network.py` now asserts the header is actually present.
- **No git history existed** when this work started; see "Version control"
  above. The initial commit has not been made - `git diff --cached --stat`
  shows what would be recorded.