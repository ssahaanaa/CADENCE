# CADENCE Console

A shared dashboard for finding weak cryptography, mapping enterprise
dependencies, and planning a safer post-quantum migration. Click **Run scan**
(or configure a schedule) to scan an authorized target and share the latest
results with your team.

Live findings always come from a completed scan of a configured source path,
GitHub org, or authorized domain. The dependency graph loads an editable
enterprise-architecture template from `cadence_module2/enterprise_architecture.json`;
replace its example systems, file ownership mappings, and links with the
organization's verified architecture before relying on production priorities.

## The workflow

CADENCE combines three user-facing capabilities: cryptographic discovery,
enterprise dependency mapping, and migration planning. The web console runs
the analysis pipeline and stores each scan as a separate snapshot. The
frontend is plain HTML, CSS, and JavaScript, with no build step or CDN.

The dependency view models enterprise systems and their configured
service-to-service links. Scanner findings are rolled up using the file-to-
system ownership map in the architecture JSON; unowned findings remain
separate rather than being attributed to an unrelated service. The full
enterprise graph informs dependency centrality, while each run's roadmap
contains only systems with findings from that run. Clean systems remain in
the graph as architecture context, not as placeholder remediation tasks.

## Solutions: how to actually migrate

The **Solutions** page turns the roadmap into work. For every system in
the migration plan it gives you:

- **What to change**: each weak algorithm mapped to its replacement, with
  a plain-English explanation, the real risk (broken today, broken by a
  quantum computer, or both), pitfalls, and the file and line it was
  found at.
- **A phased plan** (Prepare, Fix now, Deploy PQC, Validate and retire)
  with checkboxes. Ticks are stored in SQLite for the selected scan and shared
  by the team; a new scan starts with fresh checklist progress.
- **Code before and after** in Python, Java, JavaScript and proxy/TLS
  config, with the language picked from the files the scan found. Supported,
  high-confidence hash/RSA findings have individual fix actions and a
  **Fix entire file & download** action for the exact mapped source file.
- **How to verify**: commands and the output to expect.
- **What gets bigger**: exact NIST key, signature and TLS handshake size
  changes for the selected security level.
- **Standard / High assurance** (CNSA 2.0 aligned) switch, an **algorithm
  guide** for everything CADENCE knows how to fix, a short **PQC primer**,
  and **Markdown export** of any plan for tickets.

It is deliberately honest about what is and isn't a post-quantum problem.
MD5, SHA-1, DES, RC4, SSLv3 and TLS 1.0/1.1 are broken by ordinary attacks
and are fixed with SHA-256, AES-256-GCM and TLS 1.3 (labelled *fix first*).
Only public-key uses (RSA, ECDSA, ECDH, DH) get an ML-KEM, ML-DSA or
SLH-DSA swap, and key exchange is recommended as a hybrid with X25519.

Two limits to be aware of: the scanner only flags RSA below 2048 bits, so
strong RSA and ECC (still quantum-vulnerable) don't appear as findings;
track them through the CBOM. And RSA findings only carry a key size, so the
plan shows both the signature and key-exchange replacements and you pick by
how the key is used. Run `python cadence_module3/test_solutions.py` for the
solution-catalog checks, `python -m unittest backend.test_repository_migrator` for
repository migration safety checks, `python -m unittest backend.test_fix_now` for
scan-bound file download/validation behavior, `python -m unittest backend.test_run_isolation`
for run-scoped data and checklist persistence, `python -m unittest backend.test_config_currency`
for one-time currency conversion, and `node frontend/test_zero_findings.js` to
verify clean-scan empty states.

**Fix now** is limited to supported Python/Java/JavaScript source patterns in
the selected successful scan. The individual action changes only its selected
finding; **Fix entire file** applies every current high-confidence finding in
that exact file that CADENCE can safely rewrite. The download notice reports
how many findings still need manual work, and those lines are not silently
changed. CADENCE rechecks that the file belongs to the selected run and remains
under the configured local source folder, then validates the output syntax and
post-edit crypto scan. The original is never overwritten. Cipher-mode, TLS,
configuration, low-confidence, GitHub-clone, and domain/host findings stay
manual; use **Migrate repository** for an uploaded repository copy when
appropriate.

API: `GET /api/solutions?run_id=&profile=standard|high`,
`GET /api/solutions/catalog`, `PUT /api/solutions/progress`, and
`POST /api/solutions/fix-file` for a validated individual-finding or whole-file
download.

## Repository migration: changed files and validation

The **Migrate repository** action returns a new ZIP containing the copied
repository with supported source replacements applied in the files themselves,
plus a patch and per-finding migration report. The original uploaded archive is
left untouched. A candidate edit is included only after language syntax
validation and a second crypto scan confirm the targeted weak use is gone.
Uncertain cipher, TLS, and unsupported call-site changes remain explicit
manual-review items. CADENCE does not execute uploaded build/test commands;
run the repository's CI and integration tests before merging or deploying the
new ZIP. Syntax checks and a clean re-scan are safeguards, not a guarantee of
runtime or production safety.

### Domain fixes

Domain and host findings describe a live endpoint, not a source file, so CADENCE
does not change DNS, certificates, load balancers, or production TLS settings.
A useful next step is a provider-aware **domain remediation pack**: prepare a
TLS 1.2/1.3 policy for the selected Nginx/Apache/Caddy/cloud load balancer,
certificate renewal/rotation steps, and copy-ready `openssl`/`curl` checks. It
should stage configuration for review and require an explicit per-domain
confirmation before any future provider integration applies it; a scanner
should not silently alter a live endpoint.

## Running it locally first

```bash
cp .env.example .env        # optionally set APP_PASSWORD / SCAN_CRON
docker compose up --build
```

Open **http://localhost:8000**, go to Settings, and point it at a real
target — a source path, a GitHub org, or a domain you're authorized to
test. Click **Run scan**. The dashboard fills in when it finishes.

If you're scanning code that lives on your machine, mount it into the
container and point Settings at the mounted path:

```yaml
# in docker-compose.yml
volumes:
  - /path/to/your/codebase:/srv/code:ro
```
then set **Source path** to `/srv/code` in Settings.

### Windows Command Prompt (CMD)

Extract the ZIP, open **Command Prompt** in the `cadence_app` project root
(the folder containing `requirements.txt`), and run:

```bat
py -3.12 -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if not exist .env copy .env.example .env
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Use a Python 3.12 installation available through the Windows `py` launcher.
Keep the Command Prompt window open while CADENCE is running, then open
**http://127.0.0.1:8000** in your browser. Stop the server with **Ctrl+C**.
Run the `uvicorn` command from the project root exactly as shown; this loads
`backend.main` as a package and avoids the relative-import error caused by
starting `main.py` as a top-level module. To start it again later, open CMD in
the same folder, run `call .venv\Scripts\activate.bat`, then repeat the final
`python -m uvicorn ...` command.

## Deploying for the whole team

### Option A — Docker anywhere (recommended)

This works identically on an internal server or a cloud host, since
it's the same container either way:

```bash
docker compose up --build -d
```

- **Internal server**: run this on any machine your team can reach,
  put it behind your existing reverse proxy / VPN for TLS and network
  access control, and set `APP_PASSWORD` at minimum.
- **Cloud host** (Render, Railway, Fly.io, a plain VM, etc.): these
  all support "deploy this Dockerfile." Point them at this repo, set
  `APP_PASSWORD` (and `SCAN_CRON` if you want scheduled scans) as
  environment variables, and attach a **persistent volume/disk at
  `/app/backend/data`** — without it, run history resets on every
  redeploy. If you're scanning a GitHub org rather than a local path,
  you don't need to mount any code at all.

### Option B — Bare metal / internal server without Docker

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export APP_PASSWORD=change-me
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000
```

Run that under `systemd` (or `pm2`, `supervisor`, etc.) so it survives
reboots, and put nginx/Caddy in front of it for TLS:

```nginx
server {
    listen 443 ssl;
    server_name cadence.your-company.internal;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
    }
}
```

## Access control

Set `APP_PASSWORD` and everyone on the team enters it once (the
dashboard keeps it for the current browser tab session). This is intentionally
minimal — it's one shared password, not per-user accounts. Given this
tool surfaces real, unpatched cryptographic weaknesses across your
systems, for anything beyond a small trusted team we'd recommend
putting it behind your actual SSO/VPN instead of relying on
`APP_PASSWORD` alone.

The GitHub token configured in Settings is stored in the server's private
`backend/data/scan_config.json` file (created with owner-only permissions on
Unix-like systems). Protect and back up the persistent data volume accordingly.
Repository migration accepts ZIP files up to 100 MB, with expanded content
limited to 500 MB; unsafe archive paths and special-file entries are rejected.
It scans supported UTF-8 source files up to 5 MB each and excludes common
vendor/build directories. Python, Java, and JavaScript detections use ASTs
when files parse; unparseable or other files use lower-confidence patterns,
which never trigger automatic edits. The output ZIP includes a JSON report
with per-finding confidence, a migration solution plan, and a unified patch.
Cipher-mode changes and ambiguous TLS updates remain manual. Supported edits
receive static syntax checks, but uploaded build/test commands are never run.
Run your own tests and review every change before use; AST detection is not a
full semantic or data-flow analysis.

## Automatic scans

Set `SCAN_CRON` (standard 5-field cron, e.g. `0 3 * * *` for daily at
3am server time) and the pipeline runs itself — no one has to remember
to click the button. Manual runs still work at any time; the two share
the same lock, so they'll never overlap.

## Settings reference

Everything below is editable from the gear icon in the app — no file
editing required day-to-day. In cloud deployments, a path on your personal
computer is not visible to the server. Upload a source-project ZIP in Settings
(or configure a GitHub organization) to scan code hosted on the cloud service.
Source ZIPs are validated before extraction and the scanner never executes
uploaded project code. Upload limit: 100 MB compressed / 500 MB expanded.

| Setting | Maps to |
|---|---|
| Source path | Cryptography scan target; accepts a single supported source file or a directory |
| Source ZIP upload | Safely extracts a project into persistent server storage and selects it as the source target |
| GitHub org / token | Organization repositories and access token |
| Domain | Authorized network target |
| Team size, planning horizon, budget | Migration planning controls |

Finer-grained planning settings (severity weights, per-system compliance
deadlines, dependency precedence) aren't in the UI yet — edit
`cadence_module3/constraints.json` directly and the next run will pick
them up.

**Currency:** Budgets and estimated costs use Indian rupees (INR, ₹). The
included example defaults preserve the prior illustrative USD scale using an
approximate rate of **₹96.80 per USD on October 8, 2026** ([Wise historical rate](https://wise.com/us/currency-converter/usd-to-inr-rate/history)); this is a fixed
conversion reference, not a live exchange-rate feed. Replace the examples with
your organization's approved INR estimates.

## Data & privacy

Every run's output (findings, dependency graph, ownership map, migration
plan, and console log) is stored in
`backend/data/cadence.db` (SQLite) and mirrored as JSON files under
`backend/data/runs/<run_id>/`. Nothing is sent anywhere outside the
server you deploy this on. Shared module output files are cleared before a
new scan starts, and checklist progress is keyed to the run, so one scan's
findings, locations, plan, or checkmarks are not merged into another.
