"""
network_discovery.py — Network-layer discovery.

Mirrors AC-Scanner's discovery chain (subfinder -> dnsx -> httpx) using
only the Python standard library:

  1. subdomain enumeration  — try common subdomain names under the root domain
  2. DNS resolution         — keep only ones that actually resolve
  3. live-host detection    — keep only ones with something listening on 443/22

The result feeds straight into network_scanner.probe_host() for the
actual TLS/cert inspection.

NOTE ON SCOPE: real subdomain enumeration tools also mine passive sources
like certificate-transparency logs (crt.sh) for far more coverage. That's
a one-line swap (add a crt.sh query) if you're running this somewhere
with open network access — left out here to keep this dependency-free
and because CT-log queries were blocked in the sandbox this was built in.

AUTHORIZATION: only ever run this against domains you own or are
explicitly authorized to test. Scanning infrastructure without permission
is illegal in most jurisdictions regardless of intent.
"""

from __future__ import annotations

import socket
import threading
import concurrent.futures
import json
import urllib.parse
import urllib.request
import urllib.error

COMMON_SUBDOMAINS = [
    "www", "api", "app", "mail", "webmail", "vpn", "remote", "portal",
    "admin", "auth", "sso", "login", "gateway", "internal", "intranet",
    "dev", "staging", "test", "uat", "qa", "demo",
    "git", "gitlab", "github", "jenkins", "ci", "jira", "confluence",
    "docs", "wiki", "support", "help", "status", "monitor",
    "cdn", "static", "assets", "files", "media",
    "shop", "store", "checkout", "payments", "billing",
    "db", "database", "sql", "backup", "ftp", "ssh",
]


def resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError):
        return None


def is_live(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


DNS_BUDGET_SECONDS = 45   # total wall-clock cap for the whole subdomain sweep
LIVE_CHECK_TIMEOUT = 5.0  # seconds per host:port liveness probe
CT_LOG_TIMEOUT_SECONDS = 15.0


def discover_passive_subdomains(domain: str, timeout: float = CT_LOG_TIMEOUT_SECONDS) -> list[str]:
    """Use crt.sh certificate-transparency records for passive subdomain coverage.

    This is best-effort: DNS/common-name discovery still runs if the public
    CT service is unavailable or rate-limits the request.
    """
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    request = urllib.request.Request(
        f"https://crt.sh/?{query}",
        headers={"User-Agent": "CADENCE-Console/1.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
        found = set()
        suffix = "." + domain.casefold().strip(".")
        for row in payload if isinstance(payload, list) else []:
            for raw in str(row.get("name_value", "")).splitlines():
                host = raw.strip().lower().lstrip("*.")
                if host == domain.casefold().strip(".") or host.endswith(suffix):
                    if host and not any(ch.isspace() for ch in host):
                        found.add(host)
        return sorted(found)
    except (OSError, ValueError, urllib.error.URLError):
        return []


def discover_subdomains(domain: str, wordlist: list[str] | None = None, max_workers: int = 30) -> list[str]:
    """Step 1+2: enumerate candidate subdomains, keep the ones that resolve.
    (max_workers is accepted for backwards compatibility with callers of
    this function but isn't used — see the daemon-thread note below.)

    socket.gethostbyname() has no built-in timeout and ThreadPoolExecutor's
    worker threads are non-daemon, so a naive thread-pool version of this
    would still make the whole process block at exit until every lookup
    eventually returns — on a domain with lots of dead subdomains and a slow
    resolver that can take minutes. We use plain daemon threads instead: a
    daemon thread stuck on a slow DNS call never blocks the process, so we
    can simply stop waiting after DNS_BUDGET_SECONDS and move on with
    whatever resolved in time."""
    wordlist = wordlist or COMMON_SUBDOMAINS
    candidates = [f"{w}.{domain}" for w in wordlist] + [domain]  # include the bare root domain too
    # Passive CT-log enumeration expands coverage beyond the small built-in
    # wordlist. Resolve these candidates below before returning them.
    candidates.extend(discover_passive_subdomains(domain))

    resolved: list[str] = []
    lock = threading.Lock()
    remaining = len(candidates)
    all_done = threading.Event()

    def worker(host: str) -> None:
        nonlocal remaining
        ip = resolve(host)
        with lock:
            if ip:
                resolved.append(host)
            remaining -= 1
            if remaining == 0:
                all_done.set()

    for host in candidates:
        threading.Thread(target=worker, args=(host,), daemon=True).start()

    all_done.wait(timeout=DNS_BUDGET_SECONDS)  # returns early once every lookup finishes
    with lock:
        return sorted(set(resolved))


def discover_live_hosts(hosts: list[str], ports: tuple[int, ...] = (443,), max_workers: int = 30) -> list[str]:
    """Step 3: keep only resolved hosts that actually answer on a target port.
    is_live() already carries a real socket timeout, so this only needs
    enough workers to run every check in parallel rather than one by one."""
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for host in hosts:
            for port in ports:
                futures[pool.submit(is_live, host, port, LIVE_CHECK_TIMEOUT)] = f"{host}:{port}"
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            if future.result():
                live.append(target)
    return sorted(set(live))


def discover_enterprise_hosts(domain: str) -> list[str]:
    """Full chain: root domain in -> list of live 'host:port' targets out."""
    print(f"[*] Enumerating subdomains of {domain}...")
    resolved = discover_subdomains(domain)
    print(f"[*] {len(resolved)} subdomain(s) resolved: {', '.join(resolved) if resolved else '(none)'}")

    print(f"[*] Checking which are live on :443...")
    live = discover_live_hosts(resolved, ports=(443,))
    print(f"[*] {len(live)} live target(s) found")
    return live
