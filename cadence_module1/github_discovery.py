"""
github_discovery.py — Code-layer discovery.

Instead of you pointing the scanner at one folder, this enumerates every
repo in a GitHub org/user via the API, shallow-clones each one, scans it,
and tags findings with which repo they came from.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from cbom import CryptoAsset
from scanner import scan_directory

API_BASE = "https://api.github.com"

# Repos are cloned+scanned concurrently instead of one at a time — this is
# the single biggest lever on wall-clock scan time for an org with more
# than a handful of repos. Kept modest by default to stay polite to the
# GitHub API / clone bandwidth; raise CADENCE_GITHUB_WORKERS if needed.
CLONE_WORKERS = int(os.environ.get("CADENCE_GITHUB_WORKERS", "6"))
# A shallow (--depth 1) clone of a typical repo finishes in a few seconds.
# 30s is generous headroom while still failing fast on an oversized or
# hung repo instead of stalling the whole scan for a full minute.
CLONE_TIMEOUT_SECONDS = int(os.environ.get("CADENCE_GITHUB_CLONE_TIMEOUT", "180"))
API_TIMEOUT_SECONDS = int(os.environ.get("CADENCE_GITHUB_API_TIMEOUT", "30"))


def _api_get(path: str, token: str | None = None) -> list | dict:
    req = urllib.request.Request(f"{API_BASE}{path}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "cadence-scanner")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=API_TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read())


def list_org_repos(org: str, token: str | None = None, max_repos: int = 100) -> list[dict]:
    """
    Enumerate repos for a GitHub org or user. Tries /orgs/ first (org
    account), falls back to /users/ (personal account) — same call shape,
    different account types.
    """
    repos, page = [], 1
    for endpoint in (f"/orgs/{org}/repos", f"/users/{org}/repos"):
        try:
            repos = []
            page = 1
            while len(repos) < max_repos:
                batch = _api_get(f"{endpoint}?per_page=50&page={page}", token=token)
                if not batch:
                    break
                repos.extend(batch)
                page += 1
            if repos:
                return repos[:max_repos]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue  # try the other endpoint shape
            if e.code == 403:
                raise RuntimeError(
                    "GitHub API rate limit hit (60 req/hr unauthenticated). "
                    "Pass a personal access token: scan_github_org(org, token='ghp_...'). "
                    "Also required for scanning private repos."
                ) from e
            raise
    return repos


def _clone_and_scan_repo(org: str, repo: dict, token: str | None = None) -> tuple[str, list[CryptoAsset], str | None]:
    """Shallow-clone one repo into a scratch dir, scan it, return findings
    re-tagged with an 'org/repo:path' location. Runs inside a worker thread."""
    name = repo["name"]
    clone_url = repo["clone_url"]

    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, name)
        try:
            # Authenticate HTTPS clones for private repositories without putting
            # the token in the clone URL or command-line arguments.
            env = os.environ.copy()
            if token:
                import base64
                auth = base64.b64encode(f"{token}:x-oauth-basic".encode()).decode()
                env["GIT_CONFIG_COUNT"] = "1"
                env["GIT_CONFIG_KEY_0"] = "http.https://github.com/.extraheader"
                env["GIT_CONFIG_VALUE_0"] = f"AUTHORIZATION: basic {auth}"
            subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", "--single-branch", clone_url, dest],
                check=True, timeout=CLONE_TIMEOUT_SECONDS, env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return name, [], "clone failed, skipped"

        repo_findings = scan_directory(dest)
        # Re-tag occurrence locations as "org/repo:path" instead of a
        # temp-dir path that won't mean anything after cleanup.
        for asset in repo_findings:
            for occ in asset.occurrences:
                rel = os.path.relpath(occ.location, dest)
                occ.location = f"{org}/{name}:{rel}"
        return name, repo_findings, None


def scan_github_org(org: str, token: str | None = None, max_repos: int = 100) -> list[CryptoAsset]:
    """Discover every repo in an org/user, shallow-clone each, scan it.

    Repos are cloned and scanned concurrently (see CLONE_WORKERS) so scan
    time scales with the slowest repo rather than the sum of every repo."""
    repos = list_org_repos(org, token=token, max_repos=max_repos)
    findings: list[CryptoAsset] = []

    scannable = [r for r in repos if not r.get("fork")]
    skipped_forks = len(repos) - len(scannable)
    print(f"[*] Discovered {len(repos)} repo(s) in '{org}'"
          + (f" ({skipped_forks} fork(s) skipped)" if skipped_forks else ""))

    if not scannable:
        return findings

    with ThreadPoolExecutor(max_workers=min(CLONE_WORKERS, len(scannable))) as pool:
        futures = {pool.submit(_clone_and_scan_repo, org, repo, token): repo for repo in scannable}
        for future in as_completed(futures):
            repo = futures[future]
            name = repo["name"]
            try:
                _, repo_findings, err = future.result()
            except Exception as exc:  # noqa: BLE001 — one bad repo shouldn't sink the org scan
                print(f"    - {name}: error ({exc}), skipped")
                continue
            if err:
                print(f"    - {name}: {err}")
                continue
            findings.extend(repo_findings)
            print(f"    - {name}: {len(repo_findings)} finding(s)")

    return findings
