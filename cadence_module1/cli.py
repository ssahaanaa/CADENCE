"""
cli.py — CADENCE Module 1 entry point.

    python cli.py scan ./path/to/code --hosts example.com internal-api.corp:8443

Outputs two files:
  cbom.json               — CycloneDX 1.6 CBOM, the new primary output
  vulnerabilities.json    — legacy CADENCE schema, kept for Module 2-4 compatibility
"""

from __future__ import annotations

import argparse
import json
import sys
import os
from pathlib import Path

from cbom import CBOMDocument
from scanner import scan_directory
from network_scanner import scan_hosts
from github_discovery import scan_github_org
from network_discovery import discover_enterprise_hosts


def main():
    parser = argparse.ArgumentParser(prog="cadence-scan", description="CADENCE Module 1 — The Scanner")
    parser.add_argument("path", nargs="?", help="Directory of source code to scan (skip if using --github-org)")
    parser.add_argument("--hosts", nargs="*", default=[],
                         help="Manual list of host[:port] entries for live TLS/network scanning")
    parser.add_argument("--github-org", default=None,
                         help="Discover and scan every repo in a GitHub org/user automatically")
    parser.add_argument("--github-token", default=None,
                         help="GitHub personal access token (raises rate limit, allows private repos)")
    parser.add_argument("--domain", default=None,
                         help="Root domain to auto-discover subdomains/live hosts under, then TLS-scan them. "
                              "Only use on domains you own or are authorized to test.")
    parser.add_argument("--project-name", default="cadence-target")
    parser.add_argument("--out-dir", default=".")
    args = parser.parse_args()

    doc = CBOMDocument(project_name=args.project_name)

    if args.path:
        print(f"[*] Scanning source tree: {args.path}", file=sys.stderr)
        doc.add_many(scan_directory(args.path))

    if args.github_org:
        doc.add_many(scan_github_org(args.github_org, token=args.github_token or os.environ.get("CADENCE_GITHUB_TOKEN")))

    if args.hosts:
        print(f"[*] Probing {len(args.hosts)} network target(s): {', '.join(args.hosts)}", file=sys.stderr)
        doc.add_many(scan_hosts(args.hosts))

    if args.domain:
        live_targets = discover_enterprise_hosts(args.domain)
        doc.add_many(scan_hosts(live_targets))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cbom_path = out_dir / "cbom.json"
    legacy_path = out_dir / "vulnerabilities.json"

    with cbom_path.open("w", encoding="utf-8") as f:
        json.dump(doc.to_dict(), f, indent=2)

    with legacy_path.open("w", encoding="utf-8") as f:
        json.dump(doc.to_legacy_vulnerabilities_json(), f, indent=2)

    high_conf = sum(1 for a in doc.assets if a.confidence == "high")
    review = sum(1 for a in doc.assets if a.confidence == "needs_review")
    print(f"[+] {len(doc.assets)} findings ({high_conf} high-confidence, {review} needs_review)", file=sys.stderr)
    print(f"[+] Wrote {cbom_path}", file=sys.stderr)
    print(f"[+] Wrote {legacy_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
