#!/usr/bin/env python3
"""Sanity tests for the PQC solutions engine.  Run:  python3 test_solutions.py"""
import json
from pathlib import Path

import pqc_solutions as S

HERE = Path(__file__).resolve().parent
FAILED = []


def check(name, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"  {detail}" if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


# 1. Every algorithm name Module 1 can emit resolves to the right recipe
expect = {
    "MD5": "md5", "SHA1": "sha1", "SHA-1": "sha1", "DES": "des", "3DES": "des", "ARC4": "rc4", "RC4": "rc4",
    "Blowfish": "blowfish", "RSA-1024": "rsa", "RSA-1024 (certificate)": "rsa-cert",
    "MD5-signed certificate": "hash-signed-cert", "SHA1-signed certificate": "hash-signed-cert",
    "SSLv2": "tls-legacy", "SSLv3": "tls-legacy", "SSLv23": "tls-legacy", "TLSv1": "tls-legacy",
    "TLSv1.1": "tls-legacy", "TLSv1.0/1.1": "tls-legacy", "expired-certificate": "expired-cert",
    "unreachable": "unreachable", "RC4-SHA": "weak-suite", "DES-CBC3-SHA": "weak-suite",
    "ECDSA-P256": "ecdsa", "ECDH": "ecdh", "AES-128-GCM": "aes128",
    "TLSv1.2": "unclassified", "TLSv1.3": "unclassified", "SHA256": "unclassified",
}
for name, want in expect.items():
    got = S.classify(name)["id"]
    check(f"classify {name!r} -> {want}", got == want, f"got {got}")

# 2. Honesty: classically broken items must not be sold as PQC swaps
for name in ("MD5", "SHA1", "DES", "RC4", "TLSv1"):
    check(f"{name} is not labelled a direct PQC swap", S.classify(name)["relevance"] != "direct")
check("RSA-1024 is a direct PQC swap", S.classify("RSA-1024")["relevance"] == "direct")

# 3. Profiles substitute real parameter names and sizes
std, high = S.build_catalog("standard"), S.build_catalog("high")
check("standard uses ML-KEM-768", any("ML-KEM-768" in " ".join(a["replace"]) for a in std["algorithms"]))
check("high uses ML-KEM-1024 / ML-DSA-87", any("ML-DSA-87" in " ".join(a["replace"]) for a in high["algorithms"]))
check("no unresolved <<TOKENS>> in catalog", "<<" not in json.dumps(std) and "<<" not in json.dumps(high))
check("FIPS sizes", S.KEM_PROFILES["ML-KEM-768"]["ciphertext"] == 1088 and S.SIG_PROFILES["ML-DSA-65"]["signature"] == 3309)

# 4. A plan builds from a real run and is internally consistent
row = {"migration_ranking_json": (HERE / "migration_ranking.json").read_text(),
       "vulnerabilities_json": (HERE.parent / "cadence_module1" / "vulnerabilities.json").read_text(),
       "system_file_map_json": json.dumps({
           "/home/claude/build/sample_target/legacy_auth.py": "Legacy Auth Service",
           "/home/claude/build/sample_target/gateway.conf": "API Gateway",
       })}
plan = S.build_plan(row, "standard")
check("one plan entry per roadmap system", len(plan["systems"]) == len(json.loads(row["migration_ranking_json"])["migration_order"]))
check("no unresolved tokens in plan", "<<" not in json.dumps(plan))
check("every step id unique per system", all(len({s["id"] for s in x["steps"]}) == len(x["steps"]) for x in plan["systems"]))
check("every system ends with a re-scan step", all(x["steps"][-1]["id"] == "rescan" for x in plan["systems"]))
check("systems without findings get a manual-check plan", all(x["steps"][0]["id"] == "verify-config" for x in plan["systems"] if x["status"] == "verify"))
check("swaps map covers every found algorithm", {"MD5", "RSA-1024", "TLSv1"} <= set(plan["swaps"]))
legacy = next(x for x in plan["systems"] if x["asset_id"] == "Legacy Auth Service")
check("file locations mapped to the system", any(c["locations"] for c in legacy["changes"]))
check("python detected from file extension", "python" in legacy["preferred_languages"])
check("RSA change offers both signature and key-exchange roles", any(c["roles"] and len(c["roles"]) == 2 for c in legacy["changes"]))
current_path = "/new/repo/auth.py"
check("solutions honor this scan's exact file mapping",
      S._system_for_file(current_path, ["Current Identity"], {current_path: "Current Identity"}) == "Current Identity")
check("solutions do not reuse an older scan's basename mapping",
      S._system_for_file(current_path, ["Old Identity"], {"auth.py": "Old Identity"}) is None)
check("a stored run without its own map never loads the shared sample map",
      S._load_file_map({"system_file_map_json": None}) == {})

# 5. Progress is applied and counted
done = {("Legacy Auth Service", "inventory"): True}
p2 = S.build_plan(row, "standard", done)
l2 = next(x for x in p2["systems"] if x["asset_id"] == "Legacy Auth Service")
check("progress applied", l2["progress"]["done"] == 1 and p2["summary"]["steps_done"] == 1)

# 6. Bad input fails loudly
try:
    S.get_profile("nope"); check("unknown profile rejected", False)
except ValueError:
    check("unknown profile rejected", True)
try:
    S.build_plan({}, "standard"); check("run without a plan rejected", False)
except ValueError:
    check("run without a plan rejected", True)

print(f"\n{len(FAILED)} failed" if FAILED else "\nall passed")
raise SystemExit(1 if FAILED else 0)
