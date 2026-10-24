#!/usr/bin/env python3
"""
CADENCE Module 3 — sanity tests (new schema: cbom.json + dependency_graph.json).

Run with:
    python3 test_module3.py
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
PASS, FAIL = "PASS", "FAIL"
results = []


def check(name: str, condition: bool, detail: str = ""):
    status = PASS if condition else FAIL
    results.append((name, status))
    print(f"[{status}] {name}" + (f" — {detail}" if detail and status == FAIL else ""))


def run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HERE / "module3_decision_engine.py")] + args,
        capture_output=True, text=True, cwd=str(HERE),
    )


def main():
    cbom = str(HERE / ".." / "cadence_module1" / "cbom.json")
    vuln = str(HERE / ".." / "cadence_module1" / "vulnerabilities.json")
    graph = str(HERE / ".." / "cadence_module2" / "dependency_graph.json")
    sysmap = str(HERE / "system_file_map.json")
    config = str(HERE / "constraints.json")

    # --- Test 1: normal run against the real bundled Module 1 + 2 data ---
    with tempfile.TemporaryDirectory() as tmp:
        out = str(Path(tmp) / "migration_ranking.json")
        result = run_cli(["--cbom", cbom, "--vulnerabilities", vuln, "--graph", graph,
                           "--system-map", sysmap, "--config", config, "--out", out])
        check("runs cleanly on the real bundled data", result.returncode == 0, result.stderr)

        if result.returncode == 0:
            data = json.loads(Path(out).read_text())
            order = data.get("migration_order", [])
            check("output is valid JSON with a migration_order list", isinstance(order, list))
            check("roadmap contains only systems with current-run findings",
                  bool(order) and all(r.get("finding_count", 0) > 0 for r in order), f"got {len(order)} rows")
            ranks = [r["priority_rank"] for r in order]
            check("priority ranks are 1..N with no gaps", ranks == list(range(1, len(order) + 1)))
            scores = [r["score"] for r in order]
            check("systems are sorted by score, highest first", scores == sorted(scores, reverse=True))
            check("every system has a scheduled_week", all(r.get("scheduled_week") is not None for r in order))
            check("every system has a reasoning string",
                  all(isinstance(r.get("reasoning"), str) and r["reasoning"] for r in order))
            check("no raw NaN leaked into the JSON", "NaN" not in Path(out).read_text())
            top = order[0]
            check("Legacy Auth Service (13 findings) is ranked in the top 2",
                  any(r["asset_id"] == "Legacy Auth Service" and r["priority_rank"] <= 2 for r in order))

    # --- Test 2: cbom.json missing falls back to vulnerabilities.json ---
    with tempfile.TemporaryDirectory() as tmp:
        out = str(Path(tmp) / "out.json")
        result = run_cli(["--cbom", "does_not_exist.json", "--vulnerabilities", vuln,
                           "--graph", graph, "--system-map", sysmap, "--config", config, "--out", out])
        check("falls back to vulnerabilities.json when cbom.json is missing",
              result.returncode == 0 and "falling back" in result.stdout.lower(), result.stderr)

    # --- Test 3: missing graph file fails loudly but cleanly ---
    result = run_cli(["--cbom", cbom, "--graph", "does_not_exist.json"])
    check("missing dependency graph exits cleanly (code 1, no traceback)",
          result.returncode == 1 and "Traceback" not in result.stderr)

    # --- Test 4: malformed JSON fails loudly but cleanly ---
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "bad.json"
        bad.write_text("{not valid json")
        result = run_cli(["--cbom", str(bad), "--graph", graph])
        check("malformed JSON exits cleanly (code 1, no traceback)",
              result.returncode == 1 and "Traceback" not in result.stderr)

    # --- Test 5: missing system_file_map.json doesn't crash (falls back gracefully) ---
    with tempfile.TemporaryDirectory() as tmp:
        out = str(Path(tmp) / "out.json")
        result = run_cli(["--cbom", cbom, "--vulnerabilities", vuln, "--graph", graph,
                           "--system-map", "does_not_exist.json", "--config", config, "--out", out])
        check("missing system_file_map.json still produces output", result.returncode == 0, result.stderr)

    # --- Test 6: --no-optimize uses the greedy fallback and still works ---
    with tempfile.TemporaryDirectory() as tmp:
        out = str(Path(tmp) / "out.json")
        result = run_cli(["--cbom", cbom, "--vulnerabilities", vuln, "--graph", graph,
                           "--system-map", sysmap, "--config", config, "--out", out, "--no-optimize"])
        ok = result.returncode == 0
        if ok:
            data = json.loads(Path(out).read_text())
            ok = data.get("scheduling_method") == "greedy_fallback"
        check("--no-optimize uses greedy fallback and still succeeds", ok, result.stderr)

    # --- Test 7: context-only compatibility nodes do not become migration tasks ---
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        graph_path = tmp_path / "context-graph.json"
        graph_path.write_text(json.dumps({
            "nodes": [
                {"id": "Legacy Auth Service", "vulnerability_count": 13},
                {"id": "Importing Module", "vulnerability_count": 0, "context_only": True},
            ],
            "edges": [{"source": "Importing Module", "target": "Legacy Auth Service",
                       "relationships": ["static_local_python_import"]}],
        }))
        out = tmp_path / "context-ranking.json"
        result = run_cli(["--cbom", cbom, "--vulnerabilities", vuln, "--graph", str(graph_path),
                          "--system-map", sysmap, "--config", config, "--out", str(out)])
        ok = result.returncode == 0
        if ok:
            rows = json.loads(out.read_text())["migration_order"]
            ok = len(rows) == 1 and rows[0]["asset_id"] == "Legacy Auth Service"
        check("context-only graph nodes are excluded from migration tasks", ok, result.stderr)

    # --- Test 8: an empty current scan has no placeholder enterprise roadmap ---
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        empty_cbom = tmp_path / "empty-cbom.json"
        empty_vuln = tmp_path / "empty-vuln.json"
        empty_graph = tmp_path / "empty-graph.json"
        empty_map = tmp_path / "empty-system-map.json"
        out = tmp_path / "empty-ranking.json"
        empty_cbom.write_text(json.dumps({"components": []}))
        empty_vuln.write_text("[]")
        empty_graph.write_text(json.dumps({"nodes": [{"id": "API Gateway", "vulnerability_count": 0}], "edges": []}))
        empty_map.write_text("{}")
        result = run_cli(["--cbom", str(empty_cbom), "--vulnerabilities", str(empty_vuln),
                          "--graph", str(empty_graph), "--system-map", str(empty_map), "--config", config,
                          "--out", str(out)])
        ok = result.returncode == 0
        if ok:
            data = json.loads(out.read_text())
            ok = data.get("migration_order") == [] and data.get("scheduling_method") == "not_required_no_findings"
        check("zero current findings produce no enterprise placeholder recommendations", ok, result.stderr)

    # --- Test 9: the active scan does not retain other clean systems in its roadmap ---
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        cbom_path = tmp_path / "cbom.json"
        vuln_path = tmp_path / "vulnerabilities.json"
        graph_path = tmp_path / "graph.json"
        map_path = tmp_path / "system-map.json"
        out = tmp_path / "ranking.json"
        cbom_path.write_text(json.dumps({"components": [{
            "type": "cryptographic-asset", "name": "MD5",
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
            "properties": [{"name": "cadence:severity", "value": "high"}],
            "evidence": {"occurrences": [{"location": "new.py", "line": 4}]},
        }]}))
        vuln_path.write_text(json.dumps([{"algorithm": "MD5", "file": "new.py", "line": 4, "severity": "high"}]))
        graph_path.write_text(json.dumps({
            "nodes": [{"id": "Old Service", "vulnerability_count": 0, "pagerank": 0.3},
                      {"id": "Customer Portal (Web App)", "vulnerability_count": 1, "pagerank": 0.5},
                      {"id": "API Gateway", "vulnerability_count": 0, "pagerank": 0.2}],
            "edges": [{"source": "Customer Portal (Web App)", "target": "API Gateway"},
                      {"source": "API Gateway", "target": "Old Service"}],
        }))
        map_path.write_text(json.dumps({"new.py": "Customer Portal (Web App)"}))
        result = run_cli(["--cbom", str(cbom_path), "--vulnerabilities", str(vuln_path),
                          "--graph", str(graph_path), "--system-map", str(map_path),
                          "--config", config, "--out", str(out), "--no-optimize"])
        ok = result.returncode == 0
        if ok:
            rows = json.loads(out.read_text())["migration_order"]
            ok = len(rows) == 1 and rows[0]["asset_id"] == "Customer Portal (Web App)" and rows[0]["finding_count"] == 1
        check("only this run's affected system is planned; enterprise dependencies remain usable", ok, result.stderr)

    # --- Test 10: every exact current-run mapping becomes a roadmap item ---
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        cbom_path = tmp_path / "cbom.json"
        vuln_path = tmp_path / "vulnerabilities.json"
        graph_path = tmp_path / "graph.json"
        map_path = tmp_path / "system-map.json"
        out = tmp_path / "ranking.json"
        current_file = "/new/repo/services/identity/auth.py"
        cbom_path.write_text(json.dumps({"components": [{
            "type": "cryptographic-asset", "name": "MD5",
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
            "properties": [{"name": "cadence:severity", "value": "high"}],
            "evidence": {"occurrences": [{"location": current_file, "line": 8}]},
        }]}))
        vuln_path.write_text(json.dumps([{
            "algorithm": "MD5", "file": current_file, "line": 8, "severity": "high",
        }]))
        graph_path.write_text(json.dumps({
            "nodes": [{"id": "Old Identity", "vulnerability_count": 0},
                      {"id": "Current Identity", "vulnerability_count": 1}],
            "edges": [],
        }))
        map_path.write_text(json.dumps({current_file: "Current Identity"}))
        result = run_cli(["--cbom", str(cbom_path), "--vulnerabilities", str(vuln_path),
                          "--graph", str(graph_path), "--system-map", str(map_path),
                          "--config", config, "--out", str(out), "--no-optimize"])
        ok = result.returncode == 0
        if ok:
            rows = json.loads(out.read_text())["migration_order"]
            ok = (len(rows) == 1 and rows[0]["asset_id"] == "Current Identity"
                  and rows[0]["finding_count"] == 1)
        check("exact mapping from this scan gets its own roadmap row, not the older service", ok, result.stderr)

    print()
    n_pass = sum(1 for _, s in results if s == PASS)
    n_fail = sum(1 for _, s in results if s == FAIL)
    print(f"{n_pass} passed, {n_fail} failed out of {len(results)} checks.")
    if n_fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
