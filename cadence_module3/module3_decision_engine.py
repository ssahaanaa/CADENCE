#!/usr/bin/env python3
"""
CADENCE — Module 3: Deciding the Migration Order
Owner: Member C ("The Brain")

Pipeline position
-----------------
    Module 1 (scanner)        -> cbom.json / vulnerabilities.json
    Module 2 (dependency map) -> dependency_graph.json
    Module 3 (you are here)   -> migration_ranking.json
    Module 4 (roadmap/testing)

What this does
--------------
Module 1 found the weak cryptography, file by file. Module 2 turned
that into a system-level dependency graph and already computed how
*connected* every system is (degree centrality, in-degree, PageRank)
plus a blended HIGH/MEDIUM/LOW "criticality" label. Neither module
answers the real question: *given a limited team, a limited budget,
and real compliance deadlines, what order should we actually migrate
systems in — and why?*

Module 3 combines four factors per system:
    1. Risk        - severity-weighted weak-crypto findings for that system
    2. Dependency   - how many other systems would be affected if it breaks
                      (reuses Module 2's own PageRank/centrality numbers)
    3. Cost         - estimated engineer-effort to migrate it
    4. Compliance   - how close its regulatory deadline is

...into one priority score, ranks every system, and (optionally)
builds a week-by-week schedule that respects team capacity and budget
using linear programming (PuLP).

A known hand-off gap, and how this fills it
--------------------------------------------
Module 2's exported graph carries component-level counts while Module 1
has per-file severity. The web runner passes Module 2's freshly generated
exact-file-path map (system_file_map.json), and Module 3 uses it to roll
severity up to the same graph components. Mapping is exact-path-only so a
same-named file in another scan cannot inherit an older scan's ownership.

Usage
-----
    pip install -r requirements.txt

    python3 module3_decision_engine.py \
        --cbom ../cadence_module1/cbom.json \
        --vulnerabilities ../cadence_module1/vulnerabilities.json \
        --graph ../cadence_module2/dependency_graph.json \
        --system-map system_file_map.json \
        --config constraints.json \
        --out migration_ranking.json

    # Skip the PuLP scheduler and just get the ranked list:
    python3 module3_decision_engine.py --no-optimize

If --cbom points at a real file, it's used (it carries the
CycloneDX-standard "primitive" per algorithm - hash/cipher/protocol/
signature - which gives a better effort estimate than guessing from
the algorithm name). Otherwise Module 3 falls back to
--vulnerabilities automatically.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import networkx as nx
import numpy as np
import pandas as pd

try:
    import pulp
    PULP_AVAILABLE = True
except ImportError:
    PULP_AVAILABLE = False


# ---------------------------------------------------------------------------
# 0. Small helpers
# ---------------------------------------------------------------------------

def _fail(message: str) -> None:
    print(f"\n[CADENCE Migration Planner] ERROR: {message}\n", file=sys.stderr)
    sys.exit(1)


def _load_json(path: str, what: str) -> Any:
    p = Path(path)
    if not p.exists():
        _fail(f"Could not find {what} at '{path}'.")
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        _fail(f"'{path}' is not valid JSON ({e}). Was it fully written by the previous scan stage?")


def _minmax_normalize(values: dict[str, float]) -> dict[str, float]:
    """Scale a dict of raw numbers into 0..1. Flat/empty input -> all 0.5."""
    if not values:
        return {}
    lo, hi = min(values.values()), max(values.values())
    if hi - lo < 1e-9:
        return {k: 0.5 for k in values}
    return {k: (v - lo) / (hi - lo) for k, v in values.items()}


def _clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


# ---------------------------------------------------------------------------
# 1. Load Module 1's findings (cbom.json preferred, vulnerabilities.json fallback)
# ---------------------------------------------------------------------------

def load_findings(cbom_path: str | None, vuln_path: str | None) -> pd.DataFrame:
    """Return one normalized DataFrame of findings regardless of which
    Module 1 output format is available.

    Normalized columns: file, line, algorithm, severity, primitive,
    confidence, notes, quantum_status
    """
    if cbom_path and Path(cbom_path).exists():
        return _load_cbom(cbom_path)
    if vuln_path and Path(vuln_path).exists():
        print(f"[CADENCE Migration Planner] '{cbom_path}' not found - falling back to '{vuln_path}'.")
        return _load_vulnerabilities(vuln_path)
    _fail(f"Neither cbom file ('{cbom_path}') nor vulnerabilities file ('{vuln_path}') could be found.")


def _load_cbom(path: str) -> pd.DataFrame:
    data = _load_json(path, "CBOM file")
    components = data.get("components", [])
    if not components:
        print("[CADENCE Migration Planner] Warning: cbom.json has no components — no findings to score.")
    rows = []
    for c in components:
        props = {p.get("name"): p.get("value") for p in c.get("properties", [])}
        occurrences = c.get("evidence", {}).get("occurrences", [{}])
        crypto = c.get("cryptoProperties", {})
        for occ in occurrences:
            rows.append({
                "file": occ.get("location", ""),
                "line": occ.get("line"),
                "algorithm": c.get("name", "unknown"),
                "severity": str(props.get("cadence:severity", "low")).lower(),
                "primitive": crypto.get("algorithmProperties", {}).get("primitive")
                             or crypto.get("assetType", "default"),
                "confidence": props.get("cadence:confidence", "needs_review"),
                "notes": props.get("cadence:notes", ""),
                "quantum_status": crypto.get("nistQuantumSecurityStatus", ""),
            })
    return pd.DataFrame(rows, columns=["file", "line", "algorithm", "severity", "primitive",
                                        "confidence", "notes", "quantum_status"])


def _load_vulnerabilities(path: str) -> pd.DataFrame:
    data = _load_json(path, "vulnerabilities file")
    if not isinstance(data, list):
        _fail("vulnerabilities.json should be a list of findings, but it wasn't.")
    rows = []
    for v in data:
        rows.append({
            "file": v.get("file", ""),
            "line": v.get("line"),
            "algorithm": v.get("algorithm", "unknown"),
            "severity": str(v.get("severity", "low")).lower(),
            "primitive": v.get("type", "default"),  # "algorithm" | "protocol" in this schema
            "confidence": v.get("confidence", "needs_review"),
            "notes": "",
            "quantum_status": "",
        })
    return pd.DataFrame(rows, columns=["file", "line", "algorithm", "severity", "primitive",
                                        "confidence", "notes", "quantum_status"])


# ---------------------------------------------------------------------------
# 2. Load Module 2's dependency graph + roll findings up to systems
# ---------------------------------------------------------------------------

def load_dependency_graph(path: str) -> tuple[nx.DiGraph, dict[str, dict]]:
    """Load Module 2's dependency_graph.json.

    Schema: {"nodes": [{"id": ..., "degree_centrality": ..., "in_degree": ...,
                          "out_degree": ..., "pagerank": ..., "criticality": ...,
                          "vulnerability_count": ...}, ...],
             "edges": [{"source": ..., "target": ...}, ...]}

    An edge {"source": A, "target": B} means "A depends on B".
    """
    data = _load_json(path, "dependency graph file")
    if "nodes" not in data or "edges" not in data:
        _fail("dependency_graph.json must contain 'nodes' and 'edges' keys.")

    G = nx.DiGraph()
    node_meta: dict[str, dict] = {}

    for node in data["nodes"]:
        node_id = node.get("id")
        if not node_id:
            continue
        G.add_node(node_id)
        node_meta[node_id] = node

    for edge in data["edges"]:
        src, tgt = edge.get("source"), edge.get("target")
        if not src or not tgt:
            continue
        G.add_edge(src, tgt)
        node_meta.setdefault(src, {"id": src})
        node_meta.setdefault(tgt, {"id": tgt})

    if G.number_of_nodes() == 0:
        _fail("dependency_graph.json has no nodes - nothing to rank.")

    return G, node_meta


def load_system_file_map(path: str | None) -> dict[str, str]:
    if not path or not Path(path).exists():
        print("[CADENCE Migration Planner] Warning: no system_file_map.json found - every system's "
              "risk score will fall back to dependency-map counts with a flat severity.")
        return {}
    raw = _load_json(path, "system-file map")
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def roll_up_findings_to_systems(findings: pd.DataFrame, system_map: dict[str, str]) -> pd.DataFrame:
    """Attach scan findings only through their exact current-run source paths."""
    def normalize(path: str) -> str:
        return str(path).replace("\\", "/").casefold().removeprefix("./")

    normalized_map = {normalize(key): value for key, value in system_map.items()}

    def to_system(file_path: str) -> str | None:
        if not file_path:
            return None
        return normalized_map.get(normalize(file_path))

    findings = findings.copy()
    findings["system"] = findings["file"].apply(to_system)
    return findings


# ---------------------------------------------------------------------------
# 3. Score every system
# ---------------------------------------------------------------------------

def compute_risk(asset_ids: list[str], findings: pd.DataFrame, node_meta: dict, config: dict) -> dict[str, dict]:
    """Risk score per system: severity-weighted findings mapped to it.

    Systems with no mapped findings fall back to a small baseline derived
    from Module 2's own vulnerability_count (so a system Module 2 already
    flagged as vulnerable isn't scored as zero-risk just because our
    file->system map doesn't cover it).
    """
    sev_weights = config["severity_weights"]
    out = {}
    for asset_id in asset_ids:
        rows = findings[findings["system"] == asset_id]
        if rows.empty:
            fallback_count = node_meta.get(asset_id, {}).get("vulnerability_count", 0)
            risk_raw = _clip01(sev_weights.get("medium", 0.5) * min(1.0, fallback_count / 5)) if fallback_count else 0.0
            out[asset_id] = {
                "risk_raw": risk_raw, "finding_count": int(fallback_count),
                "worst_severity": ("medium" if fallback_count else None), "algorithms": [],
            }
            continue
        weights = rows["severity"].map(lambda s: sev_weights.get(s, sev_weights.get("low", 0.25)))
        worst_weight = float(weights.max())
        count_bonus = min(0.2, 0.03 * (len(rows) - 1))
        risk_raw = _clip01(worst_weight + count_bonus)
        worst_idx = weights.idxmax()
        out[asset_id] = {
            "risk_raw": risk_raw,
            "finding_count": int(len(rows)),
            "worst_severity": rows.loc[worst_idx, "severity"],
            "algorithms": sorted(rows["algorithm"].dropna().unique().tolist()),
        }
    return out


def compute_dependency_impact(asset_ids: list[str], G: nx.DiGraph, node_meta: dict) -> dict[str, dict]:
    """Dependency impact per system.

    Module 2 already computed degree_centrality and pagerank for every
    node — we reuse pagerank directly as the raw signal (it's the more
    meaningful of the two: a system is "important" if *important*
    systems depend on it, not just *many* systems). We also compute
    nx.ancestors() ourselves for a plain-English dependent count.
    """
    out = {}
    for asset_id in asset_ids:
        meta = node_meta.get(asset_id, {})
        pagerank = meta.get("pagerank", 0.0)
        ancestors = nx.ancestors(G, asset_id) if asset_id in G else set()
        direct = list(G.predecessors(asset_id)) if asset_id in G else []
        out[asset_id] = {
            "dependency_raw": pagerank,
            "direct_dependents": len(direct),
            "total_dependents": len(ancestors),
            "module2_criticality": meta.get("criticality"),
        }
    return out


def compute_cost(asset_ids: list[str], findings: pd.DataFrame, node_meta: dict, config: dict) -> dict[str, dict]:
    """Cost per system: estimated engineer-effort (weeks) and money.

    Neither Module 1 nor Module 2 hand off a cost figure, so Module 3
    estimates one from each finding's cryptographic primitive (hash,
    cipher, protocol, signature - the CycloneDX-standard category),
    which is a better signal than guessing from the algorithm name.
    """
    effort_table = config["effort_days_by_primitive"]
    days_per_week = config["days_per_week"]
    cost_per_week = config["cost_per_engineer_week"]

    out = {}
    for asset_id in asset_ids:
        rows = findings[findings["system"] == asset_id]
        if rows.empty:
            fallback_count = node_meta.get(asset_id, {}).get("vulnerability_count", 0)
            effort_days = effort_table.get("default", 3) * (0.5 if not fallback_count else fallback_count)
        else:
            effort_days = sum(
                effort_table.get(prim, effort_table.get("default", 3))
                for prim in rows["primitive"]
            )
        effort_weeks = round(effort_days / days_per_week, 2)
        cost = round(effort_weeks * cost_per_week, 2)
        out[asset_id] = {"effort_weeks": effort_weeks, "estimated_cost": cost}
    return out


def compute_compliance(asset_ids: list[str], config: dict) -> dict[str, dict]:
    """Compliance urgency per system, driven entirely by constraints.json."""
    ref_date = datetime.strptime(config["reference_date"], "%Y-%m-%d")
    deadlines = {k: v for k, v in config.get("compliance_deadlines", {}).items() if not k.startswith("_")}
    default_urgency = config.get("default_compliance_urgency", 0.3)
    horizon_days = 365.0

    out = {}
    for asset_id in asset_ids:
        deadline_str = deadlines.get(asset_id)
        if deadline_str is None:
            out[asset_id] = {"compliance_raw": default_urgency, "deadline": None, "days_remaining": None}
            continue
        try:
            deadline = datetime.strptime(deadline_str, "%Y-%m-%d")
        except ValueError:
            print(f"[CADENCE Migration Planner] Warning: bad deadline '{deadline_str}' for {asset_id}; using default urgency.")
            out[asset_id] = {"compliance_raw": default_urgency, "deadline": deadline_str, "days_remaining": None}
            continue
        days_remaining = (deadline - ref_date).days
        urgency = _clip01(1 - (days_remaining / horizon_days))
        out[asset_id] = {"compliance_raw": urgency, "deadline": deadline_str, "days_remaining": days_remaining}
    return out


def build_scoreboard(asset_ids: list[str], risk: dict, dependency: dict, cost: dict,
                      compliance: dict, config: dict) -> pd.DataFrame:
    w = config["weights"]

    risk_norm = _minmax_normalize({a: risk[a]["risk_raw"] for a in asset_ids})
    dep_norm = _minmax_normalize({a: dependency[a]["dependency_raw"] for a in asset_ids})
    cost_norm = _minmax_normalize({a: cost[a]["estimated_cost"] for a in asset_ids})
    comp_norm = _minmax_normalize({a: compliance[a]["compliance_raw"] for a in asset_ids})

    rows = []
    for a in asset_ids:
        score = (
            w["risk"] * risk_norm[a]
            + w["dependency"] * dep_norm[a]
            + w["compliance"] * comp_norm[a]
            - w["cost"] * cost_norm[a]
        )
        rows.append({
            "asset_id": a,
            "score": round(float(score), 4),
            "risk_score": round(risk_norm[a], 4),
            "dependency_score": round(dep_norm[a], 4),
            "compliance_score": round(comp_norm[a], 4),
            "cost_score": round(cost_norm[a], 4),
            "worst_severity": risk[a]["worst_severity"],
            "finding_count": risk[a]["finding_count"],
            "algorithms": risk[a]["algorithms"],
            "direct_dependents": dependency[a]["direct_dependents"],
            "total_dependents": dependency[a]["total_dependents"],
            "module2_criticality": dependency[a]["module2_criticality"],
            "effort_weeks": cost[a]["effort_weeks"],
            "estimated_cost": cost[a]["estimated_cost"],
            "compliance_deadline": compliance[a]["deadline"],
            "days_remaining": compliance[a]["days_remaining"],
        })

    df = pd.DataFrame(rows).sort_values("score", ascending=False).reset_index(drop=True)
    df.insert(0, "priority_rank", df.index + 1)
    return df


def generate_reasoning(row: pd.Series) -> str:
    parts = []
    if row["finding_count"] > 0:
        algos = ", ".join(row["algorithms"][:3]) if row["algorithms"] else "weak cryptography"
        sev = row["worst_severity"] or "unknown"
        parts.append(f"has {row['finding_count']} finding(s) of {sev} severity ({algos})")
    else:
        parts.append("has no directly mapped weak-crypto findings")

    if row["total_dependents"] > 0:
        parts.append(f"{row['total_dependents']} other system(s) depend on it")
    if row.get("module2_criticality"):
        parts.append(f"Enterprise dependency analysis identified this system as {row['module2_criticality']} criticality")

    if pd.notna(row["compliance_deadline"]):
        days = row["days_remaining"]
        days = None if pd.isna(days) else int(days)
        if days is not None and days >= 0:
            parts.append(f"a compliance deadline in {days} day(s) ({row['compliance_deadline']})")
        elif days is not None:
            parts.append(f"a compliance deadline that has already passed ({row['compliance_deadline']})")

    parts.append(f"an estimated effort of {row['effort_weeks']} engineer-week(s)")
    return f"{row['asset_id']} is ranked #{row['priority_rank']} because it " + "; ".join(parts) + "."


# ---------------------------------------------------------------------------
# 4. Turn the ranking into a schedule (PuLP optimization, with a fallback)
# ---------------------------------------------------------------------------

def optimize_schedule_pulp(scoreboard: pd.DataFrame, G: nx.DiGraph, config: dict) -> dict[str, int]:
    """Assign every system to a migration week using linear programming.

    x[i, w] = 1 if system i is migrated in week w.
    Minimizes   sum(score_i * week_assigned_i)  -> high-priority systems pulled earlier.
    Subject to: each system scheduled once; weekly effort <= team_size;
    total cost <= total_budget; (optional) dependencies migrated no later
    than their dependents.
    """
    weeks = list(range(1, config["planning_horizon_weeks"] + 1))
    assets = scoreboard["asset_id"].tolist()
    score = dict(zip(scoreboard["asset_id"], scoreboard["score"]))
    effort = dict(zip(scoreboard["asset_id"], scoreboard["effort_weeks"]))
    cost = dict(zip(scoreboard["asset_id"], scoreboard["estimated_cost"]))

    # System names here can contain spaces, parentheses, and slashes
    # (e.g. "Customer Portal (Web App)"). Those characters can corrupt
    # the LP/MPS file PuLP hands to the CBC solver and cause a false
    # "infeasible" result, so every asset gets a safe internal variable
    # name purely for the solver and results are mapped back afterwards.
    safe_name = {a: f"a_{i}" for i, a in enumerate(assets)}

    prob = pulp.LpProblem("CADENCE_Migration_Schedule", pulp.LpMinimize)
    raw_x = pulp.LpVariable.dicts("assign", (list(safe_name.values()), weeks), cat="Binary")
    x = {a: raw_x[safe_name[a]] for a in assets}

    for a in assets:
        prob += pulp.lpSum(x[a][w] for w in weeks) == 1

    # Cumulative team capacity: by the end of week w, the team has done
    # team_size * w engineer-weeks of work in total. This lets one large
    # system (e.g. 8 engineer-weeks of work) still get scheduled - it just
    # means nothing else finishes until the team's cumulative capacity
    # catches up - instead of the model being infeasible just because one
    # system's effort alone exceeds a single week's headcount.
    for w in weeks:
        prob += pulp.lpSum(effort[a] * x[a][w2] for a in assets for w2 in weeks if w2 <= w) \
                <= config["team_size"] * w

    prob += pulp.lpSum(cost[a] * x[a][w] for a in assets for w in weeks) <= config["total_budget"]

    week_of = {a: pulp.lpSum(w * x[a][w] for w in weeks) for a in assets}

    if config.get("enforce_dependency_precedence", True):
        for src, tgt in G.edges():
            if src in week_of and tgt in week_of:
                prob += week_of[tgt] <= week_of[src]

    prob += pulp.lpSum(score[a] * week_of[a] for a in assets)

    solver = pulp.PULP_CBC_CMD(msg=0)
    status = prob.solve(solver)

    if pulp.LpStatus[status] != "Optimal":
        raise RuntimeError(f"PuLP could not find an optimal schedule (status: {pulp.LpStatus[status]}). "
                            f"Try raising team_size, total_budget, or planning_horizon_weeks in constraints.json.")

    schedule = {}
    for a in assets:
        for w in weeks:
            if pulp.value(x[a][w]) and pulp.value(x[a][w]) > 0.5:
                schedule[a] = w
                break
    return schedule


def schedule_greedy_fallback(scoreboard: pd.DataFrame, config: dict) -> dict[str, int]:
    """Dependency-free fallback scheduler used if PuLP isn't installed or
    the LP turns out infeasible. Uses the same cumulative-capacity idea as
    the optimizer: the team accumulates team_size engineer-weeks of
    capacity every week, and each system (in priority order) is placed in
    the earliest week by which enough cumulative capacity - and budget -
    is available to finish it.
    """
    horizon = config["planning_horizon_weeks"]
    team_size = config["team_size"]
    remaining_budget = config["total_budget"]
    used_so_far = 0.0
    schedule = {}

    for _, row in scoreboard.sort_values("score", ascending=False).iterrows():
        if row["estimated_cost"] > remaining_budget:
            schedule[row["asset_id"]] = horizon + 1  # can't afford it within budget at all
            continue
        needed_total = used_so_far + row["effort_weeks"]
        week = max(1, int(np.ceil(needed_total / team_size))) if team_size > 0 else horizon + 1
        if week > horizon:
            schedule[row["asset_id"]] = horizon + 1
            continue
        schedule[row["asset_id"]] = week
        used_so_far = needed_total
        remaining_budget -= row["estimated_cost"]
    return schedule


def build_schedule(scoreboard: pd.DataFrame, G: nx.DiGraph, config: dict, use_optimizer: bool) -> tuple[dict[str, int], str]:
    if use_optimizer and PULP_AVAILABLE:
        try:
            return optimize_schedule_pulp(scoreboard, G, config), "pulp_optimal"
        except Exception as e:
            print(f"[CADENCE Migration Planner] Warning: PuLP optimization failed ({e}). Falling back to greedy scheduling.")
    elif use_optimizer and not PULP_AVAILABLE:
        print("[CADENCE Migration Planner] Warning: PuLP is not installed (pip install pulp). Falling back to greedy scheduling.")
    return schedule_greedy_fallback(scoreboard, config), "greedy_fallback"


# ---------------------------------------------------------------------------
# 5. Export migration_ranking.json for Module 4
# ---------------------------------------------------------------------------

def _clean_nans(obj: Any) -> Any:
    """Turn pandas/numpy NaN into JSON-valid null - standard JSON has no
    NaN literal, and Module 4 shouldn't have to guard against it."""
    if isinstance(obj, dict):
        return {k: _clean_nans(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean_nans(v) for v in obj]
    if isinstance(obj, float) and np.isnan(obj):
        return None
    return obj


def export_ranking(scoreboard: pd.DataFrame, schedule: dict[str, int], schedule_method: str,
                    config: dict, out_path: str) -> None:
    records = []
    for _, row in scoreboard.iterrows():
        record = row.to_dict()
        record["scheduled_week"] = schedule.get(row["asset_id"])
        record["reasoning"] = generate_reasoning(row)
        records.append(_clean_nans(record))

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "scheduling_method": schedule_method,
        "constraints_used": {
            "team_size": config["team_size"],
            "planning_horizon_weeks": config["planning_horizon_weeks"],
            "total_budget": config["total_budget"],
            "currency": config.get("currency", "INR"),
            "weights": config["weights"],
        },
        "migration_order": records,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)

    print(f"Hand-off file written: {out_path}")


# ---------------------------------------------------------------------------
# 6. CLI
# ---------------------------------------------------------------------------

INR_PER_USD_REFERENCE = 96.8

DEFAULT_CONFIG = {
    "team_size": 4,
    "planning_horizon_weeks": 10,
    "total_budget": 7744000,
    "cost_per_engineer_week": 387200,
    "currency": "INR",
    "weights": {"risk": 0.4, "dependency": 0.3, "compliance": 0.2, "cost": 0.1},
    "severity_weights": {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25},
    "effort_days_by_primitive": {"hash": 2, "cipher": 4, "protocol": 3, "signature": 5, "algorithm": 3, "default": 3},
    "days_per_week": 5,
    "reference_date": datetime.now().strftime("%Y-%m-%d"),
    "default_compliance_urgency": 0.3,
    "compliance_deadlines": {},
    "enforce_dependency_precedence": True,
}


def load_config(path: str | None) -> dict:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    if path and Path(path).exists():
        user_config = _load_json(path, "config file")
        if str(user_config.get("currency", "USD")).upper() == "USD":
            for field in ("total_budget", "cost_per_engineer_week"):
                if field in user_config:
                    user_config[field] = round(float(user_config[field]) * INR_PER_USD_REFERENCE)
            user_config["currency"] = "INR"
        for key, value in user_config.items():
            if key.startswith("_"):
                continue
            if isinstance(value, dict) and isinstance(config.get(key), dict):
                config[key].update({k: v for k, v in value.items() if not k.startswith("_")})
            else:
                config[key] = value

    for key in ("team_size", "planning_horizon_weeks", "total_budget", "cost_per_engineer_week"):
        if config.get(key, 0) <= 0:
            _fail(f"constraints.json: '{key}' must be greater than 0.")
    if not all(k in config["weights"] for k in ("risk", "dependency", "compliance", "cost")):
        _fail("constraints.json: 'weights' must include risk, dependency, compliance, and cost.")

    return config


def run(cbom_path: str, vuln_path: str, graph_path: str, system_map_path: str | None,
        config_path: str | None, out_path: str, use_optimizer: bool = True) -> pd.DataFrame:
    config = load_config(config_path)

    findings = load_findings(cbom_path, vuln_path)
    system_map = load_system_file_map(system_map_path)
    findings = roll_up_findings_to_systems(findings, system_map)

    G, node_meta = load_dependency_graph(graph_path)
    # Local-import neighbors without findings help explain centrality, but
    # they are context, not crypto-migration work items.
    asset_ids = sorted(node for node in G.nodes()
                       if not node_meta.get(node, {}).get("context_only", False))
    if not asset_ids:
        asset_ids = sorted(G.nodes())

    risk = compute_risk(asset_ids, findings, node_meta, config)
    dependency = compute_dependency_impact(asset_ids, G, node_meta)
    cost = compute_cost(asset_ids, findings, node_meta, config)
    compliance = compute_compliance(asset_ids, config)

    # The graph remains enterprise-wide so dependency centrality is calculated
    # against the complete architecture, but only systems affected by findings
    # in this run belong in its remediation roadmap. Otherwise every clean
    # system gets a placeholder schedule row and appears to be old work carried
    # into the latest scan.
    full_scoreboard = build_scoreboard(asset_ids, risk, dependency, cost, compliance, config)
    scoreboard = full_scoreboard[full_scoreboard["finding_count"] > 0].copy().reset_index(drop=True)
    scoreboard["priority_rank"] = range(1, len(scoreboard) + 1)
    if scoreboard.empty:
        schedule, schedule_method = {}, "not_required_no_findings"
    else:
        schedule_graph = G.subgraph(scoreboard["asset_id"].tolist()).copy()
        schedule, schedule_method = build_schedule(scoreboard, schedule_graph, config, use_optimizer)

    export_ranking(scoreboard, schedule, schedule_method, config, out_path)

    unmapped = findings[findings["system"].isna()]
    if not unmapped.empty:
        print(f"\n[CADENCE Migration Planner] Note: {len(unmapped)} finding(s) had no system in "
              f"system_file_map.json and were not counted toward any system's risk score: "
              f"{sorted(unmapped['file'].unique().tolist())}")

    print(f"\nSystems in roadmap   : {len(scoreboard)}")
    print(f"Scheduling method    : {schedule_method}")
    print("\nTop priorities:")
    preview = scoreboard.copy()
    preview["scheduled_week"] = preview["asset_id"].map(schedule)
    print(preview[["priority_rank", "asset_id", "score", "worst_severity",
                    "total_dependents", "scheduled_week"]].head(10).to_string(index=False))

    return scoreboard


def main():
    parser = argparse.ArgumentParser(description="CADENCE migration planner")
    parser.add_argument("--cbom", default="../cadence_module1/cbom.json",
                         help="Path to the scanner's CBOM output (preferred)")
    parser.add_argument("--vulnerabilities", default="../cadence_module1/vulnerabilities.json",
                         help="Path to the scanner's legacy output (used if --cbom is missing)")
    parser.add_argument("--graph", default="../cadence_module2/dependency_graph.json",
                         help="Path to the enterprise dependency map")
    parser.add_argument("--system-map", default="system_file_map.json",
                         help="Path to the file->system rollup map")
    parser.add_argument("--config", default="constraints.json",
                         help="Path to the business-constraints config")
    parser.add_argument("--out", default="migration_ranking.json",
                         help="Where to write the migration roadmap")
    parser.add_argument("--no-optimize", action="store_true",
                         help="Skip the PuLP scheduler and use simple greedy scheduling instead")
    args = parser.parse_args()

    run(args.cbom, args.vulnerabilities, args.graph, args.system_map,
        args.config, args.out, use_optimizer=not args.no_optimize)


if __name__ == "__main__":
    main()
