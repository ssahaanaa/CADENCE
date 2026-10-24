"""
config.py — the scan target + business constraints the team edits from
the Settings panel. Two files back this:

  backend/data/scan_config.json   -> what to scan (path / github org / domain / hosts)
  cadence_module3/constraints.json -> team size, budget, weights, deadlines
                                       (owned by Module 3 already — we just read/write it
                                       through the same API so there's one Settings screen)
"""

from __future__ import annotations

import json
import os
import tempfile
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(__file__).resolve().parent / "data"
SCAN_CONFIG_PATH = DATA_DIR / "scan_config.json"
CONSTRAINTS_PATH = ROOT / "cadence_module3" / "constraints.json"
INR_PER_USD_REFERENCE = 96.8

DEFAULT_SCAN_CONFIG = {
    "path": "",
    "github_org": "",
    "github_token": "",
    "domain": "",
    "hosts": [],
    "project_name": "your-company",
}

DEFAULT_CONSTRAINTS = {
    "team_size": 4,
    "planning_horizon_weeks": 10,
    "total_budget": 7744000,
    "cost_per_engineer_week": 387200,
    "currency": "INR",
    "weights": {"risk": 0.4, "dependency": 0.3, "compliance": 0.2, "cost": 0.1},
    "compliance_deadlines": {},
    "enforce_dependency_precedence": True,
}


def _read_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return dict(default)
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else dict(default)
    except (json.JSONDecodeError, OSError):
        return dict(default)


def _write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _ensure_inr_constraints(constraints: dict, path: Path = CONSTRAINTS_PATH) -> dict:
    currency = str(constraints.get("currency", "USD")).upper()
    if currency == "INR":
        return constraints
    if currency != "USD":
        return constraints
    for field in ("total_budget", "cost_per_engineer_week"):
        if field in constraints:
            try:
                constraints[field] = round(float(constraints[field]) * INR_PER_USD_REFERENCE)
            except (TypeError, ValueError):
                pass
        else:
            constraints[field] = DEFAULT_CONSTRAINTS[field]
    constraints["currency"] = "INR"
    _write_json(path, constraints)
    return constraints


def _workspace_paths(workspace_id: str):
    if not workspace_id or workspace_id == "default":
        return SCAN_CONFIG_PATH, CONSTRAINTS_PATH
    digest = hashlib.sha256(workspace_id.encode("utf-8")).hexdigest()
    directory = DATA_DIR / "workspaces" / digest
    return directory / "scan_config.json", directory / "constraints.json"


def load(workspace_id: str = "default") -> dict:
    scan_path, constraints_path = _workspace_paths(workspace_id)
    scan_cfg = _read_json(scan_path, DEFAULT_SCAN_CONFIG)
    constraints = _ensure_inr_constraints(_read_json(constraints_path, DEFAULT_CONSTRAINTS), constraints_path)
    merged = dict(DEFAULT_SCAN_CONFIG)
    merged.update(scan_cfg)
    merged["constraints"] = constraints
    return merged


def save(payload: dict, workspace_id: str = "default") -> dict:
    scan_path, constraints_path = _workspace_paths(workspace_id)
    scan_fields = {k: payload.get(k, DEFAULT_SCAN_CONFIG[k]) for k in DEFAULT_SCAN_CONFIG}
    _write_json(scan_path, scan_fields)
    if "constraints" in payload and isinstance(payload["constraints"], dict):
        constraints = dict(DEFAULT_CONSTRAINTS)
        constraints.update(payload["constraints"])
        _write_json(constraints_path, _ensure_inr_constraints(constraints, constraints_path))
    return load(workspace_id)


def activate_constraints(cfg: dict):
    """Copy one workspace's constraints into the legacy module-3 path for a locked run."""
    constraints = cfg.get("constraints")
    if isinstance(constraints, dict):
        _write_json(CONSTRAINTS_PATH, constraints)

def is_target_configured(cfg: dict) -> bool:
    return bool(cfg.get("path") or cfg.get("github_org") or cfg.get("domain"))
