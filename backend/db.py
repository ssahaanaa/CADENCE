"""
db.py — tiny SQLite persistence layer for CADENCE run history.

Deliberately dependency-free (stdlib sqlite3 only) so the whole backend
needs nothing beyond `pip install -r requirements.txt` to run anywhere.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
DB_PATH = DATA_DIR / "cadence.db"

_lock = threading.Lock()


def _conn():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock, _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL DEFAULT 'default',
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,           -- queued | running | success | failed
                trigger_type TEXT NOT NULL,     -- manual | scheduled
                error TEXT,
                log TEXT NOT NULL DEFAULT '',
                cbom_json TEXT,
                vulnerabilities_json TEXT,
                dependency_graph_json TEXT,
                centrality_scores_json TEXT,
                migration_ranking_json TEXT,
                system_file_map_json TEXT
            )
        """)
        run_columns = {r[1] for r in conn.execute("PRAGMA table_info(runs)")}
        if "workspace_id" not in run_columns:
            conn.execute("ALTER TABLE runs ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'default'")
        if "system_file_map_json" not in run_columns:
            conn.execute("ALTER TABLE runs ADD COLUMN system_file_map_json TEXT")
        progress_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='solution_progress'"
        ).fetchone()
        if progress_exists:
            columns = {r[1] for r in conn.execute("PRAGMA table_info(solution_progress)")}
            if "run_id" not in columns:
                # Preserve the old global checklist for audit/recovery, but do
                # not apply it to any new scan: it has no reliable run owner.
                legacy_name = "solution_progress_legacy_v1"
                suffix = 1
                while conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (legacy_name,)
                ).fetchone():
                    suffix += 1
                    legacy_name = f"solution_progress_legacy_v{suffix}"
                conn.execute(f"ALTER TABLE solution_progress RENAME TO {legacy_name}")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS solution_progress (
                run_id TEXT NOT NULL,
                system TEXT NOT NULL,
                step_id TEXT NOT NULL,
                done INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (run_id, system, step_id)
            )
        """)
        conn.commit()


def _now():
    return datetime.now(timezone.utc).isoformat()


def create_run(run_id: str, trigger_type: str = "manual", workspace_id: str = "default"):
    with _lock, _conn() as conn:
        conn.execute(
            "INSERT INTO runs (id, workspace_id, started_at, status, trigger_type, log) VALUES (?,?,?,?,?,?)",
            (run_id, workspace_id, _now(), "queued", trigger_type, ""),
        )
        conn.commit()


def set_status(run_id: str, status: str, error: str | None = None):
    with _lock, _conn() as conn:
        if status in ("success", "failed"):
            conn.execute(
                "UPDATE runs SET status=?, error=?, finished_at=? WHERE id=?",
                (status, error, _now(), run_id),
            )
        else:
            conn.execute("UPDATE runs SET status=?, error=? WHERE id=?", (status, error, run_id))
        conn.commit()


def append_log(run_id: str, line: str):
    with _lock, _conn() as conn:
        conn.execute(
            "UPDATE runs SET log = log || ? || char(10) WHERE id=?",
            (line, run_id),
        )
        conn.commit()


def set_outputs(run_id: str, outputs: dict):
    """outputs keys: cbom.json, vulnerabilities.json, dependency_graph.json,
    centrality_scores.json, migration_ranking.json, current_system_file_map.json."""
    mapping = {
        "cbom.json": "cbom_json",
        "vulnerabilities.json": "vulnerabilities_json",
        "dependency_graph.json": "dependency_graph_json",
        "centrality_scores.json": "centrality_scores_json",
        "migration_ranking.json": "migration_ranking_json",
        "current_system_file_map.json": "system_file_map_json",
    }
    cols, vals = [], []
    for filename, col in mapping.items():
        if filename in outputs:
            cols.append(f"{col}=?")
            vals.append(outputs[filename])
    if not cols:
        return
    vals.append(run_id)
    with _lock, _conn() as conn:
        conn.execute(f"UPDATE runs SET {', '.join(cols)} WHERE id=?", vals)
        conn.commit()


def _row_to_summary(row) -> dict:
    raw_findings = row["vulnerabilities_json"]
    if raw_findings is not None:
        try:
            parsed = json.loads(raw_findings)
            has_findings = isinstance(parsed, list) and bool(parsed)
        except (TypeError, json.JSONDecodeError):
            has_findings = False
    else:
        has_findings = False
    if not has_findings and raw_findings is None and row["cbom_json"]:
        try:
            components = json.loads(row["cbom_json"]).get("components", [])
            has_findings = bool(components)
        except (AttributeError, TypeError, json.JSONDecodeError):
            pass
    return {
        "id": row["id"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "status": row["status"],
        "trigger_type": row["trigger_type"],
        "error": row["error"],
        "has_findings": has_findings,
        "has_graph": bool(row["dependency_graph_json"]),
        "has_plan": bool(row["migration_ranking_json"]),
    }


def list_runs(limit: int = 30, workspace_id: str = "default") -> list[dict]:
    with _lock, _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM runs WHERE workspace_id=? ORDER BY started_at DESC LIMIT ?", (workspace_id, limit)
        ).fetchall()
        return [_row_to_summary(r) for r in rows]


def get_run(run_id: str, workspace_id: str = "default") -> dict | None:
    with _lock, _conn() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id=? AND workspace_id=?", (run_id, workspace_id)).fetchone()
        if not row:
            return None
        d = dict(row)
        return d


def get_latest_success(workspace_id: str = "default") -> dict | None:
    with _lock, _conn() as conn:
        row = conn.execute(
            "SELECT * FROM runs WHERE workspace_id=? AND status='success' ORDER BY finished_at DESC LIMIT 1", (workspace_id,)
        ).fetchone()
        return dict(row) if row else None


# ------------------------------------------------- remediation progress ---
# Keyed by (run, system, step): the team shares progress for one snapshot, but
# new scans start fresh and historical runs retain their own checklist state.
def get_progress(run_id: str) -> dict:
    with _lock, _conn() as conn:
        rows = conn.execute(
            "SELECT system, step_id, done FROM solution_progress WHERE run_id=?", (run_id,)
        ).fetchall()
        return {(r["system"], r["step_id"]): bool(r["done"]) for r in rows}


def set_progress(run_id: str, system: str, step_id: str, done: bool):
    with _lock, _conn() as conn:
        conn.execute(
            "INSERT INTO solution_progress (run_id, system, step_id, done, updated_at) VALUES (?,?,?,?,?) "
            "ON CONFLICT(run_id, system, step_id) DO UPDATE SET done=excluded.done, updated_at=excluded.updated_at",
            (run_id, system, step_id, 1 if done else 0, _now()),
        )
        conn.commit()
