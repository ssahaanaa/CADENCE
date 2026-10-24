import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import db, runner
from cadence_module3 import pqc_solutions


class RunIsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_solution_progress_is_scoped_to_run_and_empty_findings_are_counted_as_empty(self):
        data_dir = self.root / "data"
        with patch.object(db, "DATA_DIR", data_dir), patch.object(db, "DB_PATH", data_dir / "cadence.db"):
            db.init_db()
            db.create_run("run-old")
            db.set_outputs("run-old", {
                "vulnerabilities.json": "[]",
                "cbom.json": json.dumps({"components": [{"type": "cryptographic-asset", "name": "MD5"}]}),
                "migration_ranking.json": json.dumps({"migration_order": []}),
                "current_system_file_map.json": json.dumps({"old.py": "Legacy Service"}),
            })
            db.set_status("run-old", "success")
            db.set_progress("run-old", "API Gateway", "fix-hash", True)

            db.create_run("run-new")
            db.set_outputs("run-new", {
                "vulnerabilities.json": json.dumps([{"algorithm": "DES"}]),
                "migration_ranking.json": json.dumps({"migration_order": []}),
                "current_system_file_map.json": json.dumps({"new.py": "Current Service"}),
            })
            db.set_status("run-new", "success")

            self.assertEqual(db.get_progress("run-old"), {("API Gateway", "fix-hash"): True})
            self.assertEqual(db.get_progress("run-new"), {})
            summaries = {r["id"]: r for r in db.list_runs()}
            self.assertFalse(summaries["run-old"]["has_findings"],
                             "an empty vulnerabilities list is authoritative over CBOM inventory")
            self.assertTrue(summaries["run-new"]["has_findings"])
            self.assertEqual(json.loads(db.get_run("run-old")["system_file_map_json"]),
                             {"old.py": "Legacy Service"})
            self.assertEqual(json.loads(db.get_run("run-new")["system_file_map_json"]),
                             {"new.py": "Current Service"})

    def test_runs_are_isolated_by_workspace_and_cross_workspace_lookup_is_denied(self):
        data_dir = self.root / "workspace-data"
        with patch.object(db, "DATA_DIR", data_dir), patch.object(db, "DB_PATH", data_dir / "cadence.db"):
            db.init_db()
            db.create_run("run-a", workspace_id="browser-a")
            db.create_run("run-b", workspace_id="browser-b")
            db.set_status("run-a", "success")
            db.set_status("run-b", "success")
            self.assertEqual([r["id"] for r in db.list_runs(workspace_id="browser-a")], ["run-a"])
            self.assertEqual([r["id"] for r in db.list_runs(workspace_id="browser-b")], ["run-b"])
            self.assertEqual(db.get_latest_success("browser-a")["id"], "run-a")
            self.assertEqual(db.get_latest_success("browser-b")["id"], "run-b")
            self.assertIsNone(db.get_run("run-a", "browser-b"))

    def test_solution_locations_use_current_run_file_map_not_fixture(self):
        self.assertEqual(pqc_solutions._load_file_map({"system_file_map_json": None}), {})
        file_path = "/new/repo/authentication.py"
        row = {
            "vulnerabilities_json": json.dumps([{
                "algorithm": "MD5", "file": file_path, "line": 17, "severity": "high",
                "confidence": "high"
            }]),
            "system_file_map_json": json.dumps({file_path: "Current Identity Service"}),
            "migration_ranking_json": json.dumps({"migration_order": [{
                "asset_id": "Current Identity Service", "priority_rank": 1,
                "scheduled_week": 1, "finding_count": 1, "algorithms": ["MD5"],
                "worst_severity": "high", "effort_weeks": 1, "estimated_cost": 100,
                "total_dependents": 0,
            }]}),
        }
        plan = pqc_solutions.build_plan(row)
        self.assertEqual(len(plan["systems"]), 1)
        self.assertEqual(plan["systems"][0]["changes"][0]["locations"], ["authentication.py:17"])
        self.assertEqual(plan["systems"][0]["changes"][0]["file_targets"], [{
            "path": file_path, "display": "authentication.py:17", "can_fix": True
        }])
        self.assertEqual(plan["systems"][0]["preferred_languages"], ["python"])

    def test_legacy_global_progress_is_preserved_but_not_reused(self):
        data_dir = self.root / "legacy-data"
        data_dir.mkdir()
        db_path = data_dir / "cadence.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute("""CREATE TABLE solution_progress (
                system TEXT NOT NULL, step_id TEXT NOT NULL, done INTEGER NOT NULL,
                updated_at TEXT NOT NULL, PRIMARY KEY(system, step_id))""")
            conn.execute("INSERT INTO solution_progress VALUES ('API Gateway','fix-hash',1,'2026-01-01')")
            conn.execute("""CREATE TABLE runs (
                id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT,
                status TEXT NOT NULL, trigger_type TEXT NOT NULL, error TEXT,
                log TEXT NOT NULL DEFAULT '', cbom_json TEXT, vulnerabilities_json TEXT,
                dependency_graph_json TEXT, centrality_scores_json TEXT, migration_ranking_json TEXT
            )""")

        with patch.object(db, "DATA_DIR", data_dir), patch.object(db, "DB_PATH", db_path):
            db.init_db()
            self.assertEqual(db.get_progress("new-run"), {})
            with sqlite3.connect(db_path) as conn:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                self.assertIn("solution_progress_legacy_v1", tables)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM solution_progress_legacy_v1").fetchone()[0], 1)
                columns = {r[1] for r in conn.execute("PRAGMA table_info(solution_progress)")}
                self.assertIn("run_id", columns)
                run_columns = {r[1] for r in conn.execute("PRAGMA table_info(runs)")}
                self.assertIn("system_file_map_json", run_columns)

    def test_pipeline_cleanup_removes_only_prior_generated_outputs(self):
        mod1, mod2, mod3 = (self.root / name for name in ("module1", "module2", "module3"))
        for directory in (mod1, mod2, mod3):
            directory.mkdir()
        outputs = [
            mod1 / "cbom.json", mod1 / "vulnerabilities.json",
            mod2 / "dependency_graph.json", mod2 / "dependency_graph.html",
            mod2 / "centrality_scores.json",
            mod2 / "current_system_file_map.json", mod3 / "migration_ranking.json",
        ]
        for path in outputs:
            path.write_text("stale", encoding="utf-8")
        keep = mod2 / "enterprise_architecture.json"
        keep.write_text("configuration", encoding="utf-8")

        with patch.object(runner, "MOD1", mod1), patch.object(runner, "MOD2", mod2), patch.object(runner, "MOD3", mod3):
            runner._clear_previous_outputs()

        self.assertTrue(all(not path.exists() for path in outputs))
        self.assertEqual(keep.read_text(encoding="utf-8"), "configuration")

    def test_subprocess_logs_are_batched_without_losing_lines(self):
        lines = []
        command = [sys.executable, "-c", "for i in range(45): print(f'line-{i}')"]
        runner._stream(command, self.root, lines.append)
        expanded = "\n".join(lines[1:]).splitlines()
        self.assertEqual(expanded, [f"line-{i}" for i in range(45)])
        self.assertEqual(len(lines[1:]), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
