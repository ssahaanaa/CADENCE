"""Fix now regressions: python -m unittest backend.test_fix_now -v"""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import config as cfgmod, db
from backend.main import FixFilePayload, fix_scanned_file


class FixNowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.data = self.root / "data"
        self.config_patchers = [
            patch.object(db, "DATA_DIR", self.data),
            patch.object(db, "DB_PATH", self.data / "cadence.db"),
            patch.object(cfgmod, "SCAN_CONFIG_PATH", self.data / "scan_config.json"),
            patch.object(cfgmod, "CONSTRAINTS_PATH", self.data / "constraints.json"),
        ]
        for patcher in self.config_patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        db.init_db()

        self.source_file = self.source / "auth.py"
        self.original = (
            "import hashlib\n"
            "from Crypto.Cipher import DES\n"
            "md5_digest = hashlib.md5(b'example').hexdigest()\n"
            "sha1_digest = hashlib.sha1(b'example').hexdigest()\n"
            "cipher = DES.new(b'12345678', DES.MODE_ECB)\n"
        ).encode("utf-8")
        self.source_file.write_bytes(self.original)
        cfgmod.save({"path": str(self.source), "project_name": "fix-now-test"})

        run_id = "scan-fix-now"
        db.create_run(run_id)
        db.set_outputs(run_id, {
            "vulnerabilities.json": json.dumps([{
                "algorithm": "MD5", "file": str(self.source_file), "line": 3,
                "confidence": "high", "severity": "high",
            }, {
                "algorithm": "SHA1", "file": str(self.source_file), "line": 4,
                "confidence": "high", "severity": "high",
            }, {
                "algorithm": "DES", "file": str(self.source_file), "line": 5,
                "confidence": "high", "severity": "high",
            }]),
            "migration_ranking.json": json.dumps({"migration_order": [{
                "asset_id": "Identity Service", "priority_rank": 1,
                "scheduled_week": 1, "finding_count": 3, "algorithms": ["MD5", "SHA1", "DES"],
                "worst_severity": "high", "effort_weeks": 1,
                "estimated_cost": 100, "total_dependents": 0,
            }]}),
            "current_system_file_map.json": json.dumps({str(self.source_file): "Identity Service"}),
        })
        db.set_status(run_id, "success")
        self.payload = FixFilePayload(run_id=run_id, system="Identity Service",
                                      file_path=str(self.source_file), algorithm="MD5")

    def test_downloads_validated_copy_for_exact_current_scan_and_preserves_original(self):
        response = fix_scanned_file(self.payload)

        async def collect():
            return b"".join([chunk async for chunk in response.body_iterator])

        fixed = asyncio.run(collect())
        self.assertIn(b"hashlib.sha256", fixed)
        self.assertNotIn(b"hashlib.md5", fixed)
        self.assertEqual(self.source_file.read_bytes(), self.original)
        self.assertIn("cadence-fixed.py", response.headers["content-disposition"])
        self.assertEqual(response.headers["x-cadence-post-edit-verified"], "true")
        self.assertEqual(response.headers["x-cadence-original-modified"], "false")

    def test_entire_file_fixes_all_safe_findings_and_reports_manual_leftovers(self):
        payload = FixFilePayload(run_id=self.payload.run_id, system=self.payload.system,
                                 file_path=self.payload.file_path, fix_entire_file=True)
        response = fix_scanned_file(payload)

        async def collect():
            return b"".join([chunk async for chunk in response.body_iterator])

        fixed = asyncio.run(collect())
        self.assertIn(b"hashlib.sha256", fixed)
        self.assertNotIn(b"hashlib.md5", fixed)
        self.assertNotIn(b"hashlib.sha1", fixed)
        self.assertEqual(fixed.count(b"hashlib.sha256"), 2)
        self.assertIn(b"DES.new", fixed)
        self.assertEqual(self.source_file.read_bytes(), self.original)
        self.assertEqual(response.headers["x-cadence-fix-scope"], "entire-file")
        self.assertEqual(response.headers["x-cadence-auto-fixed-findings"], "2")
        self.assertGreaterEqual(int(response.headers["x-cadence-manual-findings"]), 1)

    def test_rejects_file_not_in_exact_run_mapping(self):
        bad = FixFilePayload(run_id=self.payload.run_id, system="Identity Service",
                             file_path=str(self.source / "other.py"), algorithm="MD5")
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as caught:
            fix_scanned_file(bad)
        self.assertEqual(caught.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main(verbosity=2)
