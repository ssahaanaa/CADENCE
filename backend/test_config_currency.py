import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import config


class ConfigCurrencyTests(unittest.TestCase):
    def test_legacy_usd_constraints_convert_once_to_inr(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            constraints_path = Path(temporary_directory) / "constraints.json"
            constraints_path.write_text(
                json.dumps({
                    "team_size": 4,
                    "planning_horizon_weeks": 10,
                    "total_budget": 80000,
                    "cost_per_engineer_week": 4000,
                }),
                encoding="utf-8",
            )
            with patch.object(config, "CONSTRAINTS_PATH", constraints_path):
                first = config.load()["constraints"]
                second = config.load()["constraints"]

            self.assertEqual(first["total_budget"], 7744000)
            self.assertEqual(first["cost_per_engineer_week"], 387200)
            self.assertEqual(first["currency"], "INR")
            self.assertEqual(second, first, "the persisted currency marker prevents double conversion")
            saved = json.loads(constraints_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["currency"], "INR")


if __name__ == "__main__":
    unittest.main()
