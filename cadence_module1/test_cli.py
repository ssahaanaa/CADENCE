import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliOutputTests(unittest.TestCase):
    def test_missing_output_directory_is_created(self):
        module_dir = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.py"
            source.write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
            output = root / "nested" / "scan-output"
            subprocess.run(
                [sys.executable, "cli.py", str(source), "--out-dir", str(output)],
                cwd=module_dir,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue((output / "cbom.json").is_file())
            self.assertTrue((output / "vulnerabilities.json").is_file())
            findings = json.loads((output / "vulnerabilities.json").read_text())
            self.assertEqual(findings[0]["algorithm"], "MD5")


if __name__ == "__main__":
    unittest.main()
