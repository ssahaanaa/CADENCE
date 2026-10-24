#!/usr/bin/env python3
"""Traversal regressions: python3 test_scanner.py"""
import tempfile
import unittest
from pathlib import Path

from scanner import scan_directory


class ScanDirectoryTests(unittest.TestCase):
    def test_prunes_history_and_build_trees_but_keeps_source_and_vendor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = {
                "src/current.py": "import hashlib\nhashlib.md5(b'x')\n",
                "vendor/lib/crypto.py": "import hashlib\nhashlib.sha1(b'x')\n",
                ".git/objects/old.py": "import hashlib\nhashlib.md5(b'x')\n",
                ".venv/lib/site-packages/ignored.py": "import hashlib\nhashlib.md5(b'x')\n",
                "build/generated.py": "import hashlib\nhashlib.md5(b'x')\n",
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            findings = scan_directory(str(root))
            locations = {asset.occurrences[0].location for asset in findings}
            self.assertEqual(len(findings), 2)
            self.assertEqual(locations, {
                str(root / "src/current.py"),
                str(root / "vendor/lib/crypto.py"),
            })


    def test_single_python_file_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "single.py"
            path.write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
            findings = scan_directory(str(path))
            self.assertEqual([asset.name for asset in findings], ["MD5"])
            self.assertEqual(findings[0].occurrences[0].line, 2)

    def test_missing_source_path_fails_clearly(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does-not-exist.py"
            with self.assertRaises(FileNotFoundError):
                scan_directory(str(missing))

    def test_single_javascript_module_file_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.mjs"
            path.write_text("const crypto = require('crypto');\ncrypto.createHash('md5');\n", encoding="utf-8")
            findings = scan_directory(str(path))
            self.assertTrue(any(asset.name.upper() == "MD5" for asset in findings))

if __name__ == "__main__":
    unittest.main(verbosity=2)
