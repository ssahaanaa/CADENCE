#!/usr/bin/env python3
"""Repository migration regressions: python -m unittest backend.test_repository_migrator"""
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from backend.repository_migrator import build_existing_module3_plan, migrate_repository, scan_repository


class RepositoryMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()

    def test_safe_hash_edit_and_cipher_manual_review_are_reported_separately(self):
        (self.source / "hashing.py").write_bytes(b"\xef\xbb\xbfimport hashlib\r\nvalue = hashlib.md5(b'x').hexdigest()\r\n")
        (self.source / "cipher.py").write_text("from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_ECB)\n", encoding="utf-8")
        scan = scan_repository(self.source)
        algorithms = sorted({a for entry in scan["inventory"] for a in entry["algorithms"]})
        plan = build_existing_module3_plan(algorithms)
        output = self.root / "output"
        report = migrate_repository(self.source, output, plan, scan)
        migrated = (output / "hashing.py").read_text(encoding="utf-8")
        migrated_bytes = (output / "hashing.py").read_bytes()
        untouched = (output / "cipher.py").read_text(encoding="utf-8")
        self.assertIn("hashlib.sha256", migrated)
        self.assertTrue(migrated_bytes.startswith(b"\xef\xbb\xbf"))
        self.assertIn(b"\r\n", migrated_bytes)
        self.assertIn("from Crypto.Cipher import DES", untouched)
        artifacts = output / report["artifacts_directory"]
        data = json.loads((artifacts / "cadence-migration-report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["files_scanned"], 2)
        self.assertEqual(report["summary"]["files_changed"], 1)
        self.assertEqual(report["summary"]["automatically_updated"], 1)
        self.assertEqual(report["summary"]["manual_review"], 1)
        self.assertEqual(report["summary"]["statically_validated_files"], 1)
        self.assertEqual(report["summary"]["post_edit_verified_files"], 1)
        self.assertEqual(report["summary"]["python_files_syntax_checked"], 1)
        self.assertFalse(report["summary"]["uploaded_project_tests_executed"])
        self.assertTrue((artifacts / "cadence-migration.patch").read_text(encoding="utf-8"))
        self.assertFalse(data["original_repository_modified"])
        self.assertIn("nonce/IV", data["manual_review"][0]["reason"])
        self.assertEqual(data["findings"][0]["confidence"], "high")

    def test_ambiguous_tls_endpoint_is_left_untouched_for_review(self):
        original = "import ssl\ncontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n"
        (self.source / "tls.py").write_text(original, encoding="utf-8")
        scan = scan_repository(self.source)
        plan = build_existing_module3_plan([a for item in scan["inventory"] for a in item["algorithms"]])
        output = self.root / "tls-output"
        report = migrate_repository(self.source, output, plan, scan)
        self.assertEqual((output / "tls.py").read_text(encoding="utf-8"), original)
        self.assertEqual(report["summary"]["files_changed"], 0)
        self.assertEqual(report["summary"]["manual_review"], 1)
        self.assertIn("client/server", report["manual_review"][0]["reason"])

    def test_ast_scan_resolves_python_aliases_and_ignores_comments_and_strings(self):
        source = self.source / "aliases.py"
        source.write_text(
            "# hashlib.md5(b'x') is only a comment\n"
            "note = \"hashlib.sha1(b'x')\"\n"
            "import hashlib as h\n"
            "from hashlib import sha1 as weak_hash\n"
            "a = h.md5(b'x')\n"
            "b = weak_hash(b'x')\n",
            encoding="utf-8",
        )
        scan = scan_repository(self.source)
        item = scan["inventory"][0]
        self.assertEqual(set(item["algorithms"]), {"MD5", "SHA1"})
        self.assertEqual(item["confidence"], "high")
        self.assertEqual(item["detector"], "python_ast")
        output = self.root / "alias-output"
        report = migrate_repository(self.source, output,
                                   build_existing_module3_plan(item["algorithms"]), scan)
        migrated = (output / "aliases.py").read_text(encoding="utf-8")
        self.assertIn("h.sha256(b'x')", migrated)
        self.assertIn("from hashlib import sha256 as weak_hash", migrated)
        self.assertIn("b = weak_hash(b'x')", migrated)
        self.assertNotIn("h.md5", migrated)
        self.assertNotIn("import sha1", migrated)
        self.assertEqual(report["summary"]["automatically_updated"], 2)
        self.assertEqual(report["summary"]["statically_validated_files"], 1)
        self.assertEqual(report["summary"]["post_edit_verified_files"], 1)
        line_by_algorithm = {finding["algorithm"]: finding["line"] for finding in report["findings"]}
        self.assertEqual(line_by_algorithm, {"MD5": 5, "SHA1": 6})

    def test_js_module_alias_and_java_protocol_version_are_ast_checked(self):
        (self.source / "hash.js").write_text(
            "// crypto.createHash('sha1') is not active code\n"
            "const c = require('node:crypto');\n"
            "const h = c.createHash('md5');\n", encoding="utf-8")
        (self.source / "Tls.java").write_text(
            'class T { void f() throws Exception { '
            'SSLContext.getInstance("TLSv1.2"); '
            'SSLContext.getInstance("TLSv1.1"); } }', encoding="utf-8")
        scan = scan_repository(self.source)
        by_file = {entry["file"]: entry for entry in scan["inventory"]}
        self.assertEqual(by_file["hash.js"]["algorithms"], ["MD5"])
        self.assertEqual(by_file["Tls.java"]["algorithms"], ["TLSv1.0/1.1"])
        self.assertEqual(by_file["hash.js"]["confidence"], "high")

    def test_js_named_import_alias_and_python_des3_are_detected(self):
        (self.source / "named.mjs").write_text(
            "import { createHash as makeHash } from 'node:crypto';\n"
            "// makeHash('sha1') is only documentation\nmakeHash('sha1');\n",
            encoding="utf-8")
        (self.source / "triple.py").write_text(
            "from Crypto.Cipher import DES3 as LegacyCipher\nLegacyCipher.new(key)\n",
            encoding="utf-8")
        scan = scan_repository(self.source)
        by_file = {item["file"]: item for item in scan["inventory"]}
        self.assertEqual(by_file["named.mjs"]["algorithms"], ["SHA1"])
        self.assertEqual(by_file["triple.py"]["algorithms"], ["3DES"])
        self.assertEqual(by_file["named.mjs"]["confidence"], "high")
        output = self.root / "named-js-output"
        report = migrate_repository(self.source, output,
                                   build_existing_module3_plan(by_file["named.mjs"]["algorithms"]), scan)
        migrated = (output / "named.mjs").read_text(encoding="utf-8")
        self.assertIn("// makeHash('sha1') is only documentation", migrated)
        self.assertIn("makeHash('sha256');", migrated)
        self.assertEqual(report["summary"]["automatically_updated"], 1)
        self.assertEqual(report["summary"]["post_edit_verified_files"], 1)

    def test_js_hash_rewrite_passes_syntax_and_post_edit_rescan(self):
        source = self.source / "hash.js"
        source.write_text("const c = require('crypto');\nconst h = c.createHash('md5');\n", encoding="utf-8")
        scan = scan_repository(self.source)
        plan = build_existing_module3_plan([a for item in scan["inventory"] for a in item["algorithms"]])
        output = self.root / "js-output"
        report = migrate_repository(self.source, output, plan, scan)
        self.assertIn("createHash('sha256')", (output / "hash.js").read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["statically_validated_files"], 1)
        self.assertEqual(report["summary"]["post_edit_verified_files"], 1)
        self.assertFalse(report["validation"]["uploaded_project_tests_executed"])
        self.assertEqual(report["changes"][0]["static_validation"], "tree_sitter_ast")

    def test_low_confidence_matches_are_reported_but_not_auto_edited(self):
        original = "# legacy note: hashlib.md5(value)\n"
        (self.source / "settings.env").write_text(original, encoding="utf-8")
        scan = scan_repository(self.source)
        item = scan["inventory"][0]
        self.assertEqual(item["confidence"], "needs_review")
        plan = build_existing_module3_plan(item["algorithms"])
        output = self.root / "fallback-output"
        report = migrate_repository(self.source, output, plan, scan)
        self.assertEqual((output / "settings.env").read_text(encoding="utf-8"), original)
        self.assertEqual(report["summary"]["files_changed"], 0)
        self.assertEqual(report["summary"]["needs_review_findings"], 1)
        self.assertIn("Low-confidence", report["manual_review"][0]["reason"])

    def test_vendor_build_directories_are_not_scanned_or_copied(self):
        (self.source / "NoDe_Modules").mkdir()
        (self.source / "NoDe_Modules" / "third_party.py").write_text("hashlib.md5(x)", encoding="utf-8")
        (self.source / "src").mkdir()
        (self.source / "src" / "app.py").write_text("print('ok')", encoding="utf-8")
        scan = scan_repository(self.source)
        self.assertEqual(scan["files_scanned"], 1)
        output = self.root / "out"
        migrate_repository(self.source, output, build_existing_module3_plan([]), scan)
        self.assertFalse((output / "NoDe_Modules").exists())

    def test_oversized_text_is_reported_as_skipped(self):
        large = self.source / "large.py"
        large.write_bytes(b"#" + b" " * (5 * 1024 * 1024))
        scan = scan_repository(self.source)
        self.assertEqual(scan["files_scanned"], 0)
        self.assertEqual(scan["skipped_files"][0]["file"], "large.py")

    def test_zip_path_traversal_is_rejected(self):
        archive = self.root / "unsafe.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../outside.txt", "no")
        with zipfile.ZipFile(archive) as zf:
            with self.assertRaises(ValueError):
                from backend.repository_migrator import _safe_extract
                _safe_extract(zf, self.root / "extract")

    def test_duplicate_normalized_zip_paths_are_rejected(self):
        archive = self.root / "duplicate.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("repo/file.py", "first")
            zf.writestr("repo/./file.py", "second")
        with zipfile.ZipFile(archive) as zf:
            with self.assertRaisesRegex(ValueError, "duplicate"):
                from backend.repository_migrator import _safe_extract
                _safe_extract(zf, self.root / "duplicate-extract")

    def test_existing_artifact_named_file_is_never_overwritten(self):
        original = "source-owned report\n"
        (self.source / "cadence-migration-report.json").write_text(original, encoding="utf-8")
        scan = scan_repository(self.source)
        output = self.root / "collision-output"
        report = migrate_repository(self.source, output, build_existing_module3_plan([]), scan)
        self.assertEqual((output / "cadence-migration-report.json").read_text(encoding="utf-8"), original)
        self.assertEqual(report["artifacts_directory"], "cadence-migration-artifacts")


if __name__ == "__main__":
    unittest.main(verbosity=2)
