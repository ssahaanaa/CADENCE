"""
scanner.py — Source-code layer of CADENCE Module 1.

Primary detection: AST walk (WeakCryptoVisitor) — high confidence.
Fallback detection: keyword/regex scan — used for non-Python files or when
AST parsing fails — lower confidence ("needs_review"), matching CADENCE's
existing triage convention.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

from cbom import CryptoAsset, Occurrence

WEAK_HASHES = {"md5", "sha1"}
WEAK_CIPHERS = {"DES", "DES3", "3DES", "ARC4", "RC4", "Blowfish"}
MIN_RSA_KEY_SIZE = 2048
MAX_SOURCE_FILE_BYTES = 5 * 1024 * 1024
WEAK_TLS_PROTOCOLS = {
    "PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_SSLv23",
    "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1",
}

KEYWORD_PATTERNS = {
    "MD5": re.compile(r"\bmd5\b", re.IGNORECASE),
    "SHA1": re.compile(r"\bsha-?1\b", re.IGNORECASE),
    "DES": re.compile(r"\bDES\b"),
    "RC4": re.compile(r"\bRC4\b|\bARC4\b"),
    "SSLv3": re.compile(r"\bSSLv3\b"),
    "TLSv1.0/1.1": re.compile(r"\bTLSv1(?!\.?[23])\b|\bTLS1\.[01]\b"),
}


class WeakCryptoVisitor(ast.NodeVisitor):
    """AST walker — the primary, high-confidence detection path."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: list[CryptoAsset] = []
        self.hashlib_modules = {"hashlib"}
        self.hashlib_functions: dict[str, str] = {}
        self.cipher_classes = {"DES": "DES", "DES3": "3DES", "ARC4": "ARC4", "Blowfish": "Blowfish"}

    def _emit(self, name, asset_type, primitive, node, severity="medium", notes=""):
        self.findings.append(CryptoAsset(
            name=name,
            asset_type=asset_type,
            primitive=primitive,
            confidence="high",
            detection_method="ast",
            severity=severity,
            occurrences=[Occurrence(location=self.filepath, line=getattr(node, "lineno", None))],
            notes=notes,
        ))

    def _dotted_name(self, node: ast.AST) -> str:
        """Reconstruct a dotted attribute/call chain, e.g. hashlib.md5 -> 'hashlib.md5'."""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def visit_Call(self, node: ast.Call):
        raw_name = self._dotted_name(node.func) if isinstance(node.func, (ast.Attribute, ast.Name)) else ""
        func_name = self.hashlib_functions.get(raw_name, raw_name)
        if "." in func_name:
            module_name, method_name = func_name.rsplit(".", 1)
            if module_name in self.hashlib_modules:
                func_name = "hashlib." + method_name
        parts = func_name.split(".")
        if len(parts) >= 2 and parts[-1] == "new" and parts[-2] in self.cipher_classes:
            func_name = self.cipher_classes[parts[-2]] + ".new"

        # hashlib.md5() / hashlib.sha1() / hashlib.new("md5")
        if func_name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
            algo = func_name.split(".")[-1].upper()
            self._emit(algo, "algorithm", "hash", node, severity="medium",
                       notes="Cryptographically broken hash used directly.")
        elif func_name == "hashlib.new" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.lower() in WEAK_HASHES:
                self._emit(arg.value.upper(), "algorithm", "hash", node, severity="medium",
                           notes="Weak hash requested via hashlib.new().")

        # Crypto.Cipher.DES / ARC4 usage: DES.new(...) / ARC4.new(...)
        elif (func_name in {"DES.new", "DES3.new", "3DES.new", "ARC4.new", "Blowfish.new"}
              or func_name.endswith(".DES3.new")
              or func_name == "TripleDES"
              or func_name.endswith(".TripleDES")):
            algo = "3DES" if "DES3" in func_name or "3DES" in func_name or "TripleDES" in func_name else func_name.split(".")[-2]
            self._emit(algo, "algorithm", "cipher", node, severity="high",
                       notes="Deprecated symmetric cipher.")

        # rsa.generate_private_key(key_size=...)
        elif func_name in {"rsa.generate_private_key", "RSA.generate"}:
            key_size = None
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    key_size = kw.value.value
            if key_size is None and node.args:
                # RSA.generate(1024) positional form
                if isinstance(node.args[0], ast.Constant):
                    key_size = node.args[0].value
            if isinstance(key_size, int) and key_size < MIN_RSA_KEY_SIZE:
                self._emit(f"RSA-{key_size}", "algorithm", "signature", node, severity="high",
                           notes=f"RSA key size {key_size} < {MIN_RSA_KEY_SIZE}-bit minimum.")

        # ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1) or SSLContext(ssl.PROTOCOL_TLSv1)
        elif func_name in {"ssl.wrap_socket", "ssl.SSLContext"}:
            for arg in node.args + [kw.value for kw in node.keywords]:
                proto = self._dotted_name(arg) if isinstance(arg, ast.Attribute) else None
                if proto and proto.split(".")[-1] in WEAK_TLS_PROTOCOLS:
                    self._emit(proto.split(".")[-1].replace("PROTOCOL_", ""), "protocol", None,
                               node, severity="high", notes="Deprecated TLS/SSL protocol version.")

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "hashlib":
                self.hashlib_modules.add(alias.asname or "hashlib")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "hashlib":
            for alias in node.names:
                if alias.name.lower() in {"md5", "sha1", "new"}:
                    self.hashlib_functions[alias.asname or alias.name] = "hashlib." + alias.name.lower()
        if node.module == "Crypto.Cipher":
            for alias in node.names:
                if alias.name in self.cipher_classes:
                    self.cipher_classes[alias.asname or alias.name] = self.cipher_classes[alias.name]
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # Bare reference e.g. ssl.PROTOCOL_TLSv1 used outside a call (assigned to a var)
        name = self._dotted_name(node)
        tail = name.split(".")[-1]
        if tail in WEAK_TLS_PROTOCOLS and name.startswith("ssl."):
            self._emit(tail.replace("PROTOCOL_", ""), "protocol", None, node,
                       severity="high", notes="Deprecated TLS/SSL protocol constant referenced.")
        self.generic_visit(node)


def scan_python_file(path: Path) -> list[CryptoAsset]:
    try:
        source = path.read_text(encoding="utf-8-sig", errors="ignore")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return scan_with_keywords(path)  # AST failed -> fall back

    visitor = WeakCryptoVisitor(str(path))
    visitor.visit(tree)
    return visitor.findings


def scan_with_keywords(path: Path) -> list[CryptoAsset]:
    """Fallback for non-Python files, or Python files that failed to parse."""
    findings = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings

    for lineno, line in enumerate(lines, start=1):
        for name, pattern in KEYWORD_PATTERNS.items():
            if pattern.search(line):
                asset_type = "protocol" if "TLS" in name or "SSL" in name else "algorithm"
                findings.append(CryptoAsset(
                    name=name,
                    asset_type=asset_type,
                    confidence="needs_review",
                    detection_method="keyword",
                    severity="low",
                    occurrences=[Occurrence(location=str(path), line=lineno)],
                    notes="Keyword match — not contextually verified, requires manual review.",
                ))
    return findings


PYTHON_EXT = {".py"}
JAVA_EXT = {".java"}
JS_EXT = {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"}
FALLBACK_EXT = {".go", ".rb", ".php", ".cs", ".cpp", ".c", ".conf", ".yml", ".yaml", ".env"}
IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "virtualenv", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox", ".cache",
    ".gradle", ".next", ".nuxt", ".turbo", "build", "dist", "coverage", "target",
}


def scan_directory(root: str) -> list[CryptoAsset]:
    """Scan a single supported source file or every supported file in a directory.

    The Settings UI accepts a source path, and users commonly select a file
    rather than its parent directory. os.walk(file_path) yields no entries,
    which previously made such scans look successful while returning zero
    findings. Normalize both forms through the same file scanner.
    """
    try:
        from ast_multilang import scan_java_file, scan_js_file
    except ImportError:
        # Keep Python and keyword scanning available if optional parser wheels
        # are unavailable on a platform; deployments should install requirements.
        scan_java_file = scan_js_file = None

    root_path = Path(root).expanduser()
    if not root_path.exists():
        raise FileNotFoundError(f"Source scan path does not exist: {root_path}")
    if root_path.is_file():
        files = [root_path]
    elif root_path.is_dir():
        files = []
        for directory, child_dirs, filenames in os.walk(root_path, topdown=True, followlinks=False):
            child_dirs[:] = sorted(name for name in child_dirs if name.casefold() not in IGNORED_DIRS)
            files.extend(Path(directory) / name for name in sorted(filenames))
    else:
        raise ValueError(f"Source scan path is not a regular file or directory: {root_path}")

    findings: list[CryptoAsset] = []
    supported_files = 0
    for path in files:
        suffix = path.suffix.casefold()
        if suffix not in PYTHON_EXT | JAVA_EXT | JS_EXT | FALLBACK_EXT:
            continue
        try:
            size = path.stat().st_size
            if size > MAX_SOURCE_FILE_BYTES:
                print(f"[!] Skipping {path}: {size} bytes exceeds the "
                      f"{MAX_SOURCE_FILE_BYTES}-byte source-file limit.")
                continue
            supported_files += 1
            if suffix in PYTHON_EXT:
                findings.extend(scan_python_file(path))
            elif suffix in JAVA_EXT:
                ast_findings = scan_java_file(path) if scan_java_file else None
                findings.extend(ast_findings if ast_findings is not None else scan_with_keywords(path))
            elif suffix in JS_EXT:
                ast_findings = scan_js_file(path) if scan_js_file else None
                findings.extend(ast_findings if ast_findings is not None else scan_with_keywords(path))
            elif suffix in FALLBACK_EXT:
                findings.extend(scan_with_keywords(path))
        except OSError as exc:
            # A file that disappears or becomes unreadable should not silently
            # make the entire repository scan fail or count as clean.
            print(f"[!] Could not scan {path}: {exc}")
    if supported_files == 0:
        print(f"[!] No supported source files found under {root_path}")
    else:
        print(f"[+] Scanned {supported_files} supported source file(s); "
              f"found {len(findings)} cryptographic finding(s).")
    return findings
