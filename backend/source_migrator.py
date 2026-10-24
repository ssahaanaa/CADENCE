"""Plan-driven, conservative crypto source transformations.

Only mechanically bounded edits are applied. Ambiguous cipher, protocol, key
lifecycle, and call-site migrations stay in manual review in the repository
migration report.
"""
from __future__ import annotations

import ast
import re


def detect_algorithms(text: str, suffix: str) -> list[str]:
    """Low-confidence fallback vocabulary for files without a usable AST scan."""
    found: list[str] = []
    patterns = [
        ("MD5", r"\b(?:hashlib\.)?md5\s*\("),
        ("SHA1", r"\b(?:hashlib\.)?sha[-_]?1\s*\("),
        ("3DES", r"\b3DES\b|\bDESede\b|DES/(?:CBC3|EDE)"),
        ("DES", r"\b(?:DES|des)\s*\.\s*new\s*\(|\bDES/(?:ECB|CBC)"),
        ("RC4", r"\b(?:RC4|ARC4|ARCFOUR)\b"),
        ("Blowfish", r"\b(?:Blowfish|BLOWFISH)\b"),
        ("TLSv1.0/1.1", r"\b(?:PROTOCOL_TLSv1(?:_1)?|TLSv1(?:\.0|\.1)?|TLS1\.[01])\b"),
        ("SSLv2", r"\b(?:PROTOCOL_SSLv2|PROTOCOL_SSLv23|SSLv2|SSLv23)\b"),
        ("SSLv3", r"\b(?:PROTOCOL_SSLv3|SSLv3)\b"),
    ]
    for name, pattern in patterns:
        if re.search(pattern, text, re.I if name not in {"DES"} else 0):
            found.append(name)
    for match in re.finditer(r"(?:RSA\.generate\(\s*|key_size\s*=\s*)(\d{3,4})", text, re.I):
        bits = int(match.group(1))
        if bits < 2048:
            found.append(f"RSA-{bits}")
    return list(dict.fromkeys(found))


def _python_hash_rewrites(text: str, replacements: dict[str, str]) -> tuple[str, dict[str, int]]:
    """Rewrite recognized hashlib AST calls/imports without broad text substitutions."""
    tree = ast.parse(text)
    lines = text.splitlines(keepends=True)
    line_offsets = [0]
    for line in lines:
        line_offsets.append(line_offsets[-1] + len(line))

    def offset(line: int, byte_col: int) -> int:
        prefix = lines[line - 1].encode("utf-8")[:byte_col]
        return line_offsets[line - 1] + len(prefix.decode("utf-8"))

    edits: list[tuple[int, int, str]] = []
    counts = {algorithm: 0 for algorithm in replacements}
    modules = {"hashlib"}
    imported_functions: dict[str, tuple[str, bool]] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "hashlib":
                    modules.add(alias.asname or "hashlib")
        elif isinstance(node, ast.ImportFrom) and node.module == "hashlib":
            for alias in node.names:
                original = alias.name.lower()
                algorithm = "MD5" if original == "md5" else ("SHA1" if original in {"sha1", "sha_1"} else None)
                if algorithm not in replacements:
                    continue
                imported_functions[alias.asname or alias.name] = (algorithm, alias.asname is None)
                start = offset(alias.lineno, alias.col_offset)
                end = offset(alias.end_lineno, alias.end_col_offset)
                segment = text[start:end]
                match = re.match(r"\s*(md5|sha[-_]?1)\b", segment, re.I)
                if match:
                    replacement_name = replacements[algorithm]
                    edits.append((start + match.start(1), start + match.end(1), replacement_name))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        algorithm = None
        edit_start = edit_end = None
        if isinstance(function, ast.Attribute) and function.attr.lower() in {"md5", "sha1", "sha_1"}:
            if isinstance(function.value, ast.Name) and function.value.id in modules:
                algorithm = "MD5" if function.attr.lower() == "md5" else "SHA1"
                edit_start = offset(function.end_lineno, function.end_col_offset) - len(function.attr)
                edit_end = edit_start + len(function.attr)
        elif isinstance(function, ast.Attribute) and function.attr.lower() == "new":
            if isinstance(function.value, ast.Name) and function.value.id in modules and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    algo_name = first.value.lower().replace("-", "")
                    algorithm = "MD5" if algo_name == "md5" else ("SHA1" if algo_name in {"sha1", "sha_1"} else None)
                    if algorithm:
                        edit_start = offset(first.lineno, first.col_offset)
                        edit_end = offset(first.end_lineno, first.end_col_offset)
                        quote = text[edit_start:edit_start + 1]
                        edits.append((edit_start, edit_end, quote + replacements.get(algorithm, first.value) + quote))
                        counts[algorithm] += 1
                        continue
        elif isinstance(function, ast.Name) and function.id in imported_functions:
            algorithm, update_call_name = imported_functions[function.id]
            if update_call_name:
                edit_start = offset(function.lineno, function.col_offset)
                edit_end = offset(function.end_lineno, function.end_col_offset)
            else:
                # The import token changes to sha256 while the local alias is
                # intentionally preserved at this call site.
                if algorithm in replacements:
                    counts[algorithm] += 1
                continue
        if algorithm in replacements and edit_start is not None and edit_end is not None:
            edits.append((edit_start, edit_end, replacements[algorithm]))
            counts[algorithm] += 1

    if not edits:
        return text, counts
    edits.sort(key=lambda item: (item[0], item[1]))
    for previous, current in zip(edits, edits[1:]):
        if current[0] < previous[1]:
            raise ValueError("Overlapping source transformation spans")
    out = text
    for start, end, replacement in reversed(edits):
        out = out[:start] + replacement + out[end:]
    return out, counts


def migrate_source(text: str, suffix: str, algorithms: list[str],
                   replacements: dict[str, str] | None = None) -> tuple[str, list[dict]]:
    """Apply only syntax-aware or exact-call-site rewrites supported by the plan."""
    out = text
    changes: list[dict] = []
    replacements = replacements or {}
    ext = suffix.lower()

    if ext == ".py" and any(algorithm in algorithms for algorithm in ("MD5", "SHA1")):
        python_targets = {}
        for algorithm in ("MD5", "SHA1"):
            if algorithm in algorithms:
                target = replacements.get(algorithm, "SHA-256")
                python_targets[algorithm] = target.lower().replace("-", "")
        migrated, counts = _python_hash_rewrites(out, python_targets)
        out = migrated
        changes.extend({"algorithm": algorithm, "count": count}
                       for algorithm, count in counts.items() if count)

    def sub(pattern: str, repl: str, algorithm: str, flags: int = 0):
        nonlocal out
        new, count = re.subn(pattern, repl, out, flags=flags)
        if count:
            out = new
            changes.append({"algorithm": algorithm, "count": count})

    if ext in {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"} and any(
            algorithm in algorithms for algorithm in ("MD5", "SHA1")):
        js_targets = {algorithm: replacements.get(algorithm, "SHA-256")
                      for algorithm in ("MD5", "SHA1") if algorithm in algorithms}
        out, counts = _javascript_hash_rewrites(out, js_targets)
        changes.extend({"algorithm": algorithm, "count": count}
                       for algorithm, count in counts.items() if count)

    if "MD5" in algorithms and ext == ".java":
        name = replacements.get("MD5", "SHA-256")
        sub(r'getInstance\s*\(\s*["\']MD5["\']\s*\)', 'getInstance("' + name + '")', "MD5", re.I)

    if "SHA1" in algorithms and ext == ".java":
        name = replacements.get("SHA1", "SHA-256")
        sub(r'getInstance\s*\(\s*["\']SHA-?1["\']\s*\)', 'getInstance("' + name + '")', "SHA1", re.I)

    if "RSA-1024" in algorithms:
        if ext == ".py":
            sub(r"key_size\s*=\s*1024", "key_size=3072", "RSA-1024")
            sub(r"RSA\.generate\(\s*1024\s*\)", "RSA.generate(3072)", "RSA-1024")
        elif ext == ".java":
            sub(r"initialize\s*\(\s*1024\s*\)", "initialize(3072)", "RSA-1024")

    # Ciphers and protocol configuration require system-specific changes to
    # keys, modes, nonce/IV handling, peer compatibility, and rollout policy.
    # They stay untouched for explicit engineering review.
    return out, changes


def _javascript_hash_rewrites(text: str, replacements: dict[str, str]) -> tuple[str, dict[str, int]]:
    """Rewrite only AST-confirmed crypto.createHash call arguments."""
    from pathlib import Path
    import sys
    module1 = Path(__file__).resolve().parent.parent / "cadence_module1"
    if str(module1) not in sys.path:
        sys.path.insert(0, str(module1))
    from ast_multilang import JS_DIRECT_QUERY, JS_LANGUAGE, JS_QUERY
    from tree_sitter import Parser, QueryCursor

    source = text.encode("utf-8")
    tree = Parser(JS_LANGUAGE).parse(source)
    if tree.root_node.has_error:
        raise SyntaxError("JavaScript parser reported syntax errors")
    source_text = text
    crypto_aliases = {"crypto"}
    crypto_aliases.update(re.findall(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"](?:node:)?crypto['\"]\s*\)",
        source_text,
    ))
    crypto_aliases.update(re.findall(
        r"import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['\"](?:node:)?crypto['\"]",
        source_text,
    ))
    crypto_aliases.update(re.findall(
        r"import\s+([A-Za-z_$][\w$]*)\s+from\s+['\"](?:node:)?crypto['\"]",
        source_text,
    ))
    named_methods: dict[str, str] = {}
    named_imports = re.finditer(
        r"import\s*\{([^}]+)\}\s*from\s*['\"](?:node:)?crypto['\"]|"
        r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['\"](?:node:)?crypto['\"]\s*\)",
        source_text,
    )
    for match in named_imports:
        for entry in (match.group(1) or match.group(2)).split(","):
            tokens = re.split(r"\s+as\s+|\s*:\s*", entry.strip())
            if tokens and tokens[0].strip():
                named_methods[tokens[-1].strip()] = tokens[0].strip()

    edits: list[tuple[int, int, bytes]] = []
    counts = {algorithm: 0 for algorithm in replacements}
    for _, captures in QueryCursor(JS_QUERY).matches(tree.root_node):
        obj = captures["obj"][0].text.decode()
        method = captures["method"][0].text.decode()
        arg = captures["arg"][0]
        algorithm = "MD5" if arg.text.decode().lower() == "md5" else (
            "SHA1" if arg.text.decode().lower() == "sha1" else None)
        if obj in crypto_aliases and method == "createHash" and algorithm in replacements:
            edits.append((arg.start_byte, arg.end_byte, replacements[algorithm].lower().replace("-", "").encode()))
            counts[algorithm] += 1

    for _, captures in QueryCursor(JS_DIRECT_QUERY).matches(tree.root_node):
        local = captures["method"][0].text.decode()
        if named_methods.get(local) != "createHash":
            continue
        arg = captures["arg"][0]
        algorithm = "MD5" if arg.text.decode().lower() == "md5" else (
            "SHA1" if arg.text.decode().lower() == "sha1" else None)
        if algorithm in replacements:
            edits.append((arg.start_byte, arg.end_byte, replacements[algorithm].lower().replace("-", "").encode()))
            counts[algorithm] += 1

    if not edits:
        return text, counts
    edits.sort(key=lambda item: (item[0], item[1]))
    out = source
    for start, end, replacement in reversed(edits):
        out = out[:start] + replacement + out[end:]
    return out.decode("utf-8"), counts
