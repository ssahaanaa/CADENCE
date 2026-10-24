"""Safe, auditable repository scanning and conservative migration helpers."""
from __future__ import annotations

import ast
import difflib
import json
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

if __package__:
    from .source_migrator import detect_algorithms, migrate_source
else:  # Compatibility when imported by `cd backend && uvicorn main:app`.
    from source_migrator import detect_algorithms, migrate_source
from cadence_module3 import pqc_solutions
MODULE1_DIR = Path(__file__).resolve().parent.parent / "cadence_module1"
if str(MODULE1_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE1_DIR))
from scanner import scan_python_file as _scan_python_file

SUPPORTED = {".py", ".java", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".conf", ".cnf", ".txt", ".nginx", ".cfg", ".ini", ".yml", ".yaml", ".env"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target", "vendor"}
MAX_TEXT_FILE_BYTES = 5 * 1024 * 1024


def _ignore_output_directory(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name.lower() in SKIP_DIRS}


def _canonical_algorithm(name: str) -> str:
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    if "md5" in compact:
        return "MD5"
    if "sha1" in compact:
        return "SHA1"
    if "blowfish" in compact:
        return "Blowfish"
    if "arcfour" in compact or "arc4" in compact or "rc4" in compact:
        return "RC4"
    if compact in {"3des", "tripledes"} or "desede" in compact:
        return "3DES"
    if "des" in compact:
        return "DES"
    rsa = re.search(r"rsa(?:key)?(\d+)", compact)
    if rsa:
        return f"RSA-{rsa.group(1)}"
    if "sslv2" in compact or "sslv23" in compact:
        return "SSLv2"
    if "sslv3" in compact:
        return "SSLv3"
    if "tlsv1" in compact or "tls10" in compact or "tls11" in compact:
        return "TLSv1.0/1.1"
    return name


def _detect_file(path: Path, text: str) -> tuple[list[str], str, str, dict[str, list[int]]]:
    """Return algorithms, detector, confidence, and precise AST call lines."""
    suffix = path.suffix.lower()
    assets = None
    detector = None
    if suffix == ".py":
        try:
            ast.parse(text, filename=str(path))
        except SyntaxError:
            pass
        else:
            assets = _scan_python_file(path)
            detector = "python_ast"
    elif suffix == ".java" or suffix in {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}:
        try:
            from ast_multilang import scan_java_file, scan_js_file
            if suffix == ".java":
                assets = scan_java_file(path)
                detector = "java_ast"
            else:
                assets = scan_js_file(path)
                detector = "javascript_ast"
        except (ImportError, OSError):
            assets = None
    if assets is not None:
        locations: dict[str, list[int]] = {}
        for asset in assets:
            name = _canonical_algorithm(asset.name)
            lines = [int(occurrence.line) for occurrence in (getattr(asset, "occurrences", None) or [])
                     if getattr(occurrence, "line", None)]
            locations.setdefault(name, [])
            locations[name].extend(lines)
        locations = {name: sorted(set(lines)) for name, lines in locations.items()}
        normalized = list(dict.fromkeys(_canonical_algorithm(asset.name) for asset in assets))
        return normalized, detector or "language_ast", "high", locations
    return detect_algorithms(text, suffix), "pattern_fallback", "needs_review", {}


def _validate_source_syntax(text: str, suffix: str) -> str | None:
    """Parse transformed source without importing or executing any project code."""
    suffix = suffix.lower()
    if suffix == ".py":
        ast.parse(text)
        return "python_ast"
    if suffix == ".java" or suffix in {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}:
        from ast_multilang import JAVA_LANGUAGE, JS_LANGUAGE
        from tree_sitter import Parser
        language = JAVA_LANGUAGE if suffix == ".java" else JS_LANGUAGE
        tree = Parser(language).parse(text.encode("utf-8"))
        if tree.root_node.has_error:
            raise SyntaxError(f"{suffix} parser reported syntax errors")
        return "tree_sitter_ast"
    return None


def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    """Validate every member before extraction; reject traversal and special files."""
    root = dest.resolve()
    seen = set()
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or ".." in Path(name).parts or "\x00" in name:
            raise ValueError("Unsafe path in repository archive")
        mode = info.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if stat.S_ISLNK(mode) or (kind and kind not in (stat.S_IFREG, stat.S_IFDIR)):
            raise ValueError("Repository archive contains an unsupported special file")
        target = (dest / name).resolve()
        if root != target and root not in target.parents:
            raise ValueError("Unsafe path in repository archive")
        canonical = target.relative_to(root).as_posix().casefold()
        if canonical and canonical in seen:
            raise ValueError("Repository archive contains duplicate paths")
        if canonical:
            seen.add(canonical)
    zf.extractall(dest)


def scan_repository(source_root: Path) -> dict:
    """Scan eligible UTF-8 source files once, excluding vendor/build trees."""
    source_root = source_root.resolve()
    inventory = []
    skipped = []
    files_scanned = 0
    total_bytes = 0
    for path in sorted(source_root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(source_root)
        if any(part.lower() in SKIP_DIRS for part in relative.parts[:-1]):
            continue
        if path.suffix.lower() not in SUPPORTED:
            continue
        try:
            size = path.stat().st_size
            if size > MAX_TEXT_FILE_BYTES:
                skipped.append({"file": relative.as_posix(), "reason": "Exceeds 5 MB text-file scan limit"})
                continue
            raw = path.read_bytes()
            text = raw.decode("utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            skipped.append({"file": relative.as_posix(), "reason": "Unreadable or not UTF-8 text"})
            continue
        files_scanned += 1
        total_bytes += size
        algorithms, detector, confidence, locations = _detect_file(path, text)
        newline = "\r\n" if b"\r\n" in raw else ("\r" if b"\r" in raw else "\n")
        inventory.append({"file": relative.as_posix(), "algorithms": algorithms,
                          "detector": detector, "confidence": confidence,
                          "locations": locations,
                          "newline": newline, "bom": raw.startswith(b"\xef\xbb\xbf")})
    return {"files_scanned": files_scanned, "bytes_scanned": total_bytes,
            "inventory": inventory, "skipped_files": skipped}


def _replacement_map(resolved_plan: dict) -> dict[str, str]:
    """Use the resolved Module 3 solution catalog as the replacement source."""
    out: dict[str, str] = {}
    for system in resolved_plan.get("systems", []):
        for change in system.get("changes", []):
            name, swap = (change.get("name") or "").strip(), (change.get("swap") or "").strip()
            if name and swap:
                out[name] = swap
    return out


def _lookup(mapping: dict[str, str], algorithm: str) -> str | None:
    norm = algorithm.lower().replace("-", "").replace("/", "")
    for key, value in mapping.items():
        if key.lower().replace("-", "").replace("/", "") == norm:
            return value
    for key, value in mapping.items():
        if key.lower() == "des" and algorithm in {"DES", "3DES"}:
            return value
        if key.lower() == "rc4" and algorithm == "RC4":
            return value
        if key.lower() == "blowfish" and algorithm == "Blowfish":
            return value
    return None


def build_existing_module3_plan(algorithms: list[str], profile: str = "standard") -> dict:
    """Resolve each detected algorithm through the existing Module 3 catalog."""
    changes = []
    seen = set()
    for algorithm in algorithms:
        key = algorithm.lower().replace("-", "").replace("/", "")
        if key in seen:
            continue
        seen.add(key)
        resolved = pqc_solutions.swap_for(algorithm, profile)
        changes.append({"name": algorithm, **resolved})
    return {"profile": profile, "source_of_truth": "CADENCE Module 3 solution catalog",
            "systems": [{"asset_id": "uploaded-repository", "changes": changes}]}


def _line_number(text: str, algorithm: str) -> int | None:
    token = re.sub(r"[^a-z0-9]", "", algorithm.lower())
    if not token:
        return None
    for number, line in enumerate(text.splitlines(), 1):
        normalized = re.sub(r"[^a-z0-9]", "", line.lower())
        if token in normalized or (algorithm == "TLSv1.0/1.1" and "tlsv1" in normalized):
            return number
    return None


def _manual_reason(algorithm: str, changes: list[dict]) -> str:
    if algorithm in {"DES", "3DES", "RC4", "Blowfish"}:
        return "Cipher migration changes key, mode, nonce/IV, padding and authentication handling; no semantics-safe automatic rewrite was applied."
    if algorithm in {"TLSv1.0/1.1", "SSLv2", "SSLv3"}:
        return "Protocol configuration and client/server behavior need review; confirm TLS 1.2/1.3 compatibility at each call site."
    if changes:
        return "A related mechanical edit was made, but this detection was not fully rewritten. Review the call site and test it."
    return "No supported, semantics-safe automatic rewrite matched this occurrence. Use the proposed replacement as a manual migration task."


def migrate_repository(source_root: Path, output_root: Path, resolved_plan: dict,
                       scan: dict | None = None) -> dict:
    """Copy the source unchanged, apply only safe rewrites, emit a report and patch."""
    if output_root.exists():
        raise FileExistsError(f"Migration output directory already exists: {output_root}")
    scan = scan or scan_repository(source_root)
    shutil.copytree(source_root, output_root, ignore=_ignore_output_directory)
    mapping = _replacement_map(resolved_plan)
    findings, manual_review, changes, patches = [], [], [], []
    validation_rejections = []
    files_changed = 0
    changed_python = 0
    statically_validated = 0
    post_edit_verified = 0
    for item in scan["inventory"]:
        relative = item["file"]
        algorithms = item["algorithms"]
        if not algorithms:
            continue
        original_path = source_root / relative
        try:
            original = original_path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            for algorithm in algorithms:
                manual_review.append({"file": relative, "algorithm": algorithm,
                                     "proposed_replacement": _lookup(mapping, algorithm),
                                     "status": "manual_review", "reason": "File could not be re-read for migration."})
            continue
        replacements = {algo: _lookup(mapping, algo) for algo in algorithms if _lookup(mapping, algo)}
        if any(algo in algorithms for algo in ("DES", "3DES", "RC4", "Blowfish")):
            symmetric = next((algo for algo in algorithms if algo in {"DES", "3DES", "RC4", "Blowfish"}), None)
            if symmetric:
                replacements["symmetric"] = _lookup(mapping, symmetric) or "AES-256-GCM"
        if item.get("confidence") == "high":
            migrated, applied = migrate_source(original, Path(relative).suffix, algorithms, replacements)
        else:
            migrated, applied = original, []
        validation_method = None
        if migrated != original:
            try:
                validation_method = _validate_source_syntax(migrated, Path(relative).suffix)
            except Exception as exc:
                validation_rejections.append({"file": relative, "algorithms": algorithms,
                                              "stage": "static_syntax", "reason": str(exc) or type(exc).__name__})
                migrated, applied = original, []
        if migrated != original and applied:
            try:
                with tempfile.TemporaryDirectory(prefix="cadence-postscan-") as temp_dir:
                    candidate = Path(temp_dir) / ("candidate" + Path(relative).suffix)
                    candidate.write_text(migrated, encoding="utf-8", newline="")
                    remaining, _, _, _ = _detect_file(candidate, migrated)
                changed_algorithms = {entry.get("algorithm") for entry in applied}
                residual = sorted(changed_algorithms.intersection(remaining))
                if residual:
                    raise ValueError("deprecated crypto remains detectable after edit: " + ", ".join(residual))
                post_edit_verified += 1
            except Exception as exc:
                validation_rejections.append({"file": relative, "algorithms": algorithms,
                                              "stage": "post_edit_scan", "reason": str(exc) or type(exc).__name__})
                migrated, applied = original, []
        if migrated != original:
            target = output_root / relative
            line_ending = item.get("newline", "\n")
            serialized = migrated.replace("\n", line_ending)
            if item.get("bom"):
                serialized = "\ufeff" + serialized
            target.write_text(serialized, encoding="utf-8", newline="")
            files_changed += 1
            if validation_method:
                statically_validated += 1
            if validation_method == "python_ast":
                changed_python += 1
            patches.extend(difflib.unified_diff(original.splitlines(keepends=True), migrated.splitlines(keepends=True),
                                                fromfile=f"a/{relative}", tofile=f"b/{relative}"))
            changes.append({"file": relative, "algorithms": applied,
                            "static_validation": validation_method or "not_available",
                            "post_edit_crypto_scan": "passed",
                            "status": "updated; review and test before use"})
        applied_names = {entry.get("algorithm") for entry in applied}
        for algorithm in algorithms:
            replacement = _lookup(mapping, algorithm)
            is_applied = algorithm in applied_names or (algorithm == "DES" and "symmetric" in applied_names)
            location_lines = item.get("locations", {}).get(algorithm, [])
            finding = {"file": relative,
                       "line": location_lines[0] if location_lines else _line_number(original, algorithm),
                       "algorithm": algorithm, "proposed_replacement": replacement,
                       "confidence": item.get("confidence", "needs_review"),
                       "detection_method": item.get("detector", "pattern_fallback"),
                       "status": "automatically_updated" if is_applied else "manual_review"}
            findings.append(finding)
            if not is_applied:
                reason = _manual_reason(algorithm, applied)
                if item.get("confidence") != "high":
                    reason = "Low-confidence pattern match; verify this is active crypto use before changing it. " + reason
                rejected = next((entry for entry in validation_rejections if entry["file"] == relative), None)
                if rejected:
                    stage = "post-edit crypto scan" if rejected.get("stage") == "post_edit_scan" else "static syntax validation"
                    reason = f"Candidate edit was rejected by {stage}: " + rejected["reason"]
                manual_review.append({**finding, "reason": reason})

    artifact_name = "cadence-migration-artifacts"
    suffix = 2
    while (output_root / artifact_name).exists():
        artifact_name = f"cadence-migration-artifacts-{suffix}"
        suffix += 1
    artifacts = output_root / artifact_name
    artifacts.mkdir()
    report = {
        "schema_version": "1.0",
        "generated_by": "CADENCE Repository Migration",
        "source_of_truth": "CADENCE Module 3 solution catalog",
        "detection_method": "AST-backed for supported Python/Java/JavaScript; pattern fallback for unsupported or unparseable files. Not a full semantic/data-flow analysis.",
        "validation": {"static_syntax_validation": "Python AST and Java/JavaScript tree-sitter parser where applicable",
                       "post_edit_crypto_rescan": True,
                       "uploaded_project_tests_executed": False,
                       "reason": "Uploaded build and test commands are not executed by CADENCE."},
        "profile": resolved_plan.get("profile"),
        "original_repository_modified": False,
        "artifacts_directory": artifact_name,
        "limits": {"max_text_file_bytes": MAX_TEXT_FILE_BYTES, "excluded_directories": sorted(SKIP_DIRS)},
        "summary": {
            "files_scanned": scan["files_scanned"], "bytes_scanned": scan["bytes_scanned"],
            "files_changed": files_changed, "findings": len(findings),
            "automatically_updated": sum(f["status"] == "automatically_updated" for f in findings),
            "manual_review": len(manual_review), "skipped_files": len(scan["skipped_files"]),
            "high_confidence_findings": sum(f["confidence"] == "high" for f in findings),
            "needs_review_findings": sum(f["confidence"] != "high" for f in findings),
            "python_files_syntax_checked": changed_python,
            "statically_validated_files": statically_validated,
            "post_edit_verified_files": post_edit_verified,
            "static_validation_rejections": len(validation_rejections),
            "uploaded_project_tests_executed": False,
        },
        "findings": findings,
        "changes": changes,
        "manual_review": manual_review,
        "static_validation_rejections": validation_rejections,
        "skipped_files": scan["skipped_files"],
    }
    (artifacts / "cadence-migration-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (artifacts / "cadence-migration.patch").write_text("".join(patches), encoding="utf-8")
    return report
