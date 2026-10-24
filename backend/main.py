"""
main.py — CADENCE Console backend.

Serves the dashboard (frontend/) and a small REST API that:
  - triggers real pipeline runs (Module 1 -> 2 -> 3) on demand or on a schedule
  - stores every run's output in SQLite so the whole team sees the same data
  - gates access behind a shared password if APP_PASSWORD is set

Run it directly:
    uvicorn main:app --host 0.0.0.0 --port 8000
or via the Dockerfile / docker-compose.yml in the project root.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import uuid
import io
import zipfile
import tempfile
import shutil
import re
import secrets
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT / "frontend"
APP_PASSWORD = os.environ.get("APP_PASSWORD", "").strip()
for _path in (ROOT, ROOT / "cadence_module3"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

if __package__:
    from . import db, runner, scheduler
    from . import config as cfgmod
    from .file_migrator import migrate_bytes
    from .source_migrator import detect_algorithms, migrate_source
    from .repository_migrator import (migrate_repository, scan_repository, _safe_extract,
                                      build_existing_module3_plan, _detect_file,
                                      _canonical_algorithm, MAX_TEXT_FILE_BYTES)
else:  # Compatibility with `cd backend && uvicorn main:app`.
    import db
    import runner
    import scheduler
    import config as cfgmod
    from file_migrator import migrate_bytes
    from source_migrator import detect_algorithms, migrate_source
    from repository_migrator import (migrate_repository, scan_repository, _safe_extract,
                                     build_existing_module3_plan, _detect_file,
                                     _canonical_algorithm, MAX_TEXT_FILE_BYTES)

import pqc_solutions  # noqa: E402

app = FastAPI(title="CADENCE Console")


# ---------------------------------------------------------------- auth ----
def check_auth(x_app_password: str | None = Header(default=None)):
    if APP_PASSWORD and x_app_password != APP_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid or missing password")


def current_workspace(request: Request, response: Response, _auth=Depends(check_auth)) -> str:
    value = request.cookies.get("cadence_workspace")
    if not value or len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        value = secrets.token_urlsafe(32)
        response.set_cookie("cadence_workspace", value, max_age=31536000,
                           httponly=True, samesite="lax", secure=request.url.scheme == "https")
    return value


# --------------------------------------------------------------- models ---
class ConfigPayload(BaseModel):
    path: str = ""
    github_org: str = ""
    github_token: str = ""
    domain: str = ""
    hosts: list[str] = []
    project_name: str = "your-company"
    constraints: dict = {}


class ProgressPayload(BaseModel):
    run_id: str
    system: str
    step_id: str
    done: bool


class FixFilePayload(BaseModel):
    run_id: str
    system: str
    file_path: str
    algorithm: str = ""
    profile: str = "standard"
    fix_entire_file: bool = False


# ------------------------------------------------------------- lifecycle --
@app.on_event("startup")
def on_startup():
    db.init_db()

    def _trigger_scheduled(trigger_type: str):
        if not runner.reserve_run():
            return
        run_id = uuid.uuid4().hex[:12]
        db.create_run(run_id, trigger_type=trigger_type, workspace_id="default")
        threading.Thread(target=_execute_run, args=(run_id, "default"), daemon=True).start()

    scheduler.start_if_configured(_trigger_scheduled)


@app.on_event("shutdown")
def on_shutdown():
    scheduler.shutdown()


# ------------------------------------------------------------- run logic --
def _execute_run(run_id: str, workspace: str = "default"):
    db.set_status(run_id, "running")

    def log(line: str):
        db.append_log(run_id, line)

    try:
        cfg = cfgmod.load(workspace)
        cfgmod.activate_constraints(cfg)
        outputs = runner.run_pipeline(run_id, cfg, log, reserved=True)
        db.set_outputs(run_id, outputs)
        db.set_status(run_id, "success")
    except Exception as exc:  # noqa: BLE001 — surfaced to the UI, not swallowed
        db.append_log(run_id, f"ERROR: {exc}")
        db.set_status(run_id, "failed", error=str(exc))


# ------------------------------------------------------------------ API ---
@app.get("/api/health")
def health():
    return {"ok": True, "auth_required": bool(APP_PASSWORD)}


@app.get("/api/config")
def get_config(workspace: str = Depends(current_workspace)):
    return cfgmod.load(workspace)


@app.put("/api/config")
def put_config(payload: ConfigPayload, workspace: str = Depends(current_workspace)):
    return cfgmod.save(payload.model_dump(), workspace)


@app.post("/api/source-upload")
async def upload_source_archive(file: UploadFile = File(...), workspace: str = Depends(current_workspace)):
    """Safely extract a source ZIP into server-owned storage and select it as scan target.

    Uploaded source is analyzed as data only: CADENCE never executes project code.
    """
    filename = Path(file.filename or "").name
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip archive of your source project.")
    max_upload_bytes = 100 * 1024 * 1024
    max_expanded_bytes = 500 * 1024 * 1024
    upload_dir = Path(__file__).resolve().parent / "data" / "source_uploads"
    archive_dir = upload_dir / uuid.uuid4().hex
    archive_dir.mkdir(parents=True, exist_ok=False)
    archive_path = archive_dir / "source.zip"
    try:
        total = 0
        with archive_path.open("wb") as destination:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_upload_bytes:
                    raise HTTPException(status_code=413, detail="Source ZIP exceeds the 100 MB upload limit.")
                destination.write(chunk)
        try:
            with zipfile.ZipFile(archive_path) as archive:
                archive_members = archive.infolist()
                if len(archive_members) > 20000:
                    raise HTTPException(status_code=413, detail="Source ZIP contains too many entries (maximum 20,000).")
                members = [item for item in archive_members if not item.is_dir()]
                if not members:
                    raise HTTPException(status_code=400, detail="The ZIP archive contains no files.")
                if sum(item.file_size for item in members) > max_expanded_bytes:
                    raise HTTPException(status_code=413, detail="Expanded source exceeds the 500 MB limit.")
                extracted = archive_dir / "project"
                extracted.mkdir()
                _safe_extract(archive, extracted)
        except zipfile.BadZipFile as exc:
            raise HTTPException(status_code=400, detail="The uploaded file is not a valid ZIP archive.") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            archive_path.unlink(missing_ok=True)

        entries = list(extracted.iterdir())
        source_root = entries[0] if len(entries) == 1 and entries[0].is_dir() else extracted
        current = cfgmod.load(workspace)
        current["path"] = str(source_root.resolve())
        current["project_name"] = Path(filename).stem or "uploaded-source"
        cfgmod.save(current, workspace)
        return {"ok": True, "path": str(source_root.resolve()),
                "message": "Source uploaded safely and selected as the scan target. Click Run scan to analyze it."}
    except HTTPException:
        shutil.rmtree(archive_dir, ignore_errors=True)
        raise
    except Exception as exc:
        shutil.rmtree(archive_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Could not prepare source archive: {type(exc).__name__}") from exc
    finally:
        await file.close()


@app.get("/api/runs")
def list_runs(limit: int = 30, workspace: str = Depends(current_workspace)):
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 200")
    return db.list_runs(limit=limit, workspace_id=workspace)


@app.get("/api/runs/latest")
def latest_run(workspace: str = Depends(current_workspace)):
    row = db.get_latest_success(workspace)
    if not row:
        raise HTTPException(status_code=404, detail="No successful runs yet")
    return row


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str, workspace: str = Depends(current_workspace)):
    row = db.get_run(run_id, workspace)
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")
    return row


@app.get("/api/solutions/catalog", dependencies=[Depends(check_auth)])
def solutions_catalog(profile: str = "standard"):
    """The algorithm guide: every known weak algorithm, its replacement, plain-English
    explanation and reference sizes. Independent of any scan."""
    try:
        return pqc_solutions.build_catalog(profile)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/solutions", dependencies=[Depends(check_auth)])
def solutions(run_id: str = "", profile: str = "standard", workspace: str = Depends(current_workspace)):
    """Per-system PQC remediation plan for a run (defaults to the latest successful one)."""
    row = db.get_run(run_id, workspace) if run_id else db.get_latest_success(workspace)
    if not row or not row.get("migration_ranking_json"):
        raise HTTPException(
            status_code=404,
            detail="No migration plan to build solutions from yet — run a scan first.",
        )
    try:
        return pqc_solutions.build_plan(row, profile, db.get_progress(row["id"]))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.put("/api/solutions/progress", dependencies=[Depends(check_auth)])
def solutions_progress(payload: ProgressPayload, workspace: str = Depends(current_workspace)):
    if not payload.run_id.strip() or not payload.system.strip() or not payload.step_id.strip():
        raise HTTPException(status_code=400, detail="run_id, system and step_id are required")
    run = db.get_run(payload.run_id, workspace)
    if not run or run.get("status") != "success":
        raise HTTPException(status_code=404, detail="Successful scan run not found")
    if not run.get("migration_ranking_json"):
        raise HTTPException(status_code=409, detail="This scan has no remediation plan")
    db.set_progress(payload.run_id, payload.system, payload.step_id, payload.done)
    return {"ok": True}


@app.post("/api/solutions/fix-file", dependencies=[Depends(check_auth)])
def fix_scanned_file(payload: FixFilePayload, workspace: str = Depends(current_workspace)):
    """Download a safe, validated copy of one exact file from this successful scan.

    A single-finding request changes only that selected algorithm. Whole-file
    mode applies all current high-confidence findings that the plan can safely
    rewrite, while retaining a count of findings that still require manual work.
    The configured source is never modified.
    """
    # Direct unit-test callers do not run FastAPI dependency injection.
    if not isinstance(workspace, str):
        workspace = "default"
    run = db.get_run(payload.run_id, workspace)
    if not run or run.get("status") != "success":
        raise HTTPException(status_code=404, detail="Successful scan run not found")
    if not run.get("migration_ranking_json"):
        raise HTTPException(status_code=409, detail="This scan has no solution plan")

    file_map = pqc_solutions._load_file_map(run)
    if file_map.get(payload.file_path) != payload.system:
        raise HTTPException(status_code=409, detail="That exact file is not mapped to this system in the selected scan")

    file_findings = [finding for finding in pqc_solutions.extract_findings(run)
                     if finding.get("file") == payload.file_path]
    if not file_findings:
        raise HTTPException(status_code=409, detail="This exact file has no findings in the selected scan")
    algorithm = _canonical_algorithm(payload.algorithm) if payload.algorithm else ""
    if not payload.fix_entire_file:
        scan_findings = [finding for finding in file_findings
                         if _canonical_algorithm(str(finding.get("algorithm") or "")) == algorithm]
        if not algorithm or not scan_findings:
            raise HTTPException(status_code=409, detail="That algorithm was not found in this file for the selected scan")
        if not any(str(finding.get("confidence") or "").lower() == "high" for finding in scan_findings):
            raise HTTPException(status_code=409, detail="This was not a high-confidence source finding; use the manual solution")
        requested_algorithms = {algorithm}
    else:
        requested_algorithms = {
            _canonical_algorithm(str(finding.get("algorithm") or ""))
            for finding in file_findings if finding.get("algorithm")
        }
        if not requested_algorithms:
            raise HTTPException(status_code=409, detail="No algorithms were recorded for this file in the selected scan")

    try:
        plan = pqc_solutions.build_plan(run, payload.profile, db.get_progress(payload.run_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    system_plan = next((item for item in plan.get("systems", []) if item.get("asset_id") == payload.system), None)
    plan_changes = {
        _canonical_algorithm(str(item.get("name") or "")): item
        for item in (system_plan or {}).get("changes", []) if item.get("name")
    }
    if not any(name in plan_changes and plan_changes[name].get("swap") for name in requested_algorithms):
        raise HTTPException(status_code=409, detail="No replacement is available for these findings in the selected scan's plan")

    configured_root = cfgmod.load(workspace).get("path")
    if not configured_root:
        raise HTTPException(status_code=409, detail="This scan has no configured local source folder. For GitHub or domain scans, use the Repository migration upload instead.")
    source_root = Path(configured_root).expanduser()
    if not source_root.is_absolute():
        source_root = runner.MOD1 / source_root
    try:
        source_root = source_root.resolve(strict=True)
        candidate = Path(payload.file_path).expanduser()
        if not candidate.is_absolute():
            candidate = source_root / candidate
        source_path = candidate.resolve(strict=True)
        relative = source_path.relative_to(source_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail="The scanned source file is no longer available beneath the configured scan folder") from exc
    if not source_path.is_file():
        raise HTTPException(status_code=409, detail="The scanned source path is not a regular file")

    try:
        raw_bytes = source_path.read_bytes()
        if not raw_bytes:
            raise HTTPException(status_code=409, detail="The scanned source file is now empty")
        if len(raw_bytes) > MAX_TEXT_FILE_BYTES:
            raise HTTPException(status_code=413, detail="The source file exceeds the 5 MB single-file fix limit")
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=409, detail="The scanned file is no longer a UTF-8 text source file") from exc
    except OSError as exc:
        raise HTTPException(status_code=409, detail="Could not read the scanned source file") from exc

    detected, _detector, confidence, locations = _detect_file(source_path, text)
    detected_algorithms = {_canonical_algorithm(name) for name in detected}
    if confidence != "high":
        raise HTTPException(status_code=409, detail="CADENCE cannot currently parse this file with high confidence; use the manual solution")

    supported = {
        ".py": {"MD5", "SHA1", "RSA-1024"},
        ".java": {"MD5", "SHA1", "RSA-1024"},
        ".js": {"MD5", "SHA1"}, ".mjs": {"MD5", "SHA1"},
        ".cjs": {"MD5", "SHA1"}, ".ts": {"MD5", "SHA1"},
        ".jsx": {"MD5", "SHA1"}, ".tsx": {"MD5", "SHA1"},
    }
    suffix = source_path.suffix.lower()
    if not payload.fix_entire_file and algorithm not in supported.get(suffix, set()):
        raise HTTPException(status_code=409, detail="This finding needs a manual engineering change; CADENCE will not guess at cipher, protocol, or configuration semantics")

    active_algorithms = []
    resolved_changes = []
    manual_before_migration = set()
    for name in sorted(requested_algorithms):
        matching = [finding for finding in file_findings
                    if _canonical_algorithm(str(finding.get("algorithm") or "")) == name]
        # A whole-file pass excludes any algorithm whose scan records contain
        # uncertain evidence. It may still fix other high-confidence findings.
        if not any(str(finding.get("confidence") or "").lower() == "high" for finding in matching):
            manual_before_migration.add(name)
            continue
        if name not in detected_algorithms:
            continue  # already changed since the scan; do not recreate it
        change = plan_changes.get(name)
        if not change or not change.get("swap"):
            manual_before_migration.add(name)
            continue
        active_algorithms.append(name)
        resolved_changes.append(change)

    if not active_algorithms:
        raise HTTPException(status_code=409, detail="No current high-confidence scan findings remain in this file that CADENCE can process; follow the manual plan or scan again")

    # Use the exact solution selected for this run/system, not a latest-run or
    # sample catalog fallback. The isolated temp tree keeps the original intact.
    with tempfile.TemporaryDirectory(prefix="cadence-fix-now-") as tmp:
        temp_root = Path(tmp)
        source = temp_root / "source"
        output = temp_root / "output"
        source.mkdir()
        temp_name = re.sub(r"[^A-Za-z0-9._-]+", "_", source_path.name) or "source" + suffix
        if not Path(temp_name).suffix:
            temp_name += suffix or ".txt"
        (source / temp_name).write_bytes(raw_bytes)
        newline = "\r\n" if b"\r\n" in raw_bytes else ("\r" if b"\r" in raw_bytes else "\n")
        current_locations = {name: locations.get(name, []) for name in active_algorithms}
        scan = {"files_scanned": 1, "bytes_scanned": len(raw_bytes), "skipped_files": [],
                "inventory": [{"file": temp_name, "algorithms": active_algorithms, "detector": "scan_recheck",
                               "confidence": confidence, "locations": current_locations,
                               "newline": newline, "bom": raw_bytes.startswith(b"\xef\xbb\xbf")}]}
        resolved_plan = {"profile": payload.profile,
                         "systems": [{"asset_id": payload.system, "changes": resolved_changes}]}
        try:
            report = migrate_repository(source, output, resolved_plan, scan)
        except (OSError, ValueError, SyntaxError) as exc:
            raise HTTPException(status_code=422, detail=f"CADENCE could not safely validate this file edit: {exc}") from exc
        summary = report.get("summary", {})
        migrated_path = output / temp_name
        if (summary.get("files_changed") != 1
                or summary.get("post_edit_verified_files") != 1
                or not migrated_path.is_file()):
            raise HTTPException(status_code=409, detail="No safe, syntax-checked automatic edit was available for this file; follow the manual solution instead")
        migrated_bytes = migrated_path.read_bytes()

    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", source_path.stem).strip(".-_")[:100] or "source"
    download_name = f"{stem}.cadence-fixed{suffix}"
    manual_count = (int(summary.get("manual_review", 0) or 0)
                    + int(summary.get("needs_review_findings", 0) or 0)
                    + len(manual_before_migration))
    return StreamingResponse(
        io.BytesIO(migrated_bytes), media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{download_name}"',
                 "X-Cadence-Fixed-Algorithm": algorithm or "multiple",
                 "X-Cadence-Post-Edit-Verified": "true",
                 "X-Cadence-Original-Modified": "false",
                 "X-Cadence-Auto-Fixed-Findings": str(summary.get("automatically_updated", 0) or 0),
                 "X-Cadence-Manual-Findings": str(manual_count),
                 "X-Cadence-Fix-Scope": "entire-file" if payload.fix_entire_file else "single-finding"},
    )


@app.post("/api/auto-migrate-source")
async def auto_migrate_source(file: UploadFile = File(...), workspace: str = Depends(current_workspace)):
    """Execute the replacement already selected by CADENCE's Module 3 plan.

    The user does not choose the target algorithm. CADENCE uses the latest
    successful scan, resolves its existing migration plan, and only then
    applies supported mechanical source transformations.
    """
    filename = Path(file.filename or "source.txt").name
    data = await file.read(10 * 1024 * 1024 + 1)
    if not data:
        raise HTTPException(status_code=400, detail="The uploaded file is empty")
    if len(data) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Maximum source migration file size is 10 MB")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Auto migration expects a UTF-8 source/configuration file, not an encrypted binary ciphertext") from exc

    algorithms = detect_algorithms(text, Path(filename).suffix)
    if not algorithms:
        return {"changed": False, "message": "No supported weak cryptography was detected.", "algorithms": [], "source": text}

    # Do not invent a target here. Resolve the same Module 3 plan the user
    # sees in CADENCE and execute that plan.
    row = db.get_latest_success(workspace)
    if not row or not row.get("migration_ranking_json"):
        raise HTTPException(status_code=409, detail="Run a CADENCE scan first so the migration plan can choose the replacement.")
    try:
        resolved_plan = pqc_solutions.build_plan(row, "standard", db.get_progress(row["id"]))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    planned = {}
    for system in resolved_plan.get("systems", []):
        for change in system.get("changes", []):
            planned[change.get("name", "").lower()] = change
    selected = []
    replacements = {}
    for algo in algorithms:
        change = planned.get(algo.lower())
        if not change:
            # Findings can use slightly different display names (e.g. SHA-1).
            change = next((c for k, c in planned.items() if k.replace("-", "") == algo.lower().replace("-", "")), None)
        if not change:
            raise HTTPException(status_code=409, detail=f"Detected {algo}, but it is not present in the current CADENCE migration plan. Re-run the scan.")
        selected.append({"detected": algo, "plan": change})
        replacements[algo] = change.get("swap", "")

    # Symmetric findings share one catalog target.
    for algo in ("DES", "RC4", "Blowfish"):
        if algo in algorithms:
            c = next((x for x in selected if x["detected"] == algo), None)
            if c:
                replacements["symmetric"] = c["plan"].get("swap", "AES-256-GCM")

    migrated, changes = migrate_source(text, Path(filename).suffix, algorithms, replacements)
    changed = migrated != text
    report = {"changed": changed, "algorithms": selected, "changes": changes, "profile": resolved_plan.get("profile"), "source": "CADENCE migration plan"}
    if not changed:
        report["message"] = "A weak algorithm was detected, but CADENCE could not safely rewrite this source pattern automatically. Use the generated plan as the manual migration recipe."

    stem = Path(filename).stem or "migrated"
    out_name = stem + ".cadence-migrated" + (Path(filename).suffix or ".txt")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(out_name, migrated)
        z.writestr("migration-plan.json", json.dumps(report, indent=2))
        z.writestr("README.txt", "CADENCE automatic source migration\n\nThe algorithm was detected automatically using CADENCE's crypto detection vocabulary, then CADENCE's migration plan selected and applied the replacement. Review and test the generated source before production deployment.\n")
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{stem}-cadence-auto-migrated.zip"'})


@app.post("/api/auto-migrate-repository", dependencies=[Depends(check_auth)])
async def auto_migrate_repository(file: UploadFile = File(...)):
    """Scan a ZIP safely, apply conservative changes, and return an auditable bundle."""
    data = await file.read(100 * 1024 * 1024 + 1)
    if not data:
        raise HTTPException(status_code=400, detail="The repository archive is empty")
    if len(data) > 100 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Maximum repository archive size is 100 MB")

    # The replacement decision comes from the existing Module 3 migration
    # catalog. The uploaded repository itself is the scan target, so no
    # separate one-file upload or prior run is required.
    with tempfile.TemporaryDirectory(prefix="cadence-repo-") as tmp:
        tmp_root = Path(tmp)
        archive = tmp_root / "repository.zip"
        source = tmp_root / "source"
        output = tmp_root / "migrated"
        archive.write_bytes(data)
        source.mkdir()
        try:
            with zipfile.ZipFile(archive) as zf:
                if zf.testzip() is not None:
                    raise ValueError("Repository archive is corrupted")
                _members = zf.infolist()
                if len(_members) > 20000:
                    raise ValueError("Repository archive contains too many entries")
                expanded_size = sum(member.file_size for member in _members)
                if expanded_size > 500 * 1024 * 1024:
                    raise ValueError("Repository archive expands beyond the 500 MB limit")
                if any(member.file_size > 100 * 1024 * 1024 for member in _members):
                    raise ValueError("A repository archive entry exceeds the 100 MB limit")
                _safe_extract(zf, source)
        except (zipfile.BadZipFile, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        # Archives commonly contain one top-level repository directory.
        children = [p for p in source.iterdir()]
        if len(children) == 1 and children[0].is_dir():
            source_root = children[0]
        else:
            source_root = source

        scan = scan_repository(source_root)
        detected = sorted({algorithm for item in scan["inventory"] for algorithm in item["algorithms"]})
        resolved_plan = build_existing_module3_plan(detected, "standard")
        report = migrate_repository(source_root, output, resolved_plan, scan)
        artifacts = output / report["artifacts_directory"]
        (artifacts / "CADENCE-README.txt").write_text(
            "CADENCE repository migration bundle\n\n"
            "The original uploaded repository was not modified. Review "
            "cadence-migration-report.json and cadence-migration.patch. "
            "AST-backed findings are preferred; lower-confidence pattern "
            "matches are never auto-edited. Changed supported source files "
            "receive static syntax checks; project tests/builds are not run. "
            "Run your project's tests, build, and security review before use. "
            "Findings marked manual_review require an engineer to update them.\n",
            encoding="utf-8",
        )
        result = io.BytesIO()
        with zipfile.ZipFile(result, "w", zipfile.ZIP_DEFLATED) as z:
            for path in output.rglob("*"):
                if path.is_file():
                    z.write(path, path.relative_to(output).as_posix())
            z.writestr(f'{report["artifacts_directory"]}/cadence-migration-plan.json', json.dumps(resolved_plan, indent=2))
        result.seek(0)
        safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(file.filename or "repository.zip").stem).strip(".-_")[:80] or "repository"
        summary = report["summary"]
        headers = {
            "Content-Disposition": f'attachment; filename="{safe_stem}-cadence-migrated.zip"',
            "X-Cadence-Files-Scanned": str(summary["files_scanned"]),
            "X-Cadence-Files-Changed": str(summary["files_changed"]),
            "X-Cadence-Findings": str(summary["findings"]),
            "X-Cadence-Auto-Updated": str(summary["automatically_updated"]),
            "X-Cadence-Manual-Review": str(summary["manual_review"]),
            "X-Cadence-Skipped-Files": str(summary["skipped_files"]),
            "X-Cadence-High-Confidence": str(summary["high_confidence_findings"]),
            "X-Cadence-Needs-Review": str(summary["needs_review_findings"]),
            "X-Cadence-Syntax-Validated": str(summary["statically_validated_files"]),
            "X-Cadence-Post-Edit-Verified": str(summary["post_edit_verified_files"]),
            "X-Cadence-Static-Rejections": str(summary["static_validation_rejections"]),
        }
        return StreamingResponse(result, media_type="application/zip", headers=headers)


@app.post("/api/migrate-file", dependencies=[Depends(check_auth)])
async def migrate_file(
    file: UploadFile = File(...),
    algorithm: str = Form(...),
    old_key: str = Form(...),
    mode: str = Form("ECB"),
    iv: str = Form(""),
    new_key: str = Form(""),
):
    """Decrypt a supported legacy symmetric ciphertext and re-encrypt it with AES-256-GCM.

    The old key is supplied by the owner; CADENCE never stores it. The response is a
    ZIP containing the migrated ciphertext, the AES key, and a format note.
    """
    filename = Path(file.filename or "encrypted.bin").name
    if not filename:
        filename = "encrypted.bin"
    if len(filename) > 180:
        filename = filename[-180:]
    data = await file.read(50 * 1024 * 1024 + 1)
    if not data:
        raise HTTPException(status_code=400, detail="The uploaded file is empty")
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Maximum migration file size is 50 MB")
    try:
        migrated, key = migrate_bytes(data, algorithm, old_key, mode, iv, new_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not decrypt the legacy file: {exc}") from exc

    stem = Path(filename).stem or "migrated"
    out_name = stem + ".aes256gcm"
    key_text = key.hex()
    readme = (
        "CADENCE encrypted-file migration\n\n"
        f"Original file: {filename}\n"
        f"Legacy algorithm: {algorithm.upper()} / {mode.upper()}\n"
        "New algorithm: AES-256-GCM\n"
        "Container: CADENCE-AES256-GCM-V1\n\n"
        "The .key.txt file contains the 32-byte AES-256 key as hexadecimal.\n"
        "Store it in a KMS/secret manager in a real deployment and do not commit it to source control.\n"
        "The migrated file contains the plaintext encrypted with AES-256-GCM using a fresh random 96-bit nonce.\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(out_name, migrated)
        z.writestr(out_name + ".key.txt", key_text + "\n")
        z.writestr("README.txt", readme)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{stem}-cadence-migrated.zip"'},
    )


@app.post("/api/runs", dependencies=[Depends(check_auth)])
def trigger_run(workspace: str = Depends(current_workspace)):
    if not runner.reserve_run():
        raise HTTPException(status_code=409, detail="A scan is already running")
    cfg = cfgmod.load(workspace)
    if not cfgmod.is_target_configured(cfg):
        runner.release_run()
        raise HTTPException(
            status_code=400,
            detail="No scan target configured yet — open Settings and set a source path, "
                   "GitHub org, or domain first.",
        )
    run_id = uuid.uuid4().hex[:12]
    db.create_run(run_id, trigger_type="manual", workspace_id=workspace)
    try:
        threading.Thread(target=_execute_run, args=(run_id, workspace), daemon=True).start()
    except Exception:
        db.set_status(run_id, "failed", error="Could not start scan worker")
        runner.release_run()
        raise
    return {"run_id": run_id}


# ------------------------------------------------------------- frontend ---
# Mounted last so it never shadows the /api routes above.
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
