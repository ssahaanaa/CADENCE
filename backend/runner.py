"""
runner.py — runs the real CADENCE pipeline (Module 1 -> 2 -> 3) as three
subprocesses, in-place, exactly the way each module's own README documents.
No pipeline shortcuts: this shells out to the same cli.py / main.py /
module3_decision_engine.py you'd run by hand. Module 2 reads the configured
enterprise topology; it does not infer service relationships from source imports.

Only one run is allowed at a time (the modules write to fixed, shared
filenames on disk by design) — `is_running()` / the lock below enforce that.
"""

from __future__ import annotations

import subprocess
import json
import os
import sys
import threading
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
MOD1 = ROOT / "cadence_module1"
MOD2 = ROOT / "cadence_module2"
MOD3 = ROOT / "cadence_module3"
RUNS_DIR = Path(__file__).resolve().parent / "data" / "runs"
STEP_TIMEOUT_SECONDS = int(os.environ.get("CADENCE_STEP_TIMEOUT_SECONDS", "3600"))

_run_lock = threading.Lock()
_currently_running = False


def is_running() -> bool:
    return _currently_running


def reserve_run() -> bool:
    """Atomically reserve the pipeline before a queued run is created."""
    global _currently_running
    if not _run_lock.acquire(blocking=False):
        return False
    _currently_running = True
    return True


def release_run() -> None:
    """Release a reservation when a worker cannot be started."""
    global _currently_running
    _currently_running = False
    if _run_lock.locked():
        _run_lock.release()


class PipelineError(RuntimeError):
    pass


def _stream(cmd: list[str], cwd: Path, log: Callable[[str], None], *, env: dict[str, str] | None = None):
    try:
        where = cwd.resolve().relative_to(ROOT)
    except ValueError:
        where = cwd
    log(f"$ {' '.join(cmd)}   (in {where})")
    proc = subprocess.Popen(
        cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, start_new_session=(os.name == "posix"), env=env,
    )
    assert proc.stdout is not None

    def enforce_timeout():
        if proc.poll() is not None:
            return
        log(f"[!] Step exceeded {STEP_TIMEOUT_SECONDS}s; terminating it.")
        try:
            if os.name == "posix":
                import signal
                os.killpg(proc.pid, signal.SIGTERM)
            else:
                proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            try:
                if os.name == "posix":
                    import signal
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
            except Exception:
                pass

    timer = threading.Timer(STEP_TIMEOUT_SECONDS, enforce_timeout)
    timer.daemon = True
    timer.start()
    buffered_lines: list[str] = []
    try:
        for line in proc.stdout:
            buffered_lines.append(line.rstrip("\n"))
            # Batch log writes to reduce SQLite commit overhead.
            if len(buffered_lines) >= 20:
                log("\n".join(buffered_lines))
                buffered_lines.clear()
        proc.stdout.close()
        if buffered_lines:
            log("\n".join(buffered_lines))
        proc.wait()
    finally:
        timer.cancel()
    if proc.returncode != 0:
        raise PipelineError(
            f"{cmd[1] if len(cmd) > 1 else cmd[0]} exited with code {proc.returncode}. "
            f"Check the scan log above for details."
        )


def _resolve_source_path(raw_path: str) -> Path:
    path = Path(raw_path).expanduser()
    if path.is_absolute():
        return path.resolve()
    project_relative = (ROOT / path).resolve()
    if project_relative.exists():
        return project_relative
    return (MOD1 / path).resolve()


def _build_module1_cmd(cfg: dict) -> list[str]:
    cmd = [sys.executable, "cli.py"]
    if cfg.get("path"):
        source_path = _resolve_source_path(cfg["path"])
        cmd.append(str(source_path))
    if cfg.get("github_org"):
        cmd += ["--github-org", cfg["github_org"]]
    if cfg.get("domain"):
        cmd += ["--domain", cfg["domain"]]
    if cfg.get("hosts"):
        cmd += ["--hosts", *cfg["hosts"]]
    cmd += ["--project-name", cfg.get("project_name") or "your-company", "--out-dir", "."]
    return cmd


def _clear_previous_outputs() -> None:
    """Remove shared module outputs before a run so captures are run-local."""
    outputs = [
        MOD1 / "cbom.json",
        MOD1 / "vulnerabilities.json",
        MOD2 / "dependency_graph.json",
        MOD2 / "dependency_graph.html",
        MOD2 / "centrality_scores.json",
        MOD2 / "current_system_file_map.json",
        MOD3 / "migration_ranking.json",
    ]
    for output in outputs:
        output.unlink(missing_ok=True)


def run_pipeline(run_id: str, cfg: dict, log: Callable[[str], None], *, reserved: bool = False) -> dict[str, str]:
    """Runs the full pipeline. Returns {filename: raw_json_text} for whatever
    output files exist afterwards. Raises PipelineError on any step failure."""
    global _currently_running

    # API/scheduler callers reserve before queuing; direct callers acquire here.
    if not reserved and not reserve_run():
        raise PipelineError("A scan is already running — wait for it to finish.")
    try:
        if not (cfg.get("path") or cfg.get("github_org") or cfg.get("domain")):
            raise PipelineError(
                "No scan target configured. Open Settings and set a source path, "
                "a GitHub org, or an authorized domain before running a scan."
            )
        _clear_previous_outputs()
        log("=== Step 1/3 — Scanning for cryptographic risks ===")
        module1_env = os.environ.copy()
        if cfg.get("github_token"):
            # Pass credentials through the subprocess environment, never argv
            # (argv is logged and can be visible in process listings).
            module1_env["CADENCE_GITHUB_TOKEN"] = cfg["github_token"]
        _stream(_build_module1_cmd(cfg), MOD1, log, env=module1_env)

        log("")
        log("=== Step 2/3 — Mapping enterprise dependencies ===")
        module2_cmd = [sys.executable, "main.py", "--architecture",
                       str(MOD2 / "enterprise_architecture.json"), "--scan-only", "--skip-html", "--quiet-summary"]
        if cfg.get("path"):
            resolved_source_root = _resolve_source_path(cfg["path"])
            if resolved_source_root.is_file():
                resolved_source_root = resolved_source_root.parent
            module2_cmd += ["--source-root", str(resolved_source_root)]
        _stream(module2_cmd, MOD2, log)

        log("")
        log("=== Step 3/3 — Prioritizing the migration roadmap ===")
        _stream(
            [sys.executable, "module3_decision_engine.py", "--system-map",
             str(MOD2 / "current_system_file_map.json")],
            MOD3,
            log,
        )

        log("")
        log("=== Collecting outputs ===")
        outputs: dict[str, str] = {}
        for filename, srcdir in [
            ("cbom.json", MOD1),
            ("vulnerabilities.json", MOD1),
            ("dependency_graph.json", MOD2),
            ("centrality_scores.json", MOD2),
            ("migration_ranking.json", MOD3),
            ("current_system_file_map.json", MOD2),
        ]:
            p = srcdir / filename
            if p.exists():
                outputs[filename] = p.read_text()
                log(f"[+] captured {filename} ({len(outputs[filename])} bytes)")
            else:
                log(f"[!] {filename} was not produced")

        # Make the dependency artifact explicitly identifiable as this scan's
        # snapshot when it is persisted and later loaded by the dashboard.
        if "dependency_graph.json" in outputs:
            graph = json.loads(outputs["dependency_graph.json"])
            graph["scan_id"] = run_id
            graph["scope"] = "scan"
            outputs["dependency_graph.json"] = json.dumps(graph, indent=2)

        run_dir = RUNS_DIR / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        for filename, content in outputs.items():
            (run_dir / filename).write_text(content)

        log("Done.")
        return outputs
    finally:
        release_run()
