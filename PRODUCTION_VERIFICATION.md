# CADENCE Console — Production Verification

## Changes in this build

The Module 1 CLI now creates `--out-dir` recursively before writing `cbom.json` and `vulnerabilities.json`. A regression test covers missing nested output directories. The project also includes a portable production-boundary test suite covering API authentication, ZIP validation, database persistence, GitHub credential forwarding and clone failures, domain discovery scope, and invalid run requests.

## Final verification evidence

The complete local verification pass is clean. The backend suite passed **27 tests**. Module 1 passed **6 tests**, including the new CLI test. Module 2 passed **7 tests**. Module 3 passed **18 decision-engine checks** and the complete solution-catalog script. Frontend zero-findings/accessibility checks passed, all frontend JavaScript files passed `node --check`, and all backend/module Python files passed compilation.

A real CLI smoke scan created a previously missing nested output directory and produced an MD5 finding. A full local Module 1 → Module 2 → Module 3 pipeline run completed and persisted all six expected per-run artifacts. The API health endpoint started successfully. The final source audit found no embedded credentials or TODO/FIXME markers. The bundled sample fixtures were restored and verified; they retain the expected `Legacy Auth Service` data.

## Security and boundary coverage

Authentication behavior, missing and correct passwords, ZIP type validation, path traversal rejection, database commits, scan run isolation, GitHub bearer-header forwarding, clone failure handling, passive-domain scope filtering, liveness failure handling, invalid run limits, and no-target rejection all passed the extended boundary suite. Uploaded archives remain size- and entry-limited, special paths are rejected, and uploaded project code is not executed.

## Evidence limits

This is comprehensive local verification, not a guarantee of zero defects. Docker is unavailable in the current sandbox, so a real image build was not performed here. Render deployment, persistent-disk behavior across a real service restart, production TLS/reverse-proxy behavior, and live public/private GitHub and authorized-domain scans require the target deployment environment and credentials.

## Required deployment release checks

Build the Docker image from a clean checkout in CI or on the deployment host. Deploy the exact commit to Render, set a strong `APP_PASSWORD`, and mount persistent storage at `/app/backend/data`. Then run authorized public and private GitHub scans, an authorized domain scan with reachable/unreachable/invalid cases, two successive system scans, and a restart-persistence check. Retain those logs as deployment evidence.
