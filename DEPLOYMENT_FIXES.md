# CADENCE Console — repair notes

## Changes in this build

- Source scanning now accepts either one supported source file or a directory. Missing paths fail with an explicit error instead of looking like a clean scan.
- Scanner logs the number of supported source files scanned and the number of cryptographic findings; unsupported and oversized files are reported instead of silently appearing as zero findings.
- Added `.mjs`, `.cjs`, `.mts`, and `.cts` JavaScript/TypeScript extensions.
- Added authenticated source-project ZIP upload in Settings. The archive is path-validated, limited to 100 MB compressed / 500 MB expanded and 20,000 entries, and uploaded code is never executed. The uploaded source is stored under `backend/data/source_uploads`.
- GitHub API pagination now forwards the configured token. Git clones can use the token for private repositories without adding it to command-line arguments or scan logs.
- Increased GitHub API timeout to 30 seconds, clone timeout to 180 seconds, and the overall subprocess step timeout to 60 minutes (all configurable by environment variables).
- Domain discovery now also attempts passive certificate-transparency lookup and allows a longer DNS/liveness budget; it gracefully falls back when the CT service is unavailable.
- Single-file source targets use the file's parent directory for the dependency file-ownership mapping.
- Dependency graph, system file map, migration roadmap, and solution progress remain stored per scan run; the runner clears shared intermediate outputs before each new run.

## Deployment notes

1. Commit the contents of this updated project to the GitHub repository used by Render.
2. In Render, trigger a deploy of the latest commit.
3. Keep a persistent disk mounted at `/app/backend/data`; this retains scan history and uploaded source ZIP contents.
4. Set `APP_PASSWORD` before making the app public. Set a GitHub token in Settings when scanning private repositories or to avoid the low unauthenticated API rate limit.
5. For local source scans on a cloud deployment, upload a source ZIP in Settings or scan a GitHub organization. A Windows path on your own PC is not visible to Render.
6. Scan only domains and repositories you own or are authorized to assess.

## Validation performed in the repair workspace

Passed:
- Module 1 scanner tests, including single-file Python and JavaScript module scans (4 tests).
- GitHub API token-forwarding regression test.
- Frontend zero-findings test.
- Frontend JavaScript syntax check.
- Python compilation check for backend and all three modules.
- Module 3 solution catalog tests.
- Configuration currency test.
- Three run-isolation tests, including per-run dependency file maps and per-run solution progress.
- End-to-end Module 1 smoke test: a single Python file containing `hashlib.md5()` produced one MD5 finding at line 2.

Limitations:
- The sandbox could not install dependencies because outbound package access was unavailable. Full backend/repository-migration tests requiring PyCryptodome and tree-sitter, plus live GitHub/domain network integration tests, could not be completed here. The deployed Docker image installs the declared `requirements.txt`; run the full test suite in CI after deployment.
