/* CADENCE: cautious, auditable, catalog-driven repository migration. */
function renderMigration() {
  const root = $('view-migrate');
  if (!root) return;
  root.innerHTML = `
    <div class="migration-hero">
      <div><span class="tag critical">REPOSITORY MIGRATION</span><h2>Scan weak crypto → prepare a migration bundle</h2>
      <p class="lede">Upload a ZIP. CADENCE uses AST-backed detection for supported Python, Java, and JavaScript, with lower-confidence patterns for other or unparseable files. Supported replacements are written into the files in the downloaded copy; every edit must pass syntax validation and a post-edit crypto rescan. Findings needing judgment are left for manual review.</p></div>
    </div>
    <div class="block migration-card">
      <div class="field"><label for="migFile">Organisation repository <span class="hint">ZIP archive, maximum 100 MB (500 MB expanded)</span></label><input type="file" id="migFile" accept=".zip,application/zip"></div>
      <div class="toolbar"><button class="btn primary" id="migrateBtn">Scan &amp; Prepare Migration Bundle</button><span class="faint small" id="migStatus" role="status" aria-live="polite"></span></div>
    </div>
    <div class="block"><h3>What the bundle contains</h3><div class="two-col"><div><div class="kv"><span>1. Scan</span><span>Supported UTF-8 source files; common vendor/build folders excluded</span></div><div class="kv"><span>2. Plan</span><span>Proposed replacements from CADENCE's migration solution catalog</span></div></div><div><div class="kv"><span>3. Update</span><span>Only supported mechanical edits; uncertain changes are left untouched</span></div><div class="kv"><span>4. Review</span><span>Report, static syntax-check results, unified patch, and migration-plan JSON</span></div></div></div></div>
    <div class="notice"><b>Before production:</b> Your uploaded ZIP remains unchanged; the downloaded migrated ZIP contains the changed source files. Review the report and patch, resolve all manual-review items, and run your own tests, build, and security review on that copy before merging or deploying.</div>
    <div class="block" id="migReport" style="display:none"></div>`;
  $('migrateBtn').addEventListener('click', runAutoMigration);
}

async function runAutoMigration() {
  const input = $('migFile');
  const file = input.files[0];
  const status = $('migStatus');
  if (!file) { toast('err', 'Choose the organisation repository ZIP first.'); return; }
  if (!file.name.toLowerCase().endsWith('.zip')) { toast('err', 'Select a .zip repository archive.'); return; }
  if (file.size > 100 * 1024 * 1024) { toast('err', 'The ZIP exceeds the 100 MB upload limit.'); return; }
  const fd = new FormData();
  fd.append('file', file);
  const btn = $('migrateBtn');
  const originalLabel = btn.textContent;
  btn.disabled = true; input.disabled = true; btn.textContent = 'Scanning & packaging…';
  status.textContent = 'Uploading archive, scanning supported source files, and preparing the review bundle…';
  try {
    const headers = {}; if (appPassword) headers['X-App-Password'] = appPassword;
    const res = await fetch('/api/auto-migrate-repository', { method: 'POST', headers, body: fd });
    if (res.status === 401) { $('authOverlay').classList.add('open'); throw new Error('unauthorized'); }
    if (!res.ok) { const body = await res.json().catch(() => ({})); throw new Error(body.detail || 'Repository migration failed'); }
    if (!(res.headers.get('Content-Type') || '').includes('application/zip')) throw new Error('The server returned an unexpected response instead of a ZIP bundle.');
    const blob = await res.blob();
    if (!blob.size) throw new Error('The server returned an empty migration bundle.');
    const cd = res.headers.get('Content-Disposition') || '';
    const match = cd.match(/filename="?([^";]+)"?/i);
    downloadFileBlob(match ? match[1] : 'cadence-migrated-repository.zip', blob);
    const count = key => Number(res.headers.get('X-Cadence-' + key) || 0);
    const scanned = count('Files-Scanned'), changed = count('Files-Changed'), findings = count('Findings');
    const auto = count('Auto-Updated'), manual = count('Manual-Review'), skipped = count('Skipped-Files');
    const high = count('High-Confidence'), low = count('Needs-Review'), syntax = count('Syntax-Validated');
    const rejected = count('Static-Rejections'), postVerified = count('Post-Edit-Verified');
    status.textContent = `Bundle downloaded: ${scanned} files scanned; ${findings} findings (${high} AST/high-confidence, ${low} lower-confidence); ${changed} source files changed (${auto} findings auto-updated, ${manual} need review); ${syntax} edits passed syntax checks, ${postVerified} files passed the post-edit crypto rescan, ${rejected} candidate edits rejected; ${skipped} files skipped. Project tests/builds were not run. See the report and patch inside the ZIP.`;
    if (manual) toast('ok', `Migration bundle ready. ${manual} finding${manual === 1 ? '' : 's'} require manual review; test all changes before use.`);
    else toast('ok', 'Migration bundle ready. Review the included report and run your project tests before use.');
  } catch (e) {
    status.textContent = e.message === 'unauthorized' ? 'Sign in to run repository migration.' : 'Migration did not complete.';
    if (e.message !== 'unauthorized') toast('err', e.message);
  } finally {
    btn.disabled = false; input.disabled = false; btn.textContent = originalLabel;
  }
}
function downloadFileBlob(filename, blob) {
  const url = URL.createObjectURL(blob); const a = document.createElement('a');
  a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}
