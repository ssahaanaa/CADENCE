/* CADENCE console: core, overview, findings, dependency map, roadmap.
   Solutions lives in solutions.js. Everything user-visible that comes from scan
   data goes through esc() before it reaches innerHTML. */

const state = {
  findings: [], findingsSource: null,
  graph: null, migration: null,
  runId: null, runTime: null, latestRunId: null,
  polling: false,
  view: 'overview',
  selectedNode: null,
  // solutions
  plan: null, catalog: null, profile: 'standard',
  selectedSystem: null, solTab: 'systems', langBySystem: {}, guideQuery: '',
};
let appPassword = sessionStorage.getItem('cadence_app_password') || '';
const copyStore = [];

/* ============================= helpers ============================= */
function esc(v) {
  return String(v === null || v === undefined ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
const $ = (id) => document.getElementById(id);
function fmtDate(iso) { return iso ? new Date(iso).toLocaleString() : 'n/a'; }
const INR_PER_USD_REFERENCE = 96.8;
const inrFormatter = new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 });
function money(n) { return inrFormatter.format(Number(n || 0)); }
function normalizeMigrationCurrency(plan) {
  if (!plan || !plan.constraints_used) return plan;
  const constraints = plan.constraints_used;
  const currency = String(constraints.currency || 'USD').toUpperCase();
  if (currency === 'INR' || currency !== 'USD') return plan;
  const toInr = value => Number.isFinite(Number(value)) ? Math.round(Number(value) * INR_PER_USD_REFERENCE * 100) / 100 : value;
  if (constraints.total_budget != null) constraints.total_budget = toInr(constraints.total_budget);
  for (const row of plan.migration_order || []) {
    if (row.estimated_cost != null) row.estimated_cost = toInr(row.estimated_cost);
    if (row.reasoning) row.reasoning = String(row.reasoning).replace(
      /The dependency analysis independently flagged it as ([A-Z]+) criticality/g,
      'Enterprise dependency analysis identified this system as $1 criticality'
    );
  }
  constraints.currency = 'INR';
  return plan;
}
function cap(s) { s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); }
function sev(level) {
  const l = String(level || '').toLowerCase();
  return l ? '<span class="sev ' + esc(l) + '">' + esc(cap(l)) + '</span>' : '<span class="sev none">None</span>';
}
function emptyState(title, msg, actions) {
  return '<div class="empty"><h3>' + esc(title) + '</h3><p>' + esc(msg) + '</p>' +
    (actions || []).map(a => '<button class="btn ' + (a.primary ? 'primary' : '') + '" data-act="' + a.act + '">' + esc(a.label) + '</button> ').join('') + '</div>';
}
function toast(kind, msg) {
  const el = document.createElement('div');
  el.className = 'toast ' + kind; el.textContent = msg;
  $('toastStack').appendChild(el);
  setTimeout(() => el.remove(), 4200);
}
function downloadFile(filename, content, mime) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement('a');
  a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function fixSolutionFile(button) {
  const originalLabel = button.textContent;
  button.disabled = true; button.textContent = 'Checking & fixing…';
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (appPassword) headers['X-App-Password'] = appPassword;
    const res = await fetch('/api/solutions/fix-file', {
      method: 'POST', headers,
      body: JSON.stringify({ run_id: button.dataset.run, system: button.dataset.system,
        file_path: button.dataset.filePath, algorithm: button.dataset.algorithm || '',
        fix_entire_file: button.dataset.fixEntireFile === 'true',
        profile: button.dataset.profile || state.profile }),
    });
    if (res.status === 401) { $('authOverlay').classList.add('open'); throw new Error('Sign in to prepare a file fix.'); }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || 'Could not prepare a validated file fix.');
    }
    if (res.headers.get('X-Cadence-Post-Edit-Verified') !== 'true') {
      throw new Error('The server did not confirm post-edit validation; no file was downloaded.');
    }
    const blob = await res.blob();
    if (!blob.size) throw new Error('The server returned an empty fixed file.');
    const cd = res.headers.get('Content-Disposition') || '';
    const match = cd.match(/filename="?([^";]+)"?/i);
    downloadFile(match ? match[1] : 'cadence-fixed-source.txt', blob,
      res.headers.get('Content-Type') || 'application/octet-stream');
    if (button.dataset.fixEntireFile === 'true') {
      const fixed = Number(res.headers.get('X-Cadence-Auto-Fixed-Findings') || 0);
      const manual = Number(res.headers.get('X-Cadence-Manual-Findings') || 0);
      const remainder = manual ? `${manual} finding(s) still need manual work.` : 'No manual-only findings were reported.';
      toast('ok', `Whole-file copy downloaded: ${fixed} safe change(s) applied. ${remainder} Original unchanged.`);
    } else {
      toast('ok', 'Validated fixed copy downloaded. The original source file was left unchanged.');
    }
  } catch (err) {
    toast('err', err.message);
  } finally {
    button.disabled = false; button.textContent = originalLabel;
  }
}
function copyText(text) {
  const done = () => toast('ok', 'Copied.');
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
  } else fallbackCopy(text, done);
}
function fallbackCopy(text, done) {
  const t = document.createElement('textarea'); t.value = text; t.style.position = 'fixed'; t.style.opacity = '0';
  document.body.appendChild(t); t.select();
  try { document.execCommand('copy'); done(); } catch (e) { toast('err', 'Copy failed. Select the text and copy it manually.'); }
  t.remove();
}
function stash(text) { copyStore.push(text); return copyStore.length - 1; }

/* ============================= API + auth ============================= */
async function api(path, opts) {
  opts = opts || {};
  const isFormData = typeof FormData !== 'undefined' && opts.body instanceof FormData;
  const headers = Object.assign(isFormData ? {} : { 'Content-Type': 'application/json' }, opts.headers || {});
  if (appPassword) headers['X-App-Password'] = appPassword;
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (res.status === 401) { $('authOverlay').classList.add('open'); throw new Error('unauthorized'); }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || ('Request failed (' + res.status + ')'));
  }
  return res.status === 204 ? null : res.json();
}
$('authSubmitBtn').addEventListener('click', async () => {
  appPassword = $('authPasswordInput').value;
  try {
    await api('/api/config');
    sessionStorage.setItem('cadence_app_password', appPassword);
    $('authError').style.display = 'none';
    $('authOverlay').classList.remove('open');
    bootstrap();
  } catch (e) { $('authError').style.display = 'block'; }
});
$('authPasswordInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('authSubmitBtn').click(); });

/* ============================= theme ============================= */
function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('cadence_theme', t);
  $('themeToggle').textContent = t === 'dark' ? 'Light theme' : 'Dark theme';
}
function initTheme() {
  const saved = localStorage.getItem('cadence_theme');
  const dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  setTheme(saved || (dark ? 'dark' : 'light'));
}
$('themeToggle').addEventListener('click', () =>
  setTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'));

/* ============================= navigation ============================= */
const VIEW_TITLES = { overview: 'Overview', findings: 'Findings', graph: 'Dependencies', roadmap: 'Roadmap', solutions: 'Solutions', migrate: 'Repository migration' };
function showView(name) {
  if (!VIEW_TITLES[name]) name = 'overview';
  state.view = name;
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
  document.querySelectorAll('#nav button').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  $('pageTitle').textContent = VIEW_TITLES[name];
  document.title = VIEW_TITLES[name] + ' - CADENCE Console';
  if (location.hash.slice(1) !== name) history.replaceState(null, '', '#' + name);
  window.scrollTo(0, 0);
}
window.addEventListener('hashchange', () => showView(location.hash.slice(1)));

/* ============================= branded launch ============================= */
const welcomeScreen = $('welcomeScreen');
const appShell = $('appShell');
let welcomeTouchStart = null;
let lastWelcomeTap = 0;
let dashboardOpening = false;

function enterDashboard() {
  if (!welcomeScreen || !appShell || welcomeScreen.hidden || dashboardOpening) return;
  dashboardOpening = true;
  welcomeScreen.classList.add('is-leaving');
  const reveal = () => {
    welcomeScreen.hidden = true;
    welcomeScreen.setAttribute('aria-hidden', 'true');
    appShell.hidden = false;
    appShell.inert = false;
    appShell.removeAttribute('aria-hidden');
    const heading = $('pageTitle');
    if (heading) heading.focus({ preventScroll: true });
  };
  const reducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  setTimeout(reveal, reducedMotion ? 0 : 240);
}

if (welcomeScreen && appShell) {
  $('welcomeEnter').addEventListener('click', enterDashboard);
  welcomeScreen.addEventListener('dblclick', (event) => {
    if (!event.target.closest('button')) enterDashboard();
  });
  welcomeScreen.addEventListener('pointerdown', (event) => {
    if (event.pointerType === 'touch') welcomeTouchStart = { x: event.clientX, y: event.clientY };
  });
  welcomeScreen.addEventListener('pointerup', (event) => {
    if (event.pointerType !== 'touch' || !welcomeTouchStart) return;
    const dx = event.clientX - welcomeTouchStart.x;
    const dy = event.clientY - welcomeTouchStart.y;
    if (dy < -65 && Math.abs(dy) > Math.abs(dx) * 1.2) {
      lastWelcomeTap = 0;
      enterDashboard();
    } else if (!event.target.closest('button')) {
      const now = Date.now();
      if (lastWelcomeTap && now - lastWelcomeTap < 450) {
        lastWelcomeTap = 0;
        enterDashboard();
      } else lastWelcomeTap = now;
    }
    welcomeTouchStart = null;
  });
  welcomeScreen.addEventListener('pointercancel', () => { welcomeTouchStart = null; });
  document.addEventListener('keydown', (event) => {
    if (!welcomeScreen.hidden && !event.target.closest('button') && (event.key === 'Enter' || event.key === ' ')) {
      event.preventDefault();
      enterDashboard();
    }
  });
}

/* One delegated handler for every data-act button, so re-rendered HTML never loses its wiring. */
document.addEventListener('click', (e) => {
  const navBtn = e.target.closest('#nav button');
  if (navBtn) { showView(navBtn.dataset.view); return; }
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const act = el.dataset.act;
  if (act === 'run') triggerRun();
  else if (act === 'settings') openSettings();
  else if (act === 'open-migrate') showView('migrate');
  else if (act === 'open-graph') showView('graph');
  else if (act === 'open-solution') { state.selectedSystem = el.dataset.system; state.solTab = 'systems'; renderSolutions(); showView('solutions'); }
  else if (act === 'select-system') { state.selectedSystem = el.dataset.system; renderSolutions(); }
  else if (act === 'select-node') { state.selectedNode = el.dataset.node; renderGraph(); }
  else if (act === 'profile') setProfile(el.dataset.profile);
  else if (act === 'soltab') { state.solTab = el.dataset.tab; renderSolutions(); }
  else if (act === 'lang') { state.langBySystem[state.selectedSystem] = el.dataset.lang; renderSolutions(); }
  else if (act === 'copy') copyText(copyStore[Number(el.dataset.copy)] || '');
  else if (act === 'export-plan') exportSolutionsMarkdown(el.dataset.system || null);
  else if (act === 'fix-file') fixSolutionFile(el);
  else if (act === 'export-csv') exportRoadmapCsv();
  else if (act === 'export-json') exportRoadmapJson();
});

/* ============================= settings ============================= */
function openSettings() { $('settingsOverlay').classList.add('open'); loadSettingsIntoForm(); }
$('settingsToggle').addEventListener('click', openSettings);
$('settingsOverlay').addEventListener('click', (e) => { if (e.target.id === 'settingsOverlay') $('settingsOverlay').classList.remove('open'); });
async function loadSettingsIntoForm() {
  try {
    const cfg = await api('/api/config'); const c = cfg.constraints || {};
    $('cfgPath').value = cfg.path || ''; $('cfgGithubOrg').value = cfg.github_org || '';
    $('cfgGithubToken').value = cfg.github_token || ''; $('cfgDomain').value = cfg.domain || '';
    $('cfgProjectName').value = cfg.project_name || '';
    $('cfgTeamSize').value = c.team_size ?? 4; $('cfgHorizon').value = c.planning_horizon_weeks ?? 10;
    $('cfgBudget').value = c.total_budget ?? 7744000;
  } catch (e) { /* auth prompt already shown */ }
}
$('uploadSourceBtn').addEventListener('click', async () => {
  const file = $('sourceZip').files && $('sourceZip').files[0];
  const status = $('sourceUploadStatus');
  if (!file) { status.textContent = 'Choose a ZIP file first.'; return; }
  if (!file.name.toLowerCase().endsWith('.zip')) { status.textContent = 'Please choose a .zip archive.'; return; }
  status.textContent = 'Uploading and checking your project ZIP…';
  const body = new FormData();
  body.append('file', file);
  try {
    const result = await api('/api/source-upload', { method: 'POST', body });
    $('cfgPath').value = result.path || '';
    $('cfgProjectName').value = file.name.replace(/\\.zip$/i, '') || 'uploaded-source';
    status.textContent = 'ZIP uploaded and selected. Click Save settings, then Run scan.';
    toast('ok', 'Source ZIP uploaded. Save settings to use it.');
  } catch (e) {
    status.textContent = e.message;
    toast('err', e.message);
  }
});
$('sourceZip').addEventListener('change', () => {
  const file = $('sourceZip').files && $('sourceZip').files[0];
  $('sourceUploadStatus').textContent = file ? 'Ready to upload: ' + file.name : '';
});
$('saveSettingsBtn').addEventListener('click', async () => {
  const payload = {
    path: $('cfgPath').value.trim(), github_org: $('cfgGithubOrg').value.trim(),
    github_token: $('cfgGithubToken').value.trim(), domain: $('cfgDomain').value.trim(), hosts: [],
    project_name: $('cfgProjectName').value.trim() || 'your-company',
    constraints: {
      team_size: Number($('cfgTeamSize').value) || 4,
      planning_horizon_weeks: Number($('cfgHorizon').value) || 10,
      total_budget: Number($('cfgBudget').value) || 0,
    },
  };
  try {
    await api('/api/config', { method: 'PUT', body: JSON.stringify(payload) });
    toast('ok', 'Settings saved.'); $('settingsOverlay').classList.remove('open');
  } catch (e) { toast('err', e.message); }
});

/* ============================= history ============================= */
$('historyToggle').addEventListener('click', () => { $('historyOverlay').classList.add('open'); loadHistory(); });
$('historyOverlay').addEventListener('click', (e) => { if (e.target.id === 'historyOverlay') $('historyOverlay').classList.remove('open'); });
async function loadHistory() {
  const list = $('historyList');
  list.innerHTML = '<p class="muted">Loading…</p>';
  try {
    const runs = await api('/api/runs?limit=30');
    if (!runs.length) { list.innerHTML = '<p class="muted">No runs yet.</p>'; return; }
    list.innerHTML = runs.map(r => {
      const tone = r.status === 'success' ? 'ok' : r.status === 'failed' ? 'high' : '';
      return '<div class="history-item' + (r.id === state.runId ? ' current' : '') + '" data-run="' + esc(r.id) + '">' +
        '<div class="r1"><span class="mono">' + esc(r.id) + '</span><span>' +
        (r.id === state.latestRunId ? '<span class="tag ok">Latest</span> ' : '') +
        '<span class="tag ' + tone + '">' + esc(r.status) + '</span></span></div>' +
        '<div class="faint small">' + esc(fmtDate(r.started_at)) + ', ' + esc(r.trigger_type) + '</div>' +
        (r.error ? '<div class="err">' + esc(r.error) + '</div>' : '') + '</div>';
    }).join('');
  } catch (e) { list.innerHTML = '<p class="muted">Could not load run history.</p>'; }
}
$('historyList').addEventListener('click', async (e) => {
  const item = e.target.closest('[data-run]'); if (!item) return;
  try {
    const run = await api('/api/runs/' + encodeURIComponent(item.dataset.run));
    if (run.status !== 'success') { toast('err', 'That run ' + run.status + '. Pick a successful one.'); return; }
    await loadRunIntoState(run);
    $('historyOverlay').classList.remove('open');
    toast('ok', 'Viewing scan ' + run.id + '.');
  } catch (err) { toast('err', err.message); }
});
$('jumpToLatestBtn').addEventListener('click', async () => {
  if (!state.latestRunId) return;
  try { await loadRunIntoState(await api('/api/runs/' + state.latestRunId)); toast('ok', 'Showing the latest scan.'); }
  catch (e) { toast('err', e.message); }
});

/* ============================= run a scan ============================= */
$('runScanBtn').addEventListener('click', triggerRun);
async function triggerRun() {
  $('runScanBtn').disabled = true;
  try {
    const res = await api('/api/runs', { method: 'POST' });
    clearDisplayedRun();
    document.body.classList.add('scanning'); $('scanBanner').classList.add('on'); $('scanLine').textContent = 'Starting…';
    pollRun(res.run_id);
  } catch (e) { toast('err', e.message); $('runScanBtn').disabled = false; }
}
function clearDisplayedRun() {
  // A new scan starts a new snapshot. Do not leave an older scan's graph,
  // roadmap or solution checklist visible while the new snapshot is building.
  state.findings = []; state.findingsSource = null;
  state.graph = null; state.migration = null;
  state.plan = null; state.selectedSystem = null; state.selectedNode = null;
  state.runId = null; state.runTime = null;
  renderScanChip();
  renderEverything();
}
function endScanUi() {
  state.polling = false; $('runScanBtn').disabled = false;
  document.body.classList.remove('scanning'); $('scanBanner').classList.remove('on');
}
function pollRun(runId) {
  if (state.polling) return;
  state.polling = true;
  const tick = async () => {
    try {
      const run = await api('/api/runs/' + runId);
      if (run.status === 'running' || run.status === 'queued') {
        const lines = String(run.log || '').split('\n').filter(Boolean);
        if (lines.length) $('scanLine').textContent = lines[lines.length - 1];
        setTimeout(tick, 1500); return;
      }
      endScanUi();
      if (run.status === 'success') {
        state.latestRunId = run.id; await loadRunIntoState(run);
        toast('ok', 'Scan finished. Showing its results.');
      } else toast('err', run.error || 'Scan failed. Open Run history to see the error.');
    } catch (e) { endScanUi(); toast('err', 'Lost connection to the server.'); }
  };
  tick();
}

/* ============================= load a run ============================= */
async function loadRunIntoState(run) {
  if (run.vulnerabilities_json) { state.findings = normalizeVulns(JSON.parse(run.vulnerabilities_json)); state.findingsSource = 'vulnerabilities'; }
  else if (run.cbom_json) { state.findings = normalizeCbom(JSON.parse(run.cbom_json)); state.findingsSource = 'cbom'; }
  else { state.findings = []; state.findingsSource = null; }
  state.graph = run.dependency_graph_json ? JSON.parse(run.dependency_graph_json) : null;
  state.migration = run.migration_ranking_json ? normalizeMigrationCurrency(JSON.parse(run.migration_ranking_json)) : null;
  state.runId = run.id; state.runTime = run.finished_at || run.started_at;
  state.selectedNode = null;
  renderScanChip();
  await loadSolutions();
  renderEverything();
}
function renderScanChip() {
  $('scanChip').style.display = state.runId ? 'flex' : 'none';
  if (!state.runId) return;
  const latest = !state.latestRunId || state.runId === state.latestRunId;
  $('scanId').textContent = state.runId; $('scanWhen').textContent = fmtDate(state.runTime);
  $('scanBadge').textContent = latest ? 'Latest' : 'Older scan';
  $('scanBadge').className = 'tag ' + (latest ? 'ok' : 'medium');
  $('jumpToLatestBtn').style.display = latest ? 'none' : 'inline-flex';
}

function normalizeVulns(arr) {
  return arr.map(f => ({
    algorithm: f.algorithm, kind: f.type || 'algorithm', file: f.file || '', line: f.line ?? '',
    severity: (f.severity || 'low').toLowerCase(), confidence: f.confidence || '', method: f.detection_method || '', quantumSafe: null,
  }));
}
function normalizeCbom(cbom) {
  const out = [];
  (cbom.components || []).forEach(c => {
    if (c.type !== 'cryptographic-asset') return;
    const props = {}; (c.properties || []).forEach(p => { props[p.name.replace('cadence:', '')] = p.value; });
    const occ = (c.evidence && c.evidence.occurrences && c.evidence.occurrences[0]) || {};
    const cp = c.cryptoProperties || {};
    out.push({
      algorithm: c.name, kind: (cp.algorithmProperties && cp.algorithmProperties.primitive) || cp.assetType || 'algorithm',
      file: occ.location || '', line: occ.line ?? '', severity: (props.severity || 'low').toLowerCase(),
      confidence: props.confidence || '', method: props.detectionMethod || '', quantumSafe: cp.nistQuantumSecurityStatus || null,
    });
  });
  return out;
}

function renderEverything() {
  for (const [name, fn] of [['overview', renderOverview], ['findings', renderFindings], ['graph', renderGraph],
                            ['roadmap', renderRoadmap], ['solutions', renderSolutions], ['chrome', renderChrome]]) {
    try { fn(); } catch (err) { console.error('CADENCE render error in ' + name, err); toast('err', 'Could not draw ' + name + '. See the browser console.'); }
  }
}
function renderChrome() {
  $('navFindings').textContent = state.findings.length || '';
  const s = state.plan && state.plan.summary;
  $('navSolutions').textContent = s && s.urgent ? s.urgent + ' urgent' : '';
  $('navSolutions').className = 'count' + (s && s.urgent ? ' alert' : '');
  $('readiness').style.display = s && s.steps_total ? 'block' : 'none';
  if (s && s.steps_total) {
    const pct = Math.round(s.steps_done / s.steps_total * 100);
    $('readinessText').textContent = s.steps_done + ' of ' + s.steps_total;
    $('readinessBar').style.width = pct + '%';
  }
}

/* ============================= overview ============================= */
function renderOverview() {
  const root = $('view-overview');
  if (!state.runId) {
    root.innerHTML = '<p class="lede">Find weak cryptography in your code and infrastructure, decide what to fix first, and move to post-quantum algorithms with a step-by-step plan for every system.</p>' +
      emptyState('No scan yet', 'Choose what to scan in Settings, then run your first scan. Everyone on the team sees the same results.',
        [{ label: 'Open settings', act: 'settings' }, { label: 'Run scan', act: 'run', primary: true }]);
    return;
  }
  const f = state.findings, ps = state.plan ? state.plan.summary : null;
  const high = f.filter(x => x.severity === 'high' || x.severity === 'critical').length;
  const med = f.filter(x => x.severity === 'medium').length;
  const low = f.length - high - med;
  const files = new Set(f.map(x => x.file)).size;
  const systems = state.graph ? state.graph.nodes.length : (ps ? ps.systems : 0);

  let line;
  if (!f.length) line = 'This scan found <b>no weak cryptography</b>. No remediation roadmap is shown for this run. Keep scanning on a schedule; zero findings do not prove risks are absent.';
  else if (ps) line = '<b>' + f.length + '</b> weak-crypto findings in <b>' + ps.systems_needing_action + '</b> of ' + ps.systems + ' systems. ' +
    'Of the ' + (ps.direct_pqc + ps.fix_first) + ' changes needed, <b>' + ps.direct_pqc + '</b> ' + (ps.direct_pqc === 1 ? 'replaces' : 'replace') + ' an algorithm a quantum computer will break, ' +
    'and <b>' + ps.fix_first + '</b> ' + (ps.fix_first === 1 ? 'fixes an algorithm that is' : 'fix algorithms that are') + ' already broken today.';
  else line = '<b>' + f.length + '</b> weak-crypto findings across ' + files + ' files.';

  const facts = [
    [f.length, 'Findings'], [high, 'High severity'], [files, 'Files affected'], [systems, 'Systems mapped'],
    [f.length && ps ? ps.steps_done + ' of ' + ps.steps_total : (f.length ? 'n/a' : 'None needed'), 'Migration steps done'],
  ].map(x => '<div class="fact"><dt>' + esc(x[1]) + '</dt><dd>' + esc(x[0]) + '</dd></div>').join('');

  const total = f.length || 1;
  const stack = '<div class="stack" role="img" aria-label="Severity split">' +
    '<span style="width:' + high / total * 100 + '%;background:var(--high)"></span>' +
    '<span style="width:' + med / total * 100 + '%;background:var(--medium)"></span>' +
    '<span style="width:' + low / total * 100 + '%;background:var(--low)"></span></div>' +
    '<div class="legend"><span class="sev high">High ' + high + '</span><span class="sev medium">Medium ' + med + '</span><span class="sev low">Low ' + low + '</span></div>';

  const counts = {}; f.forEach(x => { counts[x.algorithm] = (counts[x.algorithm] || 0) + 1; });
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 7);
  const maxC = top.length ? top[0][1] : 1;
  const swaps = (state.plan && state.plan.swaps) || {};
  const algoRows = top.length ? top.map(([name, n]) =>
    '<div class="bar-row"><span class="name" title="' + esc(name) + '">' + esc(name) + '</span>' +
    '<span><div class="meter"><span style="width:' + n / maxC * 100 + '%"></span></div>' +
    (swaps[name] ? '<div class="faint small" style="margin-top:2px;">Replace with ' + esc(swaps[name].swap) + '</div>' : '') +
    '</span><span class="n">' + n + '</span></div>').join('') : '<p class="muted">No findings in this scan.</p>';

  const start = state.plan ? state.plan.systems.filter(s => s.status === 'action').slice(0, 6) : [];
  const startRows = start.length ? start.map(s =>
    '<div class="list-row"><span class="rk">#' + esc(s.priority_rank) + '</span><span class="grow"><button class="link-btn" data-act="open-solution" data-system="' + esc(s.asset_id) + '">' + esc(s.asset_id) + '</button></span>' +
    sev(s.top_urgency) + '<span class="tag">' + s.progress.done + '/' + s.progress.total + ' done</span></div>').join('')
    : '<p class="muted">No system needs a code change.</p>';

  const next = f.length && state.migration ? [...state.migration.migration_order].sort((a, b) => a.priority_rank - b.priority_rank).slice(0, 6) : [];
  const nextRows = next.map(m =>
    '<div class="list-row"><span class="rk">#' + esc(m.priority_rank) + '</span><span class="grow">' + esc(m.asset_id) + '</span><span class="faint small">Week ' + esc(m.scheduled_week) + '</span></div>').join('')
    || '<p class="muted">No migration plan in this scan.</p>';

  root.innerHTML =
    (f.length ? '<div class="org-migration-banner">' +
      '<div><span class="tag ok">REPOSITORY MIGRATION</span><h2>Prepare a reviewable migration bundle</h2>' +
      '<p>CADENCE uses AST-backed detection where supported, makes only narrowly recognized safe edits, and packages a report and patch. Uncertain changes stay marked for manual review.</p></div>' +
      '<button class="btn primary" data-act="open-migrate">Migrate repository</button>' +
    '</div>' : '') +
    '<p class="summary-line">' + line + '</p>' +
    '<dl class="facts">' + facts + '</dl>' +
    '<div class="two-col section"><div><h2 style="margin-bottom:10px;">Severity</h2>' + stack +
    '<h2 style="margin:26px 0 6px;">Weakest algorithms</h2>' + algoRows + '</div>' +
    '<div><h2 style="margin-bottom:6px;">Start here</h2><p class="faint small" style="margin-bottom:6px;">' + (f.length ? 'Systems with weak cryptography, in migration order. Open one for its plan.' : 'No cryptographic remediation is indicated by this scan.') + '</p>' + startRows +
    (f.length ? '<h2 style="margin:26px 0 6px;">Migration schedule</h2>' + nextRows : '') + '</div></div>';
}

/* ============================= findings ============================= */
function renderFindings() {
  const root = $('view-findings');
  if (!state.runId) { root.innerHTML = emptyState('No findings yet', 'Run a scan to list every weak algorithm, protocol and key, down to the file and line.', [{ label: 'Run scan', act: 'run', primary: true }]); return; }
  if (!state.findings.length) { root.innerHTML = '<p class="lede">This scan found no weak cryptography.</p>'; return; }
  const kinds = [...new Set(state.findings.map(f => f.kind))].sort();
  root.innerHTML =
    '<p class="lede">Every weak algorithm, protocol or key the scan found. The last column says what replaces it.</p>' +
    '<div class="toolbar"><input type="text" id="fSearch" placeholder="Search algorithm or file" aria-label="Search findings">' +
    '<select id="fSev" aria-label="Severity"><option value="all">All severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>' +
    '<select id="fKind" aria-label="Kind"><option value="all">All kinds</option>' + kinds.map(k => '<option>' + esc(k) + '</option>').join('') + '</select>' +
    '<span class="count" id="fCount"></span></div>' +
    '<div class="table-wrap"><table class="tbl"><thead><tr><th>Severity</th><th>Algorithm</th><th>Kind</th><th>Location</th><th>Detected by</th><th>Replace with</th></tr></thead><tbody id="fBody"></tbody></table></div>';
  ['fSearch', 'fSev', 'fKind'].forEach(id => $(id).addEventListener(id === 'fSearch' ? 'input' : 'change', drawFindings));
  drawFindings();
}
function drawFindings() {
  const q = $('fSearch').value.toLowerCase(), sv = $('fSev').value, kd = $('fKind').value;
  const swaps = (state.plan && state.plan.swaps) || {};
  const rows = state.findings.filter(f =>
    (sv === 'all' || f.severity === sv || (sv === 'high' && f.severity === 'critical')) &&
    (kd === 'all' || f.kind === kd) &&
    (!q || f.algorithm.toLowerCase().includes(q) || f.file.toLowerCase().includes(q)));
  $('fCount').textContent = rows.length + ' of ' + state.findings.length;
  $('fBody').innerHTML = rows.map(f => {
    const s = swaps[f.algorithm];
    const full = f.file + (f.line !== '' && f.line != null ? ':' + f.line : '');
    const short = (f.file.split(/[\\/]/).pop() || f.file) + (f.line !== '' && f.line != null ? ':' + f.line : '');
    return '<tr><td>' + sev(f.severity) + '</td><td class="mono">' + esc(f.algorithm) + '</td><td>' + esc(f.kind) + '</td>' +
      '<td class="path mono" title="' + esc(full) + '">' + esc(short) + '</td><td>' + esc(f.method) + '</td>' +
      '<td>' + (s ? '<b style="font-weight:560">' + esc(s.swap) + '</b><div class="faint small">' + esc(s.relevance_label) + '</div>' : '<span class="faint">n/a</span>') + '</td></tr>';
  }).join('') || '<tr><td colspan="6" class="faint" style="padding:24px;">No findings match these filters.</td></tr>';
}

/* ============================= dependency map ============================= */
function layoutGraph(g) {
  const ids = g.nodes.map(n => n.id), byId = new Map(g.nodes.map(n => [n.id, n]));
  const edges = g.edges.filter(e => byId.has(e.source) && byId.has(e.target));
  const layer = new Map(ids.map(i => [i, 0]));
  for (let i = 0; i < ids.length; i++) {            // longest-path layering; the cap stops cycles looping
    let changed = false;
    edges.forEach(e => { const want = layer.get(e.source) + 1; if (layer.get(e.target) < want && want < ids.length) { layer.set(e.target, want); changed = true; } });
    if (!changed) break;
  }
  const cols = []; ids.forEach(i => { (cols[layer.get(i)] = cols[layer.get(i)] || []).push(i); });
  const BW = 172, BH = 42, GX = 46, GY = 12, pos = new Map();
  const critRank = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  cols.forEach((col, ci) => {
    if (ci === 0) col.sort((a, b) => (critRank[byId.get(a).criticality] ?? 3) - (critRank[byId.get(b).criticality] ?? 3) || a.localeCompare(b));
    else {                                           // barycentre ordering cuts edge crossings
      const bary = id => { const ps = edges.filter(e => e.target === id).map(e => pos.get(e.source)).filter(Boolean); return ps.length ? ps.reduce((s, p) => s + p.y, 0) / ps.length : 1e6; };
      col.sort((a, b) => bary(a) - bary(b));
    }
    col.forEach((id, ri) => pos.set(id, { x: ci * (BW + GX), y: ri * (BH + GY), col: ci }));
  });
  const tallest = Math.max(...cols.map(c => c.length));
  cols.forEach((col) => { const off = (tallest - col.length) * (BH + GY) / 2; col.forEach(id => { pos.get(id).y += off; }); });
  return { pos, edges, BW, BH, width: cols.length * (BW + GX) - GX, height: tallest * (BH + GY) - GY };
}

function renderGraph() {
  const root = $('view-graph');
  if (!state.graph) { root.innerHTML = emptyState('No dependency map yet', 'Run a scan to see the systems and relationships found in that scan.', [{ label: 'Run scan', act: 'run', primary: true }]); return; }
  if (!Array.isArray(state.graph.nodes) || !state.graph.nodes.length) { root.innerHTML = emptyState('No dependencies found in this scan', 'This scan did not produce any systems or dependency relationships. A new scan starts with a fresh map.', [{ label: 'Run another scan', act: 'run', primary: true }]); return; }
  const L = layoutGraph(state.graph);
  const sel = state.selectedNode;
  const hot = new Set(); if (sel) { hot.add(sel); L.edges.forEach(e => { if (e.source === sel) hot.add(e.target); if (e.target === sel) hot.add(e.source); }); }
  const mig = new Map(((state.migration && state.migration.migration_order) || []).map(m => [m.asset_id, m]));
  const color = c => !L.edges.length ? 'var(--ink-3)' : c === 'HIGH' ? 'var(--high)' : c === 'MEDIUM' ? 'var(--medium)' : 'var(--low)';

  const paths = L.edges.map(e => {
    const a = L.pos.get(e.source), b = L.pos.get(e.target);
    const x1 = a.x + L.BW, y1 = a.y + L.BH / 2, x2 = b.x, y2 = b.y + L.BH / 2, mx = (x1 + x2) / 2;
    const isHot = sel && (e.source === sel || e.target === sel);
    return '<path class="map-edge' + (isHot ? ' hot' : '') + '" d="M' + x1 + ' ' + y1 + ' C' + mx + ' ' + y1 + ' ' + mx + ' ' + y2 + ' ' + (x2 - 6) + ' ' + y2 + '" marker-end="url(#arrow' + (isHot ? 'Hot' : '') + ')"/>';
  }).join('');
  const nodes = state.graph.nodes.map(n => {
    const p = L.pos.get(n.id), m = mig.get(n.id);
    const label = n.id.length > 22 ? n.id.slice(0, 21) + '…' : n.id;
    const sub = !state.findings.length ? 'No remediation recommendations' :
      (m ? 'Rank ' + m.priority_rank + ', week ' + m.scheduled_week : 'No findings in this scan');
    return '<g class="map-node' + (sel === n.id ? ' sel' : '') + (sel && !hot.has(n.id) ? ' dim' : '') + '" data-act="select-node" data-node="' + esc(n.id) + '" transform="translate(' + p.x + ',' + p.y + ')" tabindex="0" role="button" aria-label="' + esc(n.id) + '">' +
      '<title>' + esc(n.id) + '</title><rect class="box" width="' + L.BW + '" height="' + L.BH + '" rx="3"/>' +
      '<rect width="5" height="' + L.BH + '" rx="2" fill="' + color(n.criticality) + '"/>' +
      '<text x="15" y="18">' + esc(label) + '</text><text class="sub" x="15" y="33">' + esc(sub) + '</text></g>';
  }).join('');

  const architecture = state.graph.architecture || {};
  const graphIntro = L.edges.length
    ? (architecture.is_template
        ? 'System names and dependency links are illustrative reference topology; scanned files are not assigned to those sample services. Replace the template with your verified architecture before using centrality or roadmap priorities for production.'
        : 'Arrows show configured enterprise dependencies: each source system relies on its target. The coloured bar indicates centrality across the configured topology.')
    : 'No enterprise dependency links were configured. The inventory contains scan findings, but system interconnections and architecture-level centrality remain unknown.';
  root.innerHTML =
    '<p class="lede">' + graphIntro + '</p>' +
    '<div class="map-shell"><div class="map-canvas"><svg width="' + (L.width + 12) + '" height="' + (L.height + 12) + '" viewBox="-6 -6 ' + (L.width + 12) + ' ' + (L.height + 12) + '" role="group" aria-label="Dependency map">' +
    '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="var(--ink-3)"/></marker>' +
    '<marker id="arrowHot" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="var(--accent)"/></marker></defs>' +
    paths + nodes + '</svg></div><div class="map-side" id="mapSide"></div></div>' +
    (L.edges.length ? '<div class="legend"><span class="sev high">High centrality</span><span class="sev medium">Medium</span><span class="sev low">Low</span></div>' : '<p class="faint small">Centrality is unavailable until dependency relationships are provided.</p>');
  root.querySelectorAll('.map-node').forEach(g => g.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); g.dispatchEvent(new MouseEvent('click', { bubbles: true })); } }));
  renderNodeDetail(L);
}
function renderNodeDetail(L) {
  const side = $('mapSide'), id = state.selectedNode;
  if (!id) { side.innerHTML = '<p class="muted">' + (!state.findings.length
    ? 'Select a system to inspect its configured enterprise dependencies.'
    : (L.edges.length ? 'Select a system to see what it depends on, what depends on it, and where it sits in the migration order.' : 'Select a system to see its findings and migration-plan position. No dependency relationships were configured.')) + '</p>'; return; }
  const n = state.graph.nodes.find(x => x.id === id); if (!n) return;
  const m = state.migration && state.migration.migration_order.find(x => x.asset_id === id);
  const calls = L.edges.filter(e => e.source === id).map(e => e.target), calledBy = L.edges.filter(e => e.target === id).map(e => e.source);
  const links = arr => arr.length ? arr.map(x => '<div><button class="link-btn" data-act="select-node" data-node="' + esc(x) + '">' + esc(x) + '</button></div>').join('') : '<span class="faint">None</span>';
  const crit = String(n.criticality || '');
  const critLabel = L.edges.length ? esc(cap(crit.toLowerCase())) + ' centrality' : 'Dependency centrality unknown';
  const metrics = L.edges.length
    ? '<div class="kv"><span>Depends on</span><span>' + n.out_degree + '</span></div><div class="kv"><span>Depended on by</span><span>' + n.in_degree + '</span></div><div class="kv"><span>PageRank</span><span>' + esc(n.pagerank) + '</span></div>'
    : '<p class="faint small">Dependency metrics unavailable</p>';
  const col1 = '<div><div class="side-title">' + esc(n.id) + '</div><span class="tag ' + (L.edges.length && crit === 'HIGH' ? 'high' : L.edges.length && crit === 'MEDIUM' ? 'medium' : '') + '">' + critLabel + '</span>' +
    '<div style="margin-top:12px;">' + metrics + '</div></div>';
  const col2 = L.edges.length
    ? '<div><h3 style="margin-bottom:4px;">Depends on</h3>' + links(calls) + '<h3 style="margin:14px 0 4px;">Depended on by</h3>' + links(calledBy) + '</div>'
    : '<div><h3 style="margin-bottom:4px;">Dependencies</h3><p class="faint small">No dependency records were provided for this scan.</p></div>';
  let col3 = '<div><h3 style="margin-bottom:4px;">Migration</h3>';
  if (!state.findings.length) {
    col3 += '<p class="muted">No remediation roadmap is needed for this scan. The dependency map remains available as architecture context.</p>';
  } else if (m) {
    col3 += '<div class="kv"><span>Rank</span><span>#' + esc(m.priority_rank) + '</span></div><div class="kv"><span>Start</span><span>Week ' + esc(m.scheduled_week) + '</span></div>' +
      (m.compliance_deadline ? '<div class="kv"><span>Deadline</span><span>' + esc(m.compliance_deadline) + '</span></div>' : '') +
      '<div class="kv"><span>Effort</span><span>' + esc(m.effort_weeks) + ' eng-weeks</span></div><div class="kv"><span>Cost</span><span>' + money(m.estimated_cost) + '</span></div>';
    if (m.algorithms && m.algorithms.length) col3 += '<div class="chips">' + m.algorithms.map(a => '<span class="tag mono">' + esc(a) + '</span>').join('') + '</div>';
  } else col3 += '<p class="muted">No findings from this scan were mapped to this system, so it has no remediation task.</p>';
  if (state.findings.length && m) col3 += '<p style="margin-top:12px;"><button class="btn small" data-act="open-solution" data-system="' + esc(id) + '">Open solution plan</button></p>';
  else if (state.findings.length && n.context_only) col3 += '<p class="faint small" style="margin-top:12px;">Context-only source file; no migration task was created.</p>';
  col3 += '</div>';
  side.innerHTML = '<div class="side-grid">' + col1 + col2 + col3 + '</div>';
}

/* ============================= roadmap ============================= */
function renderRoadmap() {
  const root = $('view-roadmap');
  if (!state.runId) { root.innerHTML = emptyState('No migration plan yet', 'Run a scan to see whether any remediation is needed.', [{ label: 'Run scan', act: 'run', primary: true }]); return; }
  if (!state.findings.length) {
    root.innerHTML = emptyState('No remediation roadmap for this scan',
      'No weak-cryptography findings were reported, so system rankings and migration recommendations are hidden for this run. A zero-finding scan is not proof that risks are absent; confirm the scan target and scope.',
      [{ label: 'View dependencies', act: 'open-graph' }, { label: 'Run another scan', act: 'run', primary: true }]);
    return;
  }
  if (!state.migration) { root.innerHTML = emptyState('No migration plan available', 'This scan has findings, but its migration schedule could not be loaded. Run the scan again or inspect the run history.'); return; }
  const c = state.migration.constraints_used || {};
  const rows = [...state.migration.migration_order].sort((a, b) => a.priority_rank - b.priority_rank);
  const body = rows.map(m =>
    '<details><summary><span class="rk">#' + esc(m.priority_rank) + '</span><span><b style="font-weight:600">' + esc(m.asset_id) + '</b></span>' +
    '<span>Week ' + esc(m.scheduled_week) + '</span><span>' + sev(m.worst_severity) + '</span><span>' + esc(m.effort_weeks) + ' wk</span><span>' + money(m.estimated_cost) + '</span>' +
    '<span class="small">' + (m.compliance_deadline ? esc(m.compliance_deadline) + ' (' + Math.round(m.days_remaining) + ' days)' : '<span class="faint">No deadline</span>') + '</span></summary>' +
    '<div class="body"><p>' + esc(m.reasoning) + '</p>' +
    (m.algorithms && m.algorithms.length ? '<div class="chips">' + m.algorithms.map(a => '<span class="tag mono">' + esc(a) + '</span>').join('') + '</div>' : '') +
    '<p style="margin-top:10px;"><button class="btn small" data-act="open-solution" data-system="' + esc(m.asset_id) + '">Open solution plan</button></p></div></details>').join('');
  root.innerHTML =
    '<div class="toolbar"><p class="lede" style="margin:0;flex:1;">Systems in the order to migrate them, scheduled over <b>' + esc(c.planning_horizon_weeks || 'n/a') + ' weeks</b> for a team of <b>' + esc(c.team_size || 'n/a') + '</b> within <b>' + money(c.total_budget) + '</b>. Select a row for the reasoning.</p>' +
    '<button class="btn" data-act="export-csv">Export CSV</button><button class="btn" data-act="export-json">Export JSON</button></div>' +
    '<div class="table-wrap road"><div class="head"><span>Rank</span><span>System</span><span>Start</span><span>Worst finding</span><span>Effort</span><span>Cost</span><span>Deadline</span></div>' + body + '</div>';
}
function csvCell(v) { const s = v === null || v === undefined ? '' : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
function exportName(ext) { return 'cadence-roadmap' + (state.runId ? '-' + state.runId : '') + '-' + new Date().toISOString().slice(0, 10) + '.' + ext; }
function exportRoadmapCsv() {
  if (!state.findings.length || !state.migration) return;
  const head = ['Rank', 'System', 'Score', 'Worst severity', 'Findings', 'Criticality', 'Dependent systems', 'Effort (eng-weeks)', 'Cost (INR)', 'Week', 'Deadline', 'Days remaining', 'Algorithms', 'Reasoning'];
  const lines = [head.map(csvCell).join(',')];
  [...state.migration.migration_order].sort((a, b) => a.priority_rank - b.priority_rank).forEach(m => {
    const dependencyCriticality = m.dependency_criticality || m['module' + '2_criticality'] || '';
    lines.push([m.priority_rank, m.asset_id, m.score, m.worst_severity || '', m.finding_count, dependencyCriticality, m.total_dependents, m.effort_weeks, m.estimated_cost, m.scheduled_week, m.compliance_deadline || '', m.days_remaining ?? '', (m.algorithms || []).join('; '), m.reasoning || ''].map(csvCell).join(','));
  });
  downloadFile(exportName('csv'), lines.join('\r\n'), 'text/csv;charset=utf-8'); toast('ok', 'Roadmap exported as CSV.');
}
function exportRoadmapJson() {
  if (!state.findings.length || !state.migration) return;
  downloadFile(exportName('json'), JSON.stringify({
    exported_at: new Date().toISOString(), run_id: state.runId, constraints_used: state.migration.constraints_used || null,
    scheduling_method: state.migration.scheduling_method || null,
    migration_order: [...state.migration.migration_order].sort((a, b) => a.priority_rank - b.priority_rank),
  }, null, 2), 'application/json;charset=utf-8');
  toast('ok', 'Roadmap exported as JSON.');
}

/* ============================= bootstrap ============================= */
async function bootstrap() {
  try {
    const health = await fetch('/api/health').then(r => r.json());
    if (health.auth_required && !appPassword) { $('authOverlay').classList.add('open'); return; }
  } catch (e) { /* surfaces on the next call */ }
  try {
    const runs = await api('/api/runs?limit=1');
    if (Array.isArray(runs) && runs.length && runs[0].status === 'success') {
      state.latestRunId = runs[0].id;
      await loadRunIntoState(await api('/api/runs/' + runs[0].id));
    } else renderEverything();
  } catch (e) { renderEverything(); }
  showView(location.hash.slice(1) || 'overview');
}

initTheme();
renderMigration();
bootstrap();
