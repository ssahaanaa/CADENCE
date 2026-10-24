/* CADENCE console: Solutions.
   Turns the roadmap into per-system work: what to change, an ordered plan the
   team ticks off, code before/after, how to verify, and what changes in size.
   Globals (state, esc, api, toast, ...) come from app.js and are used lazily. */

const LANGS = [['python', 'Python'], ['java', 'Java'], ['javascript', 'JavaScript'], ['config', 'Proxy / TLS config']];
const THREAT = {
  classical: ['Broken today', 'high'],
  quantum: ['Quantum risk', 'medium'],
  both: ['Broken today and by quantum', 'critical'],
  none: ['Operational', ''],
};

/* ----------------------------- data ----------------------------- */
async function loadSolutions() {
  if (!state.migration || !state.findings.length) {
    state.plan = null;
    state.selectedSystem = null;
    return;
  }
  try {
    const q = '?run_id=' + encodeURIComponent(state.runId || '') + '&profile=' + encodeURIComponent(state.profile);
    state.plan = await api('/api/solutions' + q);
  } catch (e) { state.plan = null; console.error('Could not load solutions:', e); }
  // keep the selection valid, and default to the most urgent system that needs work
  const systems = state.plan ? state.plan.systems : [];
  if (!systems.some(s => s.asset_id === state.selectedSystem)) {
    const first = systems.find(s => s.status === 'action') || systems[0];
    state.selectedSystem = first ? first.asset_id : null;
  }
}
async function loadCatalog() {
  try { state.catalog = await api('/api/solutions/catalog?profile=' + encodeURIComponent(state.profile)); }
  catch (e) { state.catalog = null; }
}
async function setProfile(id) {
  if (id === state.profile) return;
  state.profile = id;
  await loadSolutions();
  if (state.catalog) await loadCatalog();
  renderSolutions(); renderChrome();
}
async function toggleStep(system, stepId, done) {
  const sys = state.plan.systems.find(s => s.asset_id === system);
  const step = sys && sys.steps.find(s => s.id === stepId);
  if (!step) return;
  step.done = done; recount(); renderSolutions(); renderChrome();
  try { await api('/api/solutions/progress', { method: 'PUT', body: JSON.stringify({ run_id: state.runId, system, step_id: stepId, done }) }); }
  catch (e) { step.done = !done; recount(); renderSolutions(); renderChrome(); toast('err', 'Could not save that change: ' + e.message); }
}
function recount() {
  let t = 0, d = 0;
  state.plan.systems.forEach(s => {
    s.progress = { done: s.steps.filter(x => x.done).length, total: s.steps.length };
    t += s.progress.total; d += s.progress.done;
  });
  state.plan.summary.steps_total = t; state.plan.summary.steps_done = d;
}
document.addEventListener('change', (e) => {
  const cb = e.target.closest('input[data-step]');
  if (cb) toggleStep(cb.dataset.system, cb.dataset.step, cb.checked);
  if (e.target.id === 'guideSearch') { state.guideQuery = e.target.value; drawGuideList(); }
});
document.addEventListener('input', (e) => { if (e.target.id === 'guideSearch') { state.guideQuery = e.target.value; drawGuideList(); } });

/* ----------------------------- page ----------------------------- */
function renderSolutions() {
  const root = $('view-solutions');
  if (!state.runId) {
    root.innerHTML = emptyState('No solution plan yet',
      'Run a scan first. For every system CADENCE will list what to change, give a step-by-step plan, show code before and after, and tell you how to check it worked.',
      [{ label: 'Run scan', act: 'run', primary: true }]);
    return;
  }
  if (!state.findings.length) {
    root.innerHTML = emptyState('No remediation items for this scan',
      'CADENCE detected no weak-cryptography findings, so there are no system change recommendations to show. A zero-finding scan is not proof that cryptography risks are absent; confirm the scan target and scope.',
      [{ label: 'View dependencies', act: 'open-graph' }, { label: 'Run another scan', act: 'run', primary: true }]);
    return;
  }
  if (!state.plan) {
    root.innerHTML = emptyState('No solution plan available',
      'This scan has findings, but its remediation plan could not be loaded. Try reloading the run or running a new scan.');
    return;
  }
  const p = state.plan, s = p.summary;
  const prof = p.profiles.map(x => '<button class="' + (x.id === p.profile.id ? 'on' : '') + '" data-act="profile" data-profile="' + esc(x.id) + '" title="' + esc(x.blurb) + '">' + esc(x.label) + '</button>').join('');
  const tabs = [['systems', 'By system'], ['guide', 'Algorithm guide'], ['primer', 'PQC primer']]
    .map(t => '<button class="' + (state.solTab === t[0] ? 'on' : '') + '" data-act="soltab" data-tab="' + t[0] + '">' + t[1] + '</button>').join('');

  let body = '';
  if (state.solTab === 'systems') body = systemsTab();
  else if (state.solTab === 'guide') body = '<div id="guideHost"><p class="muted">Loading…</p></div>';
  else body = '<div id="primerHost"><p class="muted">Loading…</p></div>';

  const openIdx = [...root.querySelectorAll('details[open]')].map(d => [...root.querySelectorAll('details')].indexOf(d));
  const listScroll = root.querySelector('.sys-list') ? root.querySelector('.sys-list').scrollTop : 0;
  root.innerHTML =
    '<div class="sol-top"><div class="seg" role="group" aria-label="Security level">' + prof + '</div>' +
    '<span class="muted small grow">' + esc(p.profile.blurb) + ' Uses <b>' + esc(p.profile.kem) + '</b> for key exchange and <b>' + esc(p.profile.sig) + '</b> for signatures.</span>' +
    '<button class="btn" data-act="export-plan">Export all as Markdown</button></div>' +
    '<p class="sol-summary">' + summaryText(s) + '</p>' +
    '<div class="tabs" role="tablist">' + tabs + '</div>' + body;

  const all = root.querySelectorAll('details');           // keep expanded rows open across re-renders
  openIdx.forEach(i => { if (all[i]) all[i].open = true; });
  if (root.querySelector('.sys-list')) root.querySelector('.sys-list').scrollTop = listScroll;
  if (state.solTab === 'guide') withCatalog(renderGuide);
  if (state.solTab === 'primer') withCatalog(renderPrimer);
}
function summaryText(s) {
  if (!s.systems_needing_action) return 'No system has weak cryptography in code. Each one still has a short checklist to confirm its TLS setup is ready for hybrid post-quantum key exchange.';
  return '<b>' + s.systems_needing_action + ' of ' + s.systems + '</b> systems need code or config changes, covering <b>' + s.distinct_algorithms + '</b> weak algorithms. ' +
    '<b>' + s.urgent + '</b> of the changes are urgent. Most items marked <i>fix first</i> are broken by ordinary attacks today and are fixed with AES, SHA-256 and TLS 1.3. ' +
    'The post-quantum swap (ML-KEM, ML-DSA) is for the public-key items.';
}
async function withCatalog(fn) { if (!state.catalog) await loadCatalog(); fn(); }

/* ----------------------------- systems tab ----------------------------- */
function systemsTab() {
  const systems = state.plan.systems;
  const act = systems.filter(s => s.status === 'action'), ver = systems.filter(s => s.status !== 'action');
  const item = s =>
    '<button class="sys-item' + (s.asset_id === state.selectedSystem ? ' on' : '') + '" data-act="select-system" data-system="' + esc(s.asset_id) + '">' +
    '<div class="row1"><span class="rk">#' + esc(s.priority_rank) + '</span><span class="nm">' + esc(s.asset_id) + '</span></div>' +
    '<div class="row2">' + (s.top_urgency ? sev(s.top_urgency) : '<span class="sev none">Verify</span>') + '<div class="meter"><span style="width:' + (s.progress.total ? s.progress.done / s.progress.total * 100 : 0) + '%"></span></div><span>' + s.progress.done + '/' + s.progress.total + '</span></div></button>';
  const list = (act.length ? '<div class="sys-group">Needs changes (' + act.length + ')</div>' + act.map(item).join('') : '') +
    (ver.length ? '<div class="sys-group">Nothing found, verify (' + ver.length + ')</div>' + ver.map(item).join('') : '');
  const cur = systems.find(s => s.asset_id === state.selectedSystem);
  return '<div class="sol-layout"><div class="sys-list">' + list + '</div><div class="sol-detail">' + (cur ? systemDetail(cur) : '<p class="muted">Select a system.</p>') + '</div></div>';
}

function systemDetail(s) {
  const pct = s.progress.total ? Math.round(s.progress.done / s.progress.total * 100) : 0;
  const meta = [
    ['Rank', '#' + s.priority_rank], ['Start', 'Week ' + s.scheduled_week],
    s.compliance_deadline ? ['Deadline', s.compliance_deadline + ' (' + Math.round(s.days_remaining) + ' days)'] : null,
    ['Depended on by', s.total_dependents + ' system' + (s.total_dependents === 1 ? '' : 's')],
    ['Effort', s.effort_weeks + ' eng-weeks'], ['Estimate', money(s.estimated_cost)],
  ].filter(Boolean).map(m => '<span>' + esc(m[0]) + ' <b>' + esc(m[1]) + '</b></span>').join('');

  let h = '<div class="sol-head"><div><h2>' + esc(s.asset_id) + '</h2><div class="sol-meta">' + meta + '</div></div>' +
    '<div class="sol-progress"><div class="label"><span>Plan progress</span><span>' + s.progress.done + ' of ' + s.progress.total + ' steps</span></div><div class="meter"><span style="width:' + pct + '%"></span></div>' +
    '<p style="margin-top:10px;"><button class="btn small" data-act="export-plan" data-system="' + esc(s.asset_id) + '">Export this plan</button></p></div></div>';

  if (s.status !== 'action') {
    h += '<div class="notice">The scan found no weak cryptography in code for this system. That does not prove there is none, so the plan below is a short manual check. ' +
      (s.total_dependents ? esc(s.total_dependents) + ' other systems depend on it, which increases its migration impact.' : '') + '</div>';
  } else {
    h += '<div class="block"><h3>What to change</h3><p class="sub">Select a row for a plain-English explanation, the pitfalls, and where the scan found it.</p>' + s.changes.map(c => changeRow(c, true)).join('') + '</div>';
  }

  h += '<div class="block"><h3>Plan</h3><p class="sub">Work top to bottom. Ticks are shared for this scan only; a new scan starts with fresh progress.</p>' + phases(s) + '</div>';
  if (s.snippet_ids.length) h += '<div class="block"><h3>Code changes</h3><p class="sub">Before and after for the changes above. Copy, adapt to your codebase, then test.</p>' + snippets(s) + '</div>';
  h += '<div class="block"><h3>How to verify</h3><p class="sub">Run these after each change. “HOST” is the endpoint you changed.</p>' + s.verify.map(verifyRow).join('') + '</div>';
  if (s.impact.length) h += '<div class="block"><h3>What gets bigger</h3><p class="sub">Post-quantum keys and signatures are larger. These are the exact NIST sizes for the selected level, so check any field, header or buffer that holds them.</p>' + impactTable(s.impact) + '</div>';
  return h;
}

function changeRow(c, showWhere) {
  const t = THREAT[c.threat] || THREAT.none;
  const where = showWhere && c.locations && c.locations.length ? '<h4>Found in</h4><p class="mono small">' + c.locations.map(esc).join('<br>') + '</p>' : '';
  const roles = c.roles ? '<h4>Which replacement depends on how the key is used</h4><ul>' + c.roles.map(r => '<li><b>' + esc(r.role) + ':</b> ' + esc(r.replace) + '</li>').join('') + '</ul>' : '';
  return '<details class="change"' + '><summary>' +
    '<div><span class="cell-label">Found</span><b class="mono" style="font-weight:600">' + esc(c.name) + '</b>' + (c.occurrences > 1 ? ' <span class="faint small">x' + c.occurrences + '</span>' : '') + '</div>' +
    '<div><span class="cell-label">Risk</span><span class="tag ' + t[1] + '">' + esc(t[0]) + '</span></div>' +
    '<div><span class="cell-label">' + esc(c.relevance_label) + '</span><span class="swap">' + esc(c.swap) + '</span></div>' +
    '<span class="caret"></span></summary><div class="detail">' +
    '<h4>In plain English</h4><p>' + esc(c.plain) + '</p>' +
    '<h4>Why it matters</h4><p>' + esc(c.threat_text) + '</p>' +
    (c.roles ? '' : '<h4>Replace with</h4><ul>' + c.replace.map(r => '<li>' + esc(r) + '</li>').join('') + '</ul>') + roles + where +
    (c.gotchas && c.gotchas.length ? '<h4>Watch out for</h4><ul>' + c.gotchas.map(g => '<li>' + esc(g) + '</li>').join('') + '</ul>' : '') +
    '<p class="faint small" style="margin-top:10px;">Effort: ' + esc(c.difficulty) + '</p></div></details>';
}

function phases(s) {
  const groups = {};
  s.steps.forEach(st => { (groups[st.phase] = groups[st.phase] || { label: st.phase_label, steps: [] }).steps.push(st); });
  return Object.keys(groups).sort().map((k, i) => {
    const g = groups[k];
    return '<div class="phase"><div class="phase-title"><span>' + esc(g.label) + '</span><span class="line"></span><span class="faint small">' +
      g.steps.filter(x => x.done).length + '/' + g.steps.length + '</span></div>' +
      g.steps.map(st => '<label class="step' + (st.done ? ' done' : '') + '"><input type="checkbox" data-system="' + esc(s.asset_id) + '" data-step="' + esc(st.id) + '"' + (st.done ? ' checked' : '') + '>' +
        '<span><span class="t">' + esc(st.title) + '</span><span class="d" style="display:block">' + esc(st.detail) + '</span></span></label>').join('') + '</div>';
  }).join('');
}

function snippets(s) {
  const sn = state.plan.snippets;
  const lang = state.langBySystem[s.asset_id] || s.preferred_languages[0] || 'python';
  const avail = LANGS.filter(l => s.snippet_ids.some(id => sn[id] && sn[id][l[0]]));
  const bar = '<div class="lang-bar"><div class="seg" role="group" aria-label="Language">' +
    avail.map(l => '<button class="' + (l[0] === lang ? 'on' : '') + '" data-act="lang" data-lang="' + l[0] + '">' + esc(l[1]) + '</button>').join('') + '</div>' +
    (s.preferred_languages.length ? '<span class="faint small">Languages found in this system: ' + s.preferred_languages.map(esc).join(', ') + '</span>' : '') + '</div>';
  const items = s.snippet_ids.filter(id => sn[id] && sn[id][lang]).map(id => {
    const v = sn[id][lang];
    const pane = (cls, label, code) => '<div class="' + cls + '"><div class="codehead"><span>' + label + '</span><button class="btn small" data-act="copy" data-copy="' + stash(code) + '">Copy</button></div><pre><code>' + esc(code) + '</code></pre></div>';
    return '<div class="snip"><h4>' + esc(sn[id].title) + '</h4><div class="codepair">' + pane('before', 'Before', v.before) + pane('after', 'After', v.after) + '</div>' +
      (v.note ? '<p class="note">' + esc(v.note) + '</p>' : '') + '</div>';
  });
  const targets = s.changes.flatMap(c => (c.file_targets || []).map(file => ({ change: c, file })));
  const fileGroups = new Map();
  targets.forEach(target => {
    const key = target.file.path;
    if (!fileGroups.has(key)) fileGroups.set(key, { path: key, display: target.file.display, targets: [] });
    fileGroups.get(key).targets.push(target);
  });
  const fileRows = [...fileGroups.values()].map(group => {
    const algorithms = [...new Set(group.targets.map(target => target.change.name))];
    const anySafe = group.targets.some(target => target.file.can_fix);
    const fileAttrs = ' data-run="' + esc(state.runId) + '" data-system="' + esc(s.asset_id) + '" data-file-path="' + esc(group.path) + '" data-profile="' + esc(state.profile) + '"';
    const wholeFile = anySafe
      ? '<button class="btn small primary" data-act="fix-file" data-fix-entire-file="true"' + fileAttrs + '>Fix entire file &amp; download</button>'
      : '<span class="tag">Manual changes only</span>';
    const individual = group.targets.map(({ change, file }) => file.can_fix
      ? '<button class="btn small" data-act="fix-file" data-algorithm="' + esc(change.name) + '"' + fileAttrs + '>Fix ' + esc(change.name) + ' only</button>'
      : '<span class="tag">' + esc(change.name) + ': manual</span>').join('');
    return '<div class="fix-now-file-group"><div class="fix-now-row"><span><b class="mono">' + esc(group.display) + '</b><span class="faint small"> · ' + esc(algorithms.join(', ')) + '</span></span>' + wholeFile + '</div>' +
      '<div class="fix-now-subrows">' + individual + '</div></div>';
  }).join('');
  const fixPanel = targets.length ? '<div class="fix-now-panel"><h4>Fix scanned file(s)</h4>' +
    '<p class="faint small">“Fix entire file” applies all current high-confidence findings in that file that CADENCE can safely edit; unsupported or uncertain findings remain unchanged and are reported. Individual actions apply only the named finding. Every download is rechecked and syntax/post-edit validated. The original file is never changed.</p>' +
    '<div class="fix-now-list">' + fileRows + '</div></div>' : '';
  return bar + fixPanel + (items.join('') || '<p class="muted">No ' + esc(lang) + ' example for these changes. Pick another language above.</p>');
}

function verifyRow(v) {
  return '<div class="verify-item"><div class="lbl">' + esc(v.label) + '</div>' +
    (v.command ? '<div class="cmd"><code>' + esc(v.command) + '</code><button data-act="copy" data-copy="' + stash(v.command) + '">Copy</button></div>' : '') +
    '<div class="expect">Expected: ' + esc(v.expect) + '</div></div>';
}
function impactTable(rows) {
  return '<div class="table-wrap"><table class="tbl"><thead><tr><th>What</th><th class="num">Before</th><th class="num">After</th><th class="num">Growth</th></tr></thead><tbody>' +
    rows.map(r => '<tr><td>' + esc(r.label) + (r.note ? '<div class="faint small">' + esc(r.note) + '</div>' : '') + '</td><td class="num">' + esc(r.before) + '</td><td class="num">' + esc(r.after) + '</td><td class="num"><b>' + esc(r.multiplier) + 'x</b></td></tr>').join('') +
    '</tbody></table></div>';
}

/* ----------------------------- algorithm guide ----------------------------- */
function renderGuide() {
  const host = $('guideHost'); if (!host) return;
  if (!state.catalog) { host.innerHTML = '<p class="muted">The guide could not be loaded.</p>'; return; }
  host.innerHTML = '<p class="lede">Every algorithm CADENCE knows how to fix, whether or not your scan found it. Use it to plan ahead.</p>' +
    '<div class="toolbar"><input type="text" id="guideSearch" placeholder="Search, for example RSA or MD5" aria-label="Search algorithms" value="' + esc(state.guideQuery) + '"></div><div id="guideList"></div>';
  drawGuideList();
}
function drawGuideList() {
  const list = $('guideList'); if (!list || !state.catalog) return;
  const q = state.guideQuery.toLowerCase();
  const algos = state.catalog.algorithms.filter(a => !q || (a.title + ' ' + a.swap + ' ' + a.category_label).toLowerCase().includes(q));
  const order = ['public_key', 'certificate', 'protocol', 'cipher_suite', 'symmetric', 'hash', 'hygiene', 'other'];
  list.innerHTML = order.map(cat => {
    const items = algos.filter(a => a.category === cat); if (!items.length) return '';
    return '<h3 style="margin:18px 0 8px;">' + esc(items[0].category_label) + '</h3>' + items.map(a => changeRow(Object.assign({}, a, { name: a.title, occurrences: 0, locations: [] }), false)).join('');
  }).join('') || '<p class="muted">Nothing matches that search.</p>';
}

/* ----------------------------- primer ----------------------------- */
function renderPrimer() {
  const host = $('primerHost'); if (!host) return;
  const ref = state.catalog && state.catalog.reference;
  const kemRows = ref ? Object.entries(ref.kem).map(([n, v]) => '<tr><td class="mono">' + esc(n) + '</td><td class="num">' + v.nist_level + '</td><td class="num">' + v.public_key.toLocaleString() + ' B</td><td class="num">' + v.ciphertext.toLocaleString() + ' B</td></tr>').join('') : '';
  const sigRows = ref ? Object.entries(ref.signature).map(([n, v]) => '<tr><td class="mono">' + esc(n) + '</td><td class="num">' + v.nist_level + '</td><td class="num">' + v.public_key.toLocaleString() + ' B</td><td class="num">' + v.signature.toLocaleString() + ' B</td></tr>').join('') : '';
  host.innerHTML =
    '<div class="prose">' +
    '<h3>Why move now</h3><p>A large quantum computer would break RSA, Diffie-Hellman and elliptic-curve cryptography. Nobody can build one yet, but an attacker can <b>record encrypted traffic today and decrypt it later</b>. Anything that must stay secret for many years is already exposed to that, which is why key exchange is the most urgent change. Signatures only matter once the computer exists, but certificates and firmware live for years, so they need a head start too.</p>' +
    '<p>NIST published the first three post-quantum standards in August 2024, and its transition guidance sets timelines for retiring RSA and elliptic-curve algorithms. Check the current NIST and your regulator\'s deadlines when you finalise your schedule.</p>' +
    '<h3>Which algorithm does which job</h3>' +
    '<p><b>ML-KEM (FIPS 203)</b> agrees on a shared secret key. It replaces RSA key transport, Diffie-Hellman and ECDH. <b>ML-DSA (FIPS 204)</b> is the general-purpose signature. It replaces RSA and ECDSA signing. <b>SLH-DSA (FIPS 205)</b> is a conservative, hash-based signature with tiny keys but large, slow signatures, best for firmware and long-lived roots that are signed rarely.</p>' +
    '<h3>Not everything needs a post-quantum algorithm</h3>' +
    '<p>MD5, SHA-1, DES, RC4 and SSLv3 or TLS 1.0 and 1.1 are broken by ordinary attacks. They are fixed with SHA-256, AES-256-GCM and TLS 1.3, which also stay safe against quantum computers at those sizes. CADENCE labels these <i>fix first</i>. TLS 1.3 is also the prerequisite for hybrid post-quantum key exchange.</p>' +
    '<h3>Why hybrid</h3>' +
    '<p>A hybrid key exchange runs a classical algorithm (X25519) and ML-KEM together and mixes the two secrets. It stays secure if either one holds, which protects you from both a future quantum computer and an undiscovered flaw in the new algorithm. Browsers and TLS libraries already offer it, and clients that do not support it fall back automatically.</p>' +
    '<h3>What the scanner does not flag</h3>' +
    '<p>The scan reports weak or outdated algorithms. Strong classical public-key cryptography such as RSA-2048 or ECDSA P-256 is secure against today\'s computers, so it is not flagged, but it is still quantum-vulnerable. Use the cryptographic inventory (CBOM) to track those and schedule their migration.</p></div>' +
    '<div class="two-col section"><div><h3 style="margin-bottom:8px;">Key exchange (ML-KEM)</h3><div class="table-wrap"><table class="tbl"><thead><tr><th>Parameter set</th><th class="num">NIST level</th><th class="num">Public key</th><th class="num">Ciphertext</th></tr></thead><tbody>' + kemRows + '</tbody></table></div></div>' +
    '<div><h3 style="margin-bottom:8px;">Signatures (ML-DSA, SLH-DSA)</h3><div class="table-wrap"><table class="tbl"><thead><tr><th>Parameter set</th><th class="num">NIST level</th><th class="num">Public key</th><th class="num">Signature</th></tr></thead><tbody>' + sigRows + '</tbody></table></div>' +
    '<p class="faint small" style="margin-top:8px;">For comparison, RSA-2048 signatures are 256 bytes and Ed25519 signatures are 64 bytes.</p></div></div>';
}

/* ----------------------------- export ----------------------------- */
function planToMarkdown(systems, plan) {
  const out = ['# PQC migration plan', '',
    'Scan: ' + (state.runId || 'n/a') + '. Security level: ' + plan.profile.label + ' (' + plan.profile.kem + ', ' + plan.profile.sig + '). Exported ' + new Date().toISOString().slice(0, 10) + '.', ''];
  systems.forEach(s => {
    out.push('## #' + s.priority_rank + ' ' + s.asset_id, '',
      'Start: week ' + s.scheduled_week + (s.compliance_deadline ? '. Deadline: ' + s.compliance_deadline : '') + '. Effort: ' + s.effort_weeks + ' eng-weeks. Progress: ' + s.progress.done + '/' + s.progress.total + '.', '');
    if (s.changes.length) {
      out.push('### What to change', '');
      s.changes.forEach(c => out.push('- **' + c.name + '** (' + c.relevance_label + '): ' + c.swap + '. ' + c.plain));
      out.push('');
    }
    out.push('### Plan', '');
    s.steps.forEach(st => out.push('- [' + (st.done ? 'x' : ' ') + '] **' + st.title + '** (' + st.phase_label + '). ' + st.detail));
    out.push('', '### Verify', '');
    s.verify.forEach(v => { out.push('- ' + v.label + '. Expected: ' + v.expect); if (v.command) out.push('  ```', '  ' + v.command, '  ```'); });
    out.push('');
  });
  return out.join('\n');
}
function exportSolutionsMarkdown(system) {
  if (!state.plan) return;
  const systems = system ? state.plan.systems.filter(s => s.asset_id === system) : state.plan.systems;
  const name = 'cadence-pqc-plan' + (system ? '-' + system.toLowerCase().replace(/[^a-z0-9]+/g, '-') : '') + (state.runId ? '-' + state.runId : '') + '.md';
  downloadFile(name, planToMarkdown(systems, state.plan), 'text/markdown;charset=utf-8');
  toast('ok', 'Plan exported as Markdown.');
}
