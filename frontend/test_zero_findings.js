#!/usr/bin/env node
/* Zero-finding UI regression test; no third-party DOM package required. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class ElementStub {
  constructor(id = '') {
    this.id = id;
    this.innerHTML = '';
    this.textContent = '';
    this.value = '';
    this.className = '';
    this.disabled = false;
    this.dataset = {};
    this.hidden = false;
    this.inert = false;
    this.style = { display: '' };
    this.listeners = {};
    this.attributes = {};
    this.classList = { add() {}, remove() {}, toggle() {} };
  }
  addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
  dispatch(type, event = {}) {
    for (const handler of this.listeners[type] || []) handler(Object.assign({ target: this }, event));
  }
  querySelectorAll() { return []; }
  querySelector(selector) { return selector === '#mapSide' ? elements.get('mapSide') : null; }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }
  focus() { this.focused = true; }
  appendChild() {}
  remove() {}
  click() {}
}

const elements = new Map();
const documentListeners = {};
const pendingTimers = [];
const getElement = id => {
  if (!elements.has(id)) elements.set(id, new ElementStub(id));
  return elements.get(id);
};
const documentStub = {
  getElementById: getElement,
  querySelectorAll: () => [],
  addEventListener: (type, handler) => { (documentListeners[type] ||= []).push(handler); },
  createElement: tag => new ElementStub(tag),
  body: new ElementStub('body'),
  documentElement: new ElementStub('html'),
  title: '',
};
const context = {
  console,
  document: documentStub,
  pendingTimers,
  documentListeners,
  window: { matchMedia: () => ({ matches: false }), scrollTo() {}, addEventListener() {} },
  location: { hash: '' },
  history: { replaceState() {} },
  localStorage: { getItem: () => null, setItem() {} },
  sessionStorage: { getItem: () => '', setItem() {} },
  fetch: async url => ({
    status: 200,
    ok: true,
    json: async () => url === '/api/health' ? { auth_required: false } : [],
  }),
  setTimeout: (fn, delay) => { pendingTimers.push({ fn, delay }); return pendingTimers.length; },
  clearTimeout() {},
  URL,
  Blob,
  MouseEvent: function MouseEvent() {},
};
context.globalThis = context;

const source = ['solutions.js', 'migrate.js', 'app.js']
  .map(file => fs.readFileSync(path.join(__dirname, file), 'utf8'))
  .join('\n');
const testHook = `
globalThis.__formatMoney = money;
globalThis.__normalizeLegacyPlan = normalizeMigrationCurrency;
globalThis.__clearPriorScanFixture = () => {
  state.findings = [{ algorithm: 'MD5', kind: 'algorithm', file: 'old.py', severity: 'high' }];
  state.graph = { nodes: [{ id: 'Older Scan Service' }], edges: [] };
  state.migration = { migration_order: [{ asset_id: 'Older Scan Service' }] };
  state.plan = { systems: [{ asset_id: 'Older Scan Service' }] };
  state.runId = 'older-run'; state.runTime = '2026-01-01T00:00:00Z';
  clearDisplayedRun();
  return {
    findings: state.findings, graph: state.graph, migration: state.migration,
    plan: state.plan, runId: state.runId,
    html: ['view-overview', 'view-findings', 'view-graph', 'view-roadmap', 'view-solutions']
      .map(id => $(id).innerHTML).join(' | '),
  };
};
globalThis.__renderZeroFindingsFixture = async () => {
  await loadRunIntoState({
    id: 'zero-run', started_at: '2026-01-01T00:00:00Z',
    vulnerabilities_json: '[]',
    cbom_json: JSON.stringify({ components: [{ type: 'cryptographic-asset', name: 'MD5' }] }),
    dependency_graph_json: JSON.stringify({
      nodes: [{ id: 'API Gateway', criticality: 'LOW', in_degree: 0,
        out_degree: 0, pagerank: 0, vulnerability_count: 0 }],
      edges: [], architecture: { is_template: true }
    }),
    migration_ranking_json: JSON.stringify({ migration_order: [{
      asset_id: 'API Gateway', priority_rank: 1, scheduled_week: 1,
      reasoning: 'fixture recommendation', algorithms: [], worst_severity: 'low',
      effort_weeks: 1, estimated_cost: 100, compliance_deadline: null, days_remaining: null
    }] }),
  });
  return {
    findings: state.findings.length, plan: state.plan,
    overview: $('view-overview').innerHTML,
    roadmap: $('view-roadmap').innerHTML,
    solutions: $('view-solutions').innerHTML,
    graph: $('view-graph').innerHTML,
  };
};
globalThis.__renderPositiveFindingsFixture = () => {
  state.findings = [{ algorithm: 'MD5', kind: 'algorithm', file: 'auth.py', severity: 'high' }];
  renderOverview();
  renderRoadmap();
  return { overview: $('view-overview').innerHTML, roadmap: $('view-roadmap').innerHTML };
};
globalThis.__triggerWelcome = (mode) => {
  const screen = $('welcomeScreen'), shell = $('appShell');
  screen.hidden = false; shell.hidden = true; shell.inert = true;
  dashboardOpening = false; lastWelcomeTap = 0; welcomeTouchStart = null;
  const touch = (x, y) => {
    const target = { closest: () => null };
    screen.dispatch('pointerdown', { pointerType: 'touch', clientX: x, clientY: y });
    screen.dispatch('pointerup', { pointerType: 'touch', clientX: x, clientY: y, target });
  };
  if (mode === 'button') $('welcomeEnter').dispatch('click');
  else if (mode === 'swipe') { touch(40, 220); touch(40, 120); }
  else if (mode === 'double-tap') { touch(40, 220); touch(42, 218); }
  else if (mode === 'keyboard') {
    for (const handler of documentListeners.keydown || []) handler({
      target: { closest: () => null }, key: 'Enter', preventDefault() {},
    });
  }
  for (const timer of pendingTimers.splice(0)) timer.fn();
  return { welcomeHidden: screen.hidden, shellHidden: shell.hidden, shellInert: shell.inert };
};
`;

async function main() {
  vm.runInNewContext(source + testHook, context, { filename: 'cadence-ui-zero-findings.js' });
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.match(context.__formatMoney(123456), /₹/);
  assert.match(context.__formatMoney(123456), /1,23,456/);
  const legacyPlan = context.__normalizeLegacyPlan({
    constraints_used: { total_budget: 80000 },
    migration_order: [{ estimated_cost: 4000, reasoning: 'The dependency analysis independently flagged it as HIGH criticality' }],
  });
  assert.equal(legacyPlan.constraints_used.total_budget, 7744000);
  assert.equal(legacyPlan.migration_order[0].estimated_cost, 387200);
  assert.equal(legacyPlan.constraints_used.currency, 'INR');
  assert.doesNotMatch(legacyPlan.migration_order[0].reasoning, /Module 2/i);
  const result = await context.__renderZeroFindingsFixture();
  assert.equal(result.findings, 0, 'vulnerabilities.json is the canonical finding source');
  assert.equal(result.plan, null, 'do not build a remediation plan for an empty findings list');
  assert.match(result.overview, /no weak cryptography/i);
  assert.doesNotMatch(result.overview, /Migration schedule|REPOSITORY MIGRATION/);
  assert.match(result.roadmap, /No remediation roadmap for this scan/);
  assert.doesNotMatch(result.roadmap, /API Gateway/);
  assert.match(result.solutions, /No remediation items for this scan/);
  assert.match(result.graph, /API Gateway/);
  assert.match(result.graph, /No remediation recommendations/);
  assert.doesNotMatch(result.graph, /Rank 1, week 1/);
  const positive = context.__renderPositiveFindingsFixture();
  assert.match(positive.overview, /Migration schedule/);
  assert.match(positive.roadmap, /API Gateway/);
  assert.match(positive.roadmap, /Export CSV/);
  const cleared = context.__clearPriorScanFixture();
  assert.equal(cleared.findings.length, 0, 'new scan should clear old findings');
  assert.equal(cleared.graph, null, 'new scan should clear old dependency graph');
  assert.equal(cleared.migration, null, 'new scan should clear old roadmap');
  assert.equal(cleared.plan, null, 'new scan should clear old solutions');
  assert.equal(cleared.runId, null, 'new scan should not continue presenting the older run as current');
  assert.doesNotMatch(cleared.html, /Older Scan Service|old\.py/);
  for (const method of ['button', 'swipe', 'double-tap', 'keyboard']) {
    const opened = context.__triggerWelcome(method);
    assert.equal(opened.welcomeHidden, true, 'welcome screen should hide via ' + method);
    assert.equal(opened.shellHidden, false, 'dashboard should be visible via ' + method);
    assert.equal(opened.shellInert, false, 'dashboard should be interactive via ' + method);
  }
  console.log('PASS: zero-findings states and accessible welcome-screen entry methods.');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
