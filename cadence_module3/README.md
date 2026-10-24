# CADENCE Module 3 — Deciding the Migration Order

**Owner:** Member C ("The Brain")

```
Module 1 (scanner)        -> cbom.json / vulnerabilities.json
Module 2 (dependency map) -> dependency_graph.json
Module 3   <-- this project
Module 4 (roadmap & testing)
```

## What this does

Module 1 finds weak cryptography, file by file. Module 2 turns that
into a system-level dependency graph and already computes how
*connected* every system is (degree centrality, in-degree, PageRank)
plus its own blended HIGH/MEDIUM/LOW "criticality" label. Neither one
answers the real question: **given a limited team, a limited budget,
and real compliance deadlines, what order should we actually migrate
systems in — and why?**

Module 3:
1. **Scores** the configured enterprise systems on four factors — risk,
   dependency impact, cost, and compliance urgency — using the current run's
   findings and the full graph's centrality.
2. **Schedules** only systems with findings from this run into actual weeks using a genuine
   linear program (PuLP) that respects team capacity, budget, and
   dependency order — with a safe greedy fallback if no feasible plan
   exists.
3. **Explains** every ranking in a plain-English sentence.
4. **Exports** `migration_ranking.json` for Module 4. Clean systems remain
   in the graph as context and are not given placeholder remediation tasks.

## A hand-off gap this fills (read this first)

Module 2 exports the configured enterprise graph, current scan severity
findings, and a freshly generated **`system_file_map.json`** mapping exact
Module 1 source paths to their owning enterprise systems. Ownership comes from
`cadence_module2/enterprise_architecture.json` (or explicit system metadata
in a finding). The web runner passes this map to Module 3 so the complete
configured enterprise topology informs centrality and dependency impact, while
only the systems affected in this scan are included in the schedule. A later
scan gets a new plan from its own findings; old scan rows are not appended.
The checked-in map and graph JSON remain regression fixtures.

Module 3 uses exact paths from the current run's map only; basename fallback is
disabled so a later scan cannot inherit an older scan's ownership. If a finding
has no system mapping, Module 2 retains it as a separate graph
component and Module 3 uses that exact component rather than silently
assigning the finding to an unrelated enterprise service. Replace the
included reference topology and filename examples with verified enterprise
data before using the scores operationally.

## Files

| File | What it is |
|---|---|
| `module3_decision_engine.py` | The whole engine. |
| `constraints.json` | Business constraints you edit: team size, budget, deadlines, weights. |
| `system_file_map.json` | File→system rollup map (see above). |
| `test_module3.py` | Automated sanity tests — run before your demo. |
| `requirements.txt` | Python packages needed. |

## How to run it

```bash
pip install -r requirements.txt

python3 module3_decision_engine.py \
    --cbom ../cadence_module1/cbom.json \
    --vulnerabilities ../cadence_module1/vulnerabilities.json \
    --graph ../cadence_module2/dependency_graph.json \
    --system-map system_file_map.json \
    --config constraints.json \
    --out migration_ranking.json
```

Those are all the defaults, so from inside `cadence_module3/` (with
Module 1 and 2 already run once) you can just run:

```bash
python3 module3_decision_engine.py
```

`--cbom` is preferred (it carries the CycloneDX-standard cryptographic
"primitive" per algorithm — hash / cipher / protocol / signature —
which gives a better effort estimate than guessing from the algorithm
name). If it's missing, Module 3 automatically falls back to
`--vulnerabilities`.

Run the tests any time you change something:
```bash
python3 test_module3.py
```

Skip the optimizer (or if PuLP isn't installed) with `--no-optimize` —
you still get a full, valid schedule, just via simple greedy
scheduling instead of linear programming.

## Editing `constraints.json`

The checked-in configuration contains no sample compliance deadlines. Add
only deadlines confirmed by your organization; the reference date defaults to
the current date. Budget and cost values use INR. The following deadline is an
illustrative example only.

```json
{
  "team_size": 4,
  "planning_horizon_weeks": 10,
  "currency": "INR",
  "total_budget": 7744000,
  "weights": { "risk": 0.4, "dependency": 0.3, "compliance": 0.2, "cost": 0.1 },
  "compliance_deadlines": { "Legacy Auth Service": "2026-11-30" },
  "enforce_dependency_precedence": true
}
```

`compliance_deadlines` keys must exactly match a node `id` in
`dependency_graph.json` (i.e. a system name like `"API Gateway"`, not
a file name).

## How the score is calculated

```
score = 0.4 × risk_norm + 0.3 × dependency_norm + 0.2 × compliance_norm − 0.1 × cost_norm
```

All four are normalized to 0–1 (min–max across the current systems)
before weighting. **Dependency impact reuses Module 2's own PageRank**
for each system rather than recomputing centrality from scratch —
Module 2 already did that work well; Module 3 just weighs it against
the other three business factors Module 2 doesn't know about.

## How the schedule is calculated

A real constraint-satisfaction model, solved with **PuLP** (CBC
solver):

- **Decision variable:** `x[system, week] = 1` if migrated that week.
- **Objective:** minimize `Σ (score × week)` — pulls high-priority systems earlier.
- **Constraints:**
  - every system included in this run's roadmap is scheduled exactly once
  - **cumulative** team capacity: by the end of week *w*, the team has
    done at most `team_size × w` engineer-weeks of work in total. This
    is what lets one very large system (e.g. Legacy Auth Service's 8
    engineer-weeks of findings) still get scheduled sensibly instead
    of the whole model going infeasible just because that one system's
    effort exceeds a single week's headcount — it just delays how
    early anything smaller can finish.
  - total cost across the whole plan ≤ `total_budget`
  - (optional) if system A depends on system B, B is migrated no later than A

If no feasible schedule exists at all (e.g. the budget genuinely can't
cover anything), the engine warns clearly and falls back to greedy
scheduling rather than crashing.

## Handing off to Module 4

`migration_ranking.json` contains, per system: rank, score, score
breakdown, risk/finding details (including the specific weak
algorithms found), Module 2's own criticality label (for
cross-reference), effort/cost estimate, compliance deadline, scheduled
week, and a plain-English reasoning sentence.
