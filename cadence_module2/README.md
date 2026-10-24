# CADENCE Module 2 — Enterprise Dependency Graph

Module 2 loads `enterprise_architecture.json`, builds the directed system graph, rolls current Module 1 findings into their owning systems, calculates centrality, and exports the graph for Module 3. An edge `A -> B` means **system A depends on system B**.

## Architecture source of truth

`enterprise_architecture.json` contains:

- `systems`: enterprise system IDs and categories (application, service, database, network, platform, etc.).
- `dependencies`: directed service-to-service or service-to-platform relationships.
- `file_to_system`: exact source file paths mapped to their owning enterprise system; basename-only ownership is not used.
- `is_template`: indicates whether the configured topology is still the illustrative CADENCE reference map.

The included map restores the original 16-system / 22-link reference topology. It is an editable template, not evidence about a user's actual organization. Replace its names, relationships, categories, and source ownership mappings with the organization's CMDB, service catalog, or approved architecture before treating the resulting impact analysis or schedule as production truth. The application keeps template provenance visible in the graph explanation. The bundled template has no active file ownership mappings.

Mappings in an operator-defined architecture (`is_template: false`) use exact full paths or exact configured relative paths only. Basename-only fallback is deliberately disabled: a same-named file in another repository or scan must not inherit an old service mapping. Template mappings are never used to assign findings. If a file cannot be mapped, CADENCE keeps it as a separate scan component rather than attributing its findings to the wrong system. Operators can set `system`, `service`, or `component` on the current Module 1 finding to provide an authoritative ownership override.

## Enterprise-wide roadmap

The graph retains configured systems and links as architecture context, but the roadmap and solutions are generated from the current scan only. Every current-run finding is mapped to its configured owner or retained as its own scan component, and each affected mapped entity receives a roadmap row and matching solution plan. The exact file map, graph, findings, roadmap, and solution lookup are stored against the same run; results from other scan sessions are not merged. The roadmap ranks current-scan risk alongside dependency impact, configured compliance deadlines, effort/cost assumptions, and team capacity.

Edges are from the architecture configuration or explicit dependency metadata in scan findings; Module 1 does **not** discover service-to-service topology automatically. Do not treat source-code imports as enterprise dependencies.

## Files and use

| File | Purpose |
|---|---|
| `enterprise_architecture.json` | Editable system inventory, service links, and file ownership map |
| `main.py` | Runs graph generation, centrality analysis, and exports |
| `graph_builder.py` | Validates topology and maps scan findings into enterprise nodes |
| `centrality_analyzer.py` | Calculates dependency centrality and criticality |
| `visualize.py` | Builds a standalone interactive graph HTML |
| `test_graph_builder.py` | Architecture, ownership, validation, and graph regression tests |

```bash
pip install -r requirements.txt
python main.py --architecture enterprise_architecture.json --source-root /path/to/repository
python test_graph_builder.py
```

The web runner supplies the project-local architecture file on every scan. Module 2 regenerates `current_system_file_map.json` each run so Module 3 scores findings against the same current graph.
