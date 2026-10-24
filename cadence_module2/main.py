"""
main.py — CADENCE Module 2 entry point: "Dependency Graph Builder + Dependency Analyzer"

Run this file to execute the full Module 2 pipeline:

    Module 1
       |
    vulnerabilities.json
       |
    Module 2  <-- you are here
       |
    Dependency Graph (NetworkX)
       |
    Centrality Analysis (degree centrality, in/out-degree, PageRank, criticality)
       |
    dependency_graph.json + centrality_scores.json + dependency_graph.html
       |
    Module 3

Usage:
    python main.py
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

import networkx as nx

from graph_builder import build_dependency_graph
from centrality_analyzer import analyze

DEPENDENCY_GRAPH_JSON = "dependency_graph.json"
CENTRALITY_SCORES_JSON = "centrality_scores.json"
DEPENDENCY_GRAPH_HTML = "dependency_graph.html"


def export_dependency_graph_json(graph: nx.DiGraph, analysis: dict, path: str) -> None:
    """
    Save the graph structure (nodes + edges + each node's stats) as JSON,
    so Module 3 can load it without needing NetworkX at all.
    """
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
            "architecture": {
            "name": graph.graph.get("architecture_name"),
            "is_template": bool(graph.graph.get("architecture_is_template", False)),
            "description": graph.graph.get("architecture_description", ""),
        },
        "scan_only": bool(graph.graph.get("scan_only", False)),
        "nodes": [
            {"id": node, **analysis[node],
             "context_only": bool(graph.nodes[node].get("context_only", False)),
             "system_type": graph.nodes[node].get("system_type", "component"),
             "architecture_defined": bool(graph.nodes[node].get("architecture_defined", False))}
            for node in graph.nodes()
        ],
        "edges": [
            {"source": source, "target": target,
             "relationships": graph.get_edge_data(source, target).get("relationships", [])}
            for source, target in graph.edges()
        ],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Wrote {path}")


def export_centrality_scores_json(analysis: dict, path: str) -> None:
    """
    Save just the analysis numbers (centrality/pagerank/criticality) per
    system, keyed by system name — the file Module 3 will mainly care about.
    """
    with open(path, "w") as f:
        json.dump(analysis, f, indent=2)
    print(f"[+] Wrote {path}")


def print_summary_table(analysis: dict) -> None:
    """Print a quick, readable summary table to the console using pandas."""
    import pandas as pd

    df = pd.DataFrame.from_dict(analysis, orient="index")
    df.index.name = "system"
    df = df.sort_values("pagerank", ascending=False)
    print("\n=== Dependency Analysis Summary ===")
    print(df.to_string())

    counts = df["criticality"].value_counts()
    print("\n=== Criticality Breakdown ===")
    for level in ["HIGH", "MEDIUM", "LOW"]:
        print(f"{level}: {counts.get(level, 0)} system(s)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the enterprise system dependency graph")
    parser.add_argument("--architecture", default=None,
                        help="Path to the verified enterprise-architecture JSON (defaults to enterprise_architecture.json)")
    parser.add_argument("--source-root", default=None,
                        help="Local scan root used to match configured relative source-file ownership paths")
    parser.add_argument("--scan-only", action="store_true",
                        help="Include only systems and relationships present in this scan snapshot")
    parser.add_argument("--skip-html", action="store_true",
                        help="Skip the standalone PyVis export (the web dashboard renders the JSON graph itself)")
    parser.add_argument("--quiet-summary", action="store_true",
                        help="Skip the console-only summary table (useful when run by the web dashboard)")
    args = parser.parse_args()
    print("=== CADENCE Enterprise Dependency Map ===\n")

    print("[Step 1/4] Loading scan findings and building the enterprise dependency map...")
    graph = build_dependency_graph(source_root=args.source_root, architecture_path=args.architecture,
                                   scan_only=args.scan_only)

    print("\n[Step 2/4] Calculating centrality metrics and criticality...")
    analysis = analyze(graph)

    print("\n[Step 3/4] Exporting dependency data for migration planning...")
    export_dependency_graph_json(graph, analysis, DEPENDENCY_GRAPH_JSON)
    export_centrality_scores_json(analysis, CENTRALITY_SCORES_JSON)

    if args.skip_html:
        print("\n[Step 4/4] Skipping standalone HTML graph export.")
    else:
        from visualize import build_html_graph
        print("\n[Step 4/4] Building interactive PyVis graph...")
        build_html_graph(graph, analysis, DEPENDENCY_GRAPH_HTML)

    if not args.quiet_summary:
        print_summary_table(analysis)

    if not args.skip_html:
        print("\nDone. Open dependency_graph.html in a browser to explore the graph.")
    else:
        print("\nDone.")


if __name__ == "__main__":
    main()
