"""
centrality_analyzer.py — CADENCE Module 2, step 2: analyze the graph.

Pipeline position:

    graph --> [centrality_analyzer.py] --> centrality_scores.json

What this file does:
  1. Calculates, for every system in the graph:
       - Degree centrality  (how connected the system is overall)
       - In-degree          (how many systems depend ON it)
       - Out-degree         (how many systems it depends on)
       - PageRank           (importance, weighted by IMPORTANT
                             systems depending on it, not just any system)
  2. Combines those scores with Module 1's vulnerability data to label
     each system HIGH / MEDIUM / LOW criticality.
"""

from __future__ import annotations

import networkx as nx


def calculate_centrality(graph: nx.DiGraph) -> dict:
    """
    Calculate all four centrality metrics for every node.
    Returns: { system_name: {"degree_centrality": ..., "in_degree": ...,
                              "out_degree": ..., "pagerank": ...} }
    """
    degree_centrality = nx.degree_centrality(graph)
    pagerank = nx.pagerank(graph)

    scores = {}
    for node in graph.nodes():
        scores[node] = {
            "degree_centrality": round(degree_centrality[node], 4),
            "in_degree": graph.in_degree(node),
            "out_degree": graph.out_degree(node),
            "pagerank": round(pagerank[node], 4),
        }
    return scores


def _vulnerability_score(graph: nx.DiGraph, node: str) -> float:
    """
    Turn a system's vulnerability data into a single 0-1+ risk number.
    High-severity findings count the most, medium a bit, low a little.
    """
    data = graph.nodes[node]
    return (
        data.get("high_severity", 0) * 1.0
        + data.get("medium_severity", 0) * 0.5
        + data.get("low_severity", 0) * 0.2
    )


def classify_criticality(graph: nx.DiGraph, centrality_scores: dict) -> dict:
    """
    Label every system HIGH, MEDIUM, or LOW criticality by combining:
      - how central/depended-on it is in the graph (in_degree + pagerank)
      - how many known vulnerabilities it has (from Module 1)

    Method (kept simple on purpose):
      1. Build one combined "importance score" per system:
           importance = normalized(in_degree) + normalized(pagerank) + normalized(vuln_score)
      2. Rank all systems by that score.
      3. Split them into thirds: top third = HIGH, middle third = MEDIUM,
         bottom third = LOW.

    Returns: { system_name: "HIGH" | "MEDIUM" | "LOW" }
    """
    in_degrees = {n: centrality_scores[n]["in_degree"] for n in graph.nodes()}
    pageranks = {n: centrality_scores[n]["pagerank"] for n in graph.nodes()}
    vuln_scores = {n: _vulnerability_score(graph, n) for n in graph.nodes()}

    def normalize(d: dict) -> dict:
        max_val = max(d.values()) or 1  # avoid divide-by-zero
        return {k: v / max_val for k, v in d.items()}

    norm_in_degree = normalize(in_degrees)
    norm_pagerank = normalize(pageranks)
    norm_vuln = normalize(vuln_scores)

    importance = {
        n: norm_in_degree[n] + norm_pagerank[n] + norm_vuln[n]
        for n in graph.nodes()
    }

    # Rank highest importance first.
    ranked = sorted(importance.items(), key=lambda item: item[1], reverse=True)
    total = len(ranked)
    high_cutoff = max(1, round(total / 3))
    medium_cutoff = max(high_cutoff + 1, round(2 * total / 3))

    criticality = {}
    for i, (system, _score) in enumerate(ranked):
        if i < high_cutoff:
            criticality[system] = "HIGH"
        elif i < medium_cutoff:
            criticality[system] = "MEDIUM"
        else:
            criticality[system] = "LOW"

    return criticality


def analyze(graph: nx.DiGraph) -> dict:
    """
    Run the full analysis and return one combined dict per system:
      { system_name: {degree_centrality, in_degree, out_degree,
                       pagerank, criticality, vulnerability_count} }
    """
    centrality_scores = calculate_centrality(graph)
    criticality = classify_criticality(graph, centrality_scores)

    combined = {}
    for node in graph.nodes():
        combined[node] = {
            **centrality_scores[node],
            "criticality": criticality[node],
            "vulnerability_count": graph.nodes[node].get("vulnerability_count", 0),
        }
    return combined


if __name__ == "__main__":
    from graph_builder import build_dependency_graph

    g = build_dependency_graph()
    results = analyze(g)
    for system, data in sorted(results.items(), key=lambda kv: -kv[1]["pagerank"]):
        print(f"{data['criticality']:6} | {system:35} | pagerank={data['pagerank']}")
