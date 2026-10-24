"""
visualize.py — CADENCE Module 2, step 3: build the interactive HTML graph.

Pipeline position:

    graph + analysis --> [visualize.py] --> dependency_graph.html

Uses PyVis to draw the dependency graph so you can open it in a browser,
drag nodes around, hover for details, and zoom in/out.

Color = criticality (red/orange/green). Size = how central the system is.
"""

from __future__ import annotations

import networkx as nx
from pyvis.network import Network

CRITICALITY_COLOR = {
    "HIGH": "#e74c3c",    # red
    "MEDIUM": "#f39c12",  # orange
    "LOW": "#2ecc71",     # green
}


def build_html_graph(
    graph: nx.DiGraph,
    analysis: dict,
    output_path: str = "dependency_graph.html",
) -> None:
    """Render the dependency graph as an interactive HTML file."""
    net = Network(
        height="800px",
        width="100%",
        directed=True,
        notebook=False,
        bgcolor="#1e1e1e",
        font_color="white",
    )

    for node in graph.nodes():
        data = analysis[node]
        criticality = data["criticality"]

        # Bigger node = more central/depended-on system.
        size = 15 + data["degree_centrality"] * 60

        tooltip = (
            f"{node}\n"
            f"Criticality: {criticality}\n"
            f"In-degree: {data['in_degree']} (systems depending on this)\n"
            f"Out-degree: {data['out_degree']} (systems this depends on)\n"
            f"Degree centrality: {data['degree_centrality']}\n"
            f"PageRank: {data['pagerank']}\n"
            f"Known vulnerabilities: {data['vulnerability_count']}"
        )

        net.add_node(
            node,
            label=node,
            title=tooltip,
            color=CRITICALITY_COLOR.get(criticality, "#95a5a6"),
            size=size,
        )

    for source, target in graph.edges():
        net.add_edge(source, target, arrows="to")

    net.set_options("""
    var options = {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -60,
          "springLength": 150
        },
        "solver": "forceAtlas2Based"
      }
    }
    """)

    net.write_html(output_path)
    print(f"[+] Wrote interactive graph: {output_path}")
