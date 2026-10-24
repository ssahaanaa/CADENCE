"""Build a service/component dependency graph from enterprise architecture data.

The architecture configuration is the authority for system names, source-file
ownership, and service-to-service edges. A cryptography scan adds findings to
that graph; it cannot infer enterprise topology from source imports.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path, PurePosixPath, PureWindowsPath
import networkx as nx

HERE = Path(__file__).resolve().parent
MODULE1_VULN_PATH = HERE.parent / "cadence_module1" / "vulnerabilities.json"
ARCHITECTURE_PATH = HERE / "enterprise_architecture.json"
SYSTEM_MAP_OUTPUT = HERE / "current_system_file_map.json"


def load_vulnerabilities(path: str | Path = MODULE1_VULN_PATH) -> list[dict]:
    """Read Module 1 findings. A missing file is an empty scan."""
    path = Path(path)
    if not path.exists():
        print(f"[!] Could not find {path} — continuing with no vulnerability data.")
        return []
    with path.open(encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, list):
        raise ValueError("vulnerabilities.json must contain a JSON list")
    return data


def _load_architecture(path: str | Path | None = None) -> dict:
    config_path = Path(path) if path else ARCHITECTURE_PATH
    data = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Enterprise architecture must be a JSON object")
    systems = data.get("systems")
    dependencies = data.get("dependencies", [])
    file_map = data.get("file_to_system", {})
    if not isinstance(systems, list) or not systems:
        raise ValueError("Enterprise architecture must declare at least one system")
    if not isinstance(dependencies, list) or not isinstance(file_map, dict):
        raise ValueError("Enterprise architecture dependencies/file_to_system have invalid types")
    names = []
    types = {}
    for item in systems:
        if isinstance(item, str):
            name, kind = item.strip(), "component"
        elif isinstance(item, dict):
            name = str(item.get("id") or "").strip()
            kind = str(item.get("type") or "component").strip()
        else:
            raise ValueError("Each enterprise system must be a name or an object with id/type")
        if not name or name in types:
            raise ValueError(f"Enterprise system names must be non-empty and unique: {name!r}")
        names.append(name)
        types[name] = kind
    checked_edges = []
    for edge in dependencies:
        if not isinstance(edge, dict):
            raise ValueError("Each dependency must contain source and target")
        source, target = str(edge.get("source") or "").strip(), str(edge.get("target") or "").strip()
        if source not in types or target not in types or source == target:
            raise ValueError(f"Dependency references an unknown or identical system: {source!r} -> {target!r}")
        checked_edges.append((source, target))
    for file_key, system in file_map.items():
        if (not isinstance(file_key, str) or not file_key.strip()
                or not isinstance(system, str) or system not in types):
            raise ValueError(f"Invalid file_to_system mapping: {file_key!r} -> {system!r}")
    return {**data, "systems": names, "system_types": types,
            "dependencies": checked_edges, "file_to_system": file_map}


def has_dependency_info(vulnerabilities: list[dict]) -> bool:
    return any("depends_on" in item or "system_dependencies" in item for item in vulnerabilities)


def _display_file(raw_file: str, source_root: str | Path | None = None) -> str:
    if not raw_file:
        return "Unlocated scan finding"
    normalized = raw_file.replace("\\", "/")
    if source_root:
        root = Path(source_root).resolve()
        path = Path(raw_file).expanduser()
        if not path.is_absolute():
            candidate = (root / path).resolve()
        else:
            candidate = path.resolve()
        try:
            return candidate.relative_to(root).as_posix()
        except ValueError:
            pass
    if PureWindowsPath(normalized).is_absolute():
        parts = PureWindowsPath(normalized).parts
        return "/".join(parts[-2:]) if len(parts) > 2 else PureWindowsPath(normalized).name
    pure = PurePosixPath(normalized)
    if pure.is_absolute():
        parts = pure.parts[1:]
        return "/".join(parts[-2:]) if len(parts) > 2 else pure.name
    return normalized.removeprefix("./") or "Unlocated scan finding"


def _configured_system(raw_file: str, architecture: dict, source_root: str | Path | None = None) -> str | None:
    # The bundled 16-system topology is illustrative, not authoritative. Its
    # sample file names must never claim ownership of an unrelated repository.
    # Operators opt into file ownership only after replacing the template and
    # setting is_template=false in their verified architecture file.
    if architecture.get("is_template", False):
        return None
    mapping = architecture["file_to_system"]
    raw = raw_file.replace("\\", "/").casefold()
    raw = raw[2:] if raw.startswith("./") else raw
    if source_root:
        display = _display_file(raw_file, source_root).casefold()
        for key, system in mapping.items():
            normalized = key.replace("\\", "/").casefold()
            normalized = normalized[2:] if normalized.startswith("./") else normalized
            if "/" in normalized and normalized == display:
                return system
    for key, system in mapping.items():
        normalized = key.replace("\\", "/").casefold()
        normalized = normalized[2:] if normalized.startswith("./") else normalized
        if normalized == raw:
            return system
    # Basename-only ownership can leak a stale mapping onto a same-named file
    # in another repository or directory. Unmatched findings remain scan-local
    # components unless the current finding carries an explicit system override.
    return None


def _node_for_finding(finding: dict, architecture: dict,
                      source_root: str | Path | None = None) -> str:
    explicit = finding.get("system") or finding.get("service") or finding.get("component")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    raw = str(finding.get("file") or "").strip()
    mapped = _configured_system(raw, architecture, source_root)
    return mapped or _display_file(raw, source_root)


def _as_dependency_list(value) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _add_relation(graph: nx.DiGraph, source: str, target: str, relation: str) -> None:
    if source == target:
        return
    if graph.has_edge(source, target):
        relationships = set(graph[source][target].get("relationships", []))
        relationships.add(relation)
        graph[source][target]["relationships"] = sorted(relationships)
    else:
        graph.add_edge(source, target, relationships=[relation])


def summarize_vulnerabilities_by_system(vulnerabilities: list[dict], architecture: dict | None = None,
                                        source_root: str | Path | None = None) -> dict[str, dict]:
    architecture = architecture or _load_architecture()
    summary: dict[str, dict] = defaultdict(lambda: {"count": 0, "high": 0, "medium": 0, "low": 0})
    for finding in vulnerabilities:
        row = summary[_node_for_finding(finding, architecture, source_root)]
        row["count"] += 1
        severity = str(finding.get("severity", "low")).lower()
        if severity in ("high", "medium", "low"):
            row[severity] += 1
        elif severity == "critical":
            row["high"] += 1
    return dict(summary)


def build_dependency_graph(vulnerabilities: list[dict] | None = None,
                           source_root: str | Path | None = None,
                           architecture_path: str | Path | None = None,
                           scan_only: bool = False) -> nx.DiGraph:
    """Build the configured enterprise graph, annotating it with current findings."""
    vulnerabilities = load_vulnerabilities() if vulnerabilities is None else vulnerabilities
    architecture = _load_architecture(architecture_path)
    summary = summarize_vulnerabilities_by_system(vulnerabilities, architecture, source_root)
    graph = nx.DiGraph()
    graph.graph.update({"architecture_name": architecture.get("name", "Enterprise architecture"),
                        "architecture_is_template": bool(architecture.get("is_template", False)),
                        "scan_only": scan_only,
                        "architecture_description": architecture.get("description", "")})
    # A scan map is a snapshot of this scan, not a second copy of the full
    # enterprise inventory. In scan-only mode, omit architecture systems that
    # have no current finding so an older scan's systems cannot appear here.
    active_systems = set(summary)
    for finding in vulnerabilities:
        explicit = finding.get("system") or finding.get("service") or finding.get("component")
        if isinstance(explicit, str) and explicit.strip():
            active_systems.add(explicit.strip())
    if scan_only:
        active_systems &= set(architecture["systems"]) | set(summary)
    else:
        active_systems = set(architecture["systems"]) | active_systems

    for system in architecture["systems"]:
        if system not in active_systems:
            continue
        counts = summary.pop(system, {"count": 0, "high": 0, "medium": 0, "low": 0})
        graph.add_node(system, vulnerability_count=counts["count"],
                       high_severity=counts["high"], medium_severity=counts["medium"],
                       low_severity=counts["low"], system_type=architecture["system_types"][system],
                       architecture_defined=True)
    # Unmapped files and explicitly named systems remain visible rather than
    # being falsely attributed to an enterprise service.
    for component, counts in summary.items():
        graph.add_node(component, vulnerability_count=counts["count"],
                       high_severity=counts["high"], medium_severity=counts["medium"],
                       low_severity=counts["low"], system_type="unmapped", architecture_defined=False)

    for source, target in architecture["dependencies"]:
        if not scan_only or (source in graph and target in graph):
            _add_relation(graph, source, target, "enterprise_architecture")

    file_map = {}
    for finding in vulnerabilities:
        raw = str(finding.get("file") or "").strip()
        system = _node_for_finding(finding, architecture, source_root)
        if raw:
            file_map[raw] = system
        dependencies = _as_dependency_list(finding.get("depends_on"))
        dependencies.extend(_as_dependency_list(finding.get("system_dependencies")))
        for target in dependencies:
            if target not in graph:
                graph.add_node(target, vulnerability_count=0, high_severity=0,
                               medium_severity=0, low_severity=0, system_type="unmapped",
                               architecture_defined=False)
            _add_relation(graph, system, target, "explicit_scan_metadata")

    SYSTEM_MAP_OUTPUT.write_text(json.dumps(file_map, indent=2) + "\n", encoding="utf-8")
    print(f"[*] Enterprise architecture '{architecture.get('name', 'Enterprise architecture')}': "
          f"{graph.number_of_nodes()} systems/components, {graph.number_of_edges()} declared relationships; "
          f"{len(vulnerabilities)} scan findings mapped.")
    if architecture.get("is_template"):
        print("[!] This is the included reference topology. Replace its systems, file mappings, and links with your verified enterprise architecture.")
    return graph


if __name__ == "__main__":
    graph = build_dependency_graph()
    print(f"Graph built: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} relationships")
