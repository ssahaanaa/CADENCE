#!/usr/bin/env python3
"""Enterprise graph regressions: python test_graph_builder.py"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import graph_builder as G


class GraphBuilderTests(unittest.TestCase):

    def test_scan_only_graph_excludes_unseen_architecture_systems(self):
        config = self.root / "architecture.json"
        config.write_text(json.dumps({
            "name": "test architecture",
            "is_template": False,
            "systems": [{"id": "Current Service", "type": "service"},
                        {"id": "Older Service", "type": "service"}],
            "dependencies": [{"source": "Older Service", "target": "Current Service"}],
            "file_to_system": {"a.py": "Current Service", "old.py": "Older Service"},
        }))
        with patch.object(G, "SYSTEM_MAP_OUTPUT", self.map_path):
            graph = G.build_dependency_graph(
                vulnerabilities=[{"file": "a.py", "algorithm": "MD5", "severity": "high"}],
                architecture_path=config,
                scan_only=True,
            )
        self.assertTrue(graph.graph["scan_only"])
        self.assertIn("Current Service", graph.nodes)
        self.assertNotIn("Older Service", graph.nodes)
        self.assertEqual(list(graph.edges), [])
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.map_path = self.root / "system-map.json"

    def test_reference_enterprise_topology_and_vulnerability_ownership(self):
        findings = [
            {"file": r"C:\repo\legacy_auth.py", "algorithm": "MD5", "severity": "high"},
            {"file": r"C:\repo\legacy_auth.py", "algorithm": "DES", "severity": "medium"},
            {"file": "/repo/gateway.conf", "algorithm": "RC4", "severity": "critical"},
            {"file": "/repo/new_module/crypto.py", "algorithm": "SHA1", "severity": "low"},
        ]
        with patch.object(G, "SYSTEM_MAP_OUTPUT", self.map_path):
            graph = G.build_dependency_graph(findings)
        self.assertEqual(graph.number_of_nodes(), 19)
        self.assertEqual(graph.number_of_edges(), 22)
        self.assertIn(("Customer Portal (Web App)", "API Gateway"), graph.edges)
        self.assertIn(("Payment Service", "Payment Database"), graph.edges)
        self.assertEqual(graph.nodes["Legacy Auth Service"]["vulnerability_count"], 0)
        self.assertEqual(graph.nodes["API Gateway"]["high_severity"], 0)
        self.assertEqual(graph.nodes["repo/legacy_auth.py"]["vulnerability_count"], 2)
        self.assertIn("new_module/crypto.py", graph)
        self.assertEqual(json.loads(self.map_path.read_text()), {
            r"C:\repo\legacy_auth.py": "repo/legacy_auth.py",
            "/repo/gateway.conf": "gateway.conf",
            "/repo/new_module/crypto.py": "new_module/crypto.py",
        })

    def test_reference_template_never_uses_old_basename_ownership(self):
        source = self.root / "repo"
        (source / "auth").mkdir(parents=True)
        finding = source / "auth" / "legacy_auth.py"
        config = self.root / "template-with-old-map.json"
        config.write_text(json.dumps({
            "name": "Old reference", "is_template": True,
            "systems": ["Legacy Auth Service"], "dependencies": [],
            "file_to_system": {"legacy_auth.py": "Legacy Auth Service"},
        }), encoding="utf-8")
        with patch.object(G, "SYSTEM_MAP_OUTPUT", self.map_path):
            graph = G.build_dependency_graph(
                [{"file": str(finding), "algorithm": "MD5", "severity": "high"}],
                source_root=source, architecture_path=config,
            )
        self.assertEqual(graph.nodes["Legacy Auth Service"]["vulnerability_count"], 0)
        self.assertEqual(graph.nodes["auth/legacy_auth.py"]["vulnerability_count"], 1)

    def test_full_enterprise_plan_graph_exists_when_scan_has_no_findings(self):
        with patch.object(G, "SYSTEM_MAP_OUTPUT", self.map_path):
            graph = G.build_dependency_graph([])
        self.assertEqual(graph.number_of_nodes(), 16)
        self.assertEqual(graph.number_of_edges(), 22)
        self.assertEqual(graph.nodes["Payment Service"]["vulnerability_count"], 0)
        self.assertEqual(json.loads(self.map_path.read_text()), {})

    def test_explicit_scan_dependencies_are_added_to_enterprise_topology(self):
        findings = [{"file": "custom.py", "system": "Custom Integration",
                     "depends_on": ["API Gateway"]}]
        with patch.object(G, "SYSTEM_MAP_OUTPUT", self.map_path):
            graph = G.build_dependency_graph(findings)
        self.assertIn("Custom Integration", graph)
        self.assertIn(("Custom Integration", "API Gateway"), graph.edges)
        self.assertEqual(graph["Custom Integration"]["API Gateway"]["relationships"],
                         ["explicit_scan_metadata"])

    def test_operator_defined_architecture_maps_paths_and_links(self):
        source = self.root / "repo"
        (source / "src").mkdir(parents=True)
        finding_path = source / "src" / "crypto.py"
        finding_path.write_text("", encoding="utf-8")
        config = self.root / "architecture.json"
        config.write_text(json.dumps({
            "schema_version": "1.0", "name": "Acme production architecture", "is_template": False,
            "systems": [{"id": "Frontend", "type": "application"},
                        {"id": "Identity", "type": "service"}],
            "dependencies": [{"source": "Frontend", "target": "Identity"}],
            "file_to_system": {"src/crypto.py": "Identity"},
        }), encoding="utf-8")
        with patch.object(G, "SYSTEM_MAP_OUTPUT", self.map_path):
            graph = G.build_dependency_graph(
                [{"file": str(finding_path), "algorithm": "MD5", "severity": "high"}],
                source_root=source,
                architecture_path=config,
            )
        self.assertEqual(set(graph.nodes), {"Frontend", "Identity"})
        self.assertEqual(graph.nodes["Identity"]["vulnerability_count"], 1)
        self.assertEqual(graph.nodes["Identity"]["system_type"], "service")
        self.assertEqual(graph["Frontend"]["Identity"]["relationships"], ["enterprise_architecture"])
        self.assertEqual(json.loads(self.map_path.read_text()), {str(finding_path): "Identity"})

    def test_same_basename_in_another_scan_does_not_reuse_old_system_mapping(self):
        source = self.root / "new-repository"
        (source / "different-area").mkdir(parents=True)
        finding_path = source / "different-area" / "auth.py"
        config = self.root / "architecture.json"
        config.write_text(json.dumps({
            "name": "Configured architecture", "is_template": False,
            "systems": ["Legacy Identity"], "dependencies": [],
            "file_to_system": {"auth.py": "Legacy Identity"},
        }), encoding="utf-8")
        with patch.object(G, "SYSTEM_MAP_OUTPUT", self.map_path):
            graph = G.build_dependency_graph(
                [{"file": str(finding_path), "algorithm": "MD5", "severity": "high"}],
                source_root=source, architecture_path=config,
            )
        self.assertEqual(graph.nodes["Legacy Identity"]["vulnerability_count"], 0)
        self.assertEqual(graph.nodes["different-area/auth.py"]["vulnerability_count"], 1)
        self.assertEqual(json.loads(self.map_path.read_text()), {
            str(finding_path): "different-area/auth.py",
        })

    def test_invalid_architecture_dependency_fails_closed(self):
        config = self.root / "invalid.json"
        config.write_text(json.dumps({"systems": ["A"],
                                      "dependencies": [{"source": "A", "target": "Unknown"}]}),
                          encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unknown"):
            G.build_dependency_graph([], architecture_path=config)


if __name__ == "__main__":
    unittest.main(verbosity=2)
