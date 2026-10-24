"""
cbom.py — CycloneDX 1.6 Cryptography Bill of Materials (CBOM) builder.

CADENCE Module 1 now emits industry-standard CBOM output (CycloneDX 1.6 /
ECMA-424) instead of a bespoke schema, so results are consumable by
CBOMkit, PQC-migration tooling, and CADENCE's own Modules 2-4.

We keep it dependency-free (no cyclonedx-python-lib) so it's easy to read,
audit, and hand off to teammates.
"""

from __future__ import annotations

import uuid
import datetime
from dataclasses import dataclass, field


CADENCE_VERSION = "2.0.0"


@dataclass
class Occurrence:
    """Where a crypto asset was found (source layer) or observed (network layer)."""
    location: str          # file path, or "host:port" for network findings
    line: int | None = None
    offset: int | None = None


@dataclass
class CryptoAsset:
    """One finding, normalized to a CycloneDX cryptographic-asset component."""
    name: str                       # e.g. "MD5", "RC4", "TLSv1.0", "RSA-1024"
    asset_type: str                 # "algorithm" | "protocol" | "certificate"
    primitive: str | None = None    # e.g. "hash", "block-cipher", "stream-cipher", "signature"
    confidence: str = "high"        # "high" | "needs_review"
    detection_method: str = "ast"   # "ast" | "keyword" | "network-probe" | "cert-inspect"
    severity: str = "medium"        # "low" | "medium" | "high" | "critical"
    nist_pqc_status: str = "not-quantum-safe"  # "not-quantum-safe" | "quantum-safe" | "n/a"
    occurrences: list[Occurrence] = field(default_factory=list)
    notes: str = ""


class CBOMDocument:
    def __init__(self, project_name: str):
        self.project_name = project_name
        self.assets: list[CryptoAsset] = []

    def add(self, asset: CryptoAsset) -> None:
        self.assets.append(asset)

    def add_many(self, assets: list[CryptoAsset]) -> None:
        self.assets.extend(assets)

    def to_dict(self) -> dict:
        components = []
        for idx, a in enumerate(self.assets):
            bom_ref = f"crypto-asset/{idx}-{a.name.lower().replace(' ', '-')}"
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": bom_ref,
                "name": a.name,
                "cryptoProperties": {
                    "assetType": a.asset_type,
                    **({"algorithmProperties": {"primitive": a.primitive}} if a.primitive else {}),
                    "nistQuantumSecurityStatus": a.nist_pqc_status,
                },
                "evidence": {
                    "occurrences": [
                        {
                            k: v for k, v in {
                                "location": o.location,
                                "line": o.line,
                                "offset": o.offset,
                            }.items() if v is not None
                        }
                        for o in a.occurrences
                    ]
                },
                # CycloneDX's generic "properties" array is the sanctioned
                # extension point for tool-specific metadata like ours.
                "properties": [
                    {"name": "cadence:confidence", "value": a.confidence},
                    {"name": "cadence:detectionMethod", "value": a.detection_method},
                    {"name": "cadence:severity", "value": a.severity},
                ] + ([{"name": "cadence:notes", "value": a.notes}] if a.notes else []),
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.datetime.now(datetime.timezone.utc)
                    .isoformat(timespec="seconds"),
                "tools": {
                    "components": [
                        {"type": "application", "name": "CADENCE Module 1 — The Scanner",
                         "version": CADENCE_VERSION}
                    ]
                },
                "component": {"type": "application", "name": self.project_name},
            },
            "components": components,
        }

    # --- Legacy compatibility -------------------------------------------------
    def to_legacy_vulnerabilities_json(self) -> list[dict]:
        """
        Re-emit findings in CADENCE's original vulnerabilities.json shape,
        so Modules 2-4 (already built against the locked schema) don't break
        while the team migrates to CBOM as the primary format.
        """
        out = []
        for a in self.assets:
            for o in a.occurrences:
                out.append({
                    "algorithm": a.name,
                    "type": a.asset_type,
                    "file": o.location,
                    "line": o.line,
                    "confidence": a.confidence,
                    "detection_method": a.detection_method,
                    "severity": a.severity,
                })
        return out
