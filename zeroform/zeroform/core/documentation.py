"""
Security Documentation Compiler + Security Release Passport
================================================================

Generates human-readable Markdown documentation directly from the
compiled Reality Model: architecture summary, data flow list, trust
boundary table, identity flow, policy catalog, control matrix,
exposure summary, verification matrix, audit requirements and
scenario catalog. The Release Passport aggregates all of this plus
open findings, residual risk, artifact hashes and approval history
into a single per-version summary document.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List

from .control_synthesis import SecurityControl
from .gap_analyzer import GapFinding
from .graph_model import GraphRepository
from .policy_generator import PolicyArtifact
from .semantic_model import RealityModel
from .trust_zone import BoundaryCrossing
from .verification import InvariantResult


class SecurityDocumentationCompiler:
    def compile(self, model: RealityModel, crossings: List[BoundaryCrossing],
                controls: List[SecurityControl], findings: List[GapFinding]) -> str:
        lines: List[str] = []
        lines.append(f"# Security Architecture Documentation — {model.meta.name}")
        lines.append(f"_Version {model.meta.version} · generated {datetime.utcnow().isoformat()}Z_\n")

        lines.append("## 1. Architecture Summary")
        lines.append(f"- Entities: **{len(model.graph.nodes())}**")
        lines.append(f"- Relationships / flows: **{len(model.graph.edges())}**")
        lines.append(f"- Trust boundary crossings: **{len(crossings)}**")
        lines.append(f"- Synthesized controls: **{len(controls)}**")
        lines.append(f"- Open findings: **{len(findings)}**\n")

        lines.append("## 2. Trust Boundary Diagram (table form)")
        lines.append("| From Zone | To Zone | Edge | Classification | Required Controls |")
        lines.append("|---|---|---|---|---|")
        for c in crossings:
            lines.append(f"| {c.from_zone} | {c.to_zone} | {c.edge_source}->{c.edge_target} "
                         f"| {c.data_classification} | {', '.join(c.required_controls)} |")
        lines.append("")

        lines.append("## 3. Data Flow Diagram (table form)")
        lines.append("| Source | Target | Action | Classification |")
        lines.append("|---|---|---|---|")
        for e in model.graph.edges():
            if e.kind in ("calls", "reads", "writes", "publishes", "subscribes"):
                lines.append(f"| {e.source} | {e.target} | {e.kind} | {e.attrs.get('classification', 'n/a')} |")
        lines.append("")

        lines.append("## 4. Identity Flow")
        lines.append("| Identity | Roles | Trust Zone |")
        lines.append("|---|---|---|")
        for identity in model.graph.nodes(kind="Identity"):
            roles = identity.attrs.get("roles", [])
            lines.append(f"| {identity.id} | {', '.join(roles) if isinstance(roles, list) else roles} "
                         f"| {identity.attrs.get('trust_zone', 'Internet')} |")
        lines.append("")

        lines.append("## 5. Control Matrix")
        lines.append("| Control ID | Type | Enforcement Point | Failure Mode | Verification |")
        lines.append("|---|---|---|---|---|")
        for c in controls:
            lines.append(f"| {c.id} | {c.control_type} | {c.enforcement_point} | {c.failure_mode} | {c.verification_method} |")
        lines.append("")

        lines.append("## 6. Exposure / Gap Summary")
        lines.append("| Severity | Kind | Description |")
        lines.append("|---|---|---|")
        for f in findings:
            lines.append(f"| {f.severity} | {f.kind} | {f.description} |")
        lines.append("")

        lines.append("## 7. Scenario Catalog")
        for s in model.scenarios_raw:
            lines.append(f"- **{s.name}** — {s.get('description', '')}")
        if not model.scenarios_raw:
            lines.append("_No scenarios defined in this model._")
        lines.append("")

        if model.warnings:
            lines.append("## 8. Model Consistency Warnings")
            for w in model.warnings:
                lines.append(f"- {w}")

        return "\n".join(lines)


class SecurityReleasePassport:
    def build(self, model: RealityModel, controls: List[SecurityControl], findings: List[GapFinding],
              policy_artifacts: List[PolicyArtifact], invariant_results: List[InvariantResult],
              approval_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        open_findings = [f for f in findings]
        critical = [f for f in open_findings if f.severity == "critical"]
        return {
            "world_name": model.meta.name,
            "version": model.meta.version,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "controls_generated": len(controls),
            "policies": [{"policy_id": p.policy_id, "target": p.target, "hash": p.canonical_bytes().hex()[:16]}
                         for p in policy_artifacts],
            "verification_tests_passed": sum(1 for r in invariant_results if r.passed),
            "verification_tests_failed": sum(1 for r in invariant_results if not r.passed),
            "open_findings": len(open_findings),
            "critical_findings": len(critical),
            "residual_risk": "high" if critical else ("medium" if open_findings else "low"),
            "scenario_coverage": len(model.scenarios_raw),
            "artifact_hashes": [p.canonical_bytes().hex()[:16] for p in policy_artifacts],
            "approval_history": approval_history,
        }
