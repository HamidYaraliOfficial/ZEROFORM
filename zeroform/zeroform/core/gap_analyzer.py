"""
Security Gap Analyzer + Security Path Analyzer + Data Exposure Simulator
============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .classification import ClassificationEngine
from .control_synthesis import SecurityControl
from .graph_model import GraphRepository
from .trust_zone import BoundaryCrossing, TrustBoundaryCompiler

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class GapFinding:
    finding_id: str
    kind: str
    severity: str
    path: List[str]
    evidence: List[str]
    suggested_control: str
    description: str


class SecurityGapAnalyzer:
    def analyze(self, graph: GraphRepository, crossings: List[BoundaryCrossing],
                controls: List[SecurityControl]) -> List[GapFinding]:
        findings: List[GapFinding] = []
        covered_types_by_edge: Dict[str, Set[str]] = {}
        for c in controls:
            covered_types_by_edge.setdefault(c.trigger, set()).add(c.control_type)

        for crossing in crossings:
            trigger = f"{crossing.edge_kind}:{crossing.edge_source}->{crossing.edge_target}"
            covered = covered_types_by_edge.get(trigger, set())
            missing = set(crossing.required_controls) - covered
            for ctype in missing:
                severity = self._severity_for(ctype, crossing)
                findings.append(GapFinding(
                    finding_id=f"gap_{crossing.edge_source}_{crossing.edge_target}_{ctype}",
                    kind=f"missing_{ctype}",
                    severity=severity,
                    path=[crossing.edge_source, crossing.edge_target],
                    evidence=[trigger],
                    suggested_control=ctype,
                    description=(
                        f"Crossing from zone '{crossing.from_zone}' to '{crossing.to_zone}' via "
                        f"'{crossing.edge_kind}' carries data classified '{crossing.data_classification}' "
                        f"but is missing required control '{ctype}'."
                    ),
                ))

        findings.extend(self._structural_findings(graph))
        findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity), reverse=True)
        return findings

    def _severity_for(self, control_type: str, crossing: BoundaryCrossing) -> str:
        if control_type in ("authentication", "approval", "secrets_management") and crossing.data_classification == "Secret":
            return "critical"
        if control_type in ("authentication", "authorization", "encryption") and crossing.level_delta > 0:
            return "high"
        if control_type in ("audit", "rate_limiting", "input_validation"):
            return "medium"
        return "low"

    def _structural_findings(self, graph: GraphRepository) -> List[GapFinding]:
        findings: List[GapFinding] = []
        # direct database access from a non-service (e.g. a raw API or
        # an external system reading a Database directly).
        for edge in graph.edges(kind="reads") + graph.edges(kind="writes"):
            target = graph.get_node(edge.target)
            source = graph.get_node(edge.source)
            if not target or not source:
                continue
            if target.entity_type == "Database" and source.entity_type in ("ExternalSystem", "User"):
                findings.append(GapFinding(
                    finding_id=f"gap_direct_db_{edge.source}_{edge.target}",
                    kind="direct_database_access",
                    severity="high",
                    path=[edge.source, edge.target],
                    evidence=[f"{edge.kind}:{edge.source}->{edge.target}"],
                    suggested_control="segmentation",
                    description=f"'{edge.source}' ({source.entity_type}) accesses database "
                                 f"'{edge.target}' directly instead of through a service boundary.",
                ))

        # secret used by more than one unrelated service without a
        # dedicated secret store in between -> suggest secrets_management.
        for secret in graph.nodes(entity_type="Secret"):
            users = [n for _, n in graph.predecessors(secret.id, kind="uses")]
            if len(users) > 1:
                findings.append(GapFinding(
                    finding_id=f"gap_shared_secret_{secret.id}",
                    kind="shared_secret",
                    severity="medium",
                    path=[u.id for u in users] + [secret.id],
                    evidence=[f"uses->{secret.id}"],
                    suggested_control="secrets_management",
                    description=f"Secret '{secret.id}' is used directly by {len(users)} different "
                                 f"principals; consider brokering access through a secret provider.",
                ))

        # data without classification
        for node in graph.nodes():
            if node.kind == "Asset" and "classification" not in node.attrs and node.entity_type in ("Database", "DataSet"):
                findings.append(GapFinding(
                    finding_id=f"gap_unclassified_{node.id}",
                    kind="missing_classification",
                    severity="low",
                    path=[node.id],
                    evidence=[f"node:{node.id}"],
                    suggested_control="data_classification",
                    description=f"Data-bearing asset '{node.id}' has no declared classification.",
                ))
        return findings


@dataclass
class GraphPath:
    nodes: List[str]
    kind: str   # critical | sensitive | external | cross_boundary


class SecurityPathAnalyzer:
    def __init__(self, classifier: ClassificationEngine, boundary_compiler: TrustBoundaryCompiler):
        self.classifier = classifier
        self.boundary_compiler = boundary_compiler

    def analyze(self, graph: GraphRepository) -> List[GraphPath]:
        findings = self.classifier.classify_graph(graph)
        paths: List[GraphPath] = []
        identities = graph.nodes(kind="Identity")
        sensitive_nodes = {nid for nid, f in findings.items()
                            if self.classifier.label_rank(f.classification) >= self.classifier.label_rank("Restricted")}
        external_nodes = {n.id for n in graph.nodes(entity_type="ExternalSystem")}

        for identity in identities:
            for target_id in list(sensitive_nodes) + list(external_nodes):
                path = graph.shortest_path(identity.id, target_id)
                if not path or len(path) < 2:
                    continue
                kind = "sensitive" if target_id in sensitive_nodes else "external"
                if target_id in sensitive_nodes and identity.attrs.get("criticality") == "high":
                    kind = "critical"
                paths.append(GraphPath(nodes=path, kind=kind))

        crossings = self.boundary_compiler.compile_crossings(graph)
        for c in crossings:
            paths.append(GraphPath(nodes=[c.edge_source, c.edge_target], kind="cross_boundary"))

        return paths


class DataExposureSimulator:
    """For a sensitive path, simulate removing one control and report
    which additional zones/data types become reachable. Purely a
    graph-level *what-if*: nothing is executed against a real system."""

    def __init__(self, boundary_compiler: TrustBoundaryCompiler):
        self.boundary_compiler = boundary_compiler

    def simulate_control_removal(self, graph: GraphRepository, control_type: str) -> Dict[str, List[str]]:
        crossings = self.boundary_compiler.compile_crossings(graph)
        newly_open: Dict[str, List[str]] = {}
        for c in crossings:
            if control_type in c.required_controls:
                remaining = [ct for ct in c.required_controls if ct != control_type]
                if not remaining or control_type in ("authentication", "authorization", "encryption"):
                    newly_open.setdefault(f"{c.from_zone}->{c.to_zone}", []).append(
                        f"{c.edge_source}->{c.edge_target} ({c.data_classification})"
                    )
        return newly_open
