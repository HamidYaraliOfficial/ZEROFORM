"""
Trust Zone Engine + Trust Boundary Compiler
==============================================

The Trust Zone Engine builds the zone hierarchy (Public / Internet /
Untrusted / User Device / Internal / Secure / Restricted / Admin /
Secrets / External Partner, or any custom set declared in the DSL)
and resolves, for every entity, which zone it lives in.

The Trust Boundary Compiler then walks every edge in the graph; if an
edge's endpoints resolve to two different zones, that is a *Boundary
Crossing Event*, and a small deterministic rule table decides which
Control Requirements the crossing implies (authentication,
authorization, encryption, validation, redaction, tokenization,
approval, rate limiting, audit, data minimization, isolation).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .classification import ClassificationEngine
from .graph_model import GraphRepository

DEFAULT_ZONE_LEVELS = {
    "Internet": 0,
    "Untrusted": 1,
    "UserDevice": 2,
    "ExternalPartner": 2,
    "Internal": 5,
    "Secure": 8,
    "Restricted": 9,
    "Admin": 9,
    "Secrets": 10,
}


@dataclass
class BoundaryCrossing:
    edge_source: str
    edge_target: str
    edge_kind: str
    from_zone: str
    to_zone: str
    level_delta: int
    data_classification: str
    required_controls: List[str] = field(default_factory=list)
    removed_controls: List[str] = field(default_factory=list)

    def enforced_controls(self) -> List[str]:
        """Controls that are still actually meant to be generated,
        i.e. required minus anything a scenario has simulated as
        removed from the live configuration (see
        zeroform.core.virtual_env's `remove_control` event)."""
        return [c for c in self.required_controls if c not in self.removed_controls]


class TrustZoneEngine:
    def __init__(self, zone_levels: Optional[Dict[str, int]] = None):
        self.zone_levels = dict(zone_levels or DEFAULT_ZONE_LEVELS)

    def resolve_zone_of(self, graph: GraphRepository, node_id: str) -> str:
        """A node belongs to the trust zone that has a `contains` edge
        pointing at it. Falls back to 'Internet' (least trusted) if
        unspecified, which is the conservative default."""
        for edge, zone_node in graph.predecessors(node_id, kind="contains"):
            if zone_node.entity_type == "TrustZone":
                return zone_node.id
        return "Internet"

    def level_of(self, zone_name: str) -> int:
        return self.zone_levels.get(zone_name, 0)


class TrustBoundaryCompiler:
    """Deterministic mapping from a boundary crossing's characteristics
    to a set of required control *types* (later expanded into full
    Control objects by :mod:`zeroform.core.control_synthesis`)."""

    def __init__(self, zone_engine: TrustZoneEngine, classifier: ClassificationEngine):
        self.zones = zone_engine
        self.classifier = classifier

    def compile_crossings(self, graph: GraphRepository) -> List[BoundaryCrossing]:
        findings = self.classifier.classify_graph(graph)
        crossings: List[BoundaryCrossing] = []
        for edge in graph.edges():
            if edge.kind == "contains":
                continue
            from_zone = self.zones.resolve_zone_of(graph, edge.source)
            to_zone = self.zones.resolve_zone_of(graph, edge.target)
            if from_zone == to_zone:
                continue
            level_delta = self.zones.level_of(to_zone) - self.zones.level_of(from_zone)
            classification = findings.get(edge.target)
            label = classification.classification if classification else "Public"
            controls = self._required_controls(from_zone, to_zone, level_delta, label, edge.kind)
            removed = list(edge.attrs.get("controls_removed", []))
            crossings.append(BoundaryCrossing(
                edge_source=edge.source, edge_target=edge.target, edge_kind=edge.kind,
                from_zone=from_zone, to_zone=to_zone, level_delta=level_delta,
                data_classification=label, required_controls=controls, removed_controls=removed,
            ))
        return crossings

    def _required_controls(self, from_zone: str, to_zone: str, level_delta: int,
                            classification: str, edge_kind: str) -> List[str]:
        controls: Set[str] = {"audit"}  # every boundary crossing is audited
        rank = self.classifier.label_rank(classification)

        if self.zones.level_of(to_zone) >= self.zones.level_of("Internal"):
            controls.add("authentication")
        if level_delta > 0:
            controls.add("authorization")
        if rank >= self.classifier.label_rank("Confidential"):
            controls.add("encryption")
        if rank >= self.classifier.label_rank("Restricted"):
            controls.add("data_minimization")
        if to_zone in ("Secrets",) or classification == "Secret":
            controls.add("approval")
            controls.add("isolation")
        if from_zone in ("Internet", "Untrusted", "ExternalPartner"):
            controls.add("input_validation")
            controls.add("rate_limiting")
        if edge_kind == "publishes" and rank >= self.classifier.label_rank("Confidential"):
            controls.add("output_filtering")
        return sorted(controls)
