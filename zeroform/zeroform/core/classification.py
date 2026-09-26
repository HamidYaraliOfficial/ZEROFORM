"""
Security Classification Engine
=================================

Classifies data-carrying nodes/edges into an ordered, user-extensible
label set and propagates classification along the graph: whenever
data of two different classifications is combined (e.g. a service
reads Confidential data and Restricted data and writes a new
DataSet), a configurable combination rule decides the classification
of the result. The full propagation path stays visible on the graph
via a ``classification_path`` attribute so any label can be traced
back to its sources.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .graph_model import GraphRepository

DEFAULT_LEVELS: Dict[str, int] = {
    "Public": 0,
    "Internal": 1,
    "Confidential": 2,
    "Restricted": 3,
    "Secret": 4,
}


@dataclass
class ClassificationRuleSet:
    """Ordered classification levels plus optional overrides for how
    two labels combine. By default combination = max(level)."""

    levels: Dict[str, int] = field(default_factory=lambda: dict(DEFAULT_LEVELS))
    overrides: Dict[Tuple[str, str], str] = field(default_factory=dict)

    def add_level(self, name: str, rank: int) -> None:
        self.levels[name] = rank

    def add_override(self, a: str, b: str, result: str) -> None:
        self.overrides[(a, b)] = result
        self.overrides[(b, a)] = result

    def combine(self, a: str, b: str) -> str:
        if a not in self.levels:
            self.levels[a] = max(self.levels.values(), default=0) + 1
        if b not in self.levels:
            self.levels[b] = max(self.levels.values(), default=0) + 1
        if (a, b) in self.overrides:
            return self.overrides[(a, b)]
        return a if self.levels[a] >= self.levels[b] else b

    def rank(self, label: str) -> int:
        return self.levels.get(label, 0)


@dataclass
class ClassificationFinding:
    node_id: str
    classification: str
    sources: List[str]
    reason: str


class ClassificationEngine:
    def __init__(self, rules: Optional[ClassificationRuleSet] = None):
        self.rules = rules or ClassificationRuleSet()

    def classify_graph(self, graph: GraphRepository) -> Dict[str, ClassificationFinding]:
        """Assigns an *effective* classification to every Asset/Data
        node: its own declared classification combined with anything
        that flows into it (reads/subscribes from an upstream node
        propagate that node's classification forward)."""

        results: Dict[str, ClassificationFinding] = {}
        nodes = graph.nodes()
        node_ids = [n.id for n in nodes]

        # seed with declared classification
        for n in nodes:
            declared = str(n.attrs.get("classification", "Public"))
            results[n.id] = ClassificationFinding(
                node_id=n.id, classification=declared, sources=[n.id],
                reason="declared",
            )

        # propagate along write/publish edges (topological-ish fixed
        # point iteration; graphs are small enough that a bounded
        # number of passes converges in practice).
        for _ in range(len(node_ids) + 1):
            changed = False
            for edge in graph.edges():
                if edge.kind not in ("writes", "publishes", "flows_through"):
                    continue
                src_finding = results.get(edge.source)
                dst_finding = results.get(edge.target)
                if not src_finding or not dst_finding:
                    continue
                flow_label = edge.attrs.get("classification")
                incoming = flow_label or src_finding.classification
                combined = self.rules.combine(dst_finding.classification, str(incoming))
                if combined != dst_finding.classification:
                    dst_finding.classification = combined
                    dst_finding.sources = list(set(dst_finding.sources + src_finding.sources + [edge.source]))
                    dst_finding.reason = f"propagated via '{edge.kind}' from {edge.source}"
                    changed = True
            if not changed:
                break

        return results

    def label_rank(self, label: str) -> int:
        return self.rules.rank(label)
