"""
Graph Diff Engine
===================

Compares two Reality Graph snapshots (before/after an architecture
change, a refactor proposal, or two branches) and reports exactly
which nodes and edges were added, removed or changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .graph_model import GraphRepository


@dataclass
class GraphDiff:
    added_nodes: List[Dict[str, Any]] = field(default_factory=list)
    removed_nodes: List[Dict[str, Any]] = field(default_factory=list)
    changed_nodes: List[Dict[str, Any]] = field(default_factory=list)
    added_edges: List[Dict[str, Any]] = field(default_factory=list)
    removed_edges: List[Dict[str, Any]] = field(default_factory=list)
    changed_edges: List[Dict[str, Any]] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any([self.added_nodes, self.removed_nodes, self.changed_nodes,
                        self.added_edges, self.removed_edges, self.changed_edges])

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class GraphDiffEngine:
    def diff(self, before: GraphRepository, after: GraphRepository) -> GraphDiff:
        result = GraphDiff()
        before_nodes = {n.id: n for n in before.nodes()}
        after_nodes = {n.id: n for n in after.nodes()}

        for nid, node in after_nodes.items():
            if nid not in before_nodes:
                result.added_nodes.append(node.to_dict())
            elif node.to_dict() != before_nodes[nid].to_dict():
                result.changed_nodes.append({
                    "id": nid, "before": before_nodes[nid].to_dict(), "after": node.to_dict(),
                })
        for nid, node in before_nodes.items():
            if nid not in after_nodes:
                result.removed_nodes.append(node.to_dict())

        before_edges = {(e.source, e.target, e.kind): e for e in before.edges()}
        after_edges = {(e.source, e.target, e.kind): e for e in after.edges()}

        for key, edge in after_edges.items():
            if key not in before_edges:
                result.added_edges.append(edge.to_dict())
            elif edge.to_dict() != before_edges[key].to_dict():
                result.changed_edges.append({
                    "key": list(key), "before": before_edges[key].to_dict(), "after": edge.to_dict(),
                })
        for key, edge in before_edges.items():
            if key not in after_edges:
                result.removed_edges.append(edge.to_dict())

        return result
