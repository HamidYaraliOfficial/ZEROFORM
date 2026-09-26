"""
Canonical Reality Graph
=========================

Every source (DSL, JSON/YAML, external importer) is normalized into
this one canonical graph shape before any analysis, synthesis or
simulation happens. Node kinds map onto the categories described in
the ZEROFORM spec (Identity, Asset, Data, Boundary, Policy, Control,
Event, Observation, Scenario) and edges use a fixed, small vocabulary
(``owns``, ``uses``, ``calls``, ``reads``, ``writes``, ``publishes``,
``subscribes``, ``contains``, ``trusts``, ``authenticates_with``,
``protected_by``, ``flows_through``, ``depends_on``, ``delegates_to``,
``requires_approval``).

Storage is pluggable behind :class:`GraphRepository`. The reference
implementation (:class:`NetworkXGraphRepository`) keeps everything in
memory using ``networkx`` so the whole compiler runs with zero
external services ("Local-Only Mode"). :class:`Neo4jGraphRepository`
documents the exact adapter surface a Cypher-backed deployment would
implement -- it degrades to a clear error if the ``neo4j`` driver
isn't installed/configured rather than silently no-op-ing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

import networkx as nx

NODE_KINDS = {
    "Identity",
    "Asset",
    "Data",
    "Boundary",
    "Policy",
    "Control",
    "Event",
    "Observation",
    "Scenario",
}

EDGE_KINDS = {
    "owns",
    "uses",
    "calls",
    "reads",
    "writes",
    "publishes",
    "subscribes",
    "contains",
    "trusts",
    "authenticates_with",
    "protected_by",
    "flows_through",
    "depends_on",
    "delegates_to",
    "requires_approval",
}

# Entity "type" attribute values recognised out of the box. Custom
# types are still accepted -- this set only drives default styling /
# heuristics elsewhere in the engines.
ENTITY_TYPES = {
    "User", "Service", "Device", "API", "Database", "Agent", "Secret",
    "DataSet", "Queue", "ExternalSystem", "SecurityControl", "TrustZone",
}


@dataclass
class RealityNode:
    id: str
    kind: str                       # one of NODE_KINDS
    entity_type: str = "Generic"    # one of ENTITY_TYPES or custom
    attrs: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "entity_type": self.entity_type, **self.attrs}


@dataclass
class RealityEdge:
    source: str
    target: str
    kind: str                       # one of EDGE_KINDS
    attrs: Dict[str, Any] = field(default_factory=dict)

    def key(self) -> Tuple[str, str, str]:
        return (self.source, self.target, self.kind)

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "target": self.target, "kind": self.kind, **self.attrs}


class GraphRepository:
    """Abstract storage interface. Swap implementations without
    touching any analysis/synthesis engine."""

    def add_node(self, node: RealityNode) -> None:
        raise NotImplementedError

    def add_edge(self, edge: RealityEdge) -> None:
        raise NotImplementedError

    def get_node(self, node_id: str) -> Optional[RealityNode]:
        raise NotImplementedError

    def nodes(self, kind: Optional[str] = None, entity_type: Optional[str] = None) -> List[RealityNode]:
        raise NotImplementedError

    def edges(self, kind: Optional[str] = None) -> List[RealityEdge]:
        raise NotImplementedError

    def successors(self, node_id: str, kind: Optional[str] = None) -> List[Tuple[RealityEdge, RealityNode]]:
        raise NotImplementedError

    def predecessors(self, node_id: str, kind: Optional[str] = None) -> List[Tuple[RealityEdge, RealityNode]]:
        raise NotImplementedError

    def shortest_path(self, src: str, dst: str) -> Optional[List[str]]:
        raise NotImplementedError

    def all_paths(self, src: str, dst: str, cutoff: int = 12) -> List[List[str]]:
        raise NotImplementedError

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError

    def clone(self) -> "GraphRepository":
        raise NotImplementedError


class NetworkXGraphRepository(GraphRepository):
    """Reference in-memory graph backend used by Local-Only Mode and
    by default everywhere else. A ``MultiDiGraph`` is used because two
    entities may be connected by more than one edge kind (e.g. a
    service both ``calls`` and ``depends_on`` another service)."""

    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()

    # -- mutation ----------------------------------------------------
    def add_node(self, node: RealityNode) -> None:
        self.g.add_node(node.id, **node.to_dict())

    def add_edge(self, edge: RealityEdge) -> None:
        self.g.add_edge(edge.source, edge.target, key=edge.kind, **edge.to_dict())

    # -- reads ---------------------------------------------------------
    def get_node(self, node_id: str) -> Optional[RealityNode]:
        if node_id not in self.g.nodes:
            return None
        data = dict(self.g.nodes[node_id])
        return RealityNode(
            id=data.pop("id", node_id),
            kind=data.pop("kind", "Asset"),
            entity_type=data.pop("entity_type", "Generic"),
            attrs=data,
        )

    def nodes(self, kind: Optional[str] = None, entity_type: Optional[str] = None) -> List[RealityNode]:
        out = []
        for nid, data in self.g.nodes(data=True):
            if kind and data.get("kind") != kind:
                continue
            if entity_type and data.get("entity_type") != entity_type:
                continue
            d = dict(data)
            out.append(RealityNode(id=d.pop("id", nid), kind=d.pop("kind", "Asset"),
                                    entity_type=d.pop("entity_type", "Generic"), attrs=d))
        return out

    def edges(self, kind: Optional[str] = None) -> List[RealityEdge]:
        out = []
        for u, v, k, data in self.g.edges(keys=True, data=True):
            if kind and k != kind:
                continue
            d = dict(data)
            d.pop("source", None)
            d.pop("target", None)
            d.pop("kind", None)
            out.append(RealityEdge(source=u, target=v, kind=k, attrs=d))
        return out

    def successors(self, node_id: str, kind: Optional[str] = None) -> List[Tuple[RealityEdge, RealityNode]]:
        out = []
        for _, v, k, data in self.g.out_edges(node_id, keys=True, data=True):
            if kind and k != kind:
                continue
            d = dict(data)
            d.pop("source", None); d.pop("target", None); d.pop("kind", None)
            edge = RealityEdge(source=node_id, target=v, kind=k, attrs=d)
            node = self.get_node(v)
            if node:
                out.append((edge, node))
        return out

    def predecessors(self, node_id: str, kind: Optional[str] = None) -> List[Tuple[RealityEdge, RealityNode]]:
        out = []
        for u, _, k, data in self.g.in_edges(node_id, keys=True, data=True):
            if kind and k != kind:
                continue
            d = dict(data)
            d.pop("source", None); d.pop("target", None); d.pop("kind", None)
            edge = RealityEdge(source=u, target=node_id, kind=k, attrs=d)
            node = self.get_node(u)
            if node:
                out.append((edge, node))
        return out

    def shortest_path(self, src: str, dst: str) -> Optional[List[str]]:
        try:
            return nx.shortest_path(self.g, src, dst)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def all_paths(self, src: str, dst: str, cutoff: int = 12) -> List[List[str]]:
        try:
            return list(nx.all_simple_paths(self.g, src, dst, cutoff=cutoff))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes()],
            "edges": [e.to_dict() for e in self.edges()],
        }

    def clone(self) -> "NetworkXGraphRepository":
        new = NetworkXGraphRepository()
        new.g = self.g.copy()
        return new

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkXGraphRepository":
        repo = cls()
        for n in data.get("nodes", []):
            n = dict(n)
            nid = n.pop("id")
            kind = n.pop("kind")
            etype = n.pop("entity_type", "Generic")
            repo.add_node(RealityNode(id=nid, kind=kind, entity_type=etype, attrs=n))
        for e in data.get("edges", []):
            e = dict(e)
            src = e.pop("source")
            tgt = e.pop("target")
            kind = e.pop("kind")
            repo.add_edge(RealityEdge(source=src, target=tgt, kind=kind, attrs=e))
        return repo

    def dumps(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, default=str)


class Neo4jGraphRepository(GraphRepository):
    """Adapter surface for a real Neo4j-backed deployment.

    This class intentionally implements the *same* interface as
    :class:`NetworkXGraphRepository` so every engine in
    ``zeroform.core`` is storage-agnostic. It only activates if the
    optional ``neo4j`` driver package is installed and connection
    parameters are supplied; otherwise it raises
    :class:`RuntimeError` with clear setup instructions instead of
    silently falling back, so a misconfigured production deployment
    fails loudly rather than quietly running in memory.
    """

    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j"):
        try:
            from neo4j import GraphDatabase  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Neo4jGraphRepository requires the optional 'neo4j' package. "
                "Install with: pip install neo4j"
            ) from exc
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        self._database = database

    def _run(self, query: str, **params: Any):  # pragma: no cover - requires live DB
        with self._driver.session(database=self._database) as session:
            return list(session.run(query, **params))

    def add_node(self, node: RealityNode) -> None:  # pragma: no cover
        self._run(
            "MERGE (n:RealityNode {id: $id}) SET n += $props, n.kind=$kind, n.entity_type=$etype",
            id=node.id, props=node.attrs, kind=node.kind, etype=node.entity_type,
        )

    def add_edge(self, edge: RealityEdge) -> None:  # pragma: no cover
        self._run(
            "MATCH (a:RealityNode {id:$src}),(b:RealityNode {id:$dst}) "
            "MERGE (a)-[r:REL {kind:$kind}]->(b) SET r += $props",
            src=edge.source, dst=edge.target, kind=edge.kind, props=edge.attrs,
        )

    def close(self) -> None:  # pragma: no cover
        self._driver.close()


def new_repository(backend: str = "networkx", **kwargs: Any) -> GraphRepository:
    """Factory used by the pipeline / CLI so the storage backend is a
    one-line configuration choice."""
    if backend == "networkx":
        return NetworkXGraphRepository()
    if backend == "neo4j":
        return Neo4jGraphRepository(**kwargs)
    raise ValueError(f"unknown graph backend: {backend}")
