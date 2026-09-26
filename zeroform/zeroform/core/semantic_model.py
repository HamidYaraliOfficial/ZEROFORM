"""
Semantic Model
================

Turns a parsed :class:`zeroform.dsl.ast_nodes.Module` (or an already
normalized dict coming from an external importer) into the Canonical
Reality Graph. This is the "AST -> Semantic Model -> Graph Build"
portion of the compiler pipeline.

Recognised top level block kinds
---------------------------------
``world``               - metadata about the whole reality model
``trust_zone``          - a security trust zone / boundary container
``identity`` ``user``   - a human, service, workload, API client or
                           agent identity
``service`` ``api``
``device`` ``database`` ``queue`` ``dataset`` ``external_system``
``agent`` ``secret``    - assets / resources
``flow``                - a directed interaction between two entities
                           (call, read, write, publish, subscribe...)
``policy``              - a human authored security intent, later
                           compiled into machine-enforceable Controls
``scenario``            - a Scenario Designer definition (see
                           :mod:`zeroform.core.scenario`)

Unknown block kinds are preserved as generic ``Asset`` nodes with
``entity_type`` set to the raw kind, so importers can introduce new
categories without needing a parser change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..dsl.ast_nodes import Block, Module
from .graph_model import GraphRepository, RealityEdge, RealityNode, new_repository

# maps a DSL block kind to (graph node kind, entity_type)
_ENTITY_BLOCK_MAP = {
    "identity": ("Identity", "User"),
    "user": ("Identity", "User"),
    "service": ("Asset", "Service"),
    "api": ("Asset", "API"),
    "device": ("Asset", "Device"),
    "database": ("Asset", "Database"),
    "queue": ("Asset", "Queue"),
    "dataset": ("Asset", "DataSet"),
    "external_system": ("Asset", "ExternalSystem"),
    "agent": ("Identity", "Agent"),
    "secret": ("Asset", "Secret"),
    "trust_zone": ("Boundary", "TrustZone"),
}

FLOW_ACTIONS = {
    "calls", "reads", "writes", "publishes", "subscribes", "uses", "owns",
}


@dataclass
class WorldMeta:
    name: str = "Untitled Reality"
    version: str = "0.0.1"
    description: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RealityModel:
    """The fully built semantic model: world metadata + canonical
    graph + the raw policy / scenario declarations (kept alongside the
    graph because policies/scenarios are compiled by later stages)."""

    meta: WorldMeta
    graph: GraphRepository
    policies_raw: List[Block] = field(default_factory=list)
    scenarios_raw: List[Block] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "meta": {
                "name": self.meta.name,
                "version": self.meta.version,
                "description": self.meta.description,
                **self.meta.extra,
            },
            "graph": self.graph.to_dict(),
            "policies_raw": [p.to_dict() for p in self.policies_raw],
            "scenarios_raw": [s.to_dict() for s in self.scenarios_raw],
        }


class SemanticError(Exception):
    pass


def build_semantic_model(module: Module, backend: str = "networkx") -> RealityModel:
    repo = new_repository(backend)
    meta = WorldMeta()
    warnings: List[str] = []

    world_blocks = module.blocks_of("world")
    if world_blocks:
        wb = world_blocks[0]
        meta.name = wb.name or meta.name
        attrs = dict(wb.attrs)
        meta.version = str(attrs.pop("version", meta.version))
        meta.description = str(attrs.pop("description", meta.description))
        meta.extra = attrs

    policies_raw: List[Block] = []
    scenarios_raw: List[Block] = []

    # Pass 1: create all nodes (entities + trust zones) so pass 2 can
    # freely reference any node id regardless of declaration order.
    for block in module.blocks:
        if block.kind in ("world", "flow", "policy", "scenario"):
            continue
        if block.kind == "policy":
            continue
        node_kind, default_type = _ENTITY_BLOCK_MAP.get(block.kind, ("Asset", block.kind.title()))
        if block.name is None:
            warnings.append(f"block of kind '{block.kind}' at line {block.line} has no name/id; skipped")
            continue
        attrs = _flatten_attrs(block.attrs)
        entity_type = str(attrs.pop("type", default_type))
        node = RealityNode(id=block.name, kind=node_kind, entity_type=entity_type, attrs=attrs)
        repo.add_node(node)

    # Pass 1b: trust zone parent-child containment edges.
    tz_ids = {tz.name for tz in module.blocks_of("trust_zone") if tz.name}
    for tz in module.blocks_of("trust_zone"):
        parent = tz.get("parent")
        if parent:
            if str(parent) not in tz_ids:
                warnings.append(f"trust_zone '{tz.name}' references undeclared parent zone '{parent}'; skipped")
            else:
                repo.add_edge(RealityEdge(source=str(parent), target=tz.name, kind="contains"))

    # Pass 1c: link every entity that declares trust_zone: "X" into
    # that zone via a `contains` edge (zone -> entity), and owner: "Y"
    # via an `owns` edge (Y -> entity). If the owner isn't declared as
    # its own entity, a lightweight placeholder Identity node is
    # created for it so the graph never contains an attribute-less
    # node (networkx auto-creates bare nodes for edge endpoints that
    # don't exist yet, which would otherwise break every downstream
    # consumer of RealityNode.to_dict()).
    known_ids = {n.id for n in repo.nodes()}
    for block in module.blocks:
        if block.kind in ("world", "flow", "policy", "scenario", "trust_zone"):
            continue
        zone = block.get("trust_zone")
        if zone and block.name:
            if str(zone) not in known_ids:
                warnings.append(f"'{block.name}' references undeclared trust_zone '{zone}'; skipped")
            else:
                repo.add_edge(RealityEdge(source=str(zone), target=block.name, kind="contains"))
        owner = block.get("owner")
        if owner and block.name:
            owner_id = str(owner)
            if owner_id not in known_ids:
                repo.add_node(RealityNode(id=owner_id, kind="Identity", entity_type="Owner",
                                           attrs={"implicit": True}))
                known_ids.add(owner_id)
                warnings.append(f"owner '{owner_id}' of '{block.name}' was not declared as its own "
                                 f"entity; created an implicit placeholder Identity node for it")
            repo.add_edge(RealityEdge(source=owner_id, target=block.name, kind="owns"))

    # Pass 2: flows -> edges between already-created nodes.
    for flow in module.blocks_of("flow"):
        src = flow.get("from")
        dst = flow.get("to")
        if not src or not dst:
            warnings.append(f"flow '{flow.name}' missing from/to; skipped")
            continue
        if repo.get_node(str(src)) is None:
            warnings.append(f"flow '{flow.name}' references unknown source '{src}'")
            continue
        if repo.get_node(str(dst)) is None:
            warnings.append(f"flow '{flow.name}' references unknown destination '{dst}'")
            continue
        action = str(flow.get("action", "calls"))
        edge_kind = action if action in FLOW_ACTIONS else "flows_through"
        attrs = _flatten_attrs(flow.attrs)
        attrs.pop("from", None)
        attrs.pop("to", None)
        attrs["flow_name"] = flow.name
        repo.add_edge(RealityEdge(source=str(src), target=str(dst), kind=edge_kind, attrs=attrs))

    policies_raw.extend(module.blocks_of("policy"))
    scenarios_raw.extend(module.blocks_of("scenario"))

    return RealityModel(
        meta=meta,
        graph=repo,
        policies_raw=policies_raw,
        scenarios_raw=scenarios_raw,
        warnings=warnings,
    )


def _flatten_attrs(attrs: Dict[str, Any]) -> Dict[str, Any]:
    def unwrap(v: Any) -> Any:
        if isinstance(v, Block):
            return v.to_dict()
        if isinstance(v, list):
            return [unwrap(x) for x in v]
        return v

    return {k: unwrap(v) for k, v in attrs.items()}
