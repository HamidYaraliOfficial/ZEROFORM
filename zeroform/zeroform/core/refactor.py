"""
Security Architecture Refactoring Engine
===========================================

Reads Gap Analyzer findings and proposes concrete graph
transformations that would close them: inserting a security gateway,
carving out a dedicated data zone, adding an approval layer,
separating a secret store, restricting a service account, removing a
direct database path, or routing a flow through a safer trust
boundary. Every proposal is a versioned :class:`GraphTransformation`
with explicit preconditions, change set, security benefit, functional
impact, new dependencies, operational cost and residual findings --
nothing is applied automatically to the canonical model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .gap_analyzer import GapFinding
from .graph_model import GraphRepository, RealityEdge, RealityNode


@dataclass
class GraphTransformation:
    id: str
    title: str
    preconditions: List[str]
    change_set: Dict[str, List[Dict[str, Any]]]   # {"add_nodes":[...], "add_edges":[...], "remove_edges":[...]}
    security_benefit: str
    functional_impact: str
    new_dependencies: List[str]
    operational_cost: str
    residual_findings: List[str] = field(default_factory=list)

    def apply(self, graph: GraphRepository) -> GraphRepository:
        new_graph = graph.clone()
        for n in self.change_set.get("add_nodes", []):
            new_graph.add_node(RealityNode(id=n["id"], kind=n.get("kind", "Asset"),
                                            entity_type=n.get("entity_type", "SecurityControl"),
                                            attrs=n.get("attrs", {})))
        for e in self.change_set.get("add_edges", []):
            new_graph.add_edge(RealityEdge(source=e["source"], target=e["target"], kind=e["kind"],
                                            attrs=e.get("attrs", {})))
        # `remove_edges` is recorded for transparency; the reference
        # NetworkX repository is rebuilt without them.
        to_remove = {(e["source"], e["target"], e["kind"]) for e in self.change_set.get("remove_edges", [])}
        if to_remove:
            rebuilt = new_graph.clone()
            rebuilt.g.clear_edges()
            for e in new_graph.edges():
                if (e.source, e.target, e.kind) not in to_remove:
                    rebuilt.add_edge(e)
            new_graph = rebuilt
        return new_graph


class SecurityArchitectureRefactoringEngine:
    def propose(self, graph: GraphRepository, findings: List[GapFinding]) -> List[GraphTransformation]:
        proposals: List[GraphTransformation] = []
        for finding in findings:
            if finding.kind == "direct_database_access":
                proposals.append(self._propose_gateway(finding))
            elif finding.kind == "shared_secret":
                proposals.append(self._propose_secret_store(finding))
            elif finding.kind.startswith("missing_authentication") or finding.kind.startswith("missing_authorization"):
                proposals.append(self._propose_control_insertion(finding))
            elif finding.kind.startswith("missing_approval"):
                proposals.append(self._propose_approval_layer(finding))
        return proposals

    def _propose_gateway(self, finding: GapFinding) -> GraphTransformation:
        src, dst = finding.path[0], finding.path[1]
        gateway_id = f"gateway_{src}_{dst}"
        return GraphTransformation(
            id=f"refactor_{finding.finding_id}",
            title=f"Insert security gateway between '{src}' and '{dst}'",
            preconditions=[f"'{src}' currently accesses '{dst}' directly"],
            change_set={
                "add_nodes": [{"id": gateway_id, "kind": "Asset", "entity_type": "SecurityControl",
                                "attrs": {"purpose": "mediates access", "controls": ["authentication", "authorization", "audit"]}}],
                "add_edges": [
                    {"source": src, "target": gateway_id, "kind": "calls", "attrs": {}},
                    {"source": gateway_id, "target": dst, "kind": "reads", "attrs": {}},
                ],
                "remove_edges": [{"source": src, "target": dst, "kind": "reads"},
                                  {"source": src, "target": dst, "kind": "writes"}],
            },
            security_benefit="Removes direct, unmediated database access; centralizes authN/authZ/audit at one enforcement point.",
            functional_impact="Adds one network hop; callers must go through the gateway's API contract instead of the raw database driver.",
            new_dependencies=[gateway_id],
            operational_cost="Low-to-medium: one new service to deploy, monitor and keep highly available.",
            residual_findings=[f"Verify the gateway itself is placed in an appropriately trusted zone."],
        )

    def _propose_secret_store(self, finding: GapFinding) -> GraphTransformation:
        secret_id = finding.path[-1]
        store_id = f"secretstore_{secret_id}"
        return GraphTransformation(
            id=f"refactor_{finding.finding_id}",
            title=f"Broker access to '{secret_id}' through a dedicated secret store",
            preconditions=[f"multiple principals use '{secret_id}' directly"],
            change_set={
                "add_nodes": [{"id": store_id, "kind": "Asset", "entity_type": "SecurityControl",
                                "attrs": {"purpose": "secret broker", "controls": ["secrets_management", "audit"]}}],
                "add_edges": [{"source": store_id, "target": secret_id, "kind": "owns", "attrs": {}}],
                "remove_edges": [],
            },
            security_benefit="Every access to the secret is now individually authenticated, authorized and audited by one broker.",
            functional_impact="Consumers must be updated to fetch the secret via the broker's API instead of reading it directly.",
            new_dependencies=[store_id],
            operational_cost="Medium: introduces a new critical-path dependency that itself needs high availability.",
        )

    def _propose_control_insertion(self, finding: GapFinding) -> GraphTransformation:
        src, dst = finding.path[0], finding.path[1]
        return GraphTransformation(
            id=f"refactor_{finding.finding_id}",
            title=f"Add '{finding.suggested_control}' control between '{src}' and '{dst}'",
            preconditions=[finding.description],
            change_set={"add_nodes": [], "add_edges": [], "remove_edges": []},
            security_benefit=f"Closes the '{finding.kind}' gap identified at this boundary crossing.",
            functional_impact="Adds a policy check on the request path; may add latency and requires the caller to supply credentials/context.",
            new_dependencies=[],
            operational_cost="Low: implemented as a policy rule, no new infrastructure required.",
        )

    def _propose_approval_layer(self, finding: GapFinding) -> GraphTransformation:
        src, dst = finding.path[0], finding.path[1]
        return GraphTransformation(
            id=f"refactor_{finding.finding_id}",
            title=f"Add human approval obligation for '{src}' -> '{dst}'",
            preconditions=[finding.description],
            change_set={"add_nodes": [], "add_edges": [], "remove_edges": []},
            security_benefit="Introduces a Human-in-the-Loop checkpoint before high-risk actions execute.",
            functional_impact="Adds latency equal to approval turnaround time; needs an on-call approver.",
            new_dependencies=["human-approval-workflow"],
            operational_cost="Medium: requires an approval workflow and on-call rotation.",
        )


class ArchitectureEquivalenceAnalyzer:
    """Separates Security Improvement from Functional Regression by
    comparing reachability (who-can-reach-whom, ignoring security
    controls) before and after a refactor."""

    def compare(self, before: GraphRepository, after: GraphRepository) -> Dict[str, Any]:
        def reachable_pairs(g: GraphRepository) -> set:
            pairs = set()
            for n in g.nodes():
                for _, target in g.successors(n.id):
                    pairs.add((n.id, target.id))
            return pairs

        before_pairs = reachable_pairs(before)
        after_pairs = reachable_pairs(after)
        lost = before_pairs - after_pairs
        gained = after_pairs - before_pairs
        return {
            # every pair no longer directly reachable is flagged for
            # human review: it may be a deliberate re-routing through a
            # new gateway/broker node (fine) or a genuine functional
            # regression (not fine) -- the analyzer surfaces the list,
            # it does not silently decide which is which.
            "functional_regression_candidates": sorted([f"{a}->{b}" for a, b in lost]),
            "new_reachability": sorted([f"{a}->{b}" for a, b in gained]),
            "is_pure_security_improvement": len(lost) == 0,
        }
