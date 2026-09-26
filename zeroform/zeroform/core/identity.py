"""
Identity Reality Engine + Privilege Propagation Engine
=========================================================

Models Users, Service Identities, Workload Identities, API Clients,
Device Identities and AI Agent Identities uniformly as ``Identity``
nodes, and walks Role / Group / Service-Account / Delegation / Token
Exchange edges to compute each identity's *effective* reachable
resource set -- surfacing Excessive Privilege, Transitive Privilege,
Orphan Permissions, Privilege Chains and Dangerous Delegations.

The role -> permission table is intentionally a small, overridable
default; production deployments are expected to import their real
IAM policy (see the SBOM/IAM-export importer) instead of hand
maintaining it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from .graph_model import GraphRepository

DEFAULT_ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "Admin": {"read", "write", "delete", "approve", "manage_secrets", "manage_identities"},
    "Operator": {"read", "write"},
    "Auditor": {"read"},
    "ServiceAccount": {"read", "write"},
    "ReadOnly": {"read"},
}

DANGEROUS_PERMISSIONS = {"manage_secrets", "manage_identities", "delete", "approve"}


@dataclass
class PrivilegeFinding:
    identity_id: str
    kind: str            # excessive_privilege | transitive_privilege | orphan_permission | dangerous_delegation
    detail: str
    severity: str         # low | medium | high | critical
    path: List[str] = field(default_factory=list)


class IdentityRealityEngine:
    def __init__(self, role_permissions: Dict[str, Set[str]] = None):
        self.role_permissions = {k: set(v) for k, v in (role_permissions or DEFAULT_ROLE_PERMISSIONS).items()}

    def effective_permissions(self, graph: GraphRepository, identity_id: str) -> Set[str]:
        node = graph.get_node(identity_id)
        if not node:
            return set()
        roles = node.attrs.get("roles", [])
        if isinstance(roles, str):
            roles = [roles]
        perms: Set[str] = set()
        for role in roles:
            perms |= self.role_permissions.get(str(role), set())
        # delegated permissions (delegates_to edges bring the
        # delegate's permissions along, transitively, bounded depth).
        visited: Set[str] = {identity_id}
        frontier = [t.id for _, t in graph.successors(identity_id, kind="delegates_to")]
        depth = 0
        while frontier and depth < 6:
            nxt = []
            for nid in frontier:
                if nid in visited:
                    continue
                visited.add(nid)
                other = graph.get_node(nid)
                if other:
                    other_roles = other.attrs.get("roles", [])
                    if isinstance(other_roles, str):
                        other_roles = [other_roles]
                    for role in other_roles:
                        perms |= self.role_permissions.get(str(role), set())
                nxt.extend([t.id for _, t in graph.successors(nid, kind="delegates_to")])
            frontier = nxt
            depth += 1
        return perms

    def identity_trust_graph(self, graph: GraphRepository, identity_id: str) -> Dict[str, List[str]]:
        """Returns, for the given identity, the set of resource ids it
        can reach and the boundary-crossing path used to get there
        (via calls/uses/reads/writes edges, transitively)."""
        reachable: Dict[str, List[str]] = {}
        seen: Set[str] = set()
        stack = [(identity_id, [identity_id])]
        while stack:
            current, path = stack.pop()
            if current in seen and current != identity_id:
                continue
            seen.add(current)
            for edge, target in graph.successors(current):
                if edge.kind in ("calls", "uses", "reads", "writes", "publishes", "subscribes"):
                    if target.id not in reachable:
                        reachable[target.id] = path + [target.id]
                    if len(path) < 8:
                        stack.append((target.id, path + [target.id]))
        return reachable


class PrivilegePropagationEngine:
    def __init__(self, identity_engine: IdentityRealityEngine):
        self.identity_engine = identity_engine

    def analyze(self, graph: GraphRepository) -> List[PrivilegeFinding]:
        findings: List[PrivilegeFinding] = []
        identities = graph.nodes(kind="Identity")

        for identity in identities:
            perms = self.identity_engine.effective_permissions(graph, identity.id)
            dangerous = perms & DANGEROUS_PERMISSIONS

            zone_hint = identity.attrs.get("trust_zone", "Internet")
            if dangerous and zone_hint in ("Internet", "Untrusted", "ExternalPartner", "UserDevice"):
                findings.append(PrivilegeFinding(
                    identity_id=identity.id, kind="excessive_privilege", severity="critical",
                    detail=f"identity in low-trust zone '{zone_hint}' holds dangerous permissions {sorted(dangerous)}",
                    path=[identity.id],
                ))

            # transitive privilege via delegation chains longer than 2
            chain = self._delegation_chain(graph, identity.id)
            if len(chain) > 2:
                findings.append(PrivilegeFinding(
                    identity_id=identity.id, kind="privilege_chain", severity="medium",
                    detail=f"delegation chain of length {len(chain)}: {' -> '.join(chain)}",
                    path=chain,
                ))

            # orphan permission: identity has roles but no owner and no zone
            if identity.attrs.get("roles") and "owns" not in [e.kind for e, _ in graph.predecessors(identity.id)]:
                findings.append(PrivilegeFinding(
                    identity_id=identity.id, kind="orphan_permission", severity="low",
                    detail="identity holds roles/permissions but has no recorded owner",
                    path=[identity.id],
                ))

        # dangerous delegation: X delegates dangerous perms to a lower-trust identity
        for edge in graph.edges(kind="delegates_to"):
            src_perms = self.identity_engine.effective_permissions(graph, edge.source)
            if src_perms & DANGEROUS_PERMISSIONS:
                target = graph.get_node(edge.target)
                if target and target.attrs.get("trust_zone") in ("Internet", "Untrusted", "ExternalPartner"):
                    findings.append(PrivilegeFinding(
                        identity_id=edge.source, kind="dangerous_delegation", severity="high",
                        detail=f"'{edge.source}' delegates to low-trust identity '{edge.target}'",
                        path=[edge.source, edge.target],
                    ))
        return findings

    def _delegation_chain(self, graph: GraphRepository, identity_id: str) -> List[str]:
        chain = [identity_id]
        current = identity_id
        visited = {identity_id}
        while True:
            nxt = graph.successors(current, kind="delegates_to")
            if not nxt:
                break
            _, target = nxt[0]
            if target.id in visited:
                break
            chain.append(target.id)
            visited.add(target.id)
            current = target.id
        return chain
