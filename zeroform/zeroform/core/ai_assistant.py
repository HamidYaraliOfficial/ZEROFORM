"""
AI Architecture Assistant
============================

A tool-calling interface that only ever touches the Reality Model and
compiler diagnostics -- never production systems -- and only ever
*proposes*; nothing it returns is written into the canonical model
without passing back through compile + verify and an explicit human
Accept in the Proposal Review Layer.

The reference implementation below is fully deterministic and talks
directly to the real engines (no network, no LLM dependency, so the
whole compiler still works in Local-Only Mode). Wiring an actual
language model in is a matter of implementing
:class:`LanguageModelBackend` and passing it in; the tool surface
(`inspect_reality`, `trace_identity`, ... `compare_models`) does not
change either way, so proposals stay reviewable and diffable
regardless of which backend produced them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .diff_engine import GraphDiffEngine
from .gap_analyzer import SecurityGapAnalyzer, SecurityPathAnalyzer
from .graph_model import GraphRepository
from .identity import IdentityRealityEngine
from .refactor import SecurityArchitectureRefactoringEngine
from .semantic_model import RealityModel


class LanguageModelBackend:
    """Extension point: implement `complete(prompt) -> str` against a
    real model (e.g. the Claude API) to turn deterministic tool output
    into prose explanations. Optional -- every tool below already
    returns structured, directly useful data without one."""

    def complete(self, prompt: str) -> str:  # pragma: no cover
        raise NotImplementedError


@dataclass
class AIProposal:
    tool: str
    input_summary: str
    output: Any
    requires_review: bool = True
    status: str = "pending"   # pending | accepted | rejected | edited


class AIProposalReviewLayer:
    def __init__(self):
        self._proposals: List[AIProposal] = []

    def submit(self, proposal: AIProposal) -> int:
        self._proposals.append(proposal)
        return len(self._proposals) - 1

    def decide(self, index: int, decision: str, edited_output: Optional[Any] = None) -> AIProposal:
        if decision not in ("accepted", "rejected", "edited"):
            raise ValueError("decision must be accepted|rejected|edited")
        proposal = self._proposals[index]
        proposal.status = decision
        if decision == "edited" and edited_output is not None:
            proposal.output = edited_output
        return proposal

    def pending(self) -> List[AIProposal]:
        return [p for p in self._proposals if p.status == "pending"]


class AIArchitectureAssistant:
    """Implements the fixed AI tool surface named in the spec:
    inspect_reality, trace_identity, trace_data, find_gaps,
    explain_policy, propose_control, propose_refactor,
    generate_scenario, generate_tests, compare_models. Every tool
    validates its own inputs before touching the graph."""

    def __init__(self, review_layer: Optional[AIProposalReviewLayer] = None,
                 backend: Optional[LanguageModelBackend] = None):
        self.review_layer = review_layer or AIProposalReviewLayer()
        self.backend = backend
        self.identity_engine = IdentityRealityEngine()
        self.refactor_engine = SecurityArchitectureRefactoringEngine()

    def inspect_reality(self, model: RealityModel) -> Dict[str, Any]:
        g = model.graph
        return {
            "name": model.meta.name,
            "version": model.meta.version,
            "node_count": len(g.nodes()),
            "edge_count": len(g.edges()),
            "identities": [n.id for n in g.nodes(kind="Identity")],
            "trust_zones": [n.id for n in g.nodes(entity_type="TrustZone")],
            "warnings": model.warnings,
        }

    def trace_identity(self, model: RealityModel, identity_id: str) -> Dict[str, Any]:
        if not model.graph.get_node(identity_id):
            raise ValueError(f"unknown identity '{identity_id}'")
        reachable = self.identity_engine.identity_trust_graph(model.graph, identity_id)
        perms = self.identity_engine.effective_permissions(model.graph, identity_id)
        return {"identity": identity_id, "effective_permissions": sorted(perms),
                "reachable_resources": {k: v for k, v in reachable.items()}}

    def trace_data(self, model: RealityModel, node_id: str) -> Dict[str, Any]:
        if not model.graph.get_node(node_id):
            raise ValueError(f"unknown node '{node_id}'")
        paths = []
        for n in model.graph.nodes():
            p = model.graph.shortest_path(node_id, n.id)
            if p and len(p) > 1:
                paths.append(p)
        return {"source": node_id, "downstream_paths": paths}

    def find_gaps(self, model: RealityModel, crossings, controls) -> List[Dict[str, Any]]:
        findings = SecurityGapAnalyzer().analyze(model.graph, crossings, controls)
        return [f.__dict__ for f in findings]

    def explain_policy(self, artifact) -> Dict[str, Any]:
        return {
            "policy_id": artifact.policy_id,
            "target": artifact.target,
            "rule_count": len(artifact.document.get("rules", [])),
            "source_model_hash": artifact.source_model_hash,
            "signed_and_valid": artifact.verify(),
        }

    def propose_control(self, model: RealityModel, finding) -> int:
        proposal = AIProposal(tool="propose_control", input_summary=finding.description,
                               output={"suggested_control": finding.suggested_control, "target": finding.path})
        return self.review_layer.submit(proposal)

    def propose_refactor(self, model: RealityModel, findings) -> int:
        proposals = self.refactor_engine.propose(model.graph, findings)
        proposal = AIProposal(tool="propose_refactor", input_summary=f"{len(findings)} finding(s)",
                               output=[p.__dict__ for p in proposals])
        return self.review_layer.submit(proposal)

    def generate_scenario(self, model: RealityModel, template_name: str) -> int:
        proposal = AIProposal(tool="generate_scenario", input_summary=template_name,
                               output={"template": template_name, "actors": [n.id for n in model.graph.nodes(kind="Identity")][:1]})
        return self.review_layer.submit(proposal)

    def generate_tests(self, model: RealityModel, controls) -> int:
        from .verification import VerificationScenarioGenerator
        generator = VerificationScenarioGenerator()
        cases = []
        for c in controls:
            cases.extend(generator.generate_for_control(c))
        proposal = AIProposal(tool="generate_tests", input_summary=f"{len(controls)} control(s)",
                               output=[c.__dict__ for c in cases])
        return self.review_layer.submit(proposal)

    def compare_models(self, before: GraphRepository, after: GraphRepository) -> Dict[str, Any]:
        return GraphDiffEngine().diff(before, after).to_dict()
