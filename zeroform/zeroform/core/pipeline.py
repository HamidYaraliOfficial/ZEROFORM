"""
Reality Model Compiler Pipeline
==================================

Runs the full, documented stage sequence::

    Lex/Parse -> AST -> Semantic Model -> Graph Build ->
    Security Analysis -> Control Synthesis -> Policy Compilation ->
    Simulation Model -> Verification -> Artifact Generation

Every stage's output is captured in :class:`PipelineResult.stages` so
each intermediate representation can be inspected/debugged
independently (``zeroform compile --explain`` in the CLI dumps this).
Given a fixed input model, rule set, compiler version and
dependencies, :meth:`CompilerPipeline.run` is deterministic: the same
input hash always yields the same generated-artifact hashes, which is
what the Compiler Determinism Guarantee + Regression Suite check.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .. import COMPILER_VERSION
from ..dsl.ast_nodes import Module
from ..dsl.parser import parse_source
from .classification import ClassificationEngine
from .compliance import ComplianceMappingLayer
from .control_synthesis import ControlSynthesisEngine, SecurityControl
from .gap_analyzer import DataExposureSimulator, GapFinding, SecurityGapAnalyzer, SecurityPathAnalyzer
from .graph_model import GraphRepository
from .identity import IdentityRealityEngine, PrivilegePropagationEngine
from .policy_generator import PolicyArtifact, PolicyGenerator, hash_model
from .semantic_model import RealityModel, build_semantic_model
from .trust_zone import BoundaryCrossing, TrustBoundaryCompiler, TrustZoneEngine
from .verification import InvariantEngine, InvariantResult


@dataclass
class PipelineResult:
    model: RealityModel
    crossings: List[BoundaryCrossing]
    controls: List[SecurityControl]
    policies: List[PolicyArtifact]
    findings: List[GapFinding]
    invariant_results: List[InvariantResult]
    source_model_hash: str
    stages: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0
    compiler_version: str = COMPILER_VERSION


class CompilerPipeline:
    def __init__(self, backend: str = "networkx", policy_targets: Optional[List[str]] = None,
                 fail_safe: str = "deny"):
        self.backend = backend
        self.policy_targets = policy_targets or ["json", "wasm"]
        self.fail_safe = fail_safe
        self.classifier = ClassificationEngine()
        self.zone_engine = TrustZoneEngine()
        self.boundary_compiler = TrustBoundaryCompiler(self.zone_engine, self.classifier)
        self.control_engine = ControlSynthesisEngine()
        self.policy_generator = PolicyGenerator()
        self.gap_analyzer = SecurityGapAnalyzer()
        self.identity_engine = IdentityRealityEngine()
        self.privilege_engine = PrivilegePropagationEngine(self.identity_engine)
        self.path_analyzer = SecurityPathAnalyzer(self.classifier, self.boundary_compiler)
        self.exposure_simulator = DataExposureSimulator(self.boundary_compiler)
        self.invariant_engine = InvariantEngine()
        self.compliance_layer = ComplianceMappingLayer()

    def compile_source(self, source: str, source_name: str = "<memory>") -> PipelineResult:
        module = parse_source(source, source_name=source_name)
        return self.compile_module(module)

    def compile_module(self, module: Module) -> PipelineResult:
        t0 = time.time()
        stages: Dict[str, Any] = {"1_ast": module.to_dict()}

        model = build_semantic_model(module, backend=self.backend)
        stages["2_semantic_model"] = {"meta": model.meta.__dict__, "warnings": model.warnings}
        stages["3_graph_build"] = model.graph.to_dict()

        crossings = self.boundary_compiler.compile_crossings(model.graph)
        privilege_findings = self.privilege_engine.analyze(model.graph)
        paths = self.path_analyzer.analyze(model.graph)
        stages["4_security_analysis"] = {
            "boundary_crossings": [c.__dict__ for c in crossings],
            "privilege_findings": [p.__dict__ for p in privilege_findings],
            "sensitive_paths": [p.__dict__ for p in paths],
        }

        controls = self.control_engine.synthesize(crossings)
        stages["5_control_synthesis"] = [c.to_dict() for c in controls]

        source_model_hash = hash_model(model.to_dict())
        policies = self.policy_generator.generate(controls, source_model_hash, targets=self.policy_targets)
        stages["6_policy_compilation"] = [p.to_dict() for p in policies]

        # simulation model stage is a placeholder snapshot; the actual
        # Virtual Security Environment / Scenario Execution Engine is
        # driven separately (see zeroform.core.virtual_env) since it
        # is stateful across many runs, not a single compile pass.
        stages["7_simulation_model"] = {
            "branchable_snapshot_hash": source_model_hash,
            "scenario_templates_available": True,
        }

        invariant_results = self.invariant_engine.run_all(model.graph, crossings)
        findings = self.gap_analyzer.analyze(model.graph, crossings, controls)
        stages["8_verification"] = {
            "invariants": [{"name": r.name, "passed": r.passed, "violations": r.violations} for r in invariant_results],
            "gap_findings": [f.__dict__ for f in findings],
        }

        compliance_mappings = self.compliance_layer.map_control_types([c.control_type for c in controls])
        stages["9_artifact_generation"] = {
            "policy_artifact_ids": [p.policy_id for p in policies],
            "compliance_mappings": [m.to_dict() for m in compliance_mappings],
        }

        duration = time.time() - t0
        return PipelineResult(
            model=model, crossings=crossings, controls=controls, policies=policies,
            findings=findings, invariant_results=invariant_results,
            source_model_hash=source_model_hash, stages=stages, duration_seconds=duration,
        )
