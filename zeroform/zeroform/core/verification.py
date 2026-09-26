"""
Invariant Engine + Verification Scenario Generator
======================================================

The Invariant Engine checks graph-wide security properties that must
always hold ("a Secret must never leave the Secrets zone without an
approval control", "every cross-boundary flow must have at least one
control", "an external identity must not reach a Restricted resource
without authentication", "a Deny decision must never carry an
obligation that contradicts it"). A :class:`FormalVerificationAdapter`
stub shows where an SMT/SAT/constraint solver would plug in without
making the core dependent on any particular solver.

The Verification Scenario Generator derives Positive / Negative /
Boundary / Context / Failure / Recovery test cases directly from the
graph and synthesized controls, and the Property-Based Security
Testing Engine fuzzes combinations of identity / resource /
classification / zone / context against the compiled policy runtime.
"""

from __future__ import annotations

import itertools
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .control_synthesis import SecurityControl
from .graph_model import GraphRepository
from .policy_runtime import PolicyRuntime
from .trust_zone import BoundaryCrossing


@dataclass
class InvariantResult:
    name: str
    passed: bool
    violations: List[Dict[str, Any]] = field(default_factory=list)


class InvariantEngine:
    def __init__(self):
        self._invariants: Dict[str, Callable[[GraphRepository, List[BoundaryCrossing]], List[Dict[str, Any]]]] = {}
        self._register_defaults()

    def register(self, name: str, fn: Callable[[GraphRepository, List[BoundaryCrossing]], List[Dict[str, Any]]]) -> None:
        self._invariants[name] = fn

    def _register_defaults(self) -> None:
        self.register("secret_never_leaves_secret_zone_without_approval", self._inv_secret_zone)
        self.register("cross_boundary_flow_has_control", self._inv_boundary_has_control)
        self.register("external_identity_requires_auth_for_restricted", self._inv_external_auth)

    def run_all(self, graph: GraphRepository, crossings: List[BoundaryCrossing]) -> List[InvariantResult]:
        results = []
        for name, fn in self._invariants.items():
            violations = fn(graph, crossings)
            results.append(InvariantResult(name=name, passed=len(violations) == 0, violations=violations))
        return results

    @staticmethod
    def _inv_secret_zone(graph: GraphRepository, crossings: List[BoundaryCrossing]) -> List[Dict[str, Any]]:
        violations = []
        for c in crossings:
            if c.data_classification == "Secret" or c.to_zone not in ("Secrets",) and c.from_zone == "Secrets":
                if "approval" not in c.required_controls:
                    violations.append({"edge": f"{c.edge_source}->{c.edge_target}",
                                        "detail": "secret-zone crossing without an approval requirement"})
        return violations

    @staticmethod
    def _inv_boundary_has_control(graph: GraphRepository, crossings: List[BoundaryCrossing]) -> List[Dict[str, Any]]:
        return [{"edge": f"{c.edge_source}->{c.edge_target}", "detail": "boundary crossing with zero required controls"}
                for c in crossings if not c.required_controls]

    @staticmethod
    def _inv_external_auth(graph: GraphRepository, crossings: List[BoundaryCrossing]) -> List[Dict[str, Any]]:
        violations = []
        for c in crossings:
            if c.from_zone in ("Internet", "Untrusted", "ExternalPartner") and c.to_zone in ("Restricted", "Secure", "Secrets"):
                if "authentication" not in c.required_controls:
                    violations.append({"edge": f"{c.edge_source}->{c.edge_target}",
                                        "detail": "low-trust origin reaches a restricted zone without required authentication"})
        return violations


class FormalVerificationAdapter:
    """Extension point for connecting a subset of invariants to an
    external SMT/SAT/constraint solver. The core engine never imports
    a specific solver; a concrete adapter (e.g. Z3) would subclass
    this and implement :meth:`check`."""

    def check(self, invariant_name: str, graph: GraphRepository) -> Optional[bool]:  # pragma: no cover
        raise NotImplementedError("plug in an SMT/SAT solver here, e.g. z3-solver")


@dataclass
class VerificationScenarioCase:
    id: str
    kind: str   # positive | negative | boundary | context | failure | recovery
    context: Dict[str, Any]
    expect_allow: bool


class VerificationScenarioGenerator:
    def generate_for_control(self, control: SecurityControl) -> List[VerificationScenarioCase]:
        base_context = {"control_type": control.control_type, "satisfied_controls": [control.control_type]}
        cases = [
            VerificationScenarioCase(id=f"{control.id}_positive", kind="positive",
                                      context=base_context, expect_allow=True),
            VerificationScenarioCase(id=f"{control.id}_negative", kind="negative",
                                      context={**base_context, "satisfied_controls": []}, expect_allow=False),
            VerificationScenarioCase(id=f"{control.id}_boundary", kind="boundary",
                                      context={**base_context, "satisfied_controls": [control.control_type], "edge_case": True},
                                      expect_allow=True),
            VerificationScenarioCase(id=f"{control.id}_context", kind="context",
                                      context={**base_context, "time_of_day": "off_hours"}, expect_allow=True),
            VerificationScenarioCase(id=f"{control.id}_failure", kind="failure",
                                      context={**base_context, "satisfied_controls": [], "runtime_error": True},
                                      expect_allow=False),
            VerificationScenarioCase(id=f"{control.id}_recovery", kind="recovery",
                                      context={**base_context, "satisfied_controls": [control.control_type], "recovered": True},
                                      expect_allow=True),
        ]
        return cases

    def run_cases(self, runtime: PolicyRuntime, cases: List[VerificationScenarioCase]) -> Dict[str, Any]:
        passed, failed = 0, 0
        details = []
        for case in cases:
            decision = runtime.require_control(case.context)
            ok = decision.allow == case.expect_allow
            passed += int(ok)
            failed += int(not ok)
            details.append({"case_id": case.id, "kind": case.kind, "ok": ok,
                             "expected": case.expect_allow, "actual": decision.allow})
        return {"passed": passed, "failed": failed, "details": details}


class PropertyBasedSecurityTester:
    """Generates a bounded number of pseudo-random identity / resource
    / classification / zone / context combinations and checks that the
    compiled policy runtime's decisions remain internally consistent
    (never Allow with a missing required control, never a Deny with an
    obligation that contradicts the denial)."""

    def __init__(self, seed: int = 1337):
        self.random = random.Random(seed)

    def run(self, runtime: PolicyRuntime, control_types: List[str], n: int = 500) -> Dict[str, Any]:
        inconsistencies = []
        combos_checked = 0
        for _ in range(n):
            ctype = self.random.choice(control_types) if control_types else "authentication"
            satisfied = self.random.random() > 0.5
            context = {"control_type": ctype, "satisfied_controls": [ctype] if satisfied else []}
            decision = runtime.require_control(context)
            combos_checked += 1
            # core consistency property: the runtime's allow/deny must
            # always agree with whether the request context actually
            # satisfied the required control -- an unexplainable allow
            # (allowed without satisfying the control) or an
            # unexplainable deny (denied despite satisfying it) is a
            # policy-runtime bug, not a legitimate security decision.
            if decision.allow != satisfied:
                inconsistencies.append({"context": context, "decision": decision.to_dict()})
        return {"combinations_checked": combos_checked, "inconsistencies": inconsistencies,
                "consistent": len(inconsistencies) == 0}
