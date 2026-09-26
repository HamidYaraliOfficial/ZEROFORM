"""
Policy Mutation Engine + Security Mutation Testing Framework
================================================================

Deliberately mutates a compiled policy document (drop a rule, weaken
a control type, flip a failure mode) and re-runs the verification
suite to see whether it is actually capable of catching the
regression. A mutation that survives (i.e. is not detected) means the
verification suite has a blind spot -- this measures the quality of
the *tests*, not just the *policy*.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .policy_generator import PolicyArtifact
from .policy_runtime import PolicyRuntime
from .verification import VerificationScenarioCase, VerificationScenarioGenerator


@dataclass
class Mutation:
    id: str
    description: str
    mutate_fn_name: str


@dataclass
class MutationResult:
    mutation: Mutation
    killed: bool
    detail: str


class PolicyMutationEngine:
    MUTATIONS = [
        Mutation("drop_authentication_rule", "Remove all authentication rules from the policy", "_drop_rule_type"),
        Mutation("weaken_deny_to_allow", "Flip failure_mode from 'deny' to 'allow' on every rule", "_weaken_failure_mode"),
        Mutation("remove_audit_rule", "Remove all audit rules", "_drop_audit"),
        Mutation("expand_permissions", "Mark every control type as pre-satisfied (simulates over-broad permission grant)", "_expand_satisfaction"),
    ]

    def mutate(self, artifact: PolicyArtifact, mutation: Mutation) -> PolicyArtifact:
        mutated_doc = copy.deepcopy(artifact.document)
        fn = getattr(self, mutation.mutate_fn_name)
        mutated_doc = fn(mutated_doc)
        mutant = PolicyArtifact(
            policy_id=f"{artifact.policy_id}_mut_{mutation.id}",
            target=artifact.target,
            version=artifact.version + "-mutant",
            compiler_version=artifact.compiler_version,
            source_model_hash=artifact.source_model_hash,
            document=mutated_doc,
        )
        mutant.sign()
        return mutant

    @staticmethod
    def _drop_rule_type(doc: Dict[str, Any]) -> Dict[str, Any]:
        doc["rules"] = [r for r in doc.get("rules", []) if r.get("control_type") != "authentication"]
        return doc

    @staticmethod
    def _drop_audit(doc: Dict[str, Any]) -> Dict[str, Any]:
        doc["rules"] = [r for r in doc.get("rules", []) if r.get("control_type") != "audit"]
        return doc

    @staticmethod
    def _weaken_failure_mode(doc: Dict[str, Any]) -> Dict[str, Any]:
        for r in doc.get("rules", []):
            r["failure_mode"] = "allow"
        return doc

    @staticmethod
    def _expand_satisfaction(doc: Dict[str, Any]) -> Dict[str, Any]:
        # marker consumed by a permissive-runtime variant in tests;
        # not used by the standard PolicyRuntime evaluation path.
        doc["_all_pre_satisfied"] = True
        return doc


class SecurityMutationTestingFramework:
    def __init__(self, mutation_engine: PolicyMutationEngine, scenario_generator: VerificationScenarioGenerator):
        self.mutation_engine = mutation_engine
        self.scenario_generator = scenario_generator

    def run(self, artifact: PolicyArtifact, control_types: List[str]) -> Dict[str, Any]:
        results: List[MutationResult] = []
        for mutation in self.mutation_engine.MUTATIONS:
            mutant_artifact = self.mutation_engine.mutate(artifact, mutation)
            mutant_runtime = PolicyRuntime(mutant_artifact, fail_safe="deny")
            mutant_runtime.load()

            killed = False
            detail = "not detected by any generated verification case"
            for ctype in control_types:
                cases = self._synthetic_cases(ctype)
                for case in cases:
                    decision = mutant_runtime.require_control(case.context)
                    if decision.allow != case.expect_allow:
                        killed = True
                        detail = f"case '{case.id}' expected allow={case.expect_allow}, mutant returned {decision.allow}"
                        break
                if killed:
                    break
            results.append(MutationResult(mutation=mutation, killed=killed, detail=detail))

        total = len(results)
        killed_count = sum(1 for r in results if r.killed)
        score = killed_count / total if total else 1.0
        return {
            "mutation_score": score,
            "results": [{"mutation_id": r.mutation.id, "description": r.mutation.description,
                         "killed": r.killed, "detail": r.detail} for r in results],
        }

    @staticmethod
    def _synthetic_cases(control_type: str) -> List[VerificationScenarioCase]:
        base = {"control_type": control_type, "satisfied_controls": [control_type]}
        return [
            VerificationScenarioCase(id=f"{control_type}_positive", kind="positive", context=base, expect_allow=True),
            VerificationScenarioCase(id=f"{control_type}_negative", kind="negative",
                                      context={**base, "satisfied_controls": []}, expect_allow=False),
        ]
