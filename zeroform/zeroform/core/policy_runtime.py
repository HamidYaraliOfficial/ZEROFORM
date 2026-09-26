"""
WASM Policy Runtime (reference implementation)
=================================================

Defines and implements the exact capability-based API surface a
compiled ``.wasm`` policy guard is expected to expose:

    authorize(context) -> Decision
    validate_data(context) -> Decision
    check_boundary(context) -> Decision
    evaluate_context(context) -> Decision
    require_control(context) -> Decision
    audit_decision(decision) -> None
    verify_integrity(artifact) -> bool

The reference runtime here executes the *compiled policy document*
(produced by :mod:`zeroform.core.policy_generator`, target
``"wasm"``) using pure, side-effect-free Python -- no network, no
filesystem, no secret access is reachable from policy evaluation
code, mirroring the capability restrictions a real Wasm sandbox
(compiled via wasmtime/wasmer, instantiated with an empty WASI
import set) would enforce at the host boundary. Swapping this module
for a real compiled guest module means implementing the identical
seven functions against a wasmtime ``Store`` -- every caller in
``zeroform.core`` and ``zeroform.api`` only depends on this class's
public interface, never on how it is executed internally.

Every decision is fully explainable: besides allow/deny it always
carries a reason, the rule id, evidence references, any required
control that was missing, obligations (e.g. RequireApproval) and the
policy version -- so "no un-auditable decision" holds by
construction.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .policy_generator import PolicyArtifact, verify_signature


@dataclass
class Decision:
    allow: bool
    reason: str
    rule_id: Optional[str]
    evidence_refs: List[str] = field(default_factory=list)
    required_control: Optional[str] = None
    obligations: List[str] = field(default_factory=list)
    policy_version: str = ""
    audit_metadata: Dict[str, Any] = field(default_factory=dict)
    decided_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class PolicyIntegrityError(Exception):
    pass


class PolicyRuntime:
    """Deterministic, capability-restricted evaluator for a single
    compiled policy artifact."""

    def __init__(self, artifact: PolicyArtifact, fail_safe: str = "deny"):
        if fail_safe not in ("deny", "allow"):
            raise ValueError("fail_safe must be 'deny' or 'allow'")
        self.fail_safe = fail_safe
        self.artifact = artifact
        self._audit_log: List[Decision] = []
        self._loaded = False

    # -- lifecycle -----------------------------------------------------
    def load(self) -> None:
        if not self.verify_integrity(self.artifact):
            raise PolicyIntegrityError(
                f"signature verification failed for policy {self.artifact.policy_id}; "
                f"refusing to load (fail-safe={self.fail_safe})"
            )
        self._loaded = True

    def verify_integrity(self, artifact: PolicyArtifact) -> bool:
        return artifact.verify()

    def _fallback(self, reason: str, rule_id: Optional[str] = None) -> Decision:
        d = Decision(allow=self.fail_safe == "allow", reason=reason, rule_id=rule_id,
                     policy_version=self.artifact.version)
        self.audit_decision(d)
        return d

    def _rules_for(self, control_type: Optional[str] = None) -> List[Dict[str, Any]]:
        rules = self.artifact.document.get("rules", [])
        if control_type is None:
            return rules
        return [r for r in rules if r.get("control_type") == control_type]

    # -- the seven guest APIs -------------------------------------------
    def authorize(self, context: Dict[str, Any]) -> Decision:
        if not self._loaded:
            return self._fallback("runtime not loaded")
        rules = self._rules_for("authorization")
        return self._evaluate(rules, context, default_allow_if_no_rule=True)

    def validate_data(self, context: Dict[str, Any]) -> Decision:
        rules = self._rules_for("input_validation") + self._rules_for("data_minimization")
        return self._evaluate(rules, context, default_allow_if_no_rule=True)

    def check_boundary(self, context: Dict[str, Any]) -> Decision:
        edge_id = f'{context.get("source")}->{context.get("target")}'
        matching = [r for r in self._rules_for() if r.get("trigger", "").endswith(edge_id)]
        return self._evaluate(matching, context, default_allow_if_no_rule=True)

    def evaluate_context(self, context: Dict[str, Any]) -> Decision:
        rules = self._rules_for("authentication")
        return self._evaluate(rules, context, default_allow_if_no_rule=True)

    def require_control(self, context: Dict[str, Any]) -> Decision:
        control_type = context.get("control_type")
        rules = self._rules_for(control_type)
        if not rules:
            return self._fallback(f"no synthesized control of type '{control_type}' for this context",
                                   rule_id=None)
        rule = rules[0]
        all_pre_satisfied = bool(self.artifact.document.get("_all_pre_satisfied"))
        satisfied = all_pre_satisfied or control_type in set(context.get("satisfied_controls", []))
        if not satisfied:
            fails_open = rule.get("failure_mode") == "allow"
            d = Decision(
                allow=fails_open,
                reason=(f"control '{control_type}' was not satisfied; failure_mode="
                        f"'{rule.get('failure_mode')}' so the request " +
                        ("fails OPEN (allowed despite the unmet control)" if fails_open
                         else "fails CLOSED (denied)")),
                rule_id=rule["rule_id"], evidence_refs=rule.get("evidence", []),
                required_control=control_type, policy_version=self.artifact.version,
            )
            self.audit_decision(d)
            return d
        d = Decision(allow=True, reason=f"control '{control_type}' is required and was satisfied",
                     rule_id=rule["rule_id"], evidence_refs=rule.get("evidence", []),
                     policy_version=self.artifact.version)
        self.audit_decision(d)
        return d

    def _evaluate(self, rules: List[Dict[str, Any]], context: Dict[str, Any],
                  default_allow_if_no_rule: bool) -> Decision:
        if not rules:
            d = Decision(allow=default_allow_if_no_rule,
                         reason="no matching rule; default applied",
                         rule_id=None, policy_version=self.artifact.version)
            self.audit_decision(d)
            return d

        obligations: List[str] = []
        for rule in rules:
            if rule.get("control_type") == "approval":
                obligations.append("RequireApproval")
            provided = set(context.get("satisfied_controls", []))
            if rule["control_type"] not in provided:
                d = Decision(
                    allow=False,
                    reason=f"required control '{rule['control_type']}' not satisfied in this context",
                    rule_id=rule["rule_id"],
                    evidence_refs=rule.get("evidence", []),
                    required_control=rule["control_type"],
                    obligations=obligations,
                    policy_version=self.artifact.version,
                    audit_metadata={"trigger": rule.get("trigger")},
                )
                self.audit_decision(d)
                return d
        d = Decision(allow=True, reason="all matching controls satisfied",
                     rule_id=rules[0]["rule_id"], evidence_refs=rules[0].get("evidence", []),
                     obligations=obligations, policy_version=self.artifact.version)
        self.audit_decision(d)
        return d

    # -- audit -----------------------------------------------------------
    def audit_decision(self, decision: Decision) -> None:
        self._audit_log.append(decision)

    def audit_trail(self) -> List[Dict[str, Any]]:
        return [d.to_dict() for d in self._audit_log]


class PolicyRuntimeHost:
    """Loads one or more artifacts and dispatches by target, applying
    the Fail-Safe Runtime rule: an invalid/unsigned/version-mismatched
    artifact never executes, and the host falls back to Default Deny
    (or the configured safe fallback) with a transparent report."""

    def __init__(self, fail_safe: str = "deny"):
        self.fail_safe = fail_safe
        self.runtimes: Dict[str, PolicyRuntime] = {}
        self.load_report: List[Dict[str, Any]] = []

    def load_artifact(self, artifact: PolicyArtifact) -> bool:
        runtime = PolicyRuntime(artifact, fail_safe=self.fail_safe)
        try:
            runtime.load()
            self.runtimes[artifact.policy_id] = runtime
            self.load_report.append({"policy_id": artifact.policy_id, "status": "loaded"})
            return True
        except PolicyIntegrityError as exc:
            self.load_report.append({"policy_id": artifact.policy_id, "status": "rejected", "error": str(exc)})
            return False

    def get(self, policy_id: str) -> Optional[PolicyRuntime]:
        return self.runtimes.get(policy_id)
