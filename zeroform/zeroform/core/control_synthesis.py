"""
Security Control Synthesis Engine
====================================

Turns Trust Boundary Compiler output (required control *types* per
boundary crossing) into fully specified, machine-readable
:class:`SecurityControl` objects, each carrying id, purpose, trigger,
enforcement point, inputs/outputs, dependencies, failure mode,
evidence requirements and verification method -- the fields the
Control Coverage Engine, Policy Generator and Security Documentation
Compiler all consume downstream.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List

from .trust_zone import BoundaryCrossing

CONTROL_TEMPLATES: Dict[str, Dict[str, str]] = {
    "authentication": {
        "purpose": "Verify the identity of the calling principal before granting access.",
        "failure_mode": "deny",
        "verification_method": "auth_challenge_test",
    },
    "authorization": {
        "purpose": "Confirm the authenticated principal is permitted to perform the requested action.",
        "failure_mode": "deny",
        "verification_method": "rbac_abac_probe",
    },
    "encryption": {
        "purpose": "Protect data confidentiality/integrity while it crosses the boundary.",
        "failure_mode": "deny",
        "verification_method": "transport_and_field_encryption_check",
    },
    "input_validation": {
        "purpose": "Reject malformed, oversized or unexpected input before it reaches business logic.",
        "failure_mode": "deny",
        "verification_method": "schema_and_fuzz_validation",
    },
    "output_filtering": {
        "purpose": "Prevent leakage of fields the destination is not entitled to receive.",
        "failure_mode": "redact",
        "verification_method": "field_level_diff_test",
    },
    "rate_limiting": {
        "purpose": "Bound the request rate from lower-trust origins to limit abuse and blast radius.",
        "failure_mode": "throttle",
        "verification_method": "load_probe",
    },
    "audit": {
        "purpose": "Record the decision and its evidence for later investigation and compliance mapping.",
        "failure_mode": "fail_open_with_alert",
        "verification_method": "audit_log_presence_check",
    },
    "data_minimization": {
        "purpose": "Limit the fields/records transferred to the minimum necessary for the destination's purpose.",
        "failure_mode": "deny",
        "verification_method": "field_allowlist_check",
    },
    "approval": {
        "purpose": "Require a human (or dual/break-glass) approval obligation before the action executes.",
        "failure_mode": "hold_pending_approval",
        "verification_method": "approval_workflow_trace",
    },
    "isolation": {
        "purpose": "Physically or logically isolate the resource so a compromise cannot spread laterally.",
        "failure_mode": "quarantine",
        "verification_method": "segmentation_probe",
    },
    "segmentation": {
        "purpose": "Restrict network/service reachability between zones to declared, necessary paths only.",
        "failure_mode": "deny",
        "verification_method": "reachability_scan",
    },
    "secrets_management": {
        "purpose": "Ensure secrets are only accessed through an approved provider, never copied or logged.",
        "failure_mode": "deny",
        "verification_method": "secret_boundary_probe",
    },
    "integrity_verification": {
        "purpose": "Detect tampering of data or artifacts via signatures/hashes before use.",
        "failure_mode": "deny",
        "verification_method": "signature_verification",
    },
    "session_controls": {
        "purpose": "Bound session lifetime, idle timeout and concurrent session count.",
        "failure_mode": "expire_session",
        "verification_method": "session_lifecycle_test",
    },
    "backup_verification": {
        "purpose": "Confirm backups are complete, restorable and access-controlled.",
        "failure_mode": "alert",
        "verification_method": "restore_drill",
    },
    "data_loss_prevention": {
        "purpose": "Detect and block unauthorized export of sensitive data.",
        "failure_mode": "deny",
        "verification_method": "exfiltration_probe",
    },
}


@dataclass
class SecurityControl:
    id: str
    control_type: str
    purpose: str
    trigger: str
    enforcement_point: str
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    failure_mode: str = "deny"
    evidence: List[str] = field(default_factory=list)
    verification_method: str = ""

    def to_dict(self) -> Dict[str, object]:
        return self.__dict__.copy()


class ControlSynthesisEngine:
    def synthesize(self, crossings: List[BoundaryCrossing]) -> List[SecurityControl]:
        controls: List[SecurityControl] = []
        seen_ids = set()
        for crossing in crossings:
            for ctype in crossing.enforced_controls():
                template = CONTROL_TEMPLATES.get(ctype, {
                    "purpose": f"Enforce '{ctype}' at this boundary crossing.",
                    "failure_mode": "deny",
                    "verification_method": "manual_review",
                })
                cid = self._control_id(crossing, ctype)
                if cid in seen_ids:
                    continue
                seen_ids.add(cid)
                controls.append(SecurityControl(
                    id=cid,
                    control_type=ctype,
                    purpose=template["purpose"],
                    trigger=f"{crossing.edge_kind}:{crossing.edge_source}->{crossing.edge_target}",
                    enforcement_point=f"boundary:{crossing.from_zone}->{crossing.to_zone}",
                    inputs=[crossing.edge_source],
                    outputs=[crossing.edge_target],
                    dependencies=[],
                    failure_mode=template["failure_mode"],
                    evidence=[f"edge:{crossing.edge_source}->{crossing.edge_target}:{crossing.edge_kind}"],
                    verification_method=template["verification_method"],
                ))
        return controls

    @staticmethod
    def _control_id(crossing: BoundaryCrossing, ctype: str) -> str:
        raw = f"{crossing.edge_source}|{crossing.edge_target}|{crossing.edge_kind}|{ctype}"
        return "ctl_" + hashlib.sha256(raw.encode()).hexdigest()[:12]
