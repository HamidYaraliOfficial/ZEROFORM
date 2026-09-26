"""
Policy Generator + Policy Compiler
=====================================

Compiles synthesized :class:`SecurityControl` objects into
machine-executable policy artifacts. Every artifact records the
source model hash, compiler version, policy version and an integrity
signature so :mod:`zeroform.core.artifact_registry` and the
Cryptographic Integrity Layer can verify provenance before anything
is loaded by the runtime.

Targets implemented in this reference compiler:

``json``        - a flat, engine-independent policy document, the
                  canonical target every other target is derived from
``wasm``        - the interface contract a compiled .wasm guard
                  module exposes (see zeroform.core.policy_runtime);
                  the reference build emits the *policy document* the
                  Python reference runtime interprets 1:1 against that
                  same interface, so swapping in a real wasmtime
                  compiled module is a drop-in replacement
``opa``         - an OPA/Rego-*compatible* rule sketch (data document
                  + comment describing the equivalent Rego shape)
``http_middleware`` / ``grpc_interceptor`` / ``event_validator``
                - thin descriptors telling a host framework which
                  policy IDs to enforce at which point
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .. import COMPILER_VERSION
from .control_synthesis import SecurityControl

DEV_SIGNING_KEY_ENV = "ZEROFORM_SIGNING_KEY"
_DEV_DEFAULT_KEY = b"zeroform-local-dev-key-DO-NOT-USE-IN-PRODUCTION"


def _signing_key() -> bytes:
    """Dev-mode HMAC signing key. Production deployments MUST set
    ZEROFORM_SIGNING_KEY (or replace this function to pull from an
    HSM / KMS) -- this keeps the reference implementation runnable
    with zero external services while making the insecure default
    impossible to miss."""
    env = os.environ.get(DEV_SIGNING_KEY_ENV)
    return env.encode() if env else _DEV_DEFAULT_KEY


def sign_payload(payload: bytes) -> str:
    return hmac.new(_signing_key(), payload, hashlib.sha256).hexdigest()


def verify_signature(payload: bytes, signature: str) -> bool:
    expected = sign_payload(payload)
    return hmac.compare_digest(expected, signature)


@dataclass
class PolicyArtifact:
    policy_id: str
    target: str
    version: str
    compiler_version: str
    source_model_hash: str
    document: Dict[str, Any]
    created_at: float = field(default_factory=time.time)
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        payload = {
            "policy_id": self.policy_id,
            "target": self.target,
            "version": self.version,
            "compiler_version": self.compiler_version,
            "source_model_hash": self.source_model_hash,
            "document": self.document,
        }
        return json.dumps(payload, sort_keys=True).encode()

    def sign(self) -> None:
        self.signature = sign_payload(self.canonical_bytes())

    def verify(self) -> bool:
        return bool(self.signature) and verify_signature(self.canonical_bytes(), self.signature)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "target": self.target,
            "version": self.version,
            "compiler_version": self.compiler_version,
            "source_model_hash": self.source_model_hash,
            "document": self.document,
            "created_at": self.created_at,
            "signature": self.signature,
        }


class PolicyGenerator:
    def __init__(self, policy_version: str = "1.0.0"):
        self.policy_version = policy_version

    def generate(self, controls: List[SecurityControl], source_model_hash: str,
                 targets: Optional[List[str]] = None) -> List[PolicyArtifact]:
        targets = targets or ["json", "wasm"]
        artifacts: List[PolicyArtifact] = []
        rules = [self._control_to_rule(c) for c in controls]

        for target in targets:
            document = self._render(target, rules)
            artifact = PolicyArtifact(
                policy_id=f"policy_{source_model_hash[:10]}_{target}",
                target=target,
                version=self.policy_version,
                compiler_version=COMPILER_VERSION,
                source_model_hash=source_model_hash,
                document=document,
            )
            artifact.sign()
            artifacts.append(artifact)
        return artifacts

    @staticmethod
    def _control_to_rule(control: SecurityControl) -> Dict[str, Any]:
        return {
            "rule_id": control.id,
            "control_type": control.control_type,
            "trigger": control.trigger,
            "enforcement_point": control.enforcement_point,
            "inputs": control.inputs,
            "outputs": control.outputs,
            "failure_mode": control.failure_mode,
            "verification_method": control.verification_method,
            "evidence": control.evidence,
        }

    def _render(self, target: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        if target in ("json", "wasm"):
            return {"format": target, "rules": rules}
        if target == "opa":
            return {
                "format": "opa-compatible",
                "rego_package": "zeroform.generated",
                "note": "Rego source is derivable 1:1 from `rules`; each rule becomes "
                        "`deny[msg] { input.control_type == \"<control_type>\"; not satisfied }`",
                "rules": rules,
            }
        if target == "http_middleware":
            return {"format": "http_middleware", "enforce_rule_ids": [r["rule_id"] for r in rules]}
        if target == "grpc_interceptor":
            return {"format": "grpc_interceptor", "enforce_rule_ids": [r["rule_id"] for r in rules]}
        if target == "event_validator":
            return {"format": "event_validator", "enforce_rule_ids": [r["rule_id"] for r in rules]}
        raise ValueError(f"unknown policy target: {target}")


def hash_model(model_dict: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(model_dict, sort_keys=True, default=str).encode()).hexdigest()
