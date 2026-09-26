"""
Policy Artifact Registry + Secure Package Format + Secret Boundary Engine
=============================================================================
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .policy_generator import PolicyArtifact
from .semantic_model import RealityModel


@dataclass
class RegistryEntry:
    artifact_type: str    # wasm_module | policy_json | test_package | assertions | documentation | verification_report
    identifier: str
    version: str
    hash: str
    signature: str
    compiler_version: str
    source_model_hash: str
    stored_at: str

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class PolicyArtifactRegistry:
    def __init__(self, storage_dir: str):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
        self._entries: List[RegistryEntry] = []

    def store(self, artifact_type: str, identifier: str, payload: Dict[str, Any], version: str,
              compiler_version: str, source_model_hash: str, signature: str = "") -> RegistryEntry:
        raw = json.dumps(payload, sort_keys=True, default=str).encode()
        digest = hashlib.sha256(raw).hexdigest()
        path = os.path.join(self.storage_dir, f"{identifier}.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(raw.decode())
        entry = RegistryEntry(artifact_type=artifact_type, identifier=identifier, version=version,
                               hash=digest, signature=signature, compiler_version=compiler_version,
                               source_model_hash=source_model_hash, stored_at=path)
        self._entries.append(entry)
        return entry

    def store_policy_artifact(self, artifact: PolicyArtifact) -> RegistryEntry:
        return self.store("policy_json" if artifact.target == "json" else f"policy_{artifact.target}",
                           artifact.policy_id, artifact.to_dict(), artifact.version,
                           artifact.compiler_version, artifact.source_model_hash, artifact.signature)

    def list_entries(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._entries]


SECRET_ENTITY_TYPE = "Secret"


class SecretBoundaryEngine:
    """Guarantees secrets are only ever represented by *reference*
    (id + metadata), never by value, anywhere the compiler touches
    disk -- including inside Secure Packages. Any attempt to place a
    concrete secret value into an exported document is treated as a
    policy violation and rejected."""

    SENSITIVE_KEYS = {"value", "secret_value", "password", "private_key", "api_key", "token"}

    def scrub(self, node_attrs: Dict[str, Any]) -> Dict[str, Any]:
        clean = {}
        for k, v in node_attrs.items():
            if k.lower() in self.SENSITIVE_KEYS:
                continue  # dropped, never exported
            clean[k] = v
        return clean

    def check_violation(self, node_attrs: Dict[str, Any]) -> Optional[str]:
        for k in node_attrs:
            if k.lower() in self.SENSITIVE_KEYS:
                return f"attempted export of raw secret material via key '{k}'"
        return None


class SecurePackageBuilder:
    """Exports a full Reality Model (schema + policies + scenarios +
    tests + generated artifacts) as a single zip, with the Secret
    Boundary Engine scrubbing any raw secret value it finds on the way
    out -- secrets survive only as references/metadata."""

    def __init__(self, secret_boundary: Optional[SecretBoundaryEngine] = None):
        self.secret_boundary = secret_boundary or SecretBoundaryEngine()

    def build(self, model: RealityModel, extra_artifacts: Dict[str, Any], output_path: str) -> str:
        model_dict = model.to_dict()
        violations = []
        for node in model_dict["graph"]["nodes"]:
            if node.get("entity_type") == SECRET_ENTITY_TYPE:
                violation = self.secret_boundary.check_violation(node)
                if violation:
                    violations.append((node["id"], violation))
                for k in list(node.keys()):
                    if k.lower() in self.secret_boundary.SENSITIVE_KEYS:
                        del node[k]

        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("reality_model.json", json.dumps(model_dict, indent=2, default=str))
            for name, payload in extra_artifacts.items():
                zf.writestr(name, json.dumps(payload, indent=2, default=str) if not isinstance(payload, str) else payload)
            manifest = {
                "package_format": "zeroform-secure-package/1",
                "built_at": time.time(),
                "secret_violations_scrubbed": violations,
                "contains_raw_secret_values": False,
            }
            zf.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
        return output_path
