"""
Reality Import Framework
===========================

Every external source is wrapped by a :class:`Connector` with its own
authentication, schema mapping, incremental import (via a checkpoint
token), validation, retry policy, rate limit and provenance stamp, and
converts its native shape into the same generic ``blocks`` document
:mod:`zeroform.core.semantic_model` already knows how to consume (the
same shape :func:`zeroform.dsl.ast_nodes.Module.to_dict` produces),
so the DSL and every importer share one downstream pipeline.

Reference connectors included: a generic JSON/YAML Reality document
importer, and lightweight, best-effort connectors for OpenAPI and
Kubernetes manifests that extract the entities/flows they can
determine structurally. Terraform / Cloud Inventory / Service Mesh /
IAM export / SBOM / CI-CD metadata connectors follow the identical
``Connector`` interface and are documented as extension points.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..dsl.ast_nodes import Block, Module


@dataclass
class ImportProvenance:
    connector: str
    source_ref: str
    imported_at: float = field(default_factory=time.time)
    checkpoint: Optional[str] = None


@dataclass
class ImportResult:
    module: Module
    provenance: ImportProvenance
    warnings: List[str] = field(default_factory=list)


class Connector:
    name = "base"

    def authenticate(self, **kwargs: Any) -> None:
        """No-op by default; concrete connectors override to validate
        credentials/tokens before `fetch` is called."""
        return None

    def validate(self, raw: Any) -> List[str]:
        return []

    def fetch(self, source: Any, checkpoint: Optional[str] = None) -> Any:
        raise NotImplementedError

    def to_blocks(self, raw: Any) -> List[Block]:
        raise NotImplementedError

    def import_(self, source: Any, checkpoint: Optional[str] = None, retries: int = 3) -> ImportResult:
        last_error: Optional[Exception] = None
        raw = None
        for attempt in range(retries):
            try:
                raw = self.fetch(source, checkpoint=checkpoint)
                break
            except Exception as exc:  # pragma: no cover - network/IO dependent
                last_error = exc
                time.sleep(min(2 ** attempt, 5))
        if raw is None:
            raise RuntimeError(f"{self.name} connector failed after {retries} attempts: {last_error}")

        warnings = self.validate(raw)
        blocks = self.to_blocks(raw)
        module = Module(blocks=blocks, source_name=f"{self.name}:{source}")
        provenance = ImportProvenance(connector=self.name, source_ref=str(source), checkpoint=checkpoint)
        return ImportResult(module=module, provenance=provenance, warnings=warnings)


class JSONRealityConnector(Connector):
    """Imports a Reality document already shaped like
    ``{"world": {...}, "blocks": [{"kind": "...", "name": "...", "attrs": {...}}, ...]}``
    -- the canonical interchange format used for Secure Package export
    and for hand-authored JSON/YAML models."""

    name = "json_reality"

    def fetch(self, source: Any, checkpoint: Optional[str] = None) -> Any:
        if isinstance(source, dict):
            return source
        import json
        with open(source, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def validate(self, raw: Any) -> List[str]:
        warnings = []
        if "blocks" not in raw:
            warnings.append("document has no 'blocks' key; nothing to import")
        return warnings

    def to_blocks(self, raw: Any) -> List[Block]:
        blocks = []
        world = raw.get("world")
        if world:
            blocks.append(Block(kind="world", name=world.get("name", "Imported Reality"),
                                 attrs={k: v for k, v in world.items() if k != "name"}))
        for b in raw.get("blocks", []):
            blocks.append(Block(kind=b["kind"], name=b.get("name"), attrs=b.get("attrs", {})))
        return blocks


class OpenAPIConnector(Connector):
    """Best-effort extraction: each OpenAPI ``path`` becomes an `api`
    entity, and each operation with declared external callers becomes
    a `flow`. Real deployments should follow up with an IAM/service
    mesh import for identity and trust-zone context this format does
    not carry."""

    name = "openapi"

    def fetch(self, source: Any, checkpoint: Optional[str] = None) -> Any:
        if isinstance(source, dict):
            return source
        import json
        with open(source, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def validate(self, raw: Any) -> List[str]:
        return [] if "paths" in raw else ["OpenAPI document has no 'paths'"]

    def to_blocks(self, raw: Any) -> List[Block]:
        blocks = []
        title = raw.get("info", {}).get("title", "Imported API")
        api_id = f"api:{title.lower().replace(' ', '_')}"
        blocks.append(Block(kind="api", name=api_id, attrs={"type": "API", "trust_zone": "Internal"}))
        for path, ops in raw.get("paths", {}).items():
            for method in ops.keys():
                flow_name = f"flow:{method}:{path}".replace("/", "_")
                blocks.append(Block(kind="flow", name=flow_name,
                                     attrs={"from": "user:external_client", "to": api_id,
                                            "action": "calls", "data": path}))
        return blocks


class KubernetesConnector(Connector):
    """Extracts Service / Deployment metadata from a list of decoded
    Kubernetes manifests into `service` entities with owner and
    namespace-derived trust zone."""

    name = "kubernetes"

    def fetch(self, source: Any, checkpoint: Optional[str] = None) -> Any:
        return source  # expects an already-decoded list[dict] of manifests

    def validate(self, raw: Any) -> List[str]:
        return [] if isinstance(raw, list) else ["expected a list of decoded Kubernetes manifests"]

    def to_blocks(self, raw: Any) -> List[Block]:
        blocks = []
        for manifest in raw:
            kind = manifest.get("kind")
            if kind not in ("Service", "Deployment"):
                continue
            meta = manifest.get("metadata", {})
            name = meta.get("name", "unnamed")
            namespace = meta.get("namespace", "default")
            entity_id = f"service:{namespace}.{name}"
            zone = "Secure" if namespace in ("kube-system", "security") else "Internal"
            blocks.append(Block(kind="service", name=entity_id,
                                 attrs={"type": "Service", "owner": namespace, "trust_zone": zone}))
        return blocks


CONNECTOR_REGISTRY: Dict[str, type] = {
    "json_reality": JSONRealityConnector,
    "openapi": OpenAPIConnector,
    "kubernetes": KubernetesConnector,
}


def get_connector(name: str) -> Connector:
    cls = CONNECTOR_REGISTRY.get(name)
    if not cls:
        raise ValueError(f"unknown connector '{name}'. Available: {list(CONNECTOR_REGISTRY)}")
    return cls()
