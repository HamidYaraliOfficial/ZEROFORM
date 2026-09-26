"""
ZEROFORM Reality DSL — Abstract Syntax Tree
=============================================

The AST is intentionally source-format agnostic further downstream:
:mod:`zeroform.core.semantic_model` consumes ``Module`` regardless of
whether it came from the ``.zf`` DSL, a JSON/YAML reality document, or
an external importer (OpenAPI, Kubernetes, Terraform metadata, cloud
inventory, IAM export, SBOM, CI/CD metadata) that has been normalized
into the same shape by :mod:`zeroform.core.importers`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

Value = Union[str, int, float, bool, List["Value"], "Block"]


@dataclass
class Block:
    """A single ``kind "name" { ... }`` declaration."""

    kind: str
    name: Optional[str]
    attrs: Dict[str, Value] = field(default_factory=dict)
    line: int = 0

    def get(self, key: str, default: Any = None) -> Any:
        return self.attrs.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        def unwrap(v: Value) -> Any:
            if isinstance(v, Block):
                return v.to_dict()
            if isinstance(v, list):
                return [unwrap(x) for x in v]
            return v

        return {
            "kind": self.kind,
            "name": self.name,
            "attrs": {k: unwrap(v) for k, v in self.attrs.items()},
        }


@dataclass
class Module:
    """A parsed ``.zf`` file: an ordered list of top level blocks."""

    imports: List[str] = field(default_factory=list)
    blocks: List[Block] = field(default_factory=list)
    source_name: str = "<memory>"

    def blocks_of(self, kind: str) -> List[Block]:
        return [b for b in self.blocks if b.kind == kind]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "imports": self.imports,
            "blocks": [b.to_dict() for b in self.blocks],
        }
