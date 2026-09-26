"""
Compliance Mapping Layer
===========================

Maps synthesized Security Controls onto configurable, versioned
compliance framework references. A mapping is a *reference to review*,
never a compliance claim: ``compliant=None`` until evidence has been
attached and the mapping reviewed and approved (see
:mod:`zeroform.core.audit` for the approval trail).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Illustrative default mapping; real deployments load their own table
# (versioned, e.g. exported from a GRC tool) via `load_custom_mapping`.
DEFAULT_FRAMEWORK_MAP: Dict[str, Dict[str, List[str]]] = {
    "authentication": {"soc2": ["CC6.1"], "iso27001": ["A.9.2"], "nist_csf": ["PR.AC-1"]},
    "authorization": {"soc2": ["CC6.3"], "iso27001": ["A.9.4"], "nist_csf": ["PR.AC-4"]},
    "encryption": {"soc2": ["CC6.7"], "iso27001": ["A.10.1"], "nist_csf": ["PR.DS-1"]},
    "audit": {"soc2": ["CC7.2"], "iso27001": ["A.12.4"], "nist_csf": ["DE.AE-3"]},
    "input_validation": {"soc2": ["CC8.1"], "iso27001": ["A.14.2"], "nist_csf": ["PR.DS-6"]},
    "secrets_management": {"soc2": ["CC6.1"], "iso27001": ["A.9.4"], "nist_csf": ["PR.AC-1"]},
    "approval": {"soc2": ["CC5.2"], "iso27001": ["A.9.2"], "nist_csf": ["PR.IP-3"]},
    "data_minimization": {"soc2": ["CC6.7"], "iso27001": ["A.18.1"], "nist_csf": ["PR.DS-5"]},
    "rate_limiting": {"soc2": ["CC7.1"], "iso27001": ["A.13.1"], "nist_csf": ["PR.PT-4"]},
    "isolation": {"soc2": ["CC6.6"], "iso27001": ["A.13.1"], "nist_csf": ["PR.AC-5"]},
}


@dataclass
class ComplianceMapping:
    control_type: str
    frameworks: Dict[str, List[str]]
    version: str = "1.0.0"
    reviewed: bool = False
    evidence_complete: bool = False

    def is_claimable(self) -> bool:
        return self.reviewed and self.evidence_complete

    def to_dict(self) -> Dict[str, object]:
        return self.__dict__.copy()


class ComplianceMappingLayer:
    def __init__(self, mapping: Optional[Dict[str, Dict[str, List[str]]]] = None, version: str = "1.0.0"):
        self.mapping = mapping or DEFAULT_FRAMEWORK_MAP
        self.version = version

    def load_custom_mapping(self, mapping: Dict[str, Dict[str, List[str]]], version: str) -> None:
        self.mapping = mapping
        self.version = version

    def map_control_types(self, control_types: List[str]) -> List[ComplianceMapping]:
        out = []
        for ctype in sorted(set(control_types)):
            frameworks = self.mapping.get(ctype, {})
            out.append(ComplianceMapping(control_type=ctype, frameworks=frameworks, version=self.version))
        return out
