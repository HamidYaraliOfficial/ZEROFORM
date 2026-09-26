"""
Audit Engine
==============

Append-only (JSON Lines) record of every change to the Reality Model,
policy, scenario, control, approval, artifact and runtime simulation.
Each record is chained to the previous one's hash so tampering with
history is detectable, which is the practical minimum for an
"immutable / append-only" audit trail without requiring a dedicated
ledger service.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AuditRecord:
    seq: int
    timestamp: float
    actor: str
    action: str
    resource: str
    details: Dict[str, Any]
    prev_hash: str
    hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "seq": self.seq, "timestamp": self.timestamp, "actor": self.actor,
            "action": self.action, "resource": self.resource, "details": self.details,
            "prev_hash": self.prev_hash,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class AuditEngine:
    GENESIS_HASH = "0" * 64

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path
        self._records: List[AuditRecord] = []
        if log_path and os.path.exists(log_path):
            self._load()

    def _load(self) -> None:
        with open(self.log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                self._records.append(AuditRecord(**data))

    def record(self, actor: str, action: str, resource: str, details: Optional[Dict[str, Any]] = None) -> AuditRecord:
        prev_hash = self._records[-1].hash if self._records else self.GENESIS_HASH
        rec = AuditRecord(seq=len(self._records), timestamp=time.time(), actor=actor,
                           action=action, resource=resource, details=details or {}, prev_hash=prev_hash)
        rec.hash = rec.compute_hash()
        self._records.append(rec)
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec.to_dict(), default=str) + "\n")
        return rec

    def verify_chain(self) -> Dict[str, Any]:
        prev = self.GENESIS_HASH
        for rec in self._records:
            if rec.prev_hash != prev:
                return {"valid": False, "broken_at_seq": rec.seq, "reason": "prev_hash mismatch"}
            recomputed = rec.compute_hash()
            if recomputed != rec.hash:
                return {"valid": False, "broken_at_seq": rec.seq, "reason": "record hash mismatch (tampering?)"}
            prev = rec.hash
        return {"valid": True, "records": len(self._records)}

    def records(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._records]
