"""Pydantic schemas for the ZEROFORM REST/WebSocket API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CompileRequest(BaseModel):
    source: str = Field(..., description="ZEROFORM Reality DSL source text")
    source_name: str = "<api>"
    policy_targets: List[str] = Field(default_factory=lambda: ["json", "wasm"])


class CompileResponse(BaseModel):
    world_name: str
    version: str
    node_count: int
    edge_count: int
    boundary_crossings: int
    controls: int
    policies: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    source_model_hash: str
    duration_seconds: float


class ScenarioRunRequest(BaseModel):
    source: str
    scenario_name: str = "ad_hoc"
    actors: List[str] = Field(default_factory=list)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    expected_controls: List[str] = Field(default_factory=list)


class OperatingHoursStatusResponse(BaseModel):
    is_open: bool
    timezone_label: str
    checked_at: str
    current_window_closes_at: Optional[str] = None
    seconds_until_close: Optional[float] = None
    human_time_until_close: Optional[str] = None
    next_open_at: Optional[str] = None
    seconds_until_open: Optional[float] = None
    human_time_until_open: Optional[str] = None
