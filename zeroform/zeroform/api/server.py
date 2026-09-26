"""
ZEROFORM API Service
=======================

REST + WebSocket surface over the compiler pipeline, used by the GUI
(``gui/index.html``) and any external Developer Portal integration.
Run with::

    zeroform run --host 127.0.0.1 --port 8000
    # or
    uvicorn zeroform.api.server:app --reload

All endpoints operate on Reality Model *source text* sent by the
caller (Local-Only Mode: nothing is persisted server-side beyond the
in-memory operating-hours schedule and the append-only audit log
unless a storage path is configured).
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .. import COMPILER_VERSION
from ..core.audit import AuditEngine
from ..core.availability import OperatingHoursEngine, OperatingHoursSchedule, OperatingWindow
from ..core.diff_engine import GraphDiffEngine
from ..core.documentation import SecurityDocumentationCompiler, SecurityReleasePassport
from ..core.pipeline import CompilerPipeline
from ..core.refactor import SecurityArchitectureRefactoringEngine
from ..core.virtual_env import Scenario, ScenarioEvent, ScenarioExecutionEngine
from .schemas import CompileRequest, CompileResponse, OperatingHoursStatusResponse, ScenarioRunRequest

app = FastAPI(title="ZEROFORM Security Reality Compiler API", version=COMPILER_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_audit = AuditEngine(log_path=os.environ.get("ZEROFORM_AUDIT_LOG"))

_DEFAULT_HOURS_SCHEDULE = OperatingHoursSchedule(timezone_label="UTC")
for _wd in range(5):
    _DEFAULT_HOURS_SCHEDULE.set_day(_wd, windows=[OperatingWindow("09:00", "18:00")])
for _wd in (5, 6):
    _DEFAULT_HOURS_SCHEDULE.set_day(_wd, closed=True)
_hours_state: Dict[str, Any] = {"schedule": _DEFAULT_HOURS_SCHEDULE}


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "compiler_version": COMPILER_VERSION, "time": time.time()}


@app.post("/api/compile", response_model=CompileResponse)
def compile_model(req: CompileRequest) -> CompileResponse:
    pipeline = CompilerPipeline(policy_targets=req.policy_targets)
    try:
        result = pipeline.compile_source(req.source, source_name=req.source_name)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"compile error: {exc}") from exc

    _audit.record(actor="api", action="compile", resource=result.model.meta.name,
                  details={"source_model_hash": result.source_model_hash})

    return CompileResponse(
        world_name=result.model.meta.name,
        version=result.model.meta.version,
        node_count=len(result.model.graph.nodes()),
        edge_count=len(result.model.graph.edges()),
        boundary_crossings=len(result.crossings),
        controls=len(result.controls),
        policies=[p.to_dict() for p in result.policies],
        findings=[f.__dict__ for f in result.findings],
        source_model_hash=result.source_model_hash,
        duration_seconds=result.duration_seconds,
    )


@app.post("/api/refactor")
def refactor(req: CompileRequest) -> List[Dict[str, Any]]:
    pipeline = CompilerPipeline(policy_targets=req.policy_targets)
    result = pipeline.compile_source(req.source, source_name=req.source_name)
    proposals = SecurityArchitectureRefactoringEngine().propose(result.model.graph, result.findings)
    return [p.__dict__ for p in proposals]


@app.post("/api/report")
def report(req: CompileRequest) -> Dict[str, Any]:
    pipeline = CompilerPipeline(policy_targets=req.policy_targets)
    result = pipeline.compile_source(req.source, source_name=req.source_name)
    passport = SecurityReleasePassport().build(result.model, result.controls, result.findings,
                                                result.policies, result.invariant_results, [])
    docs = SecurityDocumentationCompiler().compile(result.model, result.crossings, result.controls, result.findings)
    return {"passport": passport, "documentation_markdown": docs}


@app.post("/api/scenario/run")
def run_scenario(req: ScenarioRunRequest) -> Dict[str, Any]:
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(req.source, source_name="<scenario>")
    engine = ScenarioExecutionEngine(pipeline.boundary_compiler, pipeline.control_engine, pipeline.gap_analyzer)
    scenario = Scenario(
        name=req.scenario_name,
        actors=req.actors or [n.id for n in result.model.graph.nodes(kind="Identity")],
        events=[ScenarioEvent(**e) for e in req.events],
        expected_controls=req.expected_controls,
    )
    scenario_result = engine.run(result.model.graph, scenario)
    _audit.record(actor="api", action="run_scenario", resource=req.scenario_name,
                  details={"violations": len(scenario_result.violations)})
    return {
        "scenario_name": scenario_result.scenario_name,
        "passed": scenario_result.passed,
        "summary": scenario_result.summary,
        "violations": scenario_result.violations,
        "entity_states": scenario_result.entity_states,
        "timeline": [t.__dict__ for t in scenario_result.timeline],
    }


@app.get("/api/hours/status", response_model=OperatingHoursStatusResponse)
def hours_status() -> Dict[str, Any]:
    engine = OperatingHoursEngine(_hours_state["schedule"])
    return engine.status()


@app.get("/api/hours/schedule")
def hours_schedule() -> Dict[str, Any]:
    return _hours_state["schedule"].to_dict()


@app.put("/api/hours/schedule")
def set_hours_schedule(schedule: Dict[str, Any]) -> Dict[str, Any]:
    _hours_state["schedule"] = OperatingHoursSchedule.from_dict(schedule)
    _audit.record(actor="api", action="update_operating_hours", resource="soc_hours", details={})
    return {"status": "updated"}


@app.get("/api/audit")
def audit_trail() -> Dict[str, Any]:
    return {"chain_valid": _audit.verify_chain(), "records": _audit.records()}


@app.websocket("/ws/scenario")
async def scenario_stream(websocket: WebSocket) -> None:
    """Streams timeline entries for a scenario run step by step, so
    the GUI's Incident Replay panel can play/pause/step through it."""
    await websocket.accept()
    try:
        payload = await websocket.receive_json()
        req = ScenarioRunRequest(**payload)
        pipeline = CompilerPipeline()
        result = pipeline.compile_source(req.source, source_name="<ws-scenario>")
        engine = ScenarioExecutionEngine(pipeline.boundary_compiler, pipeline.control_engine, pipeline.gap_analyzer)
        scenario = Scenario(
            name=req.scenario_name,
            actors=req.actors or [n.id for n in result.model.graph.nodes(kind="Identity")],
            events=[ScenarioEvent(**e) for e in req.events],
            expected_controls=req.expected_controls,
        )
        scenario_result = engine.run(result.model.graph, scenario)
        for entry in scenario_result.timeline:
            await websocket.send_json(entry.__dict__)
        await websocket.send_json({"kind": "done", "passed": scenario_result.passed,
                                    "violations": scenario_result.violations})
    except WebSocketDisconnect:
        return
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass
