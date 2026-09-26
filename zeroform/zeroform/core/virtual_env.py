"""
Virtual Security Environment
===============================

Builds a simulated runtime from the Reality Model: entities, policies
and data flows exist as a Simulated Runtime where requests,
authentication, data transfer, permission changes, policy changes,
failures, recovery and incidents can be executed -- entirely against
an in-memory graph snapshot, never against production.

Contains:
  * Scenario Designer data model (:class:`Scenario`)
  * Scenario Execution Engine (:class:`ScenarioExecutionEngine`)
  * Security State Machine (:data:`ENTITY_STATES`)
  * Virtual Runtime Engine (:class:`VirtualRuntimeEngine`) with
    snapshot branching (the Counterfactual Security Lab) and
    Virtual Incident Generator / Incident Timeline / Replay support.
"""

from __future__ import annotations

import copy
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .control_synthesis import ControlSynthesisEngine, SecurityControl
from .gap_analyzer import GapFinding, SecurityGapAnalyzer
from .graph_model import GraphRepository, NetworkXGraphRepository
from .trust_zone import TrustBoundaryCompiler

ENTITY_STATES = [
    "Healthy", "Exposed", "Protected", "Degraded",
    "Compromised-Simulated", "Isolated", "Recovered", "Quarantined-Simulated",
]


@dataclass
class ScenarioEvent:
    type: str                     # e.g. remove_control, steal_credential, call_service
    target: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    at_step: int = 0


@dataclass
class Scenario:
    name: str
    description: str = ""
    preconditions: List[str] = field(default_factory=list)
    actors: List[str] = field(default_factory=list)
    initial_state: Dict[str, str] = field(default_factory=dict)
    events: List[ScenarioEvent] = field(default_factory=list)
    expected_controls: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    failure_criteria: List[str] = field(default_factory=list)
    duration_steps: int = 10
    severity: str = "medium"
    recovery_model: str = "manual"


# a handful of ready-made scenario templates matching the spec's list
BUILTIN_SCENARIO_TEMPLATES = [
    "stolen_credential", "compromised_device", "leaked_secret",
    "misconfigured_api", "unauthorized_data_export", "service_failure",
    "identity_escalation", "third_party_trust_change", "policy_removal",
    "encryption_failure", "audit_failure", "ai_agent_over_permission",
]


@dataclass
class TimelineEntry:
    step: int
    timestamp: float
    kind: str            # state_change | decision | violation | control_activation | event
    detail: Dict[str, Any]


@dataclass
class ScenarioResult:
    scenario_name: str
    timeline: List[TimelineEntry]
    violations: List[str]
    entity_states: Dict[str, str]
    passed: bool
    summary: str


class ScenarioExecutionEngine:
    def __init__(self, boundary_compiler: TrustBoundaryCompiler, control_engine: ControlSynthesisEngine,
                 gap_analyzer: SecurityGapAnalyzer):
        self.boundary_compiler = boundary_compiler
        self.control_engine = control_engine
        self.gap_analyzer = gap_analyzer

    def run(self, graph: GraphRepository, scenario: Scenario) -> ScenarioResult:
        working = graph.clone()
        states: Dict[str, str] = {actor: "Healthy" for actor in scenario.actors}
        for nid, st in scenario.initial_state.items():
            states[nid] = st

        timeline: List[TimelineEntry] = []
        violations: List[str] = []
        step = 0

        timeline.append(TimelineEntry(step=step, timestamp=time.time(), kind="event",
                                       detail={"message": f"scenario '{scenario.name}' started"}))

        for event in sorted(scenario.events, key=lambda e: e.at_step):
            step = max(step, event.at_step)
            self._apply_event(working, event, states, timeline, step)

        # after all events, re-run gap analysis on the mutated graph to
        # see which required controls are now missing (= violations
        # introduced by the scenario's events).
        crossings = self.boundary_compiler.compile_crossings(working)
        controls = self.control_engine.synthesize(crossings)
        findings: List[GapFinding] = self.gap_analyzer.analyze(working, crossings, controls)
        for f in findings:
            if f.suggested_control in scenario.expected_controls or not scenario.expected_controls:
                violations.append(f"{f.kind}: {f.description}")
                timeline.append(TimelineEntry(step=step, timestamp=time.time(), kind="violation",
                                               detail={"finding": f.finding_id, "description": f.description}))

        passed = len(violations) == 0 if scenario.success_criteria == [] else self._check_criteria(
            scenario, violations)

        summary = (f"{len(timeline)} timeline events, {len(violations)} violation(s) detected "
                   f"over {step + 1} step(s).")
        return ScenarioResult(scenario_name=scenario.name, timeline=timeline, violations=violations,
                               entity_states=states, passed=passed, summary=summary)

    def _check_criteria(self, scenario: Scenario, violations: List[str]) -> bool:
        if scenario.failure_criteria and any(fc in v for fc in scenario.failure_criteria for v in violations):
            return False
        return True

    def _apply_event(self, graph: GraphRepository, event: ScenarioEvent, states: Dict[str, str],
                      timeline: List[TimelineEntry], step: int) -> None:
        timeline.append(TimelineEntry(step=step, timestamp=time.time(), kind="event",
                                       detail={"type": event.type, "target": event.target, "params": event.params}))

        if event.type == "remove_control" and event.target:
            # remove edges representing the control's boundary crossing
            # by tagging the edge so trust_zone compiler no longer sees
            # it as covered -- modeled by deleting the crossing edge's
            # classification requirement marker.
            for edge in list(graph.edges()):
                if f"{edge.source}->{edge.target}" == event.target:
                    edge.attrs["controls_removed"] = edge.attrs.get("controls_removed", []) + [
                        event.params.get("control_type", "unknown")]
                    graph.add_edge(edge)
            states[event.target] = "Exposed"

        elif event.type in ("steal_credential", "compromised_device", "identity_escalation"):
            if event.target:
                states[event.target] = "Compromised-Simulated"

        elif event.type == "leaked_secret" and event.target:
            states[event.target] = "Exposed"

        elif event.type == "service_failure" and event.target:
            states[event.target] = "Degraded"

        elif event.type == "isolate" and event.target:
            states[event.target] = "Isolated"

        elif event.type == "recover" and event.target:
            states[event.target] = "Recovered"

        elif event.type == "quarantine" and event.target:
            states[event.target] = "Quarantined-Simulated"

        timeline.append(TimelineEntry(step=step, timestamp=time.time(), kind="state_change",
                                       detail={"target": event.target, "state": states.get(event.target, "Healthy")}))


@dataclass
class Snapshot:
    id: str
    label: str
    graph_dict: Dict[str, Any]
    created_at: float = field(default_factory=time.time)
    parent_id: Optional[str] = None


class VirtualRuntimeEngine:
    """Owns named branches of Reality Model snapshots -- the
    Counterfactual Security Lab. Each branch can be mutated and
    scenario-tested independently and compared back to `baseline`."""

    def __init__(self, base_graph: GraphRepository, execution_engine: ScenarioExecutionEngine):
        self.execution_engine = execution_engine
        self._snapshots: Dict[str, Snapshot] = {}
        self._branches: Dict[str, str] = {}  # branch name -> snapshot id
        base_id = self._store(base_graph, "baseline", parent_id=None)
        self._branches["baseline"] = base_id

    def _store(self, graph: GraphRepository, label: str, parent_id: Optional[str]) -> str:
        snap_id = uuid.uuid4().hex[:12]
        self._snapshots[snap_id] = Snapshot(id=snap_id, label=label, graph_dict=graph.to_dict(),
                                             parent_id=parent_id)
        return snap_id

    def branch(self, from_branch: str, new_branch: str) -> str:
        if from_branch not in self._branches:
            raise KeyError(f"unknown branch '{from_branch}'")
        parent_snap = self._branches[from_branch]
        graph = NetworkXGraphRepository.from_dict(self._snapshots[parent_snap].graph_dict)
        new_id = self._store(graph, new_branch, parent_id=parent_snap)
        self._branches[new_branch] = new_id
        return new_id

    def get_graph(self, branch: str) -> GraphRepository:
        snap_id = self._branches[branch]
        return NetworkXGraphRepository.from_dict(self._snapshots[snap_id].graph_dict)

    def commit_graph(self, branch: str, graph: GraphRepository, label: Optional[str] = None) -> str:
        parent = self._branches.get(branch)
        new_id = self._store(graph, label or branch, parent_id=parent)
        self._branches[branch] = new_id
        return new_id

    def list_branches(self) -> Dict[str, str]:
        return dict(self._branches)

    def run_scenario_on_branch(self, branch: str, scenario: Scenario) -> ScenarioResult:
        graph = self.get_graph(branch)
        return self.execution_engine.run(graph, scenario)
