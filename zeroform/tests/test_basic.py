"""
Security Regression Suite (subset)
=====================================

Covers DSL parser, AST, semantic model / graph build, policy
compilation, WASM-interface runtime, scenario execution, mutation
testing, refactor proposals, version control and the operating-hours
engine, using pytest as the harness for the Security Regression Suite
+ Golden Artifact style checks described in the project spec. Run
with::

    pytest -q
"""

import os
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from zeroform.core.artifact_registry import SecretBoundaryEngine, SecurePackageBuilder
from zeroform.core.availability import OperatingHoursEngine, OperatingHoursSchedule, OperatingWindow, ScheduleException
from zeroform.core.mutation_testing import PolicyMutationEngine, SecurityMutationTestingFramework
from zeroform.core.pipeline import CompilerPipeline
from zeroform.core.policy_runtime import PolicyRuntime
from zeroform.core.refactor import SecurityArchitectureRefactoringEngine
from zeroform.core.verification import PropertyBasedSecurityTester, VerificationScenarioGenerator
from zeroform.core.version_control import RealityVersionControl
from zeroform.core.virtual_env import Scenario, ScenarioEvent, ScenarioExecutionEngine
from zeroform.dsl.lexer import tokenize
from zeroform.dsl.parser import parse_source

SAMPLE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "zeroform", "examples", "sample_world.zf")


@pytest.fixture()
def sample_source() -> str:
    with open(SAMPLE_PATH, encoding="utf-8") as fh:
        return fh.read()


# -- DSL parser tests --------------------------------------------------
def test_lexer_tokenizes_basic_block():
    tokens = tokenize('service "svc:a" { owner: "team", criticality: 3 }')
    kinds = [t.type.name for t in tokens]
    assert kinds[0] == "IDENT"
    assert "STRING" in kinds
    assert "NUMBER" in kinds
    assert kinds[-1] == "EOF"


def test_parser_builds_module_with_lists_and_nested_blocks():
    src = 'agent "a1" { capabilities: ["read", "write"], meta { owner: "x" } }'
    module = parse_source(src)
    assert len(module.blocks) == 1
    block = module.blocks[0]
    assert block.attrs["capabilities"] == ["read", "write"]
    assert block.attrs["meta"].kind == "meta"


def test_parser_rejects_malformed_source():
    from zeroform.dsl.parser import ParseError
    with pytest.raises(ParseError):
        parse_source('service "svc:a" { owner: }')


# -- semantic model / graph tests ---------------------------------------
def test_semantic_model_builds_graph(sample_source):
    module = parse_source(sample_source)
    from zeroform.core.semantic_model import build_semantic_model
    model = build_semantic_model(module)
    assert model.meta.name == "Acme Payments Reality"
    assert len(model.graph.nodes()) > 5
    assert any(n.entity_type == "TrustZone" for n in model.graph.nodes())


def test_undeclared_flow_endpoint_produces_warning():
    module = parse_source('world "w" {} \nflow "f1" { from: "ghost", to: "also_ghost" }')
    from zeroform.core.semantic_model import build_semantic_model
    model = build_semantic_model(module)
    assert any("unknown source" in w for w in model.warnings)


# -- pipeline / determinism tests ----------------------------------------
def test_pipeline_is_deterministic(sample_source):
    pipeline = CompilerPipeline()
    r1 = pipeline.compile_source(sample_source)
    r2 = pipeline.compile_source(sample_source)
    assert r1.source_model_hash == r2.source_model_hash
    assert len(r1.controls) == len(r2.controls)
    assert sorted(c.id for c in r1.controls) == sorted(c.id for c in r2.controls)


def test_pipeline_produces_signed_policies(sample_source):
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(sample_source)
    assert result.policies
    for artifact in result.policies:
        assert artifact.verify()


def test_clean_sample_world_has_no_gap_findings(sample_source):
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(sample_source)
    assert result.findings == []
    assert all(r.passed for r in result.invariant_results)


# -- gap analyzer / refactor tests ----------------------------------------
BROKEN_SOURCE = """
world "Broken" { version: "0.0.1" }
trust_zone "Internet" { level: 0 }
trust_zone "Secure" { level: 8, parent: "Internet" }
external_system "partner:x" { type: "ExternalSystem", trust_zone: "Internet" }
database "db:core" { type: "Database", trust_zone: "Secure", classification: "Restricted" }
flow "f1" { from: "partner:x", to: "db:core", action: "reads", classification: "Restricted" }
"""


def test_direct_database_access_is_flagged_and_fixable():
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(BROKEN_SOURCE)
    kinds = {f.kind for f in result.findings}
    assert "direct_database_access" in kinds

    proposals = SecurityArchitectureRefactoringEngine().propose(result.model.graph, result.findings)
    assert proposals
    fixed_graph = proposals[0].apply(result.model.graph)

    pipeline2 = CompilerPipeline()
    crossings2 = pipeline2.boundary_compiler.compile_crossings(fixed_graph)
    controls2 = pipeline2.control_engine.synthesize(crossings2)
    findings2 = pipeline2.gap_analyzer.analyze(fixed_graph, crossings2, controls2)
    assert "direct_database_access" not in {f.kind for f in findings2}


# -- policy runtime / WASM-interface tests --------------------------------
def test_policy_runtime_denies_when_control_not_satisfied(sample_source):
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(sample_source)
    artifact = next(p for p in result.policies if p.target == "json")
    runtime = PolicyRuntime(artifact)
    runtime.load()
    denied = runtime.require_control({"control_type": "authentication", "satisfied_controls": []})
    allowed = runtime.require_control({"control_type": "authentication", "satisfied_controls": ["authentication"]})
    assert denied.allow is False
    assert allowed.allow is True
    assert denied.rule_id is not None and denied.required_control == "authentication"


def test_policy_runtime_rejects_unsigned_artifact(sample_source):
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(sample_source)
    artifact = next(p for p in result.policies if p.target == "json")
    artifact.signature = "tampered" + artifact.signature[8:]
    from zeroform.core.policy_runtime import PolicyIntegrityError
    runtime = PolicyRuntime(artifact)
    with pytest.raises(PolicyIntegrityError):
        runtime.load()


def test_property_based_consistency(sample_source):
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(sample_source)
    artifact = next(p for p in result.policies if p.target == "json")
    runtime = PolicyRuntime(artifact)
    runtime.load()
    control_types = sorted({c.control_type for c in result.controls})
    report = PropertyBasedSecurityTester(seed=7).run(runtime, control_types, n=400)
    assert report["consistent"] is True


def test_mutation_testing_kills_all_default_mutations(sample_source):
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(sample_source)
    artifact = next(p for p in result.policies if p.target == "json")
    control_types = sorted({c.control_type for c in result.controls})
    framework = SecurityMutationTestingFramework(PolicyMutationEngine(), VerificationScenarioGenerator())
    report = framework.run(artifact, control_types)
    assert report["mutation_score"] == 1.0


# -- scenario / virtual environment tests ---------------------------------
def test_scenario_engine_detects_removed_control(sample_source):
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(sample_source)
    engine = ScenarioExecutionEngine(pipeline.boundary_compiler, pipeline.control_engine, pipeline.gap_analyzer)
    scenario = Scenario(
        name="policy_removal",
        actors=["user:alice"],
        events=[ScenarioEvent(type="remove_control", target="api:payments-gateway->db:payments",
                               params={"control_type": "authentication"}, at_step=1)],
    )
    result2 = engine.run(result.model.graph, scenario)
    assert result2.passed is False
    assert any("missing_authentication" in v for v in result2.violations)


# -- version control tests -------------------------------------------------
def test_version_control_commit_and_diff(tmp_path, sample_source):
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(sample_source)
    vcs = RealityVersionControl(str(tmp_path / ".zeroform"))
    c1 = vcs.commit(result.model.to_dict(), "first")
    c2 = vcs.commit(result.model.to_dict(), "second, unchanged")
    diff = vcs.diff_commits(c1.hash, c2.hash)
    assert diff.is_empty()
    assert len(vcs.log()) == 2


# -- secure package / secret boundary tests --------------------------------
def test_secure_package_never_contains_raw_secret_value(tmp_path, sample_source):
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(sample_source)
    # simulate a modeling mistake: someone put a raw secret value on the node
    for n in result.model.graph.nodes(entity_type="Secret"):
        node = result.model.graph.get_node(n.id)
        node.attrs["value"] = "hunter2"
        result.model.graph.add_node(node)

    builder = SecurePackageBuilder(SecretBoundaryEngine())
    out = builder.build(result.model, {}, str(tmp_path / "pkg.zip"))
    import zipfile, json
    with zipfile.ZipFile(out) as zf:
        model_dict = json.loads(zf.read("reality_model.json"))
    for node in model_dict["graph"]["nodes"]:
        assert "value" not in node


# -- operating hours engine tests -------------------------------------------
def test_operating_hours_open_and_closed_transitions():
    schedule = OperatingHoursSchedule(timezone_label="UTC")
    for wd in range(5):
        schedule.set_day(wd, windows=[OperatingWindow("09:00", "18:00")])
    for wd in (5, 6):
        schedule.set_day(wd, closed=True)
    engine = OperatingHoursEngine(schedule)

    # Tuesday 2026-09-22 10:00 -> open
    status_open = engine.status(datetime(2026, 9, 22, 10, 0))
    assert status_open["is_open"] is True
    assert status_open["seconds_until_close"] == pytest.approx(8 * 3600)

    # Saturday 2026-09-19 12:00 -> closed, next open Monday-equivalent weekday
    status_closed = engine.status(datetime(2026, 9, 19, 12, 0))
    assert status_closed["is_open"] is False
    assert status_closed["seconds_until_open"] is not None


def test_operating_hours_respects_holiday_exception_and_skips_ahead():
    schedule = OperatingHoursSchedule(timezone_label="UTC")
    for wd in range(7):
        schedule.set_day(wd, windows=[OperatingWindow("09:00", "18:00")])
    schedule.add_exception(ScheduleException(on_date="2026-09-21", closed=True, label="Holiday"))
    engine = OperatingHoursEngine(schedule)
    status = engine.status(datetime(2026, 9, 21, 10, 0))
    assert status["is_open"] is False
    assert status["next_open_at"].startswith("2026-09-22")


def test_operating_hours_24h_day():
    schedule = OperatingHoursSchedule(timezone_label="UTC")
    for wd in range(7):
        schedule.set_day(wd, is_24h=True)
    engine = OperatingHoursEngine(schedule)
    status = engine.status(datetime(2026, 9, 19, 3, 0))
    assert status["is_open"] is True
