"""
ZEROFORM CLI
==============

    zeroform init        scaffold a new reality model project
    zeroform model        validate / show a reality model
    zeroform import        run an import connector into a .zf-compatible json
    zeroform compile       run the full compiler pipeline
    zeroform analyze       gap + path analysis only
    zeroform policy        list/generate policy artifacts
    zeroform simulate      run a scenario against the compiled model
    zeroform verify        run invariants + verification scenario generator
    zeroform refactor      propose architecture refactors for current findings
    zeroform test          run the regression/mutation test suites
    zeroform diff          diff two model files or two commits
    zeroform package       build a Secure Package zip
    zeroform sign          re-sign a policy artifact file
    zeroform run           start the REST/WebSocket API server
    zeroform report        build the Security Release Passport + docs
    zeroform hours         show current SOC/support operating-hours status
"""

from __future__ import annotations

import json
import os
import sys
from typing import Optional

import click

from . import COMPILER_VERSION
from .core.artifact_registry import PolicyArtifactRegistry, SecretBoundaryEngine, SecurePackageBuilder
from .core.availability import (
    DaySchedule, OperatingHoursEngine, OperatingHoursSchedule, OperatingWindow, WEEKDAY_NAMES,
)
from .core.diff_engine import GraphDiffEngine
from .core.mutation_testing import PolicyMutationEngine, SecurityMutationTestingFramework
from .core.pipeline import CompilerPipeline
from .core.policy_generator import PolicyArtifact, sign_payload, verify_signature
from .core.policy_runtime import PolicyRuntime
from .core.refactor import SecurityArchitectureRefactoringEngine
from .core.verification import PropertyBasedSecurityTester, VerificationScenarioGenerator
from .core.version_control import DEFAULT_BRANCH_NAMES, RealityVersionControl
from .dsl.parser import parse_file

SAMPLE_WORLD_PATH = os.path.join(os.path.dirname(__file__), "examples", "sample_world.zf")


@click.group()
@click.version_option(COMPILER_VERSION, prog_name="zeroform")
def cli() -> None:
    """ZEROFORM — Security Reality Compiler."""


@cli.command()
@click.option("--sample/--empty", default=True, help="scaffold with the bundled sample world or an empty file")
@click.argument("path", default="world.zf")
def init(sample: bool, path: str) -> None:
    """Create a new .zf Reality Model file and a local .zeroform/ store."""
    if os.path.exists(path):
        click.echo(f"refusing to overwrite existing file: {path}", err=True)
        sys.exit(1)
    if sample:
        with open(SAMPLE_WORLD_PATH, "r", encoding="utf-8") as fh:
            content = fh.read()
    else:
        content = 'world "New Reality" {\n  version: "0.0.1"\n}\n'
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    vcs = RealityVersionControl(".zeroform")
    for branch in DEFAULT_BRANCH_NAMES:
        vcs.create_branch(branch, from_branch="baseline") if branch != "baseline" else None
    click.echo(f"initialized {path} and .zeroform/ (branches: {', '.join(DEFAULT_BRANCH_NAMES)})")


@cli.command()
@click.argument("path")
def model(path: str) -> None:
    """Parse and print a summary of a .zf model without compiling it."""
    module = parse_file(path)
    click.echo(f"blocks: {len(module.blocks)} | imports: {len(module.imports)}")
    for kind in sorted({b.kind for b in module.blocks}):
        click.echo(f"  - {kind}: {len(module.blocks_of(kind))}")


@cli.command(name="import")
@click.option("--connector", required=True, type=click.Choice(["json_reality", "openapi", "kubernetes"]))
@click.argument("source")
@click.argument("out", default="imported.json")
def import_(connector: str, source: str, out: str) -> None:
    """Run an import connector and write a JSON reality document."""
    from .core.importers import get_connector
    conn = get_connector(connector)
    result = conn.import_(source)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result.module.to_dict(), fh, indent=2, default=str)
    for w in result.warnings:
        click.echo(f"warning: {w}", err=True)
    click.echo(f"imported {len(result.module.blocks)} block(s) -> {out}")


@cli.command()
@click.argument("path", default=SAMPLE_WORLD_PATH)
@click.option("--explain/--no-explain", default=False, help="print every intermediate pipeline stage")
@click.option("--targets", default="json,wasm", help="comma separated policy targets")
def compile(path: str, explain: bool, targets: str) -> None:
    """Run the full Lex/Parse -> ... -> Artifact Generation pipeline."""
    pipeline = CompilerPipeline(policy_targets=targets.split(","))
    result = pipeline.compile_source(open(path, encoding="utf-8").read(), source_name=path)
    click.echo(f"compiled '{result.model.meta.name}' v{result.model.meta.version} in {result.duration_seconds:.4f}s")
    click.echo(f"  nodes={len(result.model.graph.nodes())} edges={len(result.model.graph.edges())}")
    click.echo(f"  boundary_crossings={len(result.crossings)} controls={len(result.controls)} policies={len(result.policies)}")
    click.echo(f"  findings={len(result.findings)} source_model_hash={result.source_model_hash[:16]}...")
    if explain:
        click.echo(json.dumps(result.stages, indent=2, default=str))


@cli.command()
@click.argument("path", default=SAMPLE_WORLD_PATH)
def analyze(path: str) -> None:
    """Gap + path analysis only."""
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(open(path, encoding="utf-8").read(), source_name=path)
    for f in result.findings:
        click.echo(f"[{f.severity:>8}] {f.kind}: {f.description}")
    if not result.findings:
        click.echo("no findings.")


@cli.command()
@click.argument("path", default=SAMPLE_WORLD_PATH)
@click.option("--out", default="policies")
def policy(path: str, out: str) -> None:
    """Generate and write policy artifacts to a directory."""
    os.makedirs(out, exist_ok=True)
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(open(path, encoding="utf-8").read(), source_name=path)
    for artifact in result.policies:
        fp = os.path.join(out, f"{artifact.policy_id}.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(artifact.to_dict(), fh, indent=2, default=str)
        click.echo(f"wrote {fp} (signature valid: {artifact.verify()})")


@cli.command()
@click.argument("path", default=SAMPLE_WORLD_PATH)
@click.option("--n", default=300, help="number of property-based combinations to check")
def verify(path: str, n: int) -> None:
    """Run invariants + a property-based consistency check against the compiled policy runtime."""
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(open(path, encoding="utf-8").read(), source_name=path)
    for r in result.invariant_results:
        status = "PASS" if r.passed else "FAIL"
        click.echo(f"[{status}] {r.name} ({len(r.violations)} violation(s))")

    json_artifact = next((p for p in result.policies if p.target == "json"), None)
    if json_artifact:
        runtime = PolicyRuntime(json_artifact)
        runtime.load()
        control_types = sorted({c.control_type for c in result.controls}) or ["authentication"]
        tester = PropertyBasedSecurityTester()
        prop_result = tester.run(runtime, control_types, n=n)
        click.echo(f"property-based test: {prop_result['combinations_checked']} combinations, "
                   f"consistent={prop_result['consistent']}")


@cli.command()
@click.argument("path", default=SAMPLE_WORLD_PATH)
def refactor(path: str) -> None:
    """Propose architecture refactors for the current findings."""
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(open(path, encoding="utf-8").read(), source_name=path)
    engine = SecurityArchitectureRefactoringEngine()
    proposals = engine.propose(result.model.graph, result.findings)
    for p in proposals:
        click.echo(f"- {p.title}\n    benefit: {p.security_benefit}\n    cost: {p.operational_cost}")
    if not proposals:
        click.echo("no refactor proposals for the current findings.")


@cli.command()
@click.argument("path", default=SAMPLE_WORLD_PATH)
def test(path: str) -> None:
    """Run the mutation-testing framework against the compiled policy."""
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(open(path, encoding="utf-8").read(), source_name=path)
    json_artifact = next((p for p in result.policies if p.target == "json"), None)
    if not json_artifact:
        click.echo("no json policy artifact produced; nothing to mutation-test", err=True)
        return
    framework = SecurityMutationTestingFramework(PolicyMutationEngine(), VerificationScenarioGenerator())
    control_types = sorted({c.control_type for c in result.controls})
    report = framework.run(json_artifact, control_types)
    click.echo(f"mutation score: {report['mutation_score']:.2f}")
    for r in report["results"]:
        click.echo(f"  [{'KILLED' if r['killed'] else 'SURVIVED'}] {r['mutation_id']}: {r['description']}")


@cli.command()
@click.argument("path_a")
@click.argument("path_b")
def diff(path_a: str, path_b: str) -> None:
    """Diff two .zf model files."""
    pipeline = CompilerPipeline()
    a = pipeline.compile_source(open(path_a, encoding="utf-8").read(), source_name=path_a)
    b = pipeline.compile_source(open(path_b, encoding="utf-8").read(), source_name=path_b)
    d = GraphDiffEngine().diff(a.model.graph, b.model.graph)
    click.echo(json.dumps(d.to_dict(), indent=2, default=str))


@cli.command()
@click.argument("path", default=SAMPLE_WORLD_PATH)
@click.option("--out", default="package.zeroform.zip")
def package(path: str, out: str) -> None:
    """Build a Secure Package zip (schema + policies, no raw secrets)."""
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(open(path, encoding="utf-8").read(), source_name=path)
    builder = SecurePackageBuilder(SecretBoundaryEngine())
    extra = {"policies.json": [p.to_dict() for p in result.policies],
             "findings.json": [f.__dict__ for f in result.findings]}
    out_path = builder.build(result.model, extra, out)
    click.echo(f"wrote secure package -> {out_path}")


@cli.command()
@click.argument("artifact_path")
def sign(artifact_path: str) -> None:
    """Re-sign a policy artifact JSON file with the local signing key."""
    with open(artifact_path, encoding="utf-8") as fh:
        data = json.load(fh)
    artifact = PolicyArtifact(**{k: v for k, v in data.items() if k != "signature"})
    artifact.sign()
    with open(artifact_path, "w", encoding="utf-8") as fh:
        json.dump(artifact.to_dict(), fh, indent=2, default=str)
    click.echo(f"re-signed {artifact_path}")


@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8000)
def run(host: str, port: int) -> None:
    """Start the REST/WebSocket API server (requires uvicorn+fastapi)."""
    import uvicorn
    uvicorn.run("zeroform.api.server:app", host=host, port=port, reload=False)


@cli.command()
@click.argument("path", default=SAMPLE_WORLD_PATH)
@click.option("--out", default="release_passport.json")
def report(path: str, out: str) -> None:
    """Build the Security Release Passport + Markdown documentation."""
    from .core.documentation import SecurityDocumentationCompiler, SecurityReleasePassport
    pipeline = CompilerPipeline()
    result = pipeline.compile_source(open(path, encoding="utf-8").read(), source_name=path)
    passport = SecurityReleasePassport().build(result.model, result.controls, result.findings,
                                                result.policies, result.invariant_results, [])
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(passport, fh, indent=2, default=str)
    docs = SecurityDocumentationCompiler().compile(result.model, result.crossings, result.controls, result.findings)
    docs_path = os.path.splitext(out)[0] + ".md"
    with open(docs_path, "w", encoding="utf-8") as fh:
        fh.write(docs)
    click.echo(f"wrote {out} and {docs_path}")


@cli.command()
@click.option("--config", default=None, help="path to a JSON OperatingHoursSchedule; uses a Mon-Fri 09:00-18:00 default if omitted")
def hours(config: Optional[str]) -> None:
    """Show current SOC/support desk status and time until the next transition."""
    if config and os.path.exists(config):
        with open(config, encoding="utf-8") as fh:
            schedule = OperatingHoursSchedule.from_dict(json.load(fh))
    else:
        schedule = OperatingHoursSchedule(timezone_label="UTC")
        for wd in range(5):
            schedule.set_day(wd, windows=[OperatingWindow("09:00", "18:00")])
        for wd in (5, 6):
            schedule.set_day(wd, closed=True)
    engine = OperatingHoursEngine(schedule)
    status = engine.status()
    click.echo(json.dumps(status, indent=2, default=str))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
