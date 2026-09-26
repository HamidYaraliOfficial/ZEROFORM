"""
ZEROFORM — Security Reality Compiler
=====================================

ZEROFORM turns a declarative description of a digital system (the
"Reality Model") into an executable, testable, simulate-able security
architecture: a canonical graph, synthesized security controls,
compiled policies, a virtual security environment and a full set of
verification / regression artifacts.

Pipeline stages (see zeroform.core.pipeline.CompilerPipeline):

    Lex/Parse -> AST -> Semantic Model -> Graph Build -> Security
    Analysis -> Control Synthesis -> Policy Compilation ->
    Simulation Model -> Verification -> Artifact Generation

Package layout:

    zeroform.dsl      - DSL lexer / parser / AST
    zeroform.core     - graph model, engines, pipeline, runtime
    zeroform.api      - REST + WebSocket service (FastAPI)
    zeroform.cli      - command line interface

This module intentionally keeps the reference implementation
dependency-light (networkx instead of a live Neo4j cluster, a pure
Python capability-sandboxed runtime instead of a compiled .wasm
binary) while defining the exact interfaces production adapters
(Neo4j, wasmtime/wasmer, HSM signing, Kubernetes) are meant to
implement. See README for the extension points.
"""

__version__ = "0.1.0"
COMPILER_VERSION = __version__
