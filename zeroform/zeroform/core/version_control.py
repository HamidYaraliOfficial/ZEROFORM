"""
Reality Version Control
==========================

A small, dependency-free, git-inspired object store for Reality
Models: every commit is content-addressed (sha256 of its JSON), refs
map branch/tag names to commit ids, and the working tree can be
checked out, diffed and restored. This backs the Security Branching
System (Baseline / Experimental / Hardened / Future / Audit Candidate
branches) and the CLI's ``commit`` / ``branch`` / ``diff`` / ``tag`` /
``restore`` commands.

Storage layout on disk (default ``.zeroform/``)::

    .zeroform/objects/<hash>.json      content-addressed commit objects
    .zeroform/refs/heads/<branch>      branch name -> commit hash
    .zeroform/refs/tags/<tag>          tag name -> commit hash
    .zeroform/HEAD                     current branch name
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .diff_engine import GraphDiff, GraphDiffEngine
from .graph_model import GraphRepository, NetworkXGraphRepository

DEFAULT_BRANCH_NAMES = ["baseline", "experimental", "hardened", "future", "audit-candidate"]


@dataclass
class Commit:
    hash: str
    message: str
    author: str
    timestamp: float
    parent: Optional[str]
    model_snapshot: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class RealityVersionControl:
    def __init__(self, root: str = ".zeroform"):
        self.root = root
        self.objects_dir = os.path.join(root, "objects")
        self.heads_dir = os.path.join(root, "refs", "heads")
        self.tags_dir = os.path.join(root, "refs", "tags")
        self.head_file = os.path.join(root, "HEAD")
        os.makedirs(self.objects_dir, exist_ok=True)
        os.makedirs(self.heads_dir, exist_ok=True)
        os.makedirs(self.tags_dir, exist_ok=True)
        if not os.path.exists(self.head_file):
            self._write(self.head_file, "baseline")

    # -- low level -------------------------------------------------------
    @staticmethod
    def _write(path: str, content: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)

    @staticmethod
    def _read(path: str) -> Optional[str]:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()

    def current_branch(self) -> str:
        return self._read(self.head_file) or "baseline"

    def checkout_branch(self, name: str) -> None:
        self._write(self.head_file, name)

    def _object_path(self, commit_hash: str) -> str:
        return os.path.join(self.objects_dir, f"{commit_hash}.json")

    def _branch_ref_path(self, name: str) -> str:
        return os.path.join(self.heads_dir, name)

    def _tag_ref_path(self, name: str) -> str:
        return os.path.join(self.tags_dir, name)

    # -- porcelain -------------------------------------------------------
    def commit(self, model_dict: Dict[str, Any], message: str, author: str = "zeroform-cli",
               branch: Optional[str] = None) -> Commit:
        branch = branch or self.current_branch()
        parent = self._read(self._branch_ref_path(branch))
        payload = {
            "message": message, "author": author, "timestamp": time.time(),
            "parent": parent, "model_snapshot": model_dict,
        }
        commit_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:16]
        commit = Commit(hash=commit_hash, **payload)
        self._write(self._object_path(commit_hash), json.dumps(commit.to_dict(), default=str))
        self._write(self._branch_ref_path(branch), commit_hash)
        return commit

    def get_commit(self, commit_hash: str) -> Optional[Commit]:
        raw = self._read(self._object_path(commit_hash))
        if raw is None:
            return None
        data = json.loads(raw)
        return Commit(**data)

    def branch_head(self, branch: str) -> Optional[Commit]:
        h = self._read(self._branch_ref_path(branch))
        return self.get_commit(h) if h else None

    def create_branch(self, name: str, from_branch: Optional[str] = None) -> None:
        source = from_branch or self.current_branch()
        head_hash = self._read(self._branch_ref_path(source))
        if head_hash:
            self._write(self._branch_ref_path(name), head_hash)
        else:
            self._write(self._branch_ref_path(name), "")

    def tag(self, name: str, branch: Optional[str] = None) -> None:
        branch = branch or self.current_branch()
        head_hash = self._read(self._branch_ref_path(branch))
        if head_hash:
            self._write(self._tag_ref_path(name), head_hash)

    def list_branches(self) -> List[str]:
        return sorted(os.listdir(self.heads_dir)) if os.path.exists(self.heads_dir) else []

    def list_tags(self) -> List[str]:
        return sorted(os.listdir(self.tags_dir)) if os.path.exists(self.tags_dir) else []

    def log(self, branch: Optional[str] = None) -> List[Commit]:
        branch = branch or self.current_branch()
        commits = []
        current = self.branch_head(branch)
        while current is not None:
            commits.append(current)
            current = self.get_commit(current.parent) if current.parent else None
        return commits

    def diff_commits(self, a_hash: str, b_hash: str) -> GraphDiff:
        a = self.get_commit(a_hash)
        b = self.get_commit(b_hash)
        if not a or not b:
            raise KeyError("unknown commit hash")
        graph_a = NetworkXGraphRepository.from_dict(a.model_snapshot.get("graph", {}))
        graph_b = NetworkXGraphRepository.from_dict(b.model_snapshot.get("graph", {}))
        return GraphDiffEngine().diff(graph_a, graph_b)

    def restore(self, commit_hash: str, branch: Optional[str] = None) -> Commit:
        branch = branch or self.current_branch()
        commit = self.get_commit(commit_hash)
        if not commit:
            raise KeyError(f"unknown commit {commit_hash}")
        self._write(self._branch_ref_path(branch), commit_hash)
        return commit
