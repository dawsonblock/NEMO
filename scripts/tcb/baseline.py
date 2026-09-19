#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Capture the minimal-trusted-kernel baseline for the current tree.

Stage 1 of the NEMO 0.10 program is a freeze: record objective measurements
before any code moves, so later milestones compare against something real
instead of a memory of the previous layout. No behavioral change belongs in
that stage, and this script makes none.

It composes existing tooling rather than re-implementing it. The canonical
source-tree digest comes from ``scripts/qualification/source_tree.py``, and the
trusted-surface measurements come from ``scripts/tcb/report.py``. What is added
here is the recording: digests, toolchain versions, and the workspace crate
graph, written under ``reports/``.

Public API enumeration is deliberately not attempted. It needs a rustdoc-JSON
or ``cargo-public-api`` pass, and a hand-rolled approximation would be a number
that looks authoritative without being one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
QUALIFICATION_DIR = SCRIPT_DIR.parent / "qualification"
for directory in (SCRIPT_DIR, QUALIFICATION_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import report  # noqa: E402  (local module)
import source_tree  # noqa: E402  (qualification module)

REPO_ROOT = SCRIPT_DIR.parents[1]

# Lockfiles whose digest pins the dependency surface for each ecosystem.
LOCKFILES = ("Cargo.lock", "uv.lock", "package-lock.json")

# Toolchains that can change what the recorded measurements mean.
TOOLS = (("rustc", ["rustc", "--version"]), ("cargo", ["cargo", "--version"]))


def lockfile_digests(root: pathlib.Path) -> dict[str, str | None]:
    """Return a SHA-256 per lockfile, or ``None`` when it is absent."""
    digests: dict[str, str | None] = {}
    for name in LOCKFILES:
        path = pathlib.Path(root) / name
        if path.is_file():
            digests[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            digests[name] = None
    return digests


def tool_versions() -> dict[str, str | None]:
    """Return the first line of each tool's version output."""
    versions: dict[str, str | None] = {}
    for name, command in TOOLS:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
        except OSError:
            versions[name] = None
            continue
        lines = (completed.stdout or completed.stderr or "").strip().splitlines()
        versions[name] = lines[0] if lines else None
    return versions


def crate_graph(metadata: dict) -> dict[str, list[str]]:
    """Return workspace-member edges, ignoring external dependencies."""
    by_id, _ = report.package_index(metadata)
    members = {by_id[identifier]["name"] for identifier in metadata["workspace_members"]}
    graph: dict[str, list[str]] = {}
    for identifier in metadata["workspace_members"]:
        package = by_id[identifier]
        graph[package["name"]] = sorted(
            {
                dependency["name"]
                for dependency in package.get("dependencies", [])
                if dependency.get("kind") is None and dependency["name"] in members
            }
        )
    return dict(sorted(graph.items()))


def capture(root: pathlib.Path) -> dict[str, dict]:
    """Capture every baseline report for the tree at ``root``."""
    metadata = report.cargo_metadata(root)
    policy = report.load_policy(report.DEFAULT_POLICY)
    by_id, _ = report.package_index(metadata)

    entries = source_tree.enumerate_entries(root)
    repository = {
        "source_tree_digest": source_tree.entries_digest(entries),
        "enumeration_policy_version": source_tree.ENUMERATION_POLICY_VERSION,
        "entry_count": len(entries),
        "lockfiles": lockfile_digests(root),
        "toolchain": tool_versions(),
        "workspace_members": sorted(by_id[identifier]["name"] for identifier in metadata["workspace_members"]),
    }

    dependency = {
        "crate_graph": crate_graph(metadata),
        "trusted_direct_dependencies": {
            crate: report.direct_dependency_names(metadata, report.dependency_tree(root, crate), crate)
            for crate in policy["trusted"]["crates"]
        },
    }

    trees = {crate: report.dependency_tree(root, crate) for crate in policy["trusted"]["crates"]}
    trusted = {
        "policy_version": policy["version"],
        "crates": {crate: vars(report.measure(metadata, trees[crate], crate)) for crate in policy["trusted"]["crates"]},
    }

    return {
        "repository-baseline.json": repository,
        "dependency-baseline.json": dependency,
        "tcb-baseline.json": trusted,
    }


def main(argv: list[str] | None = None) -> int:
    """Write the baseline reports."""
    parser = argparse.ArgumentParser(description="Capture the minimal-trusted-kernel baseline for the current tree.")
    parser.add_argument("--root", type=pathlib.Path, default=REPO_ROOT)
    parser.add_argument("--out", type=pathlib.Path, default=REPO_ROOT / "reports")
    arguments = parser.parse_args(argv)

    reports = capture(arguments.root)
    arguments.out.mkdir(parents=True, exist_ok=True)
    for name, payload in reports.items():
        path = arguments.out / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
