#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Report and enforce the trusted computing base (TCB) budget.

The TCB is the set of crates whose failure could directly violate NEMO's core
security and correctness guarantees. Repository size is not the constraint that
matters; the reachable surface of those crates is. This script measures the
trusted crates declared in ``security/tcb.toml`` and enforces two things:

* ``[forbidden]`` lists packages that must never appear anywhere in a trusted
  crate's resolved dependency tree, so an implementation cannot leak into a
  boundary that is supposed to depend only on interfaces.
* ``[limits]`` are ratchet budgets. Exceeding one fails the gate, so growing the
  trusted surface has to be an explicit, reviewable edit to the policy file
  rather than an invisible side effect of an unrelated change.

Dependencies are measured with ``cargo tree`` against ``--all-features``, so a
package cannot hide behind a feature flag. ``cargo metadata`` alone is not
enough: it resolves optional dependencies whether or not a build activates
them, which reports coupling that no build actually links.

Source metrics cover every file under a trusted crate's ``src`` directory,
including inline test modules, and strip line comments before counting
``unsafe``. Treating both numbers as upper bounds is deliberate: a budget that
silently undercounts the kernel is worse than one that is slightly pessimistic.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_POLICY = REPO_ROOT / "security" / "tcb.toml"

LINE_COMMENT = re.compile(r"//.*$")
UNSAFE = re.compile(r"\bunsafe\b")

# Budget keys mapped to the measurement they cap.
LIMIT_FIELDS = {
    "max_direct_dependencies": "direct_dependencies",
    "max_transitive_packages": "transitive_packages",
    "max_source_lines": "source_lines",
    "max_unsafe_occurrences": "unsafe_occurrences",
}


@dataclass(frozen=True)
class Metrics:
    """Measurements for one trusted crate."""

    crate: str
    source_files: int
    source_lines: int
    unsafe_occurrences: int
    direct_dependencies: int
    transitive_packages: int


def load_policy(path: pathlib.Path) -> dict:
    """Read the TCB policy file."""
    with pathlib.Path(path).open("rb") as handle:
        return tomllib.load(handle)


def cargo_metadata(repo_root: pathlib.Path) -> dict:
    """Return resolved Cargo metadata for the workspace.

    ``--locked`` is deliberate: a report that silently rewrote the lockfile
    would measure something other than what the repository records.
    """
    completed = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def package_index(metadata: dict) -> tuple[dict, dict]:
    """Return ``(by_id, by_name)`` indexes over the resolved packages."""
    by_id = {package["id"]: package for package in metadata["packages"]}
    by_name = {package["name"]: package for package in metadata["packages"]}
    return by_id, by_name


def dependency_tree(repo_root: pathlib.Path, crate: str) -> list[str]:
    """Return every package in the crate's widest build, excluding the crate."""
    completed = subprocess.run(
        [
            "cargo",
            "tree",
            "-p",
            crate,
            "--all-features",
            "--locked",
            "--prefix",
            "none",
        ],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    names = {line.split()[0] for line in completed.stdout.splitlines() if line.strip()}
    names.discard(crate)
    return sorted(names)


def direct_dependency_names(metadata: dict, tree: list[str], crate: str) -> list[str]:
    """Return the crate's declared direct dependencies that a build links."""
    _, by_name = package_index(metadata)
    declared = {
        dependency["name"] for dependency in by_name[crate].get("dependencies", []) if dependency.get("kind") is None
    }
    return sorted(declared.intersection(tree))


def source_metrics(crate_dir: pathlib.Path) -> tuple[int, int, int]:
    """Return ``(files, lines, unsafe_occurrences)`` for the crate's sources."""
    files = sorted(pathlib.Path(crate_dir).rglob("*.rs"))
    lines = 0
    unsafe_occurrences = 0
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines += text.count("\n")
        code = "\n".join(LINE_COMMENT.sub("", line) for line in text.splitlines())
        unsafe_occurrences += len(UNSAFE.findall(code))
    return len(files), lines, unsafe_occurrences


def measure(metadata: dict, tree: list[str], crate: str) -> Metrics:
    """Measure one trusted crate against the resolved metadata."""
    _, by_name = package_index(metadata)
    crate_dir = pathlib.Path(by_name[crate]["manifest_path"]).parent / "src"
    source_files, source_lines, unsafe_occurrences = source_metrics(crate_dir)
    return Metrics(
        crate=crate,
        source_files=source_files,
        source_lines=source_lines,
        unsafe_occurrences=unsafe_occurrences,
        direct_dependencies=len(direct_dependency_names(metadata, tree, crate)),
        transitive_packages=len(tree),
    )


def find_violations(metadata: dict, trees: dict[str, list[str]], policy: dict) -> tuple[list[Metrics], list[str]]:
    """Return the per-crate report and every policy violation."""
    reports: list[Metrics] = []
    problems: list[str] = []

    for crate, forbidden in sorted(policy.get("forbidden", {}).items()):
        hits = sorted(set(trees[crate]).intersection(forbidden))
        if hits:
            problems.append(f"{crate} reaches forbidden package(s): {', '.join(hits)}")

    for crate, limits in sorted(policy.get("limits", {}).items()):
        metrics = measure(metadata, trees[crate], crate)
        reports.append(metrics)
        for field, attribute in LIMIT_FIELDS.items():
            if field not in limits:
                continue
            actual = getattr(metrics, attribute)
            budget = limits[field]
            if actual > budget:
                problems.append(
                    f"{crate}: {attribute} is {actual}, budget is {budget}; "
                    "raising the budget is a security review recorded in "
                    "security/tcb.toml"
                )

    return reports, problems


def render(reports: list[Metrics]) -> str:
    """Render the report table."""
    header = f"{'crate':<22}{'files':>7}{'lines':>9}{'unsafe':>8}{'direct':>8}{'transitive':>12}"
    rows = [header, "-" * len(header)]
    for metrics in reports:
        rows.append(
            f"{metrics.crate:<22}{metrics.source_files:>7}"
            f"{metrics.source_lines:>9}{metrics.unsafe_occurrences:>8}"
            f"{metrics.direct_dependencies:>8}{metrics.transitive_packages:>12}"
        )
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    """Run the TCB gate."""
    parser = argparse.ArgumentParser(description="Report and enforce the trusted computing base budget.")
    parser.add_argument(
        "--policy",
        type=pathlib.Path,
        default=DEFAULT_POLICY,
        help="TCB policy file (default: security/tcb.toml)",
    )
    parser.add_argument(
        "--metadata",
        type=pathlib.Path,
        help="read resolved Cargo metadata from this file instead of running cargo",
    )
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=REPO_ROOT,
        help="workspace root used when invoking cargo",
    )
    arguments = parser.parse_args(argv)

    if arguments.metadata:
        metadata = json.loads(arguments.metadata.read_text(encoding="utf-8"))
    else:
        metadata = cargo_metadata(arguments.repo_root)

    policy = load_policy(arguments.policy)
    crates = sorted(set(policy.get("limits", {})) | set(policy.get("forbidden", {})))
    trees = {crate: dependency_tree(arguments.repo_root, crate) for crate in crates}
    reports, problems = find_violations(metadata, trees, policy)

    print(render(reports))
    if problems:
        print(file=sys.stderr)
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print("\nTCB budget satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
