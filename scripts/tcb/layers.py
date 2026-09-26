#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Enforce the dependency-layer rules for the NEMO workspace.

A layer assignment is a claim about which direction dependencies may flow: a
crate may depend on its own layer or a lower one, and an edge pointing upward
is an architectural violation. The kernel sitting above its own adapters is the
violation that matters most, because it means the kernel's own invariants are
enforced in code the kernel does not own.

Rewriting the graph takes several milestones, so this gate is a ratchet rather
than a wall. ``[grandfathered]`` in ``security/layers.toml`` lists the edges
that point upward today, and the check fails when a new one appears. The list
is printed on every run.

A grandfathered entry that no longer describes a real edge is also a failure,
not a note. Otherwise the exception outlives the debt it excused: an edge
removed on one milestone leaves a permanent hole that a later regression can
re-enter without the gate noticing. Failing on the stale entry forces the
policy to tighten while the improvement is still in the same change.

An unclassified crate is a failure, not a warning. A crate that nobody placed
is a crate whose dependencies nobody is checking.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
QUALIFICATION_DIR = SCRIPT_DIR.parent / "qualification"
for directory in (SCRIPT_DIR, QUALIFICATION_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import baseline  # noqa: E402  (local module)
import report  # noqa: E402  (local module)

REPO_ROOT = SCRIPT_DIR.parents[1]
DEFAULT_POLICY = REPO_ROOT / "security" / "layers.toml"


def layer_indexes(policy: dict) -> dict[str, int]:
    """Return the layer position of every classified crate, lowest first."""
    indexes: dict[str, int] = {}
    for position, crates in enumerate(policy["layers"].values()):
        for crate in crates:
            indexes[crate] = position
    return indexes


def upward_edges(graph: dict[str, list[str]], policy: dict) -> list[tuple[str, str]]:
    """Return every edge that points from a lower layer to a higher one."""
    indexes = layer_indexes(policy)
    problems = []
    for source, targets in graph.items():
        for target in targets:
            if source not in indexes or target not in indexes:
                continue
            if indexes[target] > indexes[source]:
                problems.append((source, target))
    return sorted(problems)


def unclassified_crates(graph: dict[str, list[str]], policy: dict) -> list[str]:
    """Return workspace crates that the layer policy does not place."""
    indexes = layer_indexes(policy)
    involved = set(graph)
    for targets in graph.values():
        involved.update(targets)
    return sorted(involved - set(indexes))


def grandfathered_edges(policy: dict) -> set[tuple[str, str]]:
    """Return the recorded upward edges as a set of pairs."""
    return {(source, target) for source, targets in policy.get("grandfathered", {}).items() for target in targets}


def unexpected_edges(upward: list[tuple[str, str]], policy: dict) -> list[tuple[str, str]]:
    """Return upward edges that the policy does not grandfather."""
    allowed = grandfathered_edges(policy)
    return [edge for edge in upward if edge not in allowed]


def stale_entries(upward: list[tuple[str, str]], policy: dict) -> list[tuple[str, str]]:
    """Return grandfathered edges that no longer exist."""
    present = set(upward)
    return sorted(edge for edge in grandfathered_edges(policy) if edge not in present)


def render(graph: dict[str, list[str]], upward: list[tuple[str, str]], policy: dict) -> str:
    """Render the layer report."""
    names = list(policy["layers"])
    rows = [f"layers: {' -> '.join(names)}", ""]
    counts = {name: 0 for name in names}
    indexes = layer_indexes(policy)
    for name in graph:
        if name in indexes:
            counts[names[indexes[name]]] += 1
    for name in names:
        rows.append(f"  {name:<14}{counts[name]:>3} crate(s)")
    rows.append("")
    if upward:
        rows.append(f"upward edges ({len(upward)}), all grandfathered:")
        rows.extend(f"  {source} -> {target}" for source, target in upward)
    else:
        rows.append("upward edges: none")
    return "\n".join(rows)


def problems_for(graph: dict[str, list[str]], policy: dict) -> list[str]:
    """Return every policy violation for a crate graph."""
    upward = upward_edges(graph, policy)
    problems = [
        f"{source} -> {target} is a new upward edge; either move the dependency "
        "down or record it in security/layers.toml with a milestone that removes it"
        for source, target in unexpected_edges(upward, policy)
    ]
    problems.extend(
        f"{source} -> {target} is grandfathered but the edge no longer exists; "
        "remove it from security/layers.toml so the exception cannot be reused"
        for source, target in stale_entries(upward, policy)
    )
    problems.extend(f"{crate} has no layer in security/layers.toml" for crate in unclassified_crates(graph, policy))
    return problems


def main(argv: list[str] | None = None) -> int:
    """Run the layer gate."""
    parser = argparse.ArgumentParser(description="Enforce the dependency-layer rules for the NEMO workspace.")
    parser.add_argument(
        "--policy",
        type=pathlib.Path,
        default=DEFAULT_POLICY,
        help="layer policy file (default: security/layers.toml)",
    )
    parser.add_argument("--root", type=pathlib.Path, default=REPO_ROOT)
    arguments = parser.parse_args(argv)

    metadata = report.cargo_metadata(arguments.root)
    graph = baseline.crate_graph(metadata)
    policy = report.load_policy(arguments.policy)

    upward = upward_edges(graph, policy)
    problems = problems_for(graph, policy)

    print(render(graph, upward, policy))
    sys.stdout.flush()

    if problems:
        print(file=sys.stderr)
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    print("\nLayer rules satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
