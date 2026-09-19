# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the trusted computing base gate.

The gate is only worth having if it fails when the kernel grows, so these tests
cover the two ways that happens: a forbidden package appearing in the resolved
tree, and a ratchet budget being exceeded. They run against synthetic metadata
and synthetic sources, so they never depend on the current size of the
workspace.
"""

from __future__ import annotations

import pathlib
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import report  # noqa: E402


def metadata(tmp_path: pathlib.Path, dependencies: tuple[str, ...] = ()) -> dict:
    """Build synthetic Cargo metadata describing the kernel crate."""
    return {
        "packages": [
            {
                "name": "nemo-relay",
                "id": "nemo-relay 0.1.0",
                "manifest_path": str(tmp_path / "crate" / "Cargo.toml"),
                "dependencies": [{"name": name, "kind": None, "optional": False} for name in dependencies],
            }
        ]
    }


def test_source_metrics_counts_files_lines_and_unsafe(tmp_path: pathlib.Path) -> None:
    source = tmp_path / "crate" / "src"
    source.mkdir(parents=True)
    (source / "lib.rs").write_text(
        "// unsafe is only a word in this comment\n"
        "pub fn safe() {}\n"
        "pub fn risky() { unsafe { core::ptr::null::<u8>(); } }\n",
        encoding="utf-8",
    )

    files, lines, unsafe_occurrences = report.source_metrics(source)

    assert files == 1
    assert lines == 3
    assert unsafe_occurrences == 1


def test_direct_dependencies_count_only_what_a_build_links(
    tmp_path: pathlib.Path,
) -> None:
    data = metadata(tmp_path, dependencies=("serde", "declared-but-unbuilt"))

    names = report.direct_dependency_names(data, ["serde", "transitive"], "nemo-relay")

    assert names == ["serde"]


def test_forbidden_package_fails_the_gate(tmp_path: pathlib.Path) -> None:
    policy = {"forbidden": {"nemo-relay": ["tokio-postgres"]}, "limits": {}}

    _, problems = report.find_violations(
        metadata(tmp_path),
        {"nemo-relay": ["serde", "tokio-postgres"]},
        policy,
    )

    assert problems == ["nemo-relay reaches forbidden package(s): tokio-postgres"]


def test_budget_growth_fails_the_gate(tmp_path: pathlib.Path) -> None:
    policy = {
        "forbidden": {},
        "limits": {"nemo-relay": {"max_transitive_packages": 2}},
    }

    reports, problems = report.find_violations(
        metadata(tmp_path),
        {"nemo-relay": ["one", "two", "three"]},
        policy,
    )

    assert reports[0].transitive_packages == 3
    assert problems == [
        "nemo-relay: transitive_packages is 3, budget is 2; raising the budget "
        "is a security review recorded in security/tcb.toml"
    ]


def test_a_crate_within_budget_passes(tmp_path: pathlib.Path) -> None:
    policy = {
        "forbidden": {"nemo-relay": ["tokio-postgres"]},
        "limits": {
            "nemo-relay": {
                "max_direct_dependencies": 1,
                "max_transitive_packages": 3,
            }
        },
    }

    _, problems = report.find_violations(
        metadata(tmp_path, dependencies=("serde",)),
        {"nemo-relay": ["serde", "one", "two"]},
        policy,
    )

    assert problems == []


def test_repository_policy_gives_every_trusted_crate_a_budget() -> None:
    policy = report.load_policy(report.DEFAULT_POLICY)

    assert policy["version"] == 1
    trusted = policy["trusted"]["crates"]
    assert "nemo-relay" in trusted
    for crate in trusted:
        assert crate in policy["limits"], f"{crate} is trusted but unmeasured"
        assert crate in policy["forbidden"], f"{crate} has no forbidden list"
