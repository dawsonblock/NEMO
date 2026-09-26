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


def test_source_metrics_counts_every_unsafe_token(tmp_path: pathlib.Path) -> None:
    # Counting is deliberately textual. A regular expression cannot tell a
    # comment from a `//` inside a string literal, so stripping comments can
    # only ever hide a real token. Overcounting is the correct direction for an
    # upper bound, and the first line is the case that used to swallow one.
    source = tmp_path / "crate" / "src"
    source.mkdir(parents=True)
    (source / "lib.rs").write_text(
        'let url = "https://example.com";\n'
        "// unsafe appears in this comment\n"
        "pub fn risky() { unsafe { core::ptr::null::<u8>(); } }\n",
        encoding="utf-8",
    )

    files, lines, unsafe_occurrences = report.source_metrics(source)

    assert files == 1
    assert lines == 3
    assert unsafe_occurrences == 2


def test_transitive_identity_keeps_two_versions_apart() -> None:
    identities = ["foo@1.0.0", "foo@2.0.0", "bar@1.0.0"]

    # Two resolved versions of one package are two entries, not one.
    assert len(identities) == 3
    assert report.identity_names(identities) == {"foo", "bar"}


def test_dependency_digest_ignores_order_but_not_membership() -> None:
    assert report.dependency_digest({"a", "b"}) == report.dependency_digest({"b", "a"})
    assert report.dependency_digest({"a", "b"}) != report.dependency_digest({"a", "c"})


def test_dependency_digest_distinguishes_versions() -> None:
    # The digest is computed over resolved identities. Hashing the package names
    # instead would make a version change invisible to both the count and the
    # digest.
    assert report.dependency_digest({"foo@1.0.0"}) != report.dependency_digest({"foo@2.0.0"})


def test_a_transitive_version_change_fails_the_gate(tmp_path: pathlib.Path) -> None:
    policy = {
        "forbidden": {},
        "limits": {
            "nemo-relay": {
                "transitive_dependency_digest": report.dependency_digest({"serde@1.0.0"}),
            }
        },
    }

    _, problems = report.find_violations(
        metadata(tmp_path),
        {"nemo-relay": ["serde@2.0.0"]},
        policy,
    )

    assert any("transitive_dependency_digest changed" in item for item in problems)


def test_a_swapped_direct_dependency_fails_even_though_the_count_matches(
    tmp_path: pathlib.Path,
) -> None:
    # The recorded digest is what makes a swap visible. A count-only budget
    # would pass here, which is exactly the hole this closes.
    policy = {
        "forbidden": {},
        "limits": {
            "nemo-relay": {
                "max_direct_dependencies": 1,
                "direct_dependency_digest": report.dependency_digest({"serde"}),
            }
        },
    }

    _, problems = report.find_violations(
        metadata(tmp_path, dependencies=("reqwest",)),
        {"nemo-relay": ["reqwest@0.12.0"]},
        policy,
    )

    assert any("direct_dependency_digest changed" in item for item in problems)


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


def metrics(source_lines: int) -> report.Metrics:
    """A measurement for one crate, at the size a test wants it."""
    return report.Metrics(
        crate="nemo-relay",
        source_files=1,
        source_lines=source_lines,
        unsafe_occurrences=0,
        direct_dependencies=0,
        transitive_packages=0,
        direct_dependency_digest="",
        transitive_dependency_digest="",
    )


def temporary_policy(**overrides: object) -> dict:
    """A policy with one temporary ceiling, as the repository records them."""
    entry: dict = {
        "crate": "nemo-relay",
        "field": "max_source_lines",
        "raised_to": 120,
        "target": 100,
        "reason": "a migration is in flight",
        "introduced": "abc1234",
        "must_fall_by": "loader-removal",
    }
    entry.update(overrides)
    return {
        "limits": {"nemo-relay": {"max_source_lines": entry["raised_to"]}},
        "temporary": [entry],
    }


def test_a_temporary_ceiling_has_to_promise_a_decrease() -> None:
    # A raise that does not say what it gives back is a permanent one wearing a label.
    for target in (120, 130):
        problems = report.find_temporary_problems(temporary_policy(target=target), [metrics(110)])
        assert problems, "a target at or above the ceiling must be refused"
        assert "must promise a decrease" in problems[0]


def test_a_temporary_ceiling_that_describes_no_current_budget_is_stale() -> None:
    policy = temporary_policy()
    policy["limits"]["nemo-relay"]["max_source_lines"] = 130

    problems = report.find_temporary_problems(policy, [metrics(110)])

    assert problems
    assert "describes a ceiling this policy does not have" in problems[0]


def test_a_satisfied_temporary_ceiling_has_to_be_retired() -> None:
    # The ratchet closing: once the measurement reaches the target, keeping the raised
    # budget and the entry means the ceiling was temporary in name only.
    problems = report.find_temporary_problems(temporary_policy(), [metrics(100)])

    assert problems
    assert "already fallen to 100" in problems[0]
    assert "delete the entry" in problems[0]


def test_a_temporary_ceiling_without_its_reason_is_refused() -> None:
    problems = report.find_temporary_problems(temporary_policy(must_fall_by=None), [metrics(110)])

    assert problems
    assert "is missing must_fall_by" in problems[0]


def test_a_well_formed_temporary_ceiling_passes_and_is_rendered() -> None:
    policy = temporary_policy()

    assert report.find_temporary_problems(policy, [metrics(110)]) == []
    rendered = report.render_temporary(policy)
    assert "120 -> 100" in rendered
    assert "loader-removal" in rendered
    assert report.render_temporary({}) == "temporary ceilings: none"


def test_repository_policy_measures_every_crate_it_trusts() -> None:
    policy = report.load_policy(report.DEFAULT_POLICY)

    assert policy["version"] == 1
    trusted = policy["trusted"]["crates"]
    assert "nemo-relay" in trusted
    for crate in trusted:
        assert crate in policy["limits"], f"{crate} is trusted but unmeasured"
        assert crate in policy["forbidden"], f"{crate} has no forbidden list"
        limits = policy["limits"][crate]
        assert "direct_dependency_digest" in limits, f"{crate} does not pin its direct dependency set"
        assert "transitive_dependency_digest" in limits, f"{crate} does not pin its transitive dependency set"
    for crate in policy["in_process"]["crates"]:
        assert crate in policy["limits"], f"{crate} shares the kernel's process but is unmeasured"
    for crate in policy["plugin_host"]["crates"]:
        assert crate in policy["limits"], f"{crate} hosts native plugins but is unmeasured"
