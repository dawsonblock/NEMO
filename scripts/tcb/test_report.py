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


def test_the_measurement_names_a_target_instead_of_taking_the_host(tmp_path: pathlib.Path, monkeypatch) -> None:
    # `cargo tree` answers for the machine it runs on unless a target is named, and
    # the platform-specific tail of a graph is real — Linux resolves `openssl-sys`
    # where macOS resolves `security-framework`, and a build-dependency is resolved
    # for the machine doing the building. A baseline recorded on one host and enforced
    # on another therefore disagrees with itself, which is how this gate came to fail
    # in CI while passing locally. The flag is asserted here rather than trusted to
    # review, because dropping it makes the gate depend on who ran it again and the
    # failure would land on whoever pushed from the other platform.
    calls: list[list[str]] = []

    class Completed:
        stdout = "nemo-relay v0.1.0\n"

    def run(argv, **_kwargs):  # noqa: ANN001 - stands in for subprocess.run
        calls.append(list(argv))
        return Completed()

    monkeypatch.setattr(report.subprocess, "run", run)
    report.dependency_identities(tmp_path, "nemo-relay")
    report.kernel_closure_names(tmp_path, ["nemo-relay"], target="aarch64-apple-darwin")

    def target_of(argv: list[str]) -> str:
        return argv[argv.index("--target") + 1]

    assert target_of(calls[0]) == report.BUDGET_TARGET
    assert target_of(calls[1]) == "aarch64-apple-darwin"
    # The budgets are the union, because a budget has to be the same number wherever
    # it is computed; the closure names the platform it is asking about, because it
    # asks what one process can reach rather than how large a resolved set is.
    assert report.BUDGET_TARGET == "all"
    assert report.BUDGET_TARGET not in report.DEFAULT_CLOSURE_TARGETS
    # More than one platform, because the property is about each of them: a check that
    # named one target left an edge that resolves only for musl or only for macOS
    # unasked while still reading as universal.
    assert len(report.DEFAULT_CLOSURE_TARGETS) > 1


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


# ---- the kernel closure, and what it can still reach ----

CLOSURE_POLICY = {
    "kernel_closure": {
        "targets": ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"],
        "roots": ["nemo-relay"],
        "forbidden": ["libloading", "nemo-relay-plugin", "native-loader"],
        "reachable_now": ["libloading", "nemo-relay-plugin"],
    }
}


def test_a_recorded_loader_package_is_the_remaining_work_and_not_a_failure() -> None:
    # The list is a record, not a permission: these are the crates the split still
    # has to move, and the gate stays green while the closure reaches them and no
    # further.
    reachable = {"x86_64-unknown-linux-gnu": {"nemo-relay", "libloading", "nemo-relay-plugin", "serde"}}

    assert report.kernel_closure_reachability(CLOSURE_POLICY, reachable["x86_64-unknown-linux-gnu"]) == {
        "libloading",
        "nemo-relay-plugin",
    }
    assert report.find_closure_problems(CLOSURE_POLICY, reachable) == []


def test_a_loader_package_the_policy_does_not_record_fails() -> None:
    # A crate that loads native code reaching the kernel is the failure this check
    # exists for, and it is a dependency edge somebody added rather than the work
    # the policy already knows about.
    reachable = {"x86_64-unknown-linux-gnu": {"nemo-relay", "libloading", "nemo-relay-plugin", "native-loader"}}

    problems = report.find_closure_problems(CLOSURE_POLICY, reachable)

    assert len(problems) == 1
    assert "native-loader" in problems[0]
    assert "not one of the loader packages the policy records" in problems[0]
    # The platform is part of the failure: a reach one platform's graph has is still
    # a reach, and a message that named none would leave the reader guessing which
    # build to look at.
    assert "x86_64-unknown-linux-gnu" in problems[0]


def test_a_reach_only_one_target_has_is_still_reported_for_that_target() -> None:
    clean = {"nemo-relay", "serde"}
    reaching = {"nemo-relay", "native-loader"}

    assert report.find_closure_problems(CLOSURE_POLICY, {"x86_64-unknown-linux-gnu": clean}) == []
    problems = report.find_closure_problems(
        CLOSURE_POLICY, {"x86_64-unknown-linux-gnu": clean, "aarch64-apple-darwin": reaching}
    )

    assert len(problems) == 1
    assert "aarch64-apple-darwin" in problems[0]
    assert "native-loader" in problems[0]


def test_a_policy_without_a_closure_section_checks_nothing() -> None:
    # A crate that has not been split yet has nothing to record, and the check says
    # so rather than reporting an empty closure as a pass.
    assert report.find_closure_problems({}, {"a-target": {"libloading"}}) == []


# ---- the platform that is recorded rather than enforced ----

WINDOWS_EXEMPT_POLICY = {
    "kernel_closure": {
        "targets": ["x86_64-unknown-linux-gnu"],
        "roots": ["nemo-relay"],
        "forbidden": ["libloading", "nemo-relay-plugin"],
        "reachable_now": [],
        "platform_external": [
            {
                "target": "x86_64-pc-windows-msvc",
                "packages": ["libloading"],
                "reason": "the binding's own runtime loader on that platform",
            }
        ],
    }
}


def test_a_recorded_platform_loader_has_to_still_be_there() -> None:
    # An exemption is measured like everything else in this file. If the resolve no
    # longer needs it, the record is permitting a reach that is not there instead of
    # describing one that is, and the next reader would have no reason to look.
    holds = {"x86_64-pc-windows-msvc": {"nemo-relay", "libloading"}}
    assert report.find_platform_external_problems(WINDOWS_EXEMPT_POLICY, holds) == []

    stale = {"x86_64-pc-windows-msvc": {"nemo-relay"}}
    problems = report.find_platform_external_problems(WINDOWS_EXEMPT_POLICY, stale)

    assert len(problems) == 1
    assert "stale" in problems[0]
    assert "libloading" in problems[0]


def test_a_platform_exemption_covers_only_the_packages_it_names() -> None:
    # Otherwise a platform's own loader becomes cover for this repository's: the
    # exemption is for `libloading` on Windows, not for whatever else that resolve
    # might gain.
    reaching = {"x86_64-pc-windows-msvc": {"nemo-relay", "libloading", "nemo-relay-plugin"}}
    problems = report.find_platform_external_problems(WINDOWS_EXEMPT_POLICY, reaching)

    assert len(problems) == 1
    assert "nemo-relay-plugin" in problems[0]
    assert "does not cover" in problems[0]


def test_an_enforced_target_may_not_also_be_exempt() -> None:
    policy = {
        "kernel_closure": {
            **WINDOWS_EXEMPT_POLICY["kernel_closure"],
            "targets": ["x86_64-pc-windows-msvc"],
        }
    }
    problems = report.find_platform_external_problems(policy, {"x86_64-pc-windows-msvc": {"nemo-relay", "libloading"}})

    assert len(problems) == 1
    assert "both enforced and recorded" in problems[0]


def test_a_platform_exemption_with_no_reason_is_reported() -> None:
    policy = {
        "kernel_closure": {
            **WINDOWS_EXEMPT_POLICY["kernel_closure"],
            "platform_external": [{"target": "x86_64-pc-windows-msvc", "packages": ["libloading"]}],
        }
    }
    problems = report.find_platform_external_problems(policy, {"x86_64-pc-windows-msvc": {"nemo-relay", "libloading"}})

    assert len(problems) == 1
    assert "gives no reason" in problems[0]


LIBRARY_CLOSURE_POLICY = {
    "kernel_library_closure": {
        "roots": ["nemo-relay"],
        "forbidden": ["libloading", "nemo-relay-plugin", "native-loader"],
    }
}


def test_the_kernel_library_may_not_reach_a_loader_at_all() -> None:
    # This is the property rather than the ratchet: the kernel library reaching a
    # package that loads native code is a failure, and there is no entry a policy
    # can record to make it a passing debt. A clean closure is the only pass.
    clean = {"x86_64-unknown-linux-gnu": {"nemo-relay", "nemo-relay-types", "serde"}}
    assert report.find_library_closure_problems(LIBRARY_CLOSURE_POLICY, clean) == []

    reaching = {"aarch64-apple-darwin": {"nemo-relay", "libloading", "serde"}}
    problems = report.find_library_closure_problems(LIBRARY_CLOSURE_POLICY, reaching)
    assert len(problems) == 1
    assert "libloading" in problems[0]
    assert "aarch64-apple-darwin" in problems[0]


def test_a_policy_without_a_library_closure_section_checks_nothing() -> None:
    assert report.find_library_closure_problems({}, {"a-target": {"libloading"}}) == []


def test_a_second_canonical_figure_in_the_document_fails(tmp_path: pathlib.Path) -> None:
    # The drift this gate exists for was one document stating two different figures,
    # so a lookup that returns the first number it understands is not enough: a
    # second canonical line has to fail.
    document = tmp_path / "security"
    document.mkdir()
    (document / "PLUGIN-ISOLATION.md").write_text(
        "kernel-process unsafe tokens: 648\n"
        "... prose that says nothing canonical ...\n"
        "kernel-process unsafe tokens: 622\n"
    )

    value, problems = report.documented_kernel_unsafe(tmp_path)

    assert value == 648
    assert len(problems) == 1
    assert "622" in problems[0] and "648" in problems[0]


def test_one_canonical_figure_is_not_a_problem(tmp_path: pathlib.Path) -> None:
    document = tmp_path / "security"
    document.mkdir()
    (document / "PLUGIN-ISOLATION.md").write_text("kernel-process unsafe tokens: 26\n")

    value, problems = report.documented_kernel_unsafe(tmp_path)

    assert value == 26
    assert problems == []


def test_the_surface_renders_what_the_closure_reaches() -> None:
    policy = {
        "trusted": {"crates": []},
        "in_process": {"crates": []},
        "plugin_host": {"crates": []},
        **CLOSURE_POLICY,
    }

    rendered = report.render_surface(
        {"packages": []}, {}, policy, {"x86_64-unknown-linux-gnu": {"libloading", "serde"}}
    )

    assert "kernel closure reaches (x86_64-unknown-linux-gnu): libloading" in rendered


def test_the_surface_keeps_the_test_tree_fact_visible() -> None:
    # The artifact is what the reachability target is about, so the metric counts
    # normal and build edges. What only a dev-dependency reaches is reported beside
    # it: folding it in would make the target unreachable for a reason the symbol
    # proof covers, and dropping it would hide a real dependency edge.
    policy = {
        "trusted": {"crates": []},
        "in_process": {"crates": []},
        "plugin_host": {"crates": []},
        **CLOSURE_POLICY,
    }

    rendered = report.render_surface(
        {"packages": []},
        {},
        policy,
        {"x86_64-unknown-linux-gnu": {"libloading"}},
        {"nemo-relay-plugin"},
    )

    assert "kernel closure reaches (x86_64-unknown-linux-gnu): libloading" in rendered
    assert "and the test tree alone reaches: nemo-relay-plugin" in rendered


def test_the_closure_counts_a_dev_only_package_as_part_of_the_test_tree() -> None:
    # The check itself is about the build graph, so a package that only a
    # dev-dependency reaches is not a failure — which is what makes the target
    # attainable without deleting the tests that exercise the loader.
    reachable = {"nemo-relay", "libloading"}
    everything = reachable | {"nemo-relay-plugin"}

    assert report.find_closure_problems(CLOSURE_POLICY, {"x86_64-unknown-linux-gnu": reachable}) == []
    # The test-tree half is computed the same way from the wider set, so a
    # *new* package there is still visible rather than silently accepted.
    assert report.kernel_closure_reachability(CLOSURE_POLICY, everything) == {
        "libloading",
        "nemo-relay-plugin",
    }


def test_the_repository_policy_records_a_closure_that_reaches_nothing_anywhere() -> None:
    # The policy's own record has to be the measurement: a recorded list that no
    # longer matches would make the ratchet pass by describing a graph that is not
    # there. The record is empty now, and this test is what would notice it becoming
    # non-empty again — which is the milestone's structural property rather than its
    # progress, so it is asserted here as well as in the report.
    policy = report.load_policy(report.DEFAULT_POLICY)
    closure = policy["kernel_closure"]
    reachable = {
        target: report.kernel_closure_names(report.REPO_ROOT, closure["roots"], target=target)
        for target in report.closure_targets(policy)
    }
    enforced = {target: reachable[target] for target in closure["targets"]}

    assert report.find_closure_problems(policy, enforced) == []
    assert report.find_platform_external_problems(policy, reachable) == []
    assert closure["reachable_now"] == [], (
        "the kernel and the composition surfaces reach nothing that loads native "
        "code; a non-empty record here is the split going backwards"
    )
    assert set(closure["forbidden"]), "a closure with no forbidden set checks nothing"
    for target, names in enforced.items():
        assert report.kernel_closure_reachability(policy, names) == set(), target


def test_the_repository_policy_names_every_packaged_target_and_measures_the_rest() -> None:
    # Two properties, and each one was missing at some point. The enforced set has to
    # be every platform the packages ship on, rather than the platform CI runs on; and
    # the platform that is not enforced has to be measured under a record, so a
    # target-specific reach is a named fact instead of an omission.
    policy = report.load_policy(report.DEFAULT_POLICY)
    closure = policy["kernel_closure"]
    library = policy["kernel_library_closure"]
    enforced = set(closure["targets"])

    assert enforced == set(report.DEFAULT_CLOSURE_TARGETS)
    assert set(library["targets"]) == enforced, "both closures ask about the same platforms"
    records = report.platform_external_records(policy)
    assert records, "the platform whose resolve reaches a loader is recorded rather than omitted"
    for record in records:
        assert record["target"] not in enforced
        assert record.get("reason", "").strip()
        assert set(record["packages"]).issubset(set(closure["forbidden"]))
