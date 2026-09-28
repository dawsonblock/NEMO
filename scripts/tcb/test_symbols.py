# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the artifact symbol gate's own logic."""

from __future__ import annotations

import pathlib

import pytest

import symbols


def artifact(
    *,
    name: str = "an artifact",
    package: str = "a-package",
    path: str = "target/release/a-binary",
    forbidden: list[str] | None = None,
    recorded: list[dict] | None = None,
) -> symbols.Artifact:
    """One artifact, as the policy file writes it."""
    return symbols.Artifact(
        name=name,
        package=package,
        path=path,
        forbidden=["libloading"] if forbidden is None else forbidden,
        recorded=[] if recorded is None else recorded,
    )


def test_a_forbidden_token_fails_with_no_budget() -> None:
    problems = symbols.problems_for(
        artifact(),
        ["_libloading_lookup"],
        [],
    )

    assert len(problems) == 1
    assert "libloading" in problems[0]


def test_a_clean_artifact_passes() -> None:
    assert symbols.problems_for(artifact(), ["_some_symbol"], ["_dlsym"]) == []


def test_a_recorded_token_over_its_budget_fails() -> None:
    recorded = artifact(
        recorded=[{"token": "dlsym", "budget": 1, "why": "a dependency's lookup"}]
    )

    assert symbols.problems_for(recorded, [], ["_dlsym"]) == []
    problems = symbols.problems_for(recorded, ["_dlsym_helper"], ["_dlsym"])
    assert len(problems) == 1
    assert "records 1" in problems[0]


def test_a_recorded_token_without_a_reason_fails() -> None:
    recorded = artifact(recorded=[{"token": "dlsym", "budget": 1}])

    problems = symbols.problems_for(recorded, [], [])

    assert len(problems) == 1
    assert "reason" in problems[0]


def test_an_undefined_symbol_is_not_counted_as_a_definition(tmp_path: pathlib.Path) -> None:
    # `nm` prints undefined entries too, marked `U`. Counting those as definitions made
    # one `dlsym` look like two, which is the opposite of what a ratchet is for.
    assert symbols._is_undefined("                 U _dlsym")
    assert not symbols._is_undefined("0000000100001234 T _dlsym")


def test_a_policy_with_no_artifacts_is_refused(tmp_path: pathlib.Path) -> None:
    policy = tmp_path / "symbols.toml"
    policy.write_text("version = 1\n")

    with pytest.raises(symbols.SymbolsError):
        symbols.load_policy(policy)


def test_an_artifact_entry_missing_its_claim_is_refused(tmp_path: pathlib.Path) -> None:
    policy = tmp_path / "symbols.toml"
    policy.write_text(
        "version = 1\n"
        "[[artifact]]\n"
        'name = "incomplete"\n'
        'package = "a-package"\n'
        'path = "target/release/a-binary"\n'
    )

    with pytest.raises(symbols.SymbolsError) as error:
        symbols.load_policy(policy)
    assert "forbidden" in str(error.value)


def test_a_missing_artifact_is_an_error_rather_than_a_pass(tmp_path: pathlib.Path) -> None:
    # A gate that cannot read the artifact has checked nothing; reporting success for
    # it is the failure mode this check exists against.
    with pytest.raises(symbols.SymbolsError):
        symbols.symbol_table(tmp_path / "not-built")
