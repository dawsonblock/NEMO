# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the qualification matrix gate."""

from __future__ import annotations

import pathlib
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import matrix  # noqa: E402


def tree(tmp_path: pathlib.Path, files: dict[str, str], policy: str) -> pathlib.Path:
    """Build a repository-shaped directory holding one policy file and its evidence."""
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    (tmp_path / "security").mkdir(exist_ok=True)
    (tmp_path / "security" / "qualification-matrix.toml").write_text("version = 1\n\n" + policy)
    return tmp_path


def claim(
    claim_id: str,
    status: str,
    evidence: str = "",
    note: str = "",
    terms: str = "",
) -> str:
    """Return one claim table, with the evidence and note written as they are given."""
    return (
        f'[[claim]]\nid = "{claim_id}"\nstatement = "the claim {claim_id} makes"\n'
        f'status = "{status}"\n{evidence}{note}{terms}'
    )


def check(root: pathlib.Path) -> list[str]:
    """Read and check one tree, the way the gate does."""
    return matrix.problems(matrix.read_claims(root / "security" / "qualification-matrix.toml"), root)


def test_the_repository_policy_is_green() -> None:
    """The matrix this repository checks in resolves, name by name."""
    assert matrix.problems(matrix.read_claims(matrix.POLICY), matrix.ROOT) == []


def test_the_generated_document_is_current() -> None:
    """The checked-in document is what the policy file renders to."""
    claims = matrix.read_claims(matrix.POLICY)
    assert matrix.GENERATED.read_text() == matrix.render(claims, matrix.ROOT)


def test_the_milestone_quotes_the_counts_the_matrix_has() -> None:
    """The figure the milestone states is the figure the policy file holds.

    A number maintained by hand drifts, and this repository has already shipped a
    revision where one figure appeared twice with two values.
    """
    claims = matrix.read_claims(matrix.POLICY)
    enforced = sum(1 for claim in claims if claim.status == "enforced")
    unverified = len(claims) - enforced
    assert matrix.documented_counts(matrix.MILESTONE) == (enforced, unverified)


def test_a_document_that_states_no_counts_is_not_an_error(tmp_path: pathlib.Path) -> None:
    """A document that quotes no figure is not silently read as zero."""
    milestone = tmp_path / "PLUGIN-ISOLATION.md"
    milestone.write_text("# Milestone\n\nNo counts here.\n")
    assert matrix.documented_counts(milestone) is None
    assert matrix.documented_counts(tmp_path / "absent.md") is None


def test_a_test_that_no_longer_exists_is_reported(tmp_path: pathlib.Path) -> None:
    """A test that disappeared turns the gate red rather than the table stale."""
    root = tree(
        tmp_path,
        {"crates/plugin-host/tests/architecture.rs": "fn something_else() {}\n"},
        claim(
            "an-absent-test",
            "enforced",
            'enforced_by = [\n  { rust_test = "a_test_that_was_renamed" },\n]\n',
        ),
    )
    problems = check(root)
    assert len(problems) == 1
    assert "nothing in the tree defines it" in problems[0]


def test_a_name_two_places_define_is_reported(tmp_path: pathlib.Path) -> None:
    """Two tests sharing a name are two facts wearing one label."""
    root = tree(
        tmp_path,
        {
            "crates/plugin-host/tests/one.rs": "#[test]\nfn a_shared_name() {}\n",
            "crates/plugin-host/tests/two.rs": "#[test]\nfn a_shared_name() {}\n",
        },
        claim(
            "an-ambiguous-test",
            "enforced",
            'enforced_by = [\n  { rust_test = "a_shared_name" },\n]\n',
        ),
    )
    problems = check(root)
    assert len(problems) == 1
    assert "2 places define it" in problems[0]


def test_a_function_without_a_test_attribute_is_not_evidence(tmp_path: pathlib.Path) -> None:
    """A function is not a test: the attribute is what makes anything run it.

    An audit found this by deleting `#[test]` from a referenced test and watching the
    matrix stay green, which is the failure mode this asserts against.
    """
    root = tree(
        tmp_path,
        {"crates/plugin-host/tests/one.rs": "fn a_referenced_test() {}\n"},
        claim(
            "an-unrun-test",
            "enforced",
            'enforced_by = [\n  { rust_test = "a_referenced_test" },\n]\n',
        ),
    )
    problems = check(root)
    assert len(problems) == 1
    assert "nothing in the tree defines it" in problems[0]


def test_an_attribute_with_arguments_is_still_a_test(tmp_path: pathlib.Path) -> None:
    """`#[tokio::test(flavor = "multi_thread")]` is one of the forms used here."""
    root = tree(
        tmp_path,
        {
            "crates/plugin-host/tests/one.rs": (
                '#[tokio::test(flavor = "multi_thread")]\nasync fn a_parameterized_test() {}\n'
            ),
        },
        claim(
            "a-parameterized-test",
            "enforced",
            'enforced_by = [\n  { rust_test = "a_parameterized_test" },\n]\n',
        ),
    )
    assert check(root) == []


def test_an_enforced_claim_with_no_evidence_is_reported(tmp_path: pathlib.Path) -> None:
    """An enforced claim with nothing behind it is an assertion."""
    root = tree(tmp_path, {}, claim("an-assertion", "enforced"))
    problems = check(root)
    assert len(problems) == 1
    assert "names nothing" in problems[0]


def test_an_unverified_claim_needs_a_note(tmp_path: pathlib.Path) -> None:
    """A gap that is recorded is fixable, and a gap that is not is invisible."""
    root = tree(
        tmp_path,
        {},
        claim("an-unrecorded-gap", "unverified", terms='terms = ["a phrase"]\n'),
    )
    problems = check(root)
    assert len(problems) == 1
    assert "says nothing about why" in problems[0]


def test_an_unverified_claim_names_the_terms_release_text_would_use(
    tmp_path: pathlib.Path,
) -> None:
    """Without terms the coverage invariant has nothing to look for."""
    root = tree(tmp_path, {}, claim("a-gap", "unverified", note='note = "why"\n'))
    problems = check(root)
    assert len(problems) == 1
    assert "names no terms" in problems[0]


def test_release_text_may_not_call_an_unverified_claim_covered(
    tmp_path: pathlib.Path,
) -> None:
    """A paragraph that names a gap and asserts coverage has collapsed the two."""
    root = tree(
        tmp_path,
        {},
        claim(
            "a-gap",
            "unverified",
            note='note = "why"\n',
            terms='terms = ["host discovery"]\n',
        ),
    )
    claims = matrix.read_claims(root / "security" / "qualification-matrix.toml")
    document = tmp_path / "PLUGIN-ISOLATION.md"
    document.write_text("# Milestone\n\nHost discovery from the installed package is supported by every binding.\n")
    problems = matrix.coverage_claims(claims, (document,))
    assert len(problems) == 1
    assert "a-gap" in problems[0]
    assert "host discovery" in problems[0]


def test_release_text_recording_the_gap_is_not_reported(tmp_path: pathlib.Path) -> None:
    """The honest sentence about a gap uses the words that mean "not covered"."""
    root = tree(
        tmp_path,
        {},
        claim(
            "a-gap",
            "unverified",
            note='note = "why"\n',
            terms='terms = ["host discovery"]\n',
        ),
    )
    claims = matrix.read_claims(root / "security" / "qualification-matrix.toml")
    document = tmp_path / "PLUGIN-ISOLATION.md"
    document.write_text(
        "# Milestone\n\nHost discovery from the installed package is not supported yet, and no test asserts it.\n"
    )
    assert matrix.coverage_claims(claims, (document,)) == []


def test_the_repository_release_text_does_not_call_open_claims_covered() -> None:
    """The milestone as written does not describe its gaps as covered."""
    claims = matrix.read_claims(matrix.POLICY)
    assert matrix.coverage_claims(claims, matrix.RELEASE_TEXT) == []


def test_an_unverified_claim_with_evidence_is_reported(tmp_path: pathlib.Path) -> None:
    """A claim cannot be both recorded as a gap and enforced."""
    root = tree(
        tmp_path,
        {"crates/plugin-host/tests/one.rs": "#[test]\nfn a_test() {}\n"},
        claim(
            "both-at-once",
            "unverified",
            'enforced_by = [\n  { rust_test = "a_test" },\n]\n',
            'note = "why"\n',
            'terms = ["a phrase"]\n',
        ),
    )
    problems = check(root)
    assert len(problems) == 1
    assert "one of the two is wrong" in problems[0]


def test_a_recipe_is_found_with_and_without_parameters(tmp_path: pathlib.Path) -> None:
    """A recipe's line is its name, then its parameters or the colon."""
    root = tree(
        tmp_path,
        {
            "justfile": (
                "# a comment naming a-recipe-with-parameters\n"
                'a-recipe-with-parameters one two="":\n    true\n'
                "a-recipe-without-parameters:\n    true\n"
            )
        },
        claim(
            "recipes",
            "enforced",
            "enforced_by = [\n"
            '  { recipe = "a-recipe-with-parameters" },\n'
            '  { recipe = "a-recipe-without-parameters" },\n'
            "]\n",
        ),
    )
    assert check(root) == []


def test_a_comment_that_names_a_test_is_not_evidence(tmp_path: pathlib.Path) -> None:
    """Evidence is a definition, not a mention: a comment must not satisfy a name."""
    root = tree(
        tmp_path,
        {"crates/plugin-host/src/lib.rs": "// fn a_mentioned_test() {}\n"},
        claim(
            "only-mentioned",
            "enforced",
            'enforced_by = [\n  { rust_test = "a_mentioned_test" },\n]\n',
        ),
    )
    problems = check(root)
    assert len(problems) == 1
    assert "nothing in the tree defines it" in problems[0]


def test_a_test_tree_named_coverage_is_searched(tmp_path: pathlib.Path) -> None:
    """A skipped *name* under a tests directory is sources, not build output.

    The CLI's own suite lives in `crates/cli/tests/coverage/`, so a name-based skip
    that could not tell that tree from a coverage report hid the evidence for every
    claim the CLI enforces — including the boundary claim the gate then reported as
    unverified.
    """
    root = tree(
        tmp_path,
        {"crates/cli/tests/coverage/shared/server_tests.rs": "#[tokio::test]\nasync fn a_test() {}\n"},
        claim(
            "cli-evidence",
            "enforced",
            'enforced_by = [\n  { rust_test = "a_test" },\n]\n',
        ),
    )
    assert check(root) == []


def test_the_document_records_what_the_policy_says(tmp_path: pathlib.Path) -> None:
    """The render carries each claim, its evidence and the place it was found."""
    root = tree(
        tmp_path,
        {"crates/plugin-host/tests/one.rs": "#[test]\nfn a_test() {}\n"},
        claim(
            "rendered",
            "enforced",
            'enforced_by = [\n  { rust_test = "a_test" },\n]\n',
        )
        + claim("a-gap", "unverified", note='note = "no test covers this yet"\n'),
    )
    document = matrix.render(matrix.read_claims(root / "security" / "qualification-matrix.toml"), root)
    assert "| the claim rendered makes |" in document
    assert "Rust test `a_test` — `crates/plugin-host/tests/one.rs`" in document
    assert "| the claim a-gap makes | no test covers this yet |" in document


def test_an_unknown_evidence_kind_is_reported(tmp_path: pathlib.Path) -> None:
    """A kind this gate cannot read is refused rather than skipped."""
    root = tree(
        tmp_path,
        {},
        claim(
            "an-unknown-kind",
            "enforced",
            'enforced_by = [\n  { instinct = "a_test" },\n]\n',
        ),
    )
    problems = check(root)
    assert len(problems) == 1
    assert "not an evidence kind this gate reads" in problems[0]
