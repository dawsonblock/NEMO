#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check that every claim a milestone makes names what enforces it.

A milestone document says things like "the boundary serves every registration
class" and "a hung host is killed at the deadline". Those sentences are checked by
tests, and the sentences and the tests drift apart in the ordinary way: a test is
renamed, moved behind a feature flag, or deleted, and the document goes on saying
what it said. Nothing about reading either one shows the drift.

``security/qualification-matrix.toml`` is where each claim names the test, recipe or
script that enforces it, and this gate resolves every name against the tree. What it
enforces, and why:

* **A name resolves exactly once.** Two tests sharing a name are two facts wearing
  one label. Evidence that cannot be pointed at is not evidence.
* **An enforced claim has evidence.** A claim with none is an assertion, and the
  policy file has a section for those: they are recorded as unverified, with the why.
* **The generated document matches.** ``security/QUALIFICATION-MATRIX.md`` is
  rendered from the policy file, so a claim that was edited without regenerating it
  is a difference this gate can see.

Which is the whole point: renaming or deleting a test turns the gate red, rather
than leaving a table that still reads as if it were true.
"""

from __future__ import annotations

import argparse
import difflib
import fnmatch
import os
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "security" / "qualification-matrix.toml"
GENERATED = ROOT / "security" / "QUALIFICATION-MATRIX.md"
MILESTONE = ROOT / "security" / "PLUGIN-ISOLATION.md"
#: Documents a reader takes as the release's own account of itself. A claim the
#: matrix records as unverified may be discussed in them; it may not be described
#: there in the words that mean covered.
RELEASE_TEXT = (MILESTONE, ROOT / "README.md")

#: Wording that asserts coverage, matched as stems so that "qualified",
#: "qualification" and "qualifies" all count as the same assertion.
QUALITY_WORDS = ("guarantee", "enforce", "qualif", "support")

#: Wording that says the sentence is about the gap rather than about coverage.
#: Without it the invariant would fire on the honest sentences that exist to
#: record what is *not* enforced, which is the opposite of the intent.
HEDGES = ("not ", "no test", "unverified", "asserted", "never", "cannot")

STATUSES = ("enforced", "unverified")

# Directories that hold no evidence: build output, vendored packages, generated
# release qualification, and the caches tools keep beside their inputs.
#
# The names are pruned wherever they appear except directly under a `tests`
# directory, because a test tree is sources rather than build output: the CLI's
# own suite lives in `crates/cli/tests/coverage/`, and a name-based skip that
# could not tell those two apart hid the evidence for every claim the CLI
# enforces. That is how this exemption came to exist.
SKIP_DIRECTORIES = {
    ".cache",
    ".claude",
    ".git",
    ".venv",
    "__pycache__",
    "coverage",
    "node_modules",
    "qualification",
    "target",
}

#: One walk per (root, pattern) per process. The gate is a one-shot check, and the
#: alternative is a full walk of the tree for every name it resolves.
_CANDIDATES: dict[tuple[Path, str], list[Path]] = {}


@dataclass(frozen=True)
class EvidenceKind:
    """Where one kind of evidence lives and what its name looks like there."""

    #: File-name glob, relative to the repository root.
    pattern: str
    #: A regular expression with `{name}` where the name goes.
    occurrence: str
    #: What a reader should understand the name to be.
    described: str


KINDS = {
    # Each pattern is anchored at the start of a line and allows the modifiers a
    # definition may carry, because a *mention* is not evidence: an unanchored
    # `fn name(` matches a commented-out test, and a gate that a comment can satisfy
    # is a gate that reports what nobody is checking. The TCB report deliberately
    # overcounts tokens for an upper bound; evidence has to go the other way.
    # A test is a function *with a test attribute above it*. Matching the name alone
    # was an evidence bug an audit found by deleting `#[test]` from a referenced test
    # and watching the matrix stay green: the gate proved a function existed, not that
    # anything ran it. Other attributes may sit between the attribute and the function
    # (`#[should_panic]`, `#[ignore]`, `#[serial]`), and the attribute itself may carry
    # arguments — `#[tokio::test(flavor = "multi_thread")]` is one of the forms this
    # repository uses.
    "rust_test": EvidenceKind(
        "*.rs",
        r"(?m)^\s*#\[(?:[\w:]+::)?test\b[^\]]*\]\s*\n(?:\s*#\[[^\]]*\]\s*\n)*\s*"
        r"(?:pub\s+)?(?:async\s+)?fn {name}\s*\(",
        "Rust test",
    ),
    "python_test": EvidenceKind("*.py", r"(?m)^\s*(?:async\s+)?def {name}\s*\(", "Python test"),
    "node_test": EvidenceKind("*.mjs", r"(?m)^\s*it\(\s*['\"]{name}['\"]", "Node test"),
    # A recipe's line is its name and then either its parameters or the colon, so the
    # name is matched at the start of a line and followed by whitespace or a colon.
    "recipe": EvidenceKind("justfile", r"(?m)^{name}(?=\s|:)", "just recipe"),
}


class MatrixError(Exception):
    """A policy file this gate cannot use."""


@dataclass(frozen=True)
class Claim:
    """One claim, and what enforces it."""

    id: str
    statement: str
    status: str
    enforced_by: tuple[tuple[str, str], ...]
    note: str | None
    #: Phrases a reader would use to refer to this claim. Required for an
    #: unverified claim, because it is what the invariant below searches for.
    terms: tuple[str, ...]


def read_claims(policy: Path) -> list[Claim]:
    """Read the policy file into claims, in the order it lists them.

    Raises:
        MatrixError: the file is missing, unreadable as TOML, or misshapen.
    """
    try:
        document = tomllib.loads(policy.read_text())
    except FileNotFoundError as error:
        raise MatrixError(f"{policy} does not exist") from error
    except tomllib.TOMLDecodeError as error:
        raise MatrixError(f"{policy} is not valid TOML: {error}") from error

    if document.get("version") != 1:
        raise MatrixError(f"{policy} names a version this gate does not know")
    entries = document.get("claim")
    if not isinstance(entries, list) or not entries:
        raise MatrixError(f"{policy} lists no claims")

    claims: list[Claim] = []
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            raise MatrixError(f"claim {index} is not a table")
        entry = cast("dict[str, object]", item)
        claim_id = text_field(entry, "id")
        statement = text_field(entry, "statement")
        status = text_field(entry, "status")
        if not claim_id or not statement:
            raise MatrixError(f"claim {index} needs an id and a statement")
        if status not in STATUSES:
            raise MatrixError(f"claim '{claim_id}' has status '{status}', and this gate knows {STATUSES}")
        evidence: list[tuple[str, str]] = []
        listed = entry.get("enforced_by")
        if listed is None:
            listed = []
        if not isinstance(listed, list):
            raise MatrixError(f"claim '{claim_id}' has an enforced_by that is not a list")
        for piece in listed:
            if not isinstance(piece, dict) or len(piece) != 1:
                raise MatrixError(f"claim '{claim_id}' has an evidence entry that is not one kind and one name")
            ((kind, name),) = cast("dict[str, object]", piece).items()
            if not isinstance(name, str) or not name.strip():
                raise MatrixError(f"claim '{claim_id}' has an evidence entry with no name")
            evidence.append((str(kind), name))
        note = text_field(entry, "note")
        listed_terms = entry.get("terms")
        if listed_terms is None:
            listed_terms = []
        if not isinstance(listed_terms, list):
            raise MatrixError(f"claim '{claim_id}' has a terms entry that is not a phrase")
        terms: list[str] = []
        for term in listed_terms:
            if not isinstance(term, str) or not term.strip():
                raise MatrixError(f"claim '{claim_id}' has a terms entry that is not a phrase")
            terms.append(term.strip())
        claims.append(
            Claim(
                id=claim_id,
                statement=statement,
                status=status,
                enforced_by=tuple(evidence),
                note=note or None,
                terms=tuple(terms),
            )
        )
    return claims


def text_field(entry: dict[str, object], name: str) -> str:
    """Return one string field of a claim, empty when it is absent or not a string."""
    value = entry.get(name)
    return value.strip() if isinstance(value, str) else ""


def candidate_files(root: Path, pattern: str) -> list[Path]:
    """Return the files a pattern names, without descending into what holds none.

    The pruning is the point rather than a detail: a repository with a build
    directory has more generated `.rs` files under it than sources above it, and a
    filter applied after the walk would read all of them to discard them.
    """
    key = (root, pattern)
    if key in _CANDIDATES:
        return _CANDIDATES[key]
    found: list[Path] = []
    for directory, subdirectories, filenames in os.walk(root):
        under_test_sources = Path(directory).name == "tests"
        subdirectories[:] = sorted(
            name for name in subdirectories if name not in SKIP_DIRECTORIES or under_test_sources
        )
        found.extend(Path(directory) / name for name in sorted(filenames) if fnmatch.fnmatch(name, pattern))
    _CANDIDATES[key] = found
    return found


def resolve(kind: str, name: str, root: Path) -> list[str]:
    """Return the places one evidence name is defined, as repository-relative paths.

    Raises:
        MatrixError: the kind is not one this gate reads.
    """
    if kind == "script":
        return [name] if (root / name).is_file() else []
    if kind not in KINDS:
        raise MatrixError(f"'{kind}' is not an evidence kind this gate reads")
    definition = KINDS[kind]
    occurrence = re.compile(definition.occurrence.format(name=re.escape(name)))
    return [
        str(path.relative_to(root))
        for path in candidate_files(root, definition.pattern)
        if occurrence.search(path.read_text(errors="replace"))
    ]


def problems(claims: list[Claim], root: Path) -> list[str]:
    """Return everything wrong with the claims, in the order they should be read."""
    found: list[str] = []
    seen_ids: set[str] = set()
    for claim in claims:
        if claim.id in seen_ids:
            found.append(f"claim '{claim.id}' is listed twice")
        seen_ids.add(claim.id)
        if claim.status == "enforced" and not claim.enforced_by:
            found.append(
                f"claim '{claim.id}' is enforced and names nothing: an enforced claim "
                f"needs evidence, or it is an assertion and belongs with the unverified ones"
            )
        if claim.status == "unverified" and not claim.note:
            found.append(
                f"claim '{claim.id}' is unverified and says nothing about why: a gap that "
                f"is recorded is fixable, and a gap that is not is invisible"
            )
        if claim.status == "unverified" and not claim.terms:
            found.append(
                f"claim '{claim.id}' is unverified and names no terms: the invariant that "
                f"keeps release text from calling it covered has nothing to look for"
            )
        if claim.status == "unverified" and claim.enforced_by:
            found.append(f"claim '{claim.id}' is unverified and names evidence: one of the two is wrong")
        for kind, name in claim.enforced_by:
            try:
                places = resolve(kind, name, root)
            except MatrixError as error:
                found.append(f"claim '{claim.id}': {error}")
                continue
            if not places:
                found.append(f"claim '{claim.id}' names {kind} '{name}', and nothing in the tree defines it")
            elif len(places) > 1:
                found.append(
                    f"claim '{claim.id}' names {kind} '{name}', and {len(places)} places define it: {', '.join(places)}"
                )
    return found


def documented_counts(milestone: Path) -> tuple[int, int] | None:
    """Return the counts the milestone states, when it states them.

    The document quotes them the way it quotes the `unsafe` count, and a number
    maintained by hand drifts: this repository has already shipped a revision where
    one figure appeared twice with two values. The gate compares the quoted pair
    with the matrix rather than trusting the prose.
    """
    if not milestone.is_file():
        return None
    found = re.search(r"Claims: (\d+) enforced, (\d+) asserted", milestone.read_text())
    if found is None:
        return None
    return int(found.group(1)), int(found.group(2))


def paragraphs(document: str) -> list[str]:
    """Return a document's paragraphs, which is the unit the invariant reads.

    Paragraphs rather than lines: the prose in these documents is wrapped, and a
    check that read line by line would be evaded by a sentence that happened to
    break across one.
    """
    return [block for block in re.split(r"\n\s*\n", document) if block.strip()]


def coverage_claims(claims: list[Claim], documents: tuple[Path, ...]) -> list[str]:
    """Return release text that calls an unverified claim covered.

    A claim the matrix records as unverified may be discussed in these documents —
    that is what the section is for — but a paragraph that names it and also uses
    the wording of coverage has collapsed the distinction the matrix draws, and a
    reader has no way to tell. The hedge list is what keeps this from firing on the
    honest sentences that exist to record the gap.
    """
    found: list[str] = []
    for document in documents:
        if not document.is_file():
            continue
        for block in paragraphs(document.read_text()):
            lowered = block.lower()
            if any(hedge in lowered for hedge in HEDGES):
                continue
            asserted = asserted_wording(lowered)
            if asserted is None:
                continue
            for claim in claims:
                if claim.status != "unverified":
                    continue
                named = [term for term in claim.terms if term.lower() in lowered]
                if named:
                    found.append(
                        f"{document.name} calls '{claim.id}' {asserted!r} while the matrix "
                        f"records it unverified (the paragraph names {named[0]!r})"
                    )
    return found


def asserted_wording(lowered: str) -> str | None:
    """Return the word that asserts coverage in this text, when there is one.

    The stem is matched and the word itself is reported, so the message quotes what
    the document says — "supported" rather than the stem it was found by.
    """
    for stem in QUALITY_WORDS:
        found = re.search(rf"{stem}\w*", lowered)
        if found is not None:
            return found.group(0)
    return None


def render(claims: list[Claim], root: Path) -> str:
    """Render the claims as the document this repository checks in."""
    lines = [
        "<!--",
        "SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.",
        "SPDX-License-Identifier: Apache-2.0",
        "-->",
        "",
        "<!-- Generated by scripts/qualification/matrix.py. Do not edit this file;",
        "     edit security/qualification-matrix.toml and run",
        "     `just qualification-matrix-write`. -->",
        "",
        "# Qualification matrix",
        "",
        "What this milestone claims, and what enforces each claim. Every name below is",
        "resolved against the tree by `just qualification-matrix`, so a test that is",
        "renamed or deleted turns that gate red instead of leaving this table asserting",
        "something that is no longer checked.",
        "",
        "What this proves is that the evidence exists and that exactly one thing",
        "answers to each name; it does not prove that the evidence still asserts what",
        "the claim says. A test can be weakened while keeping its name, and nothing",
        "here would notice. That limit is stated rather than left implicit, because a",
        "reader who takes this table for coverage of the *meaning* of a claim would be",
        "reading more into it than any name can carry.",
        "",
        "## Enforced",
        "",
        "| claim | enforced by |",
        "|---|---|",
    ]
    for claim in claims:
        if claim.status != "enforced":
            continue
        enforcing = []
        for kind, name in claim.enforced_by:
            places = resolve(kind, name, root)
            described = "path" if kind == "script" else KINDS[kind].described
            where = f"`{places[0]}`" if places else "**unresolved**"
            enforcing.append(f"{described} `{name}` — {where}")
        lines.append(f"| {claim.statement} | {'<br>'.join(enforcing)} |")

    lines += [
        "",
        "## Asserted, not yet enforced",
        "",
        "Claims the milestone makes that no test covers. They are listed rather than",
        "left out, because a gap that is written down is one somebody can close.",
        "",
        "| claim | why it is not enforced |",
        "|---|---|",
    ]
    for claim in claims:
        if claim.status != "unverified":
            continue
        lines.append(f"| {claim.statement} | {claim.note or ''} |")
    lines.append("")
    return "\n".join(lines)


def render_difference(current: str, wanted: str) -> str:
    """Return a readable difference between the checked-in document and the render."""
    return "".join(
        difflib.unified_diff(
            current.splitlines(keepends=True),
            wanted.splitlines(keepends=True),
            fromfile=str(GENERATED.relative_to(ROOT)),
            tofile="rendered from security/qualification-matrix.toml",
        )
    )


def main() -> int:
    """Check the matrix, or write the document it renders to."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="render the document from the policy file instead of checking it",
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    try:
        claims = read_claims(root / POLICY.relative_to(ROOT))
    except MatrixError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    found = problems(claims, root) + coverage_claims(
        claims,
        tuple(root / document.relative_to(ROOT) for document in RELEASE_TEXT if document.is_relative_to(ROOT)),
    )
    if found:
        for problem in found:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    wanted = render(claims, root)
    document = root / GENERATED.relative_to(ROOT)
    if arguments.write:
        document.write_text(wanted)
        print(f"wrote {document.relative_to(root)}")
        return 0

    enforced = sum(1 for claim in claims if claim.status == "enforced")
    unverified = len(claims) - enforced
    quoted = documented_counts(root / MILESTONE.relative_to(ROOT))
    if quoted is not None and quoted != (enforced, unverified):
        print(
            f"error: {MILESTONE.relative_to(ROOT)} says {quoted[0]} enforced and "
            f"{quoted[1]} asserted, and the matrix says {enforced} and {unverified}",
            file=sys.stderr,
        )
        return 1

    current = document.read_text() if document.is_file() else ""
    if current != wanted:
        print(
            f"error: {document.relative_to(root)} is not what the policy file renders",
            file=sys.stderr,
        )
        print(render_difference(current, wanted), file=sys.stderr)
        return 1

    print(
        f"qualification matrix: {enforced} claims enforced, {unverified} asserted and "
        f"not yet enforced, every name resolved"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
