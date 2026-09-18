#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""In-tree ``.gitignore`` evaluation without shelling out to Git.

Provenance enumeration has to answer one question the same way on a developer
workstation and inside an extracted release archive: which filesystem entries
are source content? Delegating that to ``git ls-files`` made the answer depend
on whether ``.git`` happened to exist, which is precisely how a stale manifest
can be attached to a tree it never described.

These rules are read from the tree itself. Every ``.gitignore`` file is a source
entry, so changing ignore semantics changes the source digest too.

The supported subset is the one this repository actually uses: comments,
negation, anchored and unanchored patterns, directory-only patterns, ``*``,
``?``, ``[...]`` classes, and ``**`` used as a whole path segment.

Patterns outside that subset are rejected rather than approximated. A matcher
that silently disagrees with Git changes what "same source tree" means, which is
exactly the ambiguity provenance exists to remove. ``GITIGNORE_POLICY_VERSION``
names the semantics; changing the matcher requires changing the version, which
invalidates every manifest captured under the old one.
"""

from __future__ import annotations

import pathlib
import re
from typing import Iterable, Iterator

# Semantics identifier for the matcher below. It is recorded in every source
# manifest, so a semantics change cannot silently reinterpret old evidence.
GITIGNORE_POLICY_VERSION = "nemo.gitignore.v1"


class UnsupportedIgnorePattern(Exception):
    """Raised when a pattern cannot be evaluated with Git-compatible semantics."""


def unsupported_construct(pattern: str) -> str | None:
    """Return why a pattern is outside the supported subset, if it is."""

    if "[:" in pattern or "[=" in pattern or "[." in pattern:
        return "POSIX bracket expressions are not supported"
    index = 0
    while True:
        index = pattern.find("**", index)
        if index == -1:
            return None
        before = pattern[index - 1] if index > 0 else "/"
        after_index = index + 2
        after = pattern[after_index] if after_index < len(pattern) else "/"
        if before != "/" or after != "/":
            return (
                "consecutive asterisks must form a whole path segment; "
                "elsewhere Git treats them as a single '*', and this matcher "
                "would let them cross a path separator"
            )
        index = after_index


def _translate(pattern: str) -> str:
    """Translate one gitignore pattern body into a regular expression."""

    result: list[str] = []
    index = 0
    length = len(pattern)
    while index < length:
        character = pattern[index]
        index += 1
        if character == "*":
            if index < length and pattern[index] == "*":
                index += 1
                if index < length and pattern[index] == "/":
                    index += 1
                    result.append("(?:.*/)?")
                else:
                    result.append(".*")
            else:
                result.append("[^/]*")
        elif character == "?":
            result.append("[^/]")
        elif character == "[":
            closing = index
            if closing < length and pattern[closing] in "!^":
                closing += 1
            if closing < length and pattern[closing] == "]":
                closing += 1
            while closing < length and pattern[closing] != "]":
                closing += 1
            if closing >= length:
                result.append(re.escape("["))
            else:
                inner = pattern[index:closing]
                index = closing + 1
                if inner.startswith("!"):
                    inner = "^" + inner[1:]
                result.append(f"[{inner}]")
        elif character == "\\":
            if index < length:
                result.append(re.escape(pattern[index]))
                index += 1
            else:
                result.append(re.escape("\\"))
        else:
            result.append(re.escape(character))
    return "".join(result)


class IgnoreRule:
    """One parsed ``.gitignore`` line."""

    __slots__ = ("base", "negated", "directory_only", "regex", "source", "body")

    def __init__(self, pattern: str, base: str) -> None:
        self.source = pattern
        negated = pattern.startswith("!")
        if negated:
            pattern = pattern[1:]
        directory_only = pattern.endswith("/") and not pattern.endswith("\\/")
        if directory_only:
            pattern = pattern[:-1]
        anchored = pattern.startswith("/") or "/" in pattern
        if pattern.startswith("/"):
            pattern = pattern[1:]
        self.body = pattern
        body = _translate(pattern)
        if not anchored:
            body = "(?:.*/)?" + body
        self.base = base
        self.negated = negated
        self.directory_only = directory_only
        self.regex = re.compile("(?s:" + body + r")\Z")

    def relative(self, path: str) -> str | None:
        """Return ``path`` relative to this rule's directory, or ``None``."""

        if not self.base:
            return path
        prefix = self.base + "/"
        if not path.startswith(prefix):
            return None
        return path[len(prefix) :]

    def matches(self, path: str, is_dir: bool) -> bool:
        """Return whether this rule matches ``path``."""

        if self.directory_only and not is_dir:
            return False
        relative = self.relative(path)
        if relative is None:
            return False
        return self.regex.match(relative) is not None


def parse_gitignore(text: str, base: str) -> list[IgnoreRule]:
    """Parse ``.gitignore`` text into ordered rules.

    Raises :class:`UnsupportedIgnorePattern` for any rule outside the supported
    subset, so an unrepresentable pattern can never be silently treated as
    "not ignored".
    """

    rules: list[IgnoreRule] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.endswith("\\ "):
            line = line[:-1]
        else:
            line = line.rstrip()
        stripped = line.lstrip()
        # A `\#` or `\!` prefix escapes a literal leading character.
        if stripped.startswith("\\#") or stripped.startswith("\\!"):
            stripped = stripped[1:]
        reason = unsupported_construct(stripped)
        if reason is not None:
            raise UnsupportedIgnorePattern(f"{base or '/'} .gitignore pattern {stripped!r}: {reason}")
        try:
            rules.append(IgnoreRule(stripped, base))
        except re.error as error:
            raise UnsupportedIgnorePattern(
                f"{base or '/'} .gitignore pattern {stripped!r} is not a valid regular expression: {error}"
            ) from error
    return rules


class IgnoreSet:
    """The ordered set of ignore rules collected from a source tree."""

    def __init__(self, rules: Iterable[IgnoreRule], sources: dict[str, str]) -> None:
        self.rules = list(rules)
        self.sources = dict(sorted(sources.items()))
        self.dead_negations = self._find_dead_negations()

    def _find_dead_negations(self) -> list[str]:
        """Return negations that can never re-include anything.

        Git cannot re-include a path whose parent directory is excluded. A rule
        that tries to is ambiguous: it looks like an exception but has no effect,
        so the resulting tree would not be what a reader expects.
        """

        dead: list[str] = []
        for index, rule in enumerate(self.rules):
            if not rule.negated:
                continue
            prefix = rule.body
            for marker in "*?[":
                prefix = prefix.split(marker, 1)[0]
            prefix = prefix.rstrip("/")
            candidate = f"{rule.base}/{prefix}" if rule.base else prefix
            parts = [part for part in candidate.split("/") if part]
            parents = ["/".join(parts[:depth]) for depth in range(1, len(parts))]
            for parent in parents:
                if any(earlier.matches(parent, True) and not earlier.negated for earlier in self.rules[:index]):
                    dead.append(rule.source)
                    break
        return dead

    def is_ignored(self, path: str, is_dir: bool) -> bool:
        """Return whether the last matching rule ignores ``path``."""

        ignored = False
        for rule in self.rules:
            if rule.matches(path, is_dir):
                ignored = not rule.negated
        return ignored


def collect(root: pathlib.Path, paths: Iterator[str]) -> IgnoreSet:
    """Collect ignore rules from every ``.gitignore`` in ``paths``.

    Rules are ordered so that deeper ``.gitignore`` files take precedence, which
    matches Git's "later patterns win" evaluation. Every file read here is
    authoritative and must also appear in the source manifest, so the rules that
    decided the entry set are themselves part of the verified tree.
    """

    rules: list[IgnoreRule] = []
    sources: dict[str, str] = {}
    for relative in sorted(paths, key=lambda item: (item.count("/"), item)):
        if pathlib.PurePosixPath(relative).name != ".gitignore":
            continue
        text = (root / relative).read_text(errors="surrogateescape")
        base = str(pathlib.PurePosixPath(relative).parent)
        base = "" if base == "." else base
        sources[relative] = text
        rules.extend(parse_gitignore(text, base))
    ignore_set = IgnoreSet(rules, sources)
    if ignore_set.dead_negations:
        raise UnsupportedIgnorePattern(
            "negation patterns cannot re-include a path under an excluded "
            f"directory: {sorted(set(ignore_set.dead_negations))}"
        )
    return ignore_set
