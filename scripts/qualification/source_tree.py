#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Canonical, filesystem-first source-tree enumeration and manifest model.

Provenance verification only means something when the candidate set comes from
the filesystem that is being verified. Deriving the candidate set from the
manifest under test proves ``manifest_files <= actual_tree``: a manifest can
never report a file it does not already list. Adding a brand-new source file
therefore leaves the evidence looking satisfied.

This module is the single source of truth for both the producer
(``capture_provenance.py``) and the consumer (``provenance_check.py``) so the
two cannot drift apart:

* enumeration always walks the real tree and applies narrow, recorded exclusions;
* every entry is typed (``file``, ``symlink``, or an empty ``dir``);
* file mode bits, symlink targets, and content hashes are all part of the
  canonical digest;
* comparison reports exact sets, so unexpected, missing, retyped, re-moded,
  re-contented, and re-targeted entries are all distinct findings.

Which filesystem entries count as source content is decided by two recorded
policies: a static list of build/dependency directories, and the ``.gitignore``
files found in the tree. Ignore rules are evaluated here rather than delegated
to ``git ls-files`` so the answer does not change when ``.git`` is absent, which
is the case for every extracted release archive.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import sys
from typing import Any

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from gitignore import (  # noqa: E402  (local module)
    GITIGNORE_POLICY_VERSION,
    IgnoreSet,
    UnsupportedIgnorePattern,
    collect,
)

SCHEMA_VERSION = 2
ALGORITHM = "sha256"

# Version of the enumeration policy: the static exclusions, the ignore-rule
# semantics, and the entry model below. A manifest is only comparable to a tree
# when both were enumerated under the same policy version, so bumping this
# invalidates every previously captured manifest instead of silently redefining
# what "same source tree" means.
ENUMERATION_POLICY_VERSION = "nemo-source-tree-v1"

KIND_FILE = "file"
KIND_SYMLINK = "symlink"
KIND_DIR = "dir"
KNOWN_KINDS = frozenset({KIND_FILE, KIND_SYMLINK, KIND_DIR})

# Directory names that never contain source content, pruned at any depth.
PRUNED_DIRECTORY_NAMES = (
    ".git",
    "target",
    "node_modules",
    "__pycache__",
    ".venv",
    ".uv-cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".cache",
)
# Directories pruned only where they sit at the source root.
ROOT_ONLY_PRUNED = (
    "coverage",
    "qualification",
    "build",
    "dist",
)
GENERATED_PREFIX = ("release", "artifacts")
EXCLUDED_NAMES = frozenset({".coverage"})
EXCLUDED_SUFFIXES = frozenset({".pyc", ".pyo"})

# Symlinks are themselves source content, but their targets are only allowed to
# stay inside the tree. An absolute target or a target that escapes the root
# would let a verified manifest bind content this verifier never hashed.
ABSOLUTE_SYMLINK_TARGETS = "prohibited"
ESCAPING_SYMLINK_TARGETS = "prohibited"

MAX_PATH_LENGTH = 4096


class SourceTreeError(Exception):
    """Raised when a manifest or a tree violates the provenance contract."""


def statically_excluded(relative: pathlib.PurePosixPath) -> bool:
    """Return whether the static build policy excludes a path."""

    if not relative.parts:
        return False
    if any(part in PRUNED_DIRECTORY_NAMES for part in relative.parts):
        return True
    if relative.parts[0] in ROOT_ONLY_PRUNED:
        return True
    if relative.parts[:2] == GENERATED_PREFIX:
        return True
    if any(part in EXCLUDED_NAMES for part in relative.parts):
        return True
    return relative.suffix in EXCLUDED_SUFFIXES


def excluded(relative: pathlib.PurePosixPath) -> bool:
    """Return whether the static build policy excludes a path.

    Kept as the public spelling; ignore-rule handling happens in
    :class:`Enumeration`.
    """

    return statically_excluded(relative)


class Enumeration:
    """The typed source tree plus the ignore rules that shaped it."""

    def __init__(self, entries: dict[str, dict[str, Any]], ignore_files: dict[str, str]) -> None:
        self.entries = entries
        self.ignore_files = ignore_files

    @property
    def digest(self) -> str:
        """Return the canonical digest of the typed entry set."""

        return entries_digest(self.entries)

    def policy(self) -> dict[str, Any]:
        """Return the recordable exclusion policy for a manifest."""

        return {
            "enumeration_policy_version": ENUMERATION_POLICY_VERSION,
            "gitignore_policy_version": GITIGNORE_POLICY_VERSION,
            "authoritative_ignore_files": self.ignore_files,
            "authoritative_ignore_sources": "repository-contained .gitignore files only",
            "matching_order": "shallow to deep, then lexicographic; last match wins",
            "negation": "git last-match-wins; negations that cannot re-include are rejected",
            "directory_exclusion": "excluded directories are pruned, not traversed",
            "global_git_excludes": "ignored",
            "git_info_exclude": "ignored",
            "nested_gitignore": "deeper files take precedence over shallower files",
            "symlinks": "recorded as symlinks, never followed; targets must stay inside the tree",
            "empty_directories": "recorded; a tree containing one differs from a tree without it",
            "file_modes": "recorded for regular files; symlink modes are context only",
            "pruned_directory_names": sorted(PRUNED_DIRECTORY_NAMES),
            "root_only_pruned": sorted(ROOT_ONLY_PRUNED),
            "generated_prefixes": [list(GENERATED_PREFIX)],
            "ignored_names": sorted(EXCLUDED_NAMES),
            "ignored_suffixes": sorted(EXCLUDED_SUFFIXES),
        }


def format_mode(st_mode: int) -> str:
    """Return the octal permission bits of a stat result, such as ``0644``."""

    return f"{stat.S_IMODE(st_mode):04o}"


def file_entry(root: pathlib.Path, relative: pathlib.Path) -> dict[str, Any]:
    """Describe one regular file, including its executable bit."""

    absolute = root / relative
    info = absolute.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise SourceTreeError(f"not a regular file: {relative.as_posix()}")
    return {
        "kind": KIND_FILE,
        "sha256": hashlib.sha256(absolute.read_bytes()).hexdigest(),
        "mode": format_mode(info.st_mode),
    }


def symlink_entry(root: pathlib.Path, relative: pathlib.Path) -> dict[str, Any]:
    """Describe one symlink by its raw, unresolved target."""

    absolute = root / relative
    info = absolute.lstat()
    if not stat.S_ISLNK(info.st_mode):
        raise SourceTreeError(f"not a symlink: {relative.as_posix()}")
    target = os.readlink(absolute)
    return {
        "kind": KIND_SYMLINK,
        "target": target,
        # Symlink permission bits are not portable, so they are recorded for
        # operator context but never gate verification.
        "mode": format_mode(info.st_mode),
    }


def _ancestors_ignored(ignore: IgnoreSet, path: str) -> bool:
    """Return whether any ancestor directory of ``path`` is ignored."""

    parts = path.split("/")
    for depth in range(1, len(parts)):
        if ignore.is_ignored("/".join(parts[:depth]), True):
            return True
    return False


def path_is_excluded(ignore: IgnoreSet, path: str, is_dir: bool) -> bool:
    """Return whether a path is ignored directly or through a parent directory."""

    return ignore.is_ignored(path, is_dir) or _ancestors_ignored(ignore, path)


def enumerate_tree(root: pathlib.Path) -> Enumeration:
    """Walk ``root`` and return the typed source tree.

    The walk never follows symlinks and never consults a manifest, so its result
    is an independent statement about the filesystem. Two passes are needed:
    the first collects every static-policy candidate, and the second drops
    entries matched by the tree's own ``.gitignore`` rules. Both passes are pure
    functions of the filesystem, so a checkout and an extracted archive with the
    same contents enumerate identically.
    """

    root = pathlib.Path(root).resolve()
    if not root.is_dir():
        raise SourceTreeError(f"source root is not a directory: {root}")

    entries: dict[str, dict[str, Any]] = {}
    ignore_paths: list[str] = []
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = pathlib.Path(directory)

        retained: list[str] = []
        for name in sorted(dirnames):
            absolute = base / name
            relative = absolute.relative_to(root)
            if os.path.islink(absolute):
                entries[relative.as_posix()] = symlink_entry(root, relative)
                continue
            if statically_excluded(pathlib.PurePosixPath(relative.as_posix())):
                continue
            retained.append(name)
        dirnames[:] = retained

        for name in sorted(filenames):
            absolute = base / name
            relative = absolute.relative_to(root)
            posix = pathlib.PurePosixPath(relative.as_posix())
            if statically_excluded(posix):
                continue
            if os.path.islink(absolute):
                entries[relative.as_posix()] = symlink_entry(root, relative)
            elif absolute.is_file():
                entries[relative.as_posix()] = file_entry(root, relative)
            else:
                entries[relative.as_posix()] = {"kind": "other"}

        # Git cannot represent an empty directory, so one in a source tree is
        # never expected source content. Recording it keeps a nested unexpected
        # directory visible even when it carries no files.
        if base != root and not os.listdir(base):
            entries[base.relative_to(root).as_posix()] = {"kind": KIND_DIR}

    ignore_paths = [path for path in entries if pathlib.PurePosixPath(path).name == ".gitignore"]
    try:
        ignore = collect(root, iter(ignore_paths))
    except UnsupportedIgnorePattern as error:
        raise SourceTreeError(str(error)) from error

    filtered: dict[str, dict[str, Any]] = {}
    for path, entry in entries.items():
        if path_is_excluded(ignore, path, entry["kind"] == KIND_DIR):
            continue
        filtered[path] = entry

    ignore_files = {
        path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in ignore.sources if path in filtered
    }
    unmanifested = sorted(set(ignore.sources) - set(ignore_files))
    if unmanifested:
        raise SourceTreeError(
            "authoritative ignore file(s) are not part of the manifested source "
            f"tree: {unmanifested}. Every .gitignore that decided the entry set "
            "must itself be a verified source entry, or the rules that produced "
            "the entry set cannot be reproduced."
        )
    return Enumeration(dict(sorted(filtered.items())), ignore_files)


def enumerate_entries(root: pathlib.Path) -> dict[str, dict[str, Any]]:
    """Return only the typed entry set for ``root``."""

    return enumerate_tree(root).entries


def canonical_line(path: str, entry: dict[str, Any]) -> str:
    """Return the canonical digest line for one entry.

    Symlink modes are deliberately absent: the recorded value is operator
    context, not a portable property of the source tree.
    """

    kind = entry.get("kind")
    if kind == KIND_FILE:
        return f"{path}\t{kind}\t{entry.get('mode', '')}\t{entry.get('sha256', '')}\n"
    if kind == KIND_SYMLINK:
        return f"{path}\t{kind}\t{entry.get('target', '')}\n"
    if kind == KIND_DIR:
        return f"{path}\t{kind}\n"
    return f"{path}\t{kind}\t{json.dumps(entry, sort_keys=True)}\n"


def entries_digest(entries: dict[str, dict[str, Any]]) -> str:
    """Return the canonical SHA-256 over a typed entry set."""

    canonical = "".join(canonical_line(path, entries[path]) for path in sorted(entries)).encode(
        "utf-8", "surrogateescape"
    )
    return hashlib.sha256(canonical).hexdigest()


def validate_path(raw: Any) -> str:
    """Reject manifest paths that could address anything outside the root."""

    if not isinstance(raw, str):
        raise SourceTreeError(f"manifest path is not a string: {raw!r}")
    if not raw:
        raise SourceTreeError("manifest contains an empty path")
    if len(raw) > MAX_PATH_LENGTH:
        raise SourceTreeError(f"manifest path is too long: {raw[:64]}...")
    if raw.startswith("/") or raw.startswith("\\"):
        raise SourceTreeError(f"manifest path is absolute: {raw}")
    if "\\" in raw:
        raise SourceTreeError(f"manifest path uses a non-POSIX separator: {raw}")
    if ":" in raw.split("/")[0] and len(raw.split("/")[0]) == 2:
        raise SourceTreeError(f"manifest path looks like a Windows drive path: {raw}")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw):
        raise SourceTreeError(f"manifest path contains control characters: {raw!r}")
    parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise SourceTreeError(f"manifest path contains a traversal segment: {raw}")
    return raw


def validate_symlink_target(path: str, target: Any) -> str:
    """Reject symlink targets that leave the tree or are absolute."""

    if not isinstance(target, str) or not target:
        raise SourceTreeError(f"symlink {path} has an empty or non-string target")
    if target.startswith("/"):
        if ABSOLUTE_SYMLINK_TARGETS == "prohibited":
            raise SourceTreeError(f"symlink {path} has a prohibited absolute target: {target}")
        return target
    parent = pathlib.PurePosixPath(path).parent
    normalised = os.path.normpath(str(parent / pathlib.PurePosixPath(target)))
    if normalised == ".." or normalised.startswith("../"):
        if ESCAPING_SYMLINK_TARGETS == "prohibited":
            raise SourceTreeError(f"symlink {path} escapes the source root: {target}")
    return target


def validate_entry(path: Any, entry: Any) -> tuple[str, dict[str, Any]]:
    """Validate one manifest entry and return its normalised form."""

    validated = validate_path(path)
    if not isinstance(entry, dict):
        raise SourceTreeError(f"entry {validated} is not an object")
    kind = entry.get("kind")
    if kind not in KNOWN_KINDS:
        raise SourceTreeError(f"entry {validated} has an unknown kind: {kind!r}")
    if kind == KIND_FILE:
        digest = entry.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            raise SourceTreeError(f"entry {validated} is missing a SHA-256 digest")
        mode = entry.get("mode")
        if not isinstance(mode, str) or len(mode) != 4:
            raise SourceTreeError(f"entry {validated} is missing a mode")
    elif kind == KIND_SYMLINK:
        validate_symlink_target(validated, entry.get("target"))
    return validated, entry


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    """Read and validate a typed source manifest.

    A manifest produced by an older schema is rejected outright. Old evidence
    cannot describe a tree under the current contract, and silently upgrading it
    is exactly how stale qualification certificates get reattached to new
    source.
    """

    if not path.is_file():
        raise SourceTreeError(f"missing qualification manifest: {path}")
    try:
        manifest = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise SourceTreeError(f"invalid qualification manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise SourceTreeError("qualification manifest is not an object")
    version = manifest.get("schema_version")
    if version != SCHEMA_VERSION:
        raise SourceTreeError(
            f"source manifest schema_version is {version!r}, but this verifier "
            f"only accepts {SCHEMA_VERSION}. Evidence produced under an older "
            "schema cannot describe the current tree; regenerate it with "
            "scripts/qualification/capture_provenance.py."
        )
    policy_version = manifest.get("enumeration_policy_version")
    if policy_version != ENUMERATION_POLICY_VERSION:
        raise SourceTreeError(
            f"source manifest enumeration_policy_version is {policy_version!r}, but "
            f"this verifier enumerates under {ENUMERATION_POLICY_VERSION}. The "
            "manifest and the tree were not produced by the same enumeration "
            "semantics, so they are not comparable: regenerate the evidence with "
            "scripts/qualification/capture_provenance.py."
        )
    raw_entries = manifest.get("entries")
    if not isinstance(raw_entries, dict):
        raise SourceTreeError("source manifest has no typed 'entries' object")
    entries: dict[str, dict[str, Any]] = {}
    for raw_path, raw_entry in raw_entries.items():
        validated, entry = validate_entry(raw_path, raw_entry)
        if validated in entries:
            raise SourceTreeError(f"source manifest lists {validated} twice")
        entries[validated] = entry
    manifest["entries"] = dict(sorted(entries.items()))
    return manifest


def compare(
    expected: dict[str, dict[str, Any]],
    actual: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    """Return the exact-set comparison between a manifest and a real tree."""

    expected_paths = set(expected)
    actual_paths = set(actual)
    shared = expected_paths & actual_paths
    return {
        "missing_entries": sorted(expected_paths - actual_paths),
        "unexpected_entries": sorted(actual_paths - expected_paths),
        "type_mismatches": sorted(path for path in shared if expected[path].get("kind") != actual[path].get("kind")),
        "mode_mismatches": sorted(
            path
            for path in shared
            if expected[path].get("kind") == KIND_FILE
            and actual[path].get("kind") == KIND_FILE
            and expected[path].get("mode") != actual[path].get("mode")
        ),
        "content_mismatches": sorted(
            path
            for path in shared
            if expected[path].get("kind") == KIND_FILE
            and actual[path].get("kind") == KIND_FILE
            and expected[path].get("sha256") != actual[path].get("sha256")
        ),
        "symlink_target_mismatches": sorted(
            path
            for path in shared
            if expected[path].get("kind") == KIND_SYMLINK
            and actual[path].get("kind") == KIND_SYMLINK
            and expected[path].get("target") != actual[path].get("target")
        ),
    }


CATEGORY_LABELS = {
    "missing_entries": "manifest entry(s) missing from the tree",
    "unexpected_entries": "tree entry(s) absent from the manifest",
    "type_mismatches": "entry type mismatch(es)",
    "mode_mismatches": "entry mode mismatch(es)",
    "content_mismatches": "entry content mismatch(es)",
    "symlink_target_mismatches": "symlink target mismatch(es)",
}


def describe(mismatches: dict[str, list[str]], limit: int = 5) -> list[str]:
    """Render mismatch categories as human-readable findings."""

    rendered: list[str] = []
    for category, label in CATEGORY_LABELS.items():
        paths = mismatches.get(category, [])
        if not paths:
            continue
        shown = ", ".join(paths[:limit])
        suffix = "" if len(paths) <= limit else f" (+{len(paths) - limit} more)"
        rendered.append(f"{len(paths)} {label}: {shown}{suffix}")
    return rendered


def total(mismatches: dict[str, list[str]]) -> int:
    """Return the number of individual mismatching entries."""

    return sum(len(paths) for paths in mismatches.values())


def main(argv: list[str] | None = None) -> int:
    """Print the canonical digest of a source tree.

    This is the authoritative way to read the digest: it is derived from the
    filesystem, so it can never be copied forward from a previous run.
    """

    import argparse

    parser = argparse.ArgumentParser(description="Print the canonical source tree digest.")
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd())
    parser.add_argument("--entries", action="store_true", help="also print the entry count")
    args = parser.parse_args(argv)

    enumeration = enumerate_tree(args.root)
    if args.entries:
        print(f"{enumeration.digest}\t{len(enumeration.entries)}")
    else:
        print(enumeration.digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
