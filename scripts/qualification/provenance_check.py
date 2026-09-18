#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verify that qualification evidence still describes the current source tree.

The candidate set always comes from the filesystem, never from the manifest
under test. Comparing ``manifest_entries`` against a manifest-derived candidate
set only ever proves ``manifest <= tree``; a manifest can never report a file it
does not list, so brand-new source files would verify clean. Enumerating the
tree independently turns the check into ``tree == manifest``.

Every mismatch category is a hard failure: unexpected entries, missing entries,
type mismatches, mode mismatches, content mismatches, and symlink target
mismatches.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import subprocess
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import source_tree  # noqa: E402  (local module)

ROOT = SCRIPT_DIR.parents[1]


def report_failure(messages: list[str]) -> int:
    """Print a structured failure report and return a non-zero exit code."""

    print(f"PROVENANCE FAIL\n{len(messages)} discrepancy(s)")
    for message in messages:
        print(f"- {message}")
    return 1


def git_output(root: pathlib.Path, *args: str) -> str:
    """Run a read-only Git command, returning an empty string on failure."""

    try:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def verify_archive(root: pathlib.Path, recorded: str | None, label: str, findings: list[str]) -> None:
    """Re-hash a recorded archive digest when the operator supplied the path."""

    if not recorded or recorded in {"NOT_PROVIDED", "NOT_AVAILABLE"}:
        return
    variable = "NEMO_RELAY_RELEASE_ARCHIVE" if label == "release" else "NEMO_RELAY_SOURCE_ARCHIVE"
    archive_value = os.environ.get(variable)
    if not archive_value:
        findings.append(f"{label} archive hash is recorded but archive path is not provided")
        return
    archive = pathlib.Path(archive_value).expanduser()
    if not archive.is_file():
        findings.append(f"{label} archive is missing: {archive}")
        return
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != recorded:
        findings.append(f"{label} archive digest differs: expected {recorded}, got {actual}")


def verify_lockfiles(root: pathlib.Path, manifest: dict, findings: list[str]) -> None:
    """Confirm every recorded lockfile digest still matches."""

    for lockfile, recorded in (manifest.get("lockfiles") or {}).items():
        path = root / lockfile
        actual = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}" if path.is_file() else None
        if actual != recorded:
            findings.append(f"lockfile digest differs: {lockfile}")


def verify_git(root: pathlib.Path, manifest: dict, actual_tree: str, findings: list[str]) -> None:
    """Confirm Git provenance still agrees with the recorded manifest."""

    recorded_git = manifest.get("git") or {}
    current_commit = git_output(root, "rev-parse", "HEAD")
    if current_commit and recorded_git.get("commit") and recorded_git["commit"] != current_commit:
        changed_since = git_output(root, "diff", "--name-only", f"{recorded_git['commit']}..HEAD").splitlines()
        non_generated = [
            path
            for path in changed_since
            if not path.startswith("qualification/") and not path.startswith("release/artifacts/")
        ]
        if non_generated:
            findings.append("Git commit differs with non-generated source changes")
    recorded_tree_digest = recorded_git.get("source_tree_sha256")
    if recorded_tree_digest and recorded_tree_digest != actual_tree:
        findings.append("recorded Git source tree digest differs from the actual source tree")
    elif recorded_git.get("tree") and recorded_git["tree"] != git_output(root, "rev-parse", "HEAD^{tree}"):
        findings.append("Git tree differs from qualification manifest")
    if current_commit:
        dirty = [
            line
            for line in git_output(root, "status", "--short").splitlines()
            if "qualification/" not in line and "release/artifacts/" not in line
        ]
        if dirty:
            findings.append(f"working tree is dirty: {', '.join(dirty[:5])}")


def verify_policy(manifest: dict, enumeration: "source_tree.Enumeration", findings: list[str]) -> None:
    """Confirm the recorded exclusion policy still describes how we enumerated."""

    recorded = manifest.get("policy")
    if recorded is None:
        findings.append("source manifest does not record its exclusion policy")
        return
    current = enumeration.policy()
    if recorded != current:
        differing = sorted(key for key in set(recorded) | set(current) if recorded.get(key) != current.get(key))
        findings.append(f"source exclusion policy differs from the manifest: {', '.join(differing)}")


def verify(root: pathlib.Path, manifest_path: pathlib.Path) -> list[str]:
    """Return every discrepancy between a manifest and the tree it claims.

    An empty list means the evidence describes this exact tree.
    """

    root = pathlib.Path(root).resolve()
    manifest_path = pathlib.Path(manifest_path)
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    try:
        manifest = source_tree.load_manifest(manifest_path)
    except source_tree.SourceTreeError as error:
        return [str(error)]
    try:
        enumeration = source_tree.enumerate_tree(root)
    except source_tree.SourceTreeError as error:
        return [str(error)]

    expected = manifest["entries"]
    actual = enumeration.entries
    mismatches = source_tree.compare(expected, actual)
    findings: list[str] = source_tree.describe(mismatches)

    actual_digest = enumeration.digest
    if actual_digest != manifest.get("root_digest"):
        findings.append(f"source tree digest differs: expected {manifest.get('root_digest')}, got {actual_digest}")
    verify_policy(manifest, enumeration, findings)
    verify_lockfiles(root, manifest, findings)
    verify_git(root, manifest, actual_digest, findings)
    verify_archive(root, manifest.get("source_archive_sha256"), "source", findings)
    verify_archive(root, manifest.get("release_archive_sha256"), "release", findings)
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=None,
        help="source tree root; defaults to the repository containing this script",
    )
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=None,
        help="source manifest path; defaults to qualification/source-manifest.json",
    )
    args = parser.parse_args()

    root = args.root.resolve() if args.root is not None else ROOT
    manifest_path = args.manifest or pathlib.Path(
        os.environ.get("NEMO_RELAY_SOURCE_MANIFEST", root / "qualification" / "source-manifest.json")
    )

    findings = verify(root, manifest_path)
    if findings:
        return report_failure(findings)
    entries = len(source_tree.enumerate_tree(root).entries)
    print(f"PROVENANCE PASS\n{entries} source entries match the qualification manifest")
    return 0


if __name__ == "__main__":
    sys.exit(main())
