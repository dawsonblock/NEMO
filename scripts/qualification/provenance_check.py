#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# Apache-2.0

"""Verify that qualification evidence still describes the current source tree."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import argparse
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
EXCLUDED_ROOTS = {
    ".git",
    "target",
    "node_modules",
    "coverage",
    "qualification",
    ".venv",
    ".uv-cache",
    ".pytest_cache",
    ".mypy_cache",
}
GENERATED_PREFIX = ("release", "artifacts")


def excluded(relative: pathlib.Path) -> bool:
    return bool(relative.parts) and (
        relative.parts[0] in EXCLUDED_ROOTS or relative.parts[:2] == GENERATED_PREFIX
    )


def source_files(manifest_paths: set[str] | None = None) -> list[pathlib.Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        paths = {
            pathlib.Path(raw.decode())
            for raw in result.stdout.split(b"\0")
            if raw
        }
    except (OSError, subprocess.CalledProcessError):
        paths = {pathlib.Path(name) for name in (manifest_paths or set())}
    return sorted(
        (
            relative
            for relative in paths
            if not excluded(relative)
            and (ROOT / relative).is_file()
            and not (ROOT / relative).is_symlink()
        ),
        key=lambda path: path.as_posix(),
    )


def file_hashes(files: list[pathlib.Path]) -> dict[str, str]:
    return {
        relative.as_posix(): hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        for relative in files
    }


def tree_digest(hashes: dict[str, str]) -> str:
    canonical = "".join(f"{name}\t{digest}\n" for name, digest in hashes.items()).encode()
    return hashlib.sha256(canonical).hexdigest()


def git_output(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def report_failure(messages: list[str]) -> int:
    print(f"PROVENANCE FAIL\n{len(messages)} discrepancy(s)")
    for message in messages:
        print(f"- {message}")
    return 1


def verify_archive(recorded: Any, label: str, discrepancies: list[str]) -> None:
    if not recorded or recorded in {"NOT_PROVIDED", "NOT_AVAILABLE"}:
        return
    archive_value = os.environ.get(
        "NEMO_RELAY_RELEASE_ARCHIVE" if label == "release" else "NEMO_RELAY_SOURCE_ARCHIVE"
    )
    if not archive_value:
        discrepancies.append(f"{label} archive hash is recorded but archive path is not provided")
        return
    archive = pathlib.Path(archive_value).expanduser()
    if not archive.is_file():
        discrepancies.append(f"{label} archive is missing: {archive}")
        return
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != recorded:
        discrepancies.append(f"{label} archive digest differs: expected {recorded}, got {actual}")


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
    global ROOT
    if args.root is not None:
        ROOT = args.root.resolve()
    manifest_path = args.manifest or pathlib.Path(
        os.environ.get("NEMO_RELAY_SOURCE_MANIFEST", ROOT / "qualification" / "source-manifest.json")
    )
    if not manifest_path.is_absolute():
        manifest_path = ROOT / manifest_path
    if not manifest_path.is_file():
        return report_failure([f"missing qualification manifest: {manifest_path}"])
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as error:
        return report_failure([f"invalid qualification manifest: {error}"])

    expected = manifest.get("files", {})
    actual = file_hashes(source_files(set(expected)))
    discrepancies: list[str] = []
    missing = sorted(set(expected) - set(actual))
    added = sorted(set(actual) - set(expected))
    changed = sorted(name for name in set(expected) & set(actual) if expected[name] != actual[name])
    if missing:
        discrepancies.append(f"{len(missing)} manifest source file(s) missing: {', '.join(missing[:5])}")
    if added:
        discrepancies.append(f"{len(added)} source file(s) absent from manifest: {', '.join(added[:5])}")
    if changed:
        discrepancies.append(f"{len(changed)} source file(s) differ: {', '.join(changed[:5])}")
    actual_tree = tree_digest(actual)
    if actual_tree != manifest.get("root_digest"):
        discrepancies.append(
            f"source tree digest differs: expected {manifest.get('root_digest')}, got {actual_tree}"
        )

    for lockfile, recorded in (manifest.get("lockfiles") or {}).items():
        path = ROOT / lockfile
        actual_lock = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}" if path.is_file() else None
        if actual_lock != recorded:
            discrepancies.append(f"lockfile digest differs: {lockfile}")

    recorded_git = manifest.get("git") or {}
    current_commit = git_output("rev-parse", "HEAD")
    if current_commit and recorded_git.get("commit") and recorded_git["commit"] != current_commit:
        try:
            changed_since = git_output("diff", "--name-only", f"{recorded_git['commit']}..HEAD").splitlines()
        except subprocess.CalledProcessError:
            changed_since = []
        non_generated = [
            path for path in changed_since if not path.startswith("qualification/") and not path.startswith("release/artifacts/")
        ]
        if non_generated:
            discrepancies.append("Git commit differs with non-generated source changes")
    if recorded_git.get("source_tree_sha256"):
        if recorded_git["source_tree_sha256"] != actual_tree:
            discrepancies.append("Git source tree digest differs from qualification manifest")
    elif recorded_git.get("tree") and recorded_git["tree"] != git_output("rev-parse", "HEAD^{tree}"):
        discrepancies.append("Git tree differs from qualification manifest")
    dirty = []
    if current_commit:
        dirty = [
            line
            for line in git_output("status", "--short").splitlines()
            if "qualification/" not in line and "release/artifacts/" not in line
        ]
    if dirty:
        discrepancies.append(f"working tree is dirty: {', '.join(dirty[:5])}")

    verify_archive(manifest.get("source_archive_sha256"), "source", discrepancies)
    verify_archive(manifest.get("release_archive_sha256"), "release", discrepancies)
    if discrepancies:
        return report_failure(discrepancies)
    print("PROVENANCE PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
