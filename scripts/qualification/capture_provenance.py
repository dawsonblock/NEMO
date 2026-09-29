#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Capture the canonical source manifest, environment record, and provenance.

This is the producer half of the provenance contract. It is deliberately
separate from ``provenance_check.py`` but shares ``source_tree.py`` with it, so a
tree that this script describes is exactly the tree the verifier accepts.

Evidence is captured *before* any check runs so that generated test output
cannot be laundered into the manifest, and the manifest is re-verified after the
matrix so that any source change invalidates the run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import source_tree  # noqa: E402  (local module)

LOCKFILES = ("Cargo.lock", "package-lock.json", "uv.lock")


def git_output(root: pathlib.Path, arguments: list[str]) -> str | None:
    """Run a read-only Git command, returning ``None`` when it is unavailable."""

    if shutil.which("git") is None:
        return None
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def first_line(root: pathlib.Path, command: list[str]) -> str | None:
    """Return the first output line of a version command."""

    if shutil.which(command[0]) is None:
        return None
    result = subprocess.run(command, cwd=root, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        return None
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0] if output else None


def python_runtime(executable: str | None) -> dict[str, str] | None:
    """Describe a Python interpreter precisely enough to compare runs."""

    if not executable:
        return None
    result = subprocess.run(
        [
            str(executable),
            "-c",
            "import json,platform,sys;print(json.dumps({"
            "'executable':sys.executable,'version':sys.version,"
            "'implementation':platform.python_implementation(),"
            "'machine':platform.machine()}))",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)


def project_python_runtime(root: pathlib.Path) -> dict[str, str] | None:
    """Describe the interpreter the project virtual environment provides."""

    if shutil.which("uv") is None:
        return None
    result = subprocess.run(
        ["uv", "python", "find"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return python_runtime(result.stdout.strip())


def postgres_server_version(root: pathlib.Path) -> str | None:
    """Return the live PostgreSQL server version used by database gates."""

    connection = os.environ.get("NEMO_RELAY_TEST_POSTGRES_URL")
    if not connection or shutil.which("psql") is None:
        return None
    try:
        result = subprocess.run(
            ["psql", connection, "--tuples-only", "--no-align", "--command", "SHOW server_version"],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return None
    if result.returncode != 0:
        return None
    output = result.stdout.strip().splitlines()
    return output[0] if output else None


def capture_environment(root: pathlib.Path) -> tuple[dict, str]:
    """Capture the toolchain and platform record for this run."""

    environment = {
        "schema_version": 3,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "tools": {
            "rustc": first_line(root, ["rustc", "--version"]),
            "cargo": first_line(root, ["cargo", "--version"]),
            "node": first_line(root, ["node", "--version"]),
            "npm": first_line(root, ["npm", "--version"]),
            "python": first_line(root, ["python3", "--version"]),
            "uv": first_line(root, ["uv", "--version"]),
            "go": first_line(root, ["go", "version"]),
            "protoc": first_line(root, ["protoc", "--version"]),
            "just": first_line(root, ["just", "--version"]),
            "cargo-nextest": first_line(root, ["cargo", "nextest", "--version"]),
            "cargo-deny": first_line(root, ["cargo", "deny", "--version"]),
            "cargo-audit": first_line(root, ["cargo", "audit", "--version"]),
            "cargo-about": first_line(root, ["cargo-about", "--version"]),
        },
        "qualification_python_runtime": python_runtime(shutil.which("python3")),
        "project_test_python_runtime": project_python_runtime(root),
        "postgres_server_version": postgres_server_version(root),
    }
    canonical = json.dumps(environment, sort_keys=True, separators=(",", ":")).encode()
    return environment, hashlib.sha256(canonical).hexdigest()


def archive_digest(variable: str, destination: pathlib.Path) -> str | None:
    """Record an archive digest, distinguishing absent from unreadable."""

    value = os.environ.get(variable)
    if not value:
        destination.write_text("NOT_PROVIDED\n")
        return None
    archive = pathlib.Path(value).expanduser()
    if not archive.is_file():
        destination.write_text("NOT_AVAILABLE\n")
        return None
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    destination.write_text(digest + "\n")
    return digest


def capture(root: pathlib.Path, out: pathlib.Path, mode: str) -> dict:
    """Write the manifest, environment record, and provenance for one tree."""

    root = root.resolve()
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    enumeration = source_tree.enumerate_tree(root)
    source_tree_digest = enumeration.digest
    (out / "source-tree.sha256").write_text(source_tree_digest + "\n")

    source_archive_sha256 = archive_digest("NEMO_RELAY_SOURCE_ARCHIVE", out / "source-archive.sha256")
    release_archive_sha256 = archive_digest("NEMO_RELAY_RELEASE_ARCHIVE", out / "release-archive.sha256")

    environment_path = out / "environment.json"
    environment_sha_path = out / "environment-sha256.txt"
    environment_lock_path = out / "environment-lock.json"
    reuse_environment = (
        mode == "provenance"
        and environment_path.is_file()
        and environment_sha_path.is_file()
        and environment_lock_path.is_file()
    )
    if reuse_environment:
        # Archive binding must not replace the environment that actually ran the
        # full test matrix. In particular, a release host need not have the live
        # PostgreSQL test URL that was used for the qualification gate.
        environment = json.loads(environment_path.read_text())
        environment_sha256 = environment_sha_path.read_text().strip()
    else:
        environment, environment_sha256 = capture_environment(root)
        environment_path.write_text(json.dumps(environment, indent=2) + "\n")
        environment_sha_path.write_text(environment_sha256 + "\n")
        environment_lock_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "environment_sha256": environment_sha256,
                    "environment": environment,
                },
                indent=2,
            )
            + "\n"
        )

    locks: dict[str, str | None] = {}
    for name in LOCKFILES:
        path = root / name
        locks[name] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    (out / "dependency-lock-digests.json").write_text(json.dumps(locks, indent=2) + "\n")

    status = git_output(root, ["status", "--short"])
    manifest = {
        "schema_version": source_tree.SCHEMA_VERSION,
        "enumeration_policy_version": source_tree.ENUMERATION_POLICY_VERSION,
        "algorithm": source_tree.ALGORITHM,
        "root_digest": source_tree_digest,
        "entries": enumeration.entries,
        "policy": enumeration.policy(),
        "source_archive_sha256": source_archive_sha256,
        "release_archive_sha256": release_archive_sha256,
        "lockfiles": locks,
        "git": {
            "commit": (git_output(root, ["rev-parse", "HEAD"]) or "").strip() or None,
            "tree": (git_output(root, ["rev-parse", "HEAD^{tree}"]) or "").strip() or None,
            "source_tree_sha256": source_tree_digest,
            "status": [
                line
                for line in (status or "").splitlines()
                if "qualification/" not in line and "release/artifacts/" not in line
            ],
        },
    }
    (out / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    provenance = {
        "source_tree_sha256": source_tree_digest,
        "source_archive_sha256": source_archive_sha256,
        "release_archive_sha256": release_archive_sha256,
        "environment_sha256": environment_sha256,
        "lockfiles": locks,
        "git": manifest["git"],
    }
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return provenance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--mode", default="full")
    args = parser.parse_args()
    capture(args.root, args.out, args.mode)
    return 0


if __name__ == "__main__":
    sys.exit(main())
