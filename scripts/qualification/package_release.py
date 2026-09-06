#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Create a deterministic, source-only NeMo Relay release archive.

The packager deliberately excludes generated qualification outputs and build
products. It emits a sidecar manifest that binds a release version, canonical
source-tree digest, and archive digest without making the archive recursive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import zipfile
from datetime import datetime, timezone


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_ROOT = SCRIPT_DIR.parents[1]
GENERATED_PREFIX = ("release", "artifacts")
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
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def workspace_version(root: pathlib.Path) -> str:
    in_workspace_package = False
    for raw_line in (root / "Cargo.toml").read_text().splitlines():
        line = raw_line.strip()
        if line == "[workspace.package]":
            in_workspace_package = True
            continue
        if line.startswith("["):
            in_workspace_package = False
        if in_workspace_package and line.startswith("version = "):
            return line.split("=", 1)[1].strip().strip('"')
    raise ValueError("could not determine workspace package version")


def is_excluded(relative: pathlib.Path) -> bool:
    if not relative.parts:
        return False
    return relative.parts[0] in EXCLUDED_ROOTS or relative.parts[:2] == GENERATED_PREFIX


def tracked_paths(root: pathlib.Path) -> list[pathlib.Path]:
    """Return source files using the same source selection as qualification."""

    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        candidates = [path.relative_to(root) for path in root.rglob("*") if path.is_file()]
    else:
        candidates = [
            pathlib.Path(value.decode())
            for value in result.stdout.split(b"\0")
            if value
        ]

    paths = {
        relative
        for relative in candidates
        if not is_excluded(relative)
        and (root / relative).is_file()
        and not (root / relative).is_symlink()
    }
    return sorted(paths, key=lambda path: path.as_posix())


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_tree(files: list[pathlib.Path], root: pathlib.Path) -> tuple[str, dict[str, str]]:
    hashes = {
        relative.as_posix(): sha256_bytes((root / relative).read_bytes()) for relative in files
    }
    canonical = "".join(f"{name}\t{digest}\n" for name, digest in hashes.items()).encode()
    return sha256_bytes(canonical), hashes


def zip_info(name: str, source: pathlib.Path) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
    # Preserve executability while normalizing every other permission bit.
    mode = 0o755 if source.stat().st_mode & stat.S_IXUSR else 0o644
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.create_system = 3
    return info


def write_archive(
    archive: pathlib.Path,
    root: pathlib.Path,
    version: str,
    files: list[pathlib.Path],
) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    prefix = f"NEMO-{version}/"
    with zipfile.ZipFile(
        archive,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as handle:
        for relative in files:
            handle.writestr(
                zip_info(prefix + relative.as_posix(), root / relative),
                (root / relative).read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=pathlib.Path, default=DEFAULT_ROOT)
    parser.add_argument("--version", help="release version; defaults to Cargo.toml")
    parser.add_argument("--output", type=pathlib.Path, help="archive output path")
    args = parser.parse_args()

    root = args.repo_root.resolve()
    version = args.version or workspace_version(root)
    archive = args.output or root / "release" / "artifacts" / f"NEMO-{version}-source.zip"
    archive = archive.resolve()
    files = tracked_paths(root)
    source_tree_sha256, file_hashes = canonical_tree(files, root)
    write_archive(archive, root, version, files)
    archive_sha256 = sha256_bytes(archive.read_bytes())

    checksum = archive.with_suffix(archive.suffix + ".sha256")
    checksum.write_text(f"{archive_sha256}  {archive.name}\n")
    manifest = archive.with_suffix(archive.suffix + ".manifest.json")
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "release_version": version,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "source_tree_sha256": source_tree_sha256,
                "archive_sha256": archive_sha256,
                "archive_filename": archive.name,
                "algorithm": "sha256",
                "archive_format": {
                    "format": "zip",
                    "compression": "deflate",
                    "compression_level": 9,
                    "timestamp": "1980-01-01T00:00:00Z",
                    "path_prefix": f"NEMO-{version}/",
                },
                "excluded_roots": sorted(EXCLUDED_ROOTS),
                "excluded_prefixes": ["/".join(GENERATED_PREFIX)],
                "files": file_hashes,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"Release: {version}")
    print(f"Files: {len(files)}")
    print(f"Source tree SHA-256: {source_tree_sha256}")
    print(f"Archive: {archive}")
    print(f"Archive SHA-256: {archive_sha256}")
    print(f"Manifest: {manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
