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
import sys
import zipfile
from datetime import datetime, timezone

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_ROOT = SCRIPT_DIR.parents[1]
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import source_tree  # noqa: E402  (local module)


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
    """Return whether the static source policy excludes a path."""

    return source_tree.statically_excluded(pathlib.PurePosixPath(relative.as_posix()))


def tracked_paths(root: pathlib.Path) -> list[pathlib.Path]:
    """Return the source entries the qualification manifest describes.

    Release packaging and provenance verification share one enumeration so a
    packaged archive cannot contain a different entry set than the manifest that
    qualified it.
    """

    enumeration = source_tree.enumerate_tree(root)
    return [pathlib.Path(path) for path in enumeration.entries]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_tree(files: list[pathlib.Path], root: pathlib.Path) -> tuple[str, dict[str, str]]:
    """Return the typed tree digest plus the flat file digests."""

    entries = source_tree.enumerate_tree(root).entries
    hashes = {
        relative.as_posix(): entries[relative.as_posix()].get("sha256", "")
        for relative in files
        if entries.get(relative.as_posix(), {}).get("kind") == source_tree.KIND_FILE
    }
    return source_tree.entries_digest(entries), hashes


def zip_info(name: str, source: pathlib.Path) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
    if source.is_symlink():
        # A flattened symlink would change the entry type the manifest verified.
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
    else:
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
            source = root / relative
            payload = os.readlink(source).encode() if source.is_symlink() else source.read_bytes()
            handle.writestr(
                zip_info(prefix + relative.as_posix(), source),
                payload,
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )


def qualified_source_tree(
    root: pathlib.Path, qualification_dir: pathlib.Path, actual_source_tree_sha256: str
) -> dict[str, object]:
    """Require a valid qualification record for exactly the source being packaged."""

    report_path = qualification_dir / "qualification.json"
    source_manifest_path = qualification_dir / "source-manifest.json"
    if not report_path.is_file() or not source_manifest_path.is_file():
        raise ValueError("missing qualification.json or source-manifest.json; run full qualification before packaging")

    try:
        report = json.loads(report_path.read_text())
        source_manifest = json.loads(source_manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid qualification evidence: {error}") from error

    if report.get("overall") != "PASS" or report.get("qualification_status") != "VALID":
        raise ValueError("qualification report is not a valid PASS certificate")

    qualified_digest = source_manifest.get("root_digest")
    report_digest = report.get("provenance", {}).get("source_tree_sha256")
    if not isinstance(qualified_digest, str) or qualified_digest != report_digest:
        raise ValueError("qualification report and source manifest do not agree on the source tree")
    if qualified_digest != actual_source_tree_sha256:
        raise ValueError("source tree changed after qualification; rerun full qualification before packaging")
    return {
        "source_tree_sha256": qualified_digest,
        "qualification_report": str(report_path.relative_to(root)),
        "source_manifest": str(source_manifest_path.relative_to(root)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=pathlib.Path, default=DEFAULT_ROOT)
    parser.add_argument("--version", help="release version; defaults to Cargo.toml")
    parser.add_argument("--output", type=pathlib.Path, help="archive output path")
    parser.add_argument(
        "--qualification-dir",
        type=pathlib.Path,
        help="directory containing a valid qualification.json and source-manifest.json",
    )
    args = parser.parse_args()

    root = args.repo_root.resolve()
    version = args.version or workspace_version(root)
    archive = args.output or root / "release" / "artifacts" / f"NEMO-{version}-source.zip"
    archive = archive.resolve()
    files = tracked_paths(root)
    source_tree_sha256, file_hashes = canonical_tree(files, root)
    qualification_dir = (args.qualification_dir or root / "qualification").resolve()
    try:
        qualification = qualified_source_tree(root, qualification_dir, source_tree_sha256)
    except ValueError as error:
        parser.error(str(error))
    write_archive(archive, root, version, files)
    archive_sha256 = sha256_bytes(archive.read_bytes())

    checksum = archive.with_suffix(archive.suffix + ".sha256")
    checksum.write_text(f"{archive_sha256}  {archive.name}\n")
    manifest = archive.with_suffix(archive.suffix + ".manifest.json")
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "release_version": version,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "source_tree_sha256": source_tree_sha256,
                "qualified_source_tree_sha256": qualification["source_tree_sha256"],
                "qualification_report": qualification["qualification_report"],
                "qualification_source_manifest": qualification["source_manifest"],
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
                "excluded_roots": sorted(source_tree.ROOT_ONLY_PRUNED),
                "excluded_prefixes": ["/".join(source_tree.GENERATED_PREFIX)],
                "files": file_hashes,
                "entries": len(files),
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
