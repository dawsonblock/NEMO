# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for deterministic source selection outside a Git checkout."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from package_release import canonical_tree, is_excluded, qualified_source_tree, tracked_paths


def test_generated_python_artifacts_are_excluded() -> None:
    assert is_excluded(Path("__pycache__/module.cpython-313.pyc"))
    assert is_excluded(Path("src/module.pyc"))
    assert is_excluded(Path(".coverage"))
    assert is_excluded(Path("build/output.bin"))
    assert is_excluded(Path("release/source-manifest.json"))
    assert is_excluded(Path("release/artifact.json"))


def test_filesystem_fallback_ignores_generated_python_artifacts(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text('[workspace.package]\nversion = "0.9.1-rc.4"\n')
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("pub fn ok() {}\n")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "lib.cpython-313.pyc").write_bytes(b"generated")
    (tmp_path / "src" / "module.pyc").write_bytes(b"generated")

    assert tracked_paths(tmp_path) == [Path("Cargo.toml"), Path("src/lib.rs")]


def test_packaging_requires_a_matching_valid_qualification(tmp_path: Path) -> None:
    qualification = tmp_path / "qualification"
    qualification.mkdir()
    (tmp_path / "Cargo.toml").write_text('[workspace.package]\nversion = "0.9.1-rc.4"\n')
    digest, _ = canonical_tree(tracked_paths(tmp_path), tmp_path)
    (qualification / "source-manifest.json").write_text('{"root_digest": "%s"}\n' % digest)
    (qualification / "qualification.json").write_text(
        '{"overall": "PASS", "qualification_status": "VALID", "provenance": {"source_tree_sha256": "%s"}}\n' % digest
    )

    result = qualified_source_tree(tmp_path, qualification, digest)

    assert result["source_tree_sha256"] == digest


def test_packaging_rejects_changed_or_invalid_qualification(tmp_path: Path) -> None:
    qualification = tmp_path / "qualification"
    qualification.mkdir()
    (qualification / "source-manifest.json").write_text('{"root_digest": "old"}\n')
    (qualification / "qualification.json").write_text(
        '{"overall": "FAIL", "qualification_status": "INVALID", "provenance": {"source_tree_sha256": "old"}}\n'
    )

    try:
        qualified_source_tree(tmp_path, qualification, "new")
    except ValueError as error:
        assert "not a valid PASS" in str(error)
    else:
        raise AssertionError("invalid qualification was accepted")


def test_packaging_rejects_source_changed_after_valid_qualification(tmp_path: Path) -> None:
    qualification = tmp_path / "qualification"
    qualification.mkdir()
    (qualification / "source-manifest.json").write_text('{"root_digest": "old"}\n')
    (qualification / "qualification.json").write_text(
        '{"overall": "PASS", "qualification_status": "VALID", "provenance": {"source_tree_sha256": "old"}}\n'
    )

    try:
        qualified_source_tree(tmp_path, qualification, "new")
    except ValueError as error:
        assert "changed after qualification" in str(error)
    else:
        raise AssertionError("changed source was accepted")
