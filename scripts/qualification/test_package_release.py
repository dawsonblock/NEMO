# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for deterministic source selection outside a Git checkout."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from package_release import is_excluded, tracked_paths


def test_generated_python_artifacts_are_excluded() -> None:
    assert is_excluded(Path("__pycache__/module.cpython-313.pyc"))
    assert is_excluded(Path("src/module.pyc"))
    assert is_excluded(Path(".coverage"))
    assert is_excluded(Path("build/output.bin"))


def test_filesystem_fallback_ignores_generated_python_artifacts(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[workspace.package]\nversion = \"0.9.1-rc.4\"\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("pub fn ok() {}\n")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "lib.cpython-313.pyc").write_bytes(b"generated")
    (tmp_path / "src" / "module.pyc").write_bytes(b"generated")

    assert tracked_paths(tmp_path) == [Path("Cargo.toml"), Path("src/lib.rs")]
