# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for provenance verification outside Git checkouts."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def test_provenance_check_works_without_git(tmp_path: Path) -> None:
    script = Path(__file__).with_name("provenance_check.py")
    script_path = tmp_path / "scripts" / "qualification" / script.name
    script_path.parent.mkdir(parents=True)
    shutil.copy2(script, script_path)
    (tmp_path / "hello.txt").write_text("hello\n")
    files = {
        "hello.txt": hashlib.sha256((tmp_path / "hello.txt").read_bytes()).hexdigest(),
        "scripts/qualification/provenance_check.py": hashlib.sha256(script_path.read_bytes()).hexdigest(),
    }
    root_digest = hashlib.sha256(
        "".join(f"{name}\t{digest}\n" for name, digest in files.items()).encode()
    ).hexdigest()
    manifest = tmp_path / "qualification" / "source-manifest.json"
    manifest.parent.mkdir()
    manifest.write_text(json.dumps({"files": files, "root_digest": root_digest, "lockfiles": {}, "git": {}}))

    result = subprocess.run(
        ["python3", str(script_path), "--root", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PROVENANCE PASS" in result.stdout
