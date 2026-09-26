# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for baseline capture.

The baseline only has value if it is reproducible and if the crate graph
describes the workspace rather than the whole resolved universe. These tests
pin both properties against synthetic inputs.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import baseline  # noqa: E402


def workspace_metadata() -> dict:
    """Metadata where one workspace member depends on another and on crates.io."""
    return {
        "workspace_members": ["nemo-core 0.1.0", "nemo-contracts 0.1.0"],
        "packages": [
            {
                "name": "nemo-core",
                "id": "nemo-core 0.1.0",
                "dependencies": [
                    {"name": "nemo-contracts", "kind": None},
                    {"name": "serde", "kind": None},
                    {"name": "dev-only", "kind": "dev"},
                ],
            },
            {
                "name": "nemo-contracts",
                "id": "nemo-contracts 0.1.0",
                "dependencies": [],
            },
            {"name": "serde", "id": "serde 1.0.0", "dependencies": []},
        ],
    }


def test_crate_graph_keeps_workspace_edges_only() -> None:
    graph = baseline.crate_graph(workspace_metadata())

    assert graph == {"nemo-contracts": [], "nemo-core": ["nemo-contracts"]}


def test_lockfile_digests_hash_present_files_and_skip_absent_ones(
    tmp_path: pathlib.Path,
) -> None:
    (tmp_path / "Cargo.lock").write_bytes(b"locked\n")

    digests = baseline.lockfile_digests(tmp_path)

    assert digests["Cargo.lock"] == hashlib.sha256(b"locked\n").hexdigest()
    assert digests["uv.lock"] is None
    assert digests["package-lock.json"] is None


def test_every_recorded_lockfile_is_one_the_repository_uses() -> None:
    root = pathlib.Path(baseline.REPO_ROOT)

    recorded = set(baseline.LOCKFILES)

    # A baseline that silently stopped recording a lockfile would still pass
    # every other test, so tie the list to what the tree actually carries.
    assert {"Cargo.lock", "uv.lock", "package-lock.json"} <= recorded
    assert (root / "Cargo.lock").is_file()


def test_contract_revisions_are_read_from_the_declarations() -> None:
    # The baseline records which protocol and plugin ABI it speaks. If a
    # declaration is renamed or reformatted this fails, rather than the baseline
    # quietly recording `None` for a number it is supposed to pin.
    revisions = baseline.declared_revisions(baseline.REPO_ROOT)

    assert set(revisions) == {"plugin_protocol", "native_plugin_abi"}
    for name, value in revisions.items():
        assert value is not None, f"{name} was not found in its declaration"
        assert value > 0, f"{name} recorded {value}"
