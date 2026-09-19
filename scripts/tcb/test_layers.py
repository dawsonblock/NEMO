# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dependency-layer gate.

The gate exists to stop the crate graph getting worse while it is being fixed,
so the tests pin the direction rule, the grandfather ratchet, and the refusal
to leave a crate unplaced.
"""

from __future__ import annotations

import pathlib
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import baseline  # noqa: E402
import layers  # noqa: E402
import report  # noqa: E402


def policy() -> dict:
    return {
        "layers": {
            "contracts": ["contracts"],
            "kernel": ["kernel"],
            "adapters": ["adapters"],
            "runtime": ["runtime"],
            "surfaces": ["surfaces"],
        },
        "grandfathered": {"kernel": ["adapters"]},
    }


def test_layer_indexes_follow_document_order() -> None:
    indexes = layers.layer_indexes(policy())

    assert indexes["contracts"] < indexes["kernel"] < indexes["adapters"]
    assert indexes["adapters"] < indexes["runtime"] < indexes["surfaces"]


def test_upward_edges_only_reports_lower_reaching_higher() -> None:
    graph = {
        "kernel": ["contracts", "adapters"],
        "adapters": ["kernel"],
        "runtime": ["kernel"],
    }

    assert layers.upward_edges(graph, policy()) == [("kernel", "adapters")]


def test_a_grandfathered_edge_is_not_a_failure() -> None:
    graph = {"kernel": ["adapters"]}
    upward = layers.upward_edges(graph, policy())

    assert upward == [("kernel", "adapters")]
    assert layers.unexpected_edges(upward, policy()) == []


def test_a_new_upward_edge_fails() -> None:
    graph = {"kernel": ["adapters", "runtime"]}
    upward = layers.upward_edges(graph, policy())

    assert layers.unexpected_edges(upward, policy()) == [("kernel", "runtime")]


def test_a_grandfathered_edge_that_disappeared_is_reported_stale() -> None:
    assert layers.stale_entries([], policy()) == [("kernel", "adapters")]


def test_unclassified_crates_are_reported() -> None:
    graph = {"kernel": ["contracts", "mystery"]}

    assert layers.unclassified_crates(graph, policy()) == ["mystery"]


def test_repository_policy_places_every_workspace_crate() -> None:
    metadata = report.cargo_metadata(layers.REPO_ROOT)
    graph = baseline.crate_graph(metadata)
    loaded = report.load_policy(layers.DEFAULT_POLICY)

    # A crate nobody placed is a crate whose dependencies nobody is checking,
    # so adding a workspace member without classifying it must fail here.
    assert layers.unclassified_crates(graph, loaded) == []
    assert set(loaded["layers"]) == {
        "contracts",
        "kernel",
        "adapters",
        "runtime",
        "surfaces",
        "qualification",
    }
