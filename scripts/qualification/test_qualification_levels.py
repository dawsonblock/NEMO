# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for qualification tiers and evidence-gated promotion."""

from __future__ import annotations

import pathlib
import sys
from typing import Any

import pytest

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import qualification_levels as levels  # noqa: E402

PINNED_LINUX: dict[str, Any] = {
    "platform": "Linux-6.8.0-1018-azure-x86_64-with-glibc2.36",
    "machine": "x86_64",
    "tools": {
        "rustc": "rustc 1.96.1 (31fca3adb 2026-06-26)",
        "cargo": "cargo 1.96.1 (356927216 2026-06-26)",
        "node": "v24.16.0",
        "npm": "11.11.0",
        "python": "Python 3.11.2",
        "uv": "uv 0.9.28 (abc 2026-01-01 x86_64-unknown-linux-gnu)",
        "go": "go version go1.26.1 linux/amd64",
        "just": "just 1.47.1",
        "cargo-nextest": "cargo-nextest 0.9.133 (65e806bd5 2026-04-14)",
        "cargo-deny": "cargo-deny 0.19.1",
        "cargo-audit": "cargo-audit-audit 0.22.2",
        "cargo-about": "cargo-about 0.9.1",
    },
    "postgres_server_version": "17.6",
}

MACOS_LOCAL: dict[str, Any] = {
    "platform": "macOS-26.2-arm64-arm-64bit",
    "machine": "arm64",
    "tools": {
        "rustc": "rustc 1.96.1 (31fca3adb 2026-06-26)",
        "cargo": "cargo 1.96.1 (356927216 2026-06-26)",
        "node": "v24.16.0",
        "npm": "11.13.0",
        "python": "Python 3.12.0",
        "uv": "uv 0.11.8 (0e961dd9a 2026-04-27 aarch64-apple-darwin)",
        "go": "go version go1.25.1 darwin/arm64",
        "just": "just 1.47.1",
        "cargo-nextest": "cargo-nextest 0.9.133 (65e806bd5 2026-04-14)",
        "cargo-deny": "cargo-deny 0.20.2",
        "cargo-audit": "cargo-audit-audit 0.22.2",
        "cargo-about": "cargo-about 0.9.1",
    },
    "postgres_server_version": "14.20 (Homebrew)",
}


def make_report(
    *,
    overall: str | None = None,
    statuses: dict[str, str] | None = None,
    git: dict | None = None,
) -> dict:
    """Build a qualification report shaped like run.sh writes."""

    checks = {name: "PASS" for name in levels.MANDATORY_MATRIX_CHECKS}
    checks.update({name: "PASS" for name in levels.FAULT_MATRIX_CHECKS})
    checks.update(statuses or {})
    if overall is None:
        overall = "FAIL" if "FAIL" in checks.values() else "PASS"
    return {
        "overall": overall,
        "qualification_status": "VALID" if overall == "PASS" else "INVALID",
        "checks": checks,
        "_source_manifest": {"git": git if git is not None else {"commit": "a" * 40, "status": []}},
    }


def evaluate(
    report: dict[str, Any] | None = None,
    *,
    recorded_environment: dict[str, Any] | None = None,
    current_environment: dict[str, Any] | None = None,
    release_environment: dict[str, Any] | None = None,
    release_artifact: dict[str, Any] | None = None,
    evidence_signature: str = "MISSING",
    attestation_signature: str = "MISSING",
) -> dict[str, Any]:
    """Evaluate a report against the pinned release environment."""

    return levels.evaluate(
        make_report() if report is None else report,
        recorded_environment=MACOS_LOCAL if recorded_environment is None else recorded_environment,
        current_environment=MACOS_LOCAL if current_environment is None else current_environment,
        release_environment=(levels.load_release_environment() if release_environment is None else release_environment),
        release_artifact=release_artifact,
        evidence_signature=evidence_signature,
        attestation_signature=attestation_signature,
    )


def test_release_environment_pins_linux() -> None:
    pin = levels.load_release_environment()
    assert pin["release_platform"] == "linux"
    assert pin["release_machine"] == "x86_64"


def test_macos_run_can_never_emit_a_release_tier() -> None:
    """The acceptance gate: a local macOS run must not claim the Linux tier."""

    result = evaluate()
    assert result["promotion"] == "QUALIFIED_LOCAL"
    assert result["tiers"]["QUALIFIED_CI"]["attainable"] is False
    assert result["tiers"]["PRODUCTION_CANDIDATE"]["attainable"] is False
    assert any("not the pinned release platform" in reason for reason in result["blocking_reasons"])


def test_environment_variation_downgrades_to_dev_pass() -> None:
    drifted: dict[str, Any] = {
        **MACOS_LOCAL,
        "tools": {**MACOS_LOCAL["tools"], "rustc": "rustc 1.97.0 (deadbeef 2026-01-01)"},
    }
    result = evaluate(current_environment=drifted)
    assert result["promotion"] == "DEV_PASS"
    assert any("not reproduced exactly" in reason for reason in result["blocking_reasons"])


def test_failing_matrix_is_not_a_pass_tier() -> None:
    report = make_report(statuses={"postgres-effect-store": "FAIL"})
    result = levels.evaluate(
        report,
        recorded_environment=MACOS_LOCAL,
        current_environment=MACOS_LOCAL,
    )
    assert result["promotion"] == "DEV"


def test_pinned_linux_run_reaches_qualified_ci() -> None:
    result = evaluate(recorded_environment=PINNED_LINUX, current_environment=PINNED_LINUX)
    assert result["promotion"] == "QUALIFIED_FAILURE"
    assert result["tiers"]["QUALIFIED_CI"]["attainable"] is True


def test_dirty_checkout_blocks_qualified_ci() -> None:
    report = make_report(git={"commit": "a" * 40, "status": [" M crates/core/src/lib.rs"]})
    result = levels.evaluate(
        report,
        recorded_environment=PINNED_LINUX,
        current_environment=PINNED_LINUX,
    )
    assert result["promotion"] == "QUALIFIED_LOCAL"
    assert any("clean Git checkout" in reason for reason in result["blocking_reasons"])


def test_production_controls_block_candidate_promotion() -> None:
    result = evaluate(recorded_environment=PINNED_LINUX, current_environment=PINNED_LINUX)
    assert result["tiers"]["PRODUCTION_CANDIDATE"]["attainable"] is False
    reasons = result["tiers"]["PRODUCTION_CANDIDATE"]["blocking_reasons"]
    assert any("production control checks are not all PASS" in reason for reason in reasons)


def test_unsigned_evidence_blocks_candidate_promotion() -> None:
    """A distributable promotion is impossible without a verified signature."""

    report = make_report(statuses={name: "PASS" for name in levels.PRODUCTION_CONTROL_CHECKS})
    result = levels.evaluate(
        report,
        recorded_environment=PINNED_LINUX,
        current_environment=PINNED_LINUX,
        evidence_signature="UNSIGNED",
        attestation_signature="UNSIGNED",
    )
    assert result["promotion"] == "QUALIFIED_FAILURE"
    assert any(
        "signature is UNSIGNED, not SIGNED" in reason
        for reason in result["tiers"]["PRODUCTION_CANDIDATE"]["blocking_reasons"]
    )
    assert result["signature_required_tiers"] == ["PRODUCTION_CANDIDATE", "PRODUCTION_RELEASE"]


def test_unsigned_run_can_still_reach_qualified_ci() -> None:
    """Signing is a production prerequisite, not a development one."""

    result = evaluate(
        recorded_environment=PINNED_LINUX,
        current_environment=PINNED_LINUX,
        evidence_signature="UNSIGNED",
        attestation_signature="UNSIGNED",
    )
    assert result["tiers"]["QUALIFIED_CI"]["attainable"] is True
    assert result["promotion"] == "QUALIFIED_FAILURE"


def test_unknown_signature_state_is_rejected() -> None:
    with pytest.raises(ValueError, match="signature state"):
        evaluate(evidence_signature="PROBABLY")


def test_release_requires_artifact_binding() -> None:
    report = make_report(statuses={name: "PASS" for name in levels.PRODUCTION_CONTROL_CHECKS})
    result = levels.evaluate(
        report,
        recorded_environment=PINNED_LINUX,
        current_environment=PINNED_LINUX,
        evidence_signature="SIGNED",
        release_artifact=None,
    )
    assert result["tiers"]["PRODUCTION_CANDIDATE"]["attainable"] is True
    assert result["promotion"] == "PRODUCTION_CANDIDATE"
    assert any(
        "release artifact digest" in reason for reason in result["tiers"]["PRODUCTION_RELEASE"]["blocking_reasons"]
    )


def test_release_binding_completes_the_ladder() -> None:
    report = make_report(statuses={name: "PASS" for name in levels.PRODUCTION_CONTROL_CHECKS})
    result = levels.evaluate(
        report,
        recorded_environment=PINNED_LINUX,
        current_environment=PINNED_LINUX,
        evidence_signature="SIGNED",
        attestation_signature="SIGNED",
        release_artifact={"path": "nemo.zip", "sha256": "b" * 64},
    )
    assert result["promotion"] == "PRODUCTION_RELEASE"
    assert not result["blocking_reasons"]


def test_release_requires_a_signed_attestation_too() -> None:
    report = make_report(statuses={name: "PASS" for name in levels.PRODUCTION_CONTROL_CHECKS})
    result = levels.evaluate(
        report,
        recorded_environment=PINNED_LINUX,
        current_environment=PINNED_LINUX,
        evidence_signature="SIGNED",
        attestation_signature="UNSIGNED",
        release_artifact={"path": "nemo.zip", "sha256": "b" * 64},
    )
    assert result["promotion"] == "PRODUCTION_CANDIDATE"
    assert any(
        "release attestation signature is UNSIGNED" in reason
        for reason in result["tiers"]["PRODUCTION_RELEASE"]["blocking_reasons"]
    )


def test_production_release_with_unsigned_evidence_is_never_promoted() -> None:
    """The plan's explicit gate: PRODUCTION_RELEASE + UNSIGNED must fail."""

    report = make_report(statuses={name: "PASS" for name in levels.PRODUCTION_CONTROL_CHECKS})
    result = levels.evaluate(
        report,
        recorded_environment=PINNED_LINUX,
        current_environment=PINNED_LINUX,
        evidence_signature="UNSIGNED",
        attestation_signature="UNSIGNED",
        release_artifact={"path": "nemo.zip", "sha256": "b" * 64},
    )
    assert result["promotion"] == "QUALIFIED_FAILURE"
    assert result["tiers"]["PRODUCTION_RELEASE"]["attainable"] is False
    assert result["tiers"]["PRODUCTION_CANDIDATE"]["attainable"] is False
    for tier in ("PRODUCTION_CANDIDATE", "PRODUCTION_RELEASE"):
        assert any("not SIGNED" in reason for reason in result["tiers"][tier]["blocking_reasons"])


def test_production_candidate_with_unsigned_evidence_is_never_promoted() -> None:
    report = make_report(statuses={name: "PASS" for name in levels.PRODUCTION_CONTROL_CHECKS})
    result = levels.evaluate(
        report,
        recorded_environment=PINNED_LINUX,
        current_environment=PINNED_LINUX,
        evidence_signature="UNSIGNED",
        attestation_signature="MISSING",
    )
    assert result["promotion"] != "PRODUCTION_CANDIDATE"
    assert result["tiers"]["PRODUCTION_CANDIDATE"]["attainable"] is False


def test_gate_catalog_marks_unimplemented_gates_pending() -> None:
    gates = levels.gate_statuses({})
    assert gates["E3-001"]["status"] == "NOT_SATISFIED"
    # E3.1 made migration integrity and physical schema verification real gates.
    assert gates["E3-011"]["status"] == "NOT_SATISFIED"
    assert gates["E3-012"]["status"] == "NOT_SATISFIED"
    # E3.2 and E3.3 work has not started, so those gates stay visibly open.
    assert gates["E3-016"]["status"] == "PENDING"
    assert gates["E3-020"]["status"] == "PENDING"
    assert gates["E3-024"]["status"] == "PENDING"
    assert set(gates) == set(levels.E3_GATES)


def test_gate_catalog_satisfies_implemented_gates() -> None:
    statuses = {name: "PASS" for name in levels.MANDATORY_MATRIX_CHECKS}
    gates = levels.gate_statuses(statuses)
    assert gates["E3-001"]["status"] == "PASS"
    assert gates["E3-011"]["status"] == "PASS"
    assert gates["E3-012"]["status"] == "PASS"
    assert gates["E3-010"]["status"] == "PASS"
    assert gates["E3-021"]["status"] == "PASS"
    assert gates["E3-007"]["status"] == "PENDING"


def test_e3_gate_identifiers_are_frozen() -> None:
    """The E3.1 and E3.2 identifiers are fixed by the plan; later gates shift."""

    assert [levels.E3_GATES[f"E3-{n:03d}"]["title"] for n in range(11, 16)] == [
        "Migration integrity",
        "Physical schema verification",
        "EffectStore",
        "PostgreSQL concurrency",
        "PostgreSQL restart",
    ]
    assert [levels.E3_GATES[f"E3-{n:03d}"]["title"] for n in range(16, 21)] == [
        "Runtime composition",
        "Registry sealing",
        "Identity canonicalization",
        "ABI conformance",
        "Consequential route enforcement",
    ]
    assert len(levels.E3_GATES) == len(set(levels.E3_GATES))


@pytest.mark.parametrize(
    ("platform_string", "expected"),
    [
        ("macOS-26.2-arm64", "macos"),
        ("Linux-6.8.0-x86_64-with-glibc2.36", "linux"),
        ("Windows-11-AMD64", "windows"),
        (None, "unknown"),
    ],
)
def test_platform_family_classification(platform_string, expected) -> None:
    assert levels.platform_family(platform_string) == expected
