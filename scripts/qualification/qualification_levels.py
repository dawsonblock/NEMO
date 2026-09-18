#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Qualification tiers and the evidence each tier requires.

``QUALIFIED_LOCAL`` used to be the only promotion this repository could emit, so
a macOS developer machine read the same as a pinned Linux release host. Tiers
exist to make that difference explicit and machine-checkable:

``DEV_PASS``
    Tests passed in a recorded environment. Environment variation is allowed.
``QUALIFIED_LOCAL``
    The recorded environment is reproduced exactly on this host.
``QUALIFIED_CI``
    A clean checkout on the pinned Linux release environment with a fresh
    database and the full mandatory matrix.
``QUALIFIED_FAILURE``
    ``QUALIFIED_CI`` plus fault injection and recovery qualification.
``PRODUCTION_CANDIDATE``
    ``QUALIFIED_FAILURE`` plus the real authority, providers, recovery,
    isolation, DLP, and HA database controls, with signed evidence.
``PRODUCTION_RELEASE``
    ``PRODUCTION_CANDIDATE`` bound to one exact final artifact.

Every tier is cumulative, and a tier is only reachable when each of its
prerequisites is independently satisfied. Missing evidence downgrades the
promotion; it never rounds up.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
RELEASE_ENVIRONMENT_PATH = SCRIPT_DIR / "release-environment.json"

LEVELS = (
    "DEV_PASS",
    "QUALIFIED_LOCAL",
    "QUALIFIED_CI",
    "QUALIFIED_FAILURE",
    "PRODUCTION_CANDIDATE",
    "PRODUCTION_RELEASE",
)

# The E3 gate catalog. Each gate names the checks that currently satisfy it, and
# whether this repository can produce that evidence today. Unimplemented gates
# stay visible as PENDING instead of quietly disappearing from the record.
E3_GATES: dict[str, dict[str, Any]] = {
    "E3-001": {"title": "Exact source tree", "checks": ["source-stability"], "implemented": True},
    "E3-002": {"title": "Symlink/type/mode provenance", "checks": ["source-stability"], "implemented": True},
    "E3-003": {"title": "Environment pinning", "checks": [], "implemented": False},
    "E3-004": {"title": "Dependency integrity", "checks": ["cargo-deny", "cargo-audit"], "implemented": True},
    "E3-005": {"title": "Kernel invariants", "checks": ["effect-contracts"], "implemented": True},
    "E3-006": {"title": "Ledger invariants", "checks": ["effect-contracts"], "implemented": True},
    "E3-007": {"title": "Authority cryptography", "checks": [], "implemented": False},
    "E3-008": {"title": "Process crash", "checks": ["postgres-crash-recovery"], "implemented": True},
    "E3-009": {"title": "Transport security", "checks": ["postgres-transport-security"], "implemented": True},
    "E3-010": {"title": "SBOM", "checks": ["sbom"], "implemented": True},
    # E3.1 database-readiness gates. These identifiers are fixed by the E3.1
    # gate list and must not be reused for anything else.
    "E3-011": {"title": "Migration integrity", "checks": ["migration-integrity"], "implemented": True},
    "E3-012": {
        "title": "Physical schema verification",
        "checks": ["physical-schema-verification"],
        "implemented": True,
    },
    "E3-013": {"title": "EffectStore", "checks": ["postgres-effect-store"], "implemented": True},
    "E3-014": {"title": "PostgreSQL concurrency", "checks": ["postgres-concurrency"], "implemented": True},
    "E3-015": {"title": "PostgreSQL restart", "checks": ["postgres-restart"], "implemented": True},
    # E3.2 runtime gates. Open until E3.2 lands.
    "E3-016": {"title": "Runtime composition", "checks": [], "implemented": False},
    "E3-017": {"title": "Registry sealing", "checks": [], "implemented": False},
    "E3-018": {"title": "Identity canonicalization", "checks": [], "implemented": False},
    "E3-019": {"title": "ABI conformance", "checks": [], "implemented": False},
    "E3-020": {"title": "Consequential route enforcement", "checks": [], "implemented": False},
    "E3-021": {"title": "Vulnerability policy", "checks": ["cargo-deny", "cargo-audit"], "implemented": True},
    "E3-022": {"title": "Evidence integrity", "checks": [], "implemented": False},
    "E3-023": {"title": "Exact release artifact", "checks": [], "implemented": False},
    "E3-024": {"title": "Recovery Supervisor", "checks": [], "implemented": False},
    "E3-025": {"title": "Provider runtime", "checks": [], "implemented": False},
    "E3-026": {"title": "GitHub reconciliation", "checks": [], "implemented": False},
    "E3-027": {"title": "Gmail reconciliation", "checks": [], "implemented": False},
    "E3-028": {"title": "DLP", "checks": [], "implemented": False},
    "E3-029": {"title": "Isolation", "checks": [], "implemented": False},
    "E3-030": {"title": "Secret handling", "checks": [], "implemented": False},
    "E3-031": {"title": "Multi-worker recovery", "checks": [], "implemented": False},
    "E3-032": {"title": "Property model", "checks": [], "implemented": False},
    "E3-033": {"title": "Network faults", "checks": [], "implemented": False},
    "E3-034": {"title": "PostgreSQL failover", "checks": [], "implemented": False},
    "E3-035": {"title": "Machine failure", "checks": [], "implemented": False},
    "E3-036": {"title": "Operator controls", "checks": [], "implemented": False},
    "E3-037": {"title": "Kill switches", "checks": [], "implemented": False},
    "E3-038": {"title": "Performance", "checks": [], "implemented": False},
    # Appended, not renumbered: the catalog above is frozen once attestations
    # refer to gate identifiers. This gate carries the mandatory E3.1 boundary
    # invariant that a database failure cannot decide, by itself, whether an
    # external effect happened.
    "E3-039": {
        "title": "Database failure boundary semantics",
        "checks": ["db-failure-boundaries"],
        "implemented": True,
    },
}

# Checks that must all pass for the mandatory CI matrix.
MANDATORY_MATRIX_CHECKS = (
    "source-cleanliness",
    "source-stability",
    "rust-format",
    "clippy",
    "rust-tests",
    "rust-doc-tests",
    "effect-contracts",
    "migration-integrity",
    "physical-schema-verification",
    "db-failure-boundaries",
    "postgres-transport-security",
    "postgres-effect-store",
    "postgres-concurrency",
    "postgres-restart",
    "cargo-deny",
    "cargo-audit",
    "python-tests",
    "node-tests",
    "go-tests",
    "sbom",
)

# Checks that must pass before an UNKNOWN action is trusted to recover itself.
FAULT_MATRIX_CHECKS = (
    "postgres-crash-recovery",
    "postgres-kernel-restart",
)

# Subsystems that Phase 12-24 must supply before production promotion. They are
# named here so the tiers fail closed with a reason instead of silently passing.
PRODUCTION_CONTROL_CHECKS = (
    "runtime-composition",
    "registry-sealing",
    "identity-canonicalization",
    "abi-vectors",
    "authority-cryptography",
    "physical-schema-verification",
    "recovery-supervisor",
    "provider-runtime",
    "github-reconciliation",
    "gmail-reconciliation",
    "dlp-enforcement",
    "isolation-enforcement",
    "secret-management",
    "ha-database",
    "kill-switches",
)

TOOL_VERSION_PREFIXES = {
    "rustc": "rustc",
    "cargo": "cargo",
    "node": "node",
    "npm": "npm",
    "python": "python",
    "go": "go",
}

# Tiers that may not be claimed without a verified signature over the evidence
# and the release attestation. QUALIFIED_CI is deliberately absent: an unsigned
# development run may reach it, but nothing distributable can.
SIGNATURE_REQUIRED_TIERS = ("PRODUCTION_CANDIDATE", "PRODUCTION_RELEASE")

SIGNATURE_STATES = ("SIGNED", "UNSIGNED", "MISSING")


def load_release_environment(path: pathlib.Path | None = None) -> dict[str, Any]:
    """Load the pinned release environment description."""

    return json.loads((path or RELEASE_ENVIRONMENT_PATH).read_text())


def platform_family(platform_string: str | None) -> str:
    """Classify a platform string into a coarse family."""

    lowered = (platform_string or "").lower()
    if lowered.startswith("macos") or "darwin" in lowered:
        return "macos"
    if lowered.startswith("linux") or "linux" in lowered:
        return "linux"
    if lowered.startswith("windows") or "windows" in lowered:
        return "windows"
    return "unknown"


def _version_tuple(value: str | None) -> tuple[int, ...]:
    """Extract the leading numeric version components from a version string."""

    if not value:
        return ()
    match = re.search(r"(\d+(?:\.\d+)*)", value)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def _version_matches(actual: str | None, wanted: str | None) -> bool:
    """Return whether an observed tool version satisfies a pinned version.

    Pins are written with the precision that matters (``3.11`` for Python,
    ``0.19.1`` for cargo-deny), so an observed version matches when the pinned
    components are a leading prefix of it. A pin with no numeric component is
    unconstrained, and a missing tool never satisfies a pin that names it.
    """

    if wanted is None:
        return True
    expected = _version_tuple(wanted)
    if not expected:
        return True
    observed = _version_tuple(actual)
    if not observed:
        return False
    return observed[: len(expected)] == expected


def compare_environment(actual: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    """Compare a recorded environment against a pinned one, field by field."""

    actual_tools = actual.get("tools") or {}
    expected_tools = expected.get("tools") or {}
    differences: dict[str, dict[str, Any]] = {}
    for tool, wanted in expected_tools.items():
        got = actual_tools.get(tool)
        if not _version_matches(got, wanted):
            differences[tool] = {"expected": wanted, "actual": got}

    expected_platform = expected.get("release_platform")
    actual_family = platform_family(actual.get("platform"))
    platform_matches = expected_platform is None or actual_family == expected_platform

    expected_machine = expected.get("release_machine")
    actual_machine = (actual.get("machine") or "").lower()
    machine_matches = (
        expected_machine is None
        or actual_machine == expected_machine
        or actual_machine.startswith(expected_machine + "_")
        or f"{expected_machine}-" in actual_machine
    )

    expected_postgres = expected.get("postgres_major")
    actual_postgres = _version_tuple(actual.get("postgres_server_version"))
    postgres_matches = expected_postgres is None or (
        bool(actual_postgres) and actual_postgres[0] == int(expected_postgres)
    )

    return {
        "platform_family": actual_family,
        "platform_matches": platform_matches,
        "machine_matches": machine_matches,
        "postgres_matches": postgres_matches,
        "tool_differences": differences,
        "matches_release_pin": platform_matches and machine_matches and postgres_matches and not differences,
    }


def environment_is_exactly_reproduced(recorded: dict[str, Any] | None, current: dict[str, Any] | None) -> bool:
    """Return whether the recorded environment is reproducible right now."""

    if not recorded or not current:
        return False
    return json.dumps(recorded, sort_keys=True) == json.dumps(current, sort_keys=True)


def _statuses(report: dict[str, Any]) -> dict[str, str]:
    return report.get("checks") or {}


def _all_pass(statuses: dict[str, str], names) -> tuple[bool, list[str]]:
    blocking = [name for name in names if statuses.get(name) != "PASS"]
    return not blocking, blocking


def gate_statuses(statuses: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Project the check results onto the E3 gate catalog."""

    gates: dict[str, dict[str, Any]] = {}
    for gate_id, gate in E3_GATES.items():
        checks = gate["checks"]
        if not gate["implemented"] or not checks:
            gates[gate_id] = {
                "title": gate["title"],
                "status": "PENDING",
                "satisfied_by": checks,
            }
            continue
        blocking = [name for name in checks if statuses.get(name) != "PASS"]
        gates[gate_id] = {
            "title": gate["title"],
            "status": "PASS" if not blocking else "NOT_SATISFIED",
            "satisfied_by": checks,
            "unsatisfied": blocking,
        }
    return gates


def evaluate(
    report: dict[str, Any],
    *,
    recorded_environment: dict[str, Any] | None = None,
    current_environment: dict[str, Any] | None = None,
    release_environment: dict[str, Any] | None = None,
    release_artifact: dict[str, Any] | None = None,
    evidence_signature: str = "MISSING",
    attestation_signature: str = "MISSING",
) -> dict[str, Any]:
    """Return the highest honestly attainable qualification tier.

    The result lists why each tier was withheld, so a downgrade is always
    explainable rather than a silently reduced label.
    """

    pinned = release_environment or load_release_environment()
    statuses = _statuses(report)
    overall_pass = report.get("overall") == "PASS"
    status_valid = report.get("qualification_status", "VALID") == "VALID"

    source_manifest = report.get("_source_manifest") or {}
    git = source_manifest.get("git") or {}
    clean_checkout = bool(git.get("commit")) and not (git.get("status") or [])

    environment_exact = environment_is_exactly_reproduced(recorded_environment, current_environment)
    comparison = compare_environment(current_environment or recorded_environment or {}, pinned)

    matrix_ok, matrix_blocking = _all_pass(statuses, MANDATORY_MATRIX_CHECKS)
    fault_ok, fault_blocking = _all_pass(statuses, FAULT_MATRIX_CHECKS)
    production_ok, production_blocking = _all_pass(statuses, PRODUCTION_CONTROL_CHECKS)

    evidence_signature = (evidence_signature or "MISSING").upper()
    attestation_signature = (attestation_signature or "MISSING").upper()
    if evidence_signature not in SIGNATURE_STATES or attestation_signature not in SIGNATURE_STATES:
        raise ValueError(
            f"signature state must be one of {SIGNATURE_STATES}, got {evidence_signature!r}/{attestation_signature!r}"
        )

    predicates: dict[str, tuple[bool, str]] = {
        "tests_pass": (
            overall_pass and status_valid,
            "the recorded test matrix did not pass",
        ),
        "environment_exact": (
            environment_exact,
            "the recorded environment is not reproduced exactly on this host",
        ),
        "release_platform": (
            comparison["platform_matches"],
            f"host platform {comparison['platform_family']!r} is not the pinned "
            f"release platform {pinned.get('release_platform')!r}",
        ),
        "release_machine": (
            comparison["machine_matches"],
            f"host architecture does not match the pinned release architecture {pinned.get('release_machine')!r}",
        ),
        "release_toolchain": (
            not comparison["tool_differences"],
            f"tool versions differ from the release pin: {sorted(comparison['tool_differences'])}",
        ),
        "release_postgres": (
            comparison["postgres_matches"],
            f"PostgreSQL server major does not match the release pin {pinned.get('postgres_major')!r}",
        ),
        "clean_checkout": (
            clean_checkout,
            "the source tree is not a clean Git checkout with recorded commit identity",
        ),
        "mandatory_matrix": (
            matrix_ok,
            f"mandatory CI checks are not all PASS: {matrix_blocking}",
        ),
        "fault_matrix": (
            fault_ok,
            f"fault-injection and recovery checks are not all PASS: {fault_blocking}",
        ),
        "production_controls": (
            production_ok,
            f"production control checks are not all PASS: {production_blocking}",
        ),
        "signed_evidence": (
            evidence_signature == "SIGNED",
            f"qualification evidence signature is {evidence_signature}, not SIGNED",
        ),
        "artifact_binding": (
            bool(release_artifact and release_artifact.get("sha256")),
            "no final release artifact digest is bound to this evidence",
        ),
        "signed_attestation": (
            attestation_signature == "SIGNED",
            f"release attestation signature is {attestation_signature}, not SIGNED",
        ),
    }

    requirements: dict[str, tuple[str, ...]] = {
        "DEV_PASS": ("tests_pass",),
        "QUALIFIED_LOCAL": ("tests_pass", "environment_exact"),
        "QUALIFIED_CI": (
            "tests_pass",
            "environment_exact",
            "release_platform",
            "release_machine",
            "release_toolchain",
            "release_postgres",
            "clean_checkout",
            "mandatory_matrix",
        ),
        "QUALIFIED_FAILURE": (
            "tests_pass",
            "environment_exact",
            "release_platform",
            "release_machine",
            "release_toolchain",
            "release_postgres",
            "clean_checkout",
            "mandatory_matrix",
            "fault_matrix",
        ),
        "PRODUCTION_CANDIDATE": (
            "tests_pass",
            "environment_exact",
            "release_platform",
            "release_machine",
            "release_toolchain",
            "release_postgres",
            "clean_checkout",
            "mandatory_matrix",
            "fault_matrix",
            "production_controls",
            "signed_evidence",
        ),
        "PRODUCTION_RELEASE": (
            "tests_pass",
            "environment_exact",
            "release_platform",
            "release_machine",
            "release_toolchain",
            "release_postgres",
            "clean_checkout",
            "mandatory_matrix",
            "fault_matrix",
            "production_controls",
            "signed_evidence",
            "signed_attestation",
            "artifact_binding",
        ),
    }

    tiers: dict[str, dict[str, Any]] = {}
    promotion = "DEV"
    for level in LEVELS:
        unmet = [predicates[key][1] for key in requirements[level] if not predicates[key][0]]
        tiers[level] = {"attainable": not unmet, "blocking_reasons": unmet}
        if not unmet:
            promotion = level

    blocking_reasons: list[str] = []
    for level in LEVELS:
        if level != promotion and not tiers[level]["attainable"]:
            blocking_reasons = tiers[level]["blocking_reasons"]
            break

    return {
        "promotion": promotion,
        "blocking_reasons": blocking_reasons,
        "tiers": tiers,
        "environment": comparison,
        "gates": gate_statuses(statuses),
        "signature_required_tiers": list(SIGNATURE_REQUIRED_TIERS),
        "signatures": {"evidence": evidence_signature, "attestation": attestation_signature},
    }
