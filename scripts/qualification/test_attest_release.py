# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the external release attestation.

The artifact is built after the evidence bundle exists, so the final digest has
to be bound from outside. These tests pin that direction and reject any
self-referential arrangement.
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys
import zipfile

import pytest

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import attest_release  # noqa: E402
import build_evidence_manifest as bundle  # noqa: E402


def make_evidence(root: pathlib.Path, qualification: pathlib.Path, promotion: str) -> None:
    """Write the qualification inputs the bundle builder reads."""

    qualification.mkdir(parents=True, exist_ok=True)
    (qualification / "source-manifest.json").write_text(
        json.dumps({"schema_version": 2, "root_digest": "a" * 64, "entries": {}})
    )
    (qualification / "source-tree.sha256").write_text("a" * 64 + "\n")
    (qualification / "environment-lock.json").write_text(
        json.dumps({"schema_version": 1, "environment_sha256": "b" * 64})
    )
    (qualification / "qualification.json").write_text(
        json.dumps(
            {
                "overall": "PASS",
                "qualification_status": "VALID",
                "qualification_level": promotion,
                "promotion": promotion,
                "checks": {"rust-tests": "PASS"},
            }
        )
    )
    (qualification / "rust-tests.txt").write_text("all good\n")


@pytest.fixture()
def release(tmp_path: pathlib.Path):
    """Return (qualification dir, artifact, attestation path)."""

    root = tmp_path / "repo"
    qualification = root / "qualification"
    make_evidence(root, qualification, "QUALIFIED_LOCAL")
    bundle.build(root, qualification)

    artifact = tmp_path / "artifacts" / "NEMO-0.9.1-rc.4-source.zip"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(artifact, "w") as handle:
        handle.writestr("NEMO-0.9.1-rc.4/Cargo.toml", "[workspace]\n")
    return qualification, artifact, artifact.with_name(artifact.name + ".attestation.json")


def test_attestation_binds_the_final_artifact(release) -> None:
    qualification, artifact, attestation_path = release
    attestation = attest_release.build_attestation(qualification, artifact, sign=False, require_signed=False)
    attestation_path.write_text(json.dumps(attestation))
    assert attestation["artifact"]["sha256"] == attest_release.digest_file(artifact)
    assert attest_release.verify(qualification, artifact, attestation_path) == []


def test_tampered_artifact_breaks_the_attestation(release) -> None:
    qualification, artifact, attestation_path = release
    attestation_path.write_text(
        json.dumps(attest_release.build_attestation(qualification, artifact, sign=False, require_signed=False))
    )
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    findings = attest_release.verify(qualification, artifact, attestation_path)
    assert any("different artifact digest" in finding for finding in findings)


def test_regenerated_evidence_breaks_the_attestation(release) -> None:
    qualification, artifact, attestation_path = release
    attestation_path.write_text(
        json.dumps(attest_release.build_attestation(qualification, artifact, sign=False, require_signed=False))
    )
    (qualification / "rust-tests.txt").write_text("changed\n")
    bundle.build(qualification.parent, qualification)
    findings = attest_release.verify(qualification, artifact, attestation_path)
    assert any("different evidence manifest digest" in finding for finding in findings)


def test_artifact_containing_evidence_is_rejected(tmp_path: pathlib.Path) -> None:
    qualification = tmp_path / "qualification"
    make_evidence(tmp_path, qualification, "QUALIFIED_LOCAL")
    bundle.build(tmp_path, qualification)

    artifact = tmp_path / "artifacts" / "self-referential.zip"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(artifact, "w") as handle:
        handle.writestr("NEMO-0.9.1-rc.4/Cargo.toml", "[workspace]\n")
        handle.writestr(
            "NEMO-0.9.1-rc.4/qualification/evidence-manifest.json",
            (qualification / bundle.MANIFEST_NAME).read_text(),
        )
    attestation_path = artifact.with_name(artifact.name + ".attestation.json")

    findings = attest_release.self_reference_findings(artifact, attestation_path)
    assert any("contains qualification evidence" in finding for finding in findings)


def test_attestation_inside_evidence_directory_is_rejected(release) -> None:
    qualification, artifact, _ = release
    findings = attest_release.self_reference_findings(artifact, qualification / "release.attestation.json")
    assert any("outside the evidence" in finding for finding in findings)


def test_production_promotion_requires_signed_evidence(tmp_path: pathlib.Path) -> None:
    qualification = tmp_path / "qualification"
    make_evidence(tmp_path, qualification, "PRODUCTION_CANDIDATE")
    bundle.build(tmp_path, qualification)

    artifact = tmp_path / "artifacts" / "release.zip"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(artifact, "w") as handle:
        handle.writestr("NEMO/Cargo.toml", "[workspace]\n")

    with pytest.raises(SystemExit, match="require signed evidence"):
        attest_release.build_attestation(qualification, artifact, sign=False, require_signed=True)


def test_unsigned_production_attestation_fails_verification(release) -> None:
    qualification, artifact, attestation_path = release
    attestation = attest_release.build_attestation(qualification, artifact, sign=False, require_signed=False)
    attestation["promotion"] = "PRODUCTION_RELEASE"
    attestation["signing"] = {"status": "UNSIGNED", "reason": "not requested"}
    attestation_path.write_text(json.dumps(attestation))
    findings = attest_release.verify(qualification, artifact, attestation_path)
    assert any("requires a signed release attestation" in finding for finding in findings)


def test_attestation_carries_a_dsse_in_toto_statement(release) -> None:
    qualification, artifact, _ = release
    attestation = attest_release.build_attestation(qualification, artifact, sign=False, require_signed=False)
    envelope = attestation["dsse"]
    assert envelope["payloadType"] == attest_release.DSSE_PAYLOAD_TYPE
    statement = json.loads(base64.b64decode(envelope["payload"]))
    assert statement["_type"] == attest_release.IN_TOTO_STATEMENT_TYPE
    assert statement["subject"][0]["digest"]["sha256"] == attestation["artifact"]["sha256"]
    assert statement["predicate"]["evidence_manifest_sha256"] == attestation["evidence"]["manifest_sha256"]


def test_attestation_binds_release_version_and_ci_identity(release, monkeypatch) -> None:
    """The external statement must identify what was released and by whom."""

    qualification, artifact, _ = release
    report_path = qualification / "qualification.json"
    report = json.loads(report_path.read_text())
    report["release_version"] = "0.9.1-rc.4"
    report_path.write_text(json.dumps(report))

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "NVIDIA/NeMo-Relay")
    monkeypatch.setenv("GITHUB_WORKFLOW", "release")
    monkeypatch.setenv("GITHUB_RUN_ID", "123456")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)

    attestation = attest_release.build_attestation(qualification, artifact, sign=False, require_signed=False)
    assert attestation["release_version"] == "0.9.1-rc.4"
    assert attestation["ci_identity"]["provider"] == "github-actions"
    assert attestation["ci_identity"]["repository"] == "NVIDIA/NeMo-Relay"
    statement = json.loads(base64.b64decode(attestation["dsse"]["payload"]))
    assert statement["predicate"]["release_version"] == "0.9.1-rc.4"
    assert statement["predicate"]["ci_identity"]["run_id"] == "123456"


def test_local_attestation_declares_a_local_identity(release, monkeypatch) -> None:
    qualification, artifact, _ = release
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    attestation = attest_release.build_attestation(qualification, artifact, sign=False, require_signed=False)
    assert attestation["ci_identity"] == {"provider": "local"}
