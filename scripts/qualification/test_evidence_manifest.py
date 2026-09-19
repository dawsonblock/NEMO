# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests that the evidence bundle binds every qualification output."""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_evidence_manifest as bundle  # noqa: E402


@pytest.fixture()
def evidence(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """Create a qualification directory with a built evidence bundle."""

    root = tmp_path / "repo"
    qualification = root / "qualification"
    qualification.mkdir(parents=True)
    (qualification / "source-manifest.json").write_text(
        json.dumps({"schema_version": 2, "root_digest": "a" * 64, "entries": {}})
    )
    (qualification / "source-tree.sha256").write_text("a" * 64 + "\n")
    (qualification / "environment-lock.json").write_text(
        json.dumps({"schema_version": 1, "environment_sha256": "b" * 64})
    )
    (qualification / "environment.json").write_text(json.dumps({"platform": "macOS"}))
    (qualification / "qualification.json").write_text(
        json.dumps(
            {
                "overall": "PASS",
                "qualification_status": "VALID",
                "qualification_level": "E3_LOCAL",
                "promotion": "QUALIFIED_LOCAL",
                "checks": {"rust-tests": "PASS", "postgres-effect-store": "PASS"},
            }
        )
    )
    (qualification / "rust-tests.txt").write_text("all good\n")
    (qualification / "postgres-effect-store.txt").write_text("all good\n")
    (qualification / "sbom.spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3"}))
    bundle.build(root, qualification)
    return root, qualification


def test_bundle_verifies_clean(evidence) -> None:
    root, qualification = evidence
    assert bundle.verify(root, qualification) == []


def test_manifest_records_source_and_environment_identity(evidence) -> None:
    _, qualification = evidence
    manifest = json.loads((qualification / bundle.MANIFEST_NAME).read_text())
    assert manifest["schema"] == bundle.SCHEMA
    assert manifest["source_tree_sha256"] == "a" * 64
    assert manifest["environment_sha256"] == "b" * 64
    assert manifest["qualification_level"] == "E3_LOCAL"
    assert set(manifest["e3_gates"]) == set(__import__("qualification_levels").E3_GATES)


def test_manifest_binds_every_gate_log(evidence) -> None:
    _, qualification = evidence
    manifest = json.loads((qualification / bundle.MANIFEST_NAME).read_text())
    paths = {item["path"] for item in manifest["artifacts"]}
    assert {"rust-tests.txt", "postgres-effect-store.txt", "sbom.spdx.json"} <= paths
    assert "source-manifest.json" in paths
    assert "environment-lock.json" in paths


def test_every_gate_emits_a_machine_readable_record(evidence) -> None:
    """Gates must be individually consumable, not only a summary map."""

    _, qualification = evidence
    manifest = json.loads((qualification / bundle.MANIFEST_NAME).read_text())
    assert manifest["gate_records"]
    records = sorted((qualification / "gates").glob("E3-*.json"))
    assert records, "no gate records were written"

    for path in records:
        record = json.loads(path.read_text())
        assert set(record) >= {
            "gate",
            "title",
            "status",
            "source_tree_sha256",
            "environment_sha256",
            "duration_ms",
            "evidence",
        }
        assert record["source_tree_sha256"] == "a" * 64
        assert record["environment_sha256"] == "b" * 64
        assert isinstance(record["duration_ms"], int)

    concrete = json.loads((qualification / "gates" / "E3-013.json").read_text())
    assert concrete["gate"] == "E3-013"
    assert concrete["status"] == "PASS"
    assert "postgres-effect-store.txt" in concrete["evidence"]


def test_gate_records_are_bound_by_the_bundle(evidence) -> None:
    root, qualification = evidence
    gate_file = qualification / "gates" / "E3-013.json"
    record = json.loads(gate_file.read_text())
    record["status"] = "PASS"
    record["duration_ms"] = 999_999
    gate_file.write_text(json.dumps(record))
    findings = bundle.verify(root, qualification)
    assert any("E3-013.json" in finding for finding in findings)


def test_tampered_gate_log_is_detected(evidence) -> None:
    root, qualification = evidence
    (qualification / "rust-tests.txt").write_text("all good\nactually not\n")
    findings = bundle.verify(root, qualification)
    assert any("rust-tests.txt" in finding for finding in findings)
    assert any("artifact set digest differs" in finding for finding in findings)


def test_tampered_qualification_result_is_detected(evidence) -> None:
    root, qualification = evidence
    report = json.loads((qualification / "qualification.json").read_text())
    report["overall"] = "FAIL"
    (qualification / "qualification.json").write_text(json.dumps(report))
    findings = bundle.verify(root, qualification)
    assert any("qualification.json" in finding for finding in findings)


def test_tampered_environment_record_is_detected(evidence) -> None:
    root, qualification = evidence
    (qualification / "environment.json").write_text(json.dumps({"platform": "Linux"}))
    findings = bundle.verify(root, qualification)
    assert any("environment.json" in finding for finding in findings)


def test_unbound_artifact_is_detected(evidence) -> None:
    root, qualification = evidence
    (qualification / "extra-result.txt").write_text("smuggled\n")
    findings = bundle.verify(root, qualification)
    assert any("not bound by the manifest" in finding for finding in findings)


def test_missing_artifact_is_detected(evidence) -> None:
    root, qualification = evidence
    (qualification / "sbom.spdx.json").unlink()
    findings = bundle.verify(root, qualification)
    assert any("recorded evidence artifact is missing" in finding for finding in findings)


def test_tampered_manifest_digest_is_detected(evidence) -> None:
    root, qualification = evidence
    (qualification / bundle.MANIFEST_DIGEST_NAME).write_text("0" * 64 + "\n")
    findings = bundle.verify(root, qualification)
    assert any("evidence manifest digest differs" in finding for finding in findings)


def test_evidence_cannot_be_rebound_to_another_source_tree(evidence) -> None:
    root, qualification = evidence
    manifest_path = qualification / bundle.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest["source_tree_sha256"] = "c" * 64
    manifest_path.write_text(json.dumps(manifest))
    (qualification / bundle.MANIFEST_DIGEST_NAME).write_text(bundle.digest_file(manifest_path) + "\n")
    findings = bundle.verify(root, qualification)
    assert any("different source tree digest" in finding for finding in findings)


def test_internal_bundle_never_binds_the_release_artifact(evidence) -> None:
    """The internal bundle must stay free of the final artifact digest.

    Binding an artifact that could contain the bundle would make the digest
    self-referential. The release attestation is external for that reason.
    """

    _, qualification = evidence
    manifest = json.loads((qualification / bundle.MANIFEST_NAME).read_text())
    assert manifest["release_artifact"] is None
    assert "external" in manifest["release_attestation"]
    statement = json.loads(
        __import__("base64").b64decode(json.loads((qualification / bundle.ENVELOPE_NAME).read_text())["payload"])
    )
    assert "release_artifact" not in statement["predicate"]


def test_dsse_envelope_wraps_an_in_toto_statement(evidence) -> None:
    root, qualification = evidence
    envelope = json.loads((qualification / bundle.ENVELOPE_NAME).read_text())
    assert envelope["payloadType"] == bundle.DSSE_PAYLOAD_TYPE
    import base64

    statement = json.loads(base64.b64decode(envelope["payload"]))
    assert statement["_type"] == bundle.IN_TOTO_STATEMENT_TYPE
    assert statement["predicateType"] == bundle.PREDICATE_TYPE
    subjects = {item["name"] for item in statement["subject"]}
    assert "rust-tests.txt" in subjects


def test_unsigned_evidence_is_labelled_honestly(evidence) -> None:
    _, qualification = evidence
    manifest = json.loads((qualification / bundle.MANIFEST_NAME).read_text())
    assert manifest["signing"]["status"] == "UNSIGNED"


def test_pae_encoding_matches_the_dsse_specification() -> None:
    payload_type = "application/vnd.in-toto+json"
    payload = b"{}"
    assert bundle.pre_authentication_encoding(payload_type, payload) == (b"DSSEv1 28 application/vnd.in-toto+json 2 {}")
