#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bind the final release artifact to its qualification evidence, externally.

The internal evidence bundle describes the source tree and the checks that ran
against it. The final distributed artifact is built *after* that bundle exists,
so its digest cannot live inside the bundle: if the bundle were also shipped
inside the artifact, ``sha256(artifact)`` would depend on a file that depends on
``sha256(artifact)``, which has no stable solution.

The release order is therefore strictly one-directional and the last step is
external:

.. code-block:: text

    source manifest
        -> qualification checks
        -> internal evidence bundle (qualification/evidence-manifest.json)
        -> final artifact (ZIP)
        -> SHA-256(final artifact)
        -> external release attestation   <- this script
        -> signature

The attestation is written *beside* the artifact by default, and this script
refuses to attest an artifact that already contains the evidence bundle or the
attestation itself.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_evidence_manifest as bundle  # noqa: E402  (local module)

SCHEMA = "nemo.release.attestation.v1"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://nemo-relay.nvidia.com/release/attestation/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Shipped inside the artifact, these would create the self-reference this
# module exists to prevent.
FORBIDDEN_MEMBERS = (
    "qualification/evidence-manifest.json",
    "qualification/evidence-manifest.sha256",
    "qualification/evidence-manifest.dsse.json",
)

DEFAULT_ATTESTATION_SUFFIX = ".attestation.json"
DEFAULT_SIGNATURE_SUFFIX = ".attestation.sigstore.json"


def digest_file(path: pathlib.Path) -> str:
    """Return the SHA-256 of a file's bytes."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def evidence_manifest_digest(qualification_dir: pathlib.Path) -> str:
    """Return the recorded digest of the internal evidence manifest."""

    digest_path = qualification_dir / bundle.MANIFEST_DIGEST_NAME
    if not digest_path.is_file():
        raise SystemExit(f"missing evidence manifest digest: {digest_path}")
    return digest_path.read_text().strip()


def ci_identity() -> dict:
    """Describe the CI identity that produced the release, when there is one."""

    if os.environ.get("GITHUB_ACTIONS") != "true":
        return {"provider": "local"}
    return {
        "provider": "github-actions",
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "workflow": os.environ.get("GITHUB_WORKFLOW"),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "commit": os.environ.get("GITHUB_SHA"),
        "ref": os.environ.get("GITHUB_REF"),
    }


def artifact_members(artifact: pathlib.Path) -> list[str]:
    """Return the member names of a ZIP artifact, or an empty list."""

    if not zipfile.is_zipfile(artifact):
        return []
    with zipfile.ZipFile(artifact) as handle:
        return handle.namelist()


def self_reference_findings(artifact: pathlib.Path, attestation: pathlib.Path) -> list[str]:
    """Return reasons the attestation would be self-referential."""

    findings: list[str] = []
    for member in artifact_members(artifact):
        stripped = member.rstrip("/")
        if member.startswith("NEMO-") and "/" in member:
            stripped = member.split("/", 1)[1].rstrip("/")
        if stripped in FORBIDDEN_MEMBERS or stripped == "qualification":
            findings.append(
                f"release artifact contains qualification evidence ({member}); "
                "the evidence bundle cannot be bound into an artifact that "
                "contains it"
            )
            break
    if attestation.resolve().parent.name == "qualification":
        findings.append(
            "release attestation would be written into the qualification evidence "
            "directory; the external attestation must live outside the evidence it binds"
        )
    return findings


def build_attestation(
    qualification_dir: pathlib.Path,
    artifact: pathlib.Path,
    *,
    sign: bool,
    require_signed: bool,
) -> dict:
    """Return the external attestation document for one artifact."""

    qualification_dir = qualification_dir.resolve()
    artifact = artifact.resolve()
    evidence = json.loads((qualification_dir / bundle.MANIFEST_NAME).read_text())
    evidence_digest = evidence_manifest_digest(qualification_dir)

    signing_status = evidence.get("signing", {}).get("status")
    promotion = evidence.get("promotion")
    production = isinstance(promotion, str) and promotion.startswith("PRODUCTION")
    if require_signed and production and signing_status != "SIGNED":
        raise SystemExit(
            f"refusing to attest {artifact.name}: promotion is {promotion} but the "
            f"evidence bundle is {signing_status}. PRODUCTION_CANDIDATE and "
            "PRODUCTION_RELEASE require signed evidence."
        )

    attestation = {
        "schema": SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "release_version": json.loads((qualification_dir / "qualification.json").read_text()).get("release_version"),
        "ci_identity": ci_identity(),
        "artifact": {
            "name": artifact.name,
            "sha256": digest_file(artifact),
            "bytes": artifact.stat().st_size,
        },
        "evidence": {
            "manifest": bundle.MANIFEST_NAME,
            "manifest_sha256": evidence_digest,
            "artifact_set_sha256": evidence.get("artifact_set_sha256"),
        },
        "source_tree_sha256": evidence.get("source_tree_sha256"),
        "environment_sha256": evidence.get("environment_sha256"),
        "qualification_level": evidence.get("qualification_level"),
        "promotion": promotion,
        "overall": evidence.get("overall"),
        "gates": evidence.get("gates"),
        "e3_gates": evidence.get("e3_gates"),
        "evidence_signing": signing_status,
        "signing": {"status": "UNSIGNED", "reason": "signing was not requested"},
    }

    statement = {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": artifact.name,
                "digest": {"sha256": attestation["artifact"]["sha256"]},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "source_tree_sha256": attestation["source_tree_sha256"],
            "environment_sha256": attestation["environment_sha256"],
            "evidence_manifest_sha256": evidence_digest,
            "artifact_set_sha256": attestation["evidence"]["artifact_set_sha256"],
            "qualification_level": attestation["qualification_level"],
            "promotion": promotion,
            "release_version": attestation["release_version"],
            "ci_identity": attestation["ci_identity"],
            "evidence_signing": signing_status,
        },
    }
    statement_bytes = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(statement_bytes).decode(),
        "signatures": [],
    }
    if sign:
        signing = sign_payload(
            bundle.pre_authentication_encoding(DSSE_PAYLOAD_TYPE, statement_bytes),
            artifact.parent,
            artifact.name + DEFAULT_SIGNATURE_SUFFIX,
        )
        envelope["signatures"] = signing.pop("signatures", [])
        attestation["signing"] = signing
    attestation["dsse"] = envelope
    return attestation


def sign_payload(payload: bytes, directory: pathlib.Path, bundle_name: str) -> dict:
    """Sign an attestation payload with cosign, or report why it is unsigned."""

    if shutil.which("cosign") is None:
        return {"status": "UNSIGNED", "reason": "cosign is not installed on this host", "signatures": []}
    payload_path = directory / (bundle_name + ".payload")
    bundle_path = directory / bundle_name
    payload_path.write_bytes(payload)
    command = ["cosign", "sign-blob", "--yes", "--bundle", str(bundle_path), str(payload_path)]
    key = os.environ.get("NEMO_RELAY_COSIGN_KEY")
    if key:
        command.extend(["--key", key])
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    payload_path.unlink(missing_ok=True)
    if result.returncode != 0:
        detail = (result.stderr.strip().splitlines() or ["unknown error"])[-1]
        return {"status": "UNSIGNED", "reason": f"cosign signing failed: {detail}", "signatures": []}
    return {
        "status": "SIGNED",
        "scheme": "dsse+in-toto",
        "signer": "cosign",
        "keyless": key is None,
        "bundle": bundle_name,
        "signatures": [{"sig": result.stdout.strip()}],
    }


def verify(
    qualification_dir: pathlib.Path,
    artifact: pathlib.Path,
    attestation_path: pathlib.Path,
) -> list[str]:
    """Return every reason the attestation does not bind the artifact."""

    qualification_dir = qualification_dir.resolve()
    artifact = artifact.resolve()
    attestation_path = attestation_path.resolve()
    findings: list[str] = []
    if not attestation_path.is_file():
        return [f"missing release attestation: {attestation_path}"]
    if not artifact.is_file():
        return [f"missing release artifact: {artifact}"]

    attestation = json.loads(attestation_path.read_text())
    if attestation.get("schema") != SCHEMA:
        findings.append(f"unexpected release attestation schema: {attestation.get('schema')!r}")

    actual_artifact = digest_file(artifact)
    if attestation.get("artifact", {}).get("sha256") != actual_artifact:
        findings.append("release attestation is bound to a different artifact digest")

    findings.extend(bundle.verify(qualification_dir.parent, qualification_dir))
    findings.extend(self_reference_findings(artifact, attestation_path))

    is_production = attestation.get("promotion", "").startswith("PRODUCTION")
    signing = attestation.get("signing", {})

    if is_production and signing.get("status") != "SIGNED":
        findings.append(f"promotion {attestation.get('promotion')} requires a signed release attestation")

    if signing.get("status") == "SIGNED":
        findings.extend(verify_attestation_signature(artifact, attestation, attestation_path))
    return findings


def verify_attestation_signature(
    artifact: pathlib.Path,
    attestation: dict,
    attestation_path: pathlib.Path,
) -> list[str]:
    """Cryptographically verify the signed DSSE envelope and cosign bundle."""

    findings: list[str] = []
    if shutil.which("cosign") is None:
        return ["attestation is recorded as SIGNED but cosign is unavailable to verify it"]

    envelope = attestation.get("dsse") or {}
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        findings.append(f"unexpected attestation DSSE payload type: {envelope.get('payloadType')!r}")
        return findings

    statement_bytes = base64.b64decode(envelope.get("payload", ""))
    expected_statement = {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": artifact.name,
                "digest": {"sha256": attestation.get("artifact", {}).get("sha256", "")},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "source_tree_sha256": attestation.get("source_tree_sha256"),
            "environment_sha256": attestation.get("environment_sha256"),
            "evidence_manifest_sha256": attestation.get("evidence", {}).get("manifest_sha256"),
            "artifact_set_sha256": attestation.get("evidence", {}).get("artifact_set_sha256"),
            "qualification_level": attestation.get("qualification_level"),
            "promotion": attestation.get("promotion"),
            "release_version": attestation.get("release_version"),
            "ci_identity": attestation.get("ci_identity"),
            "evidence_signing": attestation.get("evidence_signing"),
        },
    }
    expected_bytes = json.dumps(expected_statement, sort_keys=True, separators=(",", ":")).encode()
    if statement_bytes != expected_bytes:
        findings.append("attestation DSSE payload does not match the canonical statement for this artifact")

    bundle_name = attestation.get("signing", {}).get("bundle", "")
    bundle_path = attestation_path.parent / bundle_name if bundle_name else None
    if not bundle_path or not bundle_path.is_file():
        findings.append("attestation is recorded as SIGNED but the signature bundle is missing")
        return findings

    payload_path = attestation_path.parent / (bundle_name + ".verify-payload")
    payload_path.write_bytes(bundle.pre_authentication_encoding(DSSE_PAYLOAD_TYPE, statement_bytes))
    try:
        result = subprocess.run(
            ["cosign", "verify-blob", "--bundle", str(bundle_path), str(payload_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        payload_path.unlink(missing_ok=True)
    if result.returncode != 0:
        detail = (result.stderr.strip().splitlines() or ["unknown error"])[-1]
        findings.append(f"attestation signature verification failed: {detail}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification-dir", type=pathlib.Path, required=True)
    parser.add_argument("--release-artifact", type=pathlib.Path, required=True)
    parser.add_argument("--attestation", type=pathlib.Path, default=None)
    parser.add_argument("--sign", action="store_true")
    parser.add_argument(
        "--require-signed",
        action="store_true",
        help="refuse to attest a PRODUCTION_* promotion without signed evidence",
    )
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    attestation_path = args.attestation or args.release_artifact.with_name(
        args.release_artifact.name + DEFAULT_ATTESTATION_SUFFIX
    )

    if args.verify:
        findings = verify(args.qualification_dir, args.release_artifact, attestation_path)
        if findings:
            print(f"RELEASE ATTESTATION FAIL\n{len(findings)} discrepancy(s)")
            for finding in findings:
                print(f"- {finding}")
            return 1
        print("RELEASE ATTESTATION PASS")
        return 0

    conflicts = self_reference_findings(args.release_artifact, attestation_path)
    if conflicts:
        for conflict in conflicts:
            print(f"- {conflict}", file=sys.stderr)
        return 1

    attestation = build_attestation(
        args.qualification_dir,
        args.release_artifact,
        sign=args.sign,
        require_signed=args.require_signed,
    )
    attestation_path.parent.mkdir(parents=True, exist_ok=True)
    attestation_path.write_text(json.dumps(attestation, indent=2) + "\n")
    print(
        json.dumps(
            {
                "attestation": str(attestation_path),
                "artifact_sha256": attestation["artifact"]["sha256"],
                "signing": attestation["signing"]["status"],
                "promotion": attestation["promotion"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
