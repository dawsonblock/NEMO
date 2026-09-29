#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bind every qualification output into one verifiable internal evidence bundle.

Qualification results only mean something if they belong to the source that was
tested. This script walks the qualification directory, hashes every produced
artifact, and emits:

* ``evidence-manifest.json`` - the digest of each gate log, SBOM, environment
  record, migration manifest, and the source manifest itself;
* ``evidence-manifest.sha256`` - the digest of that manifest;
* ``evidence-manifest.dsse.json`` - a DSSE envelope carrying an in-toto
  statement, signed with cosign when CI identity is available.

This bundle intentionally does **not** bind the final release artifact. Binding
an artifact that contains the bundle would make the digest self-referential and
unsolvable, so the release order is strictly one-directional:

source manifest -> qualification -> internal evidence bundle -> final artifact
-> ``attest_release.py`` -> external release attestation

The external attestation lives beside the artifact, never inside it.

Signing never reads a secret from the repository. Keyless signing uses the CI
workload identity; ``NEMO_RELAY_COSIGN_KEY`` may point at an operator key for
local runs. When neither is available the envelope is written unsigned and the
manifest records ``UNSIGNED`` rather than implying a signature that does not
exist.
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
from datetime import datetime, timezone

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import qualification_levels  # noqa: E402  (local module)

SCHEMA = "nemo.qualification.evidence.v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://nemo-relay.nvidia.com/qualification/evidence/v1"

MANIFEST_NAME = "evidence-manifest.json"
MANIFEST_DIGEST_NAME = "evidence-manifest.sha256"
ENVELOPE_NAME = "evidence-manifest.dsse.json"
SIGNATURE_BUNDLE_NAME = "evidence-manifest.sigstore.json"

# Generated build products and their sidecars are not qualification evidence.
EXCLUDED_DIRECTORIES = ("coverage",)
# The signature transport files describe the bundle rather than being part of
# it; binding them inside the manifest they sign would be circular.
EXCLUDED_NAMES = frozenset({MANIFEST_NAME, MANIFEST_DIGEST_NAME, ENVELOPE_NAME, SIGNATURE_BUNDLE_NAME})


def digest_file(path: pathlib.Path) -> str:
    """Return the SHA-256 of a file's bytes."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect_artifacts(qualification_dir: pathlib.Path) -> list[dict]:
    """Hash every qualification artifact that is not a generated product."""

    artifacts: list[dict] = []
    for path in sorted(qualification_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(qualification_dir)
        if relative.name in EXCLUDED_NAMES:
            continue
        if relative.parts and relative.parts[0] in EXCLUDED_DIRECTORIES:
            continue
        artifacts.append(
            {
                "path": relative.as_posix(),
                "sha256": digest_file(path),
                "bytes": path.stat().st_size,
            }
        )
    return artifacts


def artifact_set_digest(artifacts: list[dict]) -> str:
    """Return the canonical digest over the artifact list."""

    canonical = "".join(f"{item['path']}\t{item['sha256']}\n" for item in artifacts)
    return hashlib.sha256(canonical.encode()).hexdigest()


def write_gate_records(
    qualification_dir: pathlib.Path,
    report: dict,
    source_tree_sha256: str | None,
    environment_sha256: str | None,
) -> list[str]:
    """Write one machine-readable record per E3 gate.

    Each record answers the same questions a reviewer asks: which gate, did it
    pass, against which source and environment, how long it took, and which
    artifacts back it. The records are written before the bundle is hashed, so
    they are themselves bound by the evidence manifest.
    """

    gates_dir = qualification_dir / "gates"
    gates_dir.mkdir(exist_ok=True)
    for stale in gates_dir.iterdir():
        if stale.is_file():
            stale.unlink()

    statuses = report.get("checks") or {}
    details = report.get("check_details") or {}
    gates = qualification_levels.gate_statuses(statuses)
    written: list[str] = []
    for gate_id, gate in sorted(gates.items()):
        checks = list(gate.get("satisfied_by") or [])
        evidence = [f"{name}.txt" for name in checks]
        durations = [int(details.get(name, {}).get("duration_ms") or 0) for name in checks]
        record = {
            "gate": gate_id,
            "title": gate["title"],
            "status": gate["status"],
            "source_tree_sha256": source_tree_sha256,
            "environment_sha256": environment_sha256,
            "duration_ms": max(durations, default=0),
            "checks": checks,
            "evidence": evidence,
        }
        path = gates_dir / f"{gate_id}.json"
        path.write_text(json.dumps(record, indent=2) + "\n")
        written.append(path.name)
    return written


def pre_authentication_encoding(payload_type: str, payload: bytes) -> bytes:
    """Return the DSSE PAE bytes for a payload and its type."""

    prefix = b"DSSEv1 "
    return b"".join(
        [
            prefix,
            str(len(payload_type)).encode(),
            b" ",
            payload_type.encode(),
            b" ",
            str(len(payload)).encode(),
            b" ",
            payload,
        ]
    )


def build_statement(manifest: dict) -> dict:
    """Return an in-toto statement describing the evidence bundle."""

    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [{"name": item["path"], "digest": {"sha256": item["sha256"]}} for item in manifest["artifacts"]],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "source_tree_sha256": manifest["source_tree_sha256"],
            "environment_sha256": manifest["environment_sha256"],
            "qualification_level": manifest["qualification_level"],
            "qualification_status": manifest["qualification_status"],
            "overall": manifest["overall"],
            "artifact_set_sha256": manifest["artifact_set_sha256"],
            "gates": manifest["gates"],
            "e3_gates": manifest["e3_gates"],
        },
    }


def sign_payload(payload: bytes, qualification_dir: pathlib.Path) -> dict:
    """Sign a DSSE payload with cosign when this host can produce a signature."""

    if shutil.which("cosign") is None:
        return {
            "status": "UNSIGNED",
            "reason": "cosign is not installed on this host",
            "signatures": [],
        }
    payload_path = qualification_dir / "evidence-manifest.dsse-payload.bin"
    bundle_path = qualification_dir / SIGNATURE_BUNDLE_NAME
    payload_path.write_bytes(payload)
    command = ["cosign", "sign-blob", "--yes", "--bundle", str(bundle_path), str(payload_path)]
    key = os.environ.get("NEMO_RELAY_COSIGN_KEY")
    if key:
        command.extend(["--key", key])
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    payload_path.unlink(missing_ok=True)
    if result.returncode != 0:
        detail = (result.stderr.strip().splitlines() or ["unknown error"])[-1]
        return {
            "status": "UNSIGNED",
            "reason": f"cosign signing failed: {detail}",
            "signatures": [],
        }
    return {
        "status": "SIGNED",
        "scheme": "dsse+in-toto",
        "signer": "cosign",
        "keyless": key is None,
        "key_source": "NEMO_RELAY_COSIGN_KEY" if key else "ambient-ci-identity",
        "bundle": bundle_path.name,
        "signatures": [{"sig": result.stdout.strip()}],
    }


def build(
    root: pathlib.Path,
    qualification_dir: pathlib.Path,
    sign: bool = False,
) -> dict:
    """Build and write the evidence bundle for one qualification run."""

    qualification_dir = qualification_dir.resolve()
    report = json.loads((qualification_dir / "qualification.json").read_text())
    manifest_record = json.loads((qualification_dir / "source-manifest.json").read_text())
    environment_lock = json.loads((qualification_dir / "environment-lock.json").read_text())

    statuses = report.get("checks") or {}
    gate_files = write_gate_records(
        qualification_dir,
        report,
        manifest_record.get("root_digest"),
        environment_lock.get("environment_sha256"),
    )
    artifacts = collect_artifacts(qualification_dir)
    evidence = {
        "schema": SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_tree_sha256": manifest_record.get("root_digest"),
        "environment_sha256": environment_lock.get("environment_sha256"),
        "qualification_level": report.get("qualification_level"),
        "qualification_status": report.get("qualification_status"),
        "promotion": report.get("promotion"),
        "overall": report.get("overall"),
        "gates": statuses,
        "e3_gates": qualification_levels.gate_statuses(statuses),
        "gate_records": gate_files,
        "artifacts": artifacts,
        "artifact_set_sha256": artifact_set_digest(artifacts),
        "release_artifact": None,
        "release_attestation": "external; see scripts/qualification/attest_release.py",
    }

    statement = build_statement(evidence)
    statement_bytes = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(statement_bytes).decode(),
        "signatures": [],
    }
    if sign:
        signing = sign_payload(pre_authentication_encoding(DSSE_PAYLOAD_TYPE, statement_bytes), qualification_dir)
        envelope["signatures"] = signing.pop("signatures", [])
        evidence["signing"] = signing
    else:
        evidence["signing"] = {"status": "UNSIGNED", "reason": "signing was not requested"}

    manifest_path = qualification_dir / MANIFEST_NAME
    manifest_path.write_text(json.dumps(evidence, indent=2) + "\n")
    manifest_digest = digest_file(manifest_path)
    (qualification_dir / MANIFEST_DIGEST_NAME).write_text(manifest_digest + "\n")
    (qualification_dir / ENVELOPE_NAME).write_text(json.dumps(envelope, indent=2) + "\n")

    return {
        "manifest": str(manifest_path),
        "sha256": manifest_digest,
        "artifacts": len(artifacts),
        "signing": evidence["signing"]["status"],
    }


def verify(root: pathlib.Path, qualification_dir: pathlib.Path) -> list[str]:
    """Return every discrepancy between the bundle and the artifacts on disk."""

    qualification_dir = qualification_dir.resolve()
    manifest_path = qualification_dir / MANIFEST_NAME
    digest_path = qualification_dir / MANIFEST_DIGEST_NAME
    if not manifest_path.is_file() or not digest_path.is_file():
        return [f"missing evidence manifest: {manifest_path}"]

    recorded_digest = digest_path.read_text().strip()
    actual_digest = digest_file(manifest_path)
    findings: list[str] = []
    if recorded_digest != actual_digest:
        findings.append(f"evidence manifest digest differs: expected {recorded_digest}, got {actual_digest}")

    evidence = json.loads(manifest_path.read_text())
    if evidence.get("schema") != SCHEMA:
        findings.append(f"unexpected evidence schema: {evidence.get('schema')!r}")

    actual_artifacts = {item["path"]: item for item in collect_artifacts(qualification_dir)}
    recorded_artifacts = {item["path"]: item for item in evidence.get("artifacts", [])}
    for path in sorted(set(recorded_artifacts) - set(actual_artifacts)):
        findings.append(f"recorded evidence artifact is missing: {path}")
    for path in sorted(set(actual_artifacts) - set(recorded_artifacts)):
        findings.append(f"evidence artifact is not bound by the manifest: {path}")
    for path in sorted(set(recorded_artifacts) & set(actual_artifacts)):
        if recorded_artifacts[path]["sha256"] != actual_artifacts[path]["sha256"]:
            findings.append(f"evidence artifact digest differs: {path}")

    reconstructed = artifact_set_digest(list(actual_artifacts.values()))
    if reconstructed != evidence.get("artifact_set_sha256"):
        findings.append("artifact set digest differs from the recorded evidence")

    source_manifest = qualification_dir / "source-manifest.json"
    if source_manifest.is_file():
        recorded_source = json.loads(source_manifest.read_text()).get("root_digest")
        if recorded_source != evidence.get("source_tree_sha256"):
            findings.append("evidence manifest is bound to a different source tree digest")
    findings.extend(verify_signature(qualification_dir, evidence))
    return findings


def verify_signature(qualification_dir: pathlib.Path, evidence: dict) -> list[str]:
    """Check the DSSE signature when the run claims one."""

    if evidence.get("signing", {}).get("status") != "SIGNED":
        return []
    if shutil.which("cosign") is None:
        return ["evidence is recorded as SIGNED but cosign is unavailable to verify it"]
    envelope_path = qualification_dir / ENVELOPE_NAME
    bundle_path = qualification_dir / SIGNATURE_BUNDLE_NAME
    if not envelope_path.is_file() or not bundle_path.is_file():
        return ["evidence is recorded as SIGNED but the envelope or bundle is missing"]
    envelope = json.loads(envelope_path.read_text())
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        return [f"unexpected DSSE payload type: {envelope.get('payloadType')!r}"]
    statement_bytes = base64.b64decode(envelope["payload"])
    expected_bytes = json.dumps(build_statement(evidence), sort_keys=True, separators=(",", ":")).encode()
    findings: list[str] = []
    if statement_bytes != expected_bytes:
        findings.append("DSSE payload does not match the canonical evidence statement")
    payload_path = qualification_dir / "evidence-manifest.dsse-payload.bin"
    payload_path.write_bytes(pre_authentication_encoding(envelope["payloadType"], statement_bytes))
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
        findings.append(f"evidence signature verification failed: {detail}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=None)
    parser.add_argument("--qualification-dir", type=pathlib.Path, default=None)
    parser.add_argument("--sign", action="store_true", help="sign the DSSE envelope with cosign")
    parser.add_argument("--verify", action="store_true", help="verify an existing evidence bundle")
    args = parser.parse_args()

    root = (args.root or SCRIPT_DIR.parents[1]).resolve()
    qualification_dir = args.qualification_dir or root / "qualification"

    if args.verify:
        findings = verify(root, qualification_dir)
        if findings:
            print(f"EVIDENCE FAIL\n{len(findings)} discrepancy(s)")
            for finding in findings:
                print(f"- {finding}")
            return 1
        print("EVIDENCE PASS")
        return 0

    result = build(root, qualification_dir, args.sign)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
