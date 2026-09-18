<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# NeMo Relay qualification artifacts

This directory holds the evidence `scripts/qualification/run.sh` generates.
Results use `PASS`, `FAIL`, `INCONCLUSIVE`, `NOT_RUN`, and `NOT_APPLICABLE`;
missing tools never become an implied pass.

**This directory does not ship a qualification certificate by default.** A tree
carries a certificate only when the evidence in it was produced for that exact
tree. Evidence from another source tree must not be copied here - the verifier
rejects it, and shipping it is the defect that created the E3 cycle. See
[`docs/e3-baseline.md`](../docs/e3-baseline.md) for the current baseline.

## Running qualification

Run the full pinned matrix inside `.devcontainer`:

```bash
scripts/qualification/run.sh
```

Use `scripts/qualification/run.sh quick` only for a local diagnostic pass and
`scripts/qualification/run.sh manifest` when only provenance capture is
possible; both are not release certificates. Use
`scripts/qualification/run.sh provenance` only after a valid full run, to bind
archive metadata to that exact unchanged source tree without overwriting the
recorded check logs. A provenance refresh inherits the promotion of the run it
binds; it never re-derives a tier from the refreshing host.

## What a run produces

| Artifact | Purpose |
| --- | --- |
| `source-manifest.json` | Typed entry set: path, kind, mode, content hash, symlink target |
| `source-tree.sha256` | Canonical digest over that entry set |
| `environment.json`, `environment-lock.json` | Toolchain and platform that ran the checks |
| `dependency-lock-digests.json` | Cargo, npm, and uv lockfile digests |
| `<gate>.txt` | Raw output of each gate |
| `sbom.spdx.json` | SPDX 2.3 inventory |
| `qualification.json` | Check results, promotion tier, and per-tier blocking reasons |
| `evidence-manifest.json` | Digest of every artifact above |
| `evidence-manifest.dsse.json` | DSSE envelope carrying an in-toto statement |

The live-database gates are separate checks with separate evidence, so a
correct migration ledger cannot stand in for a structurally correct schema:

| Gate | Check | Qualifies |
| --- | --- | --- |
| E3-011 | `migration-integrity` | Concurrent migrators, all 8 migration crash points, 50-iteration contention stress, retry after rollback, rewritten checksums, unknown versions, damaged history, and runtime-role separation |
| E3-012 | `physical-schema-verification` | Catalogue fingerprint plus destructive drift that leaves the ledger untouched |
| E3-013 | `postgres-effect-store` | Store conformance |
| E3-014 | `postgres-concurrency` | Contention behaviour |
| E3-015 | `postgres-restart` | Persistence across a fresh pool and store |
| E3-039 | `db-failure-boundaries` | The four database-failure boundaries around external dispatch, including `UNKNOWN` semantics |

Each gate also emits `gates/E3-0NN.json` recording its status, the source and
environment digests it ran against, its duration, and the artifacts that back
it. Those records are hashed into the evidence bundle like any other artifact.
The `physical-schema-verification` gate additionally emits
`expected-schema.json` and `expected-schema.sha256`: the canonical, reviewable
description of a freshly migrated database under the `nemo.effect-store.pg.v1`
model.

## Promotion tiers

`qualification.json` reports the highest tier whose evidence is present, with the
reasons each higher tier was withheld:

`DEV_PASS` -> `QUALIFIED_LOCAL` -> `QUALIFIED_CI` -> `QUALIFIED_FAILURE` ->
`PRODUCTION_CANDIDATE` -> `PRODUCTION_RELEASE`

Only the pinned Linux release environment can reach `QUALIFIED_CI` or above. A
macOS workstation is limited to `QUALIFIED_LOCAL`, and a run whose recorded
environment is not reproduced exactly on the verifying host is limited to
`DEV_PASS`.

## Verifying

```bash
just test-qualification-scripts   # mandatory provenance, tier, and bundle tests
just qualification-digest         # canonical digest of the current tree
just provenance-check             # manifest vs. this filesystem, exact sets
just evidence-verify              # every digest bound into the evidence bundle
```

`source-manifest.json` enumerates the filesystem directly and applies narrow
recorded exclusions: build and dependency directories, the generated
`release/artifacts` prefix, and the repository's own `.gitignore` rules. The
ignore rules are evaluated from the tree rather than delegated to `git ls-files`
so a checkout and an extracted archive enumerate identically. Symlinks are
recorded as symlinks with their targets, and file mode bits are part of the
digest.

Ignore semantics are part of the contract, not an implementation detail. Every
`.gitignore` that decided the entry set is authoritative, is itself a manifested
source entry, and is listed with its digest under
`policy.authoritative_ignore_files`. The manifest records both
`enumeration_policy_version` and `policy.gitignore_policy_version`; the verifier
refuses a manifest captured under different semantics rather than reinterpreting
it. Patterns outside the supported subset - POSIX bracket expressions,
consecutive asterisks that are not a whole path segment, and negations that
cannot re-include anything - are rejected instead of approximated.

The source manifest is verified before and after the checks. Any added, removed,
retyped, re-moded, re-contented, or re-targeted entry invalidates the run.

## Signing and release attestation

Set `NEMO_RELAY_EVIDENCE_SIGN=1` to request a cosign signature over the DSSE
envelope using the ambient CI workload identity. Never store a signing key in
this repository: an unsigned bundle is recorded as `UNSIGNED`, and a run whose
claimed signature state does not match the bundle it produced fails.

`PRODUCTION_CANDIDATE` and `PRODUCTION_RELEASE` require a verified signature.
An unsigned run can reach `QUALIFIED_CI` during development; it can never reach
a distributable tier.

The final artifact digest is bound from outside the evidence directory, because
an artifact that contained the bundle naming its own digest would have no stable
solution. The release order is one-directional:

```text
source manifest -> qualification -> internal evidence bundle
  -> final artifact -> SHA-256(final artifact)
  -> external release attestation -> signature
```

```bash
just attest-release release/artifacts/NEMO-0.9.1-rc.4-source.zip
just verify-release-attestation release/artifacts/NEMO-0.9.1-rc.4-source.zip
```

`attest-release` refuses to write an attestation inside the evidence directory,
refuses to attest an artifact that already contains the evidence bundle, and
with `--require-signed` refuses to attest a `PRODUCTION_*` promotion whose
evidence is unsigned.
