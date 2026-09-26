<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Baseline: NEMO 0.10 minimal trusted kernel

## Hardening baseline — 2026-09-19

This is the *NEMO hardening baseline*: the revision the hardening program starts
from, recorded so later milestones cannot obscure which guarantees already
worked. It is a new record, not a replacement — the earlier capture below stays
in place as evidence.

The four guarantees this revision already has, and which the program must not
regress:

- plugin-isolation increment 2 foundation — the kernel owns the execution seam
  and does not construct a backend
- positive TLS production composition — a verified transport composes a
  production kernel, and a test-only transport is refused
- attestation↔evidence binding fixed — an attestation stops verifying once the
  evidence manifest underneath it is regenerated
- trusted EffectStore deadline wired — terminal finalization is bounded by the
  action budget, and an expired budget becomes `UNKNOWN`

| Field | Value |
|---|---|
| Branch | `feat/native-plugin-isolation` |
| Git revision | `c7c492b674ae58fc15bc0e26d7feefc39b46d21e` |
| Workspace version | `0.9.1-rc.4` |
| Plugin protocol revision | `1` |
| Native plugin ABI revision | `4` |
| `Cargo.lock` | `fcd34ce5b38f49ebd173385279472ae9c7083778b091fbf01882d06bd4b43e9c` |

Toolchains at this revision: `rustc`/`cargo` 1.96.1, `node` v24.16.0.

| Surface | Crates | Lines | `unsafe` |
|---|---|---|---|
| Invariant-enforcing (logical TCB) | 5 | 85,737 | 299 |
| Effective in-process (logical plus additional) | 12 | 114,801 | 617 |
| Plugin host | 1 | 428 | 1 |

`kernel-process unsafe tokens` is **617**, the number the plugin-isolation
milestone exists to reduce. The plugin-host figure is reported separately and
deliberately not counted against the kernel: corruption in that process must not
be able to corrupt the kernel, which is the point of moving the loader there.

Machine-readable detail is produced by `just tcb-baseline` into the git-ignored
`reports/`; the companion record for this revision is
`qualification/baselines/2026-09-19-hardening/`.

The remainder of this file records the earlier 0.10 capture.

Stage 1 of the program is a freeze. This records what the tree measured before
any code moved, so later milestones can prove they changed only what they
intended and can detect movement they did not intend.

The measurements are produced by tooling, not transcribed by hand:

```bash
just tcb-baseline      # writes reports/*.json
just tcb-report        # prints and enforces the trusted-surface budget
```

`just tcb-baseline` snapshots the tree it is run against; it does not recreate
the frozen baseline. The immutable anchor is the revision below, and the reports
are a reproducible measurement of whatever revision you point the tool at. Run
it on a checkout of the frozen revision to compare against the original, and on
the working tree to see the current state.

`reports/` is generated and git-ignored. Keeping it out of the tree is
deliberate: the source-tree digest is computed over the tree, so a checked-in
report would change the digest of the tree it describes, and the second run
would not match the first.

## Revision

| Field | Value |
|---|---|
| Branch | `feat/effect-store-runtime-qualification` |
| Git revision | `933538a6e956eca27594b9142c1675138da8d5e5` |
| Git tree | `9c1977a7b4bb3570694bbd833468e793c562a857` |
| Workspace version | `0.9.1-rc.4` |

The Git revision and tree hash are the frozen identity: they name the state
before any of this tooling existed. Later milestones compare against that
revision, not against a working tree that happens to be dirty at capture time.

## Digests

| Artifact | Digest |
|---|---|
| Git tree at `933538a` | `9c1977a7b4bb3570694bbd833468e793c562a857` |
| `Cargo.lock` | `07d150c01c141ad8e881962e514d6e8ae6d61abb137598f413a7229bc940e30a` |
| `uv.lock` | `7951ad08421af208c71ef491584c4ca40e5c35010ba75d969b7ca736ba4879b4` |
| `package-lock.json` | `e53a090f5b553ccef443b257a38a06610173276695e319159bdd17adb4d76125` |

The source-tree digest is produced by `scripts/qualification/source_tree.py`
under the `nemo-source-tree-v1` enumeration policy, which includes file modes,
symlink targets, and content hashes, so a re-moded or re-targeted entry changes
it. `just tcb-baseline` records the current value in
`reports/repository-baseline.json`.

That value is deliberately not pinned in this file. This file is part of the
tree the digest covers, so hardcoding the number here would invalidate it the
moment anyone edited this document, and the recorded value would never match a
fresh capture. The Git tree hash above is the stable revision-level anchor; the
working-tree digest is the drift detector, and it stays in the generated report
where it is reproducible.

## Toolchain

| Tool | Version |
|---|---|
| `rustc` | 1.96.1 (31fca3adb 2026-06-26) |
| `cargo` | 1.96.1 (356927216 2026-06-26) |

## Trusted surface

Measured with `cargo tree --all-features --locked`, and enforced by
`security/tcb.toml`. That file records two tiers, because "code that enforces an
invariant" and "code that can subvert one" are different questions:

The numbers here are a snapshot, and the policy file is authoritative:
`just tcb-report` prints the live values, so a difference means this file is
stale rather than the policy being wrong. The policy previously caught exactly
that drift — a ledger budget was raised while the table below still showed the
old figure — which is why the two are stated as snapshot and source.

| Tier | Crates | Lines | `unsafe` |
|---|---|---|---|
| Invariant-enforcing | 5 | 85,329 | 299 |
| In-process | 12 | 114,393 | 617 |

The five enforcing crates:

| Crate | Files | Lines | `unsafe` | Direct deps | Transitive |
|---|---|---|---|---|---|
| `nemo-relay` | 74 | 71,241 | 299 | 39 | 264 |
| `nemo-relay-ledger` | 6 | 9,403 | 0 | 9 | 106 |
| `nemo-relay-types` | 13 | 3,681 | 0 | 7 | 25 |
| `nemo-relay-executor` | 1 | 572 | 0 | 3 | 24 |
| `nemo-relay-authority` | 1 | 432 | 0 | 3 | 25 |

Against the program's targets (`<= 15k-30k` lines, `<= 12` direct dependencies,
`0` `unsafe`), the kernel is still roughly 2-3x over on size and dependencies.
The `unsafe` surface is concentrated in the dynamic native plugin loader:
299 occurrences in `nemo-relay` and another 315 in `nemo-relay-plugin`, which
enforces none of the invariants but shares the process and therefore the attack
surface.

Line and `unsafe` counts are upper bounds that include inline test modules, and
`unsafe` is counted textually without stripping comments, because a regular
expression cannot distinguish a comment from a `//` inside a string literal.
The transitive count is a count of resolved identities, so two versions of one
package count twice instead of collapsing to one name.

## Test evidence

Recorded from a local run on the revision above. These are local results, not a
CI record.

| Command | Result |
|---|---|
| `just test-rust` | pass |
| `just test-python` | 711 passed, plus 24 in the language-binding plugin example |
| `just test-node` | 26 passed |
| `just test-go` | pass |
| `just test-tcb-scripts` | 9 passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| `cargo fmt --all` | pass |

## Known failures

One, recorded so it is not mistaken for a regression introduced by the
refactor:

**`ty` type check fails on `scripts/check-version-consistency.py`.** The
`pre-commit` hook `ty (type check)` reports two `invalid-argument-type`
diagnostics at
`scripts/check-version-consistency.py:139`, where `equal` declares
`expected: str` but is called with a `list[str]`. This reproduces with the
refactor changes stashed, so it predates them. It is unrelated to the trusted
surface and is left unchanged rather than fixed inside this stage.

## Fixed after this baseline was captured

The attestation defect this file originally recorded is fixed.
`verify()` compared the artifact digest, the current evidence bundle, and the
signature, but never compared the attestation's recorded evidence-manifest
digest against the digest of the current manifest, so evidence could be
regenerated after an attestation was issued without invalidating it.
`scripts/qualification/attest_release.py` now compares the two directly, and
`scripts/qualification/test_attest_release.py` reports 10 passed where it
previously reported 9 passed and 1 failed.

It stays recorded here rather than deleted, because the frozen baseline below
was captured while the defect was open. Note that it was missing from the first
version of this file entirely: the qualification script tests were not run when
the baseline was captured, only the Rust, Python, Node, Go, and TCB suites.

## Not captured

Two items from the program's baseline list are deliberately absent:

- **Public API items.** Enumerating these needs a rustdoc-JSON or
  `cargo-public-api` pass. An approximation would produce a number that looks
  authoritative without being comparable across releases, which is worse than
  recording nothing. The `reports/` set notes the gap rather than filling it
  with a guess.
- **Qualification tier.** This tree has not been run through
  `just qualification`, so it carries no tier. Per `qualification/README.md`
  only the pinned Linux release environment can reach `QUALIFIED_CI` or above,
  and a macOS workstation is limited to `QUALIFIED_LOCAL`.
