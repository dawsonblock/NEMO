<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Baseline: NEMO 0.10 minimal trusted kernel

Stage 1 of the program is a freeze. This records what the tree measured before
any code moved, so later milestones can prove they changed only what they
intended and can detect movement they did not intend.

The measurements are produced by tooling, not transcribed by hand:

```bash
just tcb-baseline      # writes reports/*.json
just tcb-report        # prints and enforces the trusted-surface budget
```

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

Measured with `cargo tree --all-features --locked`, and enforced as a ratchet by
`security/tcb.toml`.

| Crate | Files | Lines | `unsafe` | Direct deps | Transitive |
|---|---|---|---|---|---|
| `nemo-relay` | 74 | 71,153 | 299 | 39 | 252 |
| `nemo-relay-types` | 13 | 3,681 | 0 | 7 | 25 |

Line and `unsafe` counts are upper bounds that include inline test modules, so
they never undercount. Against the program's targets (`<= 15k-30k` lines,
`<= 12` direct dependencies, `0` `unsafe`), the kernel is roughly 2-3x over on
size and dependencies, and the `unsafe` surface is concentrated in the dynamic
native plugin loader.

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
