<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# RC4 kernel-contracts baseline

This record freezes the pre-wiring candidate at the annotated tag
`nemo-rc4-kernel-contracts-baseline`. It is a development baseline, not a
qualification certificate.

| Field | Value |
| --- | --- |
| Git commit | `d830e72614a2c6756294b2212991b437e73f7e87` (`chore: bind README update to RC4 provenance`) |
| Source tree SHA-256 | `c9856a92b973d395357a8dfbcfd5b50bcb614ff3347cfe349f20c22131cd95b9` |
| Source archive SHA-256 | `3747257a183e65935aeedf593de8e87d2b047614159200707382a6963b72f086` |
| Workspace version | `0.9.1-rc.4` |
| Qualification | `E2_LOCAL / INCONCLUSIVE / DEV` |
| Rust, Python, Node, Go gates | `NOT_RUN` in the manifest-only snapshot |

Known defects carried into the wiring cycle:

- K-001: confirmed dispatch plus unknown outcome was classified as `FAILED`.
- K-002: external mutation handlers could throw untyped ambiguous errors.
- K-003: provider contracts existed but were not wired into a runtime boundary.
- K-004: Rust and Effect Fabric used different effect-state vocabularies.
- K-005: the Correct-Once package still identified itself as RC3.
- K-006: release provenance still identified itself as RC3.
- K-007: the version checker omitted the Correct-Once package.
- K-008: stale-version detection only looked for one historical RC.
- K-009: provenance verification assumed a Git checkout.
- K-010: filesystem packaging could include generated Python caches.
- K-011: authoritative action and idempotency state remained external work.

The tag and these values must remain immutable. New wiring work belongs on the
development branch after this baseline.
