<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Hardening baseline — 2026-09-19

The revision the NEMO hardening program starts from, recorded so later
milestones cannot obscure which guarantees already worked.

| Field | Value |
|---|---|
| Branch | `feat/native-plugin-isolation` |
| Git revision | `c7c492b674ae58fc15bc0e26d7feefc39b46d21e` |
| Plugin protocol revision | `1` |
| Native plugin ABI revision | `4` |
| `kernel-process unsafe tokens` | 617 |

The full record, including the three surfaces and the guarantees this revision
holds, is in `security/BASELINE.md` under *Hardening baseline — 2026-09-19*.
Machine-readable detail comes from `just tcb-baseline`, which writes to the
git-ignored `reports/` directory.

This directory is new. The earlier RC4 evidence in
`qualification/rc4-kernel-contracts-baseline.md` is untouched: a baseline records
the state it measured, and overwriting one with a later state destroys the only
record of what changed.
