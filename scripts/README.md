<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Scripts

The canonical build and test surface now lives in the repository `justfile`.
Use `just --list` to discover supported developer workflows.

Keep `scripts/` focused on helpers that are still script-native:

## Top-Level Commands

- `build-docs.sh`: compatibility wrapper around the Fern documentation validation recipe; it regenerates ignored Fern API reference pages before checking the site
- `generate_attributions.sh`: regenerate attribution documents
- `test-install.sh`: Run live GitHub release and local interface checks for the curl-based CLI installer
- `test-install.ps1`: Run live GitHub release and local interface checks for the PowerShell CLI installer
- `test-install-mocks.sh`: Run installer scenarios that require simulated platforms or failures

## Trusted Computing Base

`security/tcb.toml` declares which crates are trusted and the budgets that keep
them small. Run `just tcb-report` to print the current surface, or
`just test-tcb-scripts` to exercise the gate itself. The check fails when a
forbidden package (a database driver or a foreign-function binding) appears
anywhere in a trusted crate's resolved tree, or when any budget grows. Alongside
the ceilings, each crate's direct and transitive dependency *sets* are pinned by
digest, so swapping one package for another cannot pass by keeping the count the
same. Raising a ceiling is an explicit edit to that policy file, so growth is
visible in review.

The policy defines two tiers: the crates that enforce a kernel invariant, and
every additional crate linked into the same process, which can subvert one
without enforcing it. Both are reported, because the second is the real attack
surface until process isolation exists.

`just tcb-baseline` captures the frozen baseline the refactor is measured
against - source-tree and lockfile digests, toolchain versions, the workspace
crate graph, and the trusted-surface measurements - into the generated,
git-ignored `reports/` directory. The recorded invariants and the known gaps
behind them live in `security/INVARIANTS.md` and `security/BASELINE.md`.

`just layer-report` enforces `security/layers.toml`, which places every
workspace crate in a layer and fails when a dependency points upward. Edges that
point the wrong way today are listed as grandfathered so the check passes on
arrival and can only get tighter; the report names them on every run. A
grandfathered entry that no longer describes a real edge also fails, so an
exception cannot outlive the debt it excused and let a later regression back in
unnoticed.

## Opt-In Coding-Agent E2E Tests

These checks exercise installed coding-agent clients and are intentionally outside the default Rust and CI test suites. Run the recipe that matches an available local client:

- `just test-codex-plugin-e2e`
- `just test-claude-plugin-e2e`

## Latency Benchmark

Run `just latency-benchmark` to build the release CLI and compare
direct provider requests with Relay's minimal, ATOF file exporter, and OTLP
exporter configurations. The benchmark also measures full hook subprocess and
cold gateway startup time. It writes structured results under
`target/benchmark-results/nemo-relay-latency-report.json` and
`target/benchmark-results/nemo-relay-latency-report.html` by default and is
intentionally outside regular CI. Large ATOF output goes to a
`nemo-relay-latency-*` directory in the operating system's temporary location
and is removed after a normal run.

Run `just test-latency-benchmark` to execute the fixture's fast unit tests
without building Relay.

The defaults live in `scripts/latency_benchmark/config/default.toml`. Supply a
partial TOML file with `--config`, or override individual values on the command
line. For example, this runs only a small OpenAI gateway matrix:

```bash
just latency-benchmark \
  --tests gateway \
  --providers openai \
  --payload-sizes 4096 \
  --concurrency 1 \
  --samples 10
```

Run `just latency-benchmark --help` to list all overrides without
building Relay. The three selectable suites are `gateway`, `hooks`, and
`startup`. Each run writes machine-readable JSON and a self-contained HTML
report with graphs. Add repeatable `--middleware NAME=PATH` options to measure
custom Relay plugin configurations alongside the three default variants. Refer
to [`latency_benchmark/README.md`](latency_benchmark/README.md) for the complete
human-facing run guide.

## Internal Layout

- `docs/`: Fern reference-generation, migration cleanup, and `docs-website` branch sync helpers. Generated API reference output under `docs/reference/api/*-library-reference/` is ignored and recreated by `just docs`.
- `licensing/`: attribution generation helpers, including license inventory diff scripts
- `lint/`: pre-commit and local lint helpers
- `test-support/`: shared test utilities
