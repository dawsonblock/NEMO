<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Kernel invariants

These are the properties the kernel is supposed to protect. They exist so that
"what belongs in the trusted core" is decided by evidence rather than by taste:
a function earns a place in the kernel only if it enforces one of these, and a
crate is trusted only while it carries them.

Each invariant records where it is enforced today, what proves it, and whether
that enforcement is structural (a type or a total `match` makes violation
unrepresentable), checked (a runtime predicate rejects it), or merely
conventional. Structural enforcement is the target; convention is a gap.

Line numbers are anchors into the tree at the revision recorded in
[BASELINE.md](./BASELINE.md). Symbol names are the durable reference.

## Status summary

| ID | Invariant | Status |
|---|---|---|
| K-001 | Only defined state transitions are legal | enforced (predicate) |
| K-002 | A terminal receipt cannot be replaced or contradicted | enforced (contract + conflict record) |
| K-003 | An idempotency key cannot refer to two incompatible fingerprints | enforced (predicate) |
| K-004 | A stale lease generation cannot finalize an effect | enforced (fencing) |
| K-005 | `UNKNOWN` does not mean `FAILED` | enforced (distinct states) |
| K-006 | `UNKNOWN` does not authorize redispatch | enforced (recovery path) |
| K-007 | A grant binds to the exact runtime identity | enforced (grant binding) |
| K-008 | A grant binds to the exact capability generation | enforced (grant binding) |
| K-009 | A grant binds operation, execution class, route, and arguments | enforced (grant binding) |
| K-010 | Capability routing cannot change after sealing | enforced (type) |
| K-011 | Production kernel construction requires verified components | enforced (type + readiness) |
| K-012 | Mutation/critical execution cannot bypass authority | enforced (kernel path) |
| K-013 | Receipt identity must match the originating action | enforced (evidence binding) |
| K-014 | Policy version/epoch cannot change between authorization and dispatch | enforced (grant binding) |
| K-015 | A failed-before-dispatch action is not treated as possibly executed | enforced (total `match`) |
| K-016 | A possibly-dispatched action enters `UNKNOWN` rather than `FAILED` | enforced (total `match`) |

## K-001 — Only defined state transitions are legal

A lifecycle state may only advance along the declared graph.

**Enforced by** `ExecutionState::is_valid_lifecycle_transition`
(`crates/ledger/src/lib.rs:87`), plus narrower predicates for each operation:
`is_valid_authorization_transition`, `is_valid_generic_transition`
(`crates/ledger/src/lib.rs:127`), and `is_valid_leased_transition`
(`crates/ledger/src/lib.rs:141`). The abstract graph is deliberately wider than
any single operation, so each store method must apply the predicate for what it
does.

**Verified by** `reference_store_rejects_authorization_and_lease_contract_misuse`
(`crates/ledger/src/lib.rs`).

## K-002 — A terminal receipt cannot be replaced or contradicted

Only fenced finalization creates the primary receipt. Observation records
conflict evidence and never overwrites what is already authoritative; a
contradiction is an integrity finding, not a repair path.

**Enforced by** `EffectStore::observe_terminal_evidence` and
`finalize_terminal_receipt` (`crates/ledger/src/lib.rs`, trait contract around
line 1240), which separates observing evidence from granting it authority.

**Verified by** `terminal_observation_cannot_create_primary_evidence`,
`receipt_finalization_is_append_only_idempotent_or_conflicting`, and
`terminal_fault_boundaries_leave_the_complete_old_state`
(`crates/ledger/src/lib.rs`); `recovery_reports_contradictory_evidence_without_rewriting_unknown_state`
and `persisted_receipt_conflicts_block_provider_reconciliation_before_dispatch`
(`crates/core/src/kernel.rs`).

## K-003 — An idempotency key cannot refer to two incompatible fingerprints

Claiming an idempotency key that already exists is only a success when the
fingerprint matches; otherwise the claim is rejected as a conflict.

**Enforced by** `PrepareActionResult::IdempotencyConflict`
(`crates/ledger/src/lib.rs:429`) and the claim path that returns it.

**Verified by** the idempotency-claim cases in the store conformance suite
(`crates/ledger/src/lib.rs`).

## K-004 — A stale lease generation cannot finalize an effect

Fencing generations are monotonic, and only a live lease matching the current
generation may perform a fenced transition.

**Enforced by** the `lease_generation` fencing token on `ActionRecord` and the
lease-validation step inside fenced operations. Generation exhaustion fails
closed rather than wrapping.

**Verified by** `stale_dispatcher_cannot_insert_receipt_after_lease_reclamation`,
`two_executors_cannot_claim_the_same_live_lease`,
`renewal_requires_the_live_exact_lease_and_preserves_fencing`, and
`fencing_generation_overflow_fails_closed` (`crates/ledger/src/lib.rs`).

## K-005 — `UNKNOWN` does not mean `FAILED`

`Unknown` and `Failed` are distinct states with distinct next steps. `Unknown`
is a durable claim about missing evidence, not an alias for failure.

**Enforced by** `ExecutionState::Unknown` vs `ExecutionState::Failed`
(`crates/ledger/src/lib.rs:76`) and the recovery decisions that branch on them
(`RecoveryDecision::RecoverUnknown`).

**Verified by** `ambiguous_dispatch_is_persisted_as_unknown_then_reconciled` and
`recovery_marks_stale_dispatching_without_a_receipt_unknown`
(`crates/core/src/kernel.rs`).

## K-006 — `UNKNOWN` does not authorize redispatch

Retrying an `UNKNOWN` action returns a reconciliation handle. It does not
redispatch the effect.

**Enforced by** `Kernel::recover`, which requires `ExecutionState::Unknown`
(rejecting anything else with `KernelError::ActionNotUnknown`) and returns
`RecoveryDecision::RecoverUnknown` rather than a new dispatch.

**Verified by** `retry_of_an_unknown_action_returns_its_reconciliation_handle_without_redispatch`
and `unknown_actions_reconcile_through_external_effect_fabric`
(`crates/core/src/kernel.rs`).

## K-007 — A grant binds to the exact runtime identity

**Enforced by** `VerifiedGrant::binds` (`crates/authority/src/lib.rs:113`),
which compares `runtime_binding_digest` as well as `tenant_id`, `principal_id`,
and `action_id`. The digest canonically covers deployment identity, environment,
and session provenance.

**Verified by** `runtime_environment_and_session_binding_are_grant_bound`
(`crates/core/src/kernel.rs`).

## K-008 — A grant binds to the exact capability generation

**Enforced by** `VerifiedGrant::binds` (`crates/authority/src/lib.rs:113`)
comparing `capability_id`, `capability_generation`, and `registration_digest`,
so a grant issued for one generation cannot authorize a later one.

## K-009 — A grant binds operation, execution class, route, and arguments

**Enforced by** `VerifiedGrant::binds` (`crates/authority/src/lib.rs:113`)
comparing `operation`, `execution_class`, `route_digest`, and `args_digest`. A
grant therefore cannot be replayed against rewritten arguments or a substituted
backend route.

**Verified by** `mismatched_grants_cancel_the_pre_dispatch_action`
(`crates/core/src/kernel.rs`).

## K-010 — Capability routing cannot change after sealing

Registration and resolution are separated: a registry is consumed by `seal`,
and only a sealed registry can produce a kernel.

**Enforced by** `CapabilityRegistry::seal` producing
`SealedCapabilityRegistry`, which is the only registry type the kernel
constructors accept. Post-boot mutation is unrepresentable rather than
discouraged.

**Verified by** `sealing_consumes_the_builder_and_fixes_the_registry_digest`
(`crates/effect-runtime/tests/production_composition.rs`).

## K-011 — Production kernel construction requires verified components

**Enforced by** `Kernel::new_production` (`crates/core/src/kernel.rs`), which
requires a sealed registry containing at least one admitted consequential
capability, a `production` environment, and a store bound by the sealed
`ProductionEffectStore` trait that attests readiness. The sealed supertrait
lives in a private module, so no other crate can implement it for its own type.

The other direction is enforced too: `Kernel::new_development` rejects a
production runtime identity, so a caller cannot hold production evidence and
compose through the development constructor to skip production admission. That
matters because the kernel is constructible from outside the runtime layer, and
the profile would otherwise be enforced only where the runtime configuration is
built.

The bound alone was not enough. Every `PostgresEffectStore` carried
`ProductionEffectStore` regardless of how it was opened, so a store built with
the explicitly local test transport could attest readiness and a production
kernel could be composed around a connection that was never verified. The
handle now records the transport it was opened with, and
`verify_production_readiness` refuses to attest for the test-only transport, so
`Kernel::new_production` rejects that combination directly rather than relying
on the runtime layer to prevent it.

**Remaining refinement.** The guarantee is enforced by a checked method rather
than by the type. A distinct `ProductionPostgresEffectStore`, produced only by
the verified-transport constructors, would make the bad combination
unrepresentable instead of rejected, and is the type-level target.

What "attests readiness" covers was also widened, because the checks behind it
proved less than the bound implied. The role check now covers the powers that
need no grant (`SUPERUSER`, `BYPASSRLS`, `CREATEROLE`) and ownership of the
effect schema or its relations, alongside the existing grant checks, including
`DELETE` on `effect_schema_state`. The server settings are compared against a
`DatabaseReadinessPolicy` rather than only reported, so a database running
`synchronous_commit = off` is rejected instead of observed. Each of those was
verified against the PostgreSQL release the repository pins for qualification,
by escalating one property at a time and asserting the specific rejection.

**Verified by** `a_production_kernel_composes_only_with_the_durable_store`,
`production_composition_is_fail_closed`, and `the_production_store_trait_is_sealed`
(`crates/effect-runtime/tests/production_composition.rs`).

## K-012 — Mutation/critical execution cannot bypass authority

**Enforced by** the kernel's begin path, which claims the action durably and
evaluates authority before dispatching for `Mutation` and `Critical` classes,
and cancels the claimed action when the decision is not an exact binding
`Allow`.

**Verified by** `mismatched_grants_cancel_the_pre_dispatch_action` and
`fast_paths_bypass_authority_and_effect_stores` (`crates/core/src/kernel.rs`).

**Caveat:** the second test is deliberate scope, not a gap. `Pure` and `Read`
classes take a fast path that calls no authority and touches no durable store.
K-012 is therefore a statement about consequential classes only, and any future
change that routes a consequential class onto that fast path would break it.

## K-013 — Receipt identity must match the originating action

**Enforced by** evidence binding: `ActionEvidenceBinding::try_from(action)` is
attached to failure evidence, and receipt records carry the same immutable
identity fields, with `EvidenceBindingError` rejecting mismatches before a
terminal transition.

**Verified by** `reconciliation_receipts_bind_the_original_principal_and_grant`
and `recovery_rejects_split_receipt_and_dispatching_state`
(`crates/core/src/kernel.rs`).

## K-014 — Policy version/epoch cannot change between authorization and dispatch

**Enforced by** `VerifiedGrant::binds` (`crates/authority/src/lib.rs:113`)
comparing `policy_version` and `policy_epoch`, which are carried into the
durable execution identity at binding time.

## K-015 — A failed-before-dispatch action is not treated as possibly executed

A terminal `FAILED` from the dispatching phase is only legal for a proven
pre-dispatch failure, and a provider receipt is never accepted on that path.

**Enforced by** `is_valid_pre_dispatch_failure_finalization`
(`crates/ledger/src/lib.rs:210`) and the requirement that
`finalize_pre_dispatch_failure` carry `PreDispatchFailureEvidence` rather than a
receipt. `is_valid_leased_transition` excludes `Dispatching -> Failed`, so the
fenced receipt path cannot produce it either.

**Verified by** `confirmed_pre_dispatch_failure_returns_the_durable_action_status`
(`crates/core/src/kernel.rs`).

## K-016 — A possibly-dispatched action enters `UNKNOWN` rather than `FAILED`

**Enforced by** `state_for_error` (`crates/executor/src/lib.rs:228`). The
`match` is total with no catch-all: `FAILED` requires exactly
`NotDispatched` with `ConfirmedFailure`. `DispatchAttempted`,
`DispatchConfirmed`, and any `Unknown` certainty all resolve to `UNKNOWN`. The
kernel then routes through `unknown_after_dispatching`
(`crates/core/src/kernel.rs:1897`) instead of terminalizing.

**Verified by** `ambiguous_dispatch_is_persisted_as_unknown_then_reconciled`,
`post_dispatch_receipt_failure_returns_a_reconciliation_handle`, and
`failed_unknown_persistence_returns_state_recovery_with_real_action_id`
(`crates/core/src/kernel.rs`).

## What is not yet enforced

These are gaps between the invariant set and the current tree. They are recorded
here rather than fixed quietly, because each one changes what may move out of
the kernel.

- **The TCB is not isolated by crate.** `nemo-relay` currently depends on
  `nemo-relay-authority`, `nemo-relay-executor`, `nemo-relay-ledger`,
  `nemo-relay-plugin`, `nemo-relay-types`, and `nemo-relay-worker-proto`. Under
  the layering in `security/layers.toml`, five of those six point upward, so the
  invariants live across four crates rather than one auditable core. K-008
  through K-014 are enforced in code the kernel does not own. `just layer-report`
  fails if a new upward edge appears, and fails on a grandfathered entry that no
  longer exists, so the five can only shrink and the exception cannot outlive
  the debt it excused.
- **The measured surface is wider than the enforcing surface.** `nemo-relay`
  carries 299 `unsafe` occurrences, dominated by the dynamic native plugin
  loader, and `nemo-relay-plugin` carries another 315. The plugin crates enforce
  none of these invariants, but they run in the same process, so a memory-safety
  bug there can subvert a correct state machine. `security/tcb.toml` therefore
  measures two tiers: 85,027 source lines in the crates that enforce an
  invariant, and 114,091 lines / 617 `unsafe` occurrences in everything sharing
  the kernel's process. The second number, not the first, is the current
  attack surface.
- **There is more than one production construction path.** K-011 governs
  `Kernel::new_production`, and
  `DurableRuntime::bootstrap` is the composition root. Both are public, so a
  deployment can bypass the runtime layer while still satisfying K-011. The
  target is one path.
- **K-007 through K-009 are runtime checks, not types.** `VerifiedGrant::binds`
  is a boolean predicate over sixteen fields. A type-level binding would make a
  mismatched grant unrepresentable rather than rejected.
