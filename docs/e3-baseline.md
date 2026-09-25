<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# E3 baseline

This record establishes the starting point for the E3 consequential-action
runtime cycle. It exists because build 3 shipped qualification evidence that
was produced for a different source tree: the bundled certificate described
commit `f2cad7f`, while the shipped source was `38dad56`, which adds the
`nemo-effect-runtime` crate and changes `crates/core`, `crates/executor`, and
`crates/ledger`.

The stale artifacts have been removed from the development branch. The current
tree carries **no** qualification certificate.

## Baseline facts

| Field | Value |
| --- | --- |
| Workspace version | `0.9.1-rc.4` |
| Workspace members | `core`, `types`, `plugin`, `plugin-protocol`, `plugin-host`, `plugin-proto`, `worker-proto`, `worker`, `adaptive`, `pii-redaction`, `authority`, `ledger`, `executor`, `effect-qualification`, `effect-runtime`, `isolation`, `dlp`, `cli`, `python`, `ffi`, `node` |
| EffectStore migration version | `1` (`crates/ledger/migrations/0001_effect_store.sql`) |
| Native plugin ABI version | `5` (`NEMO_RELAY_NATIVE_ABI_VERSION`) |
| EffectStore contract version | unversioned; the executable contract is `crates/ledger/src/conformance.rs` |
| Schema fingerprint algorithm | `1` (`crates/ledger/src/schema.rs`) |
| Qualification status | `UNQUALIFIED` until a run produces evidence for this exact tree |
| Promotion | `DEV` |

### Source tree digest

The canonical source tree digest is a derived value, not a literal in this
document. Inlining it would be self-defeating: this file is part of the tree it
describes, so writing the digest here would invalidate it immediately. The
authoritative value is generated into `qualification/source-tree.sha256` by
`scripts/qualification/capture_provenance.py`, which enumerates the filesystem
directly. Print the current digest with:

```bash
just qualification-digest
```

## Why the previous evidence was not usable

`scripts/qualification/provenance_check.py` derived its candidate set from the
manifest under test. That only ever proves `manifest_entries <= actual_tree`: a
manifest cannot report a file it does not already list, so files added after the
manifest was captured were invisible. A tree containing brand-new `.rs` files
verified identically to the pristine tree the manifest was written for, and
symlinks were filtered out of the entry set entirely.

The verifier now enumerates the filesystem first and compares exact sets. A
copied manifest cannot describe a source tree it did not enumerate, and a
manifest written under the previous flat schema is rejected rather than
upgraded.

## Qualification tiers

Promotion is now the highest tier whose evidence is actually present:

| Tier | Requires |
| --- | --- |
| `DEV_PASS` | The recorded test matrix passed. Environment variation is allowed. |
| `QUALIFIED_LOCAL` | The recorded environment is reproduced exactly on this host. |
| `QUALIFIED_CI` | Clean checkout on the pinned Linux release environment, fresh database, full mandatory matrix. |
| `QUALIFIED_FAILURE` | `QUALIFIED_CI` plus fault injection and recovery qualification. |
| `PRODUCTION_CANDIDATE` | `QUALIFIED_FAILURE` plus real authority, providers, recovery supervisor, isolation, DLP, and HA database evidence, signed. |
| `PRODUCTION_RELEASE` | `PRODUCTION_CANDIDATE` bound to one exact final artifact. |

The pinned release environment lives in
`scripts/qualification/release-environment.json` and mirrors
`.github/ci-tool-versions.env` and `.devcontainer/Dockerfile`. A macOS
workstation can reach `QUALIFIED_LOCAL`; it can never emit `QUALIFIED_CI` or a
production tier. Each withheld tier records the reason it was withheld in
`qualification.json`.

## Evidence bundle

`scripts/qualification/build_evidence_manifest.py` hashes every artifact a run
produces - gate logs, SBOM, environment record, source manifest, migration
manifest - into `qualification/evidence-manifest.json`, and emits a DSSE
envelope carrying an in-toto statement. Setting `NEMO_RELAY_EVIDENCE_SIGN`
requests a cosign signature from the ambient CI identity; no signing secret is
stored in the repository. An unsigned run is recorded as `UNSIGNED` rather than
implying a signature that does not exist.

That bundle deliberately does not name the final artifact. The artifact is built
after the bundle exists, so binding its digest inside the bundle would be
self-referential if the artifact ever shipped the bundle. The release order is
one-directional and ends outside the artifact:

```text
source manifest -> qualification -> internal evidence bundle
  -> final artifact -> SHA-256(final artifact)
  -> external release attestation -> signature
```

`scripts/qualification/attest_release.py` writes that external attestation beside
the artifact, refuses to attest an artifact that already contains the evidence
bundle, and refuses a `PRODUCTION_*` promotion whose evidence is unsigned.

Changing a gate log, the SBOM, the environment record, the qualification result,
the source manifest, the final artifact, or the attestation breaks at least one
recorded digest.

Signing is a hard release prerequisite rather than a recorded preference.
`PRODUCTION_CANDIDATE` and `PRODUCTION_RELEASE` require a verified signature over
the evidence, and `PRODUCTION_RELEASE` additionally requires the signed external
attestation. An unsigned run may reach `QUALIFIED_CI`; it cannot reach a
distributable tier.

## Ignore semantics

`.gitignore` is part of the provenance boundary, so its semantics are frozen
rather than implied. The source manifest records `enumeration_policy_version`
and `policy.gitignore_policy_version`, lists every authoritative ignore file
with its digest, and requires each of those files to be a manifested source
entry. Patterns outside the supported subset are rejected instead of
approximated, and a manifest captured under different semantics is refused
rather than reinterpreted. Changing the matcher therefore retires old evidence
instead of silently changing what "same source tree" means.

## Known defects carried into E3

| ID | Defect | Status |
| --- | --- | --- |
| P-001 | Qualification evidence did not belong to the source it shipped with. | fixed in E3.0 |
| P-002 | A stale manifest could verify a tree containing new source files. | fixed in E3.0 |
| P-003 | Symlinks were excluded from the source entry set. | fixed in E3.0 |
| S-001 | `verify_schema()` checked migration ledger rows, not the physical schema. | fixed in E3.1 |
| S-002 | Migrations used `CREATE ... IF NOT EXISTS`, so they adopted pre-existing objects of unknown shape. | fixed in E3.1 |
| S-003 | The runtime credential could modify the schema and the migration ledger. | fixed in E3.1 |
| S-004 | PostgreSQL waits used fixed 3s/10s/15s bounds regardless of the action's remaining budget. | fixed in E3.1 |
| R-001 | `Kernel::new()` remains available, so `nemo-effect-runtime` is not yet the only production composition root. | open; E3.2 |
| R-002 | The 29-second effect deadline is still hardcoded rather than capability-scoped. | open; E3.2 |

## E3.0 exit condition

A build cannot carry qualification evidence that was generated for another
source tree. That condition is enforced by
`scripts/qualification/provenance_check.py`, covered by the mandatory
provenance test suite, and recorded in the evidence bundle.

## E3.1 - database readiness

**Exit condition: a database with a correct migration ledger but a structurally
altered EffectStore schema cannot start the production runtime.**

Verification is split so a failure names the fact that failed:

| Entry point | Checks |
| --- | --- |
| `verify_migration_history` | The ledger is exactly this runtime's migration list, in order, with matching names and checksums |
| `verify_physical_schema` | The catalogue matches the recorded canonical schema |
| `verify_runtime_privileges` | The credential is data-only |
| `verify_database_readiness` | All of the above plus recorded database settings |

The canonical schema is `nemo.effect-store.pg.v1`: tables, columns, types,
nullability, defaults, generated expressions, primary/foreign/unique/check
constraints, indexes with their predicates and validity, and triggers, over the
relations the EffectStore contract owns. It is serialised with RFC 8785
canonical JSON and hashed. Row data, OIDs, physical locations, and creation
order are excluded, so recording the expected description inside the schema it
describes is not self-referential.

Failures are specific: `MigrationHistoryMismatch`, `SchemaFingerprintMismatch`,
`SchemaObjectMismatch` carrying a `SchemaObjectKind` (missing table, unexpected
table, column, constraint, index, trigger), and `DatabasePrivilegeViolation`.
Nothing collapses into one opaque database error.

Ownership is precise. The fingerprint covers the contract relations and
anything attached to them, so an unrelated co-tenant of the same schema cannot
make verification fail. Schema exclusivity is enforced where it matters instead:
the first migration refuses to claim a schema that already contains relations it
does not own.

| Area | Change |
| --- | --- |
| Physical verification | `crates/ledger/src/schema.rs`; runtime readiness calls `verify_schema` before exposing the gateway |
| Migration ownership | `0001_effect_store.sql` no longer uses `IF NOT EXISTS`; the migration fails loudly on a conflicting pre-existing object and refuses to claim a schema containing foreign relations |
| Fingerprint ordering | The fingerprint is computed and recorded inside the migration transaction before the migration version is recorded |
| Runtime role | `verify_runtime_privileges` fails readiness when the connecting role can `CREATE` in the schema or write to `effect_schema_migrations` / `effect_schema_state`; production startup requires it |
| Operation budgets | `PostgresOperationBudgets::for_remaining` derives `lock_timeout = min(configured, remaining/3)` and `statement_timeout = min(configured, remaining)`; `PostgresEffectStore::with_deadline` scopes a handle so every call it makes is bounded by the trusted deadline |
| Schema evidence | `nemo-effect-schema` emits `expected-schema.json` and `expected-schema.sha256` for a freshly migrated database into the qualification directory |
| Gate records | Each gate emits `gates/E3-0NN.json` with status, source and environment digests, duration, and backing evidence |

Machine-readable gates:

| Gate | Check |
| --- | --- |
| E3-011 | `migration-integrity` |
| E3-012 | `physical-schema-verification` |
| E3-013 | `postgres-effect-store` |
| E3-014 | `postgres-concurrency` |
| E3-015 | `postgres-restart` |

The drift matrix deliberately leaves `effect_schema_migrations` untouched and
covers fifteen alterations: a dropped index, a retyped column, a dropped check
constraint, a changed generated expression, a removed `NOT NULL`, dropped
`effect_receipts` and `effect_receipt_conflicts` tables, an added trigger, a
modified and a dropped foreign key, a changed column default, an added writable
column, a changed index predicate, and a changed unique constraint. Every case
fails verification, is attributed to a specific object kind, and none of them
changes the ledger.

Migration integrity is qualified separately: concurrent migrators, a process
killed between the schema DDL and the ledger record, retry after a rollback, a
rewritten historical checksum, an unknown future version, a damaged history, and
role separation. The runtime credential is denied eight operations - rewriting
the ledger, rewriting the recorded fingerprint, dropping or truncating durable
tables, altering columns, creating tables, dropping indexes, and escalating into
the migrator role - while ordinary EffectStore transactions still succeed. A
separate read-only observer role can inspect state but not mutate it.

### Gate catalog

The identifiers E3-011 through E3-020 are fixed by the E3.1 and E3.2 gate lists.
Adopting E3.2's runtime gates required renumbering, so the earlier draft catalog
changed. The mapping is:

| Earlier | Now | Gate |
| --- | --- | --- |
| E3-010 | E3-007 | Authority cryptography |
| E3-016 | E3-008 | Process crash |
| E3-018 | E3-009 | Transport security |
| E3-033 | E3-010 | SBOM |
| E3-011 through E3-015 | unchanged | Migration integrity, physical schema verification, EffectStore, concurrency, restart |
| new | E3-016 through E3-020 | Runtime composition, registry sealing, identity canonicalization, ABI conformance, consequential route enforcement |
| E3-034 | E3-021 | Vulnerability policy |
| E3-035 | E3-022 | Evidence integrity |
| E3-036 | E3-023 | Exact release artifact |
| E3-017 | E3-024 | Recovery Supervisor |

The catalog is now frozen: the E3.2 gates keep the identifiers the plan
assigned them, and nothing already published depends on the old numbers.

### Documented outcome for each failure class

| Observation | Classification |
| --- | --- |
| Ledger row changed, name changed, version missing, version unknown, order broken | `MigrationHistoryMismatch` |
| Physical structure differs from the recorded description | `SchemaObjectMismatch` naming the object kind |
| No recorded schema description exists | `SchemaFingerprintMismatch` |
| Credential can perform DDL or rewrite the ledger | `DatabasePrivilegeViolation` |
| Deadline already exhausted | `InvalidOperationBudget` |
| Injected boundary fault (testkit only) | `InjectedFailure` |

### Migration crash matrix

Eight deterministic kill points around one migration, each asserted on three
independent facts - physical schema, migration ledger, and whether a
subsequent `migrate()` converges:

| Point | Boundary | Expected outcome |
| --- | --- | --- |
| MIG-CRASH-01 | before advisory lock | no commit, no objects, no ledger row, retry applies once |
| MIG-CRASH-02 | after advisory lock | same |
| MIG-CRASH-03 | before DDL | same |
| MIG-CRASH-04 | after DDL | same |
| MIG-CRASH-05 | before migration-ledger insert | same |
| MIG-CRASH-06 | after migration-ledger insert | same |
| MIG-CRASH-07 | before COMMIT | same |
| MIG-CRASH-08 | after COMMIT | migration is durable: restart observes it, verifies it, and does not reapply it |

Point 08 exists because it is the opposite ambiguity from points 01-07:
PostgreSQL made the migration durable even though the client never observed the
commit.

### Database-failure boundary semantics

A database failure means something different depending on where it lands
relative to external dispatch. The boundaries are injected through named fault
points rather than sleeps, so each is deterministic.

| Boundary | Situation | Required semantics | Test |
| --- | --- | --- | --- |
| A | Failure before `DISPATCHING` is durable | No external effect is possible; an ordinary pre-dispatch failure is correct and a retry is safe | `a_pre_dispatch_database_failure_is_an_ordinary_pre_dispatch_failure` |
| B | `DISPATCHING` durable, provider never touched | Durable state cannot prove nothing happened, so the action becomes `UNKNOWN`, not "safely undispatched" | `b_stale_dispatching_becomes_unknown_rather_than_assumed_undispatched` |
| C | Provider may have executed, terminal write fails | External ambiguity: `UNKNOWN` and reconcile, never an ordinary retry | `c_provider_effect_with_failed_terminalization_becomes_unknown_then_reconciles` |
| D | Database failure during reconciliation | Uncertainty is retained and a later reconciliation can still finish | `d_database_failure_during_reconciliation_retains_uncertainty` |

Boundary C is the one that used to be a correctness hole: the provider effect
exists, the durable terminal write does not, and recovery must discover the
existing effect rather than dispatch again. Its test asserts the provider effect
count is exactly one before recovery, after recovery, and after the action
becomes `COMMITTED`.

### Migration contention

`repeated_concurrent_migrations_converge_to_one_canonical_history` runs 50
iterations of 8 simultaneously released migrators (threads with independent
connections, released by a barrier) against a fresh database each time, and
asserts one canonical history row, an exact object set, a verifying schema, and
`verify_database_readiness` passing through a data-only runtime role. The shape
is configurable via `NEMO_RELAY_MIGRATION_STRESS_ITERATIONS` and
`NEMO_RELAY_MIGRATION_STRESS_MIGRATORS` for a nightly run.

### Ledger metadata

`effect_schema_migrations.checksum` is the SHA-256 of the migration SQL. The
column keeps its original name: renaming it to `sha256` would churn the schema
for no security benefit. `application_version` records the release that *first
applied* the migration and is never rewritten by a later runtime that merely
observes it.

## E3.1 freeze gate

| Gate | Required evidence | Status |
| --- | --- | --- |
| E3-011 | Ledger corruption tests, all 8 migration crash points, repeated concurrent migration | PASS |
| E3-012 | 15 destructive drift cases, canonical schema generation | PASS |
| E3-013 | EffectStore contract and invariant suite | PASS |
| E3-014 | EffectStore concurrency and migration contention | PASS |
| E3-015 | Restart durability and pre/post-commit migration restart | PASS |
| E3-039 | Database-failure boundary and `UNKNOWN` semantics | PASS |

One item remains environment-dependent rather than code-dependent: the canonical
schema artifact is generated inside qualification and must be captured on the
pinned PostgreSQL 17 target before release attestation. The generation step is
deterministic and runs in the `physical-schema-verification` gate; only the
comparison against a checked-in constant is deferred, for the reason given
above.

## E3.2 - authoritative runtime (in progress)

Priority order for this slice: production construction ownership, sealed
registry, consequential route enforcement, identity strong types, canonical ABI,
cross-language vectors, Node lifecycle demotion.

### Landed

**Production construction ownership.** Kernel construction is split by trust
level instead of one constructor:

- `Kernel::new_development` validates the runtime identity and seals the
  registry; it accepts any store, including an in-memory one.
- `Kernel::new_production` requires a sealed registry, a `production`
  environment, at least one admitted `MUTATION` or `CRITICAL` capability, and a
  store that implements the sealed `ProductionEffectStore` trait and attests
  readiness.
- The raw assembly step is private. `Kernel::assemble` performs no admission
  checks of its own and is reachable only through the two constructors above,
  and the unchecked test constructor is compiled only for core's own test
  builds. An architectural test fails the build if a user-facing crate (`cli`,
  `python`, `node`, `ffi`) reaches it, and a second test asserts that no crate
  reaches it at all.

The load-bearing part is the store bound. `ProductionEffectStore` is declared
with a supertrait whose module is private to the ledger crate, so no other crate
can implement it for its own type: a harness cannot substitute an in-memory
store and still compose a production kernel. That is compiler-enforced, not
convention.

**Sealed capability registry.** `CapabilityRegistry::seal` consumes the builder
and returns `SealedCapabilityRegistry`, which exposes no mutation. A running
kernel therefore cannot have a capability's execution class, route, generation,
or admission changed after boot. Sealing computes one canonical digest over
every security-relevant registration field (`capability_id`,
`capability_generation`, `registration_digest`, `execution_class`, `operation`,
`route_digest`, `admission_id`, `policy_version`, `policy_epoch`, `admitted`),
exposed as `Kernel::registry_digest()`.

**Fail-closed production startup.** A production kernel is refused when the
environment is not `production`, when no consequential capability is registered,
or when the store cannot attest production readiness — which for the durable
store means migration history, physical schema, credential privileges, and
recorded database settings all hold.

### Still open in this slice

- Consequential route enforcement: proving a `CRITICAL` registration cannot be
  routed to function hooks, and that the harness cannot supply an execution
  class.
- Identity strong types and canonical ABI with cross-language vectors.
- Node lifecycle demotion.

Gate E3-016 and E3-017 stay open until those land. The evidence produced so far
is recorded under the `runtime-composition` check and is deliberately not part
of the frozen E3.1 matrix.

### Observed flakiness

`nemo-relay`'s `logging::tests::opentelemetry_batch_processor_logs_dropped_spans`
fails intermittently when the library suite runs with default parallelism and
passes in isolation and single-threaded. It is pre-existing, unrelated to the
hardening work, and is exactly the class of result the plan says must be
recorded as `PASS_WITH_FLAKE` rather than as a clean pass.
