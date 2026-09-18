-- SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
-- SPDX-License-Identifier: Apache-2.0

-- These objects are owned by this migration. They are created without
-- IF NOT EXISTS on purpose: adopting a pre-existing object of unknown shape is
-- exactly how a migration ledger blesses a schema it did not build. A
-- conflicting object fails the migration and rolls the transaction back.
create table __SCHEMA__.effect_actions (
    action_id text primary key,
    tenant_id text,
    tenant_scope text generated always as (coalesce(tenant_id, '')) stored,
    idempotency_key text not null,
    action_fingerprint text not null,
    preparation jsonb not null,
    state text not null check (
        state in (
            'PROPOSED',
            'AUTHORIZED',
            'PREPARED',
            'DISPATCHING',
            'COMMITTED',
            'FAILED',
            'UNKNOWN',
            'RECONCILING',
            'CANCELLED'
        )
    ),
    lease_owner text,
    lease_generation bigint not null default 0 check (lease_generation >= 0),
    lease_expires_at timestamptz,
    terminal_evidence jsonb,
    evidence_revision bigint not null default 0 check (evidence_revision >= 0),
    created_at timestamptz not null default clock_timestamp(),
    updated_at timestamptz not null default clock_timestamp(),
    constraint effect_actions_tenant_idempotency_key unique (tenant_scope, idempotency_key),
    constraint effect_actions_preparation_binding check (
        preparation ->> 'action_id' = action_id
        and preparation ->> 'idempotency_key' = idempotency_key
        and preparation ->> 'fingerprint' = action_fingerprint
        and (preparation ->> 'tenant_id') is not distinct from tenant_id
    ),
    constraint effect_actions_lease_shape check (
        (lease_owner is null and lease_expires_at is null)
        or (lease_owner is not null and lease_expires_at is not null)
    )
);

create index effect_actions_recovery_idx
    on __SCHEMA__.effect_actions (state, lease_expires_at);

create table __SCHEMA__.effect_receipts (
    action_id text primary key
        references __SCHEMA__.effect_actions (action_id) on delete restrict,
    receipt_identity text not null,
    receipt jsonb not null,
    created_at timestamptz not null default clock_timestamp(),
    constraint effect_receipts_action_binding check (receipt ->> 'action_id' = action_id),
    constraint effect_receipts_terminal_state check (
        receipt ->> 'final_state' in ('COMMITTED', 'FAILED')
    )
);

create table __SCHEMA__.effect_receipt_conflicts (
    conflict_digest text primary key,
    action_id text not null
        references __SCHEMA__.effect_actions (action_id) on delete restrict,
    conflict jsonb not null,
    observed_at timestamptz not null default clock_timestamp(),
    constraint effect_receipt_conflicts_action_binding check (
        conflict ->> 'action_id' = action_id
    )
);

create index effect_receipt_conflicts_action_idx
    on __SCHEMA__.effect_receipt_conflicts (action_id, observed_at, conflict_digest);

-- Expected physical schema. This row is data, not structure, so recording the
-- expected description here does not make verification self-referential: the
-- digest covers catalogs, and the row holding it is written after the digest is
-- computed. `schema_model` keeps the full canonical description so a mismatch
-- can report what drifted rather than only that a hash changed.
create table __SCHEMA__.effect_schema_state (
    id boolean primary key default true check (id),
    model_version integer not null,
    server_major integer not null,
    schema_fingerprint text not null,
    schema_model jsonb not null,
    recorded_at timestamptz not null default clock_timestamp()
);
