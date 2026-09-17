-- SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
-- SPDX-License-Identifier: Apache-2.0

alter table __SCHEMA__.effect_actions
    add column if not exists last_reconciliation_at timestamptz,
    add column if not exists next_reconciliation_at timestamptz,
    add column if not exists reconciliation_attempts bigint not null default 0,
    add column if not exists last_reconciliation_error text;

create index if not exists effect_actions_reconciliation_schedule_idx
    on __SCHEMA__.effect_actions (state, next_reconciliation_at, reconciliation_attempts);
