// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Child-process fixture for PostgreSQL terminal-finalization crash tests.

use nemo_relay_ledger::conformance::{fixture_action, fixture_receipt};
use nemo_relay_ledger::postgres::PostgresEffectStore;
use nemo_relay_ledger::unstable::{
    ActionStore, EffectStore, ExecutionState, LeaseAcquireResult, LeaseConfiguration,
};

fn connect(connection: &str, schema: &str) -> PostgresEffectStore {
    PostgresEffectStore::connect_insecure_local_for_tests(
        connection,
        schema,
        LeaseConfiguration {
            default_duration_ms: 60_000,
            maximum_duration_ms: 60_000,
            renewal_enabled: true,
        },
        2,
    )
    .expect("connect crash fixture store")
}

fn prepare(store: &PostgresEffectStore) {
    store.migrate().expect("migrate crash fixture store");
    let action = fixture_action();
    store.claim_action(&action).expect("claim crash action");
    store
        .authorize_action(
            &action.action_id,
            ExecutionState::Proposed,
            "grant",
            Some("approval"),
        )
        .expect("authorize crash action");
    store
        .transition(
            &action.action_id,
            Some(ExecutionState::Authorized),
            ExecutionState::Prepared,
        )
        .expect("prepare crash action");
    let lease = match store
        .claim_lease(
            &action.action_id,
            ExecutionState::Prepared,
            "postgres-crash-worker",
            Some(60_000),
        )
        .expect("claim crash lease")
    {
        LeaseAcquireResult::Acquired(lease) => lease,
        result => panic!("expected acquired crash lease, got {result:?}"),
    };
    store
        .transition_with_lease(
            &action.action_id,
            ExecutionState::Prepared,
            &lease,
            ExecutionState::Dispatching,
        )
        .expect("mark crash action dispatching");
}

fn finalize(store: &PostgresEffectStore) {
    let action = fixture_action();
    let record = store
        .load_action(&action.action_id)
        .expect("load crash action")
        .expect("crash action exists");
    let lease = record.lease.as_ref().expect("crash action has lease");
    let receipt = fixture_receipt(
        &record.preparation,
        ExecutionState::Committed,
        "postgres-process-crash",
    );
    store
        .finalize_terminal_receipt(
            &action.action_id,
            ExecutionState::Dispatching,
            lease,
            &receipt,
        )
        .expect("finalize crash action");
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let mode = arguments.next().expect("mode argument");
    let connection = arguments.next().expect("connection argument");
    let schema = arguments.next().expect("schema argument");
    assert!(arguments.next().is_none(), "unexpected fixture argument");

    let store = connect(&connection, &schema);
    match mode.as_str() {
        "prepare" => prepare(&store),
        "finalize" => finalize(&store),
        _ => panic!("unknown fixture mode: {mode}"),
    }
}
