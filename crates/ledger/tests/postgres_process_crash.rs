// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-kill qualification for PostgreSQL terminal finalization.

#![cfg(all(feature = "unstable-postgres", feature = "unstable-hardening-testkit"))]

use nemo_relay_ledger::conformance::{fixture_action, fixture_receipt};
use nemo_relay_ledger::postgres::PostgresEffectStore;
use nemo_relay_ledger::unstable::{
    ActionLease, ActionStore, EffectFinalizeResult, EffectStore, ExecutionState,
    LeaseConfiguration, TerminalEvidence,
};
use postgres::NoTls;
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FIXTURE: &str = env!("CARGO_BIN_EXE_nemo-postgres-crash-fixture");

struct TestSchema {
    connection: String,
    name: String,
}

impl TestSchema {
    fn create(connection: &str) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        Self {
            connection: connection.to_owned(),
            name: format!("nemo_crash_{}_{}", std::process::id(), suffix),
        }
    }

    fn store(&self) -> PostgresEffectStore {
        PostgresEffectStore::connect_insecure_local_for_tests(
            &self.connection,
            &self.name,
            LeaseConfiguration {
                default_duration_ms: 60_000,
                maximum_duration_ms: 60_000,
                renewal_enabled: true,
            },
            2,
        )
        .expect("reopen crash test store")
    }

    fn fixture(&self, mode: &str) -> Command {
        let mut command = Command::new(FIXTURE);
        command.arg(mode).arg(&self.connection).arg(&self.name);
        command
    }
}

impl Drop for TestSchema {
    fn drop(&mut self) {
        let mut client = postgres::Client::connect(&self.connection, NoTls)
            .expect("connect for crash schema cleanup");
        client
            .batch_execute(&format!("drop schema if exists \"{}\" cascade", self.name))
            .expect("drop crash test schema");
    }
}

fn wait_for_marker(child: &mut Child, marker: &Path) {
    for _ in 0..500 {
        if marker.is_file() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll crash fixture") {
            panic!("crash fixture exited before pause point: {status}");
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("crash fixture did not reach pause point");
}

fn run_crash_case(connection: &str, point: &str, committed: bool) {
    let schema = TestSchema::create(connection);
    assert!(
        schema
            .fixture("prepare")
            .status()
            .expect("prepare fixture")
            .success()
    );
    let marker = std::env::temp_dir().join(format!("{}-{point}.ready", schema.name));
    let mut child = schema
        .fixture("finalize")
        .env("NEMO_RELAY_POSTGRES_CRASH_POINT", point)
        .env("NEMO_RELAY_POSTGRES_CRASH_MARKER", &marker)
        .spawn()
        .expect("spawn crash fixture");
    wait_for_marker(&mut child, &marker);
    child.kill().expect("kill crash fixture");
    child.wait().expect("reap crash fixture");
    std::fs::remove_file(&marker).expect("remove crash marker");

    let store = schema.store();
    let action = fixture_action();
    let record = store
        .load_action(&action.action_id)
        .expect("load action after crash")
        .expect("action remains after crash");
    let snapshot = store
        .evidence_snapshot(&action.action_id)
        .expect("load evidence after crash");

    if committed {
        assert_eq!(record.state, ExecutionState::Committed);
        assert!(record.lease.is_none());
        assert!(matches!(
            record.terminal_evidence,
            Some(TerminalEvidence::Receipt(_))
        ));
        assert!(snapshot.receipt.is_some());
        assert_eq!(snapshot.revision, 1);
        let receipt = fixture_receipt(
            &record.preparation,
            ExecutionState::Committed,
            "postgres-process-crash",
        );
        let replay_lease = ActionLease {
            owner_id: "lost-response-replay".into(),
            generation: 0,
            expires_at_unix_ms: 0,
        };
        assert!(matches!(
            store
                .finalize_terminal_receipt(
                    &action.action_id,
                    ExecutionState::Dispatching,
                    &replay_lease,
                    &receipt,
                )
                .expect("replay committed receipt"),
            EffectFinalizeResult::AlreadyFinalized(_)
        ));
    } else {
        assert_eq!(record.state, ExecutionState::Dispatching);
        assert!(record.terminal_evidence.is_none());
        assert!(snapshot.receipt.is_none());
        assert_eq!(snapshot.revision, 0);
        let lease = record.lease.as_ref().expect("pre-commit lease survives");
        let receipt = fixture_receipt(
            &record.preparation,
            ExecutionState::Committed,
            "postgres-process-crash",
        );
        assert!(matches!(
            store
                .finalize_terminal_receipt(
                    &action.action_id,
                    ExecutionState::Dispatching,
                    lease,
                    &receipt,
                )
                .expect("retry rolled-back finalization"),
            EffectFinalizeResult::Finalized(_)
        ));
    }
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn process_kill_preserves_atomic_terminal_invariants() {
    let connection = std::env::var("NEMO_RELAY_TEST_POSTGRES_URL")
        .expect("NEMO_RELAY_TEST_POSTGRES_URL is required");
    for point in [
        "after_action_lock",
        "after_receipt_insert",
        "after_action_update",
        "before_commit",
    ] {
        run_crash_case(&connection, point, false);
    }
    run_crash_case(&connection, "after_commit", true);
}
