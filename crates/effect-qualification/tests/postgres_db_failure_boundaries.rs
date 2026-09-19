// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Database-failure boundary qualification for consequential actions.
//!
//! A database failure means something different depending on where it lands
//! relative to external dispatch. Four boundaries are modelled explicitly:
//!
//! * **A** - before `DISPATCHING` is durable: no external effect is possible, so
//!   an ordinary pre-dispatch failure is correct.
//! * **B** - `DISPATCHING` durable, provider never touched: recovery cannot know
//!   that nothing happened, so the action must become `UNKNOWN`, not "safely
//!   undispatched".
//! * **C** - provider may have executed, terminal write fails: external
//!   ambiguity, so `UNKNOWN` and reconcile, never an ordinary retry.
//! * **D** - database failure during reconciliation: uncertainty is retained and
//!   reconciliation can be retried later.
//!
//! Failures are injected through a named fault point rather than sleeps, so each
//! boundary is deterministic.

use postgres::{Client, NoTls};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const FIXTURE: &str = env!("CARGO_BIN_EXE_nemo-effect-qualification-fixture");

#[derive(Debug)]
struct TestSchema {
    connection: String,
    name: String,
}

impl TestSchema {
    fn new(connection: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        Self {
            connection: connection.into(),
            name: format!("nemo_boundary_{}_{}", std::process::id(), nanos),
        }
    }

    fn client(&self) -> Client {
        Client::connect(&self.connection, NoTls).expect("connect boundary test client")
    }

    fn command(&self, mode: &str) -> Command {
        let mut command = Command::new(FIXTURE);
        command
            .arg(mode)
            .arg(&self.name)
            .arg("stable-boundary-runtime")
            .env("NEMO_EFFECT_QUALIFICATION_ONLY", "1")
            .env("NEMO_RELAY_TEST_POSTGRES_URL", &self.connection);
        command
    }

    /// Run the fixture with an injected durable-operation failure.
    fn command_with_fault(&self, mode: &str, fault: &str) -> Command {
        let mut command = self.command(mode);
        command.env("NEMO_RELAY_POSTGRES_FAULT_POINT", fault);
        command
    }

    fn count(&self, table: &str) -> i64 {
        self.client()
            .query_one(
                &format!("select count(*) from \"{}\".{table}", self.name),
                &[],
            )
            .expect("count boundary table")
            .get(0)
    }

    fn action_state(&self) -> String {
        self.client()
            .query_one(
                &format!("select state from \"{}\".effect_actions", self.name),
                &[],
            )
            .expect("read durable action state")
            .get(0)
    }

    fn expire_lease(&self) {
        // The lease-shape constraint requires owner and expiry to be present or
        // absent together, so only rows that still hold a lease are advanced.
        self.client()
            .execute(
                &format!(
                    "update \"{}\".effect_actions \
                     set lease_expires_at = clock_timestamp() - interval '1 second' \
                     where lease_owner is not null",
                    self.name
                ),
                &[],
            )
            .expect("expire boundary test lease");
    }
}

impl Drop for TestSchema {
    fn drop(&mut self) {
        if let Ok(mut client) = Client::connect(&self.connection, NoTls) {
            let _ =
                client.batch_execute(&format!("drop schema if exists \"{}\" cascade", self.name));
        }
    }
}

fn connection_string() -> String {
    std::env::var("NEMO_RELAY_TEST_POSTGRES_URL")
        .expect("NEMO_RELAY_TEST_POSTGRES_URL is required for boundary qualification")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Run a mode and return its output, requiring success.
fn run_ok(schema: &TestSchema, mut command: Command) -> String {
    let output = command.output().expect("run qualification fixture");
    assert!(
        output.status.success(),
        "fixture {schema:?} failed: {}",
        stderr_of(&output)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

// -- Boundary A --------------------------------------------------------------

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_pre_dispatch_database_failure_is_an_ordinary_pre_dispatch_failure() {
    let schema = TestSchema::new(&connection_string());

    // The dispatch marker itself cannot be persisted, so no provider call can
    // have happened through this path.
    let output = schema
        .command_with_fault("invoke", "dispatching_transition")
        .arg("boundary-a")
        .output()
        .expect("run boundary A");
    assert!(
        !output.status.success(),
        "a failed dispatch marker must not report success"
    );
    let failure = stderr_of(&output);
    assert!(
        failure.contains("injected durable-operation failure at dispatching_transition"),
        "boundary A must report the persistence failure: {failure}"
    );

    // No external effect, no terminal evidence, and the action is still
    // prepared rather than unknown.
    assert_eq!(schema.count("qualification_provider_effects"), 0);
    assert_eq!(schema.count("effect_receipts"), 0);
    assert_eq!(schema.action_state(), "PREPARED");

    // Because the failure was provably pre-dispatch, a retry is safe and
    // completes exactly once.
    schema.expire_lease();
    let mut retry = schema.command("invoke");
    retry.arg("boundary-a");
    let stdout = run_ok(&schema, retry);
    assert!(stdout.contains("\"outcome\":\"completed\""), "{stdout}");
    assert_eq!(schema.count("qualification_provider_effects"), 1);
    assert_eq!(schema.action_state(), "COMMITTED");
}

// -- Boundary B --------------------------------------------------------------

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn b_stale_dispatching_becomes_unknown_rather_than_assumed_undispatched() {
    let schema = TestSchema::new(&connection_string());

    // A worker persisted DISPATCHING and died before touching the provider.
    // From durable state alone this is indistinguishable from a worker that
    // dispatched and died before recording the result.
    run_ok(&schema, schema.command("prepare-dispatching"));
    assert_eq!(schema.action_state(), "DISPATCHING");
    assert_eq!(schema.count("qualification_provider_effects"), 0);

    schema.expire_lease();
    let stdout = run_ok(&schema, schema.command("recover"));
    assert!(
        stdout.contains("\"recovery\":\"recover_unknown\""),
        "a stale dispatch must be recovered as unknown: {stdout}"
    );

    // The provider has no record of the effect, and reconciliation is
    // deliberately conservative: absence of provider evidence is not proof that
    // nothing happened, so the action must not become COMMITTED or FAILED.
    let state = schema.action_state();
    assert_eq!(state, "UNKNOWN", "unexpected resolution to {state}");
    assert_eq!(schema.count("qualification_provider_effects"), 0);
    assert_eq!(schema.count("effect_receipts"), 0);
}

// -- Boundary C --------------------------------------------------------------

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn c_provider_effect_with_failed_terminalization_becomes_unknown_then_reconciles() {
    let schema = TestSchema::new(&connection_string());

    // The provider commits the effect, then the durable terminal write fails.
    let output = schema
        .command_with_fault("invoke", "terminal_finalization")
        .arg("boundary-c")
        .output()
        .expect("run boundary C");
    assert!(
        !output.status.success(),
        "a failed terminal write must not report success"
    );
    let failure = stderr_of(&output);
    assert!(
        failure.contains("UNKNOWN") || failure.contains("Unknown"),
        "boundary C must classify the outcome as unknown, not failed: {failure}"
    );
    assert!(
        !failure.contains("EffectFailed"),
        "boundary C must never be an ordinary failure: {failure}"
    );

    // The external effect exists and is not duplicated by recovery.
    assert_eq!(schema.count("qualification_provider_effects"), 1);
    assert_eq!(schema.count("effect_receipts"), 0);

    schema.expire_lease();
    let stdout = run_ok(&schema, schema.command("recover"));
    assert!(
        stdout.contains("\"reconciled_state\":\"COMMITTED\""),
        "reconciliation must discover the existing effect: {stdout}"
    );
    assert_eq!(schema.count("qualification_provider_effects"), 1);
    assert_eq!(schema.count("effect_receipts"), 1);
    assert_eq!(schema.action_state(), "COMMITTED");
}

// -- Boundary D --------------------------------------------------------------

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn d_database_failure_during_reconciliation_retains_uncertainty() {
    let schema = TestSchema::new(&connection_string());

    // Establish the same external ambiguity as boundary C.
    let _ = schema
        .command_with_fault("invoke", "terminal_finalization")
        .arg("boundary-d")
        .output()
        .expect("run boundary D setup");
    assert_eq!(schema.count("qualification_provider_effects"), 1);

    schema.expire_lease();
    // Recovery reaches reconciliation, but persisting the reconciliation result
    // fails. The action must stay uncertain rather than being resolved by
    // inference from the database error.
    let output = schema
        .command_with_fault("recover", "reconciliation_finalization")
        .output()
        .expect("run boundary D recovery");
    assert!(
        output.status.success(),
        "an indeterminate reconciliation is a legitimate outcome: {}",
        stderr_of(&output)
    );
    let state = schema.action_state();
    assert!(
        state == "UNKNOWN" || state == "RECONCILING",
        "a failed reconciliation must retain uncertainty, found {state}"
    );
    assert_eq!(schema.count("effect_receipts"), 0);
    assert_eq!(schema.count("qualification_provider_effects"), 1);

    // A later reconciliation, with the database healthy again, resolves it to
    // the effect the provider actually applied.
    schema.expire_lease();
    let stdout = run_ok(&schema, schema.command("recover"));
    assert!(
        stdout.contains("\"reconciled_state\":\"COMMITTED\""),
        "a retried reconciliation must resolve the action: {stdout}"
    );
    assert_eq!(schema.action_state(), "COMMITTED");
    assert_eq!(schema.count("effect_receipts"), 1);
    assert_eq!(schema.count("qualification_provider_effects"), 1);
}
