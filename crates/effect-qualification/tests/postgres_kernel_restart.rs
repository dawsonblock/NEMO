// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real process restart around the provider/ledger commit gap.

use postgres::{Client, NoTls};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const FIXTURE: &str = env!("CARGO_BIN_EXE_nemo-effect-qualification-fixture");

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
            name: format!("nemo_runtime_{}_{}", std::process::id(), nanos),
        }
    }

    fn client(&self) -> Client {
        Client::connect(&self.connection, NoTls).expect("connect to local qualification PostgreSQL")
    }

    fn command(&self, mode: &str) -> Command {
        let mut command = Command::new(FIXTURE);
        command
            .arg(mode)
            .arg(&self.name)
            .arg("stable-qualification-runtime")
            .env("NEMO_EFFECT_QUALIFICATION_ONLY", "1")
            .env("NEMO_RELAY_TEST_POSTGRES_URL", &self.connection);
        command
    }

    fn count(&self, table: &str) -> i64 {
        self.client()
            .query_one(
                &format!("select count(*) from \"{}\".{table}", self.name),
                &[],
            )
            .expect("count qualification table")
            .get(0)
    }
}

impl Drop for TestSchema {
    fn drop(&mut self) {
        self.client()
            .batch_execute(&format!("drop schema if exists \"{}\" cascade", self.name))
            .expect("remove isolated qualification schema");
    }
}

fn assert_crashed_action(schema: &TestSchema) {
    assert_eq!(schema.count("qualification_provider_effects"), 1);
    assert_eq!(schema.count("effect_actions"), 1);
    assert_eq!(schema.count("effect_receipts"), 0);
    let state: String = schema
        .client()
        .query_one(
            &format!("select state from \"{}\".effect_actions", schema.name),
            &[],
        )
        .expect("load durable state after process death")
        .get(0);
    assert_eq!(state, "DISPATCHING");

    let live_owner = schema.command("recover").output().expect("scan live lease");
    assert!(live_owner.status.success());
    assert!(
        live_owner.stdout.is_empty(),
        "live lease must not be reclaimed"
    );
    assert_eq!(schema.count("effect_receipts"), 0);
}

fn expire_crashed_lease(schema: &TestSchema) {
    // Advance only the test lease expiry in the store's own database. The
    // next process must still acquire a new fence through Kernel::recover.
    schema
        .client()
        .execute(
            &format!(
                "update \"{}\".effect_actions \
                 set lease_expires_at = clock_timestamp() - interval '1 second'",
                schema.name
            ),
            &[],
        )
        .expect("expire the crashed worker lease");
}

fn assert_recovered_action(schema: &TestSchema) {
    assert_eq!(schema.count("qualification_provider_effects"), 1);
    assert_eq!(schema.count("effect_receipts"), 1);
    let row = schema
        .client()
        .query_one(
            &format!(
                "select state, lease_owner, evidence_revision from \"{}\".effect_actions",
                schema.name
            ),
            &[],
        )
        .expect("load recovered action");
    assert_eq!(row.get::<_, String>(0), "COMMITTED");
    assert_eq!(row.get::<_, Option<String>>(1), None);
    assert_eq!(row.get::<_, i64>(2), 1);
}

#[test]
fn fixture_rejects_missing_qualification_acknowledgement() {
    let result = Command::new(FIXTURE)
        .arg("invoke")
        .output()
        .expect("launch qualification fixture");
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("explicit acknowledgement"),
        "fixture must fail before connecting to a database"
    );
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn process_crash_after_provider_commit_recovers_without_redispatch() {
    let connection = std::env::var("NEMO_RELAY_TEST_POSTGRES_URL")
        .expect("set the local PostgreSQL qualification URL");
    let schema = TestSchema::new(&connection);

    let fast = schema
        .command("invoke-fast")
        .arg("fast-request")
        .status()
        .expect("run fast lane");
    assert!(fast.success());
    assert_eq!(schema.count("effect_actions"), 0);
    assert_eq!(schema.count("qualification_provider_effects"), 0);

    let crashed = schema
        .command("invoke")
        .arg("crash-request")
        .env("NEMO_EFFECT_CRASH_AFTER_PROVIDER_COMMIT", "1")
        .status()
        .expect("launch effect runtime");
    assert!(!crashed.success(), "runtime must die after provider commit");
    assert_crashed_action(&schema);
    expire_crashed_lease(&schema);

    let recovered = schema.command("recover").output().expect("restart runtime");
    assert!(
        recovered.status.success(),
        "recovery failed: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(String::from_utf8_lossy(&recovered.stdout).contains("Committed"));
    assert_recovered_action(&schema);

    let replay = schema
        .command("invoke")
        .arg("crash-request")
        .output()
        .expect("retry original request");
    assert!(
        replay.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(schema.count("qualification_provider_effects"), 1);
    assert_eq!(schema.count("effect_actions"), 1);
    assert_eq!(schema.count("effect_receipts"), 1);
}
