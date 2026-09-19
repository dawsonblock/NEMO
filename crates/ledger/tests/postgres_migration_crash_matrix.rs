// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Migration crash matrix: eight deterministic kill points around one migration.
//!
//! Every point asserts three independent facts - the physical schema, the
//! migration ledger, and whether a subsequent `migrate()` converges - rather
//! than only the process exit status.
//!
//! Points 01-07 die before the transaction commits, so PostgreSQL must roll back
//! both the objects and the ledger row and a retry must apply the migration
//! exactly once. Point 08 dies after the commit, which is the opposite
//! ambiguity: the migration is durable even though the client never observed it,
//! so restart must observe a completed migration and must not reapply it.

#![cfg(all(feature = "unstable-postgres", feature = "unstable-hardening-testkit"))]

use nemo_relay_ledger::postgres::PostgresEffectStore;
use nemo_relay_ledger::unstable::LeaseConfiguration;
use postgres::NoTls;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FIXTURE: &str = env!("CARGO_BIN_EXE_nemo-postgres-crash-fixture");

/// Crash points that occur before the migration transaction commits.
const PRE_COMMIT_POINTS: &[&str] = &[
    "mig_crash_01_before_advisory_lock",
    "mig_crash_02_after_advisory_lock",
    "mig_crash_03_before_ddl",
    "mig_crash_04_after_ddl",
    "mig_crash_05_before_ledger_insert",
    "mig_crash_06_after_ledger_insert",
    "mig_crash_07_before_commit",
];

/// The point after the transaction committed.
const POST_COMMIT_POINT: &str = "mig_crash_08_after_commit";

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
            name: format!("nemo_mig_crash_{}_{}", std::process::id(), suffix),
        }
    }

    fn client(&self) -> postgres::Client {
        postgres::Client::connect(&self.connection, NoTls).expect("connect crash matrix client")
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
            4,
        )
        .expect("connect crash matrix store")
    }

    /// Count the effect-store relations that exist for this schema.
    fn contract_objects(&self) -> i64 {
        self.client()
            .query_one(
                "select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace \
                 where n.nspname = $1 and c.relname = any($2)",
                &[&self.name, &nemo_relay_ledger::schema::EFFECT_RELATIONS],
            )
            .expect("count contract relations")
            .get(0)
    }

    /// Return the migration ledger rows, or an empty set when it is absent.
    fn ledger(&self) -> Vec<(i64, String, String)> {
        let exists: bool = self
            .client()
            .query_one(
                "select exists (select 1 from pg_class c join pg_namespace n \
                 on n.oid = c.relnamespace where n.nspname = $1 \
                 and c.relname = 'effect_schema_migrations')",
                &[&self.name],
            )
            .expect("probe migration ledger")
            .get(0);
        if !exists {
            return Vec::new();
        }
        self.client()
            .query(
                &format!(
                    "select version, name, checksum from \"{}\".effect_schema_migrations \
                     order by version",
                    self.name
                ),
                &[],
            )
            .expect("read migration ledger")
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2)))
            .collect()
    }

    fn fixture(&self, mode: &str) -> Command {
        let mut command = Command::new(FIXTURE);
        command.arg(mode).arg(&self.connection).arg(&self.name);
        command
    }
}

impl Drop for TestSchema {
    fn drop(&mut self) {
        if let Ok(mut client) = postgres::Client::connect(&self.connection, NoTls) {
            let _ =
                client.batch_execute(&format!("drop schema if exists \"{}\" cascade", self.name));
        }
    }
}

fn wait_for_marker(child: &mut Child, marker: &Path) {
    for _ in 0..500 {
        if marker.is_file() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll migration fixture") {
            panic!("migration fixture exited before its pause point: {status}");
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("migration fixture did not reach its pause point");
}

fn kill_at_point(schema: &TestSchema, point: &str) -> PathBuf {
    let marker: PathBuf = std::env::temp_dir().join(format!("{}-{point}.ready", schema.name));
    let mut child = schema
        .fixture("migrate")
        .env("NEMO_RELAY_POSTGRES_CRASH_POINT", point)
        .env("NEMO_RELAY_POSTGRES_CRASH_MARKER", &marker)
        .spawn()
        .expect("spawn migration crash fixture");
    wait_for_marker(&mut child, &marker);
    child.kill().expect("kill migration crash fixture");
    child.wait().expect("reap migration crash fixture");
    std::fs::remove_file(&marker).expect("remove migration crash marker");
    marker
}

fn connection_string() -> String {
    std::env::var("NEMO_RELAY_TEST_POSTGRES_URL")
        .expect("NEMO_RELAY_TEST_POSTGRES_URL is required for migration crash qualification")
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn every_pre_commit_migration_crash_rolls_back_and_converges() {
    for point in PRE_COMMIT_POINTS {
        let schema = TestSchema::create(&connection_string());
        kill_at_point(&schema, point);

        // Physical schema: a partial migration would be the worst outcome, since
        // objects without a version record are exactly what an IF NOT EXISTS
        // migration would later adopt.
        assert_eq!(
            schema.contract_objects(),
            0,
            "{point}: a killed migration left schema objects behind"
        );
        // Migration ledger: nothing may be recorded for a migration that did not
        // commit.
        assert!(
            schema.ledger().is_empty(),
            "{point}: a killed migration left a ledger record: {:?}",
            schema.ledger()
        );

        // Convergence: the retry must succeed and record the migration once.
        let store = schema.store();
        store.migrate().expect("retry must converge after a crash");
        store.verify_schema().expect("retried schema must verify");
        let ledger = schema.ledger();
        assert_eq!(ledger.len(), 1, "{point}: retry must record one migration");
        assert_eq!(ledger[0].0, 1);
        assert_eq!(ledger[0].1, "initial_effect_store");
    }
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_post_commit_migration_crash_is_observed_as_completed() {
    let schema = TestSchema::create(&connection_string());
    kill_at_point(&schema, POST_COMMIT_POINT);

    // PostgreSQL made the migration durable before the process died, so the
    // restart must observe a complete migration rather than a partial one.
    let store = schema.store();
    store
        .verify_schema()
        .expect("a committed migration must verify after restart");
    let ledger = schema.ledger();
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].1, "initial_effect_store");
    let recorded_checksum = ledger[0].2.clone();

    // Re-running the migrator must be a no-op, not a reapplication: the ledger
    // keeps exactly one row with the same checksum.
    store
        .migrate()
        .expect("restart migration must be idempotent");
    let after = schema.ledger();
    assert_eq!(
        after.len(),
        1,
        "a completed migration must not be reapplied"
    );
    assert_eq!(after[0].2, recorded_checksum);
    store.verify_schema().expect("schema still verifies");
}
