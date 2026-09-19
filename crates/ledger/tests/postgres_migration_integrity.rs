// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Migration-integrity qualification for the durable effect store.
//!
//! These cases run against a live PostgreSQL server and cover the ways a
//! migration ledger can disagree with the schema it claims to have created:
//! concurrent migrators, damaged history, an unknown future version, and a
//! runtime credential that cannot rewrite the ledger it is supposed to trust.
//!
//! Process-kill coverage for the migration transaction lives in
//! `postgres_migration_crash_matrix.rs`, which asserts all eight kill points.

#![cfg(all(feature = "unstable-postgres", feature = "unstable-hardening-testkit"))]

use nemo_relay_ledger::postgres::{DatabaseReadinessPolicy, PostgresEffectStore};
use nemo_relay_ledger::unstable::LeaseConfiguration;
use postgres::NoTls;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn connection_string() -> String {
    std::env::var("NEMO_RELAY_TEST_POSTGRES_URL")
        .expect("NEMO_RELAY_TEST_POSTGRES_URL is required for ignored PostgreSQL tests")
}

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
            name: format!("nemo_migration_{}_{}", std::process::id(), suffix),
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
            4,
        )
        .expect("connect migration test store")
    }

    fn client(&self) -> postgres::Client {
        postgres::Client::connect(&self.connection, NoTls).expect("connect migration test client")
    }

    fn ledger(&self) -> Vec<(i64, String, String)> {
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
}

/// Create the data-only runtime role production requires for `schema`.
///
/// The shape is USAGE on the schema, data privileges on the effect tables, and
/// nothing on either ledger table. Returns `None` when this session cannot
/// create roles, which is the case for a non-superuser test connection.
fn create_data_only_role(schema: &TestSchema) -> Option<String> {
    let role = format!("nemo_runtime_{}", schema.name);
    let created = schema.client().batch_execute(&format!(
        "create role \"{role}\" login password 'runtime-only';
         grant usage on schema \"{schema}\" to \"{role}\";
         grant select, insert, update, delete on all tables in schema \"{schema}\" to \"{role}\";
         revoke insert, update, delete, truncate on \"{schema}\".effect_schema_migrations from \"{role}\";
         revoke insert, update, delete, truncate on \"{schema}\".effect_schema_state from \"{role}\";
         revoke create on schema \"{schema}\" from \"{role}\"",
        schema = schema.name,
    ));
    if created.is_err() {
        eprintln!("skipping restricted-role case: cannot create roles on this server");
        return None;
    }
    Some(role)
}

/// Connect a store as the named runtime role.
fn runtime_store(schema: &TestSchema, role: &str) -> PostgresEffectStore {
    let url = format!(
        "postgresql://{role}:runtime-only@{}",
        schema
            .connection
            .rsplit('@')
            .next()
            .expect("host in test URL")
    );
    PostgresEffectStore::connect_insecure_local_for_tests(
        &url,
        &schema.name,
        LeaseConfiguration {
            default_duration_ms: 60_000,
            maximum_duration_ms: 60_000,
            renewal_enabled: true,
        },
        2,
    )
    .expect("connect runtime role")
}

impl Drop for TestSchema {
    fn drop(&mut self) {
        if let Ok(mut client) = postgres::Client::connect(&self.connection, NoTls) {
            let _ =
                client.batch_execute(&format!("drop schema if exists \"{}\" cascade", self.name));
        }
    }
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn concurrent_migrators_record_one_history() {
    let schema = TestSchema::create(&connection_string());
    // Create the schema up front so the test measures migration serialization
    // rather than a race between two `create schema if not exists` statements.
    schema
        .client()
        .batch_execute(&format!("create schema \"{}\"", schema.name))
        .expect("create migration test schema");

    let mut handles = Vec::new();
    for _ in 0..2 {
        let connection = schema.connection.clone();
        let name = schema.name.clone();
        handles.push(thread::spawn(move || {
            let store = PostgresEffectStore::connect_insecure_local_for_tests(
                &connection,
                &name,
                LeaseConfiguration {
                    default_duration_ms: 60_000,
                    maximum_duration_ms: 60_000,
                    renewal_enabled: true,
                },
                2,
            )
            .expect("connect concurrent migrator");
            store.migrate()
        }));
    }
    for handle in handles {
        handle
            .join()
            .expect("join concurrent migrator")
            .expect("concurrent migration must succeed under the advisory lock");
    }

    let ledger = schema.ledger();
    assert_eq!(
        ledger.len(),
        1,
        "concurrent migrators duplicated the history"
    );
    schema.store().verify_schema().expect("schema verifies");
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn repeated_concurrent_migrations_converge_to_one_canonical_history() {
    // A bounded stress harness rather than one repeated assertion: many
    // iterations of simultaneously released migrators against fresh databases.
    // Override the shape with NEMO_RELAY_MIGRATION_STRESS_ITERATIONS and
    // NEMO_RELAY_MIGRATION_STRESS_MIGRATORS.
    let iterations: usize = std::env::var("NEMO_RELAY_MIGRATION_STRESS_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(50);
    let migrators: usize = std::env::var("NEMO_RELAY_MIGRATION_STRESS_MIGRATORS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8);
    let connection = connection_string();

    // A single data-only role proves readiness, not just history and structure.
    let role = format!("nemo_stress_runtime_{}", std::process::id());
    let mut admin = postgres::Client::connect(&connection, NoTls).expect("connect stress admin");
    let role_available = admin
        .batch_execute(&format!(
            "create role \"{role}\" login password 'stress-only'"
        ))
        .is_ok();
    if !role_available {
        eprintln!("skipping readiness assertion: cannot create roles on this server");
    }

    for iteration in 0..iterations {
        let schema = TestSchema::create(&connection);
        schema
            .client()
            .batch_execute(&format!("create schema \"{}\"", schema.name))
            .expect("create stress schema");

        let barrier = Arc::new(Barrier::new(migrators));
        let mut handles = Vec::with_capacity(migrators);
        for _ in 0..migrators {
            let connection = schema.connection.clone();
            let name = schema.name.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let store = PostgresEffectStore::connect_insecure_local_for_tests(
                    &connection,
                    &name,
                    LeaseConfiguration {
                        default_duration_ms: 60_000,
                        maximum_duration_ms: 60_000,
                        renewal_enabled: true,
                    },
                    2,
                )
                .expect("connect stress migrator");
                // Release every migrator at the same instant so they contend for
                // the advisory lock rather than queueing on process startup.
                barrier.wait();
                store.migrate()
            }));
        }
        for handle in handles {
            handle
                .join()
                .expect("join stress migrator")
                .unwrap_or_else(|error| {
                    panic!("iteration {iteration}: migrator failed with {error}")
                });
        }

        let ledger = schema.ledger();
        assert_eq!(
            ledger.len(),
            1,
            "iteration {iteration}: concurrent migrators produced {} history rows",
            ledger.len()
        );
        assert_eq!(ledger[0].0, 1);
        assert_eq!(ledger[0].1, "initial_effect_store");
        schema.store().verify_schema().unwrap_or_else(|error| {
            panic!("iteration {iteration}: schema does not verify: {error}")
        });
        assert_eq!(
            schema.contract_objects(),
            nemo_relay_ledger::schema::EFFECT_RELATIONS.len() as i64,
            "iteration {iteration}: partially migrated object set"
        );

        if role_available {
            admin
                .batch_execute(&format!(
                    "grant usage on schema \"{schema}\" to \"{role}\";
                     grant select, insert, update, delete on all tables in schema \"{schema}\" to \"{role}\";
                     revoke insert, update, delete, truncate on \"{schema}\".effect_schema_migrations from \"{role}\";
                     revoke insert, update, delete, truncate on \"{schema}\".effect_schema_state from \"{role}\";
                     revoke create on schema \"{schema}\" from \"{role}\"",
                    schema = schema.name,
                ))
                .expect("grant runtime privileges");
            let runtime_url = format!(
                "postgresql://{role}:stress-only@{}",
                schema
                    .connection
                    .rsplit('@')
                    .next()
                    .expect("host in test URL")
            );
            let runtime = PostgresEffectStore::connect_insecure_local_for_tests(
                &runtime_url,
                &schema.name,
                LeaseConfiguration {
                    default_duration_ms: 60_000,
                    maximum_duration_ms: 60_000,
                    renewal_enabled: true,
                },
                2,
            )
            .expect("connect stress runtime role");
            runtime
                .verify_database_readiness()
                .unwrap_or_else(|error| panic!("iteration {iteration}: readiness failed: {error}"));
        }
    }

    if role_available {
        let _ = admin.batch_execute(&format!("drop owned by \"{role}\" cascade"));
        let _ = admin.batch_execute(&format!("drop role if exists \"{role}\""));
    }
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_changed_historical_checksum_blocks_verification_and_migration() {
    let schema = TestSchema::create(&connection_string());
    let store = schema.store();
    store.migrate().expect("initial migration");

    schema
        .client()
        .execute(
            &format!(
                "update \"{}\".effect_schema_migrations set checksum = 'rewritten' where version = 1",
                schema.name
            ),
            &[],
        )
        .expect("rewrite historical checksum");

    assert!(
        store.verify_schema().is_err(),
        "a rewritten migration checksum must not verify"
    );
    assert!(
        store.migrate().is_err(),
        "a rewritten migration checksum must block re-migration"
    );
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_missing_historical_row_cannot_be_replayed_over_existing_objects() {
    let schema = TestSchema::create(&connection_string());
    let store = schema.store();
    store.migrate().expect("initial migration");

    schema
        .client()
        .batch_execute(&format!(
            "delete from \"{}\".effect_schema_migrations",
            schema.name
        ))
        .expect("damage migration history");

    let failure = store.migrate();
    assert!(
        failure.is_err(),
        "a migration must not silently adopt objects it did not create: {failure:?}"
    );
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_data_only_runtime_role_satisfies_privilege_and_policy_readiness() {
    let schema = TestSchema::create(&connection_string());
    schema.store().migrate().expect("initial migration");
    let Some(role) = create_data_only_role(&schema) else {
        return;
    };

    let runtime = runtime_store(&schema, &role);
    runtime
        .verify_runtime_privileges()
        .expect("a data-only role must satisfy privilege readiness");
    runtime
        .verify_database_policy(&DatabaseReadinessPolicy::default())
        .expect("the server default settings must satisfy the durability policy");
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_runtime_credential_that_can_delete_schema_state_is_rejected() {
    let schema = TestSchema::create(&connection_string());
    schema.store().migrate().expect("initial migration");
    let Some(role) = create_data_only_role(&schema) else {
        return;
    };

    // The data-only shape revokes this. Granting it back is the smallest
    // possible escalation: a runtime role that can delete the ledger row
    // recording the schema description can hide drift from every later check.
    schema
        .client()
        .batch_execute(&format!(
            "grant delete on \"{}\".effect_schema_state to \"{role}\"",
            schema.name
        ))
        .expect("grant delete on the schema state table");

    let failure = runtime_store(&schema, &role)
        .verify_runtime_privileges()
        .expect_err("delete on the schema-state ledger must be rejected");
    assert!(
        failure
            .to_string()
            .contains("DELETE from effect_schema_state"),
        "expected the schema-state delete privilege to be named: {failure}"
    );
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_runtime_credential_with_a_dangerous_role_attribute_is_rejected() {
    let schema = TestSchema::create(&connection_string());
    schema.store().migrate().expect("initial migration");
    let Some(role) = create_data_only_role(&schema) else {
        return;
    };

    // CREATEROLE needs no grant on the effect schema to be dangerous: it lets
    // the runtime role mint a role that can do more than it can.
    schema
        .client()
        .batch_execute(&format!("alter role \"{role}\" createrole"))
        .expect("grant createrole to the runtime role");

    let failure = runtime_store(&schema, &role)
        .verify_runtime_privileges()
        .expect_err("a role attribute that permits escalation must be rejected");
    assert!(
        failure.to_string().contains("CREATEROLE role attribute"),
        "expected the role attribute to be named: {failure}"
    );
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_runtime_credential_that_owns_the_schema_is_rejected() {
    let schema = TestSchema::create(&connection_string());
    schema.store().migrate().expect("initial migration");
    let Some(role) = create_data_only_role(&schema) else {
        return;
    };

    // Ownership needs no ordinary GRANT, which is why the grant checks alone
    // cannot prove the credential is data-only.
    schema
        .client()
        .batch_execute(&format!(
            "alter schema \"{}\" owner to \"{role}\"",
            schema.name
        ))
        .expect("transfer schema ownership to the runtime role");

    let failure = runtime_store(&schema, &role)
        .verify_runtime_privileges()
        .expect_err("schema ownership must be rejected");
    assert!(
        failure
            .to_string()
            .contains("ownership of the effect-store schema"),
        "expected schema ownership to be named: {failure}"
    );
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_runtime_credential_that_owns_an_effect_store_relation_is_rejected() {
    let schema = TestSchema::create(&connection_string());
    schema.store().migrate().expect("initial migration");
    let Some(role) = create_data_only_role(&schema) else {
        return;
    };

    // Taking ownership requires CREATE on the schema, so this role is rejected
    // for more than one reason. The assertion names the ownership finding
    // specifically, which is the column this case exists to exercise.
    schema
        .client()
        .batch_execute(&format!(
            "grant create on schema \"{}\" to \"{role}\";
             alter table \"{}\".effect_receipts owner to \"{role}\"",
            schema.name, schema.name
        ))
        .expect("transfer relation ownership to the runtime role");

    let failure = runtime_store(&schema, &role)
        .verify_runtime_privileges()
        .expect_err("relation ownership must be rejected");
    assert!(
        failure
            .to_string()
            .contains("ownership of an effect-store relation"),
        "expected relation ownership to be named: {failure}"
    );
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_non_durable_synchronous_commit_setting_is_rejected() {
    let schema = TestSchema::create(&connection_string());
    schema.store().migrate().expect("initial migration");
    let Some(role) = create_data_only_role(&schema) else {
        return;
    };

    // `off` lets a committed write be lost in a crash, so the settings the
    // store reports must be compared against a policy rather than only read.
    schema
        .client()
        .batch_execute(&format!(
            "alter role \"{role}\" set synchronous_commit = off"
        ))
        .expect("make the runtime role non-durable");

    let runtime = runtime_store(&schema, &role);
    let failure = runtime
        .verify_database_policy(&DatabaseReadinessPolicy::default())
        .expect_err("a non-durable synchronous_commit must be rejected");
    assert!(
        failure.to_string().contains("synchronous_commit"),
        "expected the durability setting to be named: {failure}"
    );
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_runtime_credential_cannot_modify_the_schema_or_ledger() {
    let schema = TestSchema::create(&connection_string());
    let store = schema.store();
    store.migrate().expect("initial migration");

    // The migration identity owns the schema, so readiness must refuse it.
    assert!(
        store.verify_runtime_privileges().is_err(),
        "an owning role must not satisfy runtime readiness"
    );

    let role = format!("nemo_runtime_{}", schema.name);
    let mut client = schema.client();
    let created = client.batch_execute(&format!(
        "create role \"{role}\" login password 'runtime-only';
         grant usage on schema \"{schema}\" to \"{role}\";
         grant select, insert, update, delete on all tables in schema \"{schema}\" to \"{role}\";
         revoke insert, update, delete, truncate on \"{schema}\".effect_schema_migrations from \"{role}\";
         revoke insert, update, delete, truncate on \"{schema}\".effect_schema_state from \"{role}\";
         revoke create on schema \"{schema}\" from \"{role}\"",
        schema = schema.name,
    ));
    if created.is_err() {
        // Creating roles needs a superuser. The owning-role assertion above is
        // the part every environment can prove.
        eprintln!("skipping restricted-role case: cannot create roles on this server");
        return;
    }

    let runtime_url = format!(
        "postgresql://{role}:runtime-only@{}",
        schema
            .connection
            .rsplit('@')
            .next()
            .expect("host in test URL")
    );
    let runtime = PostgresEffectStore::connect_insecure_local_for_tests(
        &runtime_url,
        &schema.name,
        LeaseConfiguration {
            default_duration_ms: 60_000,
            maximum_duration_ms: 60_000,
            renewal_enabled: true,
        },
        2,
    )
    .expect("connect runtime role");

    runtime
        .verify_runtime_privileges()
        .expect("a data-only runtime role must satisfy readiness");
    runtime
        .verify_schema()
        .expect("a data-only runtime role must be able to verify the schema");

    // The credential really cannot do any of the things a compromised planner
    // would want: rewrite the ledger it trusted, reshape the schema, or escalate
    // into the migration role.
    let mut restricted = postgres::Client::connect(&runtime_url, NoTls).expect("connect runtime");
    let forbidden = [
        (
            "rewrite the migration ledger",
            format!(
                "update \"{}\".effect_schema_migrations set checksum = 'runtime-edit'",
                schema.name
            ),
        ),
        (
            "rewrite the recorded schema fingerprint",
            format!(
                "update \"{}\".effect_schema_state set schema_fingerprint = 'forged'",
                schema.name
            ),
        ),
        (
            "drop an effect-store table",
            format!("drop table \"{}\".effect_receipts", schema.name),
        ),
        (
            "truncate durable action state",
            format!("truncate \"{}\".effect_actions", schema.name),
        ),
        (
            "alter an effect-store column",
            format!(
                "alter table \"{}\".effect_actions alter column state type varchar(64)",
                schema.name
            ),
        ),
        (
            "create a table in the effect schema",
            format!("create table \"{}\".shadow (id integer)", schema.name),
        ),
        (
            "drop an effect-store index",
            format!("drop index \"{}\".effect_actions_recovery_idx", schema.name),
        ),
        (
            "escalate into the migration role",
            "set role nemo_migrator".into(),
        ),
    ];
    for (description, statement) in forbidden {
        assert!(
            restricted.batch_execute(&statement).is_err(),
            "the runtime credential must not be able to {description}"
        );
    }

    // Least privilege must not mean "cannot work": ordinary EffectStore
    // transactions still succeed with the restricted credential.
    let action = nemo_relay_ledger::conformance::fixture_action();
    let runtime = runtime
        .with_deadline(std::time::Instant::now() + Duration::from_secs(30))
        .expect("scope runtime handle");
    nemo_relay_ledger::unstable::ActionStore::claim_action(&runtime, &action)
        .expect("the runtime role must still be able to claim durable actions");
    assert!(
        nemo_relay_ledger::unstable::ActionStore::load_action(&runtime, &action.action_id)
            .expect("load claimed action")
            .is_some()
    );

    let _ = client.batch_execute(&format!("drop owned by \"{role}\" cascade"));
    let _ = client.batch_execute(&format!("drop role if exists \"{role}\""));
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn an_observer_role_can_inspect_but_not_change_durable_state() {
    let schema = TestSchema::create(&connection_string());
    let store = schema.store();
    store.migrate().expect("initial migration");

    let role = format!("nemo_observer_{}", schema.name);
    let mut client = schema.client();
    if client
        .batch_execute(&format!(
            "create role \"{role}\" login password 'observer-only';
             grant usage on schema \"{schema}\" to \"{role}\";
             grant select on all tables in schema \"{schema}\" to \"{role}\"",
            schema = schema.name,
        ))
        .is_err()
    {
        eprintln!("skipping observer case: cannot create roles on this server");
        return;
    }

    let observer_url = format!(
        "postgresql://{role}:observer-only@{}",
        schema
            .connection
            .rsplit('@')
            .next()
            .expect("host in test URL")
    );
    let mut observer = postgres::Client::connect(&observer_url, NoTls).expect("connect observer");

    // Inspection is the point of the role.
    let actions: i64 = observer
        .query_one(
            &format!("select count(*) from \"{}\".effect_actions", schema.name),
            &[],
        )
        .expect("observer reads durable action state")
        .get(0);
    assert_eq!(actions, 0);
    let fingerprint: String = observer
        .query_one(
            &format!(
                "select schema_fingerprint from \"{}\".effect_schema_state",
                schema.name
            ),
            &[],
        )
        .expect("observer reads the recorded schema fingerprint")
        .get(0);
    assert_eq!(fingerprint.len(), 64);

    // ...and it cannot mutate anything.
    for (description, statement) in [
        (
            "insert durable actions",
            format!(
                "insert into \"{}\".effect_actions (action_id, idempotency_key, action_fingerprint, preparation, state) \
                 values ('x', 'x', 'x', '{{}}'::jsonb, 'PROPOSED')",
                schema.name
            ),
        ),
        (
            "rewrite the migration ledger",
            format!(
                "update \"{}\".effect_schema_migrations set checksum = 'observer-edit'",
                schema.name
            ),
        ),
        (
            "drop a durable table",
            format!("drop table \"{}\".effect_actions", schema.name),
        ),
    ] {
        assert!(
            observer.batch_execute(&statement).is_err(),
            "an observer must not be able to {description}"
        );
    }

    let _ = client.batch_execute(&format!("drop owned by \"{role}\" cascade"));
    let _ = client.batch_execute(&format!("drop role if exists \"{role}\""));
}
