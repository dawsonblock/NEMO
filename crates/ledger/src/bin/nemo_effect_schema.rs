// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Emit the canonical effect-store schema as reviewable qualification evidence.
//!
//! Pipeline: fresh PostgreSQL -> apply all migrations -> catalogue inspection ->
//! canonical schema JSON -> SHA-256 -> `expected-schema.json` and
//! `expected-schema.sha256`.
//!
//! The description is captured from a database this process migrates itself, so
//! it cannot inherit drift from an existing deployment. It is emitted as
//! evidence rather than compared against a checked-in constant because
//! PostgreSQL catalogue deparsers are not contract-stable across server majors:
//! an expectation captured on one major must not be compared with a database on
//! another. The output records the server major it belongs to.

use nemo_relay_ledger::postgres::PostgresEffectStore;
use nemo_relay_ledger::unstable::LeaseConfiguration;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let mut arguments = std::env::args().skip(1);
    let output_directory: PathBuf = arguments
        .next()
        .expect("usage: nemo-effect-schema <output-directory>")
        .into();
    assert!(arguments.next().is_none(), "unexpected extra argument");

    let connection = std::env::var("NEMO_RELAY_TEST_POSTGRES_URL")
        .expect("NEMO_RELAY_TEST_POSTGRES_URL is required to capture the schema");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    let schema = format!("nemo_schema_evidence_{}_{}", std::process::id(), nanos);

    let store = PostgresEffectStore::connect_insecure_local_for_tests(
        &connection,
        &schema,
        LeaseConfiguration {
            default_duration_ms: 60_000,
            maximum_duration_ms: 60_000,
            renewal_enabled: true,
        },
        2,
    )
    .expect("connect schema evidence store");
    store.migrate().expect("migrate schema evidence store");
    let model = store.schema_model().expect("capture canonical schema");
    let json = model.to_json().expect("render canonical schema");
    let digest: String = Sha256::digest(
        serde_json_canonicalizer::to_vec(&model)
            .expect("canonicalise schema")
            .as_slice(),
    )
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect();

    std::fs::create_dir_all(&output_directory).expect("create evidence directory");
    std::fs::write(output_directory.join("expected-schema.json"), json + "\n")
        .expect("write canonical schema");
    std::fs::write(
        output_directory.join("expected-schema.sha256"),
        format!("{digest}\n"),
    )
    .expect("write canonical schema digest");

    drop(store);
    let mut client = postgres::Client::connect(&connection, postgres::NoTls)
        .expect("connect for schema evidence cleanup");
    client
        .batch_execute(&format!("drop schema if exists \"{schema}\" cascade"))
        .expect("remove schema evidence database");
    println!(
        "schema={} server_major={} digest={digest}",
        model.schema, model.server_major
    );
}
