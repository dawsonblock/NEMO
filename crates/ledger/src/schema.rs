// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Physical PostgreSQL schema verification for the durable effect store.
//!
//! Verifying the migration ledger proves that *this runtime recorded the
//! migrations it recognises*. It says nothing about the objects those
//! migrations were supposed to create. A database with an intact ledger and a
//! dropped index, a retyped column, a removed `NOT NULL`, or an extra trigger
//! would satisfy a ledger-only check.
//!
//! This module builds a canonical, deterministic description of the physical
//! schema from the PostgreSQL catalogs, serialises it with RFC 8785 canonical
//! JSON, and hashes it. The description is recorded when the schema is migrated
//! and compared at readiness time, and it is emitted as qualification evidence
//! so a human can review the full structure.
//!
//! Structure only. Row data, OIDs, physical locations, creation order, and
//! backend-local identifiers are all excluded, so recording the expected value
//! inside the schema it describes creates no self-reference.

use crate::postgres::{PostgresEffectStoreError, SchemaObjectKind, schema_query_error};
use postgres::GenericClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Identifier for the canonical schema model.
pub const SCHEMA_MODEL: &str = "nemo.effect-store.pg.v1";

/// Version of the canonical model and its canonicalization.
///
/// A change to the model or the canonical form invalidates every recorded
/// fingerprint, so a database migrated under an older algorithm fails
/// verification instead of being compared with incompatible semantics.
pub const SCHEMA_MODEL_VERSION: u32 = 1;

/// Relations the durable effect-store contract owns.
///
/// The fingerprint covers these relations and everything attached to them:
/// columns, constraints, indexes, and triggers. Objects that merely share the
/// schema are not part of the EffectStore contract, so a co-tenant of the same
/// schema cannot make verification fail. Isolation of the schema itself is
/// enforced at migration time instead.
pub const EFFECT_RELATIONS: &[&str] = &[
    "effect_actions",
    "effect_receipts",
    "effect_receipt_conflicts",
    "effect_schema_state",
    "effect_schema_migrations",
];

/// Return whether a relation name belongs to the effect-store contract.
pub fn is_contract_relation(name: &str) -> bool {
    EFFECT_RELATIONS.contains(&name)
}

/// One column of one contract relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalColumn {
    /// Column name.
    pub name: String,
    /// Rendered SQL type.
    pub data_type: String,
    /// Whether the column rejects nulls.
    pub not_null: bool,
    /// `s` for a stored generated column, empty otherwise.
    pub generated: String,
    /// Rendered default or generation expression.
    pub default: String,
    /// Explicit collation, when the column has one.
    pub collation: String,
}

/// One constraint of one contract relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalConstraint {
    /// Constraint name.
    pub name: String,
    /// Constraint type character (`p`, `u`, `f`, `c`, `x`).
    pub kind: String,
    /// Rendered constraint definition.
    pub definition: String,
    /// Whether the constraint may be deferred.
    pub deferrable: bool,
    /// Whether existing rows were validated against the constraint.
    pub validated: bool,
}

/// One index of one contract relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalIndex {
    /// Index name.
    pub name: String,
    /// Whether the index enforces uniqueness.
    pub unique: bool,
    /// Whether the index backs the primary key.
    pub primary: bool,
    /// Whether PostgreSQL considers the index valid.
    pub valid: bool,
    /// Access method, such as `btree`.
    pub method: String,
    /// Rendered index definition.
    pub definition: String,
    /// Partial-index predicate, when the index is partial.
    pub predicate: String,
}

/// One user-defined trigger of one contract relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalTrigger {
    /// Trigger name.
    pub name: String,
    /// Rendered trigger definition.
    pub definition: String,
}

/// One contract relation with everything attached to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalTable {
    /// Relation name.
    pub name: String,
    /// Columns, ordered by name.
    pub columns: Vec<CanonicalColumn>,
    /// Constraints, ordered by name.
    pub constraints: Vec<CanonicalConstraint>,
    /// Indexes, ordered by name.
    pub indexes: Vec<CanonicalIndex>,
    /// User-defined triggers, ordered by name.
    pub triggers: Vec<CanonicalTrigger>,
}

/// Deterministic, human-reviewable description of the effect-store schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalSchema {
    /// Canonical model identifier.
    pub schema: String,
    /// Canonical model version.
    pub schema_version: u32,
    /// Server major the description was captured on.
    ///
    /// Catalogue deparsers (`pg_get_constraintdef`, `pg_get_indexdef`) are not
    /// contract-stable across server majors, so a captured description records
    /// the major it belongs to instead of being compared across majors.
    pub server_major: i32,
    /// Contract relations, ordered by name.
    pub tables: Vec<CanonicalTable>,
}

impl CanonicalSchema {
    /// Serialise with RFC 8785 canonical JSON.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PostgresEffectStoreError> {
        serde_json_canonicalizer::to_vec(self).map_err(PostgresEffectStoreError::Serialization)
    }

    /// Return the SHA-256 over the canonical serialization.
    pub fn digest(&self) -> Result<String, PostgresEffectStoreError> {
        Ok(Sha256::digest(self.canonical_bytes()?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    /// Return the pretty JSON form used for evidence and human review.
    pub fn to_json(&self) -> Result<String, PostgresEffectStoreError> {
        serde_json::to_string_pretty(self).map_err(PostgresEffectStoreError::Serialization)
    }
}

/// Normalize catalog-rendered expressions.
///
/// The schema name is normalised out so the model is independent of where the
/// store lives, casts are stripped, and whitespace is collapsed so formatting
/// changes in the deparser do not register as drift.
fn normalize(expression: Option<String>, schema: &str) -> String {
    match expression {
        None => String::new(),
        Some(value) => value
            .replace(&format!("\"{schema}\"."), "__SCHEMA__.")
            .replace(&format!("{schema}."), "__SCHEMA__.")
            .replace("::text", "")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// Capture the physical schema description for one effect-store schema.
///
/// The result depends only on structure, so writing actions, receipts, or
/// conflict rows cannot change it.
pub fn capture(
    client: &mut impl GenericClient,
    schema: &str,
) -> Result<CanonicalSchema, PostgresEffectStoreError> {
    let server_major: i32 = client
        .query_one(
            "select current_setting('server_version_num')::integer / 10000",
            &[],
        )
        .map_err(schema_query_error)?
        .get(0);

    let columns = client
        .query(
            "select c.relname, a.attname, format_type(a.atttypid, a.atttypmod), \
             a.attnotnull, a.attgenerated::text, \
             case when a.atthasdef then pg_get_expr(d.adbin, d.adrelid) end, \
             coalesce(col.collname, '') \
             from pg_class c \
             join pg_namespace n on n.oid = c.relnamespace \
             join pg_attribute a on a.attrelid = c.oid \
             left join pg_attrdef d on d.adrelid = c.oid and d.adnum = a.attnum \
             left join pg_collation col on col.oid = a.attcollation \
             where n.nspname = $1 and c.relkind in ('r', 'p') and c.relname = any($2) \
             and a.attnum > 0 and not a.attisdropped \
             order by c.relname, a.attname",
            &[&schema, &EFFECT_RELATIONS],
        )
        .map_err(schema_query_error)?;

    let constraints = client
        .query(
            "select c.relname, con.conname, con.contype::text, \
             pg_get_constraintdef(con.oid), con.condeferrable, con.convalidated \
             from pg_constraint con \
             join pg_class c on c.oid = con.conrelid \
             join pg_namespace n on n.oid = c.relnamespace \
             where n.nspname = $1 and c.relname = any($2) \
             order by c.relname, con.conname",
            &[&schema, &EFFECT_RELATIONS],
        )
        .map_err(schema_query_error)?;

    let indexes = client
        .query(
            "select c.relname, ic.relname, i.indisunique, i.indisprimary, \
             i.indisvalid, am.amname, pg_get_indexdef(i.indexrelid), \
             pg_get_expr(i.indpred, i.indrelid) \
             from pg_index i \
             join pg_class c on c.oid = i.indrelid \
             join pg_class ic on ic.oid = i.indexrelid \
             join pg_namespace n on n.oid = c.relnamespace \
             join pg_am am on am.oid = ic.relam \
             where n.nspname = $1 and c.relname = any($2) \
             order by c.relname, ic.relname",
            &[&schema, &EFFECT_RELATIONS],
        )
        .map_err(schema_query_error)?;

    let triggers = client
        .query(
            "select c.relname, t.tgname, pg_get_triggerdef(t.oid) \
             from pg_trigger t \
             join pg_class c on c.oid = t.tgrelid \
             join pg_namespace n on n.oid = c.relnamespace \
             where n.nspname = $1 and not t.tgisinternal and c.relname = any($2) \
             order by c.relname, t.tgname",
            &[&schema, &EFFECT_RELATIONS],
        )
        .map_err(schema_query_error)?;

    let mut tables: Vec<CanonicalTable> = Vec::new();
    let table_for = |name: &str, tables: &mut Vec<CanonicalTable>| {
        if let Some(index) = tables.iter().position(|table| table.name == name) {
            return index;
        }
        tables.push(CanonicalTable {
            name: name.to_owned(),
            columns: Vec::new(),
            constraints: Vec::new(),
            indexes: Vec::new(),
            triggers: Vec::new(),
        });
        tables.len() - 1
    };

    for row in &columns {
        let table: String = row.get(0);
        let index = table_for(&table, &mut tables);
        tables[index].columns.push(CanonicalColumn {
            name: row.get(1),
            data_type: row.get(2),
            not_null: row.get(3),
            generated: row.get(4),
            default: normalize(row.get(5), schema),
            collation: row.get(6),
        });
    }
    for row in &constraints {
        let table: String = row.get(0);
        let index = table_for(&table, &mut tables);
        tables[index].constraints.push(CanonicalConstraint {
            name: row.get(1),
            kind: row.get(2),
            definition: normalize(Some(row.get(3)), schema),
            deferrable: row.get(4),
            validated: row.get(5),
        });
    }
    for row in &indexes {
        let table: String = row.get(0);
        let index = table_for(&table, &mut tables);
        tables[index].indexes.push(CanonicalIndex {
            name: row.get(1),
            unique: row.get(2),
            primary: row.get(3),
            valid: row.get(4),
            method: row.get(5),
            definition: normalize(Some(row.get(6)), schema),
            predicate: normalize(row.get(7), schema),
        });
    }
    for row in &triggers {
        let table: String = row.get(0);
        let index = table_for(&table, &mut tables);
        tables[index].triggers.push(CanonicalTrigger {
            name: row.get(1),
            definition: normalize(Some(row.get(2)), schema),
        });
    }

    // Deterministic ordering everywhere: a hash must not depend on the order a
    // catalogue happened to return rows in.
    tables.sort_by(|left, right| left.name.cmp(&right.name));
    for table in &mut tables {
        table
            .columns
            .sort_by(|left, right| left.name.cmp(&right.name));
        table
            .constraints
            .sort_by(|left, right| left.name.cmp(&right.name));
        table
            .indexes
            .sort_by(|left, right| left.name.cmp(&right.name));
        table
            .triggers
            .sort_by(|left, right| left.name.cmp(&right.name));
    }

    Ok(CanonicalSchema {
        schema: SCHEMA_MODEL.to_owned(),
        schema_version: SCHEMA_MODEL_VERSION,
        server_major,
        tables,
    })
}

/// Return relations in ``schema`` that the effect-store contract does not own.
///
/// A schema that already contains foreign objects cannot be claimed by the
/// migration that is about to create the effect store, so this is checked before
/// the first migration records anything.
pub fn foreign_relations(
    client: &mut impl GenericClient,
    schema: &str,
) -> Result<Vec<String>, PostgresEffectStoreError> {
    let rows = client
        .query(
            "select c.relname from pg_class c \
             join pg_namespace n on n.oid = c.relnamespace \
             where n.nspname = $1 and c.relkind in ('r', 'p', 'S', 'v', 'm', 'f') \
             and not (c.relname = any($2)) \
             order by c.relname",
            &[&schema, &EFFECT_RELATIONS],
        )
        .map_err(schema_query_error)?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// Expected schema recorded when the migrations that built it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedSchema {
    /// Canonicalization version the description was captured with.
    pub model_version: u32,
    /// Server major the description was captured on.
    pub server_major: i32,
    /// Digest of the canonical description.
    pub digest: String,
    /// The full canonical description.
    pub expected: CanonicalSchema,
}

/// Read the schema description recorded when the schema was migrated.
///
/// A missing record is a mismatch rather than "nothing to verify": a database
/// that cannot state its own expected schema cannot be verified.
pub fn recorded(
    client: &mut impl GenericClient,
    schema: &str,
) -> Result<RecordedSchema, PostgresEffectStoreError> {
    let row = client
        .query_opt(
            &format!(
                "select model_version, server_major, schema_fingerprint, schema_model \
                 from \"{schema}\".effect_schema_state where id"
            ),
            &[],
        )
        .map_err(schema_query_error)?;
    let Some(row) = row else {
        return Err(PostgresEffectStoreError::SchemaFingerprintMismatch(
            "the physical schema fingerprint is not recorded for this database".into(),
        ));
    };
    let model_version: i32 = row.get(0);
    let server_major: i32 = row.get(1);
    let digest: String = row.get(2);
    let model: serde_json::Value = row.get(3);
    let expected: CanonicalSchema =
        serde_json::from_value(model).map_err(PostgresEffectStoreError::Serialization)?;
    Ok(RecordedSchema {
        model_version: model_version as u32,
        server_major,
        digest,
        expected,
    })
}

/// Record the canonical description of the current physical schema.
pub fn record(
    client: &mut impl GenericClient,
    schema: &str,
    model: &CanonicalSchema,
) -> Result<(), PostgresEffectStoreError> {
    let digest = model.digest()?;
    let encoded = serde_json::to_value(model).map_err(PostgresEffectStoreError::Serialization)?;
    client.execute(
        &format!(
            "insert into \"{schema}\".effect_schema_state \
                 (id, model_version, server_major, schema_fingerprint, schema_model) \
                 values (true, $1, $2, $3, $4) \
                 on conflict (id) do update set \
                 model_version = excluded.model_version, \
                 server_major = excluded.server_major, \
                 schema_fingerprint = excluded.schema_fingerprint, \
                 schema_model = excluded.schema_model, \
                 recorded_at = clock_timestamp()"
        ),
        &[
            &(SCHEMA_MODEL_VERSION as i32),
            &model.server_major,
            &digest,
            &encoded,
        ],
    )?;
    Ok(())
}

/// Return the first structural difference between two captured schemas.
///
/// The comparison walks tables, then columns, constraints, indexes, and
/// triggers, so a caller learns *what* drifted rather than only that a digest
/// changed.
pub fn diff(
    expected: &CanonicalSchema,
    live: &CanonicalSchema,
) -> Option<(SchemaObjectKind, String)> {
    for expected_table in &expected.tables {
        let Some(live_table) = live
            .tables
            .iter()
            .find(|table| table.name == expected_table.name)
        else {
            return Some((
                SchemaObjectKind::MissingTable,
                format!("table {} is missing", expected_table.name),
            ));
        };
        if expected_table.columns != live_table.columns {
            return Some((
                SchemaObjectKind::Column,
                format!("columns of {} differ", expected_table.name),
            ));
        }
        if expected_table.constraints != live_table.constraints {
            return Some((
                SchemaObjectKind::Constraint,
                format!("constraints of {} differ", expected_table.name),
            ));
        }
        if expected_table.indexes != live_table.indexes {
            return Some((
                SchemaObjectKind::Index,
                format!("indexes of {} differ", expected_table.name),
            ));
        }
        if expected_table.triggers != live_table.triggers {
            return Some((
                SchemaObjectKind::Trigger,
                format!("triggers of {} differ", expected_table.name),
            ));
        }
    }
    for live_table in &live.tables {
        if !expected
            .tables
            .iter()
            .any(|table| table.name == live_table.name)
        {
            return Some((
                SchemaObjectKind::UnexpectedTable,
                format!(
                    "table {} is not part of the recorded schema",
                    live_table.name
                ),
            ));
        }
    }
    None
}

/// Compare the live physical schema against the recorded description.
pub fn verify(
    client: &mut impl GenericClient,
    schema: &str,
    live: &CanonicalSchema,
) -> Result<(), PostgresEffectStoreError> {
    let recorded = recorded(client, schema)?;
    verify_against(&recorded, live)
}

/// Compare a captured schema against a recorded description held in memory.
///
/// Split out so qualification tooling can verify a description it captured
/// elsewhere, such as the one emitted into the evidence bundle.
pub fn verify_against(
    recorded: &RecordedSchema,
    live: &CanonicalSchema,
) -> Result<(), PostgresEffectStoreError> {
    if recorded.model_version != SCHEMA_MODEL_VERSION {
        return Err(PostgresEffectStoreError::SchemaFingerprintMismatch(
            format!(
                "recorded schema model version {} does not match this runtime's version {}",
                recorded.model_version, SCHEMA_MODEL_VERSION
            ),
        ));
    }
    let live_digest = live.digest()?;
    if recorded.digest != live_digest {
        let (kind, detail) = diff(&recorded.expected, live).unwrap_or((
            SchemaObjectKind::DigestOnly,
            "canonical schema digest differs".into(),
        ));
        return Err(PostgresEffectStoreError::SchemaObjectMismatch { kind, detail });
    }
    Ok(())
}
