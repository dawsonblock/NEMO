// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL implementation of the experimental durable-effect store.
//!
//! The adapter is opt-in and does not change [`crate::DURABILITY_ENABLED`].
//! Every state mutation locks one action row, uses database-owned time, and
//! commits before control returns to a caller. External provider calls remain
//! outside this module and therefore cannot occur while a SQL transaction is
//! held open.

use crate::schema;
use crate::unstable::*;
use native_tls::{Certificate, Identity, Protocol, TlsConnector};
use postgres::config::{Host, SslMode, SslNegotiation};
use postgres::{Client, Config, GenericClient, IsolationLevel, NoTls, Row};
use postgres_native_tls::{MakeTlsConnector, set_postgresql_alpn};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

#[cfg(feature = "unstable-hardening-testkit")]
fn pause_at_test_crash_point(point: &str) {
    use std::io::Write;

    if std::env::var("NEMO_RELAY_POSTGRES_CRASH_POINT").as_deref() != Ok(point) {
        return;
    }
    let marker = std::env::var("NEMO_RELAY_POSTGRES_CRASH_MARKER")
        .expect("crash test marker path must be configured");
    let mut file = std::fs::File::create(marker).expect("create crash test marker");
    file.write_all(point.as_bytes())
        .expect("write crash test marker");
    file.sync_all().expect("sync crash test marker");
    loop {
        std::thread::park();
    }
}

#[cfg(not(feature = "unstable-hardening-testkit"))]
fn pause_at_test_crash_point(_point: &str) {}

impl crate::unstable::production_seal::Sealed for PostgresEffectStore {}

impl crate::unstable::ProductionEffectStore for PostgresEffectStore {
    type Error = PostgresEffectStoreError;

    fn verify_production_readiness(&self) -> Result<(), Self::Error> {
        Self::verify_production_readiness(self)
    }
}

/// Fail a durable operation at a named boundary, for qualification tests.
///
/// This exists so boundary semantics can be proven deterministically instead of
/// with sleeps or timing assumptions. It is inert unless the testkit feature is
/// enabled *and* the process was started with the matching fault point, so a
/// production build cannot reach it.
fn injected_database_failure(point: &str) -> Result<(), PostgresEffectStoreError> {
    #[cfg(feature = "unstable-hardening-testkit")]
    if std::env::var("NEMO_RELAY_POSTGRES_FAULT_POINT").as_deref() == Ok(point) {
        return Err(PostgresEffectStoreError::InjectedFailure(point.to_owned()));
    }
    let _ = point;
    Ok(())
}

type PlainManager = PostgresConnectionManager<NoTls>;
type TlsManager = PostgresConnectionManager<MakeTlsConnector>;

const POOL_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Explicit bounded PostgreSQL budgets for durable-effect operations.
///
/// The store applies these values to every checked-out session. They bound
/// database work only; callers must never treat a database timeout after
/// external dispatch as permission to repeat the provider request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresOperationBudgets {
    /// Maximum time spent waiting for a pooled connection.
    pub pool_acquire: Duration,
    /// Maximum time PostgreSQL may wait for a row or relation lock.
    pub lock: Duration,
    /// Maximum execution time for one PostgreSQL statement.
    pub statement: Duration,
    /// Maximum time a checked-out transaction may remain idle.
    pub idle_in_transaction: Duration,
}

/// Client identity material for a mutual-TLS PostgreSQL connection.
#[derive(Clone, PartialEq, Eq)]
pub struct PostgresMutualTlsCredentials {
    /// PEM-encoded trusted CA certificates.
    pub root_ca_pem: Vec<u8>,
    /// PKCS #12 client certificate and private key.
    pub client_identity_pkcs12: Vec<u8>,
    /// Password for the client identity.
    pub client_identity_password: String,
}

impl std::fmt::Debug for PostgresMutualTlsCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresMutualTlsCredentials")
            .field("root_ca_pem", &"[redacted]")
            .field("client_identity_pkcs12", &"[redacted]")
            .field("client_identity_password", &"[redacted]")
            .finish()
    }
}

impl Default for PostgresOperationBudgets {
    fn default() -> Self {
        Self {
            pool_acquire: POOL_CONNECTION_TIMEOUT,
            lock: Duration::from_secs(3),
            statement: Duration::from_secs(10),
            idle_in_transaction: Duration::from_secs(15),
        }
    }
}

impl PostgresOperationBudgets {
    /// Numerator of the share of a remaining action budget a lock wait may use.
    pub const LOCK_BUDGET_NUMERATOR: u32 = 1;
    /// Denominator of the share of a remaining action budget a lock wait may use.
    pub const LOCK_BUDGET_DENOMINATOR: u32 = 3;

    /// Derive session budgets from the remaining trusted action budget.
    ///
    /// The configured values stay maximum bounds. Each operation is instead
    /// bounded by what is left of the caller's trusted deadline, so a database
    /// wait can never outlive the action it belongs to:
    ///
    /// ```text
    /// lock_timeout      = min(configured_lock,      remaining / 3)
    /// statement_timeout = min(configured_statement, remaining)
    /// ```
    ///
    /// A zero or exhausted remaining budget is rejected rather than silently
    /// falling back to the static maximum.
    pub fn for_remaining(&self, remaining: Duration) -> Result<Self, PostgresEffectStoreError> {
        if remaining.is_zero() {
            return Err(PostgresEffectStoreError::InvalidOperationBudget(
                "remaining action budget",
            ));
        }
        let lock_share = remaining / Self::LOCK_BUDGET_DENOMINATOR;
        let derived = Self {
            pool_acquire: self.pool_acquire.min(remaining),
            lock: self.lock.min(lock_share),
            statement: self.statement.min(remaining),
            idle_in_transaction: self.idle_in_transaction.min(remaining),
        };
        derived.validate()?;
        Ok(derived)
    }

    /// Return the PostgreSQL session settings for these budgets.
    fn session_settings(&self) -> [(&'static str, u128); 3] {
        [
            ("lock_timeout", self.lock.as_millis()),
            ("statement_timeout", self.statement.as_millis()),
            (
                "idle_in_transaction_session_timeout",
                self.idle_in_transaction.as_millis(),
            ),
        ]
    }

    fn validate(&self) -> Result<(), PostgresEffectStoreError> {
        for (name, duration) in [
            ("pool_acquire", self.pool_acquire),
            ("lock", self.lock),
            ("statement", self.statement),
            ("idle_in_transaction", self.idle_in_transaction),
        ] {
            if duration.is_zero() || duration.as_millis() > i64::MAX as u128 {
                return Err(PostgresEffectStoreError::InvalidOperationBudget(name));
            }
        }
        if self.lock > self.statement {
            return Err(PostgresEffectStoreError::InvalidOperationBudget("lock"));
        }
        Ok(())
    }
}

#[derive(Clone)]
enum PostgresPool {
    Plain(Pool<PlainManager>),
    Tls(Pool<TlsManager>),
}

enum PostgresConnection {
    Plain(PooledConnection<PlainManager>),
    Tls(PooledConnection<TlsManager>),
}

fn validate_store_configuration(
    schema: &str,
    maximum_pool_size: u32,
    budgets: &PostgresOperationBudgets,
) -> Result<(), PostgresEffectStoreError> {
    validate_schema_name(schema)?;
    if maximum_pool_size == 0 {
        return Err(PostgresEffectStoreError::InvalidPoolSize(0));
    }
    budgets.validate()?;
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn validate_local_target(
    configuration: &Config,
    allow_loopback_tcp: bool,
) -> Result<(), PostgresEffectStoreError> {
    if configuration.get_hosts().is_empty() {
        return Err(PostgresEffectStoreError::InvalidTransport(
            "plaintext connections require an explicit Unix socket or loopback host".to_owned(),
        ));
    }

    for host in configuration.get_hosts() {
        match host {
            Host::Tcp(host) if allow_loopback_tcp && is_loopback_host(host) => {}
            Host::Tcp(host) if allow_loopback_tcp => {
                return Err(PostgresEffectStoreError::InvalidTransport(format!(
                    "plaintext TCP host {host:?} is not loopback"
                )));
            }
            Host::Tcp(host) => {
                return Err(PostgresEffectStoreError::InvalidTransport(format!(
                    "local-socket transport cannot use TCP host {host:?}"
                )));
            }
            #[cfg(unix)]
            Host::Unix(_) => {}
        }
    }

    if !allow_loopback_tcp && !configuration.get_hostaddrs().is_empty() {
        return Err(PostgresEffectStoreError::InvalidTransport(
            "local-socket transport cannot use hostaddr".to_owned(),
        ));
    }
    if allow_loopback_tcp
        && configuration
            .get_hostaddrs()
            .iter()
            .any(|address| !address.is_loopback())
    {
        return Err(PostgresEffectStoreError::InvalidTransport(
            "plaintext hostaddr is not loopback".to_owned(),
        ));
    }
    Ok(())
}

fn validate_tls_target(configuration: &Config) -> Result<(), PostgresEffectStoreError> {
    if configuration.get_hosts().is_empty() {
        return Err(PostgresEffectStoreError::InvalidTransport(
            "verified TLS requires an explicit TCP hostname".to_owned(),
        ));
    }
    for host in configuration.get_hosts() {
        match host {
            Host::Tcp(host) if !host.trim().is_empty() => {}
            Host::Tcp(_) => {
                return Err(PostgresEffectStoreError::InvalidTransport(
                    "verified TLS requires a non-empty TCP hostname".to_owned(),
                ));
            }
            #[cfg(unix)]
            Host::Unix(path) => {
                return Err(PostgresEffectStoreError::InvalidTransport(format!(
                    "verified TLS cannot use Unix socket {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

fn verified_tls_connector(
    configuration: &Config,
    root_ca_pem: &[u8],
    identity: Option<Identity>,
) -> Result<MakeTlsConnector, PostgresEffectStoreError> {
    verified_native_tls_connector(configuration, root_ca_pem, identity).map(MakeTlsConnector::new)
}

fn verified_native_tls_connector(
    configuration: &Config,
    root_ca_pem: &[u8],
    identity: Option<Identity>,
) -> Result<TlsConnector, PostgresEffectStoreError> {
    validate_tls_target(configuration)?;
    if root_ca_pem.is_empty() {
        return Err(PostgresEffectStoreError::InvalidTransport(
            "verified TLS requires at least one trusted CA certificate".to_owned(),
        ));
    }

    let root_certificates = Certificate::stack_from_pem(root_ca_pem)?;
    if root_certificates.is_empty() {
        return Err(PostgresEffectStoreError::InvalidTransport(
            "verified TLS requires at least one trusted CA certificate".to_owned(),
        ));
    }

    let mut builder = TlsConnector::builder();
    builder
        .disable_built_in_roots(true)
        .min_protocol_version(Some(Protocol::Tlsv12));
    for certificate in root_certificates {
        builder.add_root_certificate(certificate);
    }
    if let Some(identity) = identity {
        builder.identity(identity);
    }
    if configuration.get_ssl_negotiation() == SslNegotiation::Direct {
        set_postgresql_alpn(&mut builder);
    }
    Ok(builder.build()?)
}

fn build_plain_pool(
    manager: PlainManager,
    maximum_pool_size: u32,
    budgets: &PostgresOperationBudgets,
) -> Result<Pool<PlainManager>, PostgresEffectStoreError> {
    Pool::builder()
        .max_size(maximum_pool_size)
        .connection_timeout(budgets.pool_acquire)
        .build(manager)
        .map_err(Into::into)
}

fn build_tls_pool(
    manager: TlsManager,
    maximum_pool_size: u32,
    budgets: &PostgresOperationBudgets,
) -> Result<Pool<TlsManager>, PostgresEffectStoreError> {
    Pool::builder()
        .max_size(maximum_pool_size)
        .connection_timeout(budgets.pool_acquire)
        .build(manager)
        .map_err(Into::into)
}

impl Deref for PostgresConnection {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Plain(connection) => connection,
            Self::Tls(connection) => connection,
        }
    }
}

impl DerefMut for PostgresConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Plain(connection) => connection,
            Self::Tls(connection) => connection,
        }
    }
}

/// One immutable effect-store migration.
///
/// `sql` is the authoritative definition; the ledger records its SHA-256 as
/// `checksum`, so a rewritten migration file is detected rather than trusted.
/// `application_version` records the release that first applied the migration
/// and is never updated by a later runtime that merely observes it.
struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial_effect_store",
    sql: include_str!("../migrations/0001_effect_store.sql"),
}];

fn migration_checksum(sql: &str) -> String {
    Sha256::digest(sql.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Expected shape of the migration ledger, verified before it is trusted.
const MIGRATION_LEDGER_SHAPE: &[(&str, &str, bool)] = &[
    ("version", "bigint", true),
    ("name", "text", true),
    ("checksum", "text", true),
    ("application_version", "text", true),
    ("applied_at", "timestamp with time zone", true),
];

/// Apply bounded PostgreSQL session budgets to one checked-out connection.
/// One fenced terminalization: which action, under which lease, with which
/// evidence, bounded by which trusted budget.
struct Terminalization<'a> {
    action_id: &'a str,
    expected: ExecutionState,
    lease: &'a ActionLease,
    expected_evidence_revision: Option<u64>,
    receipt: &'a ReceiptRecord,
    remaining_action_budget: Option<Duration>,
    failure_point: &'a str,
}

/// Return the time left before a trusted action deadline.
fn remaining_deadline(deadline: Instant) -> Result<Duration, PostgresEffectStoreError> {
    deadline.checked_duration_since(Instant::now()).ok_or(
        PostgresEffectStoreError::InvalidOperationBudget("remaining action budget"),
    )
}

fn apply_operation_budgets(
    connection: &mut PostgresConnection,
    budgets: &PostgresOperationBudgets,
) -> Result<(), PostgresEffectStoreError> {
    for (name, milliseconds) in budgets.session_settings() {
        connection.query_one(
            "select set_config($1, $2, false)",
            &[&name, &milliseconds.to_string()],
        )?;
    }
    Ok(())
}

/// Reject a pre-existing migration ledger whose shape is not this contract.
///
/// `create table if not exists` cannot prove that an object it skipped is the
/// object this runtime needs. Verifying the columns immediately afterwards
/// closes that gap, so a mismatched ledger fails before any migration version is
/// recorded against it.
fn validate_migration_ledger_shape(
    client: &mut impl GenericClient,
    schema: &str,
) -> Result<(), PostgresEffectStoreError> {
    let rows = client
        .query(
            "select a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull \
             from pg_attribute a \
             join pg_class c on c.oid = a.attrelid \
             join pg_namespace n on n.oid = c.relnamespace \
             where n.nspname = $1 and c.relname = 'effect_schema_migrations' \
             and a.attnum > 0 and not a.attisdropped \
             order by a.attnum",
            &[&schema],
        )
        .map_err(schema_query_error)?;
    let actual: Vec<(String, String, bool)> = rows
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    let expected: Vec<(String, String, bool)> = MIGRATION_LEDGER_SHAPE
        .iter()
        .map(|(name, data_type, not_null)| ((*name).to_owned(), (*data_type).to_owned(), *not_null))
        .collect();
    if actual != expected {
        return Err(PostgresEffectStoreError::SchemaMismatch(format!(
            "effect_schema_migrations has an unexpected shape: expected {expected:?}, found {actual:?}"
        )));
    }
    Ok(())
}

pub(crate) fn schema_query_error(error: postgres::Error) -> PostgresEffectStoreError {
    if error
        .as_db_error()
        .is_some_and(|database| matches!(database.code().code(), "42P01" | "3F000"))
    {
        PostgresEffectStoreError::SchemaMismatch(
            "migration ledger is not installed for this effect-store schema".into(),
        )
    } else {
        PostgresEffectStoreError::Database(error)
    }
}

/// Failure returned by [`PostgresEffectStore`].
/// Which schema object a physical drift was attributed to.
///
/// Readiness failures stay specific so a release gate can say *what* drifted
/// instead of collapsing every database problem into one opaque error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaObjectKind {
    /// A contract table is absent.
    MissingTable,
    /// A table exists that the recorded schema does not describe.
    UnexpectedTable,
    /// A column was added, removed, retyped, re-moded, or changed its expression.
    Column,
    /// A constraint was added, removed, or changed.
    Constraint,
    /// An index was added, removed, or changed.
    Index,
    /// A trigger was added, removed, or changed.
    Trigger,
    /// The canonical digests differ without a first structural difference.
    DigestOnly,
}

impl std::fmt::Display for SchemaObjectKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::MissingTable => "missing table",
            Self::UnexpectedTable => "unexpected table",
            Self::Column => "column mismatch",
            Self::Constraint => "constraint mismatch",
            Self::Index => "index mismatch",
            Self::Trigger => "trigger mismatch",
            Self::DigestOnly => "schema digest mismatch",
        };
        formatter.write_str(name)
    }
}

/// PostgreSQL settings production readiness observes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresDatabaseSettings {
    /// Full server version string.
    pub server_version: String,
    /// Server major version number.
    pub server_major: i32,
    /// `synchronous_commit`, which governs durability of a committed write.
    pub synchronous_commit: String,
    /// `default_transaction_isolation`.
    pub transaction_isolation: String,
    /// `statement_timeout` as configured for the server default.
    pub statement_timeout: String,
    /// `idle_in_transaction_session_timeout` as configured by default.
    pub idle_in_transaction_session_timeout: String,
    /// `TimeZone` the session runs in.
    pub timezone: String,
}

/// Lowest PostgreSQL release this adapter is qualified against.
///
/// The repository pins PostgreSQL 17 for qualification. Refusing an older
/// server is the honest reading of "production ready": a release that was never
/// qualified has not been shown to hold the same guarantees.
pub const MINIMUM_QUALIFIED_SERVER_MAJOR: i32 = 17;

/// Durability and isolation requirements a production database must meet.
///
/// [`PostgresEffectStore::database_settings`] reports what the server is
/// configured to do; this type is what the runtime requires it to do. Without
/// the two being compared, an observation was being reported as readiness, and
/// a database running `synchronous_commit = off` passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseReadinessPolicy {
    /// Lowest acceptable `server_version_num / 10000`.
    pub minimum_server_major: i32,
    /// `synchronous_commit` settings that keep a committed effect durable.
    ///
    /// PostgreSQL accepts a comma-separated list for this setting, so each
    /// element is checked rather than the string as a whole.
    pub acceptable_synchronous_commit: Vec<String>,
    /// Transaction isolation levels the runtime accepts.
    pub acceptable_transaction_isolation: Vec<String>,
}

impl Default for DatabaseReadinessPolicy {
    fn default() -> Self {
        Self {
            minimum_server_major: MINIMUM_QUALIFIED_SERVER_MAJOR,
            // `off` and `local` both let a committed write be lost in a crash,
            // which is the one outcome a durable effect cannot tolerate.
            acceptable_synchronous_commit: vec![
                "on".to_owned(),
                "remote_write".to_owned(),
                "remote_apply".to_owned(),
            ],
            acceptable_transaction_isolation: vec![
                "read committed".to_owned(),
                "repeatable read".to_owned(),
                "serializable".to_owned(),
            ],
        }
    }
}

/// Failures the PostgreSQL durable-effect adapter can report.
#[derive(Debug)]
pub enum PostgresEffectStoreError {
    /// The configured schema identifier is not a safe lowercase SQL identifier.
    InvalidSchemaName(String),
    /// A connection pool must contain at least one connection.
    InvalidPoolSize(u32),
    /// A PostgreSQL execution budget was zero, out of range, or internally inconsistent.
    InvalidOperationBudget(&'static str),
    /// The connection target is incompatible with the selected transport.
    InvalidTransport(String),
    /// TLS trust material or a client identity could not be loaded.
    Tls(native_tls::Error),
    /// A connection could not be checked out from the bounded pool.
    Pool(r2d2::Error),
    /// PostgreSQL rejected a query or transaction.
    Database(postgres::Error),
    /// Applied migrations did not match the versioned effect-store contract.
    SchemaMismatch(String),
    /// The migration ledger disagrees with the migrations this runtime knows.
    MigrationHistoryMismatch(String),
    /// The physical schema does not match the description recorded for it.
    SchemaFingerprintMismatch(String),
    /// A specific schema object drifted from the recorded description.
    SchemaObjectMismatch {
        /// Which kind of object drifted.
        kind: SchemaObjectKind,
        /// What was observed.
        detail: String,
    },
    /// The database credential holds privileges a production runtime must not have.
    DatabasePrivilegeViolation {
        /// Role the runtime connected as.
        role: String,
        /// Privileges that must not be granted to a runtime role.
        privileges: String,
    },
    /// A production kernel was offered a store opened over the test-only transport.
    ProductionTestTransport,
    /// The server is configured in a way that cannot hold durable effects.
    DatabasePolicyViolation {
        /// Which setting failed.
        setting: &'static str,
        /// What the server reported.
        observed: String,
        /// What the runtime requires.
        requirement: String,
    },
    /// A qualification test injected a durable-operation failure at a boundary.
    ///
    /// Only produced when the testkit feature is enabled and the process was
    /// started with `NEMO_RELAY_POSTGRES_FAULT_POINT` set to a matching name.
    InjectedFailure(String),
    /// A durable JSON value could not be encoded or decoded.
    Serialization(serde_json::Error),
    /// A database value violated the durable-effect representation.
    CorruptData(String),
    /// A Rust integer cannot be represented by the PostgreSQL schema.
    IntegerOutOfRange(&'static str),
    /// The shared effect-store contract rejected the operation.
    Contract(ReferenceStoreError),
}

impl std::fmt::Display for PostgresEffectStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSchemaName(schema) => {
                write!(formatter, "invalid PostgreSQL schema name: {schema}")
            }
            Self::InvalidPoolSize(size) => {
                write!(formatter, "invalid PostgreSQL pool size: {size}")
            }
            Self::InvalidOperationBudget(name) => {
                write!(formatter, "invalid PostgreSQL operation budget: {name}")
            }
            Self::InvalidTransport(message) => {
                write!(formatter, "invalid PostgreSQL transport: {message}")
            }
            Self::Tls(error) => write!(formatter, "PostgreSQL TLS configuration error: {error}"),
            Self::Pool(error) => write!(formatter, "PostgreSQL pool error: {error}"),
            Self::Database(error) => write!(formatter, "PostgreSQL error: {error}"),
            Self::SchemaMismatch(message) => {
                write!(
                    formatter,
                    "PostgreSQL effect-store schema mismatch: {message}"
                )
            }
            Self::MigrationHistoryMismatch(message) => write!(
                formatter,
                "PostgreSQL migration history mismatch: {message}"
            ),
            Self::SchemaFingerprintMismatch(message) => {
                write!(formatter, "PostgreSQL physical schema mismatch: {message}")
            }
            Self::SchemaObjectMismatch { kind, detail } => {
                write!(formatter, "PostgreSQL {kind}: {detail}")
            }
            Self::DatabasePrivilegeViolation { role, privileges } => write!(
                formatter,
                "runtime role {role} can modify the effect-store schema and must be \
                 restricted to data privileges: {privileges}"
            ),
            Self::ProductionTestTransport => write!(
                formatter,
                "the test-only plaintext transport cannot attest production readiness"
            ),
            Self::DatabasePolicyViolation {
                setting,
                observed,
                requirement,
            } => write!(
                formatter,
                "PostgreSQL {setting} is {observed}, which does not meet the production \
                 durability requirement: {requirement}"
            ),
            Self::InjectedFailure(point) => {
                write!(formatter, "injected durable-operation failure at {point}")
            }
            Self::Serialization(error) => write!(formatter, "durable JSON error: {error}"),
            Self::CorruptData(message) => write!(formatter, "corrupt effect-store data: {message}"),
            Self::IntegerOutOfRange(field) => {
                write!(
                    formatter,
                    "value cannot be represented in PostgreSQL: {field}"
                )
            }
            Self::Contract(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PostgresEffectStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pool(error) => Some(error),
            Self::Database(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::InvalidSchemaName(_)
            | Self::InvalidPoolSize(_)
            | Self::InvalidOperationBudget(_)
            | Self::InvalidTransport(_)
            | Self::SchemaMismatch(_)
            | Self::MigrationHistoryMismatch(_)
            | Self::SchemaFingerprintMismatch(_)
            | Self::SchemaObjectMismatch { .. }
            | Self::DatabasePrivilegeViolation { .. }
            | Self::ProductionTestTransport
            | Self::DatabasePolicyViolation { .. }
            | Self::InjectedFailure(_)
            | Self::CorruptData(_)
            | Self::IntegerOutOfRange(_) => None,
        }
    }
}

impl From<r2d2::Error> for PostgresEffectStoreError {
    fn from(error: r2d2::Error) -> Self {
        Self::Pool(error)
    }
}

impl From<postgres::Error> for PostgresEffectStoreError {
    fn from(error: postgres::Error) -> Self {
        Self::Database(error)
    }
}

impl From<native_tls::Error> for PostgresEffectStoreError {
    fn from(error: native_tls::Error) -> Self {
        Self::Tls(error)
    }
}

impl From<serde_json::Error> for PostgresEffectStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

impl From<ReferenceStoreError> for PostgresEffectStoreError {
    fn from(error: ReferenceStoreError) -> Self {
        Self::Contract(error)
    }
}

/// Pooled PostgreSQL authority over one durable effect-store schema.
#[derive(Clone)]
pub struct PostgresEffectStore {
    pool: PostgresPool,
    schema: String,
    lease_configuration: LeaseConfiguration,
    budgets: PostgresOperationBudgets,
    /// Trusted action deadline this handle is scoped to, when one was supplied.
    ///
    /// The configured `budgets` stay maximum bounds. When a deadline is present
    /// every checked-out session is instead bounded by what is left of it, so no
    /// database wait can outlive the action it serves.
    deadline: Option<Instant>,
    /// Whether this handle was opened over the explicitly test-only transport.
    ///
    /// Plaintext loopback is correct for a qualification run and permanently
    /// wrong for a production kernel, so the handle remembers how it was built
    /// and refuses to attest production readiness afterwards. Without this,
    /// every store carried the `ProductionEffectStore` bound no matter which
    /// transport it was opened with, and a production kernel could be composed
    /// around a connection that was never verified.
    plaintext_test_transport: bool,
}

impl PostgresEffectStore {
    /// Attest that this database is ready to hold production durable effects.
    ///
    /// This is the readiness path a production kernel requires: migration
    /// history, physical schema, credential privileges, and recorded database
    /// settings must all hold before a kernel can be composed around it.
    pub fn verify_production_readiness(&self) -> Result<(), PostgresEffectStoreError> {
        if self.plaintext_test_transport {
            return Err(PostgresEffectStoreError::ProductionTestTransport);
        }
        self.verify_database_readiness().map(|_| ())
    }

    /// Create a plaintext pool for an explicitly local development or test target.
    ///
    /// Every configured host must be a Unix socket or a loopback TCP address.
    /// Production callers should use [`Self::connect_local_socket`],
    /// [`Self::connect_verified_tls`], or [`Self::connect_mutual_tls`].
    pub fn connect_insecure_local_for_tests(
        connection_string: &str,
        schema: &str,
        lease_configuration: LeaseConfiguration,
        maximum_pool_size: u32,
    ) -> Result<Self, PostgresEffectStoreError> {
        Self::connect_insecure_local_for_tests_with_budgets(
            connection_string,
            schema,
            lease_configuration,
            maximum_pool_size,
            PostgresOperationBudgets::default(),
        )
    }

    /// Create a local-only plaintext pool with explicit database budgets.
    pub fn connect_insecure_local_for_tests_with_budgets(
        connection_string: &str,
        schema: &str,
        lease_configuration: LeaseConfiguration,
        maximum_pool_size: u32,
        budgets: PostgresOperationBudgets,
    ) -> Result<Self, PostgresEffectStoreError> {
        let mut configuration: Config = connection_string.parse()?;
        validate_local_target(&configuration, true)?;
        configuration.ssl_mode(SslMode::Disable);
        Self::from_plain_configuration(
            configuration,
            schema,
            lease_configuration,
            maximum_pool_size,
            budgets,
            true,
        )
    }

    /// Create a plaintext pool connected exclusively through Unix sockets.
    #[cfg(unix)]
    pub fn connect_local_socket(
        connection_string: &str,
        schema: &str,
        lease_configuration: LeaseConfiguration,
        maximum_pool_size: u32,
    ) -> Result<Self, PostgresEffectStoreError> {
        Self::connect_local_socket_with_budgets(
            connection_string,
            schema,
            lease_configuration,
            maximum_pool_size,
            PostgresOperationBudgets::default(),
        )
    }

    /// Create a Unix-socket pool with explicit database budgets.
    #[cfg(unix)]
    pub fn connect_local_socket_with_budgets(
        connection_string: &str,
        schema: &str,
        lease_configuration: LeaseConfiguration,
        maximum_pool_size: u32,
        budgets: PostgresOperationBudgets,
    ) -> Result<Self, PostgresEffectStoreError> {
        let mut configuration: Config = connection_string.parse()?;
        validate_local_target(&configuration, false)?;
        configuration.ssl_mode(SslMode::Disable);
        Self::from_plain_configuration(
            configuration,
            schema,
            lease_configuration,
            maximum_pool_size,
            budgets,
            false,
        )
    }

    /// Create a TLS-required pool that verifies the server certificate and hostname.
    pub fn connect_verified_tls(
        connection_string: &str,
        schema: &str,
        lease_configuration: LeaseConfiguration,
        maximum_pool_size: u32,
        root_ca_pem: &[u8],
    ) -> Result<Self, PostgresEffectStoreError> {
        Self::connect_verified_tls_with_budgets(
            connection_string,
            schema,
            lease_configuration,
            maximum_pool_size,
            root_ca_pem,
            PostgresOperationBudgets::default(),
        )
    }

    /// Create a verified TLS pool with explicit database budgets.
    pub fn connect_verified_tls_with_budgets(
        connection_string: &str,
        schema: &str,
        lease_configuration: LeaseConfiguration,
        maximum_pool_size: u32,
        root_ca_pem: &[u8],
        budgets: PostgresOperationBudgets,
    ) -> Result<Self, PostgresEffectStoreError> {
        let configuration: Config = connection_string.parse()?;
        let connector = verified_tls_connector(&configuration, root_ca_pem, None)?;
        Self::from_tls_configuration(
            configuration,
            connector,
            schema,
            lease_configuration,
            maximum_pool_size,
            budgets,
        )
    }

    /// Create a TLS-required pool with a verified server and PKCS #12 client identity.
    pub fn connect_mutual_tls(
        connection_string: &str,
        schema: &str,
        lease_configuration: LeaseConfiguration,
        maximum_pool_size: u32,
        root_ca_pem: &[u8],
        client_identity_pkcs12: &[u8],
        client_identity_password: &str,
    ) -> Result<Self, PostgresEffectStoreError> {
        Self::connect_mutual_tls_with_budgets(
            connection_string,
            schema,
            lease_configuration,
            maximum_pool_size,
            PostgresMutualTlsCredentials {
                root_ca_pem: root_ca_pem.to_vec(),
                client_identity_pkcs12: client_identity_pkcs12.to_vec(),
                client_identity_password: client_identity_password.into(),
            },
            PostgresOperationBudgets::default(),
        )
    }

    /// Create a mutual-TLS pool with explicit database budgets.
    pub fn connect_mutual_tls_with_budgets(
        connection_string: &str,
        schema: &str,
        lease_configuration: LeaseConfiguration,
        maximum_pool_size: u32,
        credentials: PostgresMutualTlsCredentials,
        budgets: PostgresOperationBudgets,
    ) -> Result<Self, PostgresEffectStoreError> {
        let configuration: Config = connection_string.parse()?;
        let identity = Identity::from_pkcs12(
            &credentials.client_identity_pkcs12,
            &credentials.client_identity_password,
        )?;
        let connector =
            verified_tls_connector(&configuration, &credentials.root_ca_pem, Some(identity))?;
        Self::from_tls_configuration(
            configuration,
            connector,
            schema,
            lease_configuration,
            maximum_pool_size,
            budgets,
        )
    }

    fn from_plain_configuration(
        configuration: Config,
        schema: &str,
        lease_configuration: LeaseConfiguration,
        maximum_pool_size: u32,
        budgets: PostgresOperationBudgets,
        plaintext_test_transport: bool,
    ) -> Result<Self, PostgresEffectStoreError> {
        validate_store_configuration(schema, maximum_pool_size, &budgets)?;
        let manager = PostgresConnectionManager::new(configuration, NoTls);
        let pool = build_plain_pool(manager, maximum_pool_size, &budgets)?;
        Ok(Self {
            pool: PostgresPool::Plain(pool),
            schema: schema.to_owned(),
            lease_configuration,
            budgets,
            deadline: None,
            plaintext_test_transport,
        })
    }

    fn from_tls_configuration(
        mut configuration: Config,
        connector: MakeTlsConnector,
        schema: &str,
        lease_configuration: LeaseConfiguration,
        maximum_pool_size: u32,
        budgets: PostgresOperationBudgets,
    ) -> Result<Self, PostgresEffectStoreError> {
        validate_store_configuration(schema, maximum_pool_size, &budgets)?;
        validate_tls_target(&configuration)?;
        configuration.ssl_mode(SslMode::Require);
        let manager = PostgresConnectionManager::new(configuration, connector);
        let pool = build_tls_pool(manager, maximum_pool_size, &budgets)?;
        Ok(Self {
            pool: PostgresPool::Tls(pool),
            schema: schema.to_owned(),
            lease_configuration,
            budgets,
            deadline: None,
            plaintext_test_transport: false,
        })
    }

    /// Apply immutable versioned effect-store migrations.
    ///
    /// This method is for a dedicated migration role. Normal runtime workers
    /// should call [`Self::verify_schema`] and fail closed when the schema is
    /// absent, old, newer than their contract, or checksum-mismatched.
    ///
    /// The migration owns its objects. DDL runs without `IF NOT EXISTS`, so a
    /// pre-existing object of unknown shape fails the migration instead of
    /// being silently adopted, and the physical schema is fingerprinted inside
    /// the same transaction before the migration version is recorded.
    pub fn migrate(&self) -> Result<(), PostgresEffectStoreError> {
        // Deterministic crash boundaries for the migration crash matrix. Points
        // 01-07 must leave no committed migration; point 08 is the opposite
        // ambiguity, where PostgreSQL made the migration durable but the client
        // never observed the commit.
        pause_at_test_crash_point("mig_crash_01_before_advisory_lock");
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        // Serialize migrations per schema so a concurrent deployment cannot
        // observe a partially recorded migration history. The lock is scoped
        // to this transaction and is released automatically on rollback.
        let migration_lock = format!("nemo-effect-store-migrations:{}", self.schema);
        transaction.query_one(
            "select pg_advisory_xact_lock(hashtext($1))",
            &[&migration_lock],
        )?;
        pause_at_test_crash_point("mig_crash_02_after_advisory_lock");
        pause_at_test_crash_point("mig_crash_03_before_ddl");
        transaction.batch_execute(&format!(
            "create schema if not exists {}",
            self.quoted_schema()
        ))?;
        transaction.batch_execute(&format!(
            "create table if not exists {}.effect_schema_migrations (\
             version bigint primary key, name text not null, checksum text not null, \
             application_version text not null, \
             applied_at timestamptz not null default clock_timestamp())",
            self.quoted_schema()
        ))?;
        // `if not exists` above is only acceptable because the shape is verified
        // immediately. A pre-existing table with a different shape cannot be
        // used to record a migration, so it must not be blessed.
        validate_migration_ledger_shape(&mut transaction, &self.schema)?;
        let rows = transaction.query(
            &format!(
                "select version, name, checksum from {}.effect_schema_migrations order by version",
                self.quoted_schema()
            ),
            &[],
        )?;
        for row in &rows {
            let version: i64 = row.get(0);
            if !MIGRATIONS
                .iter()
                .any(|migration| migration.version == version)
            {
                return Err(PostgresEffectStoreError::SchemaMismatch(format!(
                    "database contains unsupported migration version {version}"
                )));
            }
        }
        if rows.is_empty() {
            // The migration owns the schema it builds, so it refuses to claim a
            // schema that already contains objects it did not create. Later runs
            // skip this: by then the schema legitimately contains the effect
            // store, and `create table` without IF NOT EXISTS still refuses to
            // adopt anything unexpected.
            let foreign = schema::foreign_relations(&mut transaction, &self.schema)?;
            if !foreign.is_empty() {
                return Err(PostgresEffectStoreError::SchemaMismatch(format!(
                    "schema {} already contains objects this migration does not own: {}",
                    self.schema,
                    foreign.join(", ")
                )));
            }
        }
        let mut pending: Vec<&Migration> = Vec::new();
        for migration in MIGRATIONS {
            let checksum = migration_checksum(migration.sql);
            let applied = rows
                .iter()
                .find(|row| row.get::<_, i64>(0) == migration.version);
            if let Some(applied) = applied {
                let name: String = applied.get(1);
                let applied_checksum: String = applied.get(2);
                if name != migration.name || applied_checksum != checksum {
                    return Err(PostgresEffectStoreError::SchemaMismatch(format!(
                        "migration {} has a different name or checksum",
                        migration.version
                    )));
                }
                continue;
            }
            transaction
                .batch_execute(&migration.sql.replace("__SCHEMA__", &self.quoted_schema()))?;
            pause_at_test_crash_point("mig_crash_04_after_ddl");
            pending.push(migration);
        }
        if !pending.is_empty() {
            // Record what the migration actually produced before the ledger
            // admits that the migration ran. Both happen in one transaction, so
            // a mismatch or a crash leaves neither the objects nor the record.
            let live = schema::capture(&mut transaction, &self.schema)?;
            schema::record(&mut transaction, &self.schema, &live)?;
        }
        pause_at_test_crash_point("mig_crash_05_before_ledger_insert");
        for migration in &pending {
            let checksum = migration_checksum(migration.sql);
            transaction.execute(
                &format!(
                    "insert into {}.effect_schema_migrations \
                     (version, name, checksum, application_version) values ($1, $2, $3, $4)",
                    self.quoted_schema()
                ),
                &[
                    &migration.version,
                    &migration.name,
                    &checksum,
                    // The release that first applied this migration, not the
                    // runtime that later observes it. A newer runtime must not
                    // rewrite this row.
                    &env!("CARGO_PKG_VERSION"),
                ],
            )?;
            pause_at_test_crash_point("mig_crash_06_after_ledger_insert");
        }
        pause_at_test_crash_point("mig_crash_07_before_commit");
        transaction.commit()?;
        pause_at_test_crash_point("mig_crash_08_after_commit");
        Ok(())
    }

    /// Verify that this store's schema exactly matches the runtime contract.
    ///
    /// Two independent facts are required. The migration ledger must record
    /// exactly the migrations this runtime knows, with matching names and
    /// checksums; and the *physical* schema must match the fingerprint recorded
    /// when those migrations ran. A correct ledger over a structurally altered
    /// database fails here.
    ///
    /// This is the convenience combination of
    /// [`Self::verify_migration_history`] and [`Self::verify_physical_schema`].
    /// Production readiness uses [`Self::verify_database_readiness`], which adds
    /// role permissions and database settings.
    pub fn verify_schema(&self) -> Result<(), PostgresEffectStoreError> {
        self.verify_migration_history()?;
        self.verify_physical_schema()
    }

    /// Verify that the migration ledger records exactly this runtime's contract.
    pub fn verify_migration_history(&self) -> Result<(), PostgresEffectStoreError> {
        let mut connection = self.connection()?;
        let rows = connection
            .query(
                &format!(
                    "select version, name, checksum from {}.effect_schema_migrations order by version",
                    self.quoted_schema()
                ),
                &[],
            )
            .map_err(schema_query_error)?;
        self.check_migration_rows(&rows)?;
        Ok(())
    }

    /// Assert that a ledger row set is exactly the contract, in order.
    fn check_migration_rows(&self, rows: &[postgres::Row]) -> Result<(), PostgresEffectStoreError> {
        // A superset is not acceptable: an arbitrary extra migration means the
        // database was written to by something this runtime does not know.
        if rows.len() != MIGRATIONS.len() {
            return Err(PostgresEffectStoreError::MigrationHistoryMismatch(format!(
                "applied migration count {} does not match this runtime's {}",
                rows.len(),
                MIGRATIONS.len()
            )));
        }
        let mut previous = 0_i64;
        for migration in MIGRATIONS {
            let row = rows
                .iter()
                .find(|row| row.get::<_, i64>(0) == migration.version)
                .ok_or_else(|| {
                    PostgresEffectStoreError::MigrationHistoryMismatch(format!(
                        "required migration {} is missing",
                        migration.version
                    ))
                })?;
            let version: i64 = row.get(0);
            if version <= previous {
                return Err(PostgresEffectStoreError::MigrationHistoryMismatch(format!(
                    "migration history is out of order at version {version}"
                )));
            }
            previous = version;
            let name: String = row.get(1);
            let checksum: String = row.get(2);
            if name != migration.name {
                return Err(PostgresEffectStoreError::MigrationHistoryMismatch(format!(
                    "migration {} is recorded as {name:?} but this runtime knows it as {:?}",
                    migration.version, migration.name
                )));
            }
            if checksum != migration_checksum(migration.sql) {
                return Err(PostgresEffectStoreError::MigrationHistoryMismatch(format!(
                    "migration {} has a different checksum than this runtime's SQL",
                    migration.version
                )));
            }
        }
        Ok(())
    }

    /// Verify the physical schema against the description recorded for it.
    ///
    /// This is catalogue inspection, not bookkeeping: a dropped index, a
    /// retyped column, a removed constraint, a changed generation expression, an
    /// added trigger, or an unexpected table all fail here while the migration
    /// ledger stays untouched.
    pub fn verify_physical_schema(&self) -> Result<(), PostgresEffectStoreError> {
        let mut connection = self.connection()?;
        let live = schema::capture(&mut *connection, &self.schema)?;
        schema::verify(&mut *connection, &self.schema, &live)
    }

    /// Return the physical schema fingerprint of this database.
    ///
    /// Qualification records this value as machine-readable evidence that
    /// schema verification inspected the catalog rather than only the ledger.
    pub fn schema_fingerprint(&self) -> Result<String, PostgresEffectStoreError> {
        let mut connection = self.connection()?;
        schema::capture(&mut *connection, &self.schema)?.digest()
    }

    /// Return the canonical, human-reviewable description of this database.
    pub fn schema_model(&self) -> Result<schema::CanonicalSchema, PostgresEffectStoreError> {
        let mut connection = self.connection()?;
        schema::capture(&mut *connection, &self.schema)
    }

    /// Return the PostgreSQL settings that govern durability and waiting.
    pub fn database_settings(&self) -> Result<PostgresDatabaseSettings, PostgresEffectStoreError> {
        let mut connection = self.connection()?;
        let row = connection.query_one(
            "select current_setting('server_version'), \
             current_setting('server_version_num')::integer / 10000, \
             current_setting('synchronous_commit'), \
             current_setting('default_transaction_isolation'), \
             current_setting('statement_timeout'), \
             current_setting('idle_in_transaction_session_timeout'), \
             current_setting('TimeZone')",
            &[],
        )?;
        Ok(PostgresDatabaseSettings {
            server_version: row.get(0),
            server_major: row.get(1),
            synchronous_commit: row.get(2),
            transaction_isolation: row.get(3),
            statement_timeout: row.get(4),
            idle_in_transaction_session_timeout: row.get(5),
            timezone: row.get(6),
        })
    }

    /// Run every database readiness check a production runtime must satisfy.
    ///
    /// Split from [`Self::verify_schema`] so qualification and operators get
    /// specific diagnostics: history, physical structure, credential
    /// privileges, and the settings that govern durability and waiting.
    pub fn verify_database_readiness(
        &self,
    ) -> Result<PostgresDatabaseSettings, PostgresEffectStoreError> {
        self.verify_migration_history()?;
        self.verify_physical_schema()?;
        self.verify_runtime_privileges()?;
        self.verify_database_policy(&DatabaseReadinessPolicy::default())?;
        self.database_settings()
    }

    /// Verify the server settings that durable operation depends on.
    ///
    /// `statement_timeout`, `idle_in_transaction_session_timeout`, and the
    /// session time zone are deliberately not enforced. The adapter sets
    /// statement and lock timeouts on every checked-out session from the action
    /// budget, so the server defaults are not the binding constraint; enforcing
    /// them here would reject a deployment for a setting that never applies.
    pub fn verify_database_policy(
        &self,
        policy: &DatabaseReadinessPolicy,
    ) -> Result<(), PostgresEffectStoreError> {
        let settings = self.database_settings()?;
        if settings.server_major < policy.minimum_server_major {
            return Err(PostgresEffectStoreError::DatabasePolicyViolation {
                setting: "server_version",
                observed: settings.server_version.clone(),
                requirement: format!("major version >= {}", policy.minimum_server_major),
            });
        }

        for element in settings.synchronous_commit.split(',') {
            let element = element.trim().to_ascii_lowercase();
            if !policy
                .acceptable_synchronous_commit
                .iter()
                .any(|accepted| accepted == &element)
            {
                return Err(PostgresEffectStoreError::DatabasePolicyViolation {
                    setting: "synchronous_commit",
                    observed: settings.synchronous_commit.clone(),
                    requirement: policy.acceptable_synchronous_commit.join(", "),
                });
            }
        }

        let isolation = settings.transaction_isolation.trim().to_ascii_lowercase();
        if !policy
            .acceptable_transaction_isolation
            .iter()
            .any(|accepted| accepted == &isolation)
        {
            return Err(PostgresEffectStoreError::DatabasePolicyViolation {
                setting: "default_transaction_isolation",
                observed: settings.transaction_isolation.clone(),
                requirement: policy.acceptable_transaction_isolation.join(", "),
            });
        }

        Ok(())
    }

    /// Verify that the connected role cannot modify the schema or its ledger.
    ///
    /// The runtime identity must be a data-only role. A runtime credential that
    /// can `CREATE` in the effect schema, or rewrite `effect_schema_migrations`
    /// or `effect_schema_state`, can hide drift from every later verification,
    /// so production readiness refuses to start with one.
    pub fn verify_runtime_privileges(&self) -> Result<(), PostgresEffectStoreError> {
        let mut connection = self.connection()?;
        let row = connection.query_one(
            "select current_user, \
             has_schema_privilege(current_user, $1, 'CREATE'), \
             has_schema_privilege(current_user, $1, 'USAGE'), \
             has_table_privilege(current_user, $2, 'INSERT'), \
             has_table_privilege(current_user, $2, 'UPDATE'), \
             has_table_privilege(current_user, $2, 'DELETE'), \
             has_table_privilege(current_user, $2, 'TRUNCATE'), \
             has_table_privilege(current_user, $3, 'INSERT'), \
             has_table_privilege(current_user, $3, 'UPDATE'), \
             has_table_privilege(current_user, $3, 'DELETE'), \
             has_table_privilege(current_user, $3, 'TRUNCATE'), \
             coalesce((select rolsuper from pg_roles where rolname = current_user), false), \
             coalesce((select rolbypassrls from pg_roles where rolname = current_user), false), \
             coalesce((select rolcreaterole from pg_roles where rolname = current_user), false), \
             coalesce((select pg_get_userbyid(nspowner) = current_user from pg_namespace \
                       where nspname = $1), false), \
             exists (select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace \
                     where n.nspname = $1 and pg_get_userbyid(c.relowner) = current_user), \
             coalesce((with recursive reachable(roleid) as ( \
                         select oid from pg_roles where rolname = current_user \
                         union \
                         select m.roleid from pg_auth_members m \
                         join reachable r on m.member = r.roleid \
                       ) \
                       select string_agg(rolname, ', ') from pg_roles \
                       where oid in (select roleid from reachable) \
                         and rolname <> current_user \
                         and (rolsuper or rolcreaterole or rolcreatedb or rolbypassrls)), ''), \
             coalesce((with recursive reachable(roleid) as ( \
                         select oid from pg_roles where rolname = current_user \
                         union \
                         select m.roleid from pg_auth_members m \
                         join reachable r on m.member = r.roleid \
                       ) \
                       select string_agg(rolname, ', ') from pg_roles \
                       where oid in (select roleid from reachable) \
                         and rolname <> current_user \
                         and (exists (select 1 from pg_namespace n \
                                      where n.nspname = $1 \
                                        and pg_get_userbyid(n.nspowner) = rolname) \
                              or exists (select 1 from pg_class c \
                                         join pg_namespace n2 on n2.oid = c.relnamespace \
                                         where n2.nspname = $1 \
                                           and pg_get_userbyid(c.relowner) = rolname))), '')",
            &[
                &self.schema,
                &self.table("effect_schema_migrations"),
                &self.table("effect_schema_state"),
            ],
        )?;
        let role: String = row.get(0);
        let violations: [(&str, bool); 14] = [
            ("CREATE on schema", row.get::<_, bool>(1)),
            ("INSERT into effect_schema_migrations", row.get(3)),
            ("UPDATE of effect_schema_migrations", row.get(4)),
            ("DELETE from effect_schema_migrations", row.get(5)),
            ("TRUNCATE of effect_schema_migrations", row.get(6)),
            ("INSERT into effect_schema_state", row.get(7)),
            ("UPDATE of effect_schema_state", row.get(8)),
            ("DELETE from effect_schema_state", row.get(9)),
            ("TRUNCATE of effect_schema_state", row.get(10)),
            ("SUPERUSER role attribute", row.get(11)),
            ("BYPASSRLS role attribute", row.get(12)),
            ("CREATEROLE role attribute", row.get(13)),
            ("ownership of the effect-store schema", row.get(14)),
            ("ownership of an effect-store relation", row.get(15)),
        ];
        let mut granted: Vec<String> = violations
            .iter()
            .filter(|(_, present)| *present)
            .map(|(name, _)| (*name).to_owned())
            .collect();

        // A role that inherits a dangerous role has that role's powers without
        // carrying any of its attributes, so checking only the connected role
        // proves much less than it appears to. Both walks are transitive for the
        // same reason a chain of two memberships is no safer than one.
        let inherited_dangerous: String = row.get(16);
        if !inherited_dangerous.trim().is_empty() {
            granted.push(format!(
                "inherited role(s) with dangerous attributes: {inherited_dangerous}"
            ));
        }
        let inherited_owners: String = row.get(17);
        if !inherited_owners.trim().is_empty() {
            granted.push(format!(
                "inherited role(s) owning effect-store objects: {inherited_owners}"
            ));
        }
        if !granted.is_empty() {
            return Err(PostgresEffectStoreError::DatabasePrivilegeViolation {
                role,
                privileges: granted.join(", "),
            });
        }
        if !row.get::<_, bool>(2) {
            return Err(PostgresEffectStoreError::SchemaMismatch(format!(
                "runtime role {role} has no USAGE on schema {}",
                self.schema
            )));
        }
        Ok(())
    }

    /// Finalize a terminal receipt inside a trusted remaining action budget.
    ///
    /// The trait entry point uses the configured maximum budgets. Consequential
    /// callers hold a trusted deadline, so they use this form: the store derives
    /// `lock_timeout` and `statement_timeout` from what is left of that deadline
    /// and never lets a PostgreSQL wait outlive it.
    pub fn finalize_terminal_receipt_within_budget(
        &self,
        action_id: &str,
        expected: ExecutionState,
        lease: &ActionLease,
        receipt: &ReceiptRecord,
        remaining: Duration,
    ) -> Result<EffectFinalizeResult, PostgresEffectStoreError> {
        self.finalize_receipt_transaction(Terminalization {
            action_id,
            expected,
            lease,
            expected_evidence_revision: None,
            receipt,
            remaining_action_budget: Some(remaining),
            failure_point: "terminal_finalization",
        })
    }

    /// Discover bounded, unowned or expired consequential work for a recovery worker.
    ///
    /// This is only a candidate query. The kernel must still acquire the
    /// current fenced lease before inspecting evidence or reconciling.
    pub fn recoverable_action_ids(
        &self,
        limit: u32,
    ) -> Result<Vec<String>, PostgresEffectStoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let query = format!(
            "select action_id from {}.effect_actions \
             where state in ('DISPATCHING', 'UNKNOWN', 'RECONCILING') \
             and (lease_expires_at is null or lease_expires_at <= clock_timestamp()) \
             order by updated_at, action_id limit $1",
            self.quoted_schema()
        );
        let rows = self.connection()?.query(&query, &[&i64::from(limit)])?;
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    /// Return a handle whose every store call is bounded by ``deadline``.
    ///
    /// This is how trusted execution context reaches the store without changing
    /// the shared `ActionStore`/`EffectStore` traits: a clone of the store
    /// shares the connection pool but carries the deadline, so every call made
    /// through the returned handle derives its PostgreSQL budgets from what is
    /// left of it. An already-exhausted deadline is rejected here rather than
    /// silently falling back to the static maximum.
    pub fn with_deadline(&self, deadline: Instant) -> Result<Self, PostgresEffectStoreError> {
        if remaining_deadline(deadline)?.is_zero() {
            return Err(PostgresEffectStoreError::InvalidOperationBudget(
                "remaining action budget",
            ));
        }
        Ok(Self {
            deadline: Some(deadline),
            ..self.clone()
        })
    }

    /// Return the budgets this handle would apply to its next checkout.
    pub fn effective_operation_budgets(
        &self,
    ) -> Result<PostgresOperationBudgets, PostgresEffectStoreError> {
        match self.deadline {
            Some(deadline) => self.budgets.for_remaining(remaining_deadline(deadline)?),
            None => Ok(self.budgets.clone()),
        }
    }

    fn connection(&self) -> Result<PostgresConnection, PostgresEffectStoreError> {
        self.connection_with_budget(self.effective_operation_budgets()?)
    }

    fn connection_with_budget(
        &self,
        budgets: PostgresOperationBudgets,
    ) -> Result<PostgresConnection, PostgresEffectStoreError> {
        let mut connection = match &self.pool {
            PostgresPool::Plain(pool) => pool
                .get()
                .map(PostgresConnection::Plain)
                .map_err(PostgresEffectStoreError::Pool),
            PostgresPool::Tls(pool) => pool
                .get()
                .map(PostgresConnection::Tls)
                .map_err(PostgresEffectStoreError::Pool),
        }?;
        apply_operation_budgets(&mut connection, &budgets)?;
        Ok(connection)
    }

    /// Derive the session budgets a remaining trusted action budget allows.
    ///
    /// The configured budgets stay maximum bounds. This returns the smaller of
    /// each maximum and the caller's remaining deadline, so a caller can prove
    /// that no PostgreSQL wait it starts can outlive the action it serves.
    pub fn operation_budgets_for_remaining(
        &self,
        remaining: Duration,
    ) -> Result<PostgresOperationBudgets, PostgresEffectStoreError> {
        self.budgets.for_remaining(remaining)
    }

    fn quoted_schema(&self) -> String {
        format!("\"{}\"", self.schema)
    }

    fn table(&self, table: &str) -> String {
        format!("{}.{}", self.quoted_schema(), table)
    }

    fn action_select(&self, suffix: &str) -> String {
        format!(
            "select preparation, state, lease_owner, lease_generation, \
             case when lease_expires_at is null then null else \
             floor(extract(epoch from lease_expires_at) * 1000)::bigint end \
             as lease_expires_at_unix_ms, terminal_evidence, evidence_revision \
             from {} where action_id = $1 {suffix}",
            self.table("effect_actions")
        )
    }

    fn load_action_with(
        &self,
        client: &mut impl GenericClient,
        action_id: &str,
        lock: bool,
    ) -> Result<Option<(ActionRecord, u64)>, PostgresEffectStoreError> {
        let suffix = if lock { "for update" } else { "" };
        client
            .query_opt(&self.action_select(suffix), &[&action_id])?
            .map(action_and_revision_from_row)
            .transpose()
    }

    fn load_receipt_with(
        &self,
        client: &mut impl GenericClient,
        action_id: &str,
    ) -> Result<Option<ReceiptRecord>, PostgresEffectStoreError> {
        let sql = format!(
            "select receipt from {} where action_id = $1",
            self.table("effect_receipts")
        );
        client
            .query_opt(&sql, &[&action_id])?
            .map(|row| from_json_value(row.get("receipt")))
            .transpose()
    }

    fn load_conflicts_with(
        &self,
        client: &mut impl GenericClient,
        action_id: &str,
    ) -> Result<Vec<ReceiptConflict>, PostgresEffectStoreError> {
        let sql = format!(
            "select conflict from {} where action_id = $1 \
             order by observed_at, conflict_digest",
            self.table("effect_receipt_conflicts")
        );
        client
            .query(&sql, &[&action_id])?
            .into_iter()
            .map(|row| from_json_value(row.get("conflict")))
            .collect()
    }

    fn database_now_ms(client: &mut impl GenericClient) -> Result<u64, PostgresEffectStoreError> {
        let value: i64 = client
            .query_one(
                "select floor(extract(epoch from clock_timestamp()) * 1000)::bigint",
                &[],
            )?
            .get(0);
        nonnegative_u64(value, "database clock")
    }

    fn update_action(
        &self,
        client: &mut impl GenericClient,
        action: &ActionRecord,
        evidence_revision: u64,
    ) -> Result<(), PostgresEffectStoreError> {
        let preparation = to_json_value(&action.preparation)?;
        let terminal_evidence = action
            .terminal_evidence
            .as_ref()
            .map(to_json_value)
            .transpose()?;
        let generation = postgres_i64(action.lease_generation, "lease generation")?;
        let revision = postgres_i64(evidence_revision, "evidence revision")?;
        let (owner, expires_at_ms) = match action.lease.as_ref() {
            Some(lease) => (
                Some(lease.owner_id.as_str()),
                Some(postgres_i64(lease.expires_at_unix_ms, "lease expiry")?),
            ),
            None => (None, None),
        };
        let sql = format!(
            "update {} set preparation = $2, state = $3, lease_owner = $4, \
             lease_generation = $5, lease_expires_at = case when $6::bigint is null \
             then null else to_timestamp($6::double precision / 1000.0) end, \
             terminal_evidence = $7, evidence_revision = $8, \
             updated_at = clock_timestamp() where action_id = $1",
            self.table("effect_actions")
        );
        let updated = client.execute(
            &sql,
            &[
                &action.preparation.action_id,
                &preparation,
                &state_name(action.state),
                &owner,
                &generation,
                &expires_at_ms,
                &terminal_evidence,
                &revision,
            ],
        )?;
        if updated != 1 {
            return Err(
                ReferenceStoreError::ActionMissing(action.preparation.action_id.clone()).into(),
            );
        }
        Ok(())
    }

    fn finalize_receipt_transaction(
        &self,
        request: Terminalization<'_>,
    ) -> Result<EffectFinalizeResult, PostgresEffectStoreError> {
        let Terminalization {
            action_id,
            expected,
            lease,
            expected_evidence_revision,
            receipt,
            remaining_action_budget,
            failure_point,
        } = request;
        // Boundary C or D: the external effect may already exist when the
        // terminal write fails. The caller must treat this as unknown, never as
        // a failed effect.
        injected_database_failure(failure_point)?;
        receipt
            .validate_terminal()
            .map_err(ReferenceStoreError::InvalidReceipt)?;
        if receipt.action_id != action_id {
            return Err(ReferenceStoreError::EvidenceBindingMismatch {
                action_id: action_id.to_owned(),
            }
            .into());
        }

        let mut connection = match remaining_action_budget {
            // Deadline-aware: the terminal transaction is bounded by what is
            // left of the caller's trusted action budget, or by the static
            // maximum when no deadline is supplied.
            Some(remaining) => {
                self.connection_with_budget(self.budgets.for_remaining(remaining)?)?
            }
            None => self.connection()?,
        };
        let mut transaction = connection.transaction()?;
        let (mut action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        pause_at_test_crash_point("after_action_lock");
        let evidence = TerminalEvidence::Receipt(receipt.identity());
        if !evidence
            .binds_action(&action.preparation)
            .map_err(|_| ReferenceStoreError::InvalidGrantDigest)?
        {
            return Err(ReferenceStoreError::EvidenceBindingMismatch {
                action_id: action_id.to_owned(),
            }
            .into());
        }
        let existing = self.load_receipt_with(&mut transaction, action_id)?;
        if action.state == receipt.final_state
            && action.terminal_evidence.as_ref() == Some(&evidence)
            && existing
                .as_ref()
                .is_some_and(|stored| stored.identity() == receipt.identity())
        {
            transaction.commit()?;
            return Ok(EffectFinalizeResult::AlreadyFinalized(
                existing.expect("checked above"),
            ));
        }
        if let Some(expected_revision) = expected_evidence_revision
            && revision != expected_revision
        {
            return Err(ReferenceStoreError::EvidenceRevisionChanged {
                expected: expected_revision,
                actual: revision,
            }
            .into());
        }
        validate_fenced_action(
            &action,
            expected,
            lease,
            Self::database_now_ms(&mut transaction)?,
        )?;
        if !is_valid_receipt_finalization(expected, receipt.final_state, &receipt.identity()) {
            return Err(ReferenceStoreError::EvidenceBindingMismatch {
                action_id: action_id.to_owned(),
            }
            .into());
        }

        if let Some(existing) = existing {
            if existing.identity() == receipt.identity() {
                action.terminal_evidence = Some(evidence);
                action.state = receipt.final_state;
                action.lease = None;
                self.update_action(&mut transaction, &action, revision)?;
                transaction.commit()?;
                return Ok(EffectFinalizeResult::AlreadyFinalized(existing));
            }
            let conflict = ReceiptConflict::new(&existing, receipt);
            let recorded = self.insert_conflict(&mut transaction, &conflict)?;
            if recorded {
                let next_revision = checked_revision(revision)?;
                self.update_action(&mut transaction, &action, next_revision)?;
                transaction.commit()?;
                return Ok(EffectFinalizeResult::FinalizationConflict(conflict));
            }
            transaction.commit()?;
            return Ok(EffectFinalizeResult::ConflictAlreadyRecorded(conflict));
        }

        let receipt_json = to_json_value(receipt)?;
        let identity = canonical_digest(&receipt.identity())?;
        let insert = format!(
            "insert into {} (action_id, receipt_identity, receipt) values ($1, $2, $3)",
            self.table("effect_receipts")
        );
        transaction.execute(&insert, &[&action_id, &identity, &receipt_json])?;
        pause_at_test_crash_point("after_receipt_insert");
        action.terminal_evidence = Some(evidence);
        action.state = receipt.final_state;
        action.lease = None;
        self.update_action(&mut transaction, &action, checked_revision(revision)?)?;
        pause_at_test_crash_point("after_action_update");
        pause_at_test_crash_point("before_commit");
        transaction.commit()?;
        pause_at_test_crash_point("after_commit");
        Ok(EffectFinalizeResult::Finalized(receipt.clone()))
    }

    fn insert_conflict(
        &self,
        client: &mut impl GenericClient,
        conflict: &ReceiptConflict,
    ) -> Result<bool, PostgresEffectStoreError> {
        let sql = format!(
            "insert into {} (conflict_digest, action_id, conflict) values ($1, $2, $3) \
             on conflict (conflict_digest) do nothing",
            self.table("effect_receipt_conflicts")
        );
        let conflict_json = to_json_value(conflict)?;
        Ok(client.execute(
            &sql,
            &[
                &conflict.conflict_digest,
                &conflict.action_id,
                &conflict_json,
            ],
        )? == 1)
    }

    #[cfg(all(test, feature = "unstable-hardening-testkit"))]
    fn drop_schema(&self) -> Result<(), PostgresEffectStoreError> {
        self.connection()?
            .batch_execute(&format!("drop schema {} cascade", self.quoted_schema()))?;
        Ok(())
    }
}

impl ActionStore for PostgresEffectStore {
    type Error = PostgresEffectStoreError;

    fn claim_action(&self, action: &ActionPreparation) -> Result<PrepareActionResult, Self::Error> {
        if action.grant_digest.is_some() {
            return Err(ReferenceStoreError::InvalidActionClaim(
                ClaimValidationError::PrepopulatedGrantDigest,
            )
            .into());
        }
        if action.approval_reference.is_some() {
            return Err(ReferenceStoreError::InvalidActionClaim(
                ClaimValidationError::PrepopulatedApprovalReference,
            )
            .into());
        }
        let preparation = to_json_value(action)?;
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let sql = format!(
            "insert into {} (action_id, tenant_id, idempotency_key, action_fingerprint, \
             preparation, state) values ($1, $2, $3, $4, $5, 'PROPOSED') \
             on conflict do nothing",
            self.table("effect_actions")
        );
        if transaction.execute(
            &sql,
            &[
                &action.action_id,
                &action.tenant_id,
                &action.idempotency_key,
                &action.fingerprint,
                &preparation,
            ],
        )? == 1
        {
            transaction.commit()?;
            return Ok(PrepareActionResult::NewAction);
        }
        if let Some((existing, _)) =
            self.load_action_with(&mut transaction, &action.action_id, true)?
        {
            transaction.commit()?;
            return Ok(if existing.preparation == *action {
                PrepareActionResult::ExistingSameAction(Box::new(existing))
            } else {
                PrepareActionResult::ActionIdConflict(Box::new(existing))
            });
        }
        let lookup = format!(
            "select action_id from {} where tenant_scope = coalesce($1, '') \
             and idempotency_key = $2 for update",
            self.table("effect_actions")
        );
        let existing_id: String = transaction
            .query_one(&lookup, &[&action.tenant_id, &action.idempotency_key])?
            .get(0);
        let (existing, _) = self
            .load_action_with(&mut transaction, &existing_id, false)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(existing_id.clone()))?;
        transaction.commit()?;
        Ok(if existing.preparation.fingerprint == action.fingerprint {
            PrepareActionResult::ExistingSameAction(Box::new(existing))
        } else {
            PrepareActionResult::IdempotencyConflict
        })
    }

    fn load_action(&self, action_id: &str) -> Result<Option<ActionRecord>, Self::Error> {
        let mut connection = self.connection()?;
        Ok(self
            .load_action_with(&mut *connection, action_id, false)?
            .map(|(action, _)| action))
    }

    fn authorize_action(
        &self,
        action_id: &str,
        expected: ExecutionState,
        grant_digest: &str,
        approval_reference: Option<&str>,
    ) -> Result<(), Self::Error> {
        if grant_digest.trim().is_empty() {
            return Err(ReferenceStoreError::InvalidGrantDigest.into());
        }
        if !is_valid_authorization_transition(expected, ExecutionState::Authorized) {
            return Err(ReferenceStoreError::InvalidAuthorizationState(expected).into());
        }
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (mut action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        if action.state != ExecutionState::Proposed {
            return Err(ReferenceStoreError::InvalidAuthorizationState(action.state).into());
        }
        action.preparation.grant_digest = Some(grant_digest.to_owned());
        action.preparation.approval_reference = approval_reference.map(ToOwned::to_owned);
        action.state = ExecutionState::Authorized;
        self.update_action(&mut transaction, &action, revision)?;
        transaction.commit()?;
        Ok(())
    }

    fn refresh_authorization(
        &self,
        action_id: &str,
        expected: ExecutionState,
        grant_digest: &str,
        approval_reference: Option<&str>,
    ) -> Result<(), Self::Error> {
        if grant_digest.trim().is_empty() {
            return Err(ReferenceStoreError::InvalidGrantDigest.into());
        }
        if !matches!(
            expected,
            ExecutionState::Authorized | ExecutionState::Prepared
        ) {
            return Err(ReferenceStoreError::InvalidAuthorizationRefreshState(expected).into());
        }
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (mut action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        if action.state != expected {
            return Err(ReferenceStoreError::UnexpectedState {
                expected: Some(expected),
                actual: action.state,
            }
            .into());
        }
        let now = Self::database_now_ms(&mut transaction)?;
        if expected == ExecutionState::Prepared
            && let Some(lease) = action.lease.as_ref()
            && lease.expires_at_unix_ms > now
        {
            return Err(ReferenceStoreError::AuthorizationLeaseHeld(lease.clone()).into());
        }
        action.preparation.grant_digest = Some(grant_digest.to_owned());
        action.preparation.approval_reference = approval_reference.map(ToOwned::to_owned);
        self.update_action(&mut transaction, &action, revision)?;
        transaction.commit()?;
        Ok(())
    }

    fn lease_configuration(&self) -> Result<LeaseConfiguration, Self::Error> {
        Ok(self.lease_configuration)
    }

    fn lease_status(&self, action_id: &str) -> Result<LeaseStatus, Self::Error> {
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (action, _) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        let now = Self::database_now_ms(&mut transaction)?;
        transaction.commit()?;
        Ok(match action.lease {
            Some(lease) if lease.expires_at_unix_ms > now => LeaseStatus::HeldByOther(lease),
            _ => LeaseStatus::Available,
        })
    }

    fn claim_lease(
        &self,
        action_id: &str,
        expected: ExecutionState,
        owner_id: &str,
        requested_duration_ms: Option<u64>,
    ) -> Result<LeaseAcquireResult, Self::Error> {
        let duration = match self
            .lease_configuration
            .resolve_duration(requested_duration_ms)
        {
            Ok(duration) => duration,
            Err(error) => return Ok(LeaseAcquireResult::DurationRejected(error)),
        };
        if !is_leaseable_state(expected) {
            return Err(ReferenceStoreError::InvalidLeaseState(expected).into());
        }
        let duration = postgres_i64(duration, "lease duration")?;
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (mut action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        if action.state != expected {
            return Err(ReferenceStoreError::UnexpectedState {
                expected: Some(expected),
                actual: action.state,
            }
            .into());
        }
        let now = Self::database_now_ms(&mut transaction)?;
        if let Some(lease) = action.lease.as_ref()
            && lease.expires_at_unix_ms > now
        {
            transaction.commit()?;
            return Ok(LeaseAcquireResult::HeldByOther(lease.clone()));
        }
        let reclaimed = action.lease.is_some();
        let next_generation = action
            .lease_generation
            .checked_add(1)
            .filter(|generation| *generation <= i64::MAX as u64)
            .ok_or(ReferenceStoreError::FencingGenerationExhausted)?;
        let expiry_sql = "select floor(extract(epoch from \
            (clock_timestamp() + ($1::bigint * interval '1 millisecond'))) * 1000)::bigint";
        let expiry = nonnegative_u64(
            transaction.query_one(expiry_sql, &[&duration])?.get(0),
            "lease expiry",
        )?;
        let lease = ActionLease {
            owner_id: owner_id.to_owned(),
            generation: next_generation,
            expires_at_unix_ms: expiry,
        };
        action.lease_generation = next_generation;
        action.lease = Some(lease.clone());
        self.update_action(&mut transaction, &action, revision)?;
        transaction.commit()?;
        Ok(if reclaimed {
            LeaseAcquireResult::ExpiredReclaimed(lease)
        } else {
            LeaseAcquireResult::Acquired(lease)
        })
    }

    fn renew_lease(
        &self,
        action_id: &str,
        expected: ExecutionState,
        lease: &ActionLease,
        requested_duration_ms: Option<u64>,
    ) -> Result<LeaseRenewResult, Self::Error> {
        if !self.lease_configuration.renewal_enabled {
            return Ok(LeaseRenewResult::RenewalNotPermitted);
        }
        let duration = match self
            .lease_configuration
            .resolve_duration(requested_duration_ms)
        {
            Ok(duration) => duration,
            Err(error) => return Ok(LeaseRenewResult::DurationRejected(error)),
        };
        if !is_leaseable_state(expected) {
            return Err(ReferenceStoreError::InvalidLeaseState(expected).into());
        }
        let duration = postgres_i64(duration, "lease duration")?;
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (mut action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        let now = Self::database_now_ms(&mut transaction)?;
        if action.state != expected
            || action.lease.as_ref() != Some(lease)
            || lease.expires_at_unix_ms <= now
        {
            transaction.commit()?;
            return Ok(LeaseRenewResult::LeaseLost);
        }
        let expiry_sql = "select floor(extract(epoch from \
            (clock_timestamp() + ($1::bigint * interval '1 millisecond'))) * 1000)::bigint";
        let expiry = nonnegative_u64(
            transaction.query_one(expiry_sql, &[&duration])?.get(0),
            "lease expiry",
        )?;
        let renewed = ActionLease {
            expires_at_unix_ms: expiry,
            ..lease.clone()
        };
        action.lease = Some(renewed.clone());
        self.update_action(&mut transaction, &action, revision)?;
        transaction.commit()?;
        Ok(LeaseRenewResult::Renewed(renewed))
    }

    fn release_lease(
        &self,
        action_id: &str,
        expected: ExecutionState,
        lease: &ActionLease,
    ) -> Result<LeaseReleaseResult, Self::Error> {
        if !is_leaseable_state(expected) {
            return Err(ReferenceStoreError::InvalidLeaseState(expected).into());
        }
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (mut action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        if action.state != expected || action.lease.as_ref() != Some(lease) {
            transaction.commit()?;
            return Ok(LeaseReleaseResult::LeaseLost);
        }
        action.lease = None;
        self.update_action(&mut transaction, &action, revision)?;
        transaction.commit()?;
        Ok(LeaseReleaseResult::Released)
    }

    fn transition_with_lease(
        &self,
        action_id: &str,
        expected: ExecutionState,
        lease: &ActionLease,
        next: ExecutionState,
    ) -> Result<(), Self::Error> {
        if !is_leaseable_state(expected) {
            return Err(ReferenceStoreError::InvalidLeaseState(expected).into());
        }
        if !is_valid_leased_transition(expected, next) {
            return Err(ReferenceStoreError::InvalidTransition {
                current: expected,
                next,
            }
            .into());
        }
        if next == ExecutionState::Dispatching {
            // Boundary A: the dispatch marker itself was not durably persisted,
            // so no provider call can have happened through this path. A caller
            // may classify this as an ordinary pre-dispatch failure.
            injected_database_failure("dispatching_transition")?;
        }
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (mut action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        validate_fenced_action(
            &action,
            expected,
            lease,
            Self::database_now_ms(&mut transaction)?,
        )?;
        action.state = next;
        if !matches!(
            next,
            ExecutionState::Dispatching | ExecutionState::Reconciling
        ) {
            action.lease = None;
        }
        self.update_action(&mut transaction, &action, revision)?;
        transaction.commit()?;
        Ok(())
    }

    fn finalize_pre_dispatch_failure(
        &self,
        action_id: &str,
        lease: &ActionLease,
        evidence: &PreDispatchFailureEvidence,
    ) -> Result<(), Self::Error> {
        let expected = ExecutionState::Dispatching;
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (mut action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        validate_fenced_action(
            &action,
            expected,
            lease,
            Self::database_now_ms(&mut transaction)?,
        )?;
        if !evidence
            .binds_action(&action.preparation)
            .map_err(|_| ReferenceStoreError::InvalidGrantDigest)?
        {
            return Err(ReferenceStoreError::EvidenceBindingMismatch {
                action_id: action_id.to_owned(),
            }
            .into());
        }
        if !is_valid_pre_dispatch_failure_finalization(expected) {
            return Err(ReferenceStoreError::InvalidTransition {
                current: expected,
                next: ExecutionState::Failed,
            }
            .into());
        }
        action.terminal_evidence = Some(TerminalEvidence::PreDispatchFailure(evidence.clone()));
        action.state = ExecutionState::Failed;
        action.lease = None;
        self.update_action(&mut transaction, &action, revision)?;
        transaction.commit()?;
        Ok(())
    }

    fn transition(
        &self,
        action_id: &str,
        expected: Option<ExecutionState>,
        next: ExecutionState,
    ) -> Result<(), Self::Error> {
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (mut action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        if Some(action.state) != expected {
            return Err(ReferenceStoreError::UnexpectedState {
                expected,
                actual: action.state,
            }
            .into());
        }
        if let Some(lease) = action.lease.as_ref()
            && lease.expires_at_unix_ms > Self::database_now_ms(&mut transaction)?
        {
            return Err(ReferenceStoreError::LeaseHeld(lease.clone()).into());
        }
        if !is_valid_generic_transition(action.state, next) {
            return Err(ReferenceStoreError::InvalidTransition {
                current: action.state,
                next,
            }
            .into());
        }
        if next == ExecutionState::Prepared
            && ActionEvidenceBinding::try_from(&action.preparation).is_err()
        {
            return Err(ReferenceStoreError::InvalidGrantDigest.into());
        }
        action.state = next;
        if !matches!(
            next,
            ExecutionState::Dispatching | ExecutionState::Reconciling
        ) {
            action.lease = None;
        }
        self.update_action(&mut transaction, &action, revision)?;
        transaction.commit()?;
        Ok(())
    }
}

impl EffectStore for PostgresEffectStore {
    type Error = PostgresEffectStoreError;

    fn evidence_snapshot(&self, action_id: &str) -> Result<EvidenceSnapshot, Self::Error> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()?;
        let (action, revision) = self
            .load_action_with(&mut transaction, action_id, false)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        let receipt = self.load_receipt_with(&mut transaction, action_id)?;
        let conflicts = self.load_conflicts_with(&mut transaction, action_id)?;
        transaction.commit()?;
        Ok(EvidenceSnapshot {
            action,
            revision,
            receipt,
            conflicts,
        })
    }

    fn observe_terminal_evidence(
        &self,
        action_id: &str,
        receipt: &ReceiptRecord,
    ) -> Result<EvidenceObservationResult, Self::Error> {
        receipt
            .validate_terminal()
            .map_err(ReferenceStoreError::InvalidReceipt)?;
        if receipt.action_id != action_id {
            return Err(ReferenceStoreError::EvidenceBindingMismatch {
                action_id: action_id.to_owned(),
            }
            .into());
        }
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        let evidence = TerminalEvidence::Receipt(receipt.identity());
        if !evidence
            .binds_action(&action.preparation)
            .map_err(|_| ReferenceStoreError::InvalidGrantDigest)?
        {
            return Err(ReferenceStoreError::EvidenceBindingMismatch {
                action_id: action_id.to_owned(),
            }
            .into());
        }
        let primary = self
            .load_receipt_with(&mut transaction, action_id)?
            .ok_or(ReferenceStoreError::PrimaryEvidenceRequiresFencedFinalization)?;
        if primary.identity() == receipt.identity() {
            transaction.commit()?;
            return Ok(EvidenceObservationResult::AlreadyObserved);
        }
        let conflict = ReceiptConflict::new(&primary, receipt);
        if !self.insert_conflict(&mut transaction, &conflict)? {
            transaction.commit()?;
            return Ok(EvidenceObservationResult::ConflictAlreadyRecorded(conflict));
        }
        self.update_action(&mut transaction, &action, checked_revision(revision)?)?;
        transaction.commit()?;
        Ok(EvidenceObservationResult::ConflictRecorded(conflict))
    }

    fn begin_reconciliation(
        &self,
        action_id: &str,
        lease: &ActionLease,
    ) -> Result<ReconciliationStart, Self::Error> {
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (mut action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        validate_fenced_action(
            &action,
            ExecutionState::Unknown,
            lease,
            Self::database_now_ms(&mut transaction)?,
        )?;
        let receipt = self.load_receipt_with(&mut transaction, action_id)?;
        let conflicts = self.load_conflicts_with(&mut transaction, action_id)?;
        if receipt.is_some() || !conflicts.is_empty() {
            return Err(ReferenceStoreError::ReconciliationEvidencePresent.into());
        }
        action.state = ExecutionState::Reconciling;
        self.update_action(&mut transaction, &action, revision)?;
        let snapshot = EvidenceSnapshot {
            action: action.clone(),
            revision,
            receipt,
            conflicts,
        };
        transaction.commit()?;
        Ok(ReconciliationStart {
            action,
            evidence: snapshot,
        })
    }

    fn finalize_reconciliation_receipt(
        &self,
        action_id: &str,
        lease: &ActionLease,
        expected_evidence_revision: u64,
        receipt: &ReceiptRecord,
    ) -> Result<EffectFinalizeResult, Self::Error> {
        self.finalize_receipt_transaction(Terminalization {
            action_id,
            expected: ExecutionState::Reconciling,
            lease,
            expected_evidence_revision: Some(expected_evidence_revision),
            receipt,
            remaining_action_budget: None,
            // Boundary D: a failure here must leave the action unknown or
            // reconciling so a later reconciliation can still finish.
            failure_point: "reconciliation_finalization",
        })
    }

    fn complete_reconciliation_unknown(
        &self,
        action_id: &str,
        lease: &ActionLease,
        expected_evidence_revision: u64,
    ) -> Result<(), Self::Error> {
        // Boundary D: the reconciliation outcome could not be persisted. The
        // action must remain unknown rather than being resolved by inference.
        injected_database_failure("reconciliation_completion")?;
        let mut connection = self.connection()?;
        let mut transaction = connection.transaction()?;
        let (mut action, revision) = self
            .load_action_with(&mut transaction, action_id, true)?
            .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
        if revision != expected_evidence_revision {
            return Err(ReferenceStoreError::EvidenceRevisionChanged {
                expected: expected_evidence_revision,
                actual: revision,
            }
            .into());
        }
        validate_fenced_action(
            &action,
            ExecutionState::Reconciling,
            lease,
            Self::database_now_ms(&mut transaction)?,
        )?;
        action.state = ExecutionState::Unknown;
        action.lease = None;
        self.update_action(&mut transaction, &action, revision)?;
        transaction.commit()?;
        Ok(())
    }

    fn finalize_terminal_receipt(
        &self,
        action_id: &str,
        expected: ExecutionState,
        lease: &ActionLease,
        receipt: &ReceiptRecord,
    ) -> Result<EffectFinalizeResult, Self::Error> {
        self.finalize_receipt_transaction(Terminalization {
            action_id,
            expected,
            lease,
            expected_evidence_revision: None,
            receipt,
            remaining_action_budget: None,
            failure_point: "terminal_finalization",
        })
    }

    /// Route the shared trait's budget-aware form to the adapter's own one.
    ///
    /// This is the load-bearing half of the trusted deadline: the kernel holds a
    /// deadline, the trait is what it can call, and only here does that deadline
    /// become the PostgreSQL lock and statement timeouts derived by
    /// [`PostgresEffectStore::for_remaining`].
    fn finalize_terminal_receipt_within_budget(
        &self,
        action_id: &str,
        expected: ExecutionState,
        lease: &ActionLease,
        receipt: &ReceiptRecord,
        remaining: Duration,
    ) -> Result<EffectFinalizeResult, Self::Error> {
        PostgresEffectStore::finalize_terminal_receipt_within_budget(
            self, action_id, expected, lease, receipt, remaining,
        )
    }
}

fn validate_schema_name(schema: &str) -> Result<(), PostgresEffectStoreError> {
    let mut characters = schema.chars();
    let valid_first = characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_lowercase());
    let valid_rest = characters.all(|character| {
        character == '_' || character.is_ascii_lowercase() || character.is_ascii_digit()
    });
    if schema.len() > 63 || !valid_first || !valid_rest {
        return Err(PostgresEffectStoreError::InvalidSchemaName(
            schema.to_owned(),
        ));
    }
    Ok(())
}

fn state_name(state: ExecutionState) -> &'static str {
    match state {
        ExecutionState::Proposed => "PROPOSED",
        ExecutionState::Authorized => "AUTHORIZED",
        ExecutionState::Prepared => "PREPARED",
        ExecutionState::Dispatching => "DISPATCHING",
        ExecutionState::Committed => "COMMITTED",
        ExecutionState::Failed => "FAILED",
        ExecutionState::Unknown => "UNKNOWN",
        ExecutionState::Reconciling => "RECONCILING",
        ExecutionState::Cancelled => "CANCELLED",
    }
}

fn parse_state(state: &str) -> Result<ExecutionState, PostgresEffectStoreError> {
    match state {
        "PROPOSED" => Ok(ExecutionState::Proposed),
        "AUTHORIZED" => Ok(ExecutionState::Authorized),
        "PREPARED" => Ok(ExecutionState::Prepared),
        "DISPATCHING" => Ok(ExecutionState::Dispatching),
        "COMMITTED" => Ok(ExecutionState::Committed),
        "FAILED" => Ok(ExecutionState::Failed),
        "UNKNOWN" => Ok(ExecutionState::Unknown),
        "RECONCILING" => Ok(ExecutionState::Reconciling),
        "CANCELLED" => Ok(ExecutionState::Cancelled),
        value => Err(PostgresEffectStoreError::CorruptData(format!(
            "unknown execution state {value}"
        ))),
    }
}

fn action_and_revision_from_row(row: Row) -> Result<(ActionRecord, u64), PostgresEffectStoreError> {
    let preparation = from_json_value(row.get("preparation"))?;
    let state = parse_state(row.get("state"))?;
    let lease_generation = nonnegative_u64(row.get("lease_generation"), "lease generation")?;
    let lease_owner: Option<String> = row.get("lease_owner");
    let lease_expiry: Option<i64> = row.get("lease_expires_at_unix_ms");
    let lease = match (lease_owner, lease_expiry) {
        (Some(owner_id), Some(expiry)) => Some(ActionLease {
            owner_id,
            generation: lease_generation,
            expires_at_unix_ms: nonnegative_u64(expiry, "lease expiry")?,
        }),
        (None, None) => None,
        _ => {
            return Err(PostgresEffectStoreError::CorruptData(
                "lease owner and expiry must both be present or absent".into(),
            ));
        }
    };
    let terminal_evidence = row
        .get::<_, Option<Value>>("terminal_evidence")
        .map(from_json_value)
        .transpose()?;
    let revision = nonnegative_u64(row.get("evidence_revision"), "evidence revision")?;
    Ok((
        ActionRecord {
            preparation,
            state,
            lease,
            lease_generation,
            terminal_evidence,
        },
        revision,
    ))
}

fn validate_fenced_action(
    action: &ActionRecord,
    expected: ExecutionState,
    lease: &ActionLease,
    now: u64,
) -> Result<(), PostgresEffectStoreError> {
    if !is_leaseable_state(expected) {
        return Err(ReferenceStoreError::InvalidLeaseState(expected).into());
    }
    if action.state != expected {
        return Err(ReferenceStoreError::UnexpectedState {
            expected: Some(expected),
            actual: action.state,
        }
        .into());
    }
    if action.lease.as_ref() != Some(lease) || lease.expires_at_unix_ms <= now {
        return Err(ReferenceStoreError::LeaseHeld(
            action.lease.clone().unwrap_or_else(|| lease.clone()),
        )
        .into());
    }
    Ok(())
}

fn checked_revision(revision: u64) -> Result<u64, PostgresEffectStoreError> {
    revision
        .checked_add(1)
        .filter(|revision| *revision <= i64::MAX as u64)
        .ok_or_else(|| ReferenceStoreError::EvidenceRevisionExhausted.into())
}

fn postgres_i64(value: u64, field: &'static str) -> Result<i64, PostgresEffectStoreError> {
    value
        .try_into()
        .map_err(|_| PostgresEffectStoreError::IntegerOutOfRange(field))
}

fn nonnegative_u64(value: i64, field: &'static str) -> Result<u64, PostgresEffectStoreError> {
    value
        .try_into()
        .map_err(|_| PostgresEffectStoreError::CorruptData(format!("negative {field}")))
}

fn to_json_value<T: Serialize>(value: &T) -> Result<Value, PostgresEffectStoreError> {
    serde_json::to_value(value).map_err(Into::into)
}

fn from_json_value<T: serde::de::DeserializeOwned>(
    value: Value,
) -> Result<T, PostgresEffectStoreError> {
    serde_json::from_value(value).map_err(Into::into)
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, PostgresEffectStoreError> {
    let bytes = serde_json_canonicalizer::to_vec(value)?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use native_tls::TlsAcceptor;
    use openssl::pkcs12::Pkcs12;
    use openssl::pkey::PKey;
    use openssl::x509::X509;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, date_time_ymd,
    };
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    struct TestPki {
        ca_pem: String,
        server_identity: Identity,
        client_identity_pkcs12: Vec<u8>,
        client_identity_password: String,
    }

    fn pkcs12_identity(
        certificate_der: &[u8],
        private_key_der: &[u8],
        password: &str,
    ) -> (Vec<u8>, Identity) {
        let certificate = X509::from_der(certificate_der).expect("parse X.509 certificate");
        let private_key =
            PKey::private_key_from_pkcs8(private_key_der).expect("parse PKCS #8 private key");
        let archive = Pkcs12::builder()
            .name("NEMO test identity")
            .pkey(&private_key)
            .cert(&certificate)
            .build2(password)
            .expect("build PKCS #12 identity")
            .to_der()
            .expect("serialize PKCS #12 identity");
        let identity = Identity::from_pkcs12(&archive, password).expect("load PKCS #12 identity");
        (archive, identity)
    }

    fn test_pki(hostname: &str, expired: bool) -> TestPki {
        let ca_key = KeyPair::generate().expect("generate CA key");
        let mut ca_parameters = CertificateParams::default();
        ca_parameters.distinguished_name = DistinguishedName::new();
        ca_parameters
            .distinguished_name
            .push(DnType::CommonName, "NEMO transport test root");
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_parameters.self_signed(&ca_key).expect("create CA");

        let server_key = KeyPair::generate().expect("generate server key");
        let mut server_parameters =
            CertificateParams::new(vec![hostname.to_owned()]).expect("server parameters");
        server_parameters.distinguished_name = DistinguishedName::new();
        server_parameters
            .distinguished_name
            .push(DnType::CommonName, hostname);
        server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if expired {
            server_parameters.not_before = date_time_ymd(2019, 1, 1);
            server_parameters.not_after = date_time_ymd(2020, 1, 1);
        }
        let server = server_parameters
            .signed_by(&server_key, &ca, &ca_key)
            .expect("sign server certificate");
        let (_, server_identity) = pkcs12_identity(
            server.der().as_ref(),
            &server_key.serialize_der(),
            "server-test",
        );

        let client_key = KeyPair::generate().expect("generate client key");
        let mut client_parameters =
            CertificateParams::new(Vec::<String>::new()).expect("client parameters");
        client_parameters.distinguished_name = DistinguishedName::new();
        client_parameters
            .distinguished_name
            .push(DnType::CommonName, "NEMO transport test client");
        client_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client = client_parameters
            .signed_by(&client_key, &ca, &ca_key)
            .expect("sign client certificate");

        let client_identity_password = "client-test".to_owned();
        let (client_identity_pkcs12, _) = pkcs12_identity(
            client.der().as_ref(),
            &client_key.serialize_der(),
            &client_identity_password,
        );

        TestPki {
            ca_pem: ca.pem(),
            server_identity,
            client_identity_pkcs12,
            client_identity_password,
        }
    }

    fn tls_handshake(
        connector: &TlsConnector,
        server_name: &str,
        server_identity: Identity,
    ) -> bool {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS test server");
        let address = listener.local_addr().expect("TLS test address");
        let server = thread::spawn(move || {
            let acceptor = TlsAcceptor::new(server_identity).expect("build TLS acceptor");
            let (stream, _) = listener.accept().expect("accept TLS test connection");
            acceptor.accept(stream).is_ok()
        });
        let stream = TcpStream::connect(address).expect("connect TLS test server");
        let client_succeeded = connector.connect(server_name, stream).is_ok();
        let _ = server.join().expect("join TLS test server");
        client_succeeded
    }

    #[test]
    fn plaintext_transport_rejects_non_loopback_tcp() {
        let error = PostgresEffectStore::connect_insecure_local_for_tests(
            "host=db.example.test user=nemo",
            "nemo",
            LeaseConfiguration::default(),
            1,
        )
        .err()
        .expect("remote plaintext must be rejected before pool construction");
        assert!(matches!(
            error,
            PostgresEffectStoreError::InvalidTransport(_)
        ));
    }

    #[test]
    fn plaintext_test_transport_accepts_only_local_targets() {
        let loopback: Config = "host=127.0.0.1 user=nemo".parse().unwrap();
        validate_local_target(&loopback, true).expect("loopback TCP is allowed in tests");

        let remote_address: Config = "host=localhost hostaddr=192.0.2.1 user=nemo"
            .parse()
            .unwrap();
        assert!(validate_local_target(&remote_address, true).is_err());
    }

    #[test]
    fn operation_budgets_reject_zero_or_inverted_limits() {
        let budgets = PostgresOperationBudgets {
            lock: Duration::ZERO,
            ..PostgresOperationBudgets::default()
        };
        assert!(matches!(
            budgets.validate(),
            Err(PostgresEffectStoreError::InvalidOperationBudget("lock"))
        ));

        let budgets = PostgresOperationBudgets {
            lock: Duration::from_secs(11),
            statement: Duration::from_secs(10),
            ..PostgresOperationBudgets::default()
        };
        assert!(matches!(
            budgets.validate(),
            Err(PostgresEffectStoreError::InvalidOperationBudget("lock"))
        ));
    }

    #[test]
    fn mutual_tls_credentials_redact_debug_output() {
        let credentials = PostgresMutualTlsCredentials {
            root_ca_pem: b"root-ca-secret".to_vec(),
            client_identity_pkcs12: b"client-identity-secret".to_vec(),
            client_identity_password: "client-password-secret".into(),
        };
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("root-ca-secret"));
        assert!(!debug.contains("client-identity-secret"));
        assert!(!debug.contains("client-password-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn local_socket_transport_rejects_tcp() {
        let socket: Config = "host=/var/run/postgresql user=nemo".parse().unwrap();
        validate_local_target(&socket, false).expect("Unix socket is local");

        let loopback: Config = "host=localhost user=nemo".parse().unwrap();
        assert!(validate_local_target(&loopback, false).is_err());
    }

    #[test]
    fn verified_tls_accepts_a_trusted_ca_and_matching_hostname() {
        let pki = test_pki("localhost", false);
        let configuration: Config = "host=localhost user=nemo".parse().unwrap();
        let connector = verified_native_tls_connector(&configuration, pki.ca_pem.as_bytes(), None)
            .expect("build verified TLS connector");
        assert!(tls_handshake(&connector, "localhost", pki.server_identity));
    }

    #[test]
    fn verified_tls_rejects_an_untrusted_ca() {
        let server_pki = test_pki("localhost", false);
        let untrusted_pki = test_pki("localhost", false);
        let configuration: Config = "host=localhost user=nemo".parse().unwrap();
        let connector =
            verified_native_tls_connector(&configuration, untrusted_pki.ca_pem.as_bytes(), None)
                .expect("build TLS connector with unrelated CA");
        assert!(!tls_handshake(
            &connector,
            "localhost",
            server_pki.server_identity
        ));
    }

    #[test]
    fn verified_tls_rejects_a_wrong_hostname() {
        let pki = test_pki("localhost", false);
        let configuration: Config = "host=localhost user=nemo".parse().unwrap();
        let connector = verified_native_tls_connector(&configuration, pki.ca_pem.as_bytes(), None)
            .expect("build verified TLS connector");
        assert!(!tls_handshake(
            &connector,
            "wrong.example.test",
            pki.server_identity
        ));
    }

    #[test]
    fn verified_tls_rejects_an_expired_certificate() {
        let pki = test_pki("localhost", true);
        let configuration: Config = "host=localhost user=nemo".parse().unwrap();
        let connector = verified_native_tls_connector(&configuration, pki.ca_pem.as_bytes(), None)
            .expect("build verified TLS connector");
        assert!(!tls_handshake(&connector, "localhost", pki.server_identity));
    }

    #[test]
    fn verified_tls_rejects_a_plaintext_endpoint() {
        let pki = test_pki("localhost", false);
        let configuration: Config = "host=localhost user=nemo".parse().unwrap();
        let connector = verified_native_tls_connector(&configuration, pki.ca_pem.as_bytes(), None)
            .expect("build verified TLS connector");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind plaintext test server");
        let address = listener.local_addr().expect("plaintext test address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept plaintext connection");
            stream.write_all(b"not tls\n").expect("write plaintext");
        });
        let stream = TcpStream::connect(address).expect("connect plaintext test server");
        assert!(connector.connect("localhost", stream).is_err());
        server.join().expect("join plaintext test server");
    }

    #[test]
    fn mutual_tls_accepts_a_valid_pkcs12_client_identity() {
        let pki = test_pki("localhost", false);
        let configuration: Config = "host=localhost user=nemo".parse().unwrap();
        let identity =
            Identity::from_pkcs12(&pki.client_identity_pkcs12, &pki.client_identity_password)
                .expect("load PKCS #12 client identity");
        verified_native_tls_connector(&configuration, pki.ca_pem.as_bytes(), Some(identity))
            .expect("build mutual TLS connector");
    }

    #[test]
    fn verified_tls_rejects_unix_socket_targets() {
        #[cfg(unix)]
        {
            let configuration: Config = "host=/var/run/postgresql user=nemo".parse().unwrap();
            let pki = test_pki("localhost", false);
            assert!(
                verified_native_tls_connector(&configuration, pki.ca_pem.as_bytes(), None,)
                    .is_err()
            );
        }
    }
}

#[cfg(all(test, feature = "unstable-hardening-testkit"))]
mod tests {
    use super::*;
    use crate::conformance::{
        EffectStoreConformanceHarness, StoreConformanceHarness, fixture_action, fixture_receipt,
        run_action_store_conformance, run_effect_store_conformance,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    static SCHEMA_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct PostgresHarness {
        effects: PostgresEffectStore,
        receipts: InMemoryReceiptStore,
    }

    fn test_connection_string() -> String {
        std::env::var("NEMO_RELAY_TEST_POSTGRES_URL")
            .expect("NEMO_RELAY_TEST_POSTGRES_URL is required for ignored PostgreSQL tests")
    }

    fn unique_schema() -> String {
        format!(
            "nemo_effect_test_{}_{}",
            std::process::id(),
            SCHEMA_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn create_store(connection_string: &str, schema: &str) -> PostgresEffectStore {
        let effects = PostgresEffectStore::connect_insecure_local_for_tests(
            connection_string,
            schema,
            LeaseConfiguration {
                default_duration_ms: 100,
                maximum_duration_ms: 10_000,
                renewal_enabled: true,
            },
            8,
        )
        .expect("connect PostgreSQL effect store");
        effects.migrate().expect("migrate PostgreSQL effect store");
        effects
            .verify_schema()
            .expect("fresh migrations must satisfy this runtime");
        effects
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn the_shared_trait_routes_finalization_through_the_trusted_budget() {
        let schema = unique_schema();
        let effects = create_store(&test_connection_string(), &schema);

        // The kernel holds only the shared trait, so this is the path a trusted
        // deadline actually takes. Exercising the inherent method would prove
        // nothing about what the kernel can reach.
        fn finalize_through_trait<E: EffectStore>(
            store: &E,
            action_id: &str,
            lease: &ActionLease,
            receipt: &ReceiptRecord,
            remaining: Duration,
        ) -> Result<EffectFinalizeResult, E::Error> {
            store.finalize_terminal_receipt_within_budget(
                action_id,
                ExecutionState::Dispatching,
                lease,
                receipt,
                remaining,
            )
        }

        let mut action = fixture_action();
        action.grant_digest = Some("grant".into());
        let action_id = action.action_id.clone();
        let receipt = fixture_receipt(&action, ExecutionState::Committed, "budget-routing");
        let lease = ActionLease {
            owner_id: "budget-routing".into(),
            generation: 1,
            expires_at_unix_ms: u64::MAX,
        };

        // The budget is validated before the action is loaded, so with the
        // receipt correctly bound this is a statement about the budget rather
        // than about a missing action. The default trait implementation ignores
        // its budget and would instead report the action as missing, which is
        // what makes the error variant the thing that distinguishes a wired
        // budget from an ignored one.
        let outcome =
            finalize_through_trait(&effects, &action_id, &lease, &receipt, Duration::ZERO);
        assert!(
            matches!(
                outcome,
                Err(PostgresEffectStoreError::InvalidOperationBudget(_))
            ),
            "a zero trusted budget must be refused by the adapter: {outcome:?}"
        );
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn schema_verification_rejects_modified_migration_checksums() {
        let schema = unique_schema();
        let effects = create_store(&test_connection_string(), &schema);
        effects
            .connection()
            .unwrap()
            .execute(
                &format!(
                    "update \"{schema}\".effect_schema_migrations set checksum = 'tampered' where version = 1"
                ),
                &[],
            )
            .unwrap();
        assert!(matches!(
            effects.verify_schema(),
            Err(PostgresEffectStoreError::MigrationHistoryMismatch(_))
        ));
        effects.drop_schema().unwrap();
    }

    fn dispatching_action(
        effects: &PostgresEffectStore,
    ) -> (ActionPreparation, ActionLease, ReceiptRecord) {
        let action = fixture_action();
        effects.claim_action(&action).unwrap();
        effects
            .authorize_action(&action.action_id, ExecutionState::Proposed, "grant", None)
            .unwrap();
        effects
            .transition(
                &action.action_id,
                Some(ExecutionState::Authorized),
                ExecutionState::Prepared,
            )
            .unwrap();
        let lease = match effects
            .claim_lease(
                &action.action_id,
                ExecutionState::Prepared,
                "postgres-test-worker",
                Some(10_000),
            )
            .unwrap()
        {
            LeaseAcquireResult::Acquired(lease) => lease,
            result => panic!("expected dispatch lease, got {result:?}"),
        };
        effects
            .transition_with_lease(
                &action.action_id,
                ExecutionState::Prepared,
                &lease,
                ExecutionState::Dispatching,
            )
            .unwrap();
        let prepared = effects.load_action(&action.action_id).unwrap().unwrap();
        let receipt = fixture_receipt(
            &prepared.preparation,
            ExecutionState::Committed,
            "postgres-terminal-evidence",
        );
        (action, lease, receipt)
    }

    impl PostgresHarness {
        fn create() -> Self {
            let effects = create_store(&test_connection_string(), &unique_schema());
            Self {
                effects,
                receipts: InMemoryReceiptStore::default(),
            }
        }

        fn sleep_database(&self, duration_ms: u64) {
            let seconds = duration_ms as f64 / 1_000.0;
            self.effects
                .connection()
                .unwrap()
                .query_one("select pg_sleep($1)", &[&seconds])
                .unwrap();
        }
    }

    impl Drop for PostgresHarness {
        fn drop(&mut self) {
            self.effects.drop_schema().expect("drop test schema");
        }
    }

    impl StoreConformanceHarness for PostgresHarness {
        type Actions = PostgresEffectStore;
        type Receipts = InMemoryReceiptStore;

        fn new_harness() -> Self {
            Self::create()
        }

        fn actions(&self) -> &Self::Actions {
            &self.effects
        }

        fn receipts(&self) -> &Self::Receipts {
            &self.receipts
        }

        fn advance_store_clock(&self, duration_ms: u64) {
            self.sleep_database(duration_ms);
        }
    }

    impl EffectStoreConformanceHarness for PostgresHarness {
        type Effects = PostgresEffectStore;

        fn new_harness() -> Self {
            Self::create()
        }

        fn effects(&self) -> &Self::Effects {
            &self.effects
        }

        fn advance_store_clock(&self, duration_ms: u64) {
            self.sleep_database(duration_ms);
        }

        fn advance_evidence_revision(&self, action_id: &str) {
            let sql = format!(
                "update {} set evidence_revision = evidence_revision + 1 where action_id = $1",
                self.effects.table("effect_actions")
            );
            self.effects
                .connection()
                .unwrap()
                .execute(&sql, &[&action_id])
                .unwrap();
        }
    }

    #[test]
    fn rejects_unsafe_schema_names() {
        assert!(validate_schema_name("nemo_effects").is_ok());
        assert!(validate_schema_name("NEMO").is_err());
        assert!(validate_schema_name("nemo;drop schema public").is_err());
        assert!(matches!(
            PostgresEffectStore::connect_insecure_local_for_tests(
                "host=/tmp dbname=postgres",
                "nemo_effects",
                LeaseConfiguration::default(),
                0,
            ),
            Err(PostgresEffectStoreError::InvalidPoolSize(0))
        ));
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn postgres_action_store_passes_generic_conformance() {
        run_action_store_conformance::<PostgresHarness>();
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn lifecycle_only_failure_never_creates_a_receipt_backed_terminal_state() {
        let harness = PostgresHarness::create();
        let (action, lease, _receipt) = dispatching_action(&harness.effects);
        let prepared = harness
            .effects
            .load_action(&action.action_id)
            .unwrap()
            .unwrap();
        let failure = PreDispatchFailureEvidence {
            action_binding: ActionEvidenceBinding::try_from(&prepared.preparation)
                .expect("prepared action has a complete evidence binding"),
            code: "provider-not-contacted".into(),
            evidence_digest: "postgres-pre-dispatch-failure".into(),
        };

        harness
            .effects
            .finalize_pre_dispatch_failure(&action.action_id, &lease, &failure)
            .unwrap();

        let snapshot = harness
            .effects
            .evidence_snapshot(&action.action_id)
            .unwrap();
        assert_eq!(snapshot.action.state, ExecutionState::Failed);
        assert_eq!(
            snapshot.action.terminal_evidence,
            Some(TerminalEvidence::PreDispatchFailure(failure))
        );
        assert_eq!(snapshot.receipt, None);
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn postgres_effect_store_passes_generic_conformance() {
        run_effect_store_conformance::<PostgresHarness>();
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn concurrent_identical_finalizers_commit_one_primary_receipt() {
        let harness = PostgresHarness::create();
        let (action, lease, receipt) = dispatching_action(&harness.effects);
        let worker_count = 32;
        let barrier = Arc::new(Barrier::new(worker_count));
        let outcomes = std::thread::scope(|scope| {
            let workers = (0..worker_count)
                .map(|_| {
                    let store = harness.effects.clone();
                    let barrier = barrier.clone();
                    let action_id = action.action_id.clone();
                    let lease = lease.clone();
                    let receipt = receipt.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        store.finalize_terminal_receipt(
                            &action_id,
                            ExecutionState::Dispatching,
                            &lease,
                            &receipt,
                        )
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("finalizer thread"))
                .collect::<Vec<_>>()
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Ok(EffectFinalizeResult::Finalized(_))))
                .count(),
            1,
            "outcomes: {outcomes:#?}"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Ok(EffectFinalizeResult::AlreadyFinalized(_))))
                .count(),
            worker_count - 1,
            "outcomes: {outcomes:#?}"
        );
        assert!(
            outcomes.iter().all(Result::is_ok),
            "outcomes: {outcomes:#?}"
        );
        let snapshot = harness
            .effects
            .evidence_snapshot(&action.action_id)
            .unwrap();
        assert_eq!(snapshot.action.state, ExecutionState::Committed);
        assert_eq!(snapshot.receipt, Some(receipt));
        assert_eq!(snapshot.revision, 1);
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn concurrent_idempotency_claims_create_one_logical_action() {
        let harness = PostgresHarness::create();
        let worker_count = 64;
        let barrier = Arc::new(Barrier::new(worker_count));
        let outcomes = std::thread::scope(|scope| {
            let workers = (0..worker_count)
                .map(|worker| {
                    let store = harness.effects.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        let mut action = fixture_action();
                        action.action_id = format!("concurrent-action-{worker}");
                        barrier.wait();
                        store.claim_action(&action)
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("claim thread"))
                .collect::<Vec<_>>()
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Ok(PrepareActionResult::NewAction)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    matches!(outcome, Ok(PrepareActionResult::ExistingSameAction(_)))
                })
                .count(),
            worker_count - 1
        );
        let count_sql = format!(
            "select count(*) from {}",
            harness.effects.table("effect_actions")
        );
        let count: i64 = harness
            .effects
            .connection()
            .unwrap()
            .query_one(&count_sql, &[])
            .unwrap()
            .get(0);
        assert_eq!(count, 1);
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn terminal_transaction_rolls_back_receipt_when_revision_is_exhausted() {
        let harness = PostgresHarness::create();
        let (action, lease, receipt) = dispatching_action(&harness.effects);
        let sql = format!(
            "update {} set evidence_revision = $2 where action_id = $1",
            harness.effects.table("effect_actions")
        );
        harness
            .effects
            .connection()
            .unwrap()
            .execute(&sql, &[&action.action_id, &i64::MAX])
            .unwrap();
        assert!(matches!(
            harness.effects.finalize_terminal_receipt(
                &action.action_id,
                ExecutionState::Dispatching,
                &lease,
                &receipt,
            ),
            Err(PostgresEffectStoreError::Contract(
                ReferenceStoreError::EvidenceRevisionExhausted
            ))
        ));
        let snapshot = harness
            .effects
            .evidence_snapshot(&action.action_id)
            .unwrap();
        assert_eq!(snapshot.action.state, ExecutionState::Dispatching);
        assert_eq!(snapshot.action.lease, Some(lease));
        assert_eq!(snapshot.receipt, None);
        assert_eq!(snapshot.revision, i64::MAX as u64);
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn action_state_survives_a_fresh_pool_and_store_instance() {
        let connection_string = test_connection_string();
        let schema = unique_schema();
        let effects = create_store(&connection_string, &schema);
        let action = fixture_action();
        effects.claim_action(&action).unwrap();
        effects
            .authorize_action(&action.action_id, ExecutionState::Proposed, "grant", None)
            .unwrap();
        let expected = effects.load_action(&action.action_id).unwrap();
        drop(effects);

        let reopened = create_store(&connection_string, &schema);
        assert_eq!(reopened.load_action(&action.action_id).unwrap(), expected);
        reopened.drop_schema().unwrap();
    }

    // -- E3.1 physical schema verification ----------------------------------

    fn migration_ledger(effects: &PostgresEffectStore) -> Vec<(i64, String, String)> {
        effects
            .connection()
            .unwrap()
            .query(
                &format!(
                    "select version, name, checksum from {}.effect_schema_migrations order by version",
                    effects.quoted_schema()
                ),
                &[],
            )
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2)))
            .collect()
    }

    /// Every case leaves `effect_schema_migrations` untouched on purpose: the
    /// ledger alone must not be able to certify the database.
    const DESTRUCTIVE_DRIFT: &[(&str, &str)] = &[
        (
            "drop_index",
            r#"drop index "{schema}".effect_actions_recovery_idx"#,
        ),
        (
            "alter_column_type",
            r#"alter table "{schema}".effect_receipts
               alter column receipt_identity type varchar(255)"#,
        ),
        (
            "drop_constraint",
            r#"alter table "{schema}".effect_actions
               drop constraint effect_actions_lease_shape"#,
        ),
        (
            "change_generated_expression",
            r#"alter table "{schema}".effect_actions drop column tenant_scope;
               alter table "{schema}".effect_actions add column tenant_scope text
                 generated always as (coalesce(tenant_id, 'tampered')) stored"#,
        ),
        (
            "remove_not_null",
            r#"alter table "{schema}".effect_actions
               alter column idempotency_key drop not null"#,
        ),
        ("drop_receipts", r#"drop table "{schema}".effect_receipts"#),
        (
            "add_unexpected_trigger",
            r#"create function "{schema}".effect_unexpected_noop() returns trigger
                 language plpgsql as $$ begin return new; end $$;
               create trigger effect_actions_unexpected before update
                 on "{schema}".effect_actions for each row
                 execute function "{schema}".effect_unexpected_noop()"#,
        ),
        (
            "modify_foreign_key",
            r#"alter table "{schema}".effect_receipts
                 drop constraint effect_receipts_action_id_fkey;
               alter table "{schema}".effect_receipts
                 add constraint effect_receipts_action_id_fkey
                 foreign key (action_id) references "{schema}".effect_actions (action_id)
                 on delete cascade"#,
        ),
        (
            "drop_foreign_key",
            r#"alter table "{schema}".effect_receipt_conflicts
                 drop constraint effect_receipt_conflicts_action_id_fkey"#,
        ),
        (
            "drop_check_constraint",
            r#"alter table "{schema}".effect_actions
                 drop constraint effect_actions_preparation_binding"#,
        ),
        (
            "change_default",
            r#"alter table "{schema}".effect_actions
                 alter column lease_generation set default 5"#,
        ),
        (
            "drop_conflicts",
            r#"drop table "{schema}".effect_receipt_conflicts"#,
        ),
        (
            "add_unexpected_writable_column",
            r#"alter table "{schema}".effect_actions add column backdoor text"#,
        ),
        (
            "change_index_predicate",
            r#"drop index "{schema}".effect_actions_recovery_idx;
               create index effect_actions_recovery_idx
                 on "{schema}".effect_actions (state, lease_expires_at)
                 where state <> 'COMMITTED'"#,
        ),
        (
            "change_unique_constraint",
            r#"alter table "{schema}".effect_actions
                 drop constraint effect_actions_tenant_idempotency_key;
               alter table "{schema}".effect_actions
                 add constraint effect_actions_tenant_idempotency_key
                 unique (tenant_scope, action_id)"#,
        ),
    ];

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn schema_verification_rejects_physical_drift_with_an_intact_ledger() {
        for (name, template) in DESTRUCTIVE_DRIFT {
            let connection_string = test_connection_string();
            let schema = unique_schema();
            let effects = create_store(&connection_string, &schema);
            let ledger_before = migration_ledger(&effects);
            assert!(!ledger_before.is_empty());

            effects
                .connection()
                .unwrap()
                .batch_execute(&template.replace("{schema}", &schema))
                .expect("apply destructive drift");

            let result = effects.verify_schema();
            assert!(
                matches!(
                    &result,
                    Err(PostgresEffectStoreError::SchemaObjectMismatch { .. })
                ),
                "{name}: physical drift was accepted or misreported: {result:?}"
            );
            // Drift must be attributed to a specific object kind, not collapsed
            // into one opaque database error.
            if let Err(PostgresEffectStoreError::SchemaObjectMismatch { kind, detail }) = &result {
                assert_ne!(
                    *kind,
                    SchemaObjectKind::DigestOnly,
                    "{name}: drift was not attributed to a schema object: {detail}"
                );
            }
            assert_eq!(
                migration_ledger(&effects),
                ledger_before,
                "{name}: drift test must not modify the migration ledger"
            );
            effects.drop_schema().unwrap();
        }
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn schema_fingerprint_ignores_row_data() {
        // The recorded expectation is data, so writing durable rows must not
        // change the fingerprint. That is what keeps the check non-circular.
        let schema = unique_schema();
        let effects = create_store(&test_connection_string(), &schema);
        let before = effects.schema_fingerprint().unwrap();

        let action = fixture_action();
        effects.claim_action(&action).unwrap();
        effects
            .authorize_action(&action.action_id, ExecutionState::Proposed, "grant", None)
            .unwrap();

        assert_eq!(effects.schema_fingerprint().unwrap(), before);
        effects.verify_schema().unwrap();
        effects.drop_schema().unwrap();
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn schema_verification_requires_a_recorded_fingerprint() {
        let schema = unique_schema();
        let effects = create_store(&test_connection_string(), &schema);
        effects
            .connection()
            .unwrap()
            .batch_execute(&format!("delete from \"{schema}\".effect_schema_state"))
            .unwrap();
        assert!(matches!(
            effects.verify_schema(),
            Err(PostgresEffectStoreError::SchemaFingerprintMismatch(_))
        ));
        effects.drop_schema().unwrap();
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn migration_refuses_to_adopt_a_pre_existing_object() {
        // `create table if not exists` used to adopt whatever was already there.
        // The migration now owns its objects and fails loudly instead.
        let schema = unique_schema();
        let connection_string = test_connection_string();
        let effects = create_store(&connection_string, &schema);
        effects.drop_schema().unwrap();

        let mut client = postgres::Client::connect(&connection_string, NoTls).unwrap();
        client
            .batch_execute(&format!(
                "create schema \"{schema}\";
                 create table \"{schema}\".effect_actions (bogus integer)"
            ))
            .unwrap();

        let reopened = create_store_after_migration_failure(&connection_string, &schema);
        let failure = reopened.migrate();
        assert!(
            matches!(&failure, Err(PostgresEffectStoreError::Database(_))),
            "a conflicting pre-existing object must fail the migration: {failure:?}"
        );
        // Nothing was recorded, and nothing was adopted.
        let recorded: i64 = client
            .query_one(
                &format!(
                    "select count(*) from information_schema.tables \
                     where table_schema = '{schema}' and table_name = 'effect_schema_migrations'"
                ),
                &[],
            )
            .unwrap()
            .get(0);
        assert_eq!(
            recorded, 0,
            "a failed migration must not record its version"
        );

        // Removing the conflicting object makes the same migration succeed.
        client
            .batch_execute(&format!("drop table \"{schema}\".effect_actions"))
            .unwrap();
        reopened.migrate().unwrap();
        reopened.verify_schema().unwrap();
        assert_eq!(migration_ledger(&reopened).len(), 1);
        reopened.drop_schema().unwrap();
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn migration_refuses_to_claim_a_schema_it_does_not_own() {
        let schema = unique_schema();
        let connection_string = test_connection_string();
        let mut client = postgres::Client::connect(&connection_string, NoTls).unwrap();
        client
            .batch_execute(&format!(
                "create schema \"{schema}\";
                 create table \"{schema}\".unrelated_tenant_table (id integer)"
            ))
            .unwrap();

        let store = create_store_after_migration_failure(&connection_string, &schema);
        let failure = store.migrate();
        assert!(
            matches!(&failure, Err(PostgresEffectStoreError::SchemaMismatch(message))
                if message.contains("unrelated_tenant_table")),
            "migration must not claim a schema owned by another tenant: {failure:?}"
        );
        client
            .batch_execute(&format!("drop schema \"{schema}\" cascade"))
            .unwrap();
    }

    fn create_store_after_migration_failure(
        connection_string: &str,
        schema: &str,
    ) -> PostgresEffectStore {
        PostgresEffectStore::connect_insecure_local_for_tests(
            connection_string,
            schema,
            LeaseConfiguration {
                default_duration_ms: 100,
                maximum_duration_ms: 10_000,
                renewal_enabled: true,
            },
            4,
        )
        .expect("connect PostgreSQL effect store")
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn migration_rejects_unknown_future_and_damaged_history() {
        let schema = unique_schema();
        let effects = create_store(&test_connection_string(), &schema);

        effects
            .connection()
            .unwrap()
            .execute(
                &format!(
                    "insert into \"{schema}\".effect_schema_migrations \
                     (version, name, checksum, application_version) \
                     values (99, 'from_the_future', 'whatever', 'from_the_future')"
                ),
                &[],
            )
            .unwrap();
        assert!(matches!(
            effects.migrate(),
            Err(PostgresEffectStoreError::SchemaMismatch(_))
        ));
        effects
            .connection()
            .unwrap()
            .execute(
                &format!("delete from \"{schema}\".effect_schema_migrations where version = 99"),
                &[],
            )
            .unwrap();

        // A damaged ledger cannot re-run the migration over objects that are
        // already present, because the migration does not use IF NOT EXISTS.
        effects
            .connection()
            .unwrap()
            .batch_execute(&format!(
                "delete from \"{schema}\".effect_schema_migrations"
            ))
            .unwrap();
        assert!(matches!(
            effects.migrate(),
            Err(PostgresEffectStoreError::Database(_))
        ));
        effects.drop_schema().unwrap();
    }

    // -- E3.1 verification split and ownership boundary ----------------------

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn verification_apis_report_which_fact_failed() {
        let schema = unique_schema();
        let effects = create_store(&test_connection_string(), &schema);

        // Healthy: every split check passes independently.
        effects.verify_migration_history().unwrap();
        effects.verify_physical_schema().unwrap();
        let settings = effects.database_settings().unwrap();
        assert!(settings.server_major >= 12);
        assert!(!settings.synchronous_commit.is_empty());
        assert!(!settings.timezone.is_empty());
        // This test connects as the schema owner, so aggregate readiness must
        // reject the credential even though the schema itself is healthy. A
        // data-only role passing readiness is covered by the migration-integrity
        // integration suite.
        assert!(matches!(
            effects.verify_database_readiness(),
            Err(PostgresEffectStoreError::DatabasePrivilegeViolation { .. })
        ));

        // Ledger damage is reported as history, not as a schema problem.
        effects
            .connection()
            .unwrap()
            .execute(
                &format!(
                    "update \"{schema}\".effect_schema_migrations set name = 'renamed' where version = 1"
                ),
                &[],
            )
            .unwrap();
        assert!(matches!(
            effects.verify_migration_history(),
            Err(PostgresEffectStoreError::MigrationHistoryMismatch(_))
        ));
        // ...and the physical schema check still passes on its own.
        effects.verify_physical_schema().unwrap();
        // ...while aggregate readiness fails closed.
        assert!(effects.verify_database_readiness().is_err());
        effects.drop_schema().unwrap();
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn physical_verification_is_scoped_to_contract_relations() {
        // Ownership is precise: the effect-store schema is owned by the effect
        // store, but a co-tenant relation that the contract does not claim must
        // not make readiness fail. Schema exclusivity is enforced at migration
        // time instead, where adopting a foreign object is still possible.
        let schema = unique_schema();
        let effects = create_store(&test_connection_string(), &schema);
        effects
            .connection()
            .unwrap()
            .batch_execute(&format!(
                "create table \"{schema}\".unrelated_tenant_table (id integer)"
            ))
            .unwrap();

        effects.verify_physical_schema().unwrap();
        effects.verify_migration_history().unwrap();
        effects.drop_schema().unwrap();
    }

    #[test]
    #[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
    fn deadline_scoped_store_bounds_every_call() {
        let schema = unique_schema();
        let effects = create_store(&test_connection_string(), &schema);

        // Without a deadline the configured maximum applies.
        let unscoped = effects.effective_operation_budgets().unwrap();
        assert_eq!(unscoped.statement, effects.budgets.statement);

        // With a deadline the remaining trusted budget applies instead.
        let scoped = effects
            .with_deadline(Instant::now() + Duration::from_secs(6))
            .unwrap();
        let budgeted = scoped.effective_operation_budgets().unwrap();
        assert!(budgeted.statement <= Duration::from_secs(6));
        assert!(budgeted.lock <= budgeted.statement);
        assert!(budgeted.statement < unscoped.statement);

        // The scoped handle still performs real durable work.
        let action = fixture_action();
        scoped.claim_action(&action).unwrap();
        assert!(scoped.load_action(&action.action_id).unwrap().is_some());

        // An exhausted deadline is refused rather than falling back.
        assert!(matches!(
            effects.with_deadline(Instant::now() - Duration::from_millis(1)),
            Err(PostgresEffectStoreError::InvalidOperationBudget(_))
        ));
        effects.drop_schema().unwrap();
    }

    // -- E3.1 operation budgets ---------------------------------------------

    #[test]
    fn remaining_action_budget_bounds_database_waits() {
        let configured = PostgresOperationBudgets::default();
        let remaining = Duration::from_secs(6);
        let derived = configured.for_remaining(remaining).unwrap();

        assert_eq!(derived.lock, Duration::from_secs(2));
        assert_eq!(derived.statement, remaining);
        assert_eq!(derived.idle_in_transaction, remaining);
        assert!(derived.lock <= derived.statement);
        assert!(derived.statement <= remaining);
    }

    #[test]
    fn remaining_action_budget_never_exceeds_the_configured_maximum() {
        let configured = PostgresOperationBudgets::default();
        let derived = configured.for_remaining(Duration::from_secs(3600)).unwrap();
        assert_eq!(derived.lock, configured.lock);
        assert_eq!(derived.statement, configured.statement);
        assert_eq!(derived.idle_in_transaction, configured.idle_in_transaction);
    }

    #[test]
    fn exhausted_action_budget_is_rejected() {
        let configured = PostgresOperationBudgets::default();
        assert!(matches!(
            configured.for_remaining(Duration::ZERO),
            Err(PostgresEffectStoreError::InvalidOperationBudget(_))
        ));
    }
}
