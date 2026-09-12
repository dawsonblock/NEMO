// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL implementation of the experimental durable-effect store.
//!
//! The adapter is opt-in and does not change [`crate::DURABILITY_ENABLED`].
//! Every state mutation locks one action row, uses database-owned time, and
//! commits before control returns to a caller. External provider calls remain
//! outside this module and therefore cannot occur while a SQL transaction is
//! held open.

use crate::unstable::*;
use postgres::{GenericClient, IsolationLevel, NoTls, Row};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

type Manager = PostgresConnectionManager<NoTls>;

const MIGRATION: &str = include_str!("../migrations/0001_effect_store.sql");

/// Failure returned by [`PostgresEffectStore`].
#[derive(Debug)]
pub enum PostgresEffectStoreError {
    /// The configured schema identifier is not a safe lowercase SQL identifier.
    InvalidSchemaName(String),
    /// A connection pool must contain at least one connection.
    InvalidPoolSize(u32),
    /// A connection could not be checked out from the bounded pool.
    Pool(r2d2::Error),
    /// PostgreSQL rejected a query or transaction.
    Database(postgres::Error),
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
            Self::Pool(error) => write!(formatter, "PostgreSQL pool error: {error}"),
            Self::Database(error) => write!(formatter, "PostgreSQL error: {error}"),
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
            Self::Serialization(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::InvalidSchemaName(_)
            | Self::InvalidPoolSize(_)
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
    pool: Pool<Manager>,
    schema: String,
    lease_configuration: LeaseConfiguration,
}

impl PostgresEffectStore {
    /// Create a bounded PostgreSQL connection pool.
    pub fn connect(
        connection_string: &str,
        schema: &str,
        lease_configuration: LeaseConfiguration,
        maximum_pool_size: u32,
    ) -> Result<Self, PostgresEffectStoreError> {
        validate_schema_name(schema)?;
        if maximum_pool_size == 0 {
            return Err(PostgresEffectStoreError::InvalidPoolSize(0));
        }
        let configuration = connection_string.parse()?;
        let manager = PostgresConnectionManager::new(configuration, NoTls);
        let pool = Pool::builder()
            .max_size(maximum_pool_size)
            .connection_timeout(Duration::from_secs(5))
            .build(manager)?;
        Ok(Self {
            pool,
            schema: schema.to_owned(),
            lease_configuration,
        })
    }

    /// Install the idempotent schema migration used by this adapter.
    pub fn migrate(&self) -> Result<(), PostgresEffectStoreError> {
        let migration = MIGRATION.replace("__SCHEMA__", &self.quoted_schema());
        self.connection()?.batch_execute(&migration)?;
        Ok(())
    }

    fn connection(&self) -> Result<PooledConnection<Manager>, PostgresEffectStoreError> {
        self.pool.get().map_err(Into::into)
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
        action_id: &str,
        expected: ExecutionState,
        lease: &ActionLease,
        expected_evidence_revision: Option<u64>,
        receipt: &ReceiptRecord,
    ) -> Result<EffectFinalizeResult, PostgresEffectStoreError> {
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
        let (mut action, revision) = self
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
        if !is_valid_evidence_transition(expected, receipt.final_state, &evidence) {
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
        action.terminal_evidence = Some(evidence);
        action.state = receipt.final_state;
        action.lease = None;
        self.update_action(&mut transaction, &action, checked_revision(revision)?)?;
        transaction.commit()?;
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

    fn finalize_from_evidence(
        &self,
        action_id: &str,
        expected: ExecutionState,
        lease: &ActionLease,
        evidence: &TerminalEvidence,
    ) -> Result<(), Self::Error> {
        if !is_leaseable_state(expected) {
            return Err(ReferenceStoreError::InvalidLeaseState(expected).into());
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
        let next = evidence.terminal_state();
        if !evidence
            .binds_action(&action.preparation)
            .map_err(|_| ReferenceStoreError::InvalidGrantDigest)?
        {
            return Err(ReferenceStoreError::EvidenceBindingMismatch {
                action_id: action_id.to_owned(),
            }
            .into());
        }
        if !is_valid_evidence_transition(expected, next, evidence) {
            return Err(ReferenceStoreError::InvalidTransition {
                current: expected,
                next,
            }
            .into());
        }
        action.terminal_evidence = Some(evidence.clone());
        action.state = next;
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
        self.finalize_receipt_transaction(
            action_id,
            ExecutionState::Reconciling,
            lease,
            Some(expected_evidence_revision),
            receipt,
        )
    }

    fn complete_reconciliation_unknown(
        &self,
        action_id: &str,
        lease: &ActionLease,
        expected_evidence_revision: u64,
    ) -> Result<(), Self::Error> {
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
        self.finalize_receipt_transaction(action_id, expected, lease, None, receipt)
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
        let effects = PostgresEffectStore::connect(
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
            PostgresEffectStore::connect(
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
}
