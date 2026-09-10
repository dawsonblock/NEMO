// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental durable execution-ledger contracts.
//!
//! No storage backend is active in this scaffold. OpenTelemetry and ATOF remain
//! observability outputs and must not be treated as authoritative evidence.

/// Whether durable ledger persistence is active.
pub const DURABILITY_ENABLED: bool = false;

/// Opt-in experimental contracts.
#[cfg(feature = "unstable-hardening")]
pub mod unstable {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Consequential-effect lifecycle state shared with the Effect Fabric ABI.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum ExecutionState {
        /// Intent received but not yet authorized.
        Proposed,
        /// Authority allowed the exact intent.
        Authorized,
        /// Execution resources prepared.
        Prepared,
        /// Provider dispatch is in progress.
        Dispatching,
        /// The provider has authoritatively committed the effect.
        Committed,
        /// External action failed.
        Failed,
        /// The runtime cannot prove success or failure.
        Unknown,
        /// An unknown action is being reconciled.
        Reconciling,
        /// Execution was cancelled.
        Cancelled,
    }

    /// Return whether a consequential-effect state transition is legal.
    ///
    /// This table is shared by in-memory test adapters and durable Effect
    /// Fabric implementations so an adapter cannot accidentally skip the
    /// authorization or preparation boundary.
    pub const fn is_valid_transition(
        current: Option<ExecutionState>,
        next: ExecutionState,
    ) -> bool {
        matches!(
            (current, next),
            (None, ExecutionState::Proposed)
                | (Some(ExecutionState::Proposed), ExecutionState::Authorized)
                | (Some(ExecutionState::Proposed), ExecutionState::Cancelled)
                | (Some(ExecutionState::Authorized), ExecutionState::Prepared)
                | (Some(ExecutionState::Authorized), ExecutionState::Cancelled)
                | (Some(ExecutionState::Prepared), ExecutionState::Dispatching)
                | (Some(ExecutionState::Prepared), ExecutionState::Cancelled)
                | (Some(ExecutionState::Dispatching), ExecutionState::Committed)
                | (Some(ExecutionState::Dispatching), ExecutionState::Failed)
                | (Some(ExecutionState::Dispatching), ExecutionState::Unknown)
                // Immutable terminal evidence can arrive after a conservative
                // UNKNOWN transition. Recovery may repair from that evidence
                // without asking the provider to execute or reconcile again.
                | (Some(ExecutionState::Unknown), ExecutionState::Committed)
                | (Some(ExecutionState::Unknown), ExecutionState::Failed)
                | (Some(ExecutionState::Unknown), ExecutionState::Reconciling)
                | (Some(ExecutionState::Reconciling), ExecutionState::Committed)
                | (Some(ExecutionState::Reconciling), ExecutionState::Failed)
                | (Some(ExecutionState::Reconciling), ExecutionState::Unknown)
        )
    }

    /// Minimal authoritative event written by an external effect journal.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct JournalRecord {
        /// Stable execution identity.
        pub execution_id: String,
        /// State after this event.
        pub state: ExecutionState,
        /// Digest of the event payload, never the raw sensitive payload.
        pub payload_digest: String,
    }

    /// Immutable identity claimed before an external effect is dispatched.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ActionPreparation {
        /// Stable action identifier.
        pub action_id: String,
        /// Caller-supplied idempotency key.
        pub idempotency_key: String,
        /// Digest of all security-sensitive request fields.
        pub fingerprint: String,
        /// Execution identity bound to the action.
        pub execution_id: String,
        /// Optional tenant/organization binding.
        pub tenant_id: Option<String>,
        /// Host-authenticated principal binding.
        pub principal_id: String,
        /// Runtime instance binding.
        pub runtime_id: String,
        /// Capability identity bound to the action.
        pub capability_id: String,
        /// Capability registration generation.
        pub capability_generation: u64,
        /// Immutable registration digest.
        pub registration_digest: String,
        /// Registered execution class.
        pub execution_class: String,
        /// Registered operation.
        pub operation: String,
        /// Registered route digest.
        pub route_digest: String,
        /// Canonical argument digest.
        pub args_digest: String,
        /// Runtime admission identifier.
        pub admission_id: String,
        /// Policy version and epoch used for this action.
        pub policy_version: String,
        /// Policy epoch used for this action.
        pub policy_epoch: String,
        /// Grant/approval bindings once authorization completes.
        pub grant_digest: Option<String>,
        /// Approval artifact reference once authorization completes.
        pub approval_reference: Option<String>,
    }

    /// Fenced ownership of a dispatch or reconciliation attempt.
    ///
    /// Effect Fabric persists this alongside the action. A new owner may take
    /// the lease only after its expiry, and every terminal transition carries
    /// the same owner/generation pair. This prevents a recovery worker from
    /// rewriting the state of a live dispatcher.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ActionLease {
        /// Opaque executor or recovery-worker identity.
        pub owner_id: String,
        /// Monotonic generation used as the fencing token.
        pub generation: u64,
        /// Unix timestamp in milliseconds after which another owner may claim recovery.
        pub expires_at_unix_ms: u64,
    }

    /// Store-owned configuration for action leases.
    ///
    /// Implementations apply this configuration using their own authoritative
    /// clock. Callers may request a bounded duration but never supply `now` or
    /// an expiry timestamp.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct LeaseConfiguration {
        /// Duration selected when a caller does not request one explicitly.
        pub default_duration_ms: u64,
        /// Largest duration the store will grant for one claim or renewal.
        pub maximum_duration_ms: u64,
        /// Whether the current valid owner may renew its lease.
        pub renewal_enabled: bool,
    }

    impl Default for LeaseConfiguration {
        fn default() -> Self {
            Self {
                default_duration_ms: 30_000,
                maximum_duration_ms: 120_000,
                renewal_enabled: true,
            }
        }
    }

    impl LeaseConfiguration {
        /// Resolve a request without granting temporal authority to the caller.
        pub const fn resolve_duration(
            self,
            requested_duration_ms: Option<u64>,
        ) -> Result<u64, LeaseDurationError> {
            let duration_ms = match requested_duration_ms {
                Some(duration_ms) => duration_ms,
                None => self.default_duration_ms,
            };
            if duration_ms == 0 {
                return Err(LeaseDurationError::Zero);
            }
            if duration_ms > self.maximum_duration_ms {
                return Err(LeaseDurationError::ExceedsMaximum {
                    requested_duration_ms: duration_ms,
                    maximum_duration_ms: self.maximum_duration_ms,
                });
            }
            Ok(duration_ms)
        }
    }

    /// Typed reason a lease duration request cannot be honored.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum LeaseDurationError {
        /// Leases must be positive-duration ownership records.
        Zero,
        /// The request exceeds the store-owned maximum.
        ExceedsMaximum {
            /// Requested duration.
            requested_duration_ms: u64,
            /// Store-enforced maximum duration.
            maximum_duration_ms: u64,
        },
    }

    /// Result of attempting to claim a fenced action lease.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum LeaseAcquireResult {
        /// The caller owns the returned lease.
        Acquired(ActionLease),
        /// An expired prior lease was replaced by a new owner/generation.
        ExpiredReclaimed(ActionLease),
        /// A live owner still holds the returned lease.
        HeldByOther(ActionLease),
        /// The store rejected the requested duration before granting ownership.
        DurationRejected(LeaseDurationError),
    }

    /// Store-owned observation of whether an action has a live lease.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum LeaseStatus {
        /// No valid owner remains; a caller may attempt to claim a new lease.
        Available,
        /// A valid owner currently holds the returned lease.
        HeldByOther(ActionLease),
    }

    /// Result of a CAS-like lease renewal attempt.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum LeaseRenewResult {
        /// The same owner/generation renewed its still-valid lease.
        Renewed(ActionLease),
        /// The lease expired, changed owner, changed generation, or changed state.
        LeaseLost,
        /// Renewal is disabled by store policy.
        RenewalNotPermitted,
        /// The requested duration violates store policy.
        DurationRejected(LeaseDurationError),
    }

    /// Result of a CAS-like lease release or revocation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum LeaseReleaseResult {
        /// The exact owner/generation released its lease.
        Released,
        /// The caller no longer owns the current lease.
        LeaseLost,
    }

    /// Durable action identity and current lifecycle state.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ActionRecord {
        /// Immutable action identity claimed before authorization.
        pub preparation: ActionPreparation,
        /// Current lifecycle state.
        pub state: ExecutionState,
        /// Current dispatch or reconciliation ownership, if any.
        pub lease: Option<ActionLease>,
        /// Highest lease generation ever issued for this action.
        ///
        /// This counter is retained after a terminal or rollback transition so
        /// a later lease can never reuse an earlier fencing generation.
        pub lease_generation: u64,
    }

    /// Result of atomically claiming an action/idempotency key.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum PrepareActionResult {
        /// No prior action used this idempotency key.
        NewAction,
        /// The exact same action is already known and may be observed,
        /// resumed, reconciled, or replayed without redispatching it.
        ExistingSameAction(Box<ActionRecord>),
        /// The key is already bound to different effect identity.
        IdempotencyConflict,
    }

    /// Receipt evidence bound to the action that produced it.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ReceiptRecord {
        /// Stable receipt identifier.
        pub receipt_id: String,
        /// Action that produced this receipt.
        pub action_id: String,
        /// Idempotency key bound to the action.
        pub idempotency_key: String,
        /// Execution grant digest.
        pub grant_digest: String,
        /// Principal identity.
        pub principal_id: String,
        /// Tenant/organization identity.
        pub tenant_id: Option<String>,
        /// Runtime instance identity.
        pub runtime_id: String,
        /// Capability identity.
        pub capability_id: String,
        /// Capability registration generation.
        pub capability_generation: u64,
        /// Registration digest.
        pub registration_digest: String,
        /// Operation name.
        pub operation: String,
        /// Registered execution class.
        pub execution_class: String,
        /// Canonical arguments digest.
        pub args_digest: String,
        /// Registered route digest.
        pub route_digest: String,
        /// Runtime admission identity.
        pub admission_id: String,
        /// Policy version and epoch used for this action.
        pub policy_version: String,
        /// Policy epoch used for this action.
        pub policy_epoch: String,
        /// Provider request identifier.
        pub provider_request_id: Option<String>,
        /// Terminal effect state.
        pub final_state: ExecutionState,
        /// Start timestamp in Unix milliseconds.
        pub started_at_unix_ms: u64,
        /// Finish timestamp in Unix milliseconds.
        pub finished_at_unix_ms: u64,
        /// Digest of authoritative provider evidence.
        pub evidence_digest: String,
    }

    /// Immutable receipt conflict reported by an append-only receipt store.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ReceiptConflict {
        /// Action whose evidence history conflicts.
        pub action_id: String,
        /// Previously persisted receipt identity.
        pub existing_receipt_id: String,
        /// Receipt identity supplied by the conflicting finalizer.
        pub attempted_receipt_id: String,
        /// Previously persisted evidence digest.
        pub existing_evidence_digest: String,
        /// Attempted evidence digest.
        pub attempted_evidence_digest: String,
    }

    /// Result of attempting to append immutable terminal evidence.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum FinalizeResult {
        /// This receipt was appended as the action's terminal evidence.
        Finalized(ReceiptRecord),
        /// The identical receipt was already finalized and is replayed safely.
        AlreadyFinalized(ReceiptRecord),
        /// A materially different terminal receipt already exists for the action.
        FinalizationConflict(ReceiptConflict),
    }

    /// Typed evidence-aware decision produced by recovery.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum RecoveryDecision {
        /// Immutable evidence proves the action committed.
        RecoverCommitted,
        /// Immutable evidence proves the action failed.
        RecoverFailed,
        /// A live owner still holds the action lease.
        HeldByOther,
        /// No terminal evidence exists after lease expiry; provider outcome is unknown.
        RecoverUnknown,
        /// No provider boundary was crossed and policy may resume preparation.
        RecoverRetry,
        /// State and evidence cannot both be true and require integrity handling.
        ContradictoryEvidence,
    }

    /// Clock consumed by a store implementation, never supplied per operation.
    pub trait StoreClock: Send + Sync {
        /// Return the store's current Unix timestamp in milliseconds.
        fn now_unix_ms(&self) -> u64;
    }

    /// Production-shaped wall-clock implementation for reference stores.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct SystemStoreClock;

    impl StoreClock for SystemStoreClock {
        fn now_unix_ms(&self) -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX)
        }
    }

    /// Deterministic, store-owned clock for reference-store and adapter tests.
    #[derive(Debug, Clone)]
    pub struct ManualStoreClock {
        now_unix_ms: Arc<Mutex<u64>>,
    }

    impl ManualStoreClock {
        /// Create a deterministic clock at the supplied initial timestamp.
        pub fn new(now_unix_ms: u64) -> Self {
            Self {
                now_unix_ms: Arc::new(Mutex::new(now_unix_ms)),
            }
        }

        /// Advance the store's time for deterministic expiration tests.
        pub fn advance(&self, duration_ms: u64) {
            if let Ok(mut now) = self.now_unix_ms.lock() {
                *now = now.saturating_add(duration_ms);
            }
        }

        /// Set the store's time for deterministic adapter tests.
        pub fn set(&self, now_unix_ms: u64) {
            if let Ok(mut now) = self.now_unix_ms.lock() {
                *now = now_unix_ms;
            }
        }
    }

    impl StoreClock for ManualStoreClock {
        fn now_unix_ms(&self) -> u64 {
            self.now_unix_ms.lock().map(|now| *now).unwrap_or_default()
        }
    }

    /// Adapter boundary for durable effect history.
    pub trait EffectJournal {
        /// Adapter-specific failure type.
        type Error;

        /// Append one tamper-evident state record.
        fn append(&self, record: &JournalRecord) -> Result<(), Self::Error>;
    }

    /// Adapter boundary for durable action state and transitions.
    pub trait ActionStore {
        /// Adapter-specific failure type.
        type Error;

        /// Atomically claim an action and its idempotency key before dispatch.
        fn claim_action(
            &self,
            action: &ActionPreparation,
        ) -> Result<PrepareActionResult, Self::Error>;

        /// Backwards-compatible name for adapters migrating from the old
        /// pre-authorization preparation contract.
        #[deprecated(note = "use claim_action; claims begin in PROPOSED state")]
        fn prepare_action(
            &self,
            action: &ActionPreparation,
        ) -> Result<PrepareActionResult, Self::Error> {
            self.claim_action(action)
        }

        /// Load the complete durable action identity and current state.
        fn load_action(&self, action_id: &str) -> Result<Option<ActionRecord>, Self::Error>;

        /// Load the current state for an action, if one exists.
        fn load_state(&self, action_id: &str) -> Result<Option<ExecutionState>, Self::Error> {
            Ok(self.load_action(action_id)?.map(|record| record.state))
        }

        /// Atomically attach the verified grant and approval references while
        /// transitioning a claimed action from `PROPOSED` to `AUTHORIZED`.
        ///
        /// Implementations must persist both the evidence binding and state in
        /// one durable operation. A default no-op would permit an executor to
        /// claim authorization without retaining the evidence that justified
        /// it.
        fn authorize_action(
            &self,
            action_id: &str,
            expected: ExecutionState,
            grant_digest: &str,
            approval_reference: Option<&str>,
        ) -> Result<(), Self::Error>;

        /// Refresh the exact grant/approval artifact for an already-authorized
        /// or prepared action without changing its lifecycle state.
        ///
        /// A restarted kernel never reconstructs a grant token from a digest;
        /// it asks Correct-Once for a new grant bound to the same action and
        /// persists its new digest before resuming pre-dispatch work.
        fn refresh_authorization(
            &self,
            action_id: &str,
            expected: ExecutionState,
            grant_digest: &str,
            approval_reference: Option<&str>,
        ) -> Result<(), Self::Error>;

        /// Return the store-owned lease policy used for claims and renewals.
        fn lease_configuration(&self) -> Result<LeaseConfiguration, Self::Error>;

        /// Observe whether an action has a live lease using the store's clock.
        ///
        /// This lets a retry avoid re-authorizing or cancelling a `PREPARED`
        /// action that another executor already owns. It accepts no caller
        /// timestamp.
        fn lease_status(&self, action_id: &str) -> Result<LeaseStatus, Self::Error>;

        /// Atomically claim a lease for dispatch or reconciliation.
        ///
        /// The store determines current time, expiry, and whether a prior
        /// owner has expired. It returns [`LeaseAcquireResult::HeldByOther`]
        /// while a different lease remains valid. Once expired, it assigns a
        /// strictly higher generation to the new owner.
        fn claim_lease(
            &self,
            action_id: &str,
            expected: ExecutionState,
            owner_id: &str,
            requested_duration_ms: Option<u64>,
        ) -> Result<LeaseAcquireResult, Self::Error>;

        /// Renew an unexpired lease held by the exact owner/generation pair.
        ///
        /// The store rejects renewal after expiry or reclamation and uses its
        /// own clock and configured duration bounds for the new expiry.
        fn renew_lease(
            &self,
            action_id: &str,
            expected: ExecutionState,
            lease: &ActionLease,
            requested_duration_ms: Option<u64>,
        ) -> Result<LeaseRenewResult, Self::Error>;

        /// Release an exact lease before its natural expiry.
        ///
        /// Only the matching owner/generation may release. Implementations may
        /// additionally audit revocation, but never let a different owner clear
        /// the lease without advancing the fencing generation.
        fn release_lease(
            &self,
            action_id: &str,
            expected: ExecutionState,
            lease: &ActionLease,
        ) -> Result<LeaseReleaseResult, Self::Error>;

        /// Apply a fenced state transition under a currently owned lease.
        fn transition_with_lease(
            &self,
            action_id: &str,
            expected: ExecutionState,
            lease: &ActionLease,
            next: ExecutionState,
        ) -> Result<(), Self::Error>;

        /// Apply one state transition under the backend's concurrency policy.
        fn transition(
            &self,
            action_id: &str,
            expected: Option<ExecutionState>,
            next: ExecutionState,
        ) -> Result<(), Self::Error>;
    }

    /// Adapter boundary for authoritative receipts.
    pub trait ReceiptStore {
        /// Adapter-specific failure type.
        type Error;

        /// Finalize immutable terminal evidence for one action.
        ///
        /// A matching retry returns [`FinalizeResult::AlreadyFinalized`]. A
        /// materially different receipt returns
        /// [`FinalizeResult::FinalizationConflict`] and never overwrites the
        /// first receipt.
        fn finalize(&self, receipt: &ReceiptRecord) -> Result<FinalizeResult, Self::Error>;

        /// Retrieve the persisted receipt, if one exists.
        fn load(&self, action_id: &str) -> Result<Option<ReceiptRecord>, Self::Error>;
    }

    /// Error emitted by the non-durable reference stores.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ReferenceStoreError {
        /// The requested action does not exist.
        ActionMissing(String),
        /// A compare-and-set state did not match.
        UnexpectedState {
            /// Expected state.
            expected: Option<ExecutionState>,
            /// Actual state.
            actual: ExecutionState,
        },
        /// A lifecycle transition is not legal.
        InvalidTransition {
            /// Current state.
            current: ExecutionState,
            /// Requested state.
            next: ExecutionState,
        },
        /// An unfenced update attempted to bypass a live lease.
        LeaseHeld(ActionLease),
        /// The reference store lock was poisoned.
        LockPoisoned,
    }

    impl std::fmt::Display for ReferenceStoreError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::ActionMissing(action_id) => write!(formatter, "unknown action: {action_id}"),
                Self::UnexpectedState { expected, actual } => {
                    write!(
                        formatter,
                        "unexpected state: expected {expected:?}, got {actual:?}"
                    )
                }
                Self::InvalidTransition { current, next } => {
                    write!(formatter, "invalid transition: {current:?} -> {next:?}")
                }
                Self::LeaseHeld(lease) => write!(
                    formatter,
                    "live lease held by {} generation {}",
                    lease.owner_id, lease.generation
                ),
                Self::LockPoisoned => write!(formatter, "reference store lock poisoned"),
            }
        }
    }

    impl std::error::Error for ReferenceStoreError {}

    /// In-memory reference implementation of [`ActionStore`].
    ///
    /// It exists to make the contract executable and deterministic. It is not
    /// a durable Effect Fabric implementation and must not be enabled as one.
    #[derive(Clone)]
    pub struct InMemoryActionStore<C = SystemStoreClock> {
        clock: C,
        lease_configuration: LeaseConfiguration,
        records: Arc<Mutex<HashMap<String, ActionRecord>>>,
    }

    impl InMemoryActionStore<SystemStoreClock> {
        /// Create a reference store using the process wall clock.
        pub fn new(lease_configuration: LeaseConfiguration) -> Self {
            Self::with_clock(SystemStoreClock, lease_configuration)
        }
    }

    impl<C> InMemoryActionStore<C>
    where
        C: StoreClock,
    {
        /// Create a reference store that consumes this clock internally.
        pub fn with_clock(clock: C, lease_configuration: LeaseConfiguration) -> Self {
            Self {
                clock,
                lease_configuration,
                records: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn records(
            &self,
        ) -> Result<std::sync::MutexGuard<'_, HashMap<String, ActionRecord>>, ReferenceStoreError>
        {
            self.records
                .lock()
                .map_err(|_| ReferenceStoreError::LockPoisoned)
        }
    }

    impl<C> ActionStore for InMemoryActionStore<C>
    where
        C: StoreClock,
    {
        type Error = ReferenceStoreError;

        fn claim_action(
            &self,
            action: &ActionPreparation,
        ) -> Result<PrepareActionResult, Self::Error> {
            let mut records = self.records()?;
            if let Some(existing) = records
                .values()
                .find(|record| record.preparation.idempotency_key == action.idempotency_key)
            {
                return Ok(if existing.preparation.fingerprint == action.fingerprint {
                    PrepareActionResult::ExistingSameAction(Box::new(existing.clone()))
                } else {
                    PrepareActionResult::IdempotencyConflict
                });
            }
            records.insert(
                action.action_id.clone(),
                ActionRecord {
                    preparation: action.clone(),
                    state: ExecutionState::Proposed,
                    lease: None,
                    lease_generation: 0,
                },
            );
            Ok(PrepareActionResult::NewAction)
        }

        fn load_action(&self, action_id: &str) -> Result<Option<ActionRecord>, Self::Error> {
            Ok(self.records()?.get(action_id).cloned())
        }

        fn authorize_action(
            &self,
            action_id: &str,
            expected: ExecutionState,
            grant_digest: &str,
            approval_reference: Option<&str>,
        ) -> Result<(), Self::Error> {
            let mut records = self.records()?;
            let record = records
                .get_mut(action_id)
                .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
            if record.state != expected {
                return Err(ReferenceStoreError::UnexpectedState {
                    expected: Some(expected),
                    actual: record.state,
                });
            }
            record.preparation.grant_digest = Some(grant_digest.to_owned());
            record.preparation.approval_reference = approval_reference.map(ToOwned::to_owned);
            record.state = ExecutionState::Authorized;
            Ok(())
        }

        fn refresh_authorization(
            &self,
            action_id: &str,
            expected: ExecutionState,
            grant_digest: &str,
            approval_reference: Option<&str>,
        ) -> Result<(), Self::Error> {
            let mut records = self.records()?;
            let record = records
                .get_mut(action_id)
                .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
            if record.state != expected {
                return Err(ReferenceStoreError::UnexpectedState {
                    expected: Some(expected),
                    actual: record.state,
                });
            }
            record.preparation.grant_digest = Some(grant_digest.to_owned());
            record.preparation.approval_reference = approval_reference.map(ToOwned::to_owned);
            Ok(())
        }

        fn lease_configuration(&self) -> Result<LeaseConfiguration, Self::Error> {
            Ok(self.lease_configuration)
        }

        fn lease_status(&self, action_id: &str) -> Result<LeaseStatus, Self::Error> {
            let now = self.clock.now_unix_ms();
            let records = self.records()?;
            let record = records
                .get(action_id)
                .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
            Ok(match record.lease.as_ref() {
                Some(lease) if lease.expires_at_unix_ms > now => {
                    LeaseStatus::HeldByOther(lease.clone())
                }
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
            let now = self.clock.now_unix_ms();
            let mut records = self.records()?;
            let record = records
                .get_mut(action_id)
                .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
            if record.state != expected {
                return Err(ReferenceStoreError::UnexpectedState {
                    expected: Some(expected),
                    actual: record.state,
                });
            }
            if let Some(lease) = record.lease.as_ref()
                && lease.expires_at_unix_ms > now
            {
                return Ok(LeaseAcquireResult::HeldByOther(lease.clone()));
            }
            let reclaimed = record.lease.is_some();
            let generation = record.lease_generation.saturating_add(1);
            let lease = ActionLease {
                owner_id: owner_id.to_owned(),
                generation,
                expires_at_unix_ms: now.saturating_add(duration),
            };
            record.lease = Some(lease.clone());
            record.lease_generation = generation;
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
            let now = self.clock.now_unix_ms();
            let mut records = self.records()?;
            let record = records
                .get_mut(action_id)
                .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
            if record.state != expected
                || record.lease.as_ref() != Some(lease)
                || lease.expires_at_unix_ms <= now
            {
                return Ok(LeaseRenewResult::LeaseLost);
            }
            let renewed = ActionLease {
                expires_at_unix_ms: now.saturating_add(duration),
                ..lease.clone()
            };
            record.lease = Some(renewed.clone());
            Ok(LeaseRenewResult::Renewed(renewed))
        }

        fn release_lease(
            &self,
            action_id: &str,
            expected: ExecutionState,
            lease: &ActionLease,
        ) -> Result<LeaseReleaseResult, Self::Error> {
            let mut records = self.records()?;
            let record = records
                .get_mut(action_id)
                .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
            if record.state != expected || record.lease.as_ref() != Some(lease) {
                return Ok(LeaseReleaseResult::LeaseLost);
            }
            record.lease = None;
            Ok(LeaseReleaseResult::Released)
        }

        fn transition_with_lease(
            &self,
            action_id: &str,
            expected: ExecutionState,
            lease: &ActionLease,
            next: ExecutionState,
        ) -> Result<(), Self::Error> {
            let now = self.clock.now_unix_ms();
            let mut records = self.records()?;
            let record = records
                .get_mut(action_id)
                .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
            if record.state != expected {
                return Err(ReferenceStoreError::UnexpectedState {
                    expected: Some(expected),
                    actual: record.state,
                });
            }
            if record.lease.as_ref() != Some(lease) || lease.expires_at_unix_ms <= now {
                return Err(ReferenceStoreError::LeaseHeld(
                    record.lease.clone().unwrap_or_else(|| lease.clone()),
                ));
            }
            if !is_valid_transition(Some(expected), next) {
                return Err(ReferenceStoreError::InvalidTransition {
                    current: expected,
                    next,
                });
            }
            record.state = next;
            if next != ExecutionState::Dispatching && next != ExecutionState::Reconciling {
                record.lease = None;
            }
            Ok(())
        }

        fn transition(
            &self,
            action_id: &str,
            expected: Option<ExecutionState>,
            next: ExecutionState,
        ) -> Result<(), Self::Error> {
            let now = self.clock.now_unix_ms();
            let mut records = self.records()?;
            let record = records
                .get_mut(action_id)
                .ok_or_else(|| ReferenceStoreError::ActionMissing(action_id.to_owned()))?;
            if Some(record.state) != expected {
                return Err(ReferenceStoreError::UnexpectedState {
                    expected,
                    actual: record.state,
                });
            }
            if let Some(lease) = record.lease.as_ref()
                && lease.expires_at_unix_ms > now
            {
                return Err(ReferenceStoreError::LeaseHeld(lease.clone()));
            }
            if !is_valid_transition(Some(record.state), next) {
                return Err(ReferenceStoreError::InvalidTransition {
                    current: record.state,
                    next,
                });
            }
            record.state = next;
            if next != ExecutionState::Dispatching && next != ExecutionState::Reconciling {
                record.lease = None;
            }
            Ok(())
        }
    }

    /// Append-only, non-durable reference implementation of [`ReceiptStore`].
    ///
    /// It makes idempotent finalization and conflict handling executable before
    /// a durable Effect Fabric evidence store is implemented.
    #[derive(Clone, Default)]
    pub struct InMemoryReceiptStore {
        receipts: Arc<Mutex<HashMap<String, ReceiptRecord>>>,
    }

    impl ReceiptStore for InMemoryReceiptStore {
        type Error = ReferenceStoreError;

        fn finalize(&self, receipt: &ReceiptRecord) -> Result<FinalizeResult, Self::Error> {
            let mut receipts = self
                .receipts
                .lock()
                .map_err(|_| ReferenceStoreError::LockPoisoned)?;
            match receipts.get(&receipt.action_id) {
                None => {
                    receipts.insert(receipt.action_id.clone(), receipt.clone());
                    Ok(FinalizeResult::Finalized(receipt.clone()))
                }
                Some(existing) if existing == receipt => {
                    Ok(FinalizeResult::AlreadyFinalized(existing.clone()))
                }
                Some(existing) => Ok(FinalizeResult::FinalizationConflict(ReceiptConflict {
                    action_id: receipt.action_id.clone(),
                    existing_receipt_id: existing.receipt_id.clone(),
                    attempted_receipt_id: receipt.receipt_id.clone(),
                    existing_evidence_digest: existing.evidence_digest.clone(),
                    attempted_evidence_digest: receipt.evidence_digest.clone(),
                })),
            }
        }

        fn load(&self, action_id: &str) -> Result<Option<ReceiptRecord>, Self::Error> {
            Ok(self
                .receipts
                .lock()
                .map_err(|_| ReferenceStoreError::LockPoisoned)?
                .get(action_id)
                .cloned())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn consequential_state_machine_rejects_skipped_boundaries() {
            assert!(is_valid_transition(None, ExecutionState::Proposed));
            assert!(is_valid_transition(
                Some(ExecutionState::Proposed),
                ExecutionState::Authorized
            ));
            assert!(is_valid_transition(
                Some(ExecutionState::Authorized),
                ExecutionState::Prepared
            ));
            assert!(is_valid_transition(
                Some(ExecutionState::Prepared),
                ExecutionState::Dispatching
            ));
            assert!(is_valid_transition(
                Some(ExecutionState::Dispatching),
                ExecutionState::Unknown
            ));
            assert!(!is_valid_transition(
                Some(ExecutionState::Proposed),
                ExecutionState::Committed
            ));
            assert!(!is_valid_transition(
                Some(ExecutionState::Prepared),
                ExecutionState::Committed
            ));
        }

        struct TestJournal;

        impl EffectJournal for TestJournal {
            type Error = std::convert::Infallible;

            fn append(&self, record: &JournalRecord) -> Result<(), Self::Error> {
                assert_eq!(record.state, ExecutionState::Prepared);
                Ok(())
            }
        }

        struct TestActionStore;

        impl ActionStore for TestActionStore {
            type Error = std::convert::Infallible;

            fn claim_action(
                &self,
                action: &ActionPreparation,
            ) -> Result<PrepareActionResult, Self::Error> {
                assert_eq!(action.idempotency_key, "idempotency");
                Ok(PrepareActionResult::NewAction)
            }

            fn load_action(&self, _action_id: &str) -> Result<Option<ActionRecord>, Self::Error> {
                Ok(None)
            }

            fn load_state(
                &self,
                _execution_id: &str,
            ) -> Result<Option<ExecutionState>, Self::Error> {
                Ok(Some(ExecutionState::Prepared))
            }

            fn authorize_action(
                &self,
                action_id: &str,
                expected: ExecutionState,
                grant_digest: &str,
                approval_reference: Option<&str>,
            ) -> Result<(), Self::Error> {
                assert_eq!(action_id, "execution");
                assert_eq!(expected, ExecutionState::Proposed);
                assert_eq!(grant_digest, "grant");
                assert_eq!(approval_reference, Some("approval"));
                Ok(())
            }

            fn refresh_authorization(
                &self,
                action_id: &str,
                expected: ExecutionState,
                grant_digest: &str,
                approval_reference: Option<&str>,
            ) -> Result<(), Self::Error> {
                assert_eq!(action_id, "execution");
                assert_eq!(expected, ExecutionState::Authorized);
                assert_eq!(grant_digest, "grant");
                assert_eq!(approval_reference, Some("approval"));
                Ok(())
            }

            fn lease_configuration(&self) -> Result<LeaseConfiguration, Self::Error> {
                Ok(LeaseConfiguration {
                    default_duration_ms: 2,
                    maximum_duration_ms: 2,
                    renewal_enabled: true,
                })
            }

            fn lease_status(&self, _action_id: &str) -> Result<LeaseStatus, Self::Error> {
                Ok(LeaseStatus::Available)
            }

            fn claim_lease(
                &self,
                action_id: &str,
                expected: ExecutionState,
                owner_id: &str,
                requested_duration_ms: Option<u64>,
            ) -> Result<LeaseAcquireResult, Self::Error> {
                assert_eq!(action_id, "execution");
                assert_eq!(expected, ExecutionState::Prepared);
                assert_eq!(owner_id, "owner");
                assert_eq!(requested_duration_ms, Some(2));
                Ok(LeaseAcquireResult::Acquired(ActionLease {
                    owner_id: owner_id.into(),
                    generation: 1,
                    expires_at_unix_ms: 3,
                }))
            }

            fn renew_lease(
                &self,
                _action_id: &str,
                _expected: ExecutionState,
                lease: &ActionLease,
                _requested_duration_ms: Option<u64>,
            ) -> Result<LeaseRenewResult, Self::Error> {
                Ok(LeaseRenewResult::Renewed(lease.clone()))
            }

            fn release_lease(
                &self,
                _action_id: &str,
                _expected: ExecutionState,
                _lease: &ActionLease,
            ) -> Result<LeaseReleaseResult, Self::Error> {
                Ok(LeaseReleaseResult::Released)
            }

            fn transition_with_lease(
                &self,
                action_id: &str,
                expected: ExecutionState,
                lease: &ActionLease,
                next: ExecutionState,
            ) -> Result<(), Self::Error> {
                assert_eq!(action_id, "execution");
                assert_eq!(expected, ExecutionState::Prepared);
                assert_eq!(lease.owner_id, "owner");
                assert_eq!(next, ExecutionState::Dispatching);
                Ok(())
            }

            fn transition(
                &self,
                _execution_id: &str,
                expected: Option<ExecutionState>,
                next: ExecutionState,
            ) -> Result<(), Self::Error> {
                assert_eq!(expected, Some(ExecutionState::Prepared));
                assert_eq!(next, ExecutionState::Dispatching);
                Ok(())
            }
        }

        struct TestReceiptStore;

        impl ReceiptStore for TestReceiptStore {
            type Error = std::convert::Infallible;

            fn finalize(&self, receipt: &ReceiptRecord) -> Result<FinalizeResult, Self::Error> {
                assert_eq!(receipt.final_state, ExecutionState::Committed);
                Ok(FinalizeResult::Finalized(receipt.clone()))
            }

            fn load(&self, _action_id: &str) -> Result<Option<ReceiptRecord>, Self::Error> {
                Ok(Some(ReceiptRecord {
                    receipt_id: "receipt".into(),
                    action_id: "action".into(),
                    idempotency_key: "idempotency".into(),
                    grant_digest: "grant".into(),
                    principal_id: "alice".into(),
                    tenant_id: Some("tenant".into()),
                    runtime_id: "runtime".into(),
                    capability_id: "capability".into(),
                    capability_generation: 1,
                    registration_digest: "registration".into(),
                    operation: "operation".into(),
                    execution_class: "MUTATION".into(),
                    args_digest: "args".into(),
                    route_digest: "route".into(),
                    admission_id: "admission".into(),
                    policy_version: "policy".into(),
                    policy_epoch: "epoch".into(),
                    provider_request_id: None,
                    final_state: ExecutionState::Committed,
                    started_at_unix_ms: 1,
                    finished_at_unix_ms: 2,
                    evidence_digest: "evidence".into(),
                }))
            }
        }

        #[test]
        fn external_effect_contracts_share_one_state_vocabulary() {
            let record = JournalRecord {
                execution_id: "execution".into(),
                state: ExecutionState::Prepared,
                payload_digest: "payload".into(),
            };
            TestJournal
                .append(&record)
                .expect("journal append should compile");
            assert_eq!(
                TestActionStore.load_state("execution").unwrap(),
                Some(ExecutionState::Prepared)
            );
            assert_eq!(
                TestActionStore
                    .claim_action(&ActionPreparation {
                        action_id: "action".into(),
                        idempotency_key: "idempotency".into(),
                        fingerprint: "fingerprint".into(),
                        execution_id: "execution".into(),
                        tenant_id: None,
                        principal_id: "alice".into(),
                        runtime_id: "runtime".into(),
                        capability_id: "capability".into(),
                        capability_generation: 1,
                        registration_digest: "registration".into(),
                        execution_class: "MUTATION".into(),
                        operation: "operation".into(),
                        route_digest: "route".into(),
                        args_digest: "args".into(),
                        admission_id: "admission".into(),
                        policy_version: "policy".into(),
                        policy_epoch: "epoch".into(),
                        grant_digest: None,
                        approval_reference: None,
                    })
                    .unwrap(),
                PrepareActionResult::NewAction
            );
            TestActionStore
                .transition(
                    "execution",
                    Some(ExecutionState::Prepared),
                    ExecutionState::Dispatching,
                )
                .expect("transition should compile");
            TestActionStore
                .authorize_action(
                    "execution",
                    ExecutionState::Proposed,
                    "grant",
                    Some("approval"),
                )
                .expect("authorization binding should compile");
            TestActionStore
                .refresh_authorization(
                    "execution",
                    ExecutionState::Authorized,
                    "grant",
                    Some("approval"),
                )
                .expect("authorization refresh should compile");
            let lease = match TestActionStore
                .claim_lease("execution", ExecutionState::Prepared, "owner", Some(2))
                .expect("lease claim should compile")
            {
                LeaseAcquireResult::Acquired(lease) => lease,
                LeaseAcquireResult::HeldByOther(_)
                | LeaseAcquireResult::ExpiredReclaimed(_)
                | LeaseAcquireResult::DurationRejected(_) => panic!("test lease must be acquired"),
            };
            TestActionStore
                .transition_with_lease(
                    "execution",
                    ExecutionState::Prepared,
                    &lease,
                    ExecutionState::Dispatching,
                )
                .expect("fenced transition should compile");
            assert_eq!(
                TestReceiptStore
                    .load("action")
                    .unwrap()
                    .map(|receipt| receipt.receipt_id),
                Some("receipt".into())
            );
        }

        fn reference_action() -> ActionPreparation {
            ActionPreparation {
                action_id: "reference-action".into(),
                idempotency_key: "reference-idempotency".into(),
                fingerprint: "reference-fingerprint".into(),
                execution_id: "reference-execution".into(),
                tenant_id: Some("tenant".into()),
                principal_id: "alice".into(),
                runtime_id: "runtime".into(),
                capability_id: "capability".into(),
                capability_generation: 1,
                registration_digest: "registration".into(),
                execution_class: "MUTATION".into(),
                operation: "operation".into(),
                route_digest: "route".into(),
                args_digest: "args".into(),
                admission_id: "admission".into(),
                policy_version: "policy".into(),
                policy_epoch: "epoch".into(),
                grant_digest: Some("grant".into()),
                approval_reference: None,
            }
        }

        fn reference_receipt(final_state: ExecutionState, evidence_digest: &str) -> ReceiptRecord {
            ReceiptRecord {
                receipt_id: "reference-receipt".into(),
                action_id: "reference-action".into(),
                idempotency_key: "reference-idempotency".into(),
                grant_digest: "grant".into(),
                principal_id: "alice".into(),
                tenant_id: Some("tenant".into()),
                runtime_id: "runtime".into(),
                capability_id: "capability".into(),
                capability_generation: 1,
                registration_digest: "registration".into(),
                operation: "operation".into(),
                execution_class: "MUTATION".into(),
                args_digest: "args".into(),
                route_digest: "route".into(),
                admission_id: "admission".into(),
                policy_version: "policy".into(),
                policy_epoch: "epoch".into(),
                provider_request_id: None,
                final_state,
                started_at_unix_ms: 1,
                finished_at_unix_ms: 2,
                evidence_digest: evidence_digest.into(),
            }
        }

        fn prepared_reference_store() -> (InMemoryActionStore<ManualStoreClock>, ManualStoreClock) {
            let clock = ManualStoreClock::new(1_000);
            let store =
                InMemoryActionStore::with_clock(clock.clone(), LeaseConfiguration::default());
            let action = reference_action();
            store.claim_action(&action).unwrap();
            store
                .authorize_action(&action.action_id, ExecutionState::Proposed, "grant", None)
                .unwrap();
            store
                .transition(
                    &action.action_id,
                    Some(ExecutionState::Authorized),
                    ExecutionState::Prepared,
                )
                .unwrap();
            (store, clock)
        }

        #[test]
        fn reference_store_owns_time_and_reclaims_only_after_its_clock_expires() {
            let (store, clock) = prepared_reference_store();
            let first = match store
                .claim_lease("reference-action", ExecutionState::Prepared, "first", None)
                .unwrap()
            {
                LeaseAcquireResult::Acquired(lease) => lease,
                result => panic!("unexpected initial lease result: {result:?}"),
            };
            assert_eq!(first.expires_at_unix_ms, 31_000);
            assert!(matches!(
                store
                    .claim_lease(
                        "reference-action",
                        ExecutionState::Prepared,
                        "malicious-client-clock",
                        None,
                    )
                    .unwrap(),
                LeaseAcquireResult::HeldByOther(_)
            ));
            clock.advance(30_000);
            assert!(matches!(
                store
                    .claim_lease(
                        "reference-action",
                        ExecutionState::Prepared,
                        "recovery",
                        None
                    )
                    .unwrap(),
                LeaseAcquireResult::ExpiredReclaimed(_)
            ));
        }

        #[test]
        fn renewal_requires_the_live_exact_lease_and_preserves_fencing() {
            let (store, clock) = prepared_reference_store();
            let first = match store
                .claim_lease(
                    "reference-action",
                    ExecutionState::Prepared,
                    "first",
                    Some(10),
                )
                .unwrap()
            {
                LeaseAcquireResult::Acquired(lease) => lease,
                result => panic!("unexpected initial lease result: {result:?}"),
            };
            clock.advance(9);
            let renewed = match store
                .renew_lease(
                    "reference-action",
                    ExecutionState::Prepared,
                    &first,
                    Some(10),
                )
                .unwrap()
            {
                LeaseRenewResult::Renewed(lease) => lease,
                result => panic!("unexpected renewal result: {result:?}"),
            };
            assert_eq!(renewed.generation, first.generation);
            clock.advance(10);
            assert_eq!(
                store
                    .renew_lease(
                        "reference-action",
                        ExecutionState::Prepared,
                        &renewed,
                        Some(10),
                    )
                    .unwrap(),
                LeaseRenewResult::LeaseLost
            );
            let reclaimed = match store
                .claim_lease(
                    "reference-action",
                    ExecutionState::Prepared,
                    "second",
                    Some(10),
                )
                .unwrap()
            {
                LeaseAcquireResult::ExpiredReclaimed(lease) => lease,
                result => panic!("unexpected reclaim result: {result:?}"),
            };
            assert!(reclaimed.generation > renewed.generation);
            assert_eq!(
                store
                    .renew_lease(
                        "reference-action",
                        ExecutionState::Prepared,
                        &renewed,
                        Some(10),
                    )
                    .unwrap(),
                LeaseRenewResult::LeaseLost
            );
        }

        #[test]
        fn receipt_finalization_is_append_only_idempotent_or_conflicting() {
            let store = InMemoryReceiptStore::default();
            let committed = reference_receipt(ExecutionState::Committed, "evidence-a");
            assert!(matches!(
                store.finalize(&committed).unwrap(),
                FinalizeResult::Finalized(_)
            ));
            assert!(matches!(
                store.finalize(&committed).unwrap(),
                FinalizeResult::AlreadyFinalized(_)
            ));
            assert!(matches!(
                store
                    .finalize(&reference_receipt(ExecutionState::Failed, "evidence-b"))
                    .unwrap(),
                FinalizeResult::FinalizationConflict(_)
            ));
            assert_eq!(store.load("reference-action").unwrap(), Some(committed));
        }

        #[test]
        fn two_executors_cannot_claim_the_same_live_lease() {
            use std::sync::{Arc, Barrier};
            use std::thread;

            let (store, _clock) = prepared_reference_store();
            let barrier = Arc::new(Barrier::new(2));
            let first_store = store.clone();
            let first_barrier = barrier.clone();
            let first = thread::spawn(move || {
                first_barrier.wait();
                first_store
                    .claim_lease("reference-action", ExecutionState::Prepared, "first", None)
                    .unwrap()
            });
            let second_store = store.clone();
            let second = thread::spawn(move || {
                barrier.wait();
                second_store
                    .claim_lease("reference-action", ExecutionState::Prepared, "second", None)
                    .unwrap()
            });
            let results = [first.join().unwrap(), second.join().unwrap()];
            assert_eq!(
                results
                    .iter()
                    .filter(|result| matches!(result, LeaseAcquireResult::Acquired(_)))
                    .count(),
                1
            );
            assert_eq!(
                results
                    .iter()
                    .filter(|result| matches!(result, LeaseAcquireResult::HeldByOther(_)))
                    .count(),
                1
            );
        }

        #[test]
        fn prepared_actions_reject_unfenced_cancellation_while_leased() {
            let (store, _clock) = prepared_reference_store();
            store
                .claim_lease("reference-action", ExecutionState::Prepared, "owner", None)
                .unwrap();
            assert!(matches!(
                store.transition(
                    "reference-action",
                    Some(ExecutionState::Prepared),
                    ExecutionState::Cancelled,
                ),
                Err(ReferenceStoreError::LeaseHeld(_))
            ));
        }
    }
}
