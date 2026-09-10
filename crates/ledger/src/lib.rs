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

    /// Result of attempting to claim a fenced action lease.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum LeaseClaim {
        /// The caller owns the returned lease.
        Acquired(ActionLease),
        /// A live owner still holds the returned lease.
        Held(ActionLease),
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

        /// Atomically claim a lease for dispatch or reconciliation.
        ///
        /// The store must return [`LeaseClaim::Held`] while a different lease
        /// remains unexpired. Once expired, it assigns a strictly higher
        /// generation to the new owner.
        fn claim_lease(
            &self,
            action_id: &str,
            expected: ExecutionState,
            owner_id: &str,
            now_unix_ms: u64,
            lease_duration_ms: u64,
        ) -> Result<LeaseClaim, Self::Error>;

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

        /// Persist a receipt with its complete binding identity.
        fn store(&self, receipt: &ReceiptRecord) -> Result<(), Self::Error>;

        /// Retrieve the persisted receipt, if one exists.
        fn load(&self, action_id: &str) -> Result<Option<ReceiptRecord>, Self::Error>;
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

            fn claim_lease(
                &self,
                action_id: &str,
                expected: ExecutionState,
                owner_id: &str,
                now_unix_ms: u64,
                lease_duration_ms: u64,
            ) -> Result<LeaseClaim, Self::Error> {
                assert_eq!(action_id, "execution");
                assert_eq!(expected, ExecutionState::Prepared);
                assert_eq!(owner_id, "owner");
                assert_eq!(now_unix_ms, 1);
                assert_eq!(lease_duration_ms, 2);
                Ok(LeaseClaim::Acquired(ActionLease {
                    owner_id: owner_id.into(),
                    generation: 1,
                    expires_at_unix_ms: 3,
                }))
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

            fn store(&self, receipt: &ReceiptRecord) -> Result<(), Self::Error> {
                assert_eq!(receipt.final_state, ExecutionState::Committed);
                Ok(())
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
                .claim_lease("execution", ExecutionState::Prepared, "owner", 1, 2)
                .expect("lease claim should compile")
            {
                LeaseClaim::Acquired(lease) => lease,
                LeaseClaim::Held(_) => panic!("test lease must be acquired"),
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
    }
}
