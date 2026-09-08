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
        /// Capability identity bound to the action.
        pub capability_id: String,
        /// Registered route digest.
        pub route_digest: String,
        /// Canonical argument digest.
        pub args_digest: String,
    }

    /// Result of atomically claiming an action/idempotency key.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum PrepareActionResult {
        /// No prior action used this idempotency key.
        NewAction,
        /// The exact same action is already known and may be observed/replayed.
        ExistingSameAction,
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
        /// Capability identity.
        pub capability_id: String,
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
        fn prepare_action(
            &self,
            action: &ActionPreparation,
        ) -> Result<PrepareActionResult, Self::Error>;

        /// Load the current state for an action, if one exists.
        fn load_state(&self, action_id: &str) -> Result<Option<ExecutionState>, Self::Error>;

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

            fn prepare_action(
                &self,
                action: &ActionPreparation,
            ) -> Result<PrepareActionResult, Self::Error> {
                assert_eq!(action.idempotency_key, "idempotency");
                Ok(PrepareActionResult::NewAction)
            }

            fn load_state(
                &self,
                _execution_id: &str,
            ) -> Result<Option<ExecutionState>, Self::Error> {
                Ok(Some(ExecutionState::Prepared))
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
                    capability_id: "capability".into(),
                    registration_digest: "registration".into(),
                    operation: "operation".into(),
                    execution_class: "MUTATION".into(),
                    args_digest: "args".into(),
                    route_digest: "route".into(),
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
                    .prepare_action(&ActionPreparation {
                        action_id: "action".into(),
                        idempotency_key: "idempotency".into(),
                        fingerprint: "fingerprint".into(),
                        execution_id: "execution".into(),
                        capability_id: "capability".into(),
                        route_digest: "route".into(),
                        args_digest: "args".into(),
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
