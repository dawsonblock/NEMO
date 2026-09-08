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

    /// Durable execution lifecycle state.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ExecutionState {
        /// Intent received but not evaluated.
        Proposed,
        /// Policy evaluation recorded.
        PolicyEvaluated,
        /// Authority denied the intent.
        Denied,
        /// Authority allowed the exact intent.
        Authorized,
        /// Execution resources prepared.
        Prepared,
        /// External action started.
        Started,
        /// External action succeeded.
        Succeeded,
        /// External action failed.
        Failed,
        /// Execution was cancelled.
        Cancelled,
        /// Execution exceeded its deadline.
        TimedOut,
        /// Recovery cannot prove whether the action occurred.
        PossiblyExecuted,
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

        /// Load the current state for an execution, if one exists.
        fn load_state(&self, execution_id: &str) -> Result<Option<ExecutionState>, Self::Error>;

        /// Apply one state transition under the backend's concurrency policy.
        fn transition(
            &self,
            execution_id: &str,
            expected: Option<ExecutionState>,
            next: ExecutionState,
        ) -> Result<(), Self::Error>;
    }

    /// Adapter boundary for authoritative receipts.
    pub trait ReceiptStore {
        /// Adapter-specific failure type.
        type Error;

        /// Persist a receipt digest for an execution.
        fn store(&self, execution_id: &str, receipt_digest: &str) -> Result<(), Self::Error>;

        /// Retrieve the persisted receipt digest, if one exists.
        fn load(&self, execution_id: &str) -> Result<Option<String>, Self::Error>;
    }
}
