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
}
