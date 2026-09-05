// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental durable-executor contracts.
//!
//! This scaffold does not provide retries, idempotency, reconciliation, or a
//! transactional intent boundary.

/// Whether durable execution is active.
pub const DURABLE_EXECUTION_ENABLED: bool = false;

/// Opt-in experimental contracts.
#[cfg(feature = "unstable-hardening")]
pub mod unstable {
    use serde::{Deserialize, Serialize};

    /// Immutable identity assigned before an externally meaningful action.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ExecutionIdentity {
        /// Stable execution identifier.
        pub execution_id: String,
        /// Stable invocation identifier.
        pub invocation_id: String,
        /// Idempotency key supplied by the authority-approved intent.
        pub idempotency_key: String,
        /// Absolute deadline represented as Unix milliseconds.
        pub deadline_unix_ms: u64,
    }
}
