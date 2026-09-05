// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental worker-isolation contracts.
//!
//! Existing worker processes provide dependency and crash isolation, not a
//! hostile-code sandbox. This scaffold does not change that trust boundary.

/// Whether hostile-code containment is active.
pub const SANDBOX_ENFORCEMENT_ENABLED: bool = false;

/// Opt-in experimental contracts.
#[cfg(feature = "unstable-hardening")]
pub mod unstable {
    use serde::{Deserialize, Serialize};

    /// Worker trust and isolation tier.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum TrustTier {
        /// Built-in runtime code.
        BuiltIn,
        /// Signed and explicitly trusted native code.
        TrustedNative,
        /// Trusted subprocess without a security sandbox.
        TrustedSubprocess,
        /// Sandboxed local worker.
        SandboxedLocal,
        /// Remote isolated worker.
        RemoteIsolated,
    }
}
