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

    /// Adapter boundary for acquiring an execution environment.
    pub trait IsolationProvider {
        /// Backend-specific handle returned to the caller.
        type Handle;
        /// Adapter-specific failure type.
        type Error;

        /// Acquire an environment for the requested trust tier.
        fn acquire(&self, tier: TrustTier) -> Result<Self::Handle, Self::Error>;
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        struct TestIsolation;

        impl IsolationProvider for TestIsolation {
            type Handle = &'static str;
            type Error = std::convert::Infallible;

            fn acquire(&self, tier: TrustTier) -> Result<Self::Handle, Self::Error> {
                assert_eq!(tier, TrustTier::RemoteIsolated);
                Ok("isolated-worker")
            }
        }

        #[test]
        fn external_isolation_provider_can_select_a_trust_tier() {
            assert_eq!(
                TestIsolation.acquire(TrustTier::RemoteIsolated).unwrap(),
                "isolated-worker"
            );
        }
    }
}
