// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental outbound data-loss-prevention contracts.
//!
//! Relay's telemetry sanitizers do not alter real provider or tool payloads.
//! This scaffold is intentionally separate and provides no outbound enforcement.

/// Whether outbound DLP enforcement is active.
pub const OUTBOUND_DLP_ENABLED: bool = false;

/// Opt-in experimental contracts.
#[cfg(feature = "unstable-hardening")]
pub mod unstable {
    use serde::{Deserialize, Serialize};
    use serde_json::Value as Json;

    /// Result of evaluating a real outbound payload.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum DlpDecision {
        /// Payload may leave the process unchanged.
        Allow,
        /// Payload must not leave the process.
        Block,
        /// Only the replacement payload may leave the process.
        Transform(Json),
        /// Fresh human or external-system approval is required.
        RequireApproval,
    }

    /// Adapter boundary for outbound trust-boundary inspection.
    pub trait DlpProvider {
        /// Adapter-specific failure type.
        type Error;

        /// Inspect a payload immediately before external dispatch.
        fn inspect(&self, payload: &Json) -> Result<DlpDecision, Self::Error>;
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;

        struct TestDlp;

        impl DlpProvider for TestDlp {
            type Error = std::convert::Infallible;

            fn inspect(&self, payload: &Json) -> Result<DlpDecision, Self::Error> {
                assert_eq!(payload, &json!({"safe": true}));
                Ok(DlpDecision::Allow)
            }
        }

        #[test]
        fn external_dlp_provider_inspects_the_actual_payload() {
            assert_eq!(
                TestDlp.inspect(&json!({"safe": true})).unwrap(),
                DlpDecision::Allow
            );
        }
    }
}
