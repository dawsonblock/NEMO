// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental authority boundary contracts.
//!
//! This crate is scaffolding only. It is not wired into managed execution and
//! provides no security enforcement unless a future qualified implementation
//! explicitly integrates it.

/// Whether this scaffold currently enforces runtime authority decisions.
pub const ENFORCEMENT_ENABLED: bool = false;

/// Opt-in experimental contracts.
#[cfg(feature = "unstable-hardening")]
pub mod unstable {
    use serde::{Deserialize, Serialize};
    use serde_json::Value as Json;

    /// Identity and capability request evaluated before execution.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct AuthorityRequest {
        /// Stable execution identity.
        pub execution_id: String,
        /// Tenant identity.
        pub tenant_id: String,
        /// Principal identity.
        pub principal_id: String,
        /// Requested verb-scoped capability.
        pub capability: String,
        /// Requested resource and bounded constraints.
        pub resource: Json,
        /// Policy epoch bound to this decision.
        pub policy_epoch: String,
    }

    /// Closed authority decision vocabulary.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AuthorityDecision {
        /// Permit the exact request.
        Allow,
        /// Refuse execution.
        Deny,
        /// Permit only after applying the supplied constraints.
        Modify(Json),
        /// Require a fresh external approval.
        RequireApproval,
        /// Defer the decision to another authority.
        Defer,
    }
}
