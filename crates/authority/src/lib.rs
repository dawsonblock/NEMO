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
    use nemo_relay_executor::unstable::{ExecutionClass, RuntimeIdentity};
    use serde::{Deserialize, Serialize};
    use serde_json::Value as Json;

    /// Exact identity and capability request evaluated before execution.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct AuthorityRequest {
        /// Stable execution identity.
        pub execution_id: String,
        /// Stable action identity.
        pub action_id: String,
        /// Tenant identity.
        pub tenant_id: String,
        /// Principal identity.
        pub principal_id: String,
        /// Runtime identity and deployment binding.
        pub runtime: RuntimeIdentity,
        /// Requested capability identifier.
        pub capability_id: String,
        /// Capability registration generation.
        pub capability_generation: u64,
        /// Digest of the immutable registration.
        pub registration_digest: String,
        /// Requested execution class.
        pub execution_class: ExecutionClass,
        /// Requested operation.
        pub operation: String,
        /// Digest of the registered route.
        pub route_digest: String,
        /// Canonical digest of invocation arguments.
        pub args_digest: String,
        /// Requested verb-scoped capability, retained for compatibility.
        pub capability: String,
        /// Requested resource and bounded constraints.
        pub resource: Json,
        /// Policy version bound to the authority decision.
        pub policy_version: String,
        /// Policy epoch bound to this decision.
        pub policy_epoch: String,
        /// Runtime admission identifier.
        pub admission_id: String,
        /// Idempotency key for externally meaningful work.
        pub idempotency_key: String,
        /// Exact approval artifact, when the capability is critical.
        pub approval_reference: Option<String>,
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

    /// Adapter boundary for the authoritative policy engine.
    ///
    /// NeMo Relay does not implement this trait. A Correct-Once or other
    /// externally qualified authority supplies the implementation.
    pub trait AuthorityProvider: Send + Sync {
        /// Adapter-specific failure type.
        type Error;

        /// Evaluate one exact, identity-bound capability request.
        fn decide(&self, request: &AuthorityRequest) -> Result<AuthorityDecision, Self::Error>;
    }

    /// Thin adapter around a Correct-Once client owned by another subsystem.
    ///
    /// The client is responsible for transport, signature verification, and
    /// authority-specific policy. Relay only supplies the exact bound request
    /// and receives the closed decision vocabulary.
    pub struct CorrectOnceAuthorityAdapter<C> {
        client: C,
    }

    impl<C> CorrectOnceAuthorityAdapter<C> {
        /// Wrap an external Correct-Once decision function.
        pub const fn new(client: C) -> Self {
            Self { client }
        }
    }

    impl<C, E> AuthorityProvider for CorrectOnceAuthorityAdapter<C>
    where
        C: Fn(&AuthorityRequest) -> Result<AuthorityDecision, E> + Send + Sync,
        E: Send + Sync,
    {
        type Error = E;

        fn decide(&self, request: &AuthorityRequest) -> Result<AuthorityDecision, Self::Error> {
            (self.client)(request)
        }
    }

    /// Build an authority request from a kernel execution identity.
    pub fn request_from_identity(
        identity: &nemo_relay_executor::unstable::ExecutionIdentity,
    ) -> AuthorityRequest {
        AuthorityRequest {
            execution_id: identity.execution_id.clone(),
            action_id: identity.action_id.clone(),
            tenant_id: identity.runtime.tenant_id.clone().unwrap_or_default(),
            principal_id: identity.runtime.principal_id.clone(),
            runtime: identity.runtime.clone(),
            capability_id: identity.capability.capability_id.clone(),
            capability_generation: identity.capability.capability_generation,
            registration_digest: identity.capability.registration_digest.clone(),
            execution_class: identity.capability.execution_class,
            operation: identity.capability.operation.clone(),
            route_digest: identity.capability.route_digest.clone(),
            args_digest: identity.args_digest.clone(),
            capability: identity.capability.capability_id.clone(),
            resource: Json::Null,
            policy_version: identity.policy_version.clone(),
            policy_epoch: identity.policy_epoch.clone(),
            admission_id: identity.admission_id.clone(),
            idempotency_key: identity.idempotency_key.clone(),
            approval_reference: identity.approval_reference.clone(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use nemo_relay_executor::unstable::{CapabilityIdentity, ExecutionIdentity};

        struct TestAuthority;

        impl AuthorityProvider for TestAuthority {
            type Error = std::convert::Infallible;

            fn decide(&self, request: &AuthorityRequest) -> Result<AuthorityDecision, Self::Error> {
                assert_eq!(request.capability_id, "test.capability");
                Ok(AuthorityDecision::Allow)
            }
        }

        fn identity() -> ExecutionIdentity {
            ExecutionIdentity {
                execution_id: "execution-1".into(),
                invocation_id: "invocation-1".into(),
                action_id: "action-1".into(),
                idempotency_key: "idempotency-1".into(),
                runtime: RuntimeIdentity {
                    principal_id: "alice".into(),
                    tenant_id: Some("tenant".into()),
                    runtime_id: "runtime".into(),
                    environment: "test".into(),
                    session_id: None,
                },
                capability: CapabilityIdentity {
                    capability_id: "test.capability".into(),
                    capability_generation: 1,
                    registration_digest: "registration".into(),
                    execution_class: ExecutionClass::Mutation,
                    operation: "test".into(),
                    route_digest: "route".into(),
                },
                admission_id: "admission".into(),
                policy_version: "policy".into(),
                policy_epoch: "epoch".into(),
                args_digest: "args".into(),
                grant_digest: None,
                approval_reference: None,
                deadline_unix_ms: 1_000,
            }
        }

        #[test]
        fn external_authority_implementation_compiles_and_receives_bound_identity() {
            let request = request_from_identity(&identity());
            let decision = TestAuthority
                .decide(&request)
                .expect("test authority should decide");
            assert_eq!(decision, AuthorityDecision::Allow);
            assert_eq!(request.route_digest, "route");
            assert_eq!(request.args_digest, "args");
        }

        #[test]
        fn correct_once_adapter_delegates_without_owning_policy() {
            let adapter = CorrectOnceAuthorityAdapter::new(|request: &AuthorityRequest| {
                assert_eq!(request.policy_epoch, "epoch");
                Ok::<_, std::convert::Infallible>(AuthorityDecision::RequireApproval)
            });
            assert_eq!(
                adapter.decide(&request_from_identity(&identity())).unwrap(),
                AuthorityDecision::RequireApproval
            );
        }
    }
}
