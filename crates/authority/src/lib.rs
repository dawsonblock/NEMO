// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental authority boundary contracts.
//!
//! This crate defines the authority-provider contract used by the optional
//! kernel hardening path. It does not implement Correct-Once policy,
//! cryptographic issuance, or production enforcement; those remain external
//! responsibilities until a qualified adapter is configured.

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
        /// Canonical digest binding runtime, environment, and session provenance.
        pub runtime_binding_digest: String,
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

    /// A signed authority artifact bound to one exact execution request.
    ///
    /// Correct-Once owns issuance and cryptographic verification. Relay checks
    /// the returned claims against the already-bound request before it crosses
    /// a backend boundary.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct VerifiedGrant {
        /// Opaque authority token forwarded to the execution backend.
        pub token: String,
        /// Stable digest of the verified grant bytes.
        pub digest: String,
        /// Stable action identity authorized by the grant.
        pub action_id: String,
        /// Idempotency identity authorized by the grant.
        pub idempotency_key: String,
        /// Tenant/organization authorized by the grant.
        pub tenant_id: String,
        /// Principal authorized to execute the action.
        pub principal_id: String,
        /// Canonical runtime, environment, and session binding digest.
        pub runtime_binding_digest: String,
        /// Runtime admission authorized by the grant.
        pub admission_id: String,
        /// Capability authorized by the grant.
        pub capability_id: String,
        /// Registered capability generation authorized by the grant.
        pub capability_generation: u64,
        /// Registered descriptor digest authorized by the grant.
        pub registration_digest: String,
        /// Execution classification authorized by the grant.
        pub execution_class: ExecutionClass,
        /// Operation authorized by the grant.
        pub operation: String,
        /// Registered route digest authorized by the grant.
        pub route_digest: String,
        /// Canonical argument digest authorized by the grant.
        pub args_digest: String,
        /// Policy version evaluated by the authority.
        pub policy_version: String,
        /// Policy epoch evaluated by the authority.
        pub policy_epoch: String,
        /// Approval artifact consumed for this grant, when required.
        pub approval_reference: Option<String>,
    }

    impl VerifiedGrant {
        /// Return whether every security-sensitive claim matches the request.
        pub fn binds(&self, request: &AuthorityRequest) -> bool {
            !self.digest.trim().is_empty()
                && self.action_id == request.action_id
                && self.idempotency_key == request.idempotency_key
                && self.tenant_id == request.tenant_id
                && self.principal_id == request.principal_id
                && self.runtime_binding_digest == request.runtime_binding_digest
                && self.admission_id == request.admission_id
                && self.capability_id == request.capability_id
                && self.capability_generation == request.capability_generation
                && self.registration_digest == request.registration_digest
                && self.execution_class == request.execution_class
                && self.operation == request.operation
                && self.route_digest == request.route_digest
                && self.args_digest == request.args_digest
                && self.policy_version == request.policy_version
                && self.policy_epoch == request.policy_epoch
                && self.approval_reference == request.approval_reference
        }
    }

    /// Closed authority decision vocabulary.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AuthorityDecision {
        /// Permit the exact request.
        Allow(Box<VerifiedGrant>),
        /// Refuse execution.
        Deny,
        /// Permit only after applying the supplied constraints.
        Modify(Json),
        /// Require a fresh external approval.
        RequireApproval,
        /// Defer the decision to another authority.
        Defer,
    }

    /// Cryptographic verifier for authority-issued execution grants.
    ///
    /// Implementations verify signatures, issuer/audience policy, expiry, and
    /// any authority-specific key-rotation rules. Relay separately verifies
    /// that the claims bind to its immutable execution request.
    pub trait GrantVerifier: Send + Sync {
        /// Adapter-specific failure type.
        type Error;

        /// Verify an authority artifact for one exact request.
        fn verify_grant(
            &self,
            request: &AuthorityRequest,
            grant: &VerifiedGrant,
        ) -> Result<(), Self::Error>;
    }

    /// Adapter boundary for the authoritative policy engine.
    ///
    /// NeMo Relay does not implement this trait. A Correct-Once or other
    /// externally qualified authority supplies the implementation.
    pub trait AuthorityProvider: GrantVerifier {
        /// Evaluate one exact, identity-bound capability request.
        fn decide(
            &self,
            request: &AuthorityRequest,
        ) -> Result<AuthorityDecision, <Self as GrantVerifier>::Error>;
    }

    /// Thin adapter around a Correct-Once client owned by another subsystem.
    ///
    /// The client is responsible for transport, signature verification, and
    /// authority-specific policy. Relay only supplies the exact bound request
    /// and receives the closed decision vocabulary.
    pub struct CorrectOnceAuthorityAdapter<C, V> {
        client: C,
        verifier: V,
    }

    impl<C, V> CorrectOnceAuthorityAdapter<C, V> {
        /// Wrap external Correct-Once decision and verification functions.
        pub const fn new(client: C, verifier: V) -> Self {
            Self { client, verifier }
        }
    }

    impl<C, V, E> GrantVerifier for CorrectOnceAuthorityAdapter<C, V>
    where
        C: Send + Sync,
        V: Fn(&AuthorityRequest, &VerifiedGrant) -> Result<(), E> + Send + Sync,
        E: Send + Sync,
    {
        type Error = E;

        fn verify_grant(
            &self,
            request: &AuthorityRequest,
            grant: &VerifiedGrant,
        ) -> Result<(), Self::Error> {
            (self.verifier)(request, grant)
        }
    }

    impl<C, V, E> AuthorityProvider for CorrectOnceAuthorityAdapter<C, V>
    where
        C: Fn(&AuthorityRequest) -> Result<AuthorityDecision, E> + Send + Sync,
        V: Fn(&AuthorityRequest, &VerifiedGrant) -> Result<(), E> + Send + Sync,
        E: Send + Sync,
    {
        fn decide(
            &self,
            request: &AuthorityRequest,
        ) -> Result<AuthorityDecision, <Self as GrantVerifier>::Error> {
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
            runtime_binding_digest: identity.runtime_binding_digest.clone(),
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

        impl GrantVerifier for TestAuthority {
            type Error = std::convert::Infallible;

            fn verify_grant(
                &self,
                request: &AuthorityRequest,
                grant: &VerifiedGrant,
            ) -> Result<(), Self::Error> {
                assert!(grant.binds(request));
                Ok(())
            }
        }

        impl AuthorityProvider for TestAuthority {
            fn decide(
                &self,
                request: &AuthorityRequest,
            ) -> Result<AuthorityDecision, <Self as GrantVerifier>::Error> {
                assert_eq!(request.capability_id, "test.capability");
                Ok(AuthorityDecision::Allow(Box::new(grant(request))))
            }
        }

        fn grant(request: &AuthorityRequest) -> VerifiedGrant {
            VerifiedGrant {
                token: "token".into(),
                digest: "digest".into(),
                action_id: request.action_id.clone(),
                idempotency_key: request.idempotency_key.clone(),
                tenant_id: request.tenant_id.clone(),
                principal_id: request.principal_id.clone(),
                runtime_binding_digest: request.runtime_binding_digest.clone(),
                admission_id: request.admission_id.clone(),
                capability_id: request.capability_id.clone(),
                capability_generation: request.capability_generation,
                registration_digest: request.registration_digest.clone(),
                execution_class: request.execution_class,
                operation: request.operation.clone(),
                route_digest: request.route_digest.clone(),
                args_digest: request.args_digest.clone(),
                policy_version: request.policy_version.clone(),
                policy_epoch: request.policy_epoch.clone(),
                approval_reference: request.approval_reference.clone(),
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
                runtime_binding_digest: "runtime-binding".into(),
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
            assert_eq!(
                decision,
                AuthorityDecision::Allow(Box::new(grant(&request)))
            );
            assert_eq!(request.route_digest, "route");
            assert_eq!(request.args_digest, "args");
        }

        #[test]
        fn correct_once_adapter_delegates_without_owning_policy() {
            let adapter = CorrectOnceAuthorityAdapter::new(
                |request: &AuthorityRequest| {
                    assert_eq!(request.policy_epoch, "epoch");
                    Ok::<_, std::convert::Infallible>(AuthorityDecision::RequireApproval)
                },
                |request: &AuthorityRequest, grant: &VerifiedGrant| {
                    assert!(grant.binds(request));
                    Ok::<_, std::convert::Infallible>(())
                },
            );
            assert_eq!(
                adapter.decide(&request_from_identity(&identity())).unwrap(),
                AuthorityDecision::RequireApproval
            );
        }

        #[test]
        fn grants_bind_tenant_and_admission_as_well_as_capability_claims() {
            let request = request_from_identity(&identity());
            let valid = grant(&request);
            assert!(valid.binds(&request));

            let mut wrong_tenant = valid.clone();
            wrong_tenant.tenant_id = "other-tenant".into();
            assert!(!wrong_tenant.binds(&request));

            let mut wrong_admission = valid;
            wrong_admission.admission_id = "other-admission".into();
            assert!(!wrong_admission.binds(&request));
        }

        #[test]
        fn grant_binding_rejects_every_security_claim_mutation() {
            let mut identity = identity();
            identity.approval_reference = Some("approval-1".into());
            let request = request_from_identity(&identity);
            let valid = grant(&request);
            assert!(valid.binds(&request));

            let mut mutations = Vec::new();
            macro_rules! mutated_grant {
                ($field:ident, $value:expr) => {{
                    let mut candidate = valid.clone();
                    candidate.$field = $value;
                    mutations.push(candidate);
                }};
            }
            mutated_grant!(action_id, "other-action".into());
            mutated_grant!(idempotency_key, "other-idempotency".into());
            mutated_grant!(tenant_id, "other-tenant".into());
            mutated_grant!(principal_id, "other-principal".into());
            mutated_grant!(runtime_binding_digest, "other-runtime-binding".into());
            mutated_grant!(admission_id, "other-admission".into());
            mutated_grant!(capability_id, "other-capability".into());
            mutated_grant!(capability_generation, 2);
            mutated_grant!(registration_digest, "other-registration".into());
            mutated_grant!(execution_class, ExecutionClass::Critical);
            mutated_grant!(operation, "other-operation".into());
            mutated_grant!(route_digest, "other-route".into());
            mutated_grant!(args_digest, "other-args".into());
            mutated_grant!(policy_version, "other-policy".into());
            mutated_grant!(policy_epoch, "other-epoch".into());
            mutated_grant!(approval_reference, Some("other-approval".into()));

            for candidate in mutations {
                assert!(
                    !candidate.binds(&request),
                    "mutated grant unexpectedly bound: {candidate:?}"
                );
            }

            let mut empty_digest = valid;
            empty_digest.digest = " \t".into();
            assert!(!empty_digest.binds(&request));
        }
    }
}
