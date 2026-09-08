// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract-driven capability execution for the experimental hardening ABI.
//!
//! This module is deliberately small. Relay owns classification and routing;
//! Correct-Once, Effect Fabric, workers, and DLP implementations remain
//! external providers of the contracts defined by the hardening crates.

use nemo_relay_authority::unstable::{AuthorityDecision, AuthorityProvider, request_from_identity};
use nemo_relay_executor::unstable::{
    ExecutionBackend, ExecutionClass, ExecutionRequest, ExecutionResult,
};

/// Typed failures produced before a backend crosses an execution boundary.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    /// The authority provider could not evaluate the request.
    #[error("authority provider unavailable: {0}")]
    AuthorityUnavailable(String),
    /// The authority provider denied the request.
    #[error("authority denied the capability invocation")]
    AuthorityDenied,
    /// A fresh approval is required before the effect can proceed.
    #[error("authority requires approval")]
    ApprovalRequired,
    /// The authority deferred the request to another policy boundary.
    #[error("authority deferred the capability invocation")]
    AuthorityDeferred,
    /// The authority requested changes that must be materialized as a new grant.
    #[error("authority modification requires a new normalized execution request")]
    AuthorityModificationRequired,
    /// The fast-path backend failed before an external effect boundary.
    #[error("function hooks backend failed: {0}")]
    FunctionBackend(String),
    /// The effect backend returned a structured dispatch outcome.
    #[error("effect backend failed: {0}")]
    EffectBackend(#[from] nemo_relay_executor::unstable::EffectExecutionError),
}

/// Deterministic backend router owned by the Relay kernel.
///
/// The caller supplies only an already-bound execution request. Backend
/// selection is derived from the immutable registered execution class; there
/// is no per-call backend hint to override.
pub struct BackendRouter<A, F, E> {
    authority: A,
    function_hooks: F,
    effect_fabric: E,
}

impl<A, F, E> BackendRouter<A, F, E> {
    /// Construct a router from external authority and execution providers.
    pub const fn new(authority: A, function_hooks: F, effect_fabric: E) -> Self {
        Self {
            authority,
            function_hooks,
            effect_fabric,
        }
    }

    /// Borrow the configured authority provider.
    pub const fn authority(&self) -> &A {
        &self.authority
    }
}

impl<A, F, E> BackendRouter<A, F, E>
where
    A: AuthorityProvider,
    A::Error: std::fmt::Display,
    F: ExecutionBackend,
    E: ExecutionBackend,
{
    /// Invoke one capability through the authoritative kernel boundary.
    pub fn invoke(&self, request: &ExecutionRequest) -> Result<ExecutionResult, KernelError> {
        match request.identity.capability.execution_class {
            ExecutionClass::Pure | ExecutionClass::Read => self
                .function_hooks
                .execute(request)
                .map_err(|error| KernelError::FunctionBackend(error.to_string())),
            ExecutionClass::Mutation | ExecutionClass::Critical => {
                let authority_request = request_from_identity(&request.identity);
                let decision = self
                    .authority
                    .decide(&authority_request)
                    .map_err(|error| KernelError::AuthorityUnavailable(error.to_string()))?;
                match decision {
                    AuthorityDecision::Allow => self
                        .effect_fabric
                        .execute(request)
                        .map_err(KernelError::from),
                    AuthorityDecision::Deny => Err(KernelError::AuthorityDenied),
                    AuthorityDecision::RequireApproval => Err(KernelError::ApprovalRequired),
                    AuthorityDecision::Defer => Err(KernelError::AuthorityDeferred),
                    AuthorityDecision::Modify(_) => Err(KernelError::AuthorityModificationRequired),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay_authority::unstable::{AuthorityDecision, AuthorityRequest};
    use nemo_relay_executor::unstable::{
        CapabilityIdentity, EffectExecutionError, OutcomeCertainty, RuntimeIdentity,
    };
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone)]
    struct TestAuthority {
        decision: AuthorityDecision,
        calls: Arc<AtomicUsize>,
    }

    impl AuthorityProvider for TestAuthority {
        type Error = String;

        fn decide(&self, _request: &AuthorityRequest) -> Result<AuthorityDecision, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }
    }

    #[derive(Clone)]
    struct TestBackend {
        calls: Arc<AtomicUsize>,
        outcome: OutcomeCertainty,
    }

    impl ExecutionBackend for TestBackend {
        fn execute(
            &self,
            _request: &ExecutionRequest,
        ) -> Result<ExecutionResult, EffectExecutionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ExecutionResult {
                output: json!({"ok": true}),
                outcome_certainty: self.outcome,
                receipt_digest: None,
            })
        }
    }

    fn request(class: ExecutionClass) -> ExecutionRequest {
        ExecutionRequest {
            identity: nemo_relay_executor::unstable::ExecutionIdentity {
                execution_id: "exec-1".into(),
                invocation_id: "invoke-1".into(),
                action_id: "action-1".into(),
                idempotency_key: "idem-1".into(),
                runtime: RuntimeIdentity {
                    principal_id: "alice".into(),
                    tenant_id: Some("tenant".into()),
                    runtime_id: "runtime-1".into(),
                    environment: "test".into(),
                    session_id: None,
                },
                capability: CapabilityIdentity {
                    capability_id: "capability.test".into(),
                    capability_generation: 1,
                    registration_digest: "registration".into(),
                    execution_class: class,
                    operation: "test".into(),
                    route_digest: "route".into(),
                },
                admission_id: "admission-1".into(),
                policy_version: "policy-1".into(),
                policy_epoch: "epoch-1".into(),
                args_digest: "args".into(),
                grant_digest: Some("grant".into()),
                approval_reference: None,
                deadline_unix_ms: 4_000,
            },
            args: json!({"value": 1}),
            grant: Some("grant-token".into()),
            trace_id: Some("trace-1".into()),
        }
    }

    #[test]
    fn pure_and_read_use_fast_backend_without_authority() {
        for class in [ExecutionClass::Pure, ExecutionClass::Read] {
            let authority_calls = Arc::new(AtomicUsize::new(0));
            let function_calls = Arc::new(AtomicUsize::new(0));
            let effect_calls = Arc::new(AtomicUsize::new(0));
            let router = BackendRouter::new(
                TestAuthority {
                    decision: AuthorityDecision::Allow,
                    calls: authority_calls.clone(),
                },
                TestBackend {
                    calls: function_calls.clone(),
                    outcome: OutcomeCertainty::ConfirmedSuccess,
                },
                TestBackend {
                    calls: effect_calls.clone(),
                    outcome: OutcomeCertainty::ConfirmedSuccess,
                },
            );
            router
                .invoke(&request(class))
                .expect("fast path should execute");
            assert_eq!(authority_calls.load(Ordering::SeqCst), 0);
            assert_eq!(function_calls.load(Ordering::SeqCst), 1);
            assert_eq!(effect_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn mutation_and_critical_require_authority_before_effect_backend() {
        for class in [ExecutionClass::Mutation, ExecutionClass::Critical] {
            let authority_calls = Arc::new(AtomicUsize::new(0));
            let effect_calls = Arc::new(AtomicUsize::new(0));
            let router = BackendRouter::new(
                TestAuthority {
                    decision: AuthorityDecision::Allow,
                    calls: authority_calls.clone(),
                },
                TestBackend {
                    calls: Arc::new(AtomicUsize::new(0)),
                    outcome: OutcomeCertainty::ConfirmedSuccess,
                },
                TestBackend {
                    calls: effect_calls.clone(),
                    outcome: OutcomeCertainty::ConfirmedSuccess,
                },
            );
            router
                .invoke(&request(class))
                .expect("authorized effect should execute");
            assert_eq!(authority_calls.load(Ordering::SeqCst), 1);
            assert_eq!(effect_calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn authority_denial_prevents_effect_execution() {
        let effect_calls = Arc::new(AtomicUsize::new(0));
        let router = BackendRouter::new(
            TestAuthority {
                decision: AuthorityDecision::Deny,
                calls: Arc::new(AtomicUsize::new(0)),
            },
            TestBackend {
                calls: Arc::new(AtomicUsize::new(0)),
                outcome: OutcomeCertainty::ConfirmedSuccess,
            },
            TestBackend {
                calls: effect_calls.clone(),
                outcome: OutcomeCertainty::ConfirmedSuccess,
            },
        );
        assert!(matches!(
            router.invoke(&request(ExecutionClass::Mutation)),
            Err(KernelError::AuthorityDenied)
        ));
        assert_eq!(effect_calls.load(Ordering::SeqCst), 0);
    }
}
