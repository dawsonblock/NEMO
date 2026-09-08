// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental execution-kernel contracts.
//!
//! The contracts in this crate define the narrow seam between the NeMo Relay
//! kernel and external authority/effect implementations. They do not provide
//! retries, idempotency, reconciliation, or a transactional intent boundary.

/// Whether durable execution is active.
pub const DURABLE_EXECUTION_ENABLED: bool = false;

/// Opt-in experimental contracts.
#[cfg(feature = "unstable-hardening")]
pub mod unstable {
    use serde::{Deserialize, Serialize};
    use serde_json::Value as Json;

    /// Canonical capability risk classification used for backend selection.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum ExecutionClass {
        /// Deterministic, side-effect-free computation.
        Pure,
        /// Observational or read-only work.
        Read,
        /// An externally meaningful but non-critical mutation.
        Mutation,
        /// A consequential mutation that requires the authority path.
        Critical,
    }

    /// Authenticated runtime identity supplied by the host, never by a model.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RuntimeIdentity {
        /// Stable principal identity.
        pub principal_id: String,
        /// Optional tenant or organization identity.
        pub tenant_id: Option<String>,
        /// Stable runtime instance identity.
        pub runtime_id: String,
        /// Deployment environment (for example `development` or `production`).
        pub environment: String,
        /// Optional authenticated session identity.
        pub session_id: Option<String>,
    }

    /// Immutable identity of a registered capability.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct CapabilityIdentity {
        /// Stable capability identifier.
        pub capability_id: String,
        /// Monotonic generation of the registered descriptor.
        pub capability_generation: u64,
        /// Digest of the immutable descriptor.
        pub registration_digest: String,
        /// Registered execution class.
        pub execution_class: ExecutionClass,
        /// Registered operation name.
        pub operation: String,
        /// Digest of the registered route.
        pub route_digest: String,
    }

    /// Immutable identity assigned before an invocation reaches a backend.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ExecutionIdentity {
        /// Stable execution identifier.
        pub execution_id: String,
        /// Stable invocation identifier.
        pub invocation_id: String,
        /// Stable action identifier for externally meaningful work.
        pub action_id: String,
        /// Idempotency key supplied by the authority-approved intent.
        pub idempotency_key: String,
        /// Host-authenticated runtime identity.
        pub runtime: RuntimeIdentity,
        /// Immutable registered capability identity.
        pub capability: CapabilityIdentity,
        /// Runtime admission identifier.
        pub admission_id: String,
        /// Authority policy version bound to this invocation.
        pub policy_version: String,
        /// Authority policy epoch bound to this invocation.
        pub policy_epoch: String,
        /// Canonical digest of invocation arguments.
        pub args_digest: String,
        /// Verification digest of the execution grant, when present.
        pub grant_digest: Option<String>,
        /// Correct-Once approval artifact for critical execution, when present.
        pub approval_reference: Option<String>,
        /// Absolute deadline represented as Unix milliseconds.
        pub deadline_unix_ms: u64,
    }

    /// One already-bound invocation crossing the kernel/backend boundary.
    ///
    /// This is a backend wire contract, not a harness-facing request type.
    /// The Relay kernel constructs it only after resolving immutable capability
    /// metadata and validating the unbound invocation.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct ExecutionRequest {
        /// Bound identity and capability metadata.
        pub identity: ExecutionIdentity,
        /// Validated invocation arguments.
        pub args: Json,
        /// Optional opaque grant token for backend verification.
        pub grant: Option<String>,
        /// Trace identifier used for observability correlation.
        pub trace_id: Option<String>,
    }

    /// Dispatch certainty at the external-effect boundary.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum DispatchState {
        /// The provider was not contacted.
        NotDispatched,
        /// Dispatch was attempted but acceptance is not proven.
        DispatchAttempted,
        /// The provider accepted the dispatch, but completion may remain unknown.
        DispatchConfirmed,
    }

    /// Certainty about the external effect outcome.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum OutcomeCertainty {
        /// The effect definitely did not commit.
        ConfirmedFailure,
        /// The effect definitely committed.
        ConfirmedSuccess,
        /// The runtime cannot prove success or failure.
        Unknown,
    }

    /// Structured error emitted by a backend that can cross an effect boundary.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct EffectExecutionError {
        /// Stable machine-readable error code.
        pub code: String,
        /// Whether dispatch crossed the provider boundary.
        pub dispatch_state: DispatchState,
        /// Certainty about the resulting effect.
        pub outcome_certainty: OutcomeCertainty,
        /// Provider request identifier, when available.
        pub provider_request_id: Option<String>,
        /// Whether an automatic retry is safe.
        pub retryable: bool,
        /// Whether the action must be reconciled before retry.
        pub reconciliation_required: bool,
        /// Human-readable diagnostic detail.
        pub message: String,
    }

    impl std::fmt::Display for EffectExecutionError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "{}: {}", self.code, self.message)
        }
    }

    impl std::error::Error for EffectExecutionError {}

    /// Normalized result returned by a kernel backend.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct ExecutionResult {
        /// Structured backend output.
        pub output: Json,
        /// Effect certainty for consequential work.
        pub outcome_certainty: OutcomeCertainty,
        /// Optional authoritative receipt digest.
        pub receipt_digest: Option<String>,
    }

    /// Adapter boundary for execution backends owned by another subsystem.
    ///
    /// Implementations may target Function Hooks, Effect Fabric, or a worker
    /// broker. This crate does not provide retries, persistence, or authority.
    pub trait ExecutionBackend: Send + Sync {
        /// Dispatch one already-authorized execution identity.
        fn execute(
            &self,
            request: &ExecutionRequest,
        ) -> Result<ExecutionResult, EffectExecutionError>;
    }

    fn class_mismatch(expected: &str, actual: ExecutionClass) -> EffectExecutionError {
        EffectExecutionError {
            code: "BACKEND_CLASS_MISMATCH".into(),
            dispatch_state: DispatchState::NotDispatched,
            outcome_certainty: OutcomeCertainty::ConfirmedFailure,
            provider_request_id: None,
            retryable: false,
            reconciliation_required: false,
            message: format!("{expected} backend cannot execute {actual:?} capability"),
        }
    }

    /// Adapter for an application-owned Function Hooks implementation.
    pub struct FunctionHooksExecutionBackend<F> {
        handler: F,
    }

    impl<F> FunctionHooksExecutionBackend<F> {
        /// Wrap an application-owned Function Hooks callback.
        pub const fn new(handler: F) -> Self {
            Self { handler }
        }
    }

    impl<F> ExecutionBackend for FunctionHooksExecutionBackend<F>
    where
        F: Fn(&ExecutionRequest) -> Result<ExecutionResult, EffectExecutionError> + Send + Sync,
    {
        fn execute(
            &self,
            request: &ExecutionRequest,
        ) -> Result<ExecutionResult, EffectExecutionError> {
            match request.identity.capability.execution_class {
                ExecutionClass::Pure | ExecutionClass::Read => (self.handler)(request),
                class => Err(class_mismatch("Function Hooks", class)),
            }
        }
    }

    /// Adapter for an external Effect Fabric implementation.
    pub struct EffectFabricExecutionBackend<F> {
        handler: F,
    }

    impl<F> EffectFabricExecutionBackend<F> {
        /// Wrap an external Effect Fabric callback.
        pub const fn new(handler: F) -> Self {
            Self { handler }
        }
    }

    impl<F> ExecutionBackend for EffectFabricExecutionBackend<F>
    where
        F: Fn(&ExecutionRequest) -> Result<ExecutionResult, EffectExecutionError> + Send + Sync,
    {
        fn execute(
            &self,
            request: &ExecutionRequest,
        ) -> Result<ExecutionResult, EffectExecutionError> {
            match request.identity.capability.execution_class {
                ExecutionClass::Mutation | ExecutionClass::Critical => (self.handler)(request),
                class => Err(class_mismatch("Effect Fabric", class)),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;

        struct TestBackend;

        impl ExecutionBackend for TestBackend {
            fn execute(
                &self,
                request: &ExecutionRequest,
            ) -> Result<ExecutionResult, EffectExecutionError> {
                Ok(ExecutionResult {
                    output: request.args.clone(),
                    outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
                    receipt_digest: Some("receipt".into()),
                })
            }
        }

        fn request() -> ExecutionRequest {
            ExecutionRequest {
                identity: ExecutionIdentity {
                    execution_id: "execution".into(),
                    invocation_id: "invocation".into(),
                    action_id: "action".into(),
                    idempotency_key: "idempotency".into(),
                    runtime: RuntimeIdentity {
                        principal_id: "alice".into(),
                        tenant_id: None,
                        runtime_id: "runtime".into(),
                        environment: "test".into(),
                        session_id: None,
                    },
                    capability: CapabilityIdentity {
                        capability_id: "capability".into(),
                        capability_generation: 1,
                        registration_digest: "registration".into(),
                        execution_class: ExecutionClass::Pure,
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
                },
                args: json!({"value": 1}),
                grant: None,
                trace_id: None,
            }
        }

        #[test]
        fn third_party_backend_can_implement_the_public_contract() {
            let result = TestBackend
                .execute(&request())
                .expect("backend should execute");
            assert_eq!(result.output, json!({"value": 1}));
            assert_eq!(result.outcome_certainty, OutcomeCertainty::ConfirmedSuccess);
        }

        #[test]
        fn concrete_adapters_reject_wrong_execution_classes() {
            let function = FunctionHooksExecutionBackend::new(
                |_: &ExecutionRequest| -> Result<ExecutionResult, EffectExecutionError> {
                    Ok(ExecutionResult {
                        output: json!({"path": "function-hooks"}),
                        outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
                        receipt_digest: None,
                    })
                },
            );
            let effect = EffectFabricExecutionBackend::new(
                |_: &ExecutionRequest| -> Result<ExecutionResult, EffectExecutionError> {
                    Ok(ExecutionResult {
                        output: json!({"path": "effect-fabric"}),
                        outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
                        receipt_digest: Some("receipt".into()),
                    })
                },
            );
            assert!(function.execute(&request()).is_ok());
            assert_eq!(
                effect.execute(&request()).unwrap_err().code,
                "BACKEND_CLASS_MISMATCH"
            );
        }
    }
}
