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
    use nemo_relay_ledger::unstable::{ExecutionState, ReceiptRecord};
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
        /// Stable logical deployment/runtime identity, never a per-process random ID.
        pub runtime_id: String,
        /// Deployment environment (for example `development` or `production`).
        pub environment: String,
        /// Optional authenticated session identity.
        pub session_id: Option<String>,
    }

    /// Failure returned when a host supplies an ambiguous durable runtime identity.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RuntimeIdentityError {
        /// A required identity value was blank or contained surrounding whitespace.
        InvalidField(&'static str),
        /// An identity value exceeded the durable representation limit.
        FieldTooLong(&'static str),
    }

    impl std::fmt::Display for RuntimeIdentityError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::InvalidField(field) => {
                    write!(
                        formatter,
                        "runtime identity field {field} must be non-empty and trimmed"
                    )
                }
                Self::FieldTooLong(field) => {
                    write!(
                        formatter,
                        "runtime identity field {field} exceeds 256 bytes"
                    )
                }
            }
        }
    }

    impl std::error::Error for RuntimeIdentityError {}

    impl RuntimeIdentity {
        /// Validate the durable identity supplied by the trusted runtime host.
        ///
        /// The kernel hashes these values into the action and grant bindings,
        /// so `None`, an empty string, and a whitespace-padded value must not
        /// accidentally collapse into interchangeable principals or tenants.
        pub fn validate(&self) -> Result<(), RuntimeIdentityError> {
            validate_identity_field("principal_id", &self.principal_id)?;
            validate_identity_field("runtime_id", &self.runtime_id)?;
            validate_identity_field("environment", &self.environment)?;
            if let Some(tenant_id) = &self.tenant_id {
                validate_identity_field("tenant_id", tenant_id)?;
            }
            if let Some(session_id) = &self.session_id {
                validate_identity_field("session_id", session_id)?;
            }
            Ok(())
        }
    }

    fn validate_identity_field(
        field: &'static str,
        value: &str,
    ) -> Result<(), RuntimeIdentityError> {
        if value.is_empty() || value.trim() != value {
            return Err(RuntimeIdentityError::InvalidField(field));
        }
        if value.len() > 256 {
            return Err(RuntimeIdentityError::FieldTooLong(field));
        }
        Ok(())
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
        /// Canonical digest binding runtime, environment, and session provenance.
        pub runtime_binding_digest: String,
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

    // Dispatch certainty is contract vocabulary rather than an adapter detail:
    // the kernel classifies backend errors with it, and the plugin contract has
    // to report it so a plugin failure cannot pass for a definite outcome. It
    // is canonical in `nemo-relay-types` and re-exported here so the paths that
    // already name it keep working.
    pub use nemo_relay_types::execution::{DispatchState, OutcomeCertainty};

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

    /// Classify a backend error without losing dispatch certainty.
    ///
    /// Any result after an attempted or confirmed dispatch is durable
    /// `UNKNOWN` unless the backend returned a successful [`ExecutionResult`]
    /// with a receipt. `ConfirmedSuccess` on an error is therefore treated as
    /// an invalid backend result and fails closed as `UNKNOWN`.
    pub const fn state_for_error(error: &EffectExecutionError) -> ExecutionState {
        match (error.dispatch_state, error.outcome_certainty) {
            (DispatchState::NotDispatched, OutcomeCertainty::ConfirmedFailure) => {
                ExecutionState::Failed
            }
            (_, OutcomeCertainty::Unknown) => ExecutionState::Unknown,
            (DispatchState::DispatchAttempted | DispatchState::DispatchConfirmed, _) => {
                ExecutionState::Unknown
            }
            (DispatchState::NotDispatched, OutcomeCertainty::ConfirmedSuccess) => {
                ExecutionState::Unknown
            }
        }
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
        /// Complete authoritative receipt supplied by an effect backend.
        ///
        /// Pure and read backends leave this absent. Consequential backends
        /// return it only after Effect Fabric has created the evidence object.
        pub receipt: Option<ReceiptRecord>,
    }

    /// Result of provider reconciliation for an action previously marked
    /// `UNKNOWN` by the external effect implementation.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct ReconciliationResult {
        /// Authoritative state established by reconciliation.
        pub state: ExecutionState,
        /// Optional evidence receipt created during reconciliation.
        pub receipt: Option<ReceiptRecord>,
    }

    /// Bounded request to reconcile one externally ambiguous logical action.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ReconciliationRequest {
        /// Stable durable action identity.
        pub action_id: String,
        /// Host deadline the provider must honor before its recovery lease ends.
        pub deadline_unix_ms: u64,
    }

    /// Adapter boundary for execution backends owned by another subsystem.
    ///
    /// Implementations may target Function Hooks, Effect Fabric, or a worker
    /// broker. This crate does not provide retries, persistence, or authority.
    pub trait ExecutionBackend: Send + Sync {
        /// Dispatch one already-authorized execution identity.
        ///
        /// Implementations must honor `request.identity.deadline_unix_ms`.
        /// The kernel sizes that deadline beneath the ActionStore lease policy
        /// so a conforming backend cannot remain live after its lease expires.
        fn execute(
            &self,
            request: &ExecutionRequest,
        ) -> Result<ExecutionResult, EffectExecutionError>;
    }

    /// Adapter boundary for resolving an externally ambiguous action.
    ///
    /// Effect Fabric or its provider adapter owns reconciliation mechanics.
    /// Relay only requests evidence for a stable action identifier and records
    /// the resulting shared effect state through its supplied contracts.
    pub trait ReconciliationProvider: Send + Sync {
        /// Reconcile one action previously marked `UNKNOWN`.
        ///
        /// Implementations must honor [`ReconciliationRequest::deadline_unix_ms`]
        /// and must not issue an unbounded provider operation after the deadline.
        fn reconcile(
            &self,
            request: &ReconciliationRequest,
        ) -> Result<ReconciliationResult, EffectExecutionError>;
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

        #[test]
        fn unknown_after_any_dispatch_is_never_downgraded_to_failure() {
            for dispatch_state in [
                DispatchState::DispatchAttempted,
                DispatchState::DispatchConfirmed,
            ] {
                let error = EffectExecutionError {
                    code: "ambiguous".into(),
                    dispatch_state,
                    outcome_certainty: OutcomeCertainty::Unknown,
                    provider_request_id: None,
                    retryable: false,
                    reconciliation_required: true,
                    message: "unknown".into(),
                };
                assert_eq!(state_for_error(&error), ExecutionState::Unknown);
            }
        }

        #[test]
        fn confirmed_failure_before_dispatch_is_failed() {
            let error = EffectExecutionError {
                code: "validation".into(),
                dispatch_state: DispatchState::NotDispatched,
                outcome_certainty: OutcomeCertainty::ConfirmedFailure,
                provider_request_id: None,
                retryable: false,
                reconciliation_required: false,
                message: "rejected before dispatch".into(),
            };
            assert_eq!(state_for_error(&error), ExecutionState::Failed);
        }

        #[test]
        fn success_reported_as_an_error_never_commits_without_a_receipt() {
            let error = EffectExecutionError {
                code: "INVALID_SUCCESS_ERROR".into(),
                dispatch_state: DispatchState::NotDispatched,
                outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
                provider_request_id: None,
                retryable: false,
                reconciliation_required: true,
                message: "success must be an execution result".into(),
            };
            assert_eq!(state_for_error(&error), ExecutionState::Unknown);
        }

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
                    receipt: None,
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
                    runtime_binding_digest: "runtime-binding".into(),
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
                        receipt: None,
                    })
                },
            );
            let effect = EffectFabricExecutionBackend::new(
                |_: &ExecutionRequest| -> Result<ExecutionResult, EffectExecutionError> {
                    Ok(ExecutionResult {
                        output: json!({"path": "effect-fabric"}),
                        outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
                        receipt_digest: Some("receipt".into()),
                        receipt: None,
                    })
                },
            );
            for class in [ExecutionClass::Pure, ExecutionClass::Read] {
                let mut request = request();
                request.identity.capability.execution_class = class;
                assert!(function.execute(&request).is_ok());
                assert_eq!(
                    effect.execute(&request).unwrap_err().code,
                    "BACKEND_CLASS_MISMATCH"
                );
            }
            for class in [ExecutionClass::Mutation, ExecutionClass::Critical] {
                let mut request = request();
                request.identity.capability.execution_class = class;
                assert_eq!(
                    function.execute(&request).unwrap_err().code,
                    "BACKEND_CLASS_MISMATCH"
                );
                assert!(effect.execute(&request).is_ok());
            }
        }

        #[test]
        fn runtime_identity_rejects_blank_or_noncanonical_durable_fields() {
            let valid = RuntimeIdentity {
                principal_id: "alice".into(),
                tenant_id: Some("tenant".into()),
                runtime_id: "deployment-a".into(),
                environment: "production".into(),
                session_id: None,
            };
            assert_eq!(valid.validate(), Ok(()));

            for (field, value) in [
                ("principal_id", " "),
                ("tenant_id", " tenant"),
                ("runtime_id", ""),
                ("environment", "production "),
            ] {
                let mut identity = valid.clone();
                match field {
                    "principal_id" => identity.principal_id = value.into(),
                    "tenant_id" => identity.tenant_id = Some(value.into()),
                    "runtime_id" => identity.runtime_id = value.into(),
                    "environment" => identity.environment = value.into(),
                    _ => unreachable!(),
                }
                assert_eq!(
                    identity.validate(),
                    Err(RuntimeIdentityError::InvalidField(field))
                );
            }
        }
    }
}
