// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract-driven capability execution for the experimental hardening ABI.
//!
//! This module is deliberately small. Relay owns classification and routing;
//! Correct-Once, Effect Fabric, workers, and DLP implementations remain
//! external providers of the contracts defined by the hardening crates.

use std::collections::HashMap;

use nemo_relay_authority::unstable::{AuthorityDecision, AuthorityProvider, request_from_identity};
use nemo_relay_executor::unstable::{
    CapabilityIdentity, ExecutionBackend, ExecutionClass, ExecutionIdentity, ExecutionRequest,
    ExecutionResult, RuntimeIdentity,
};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Typed failures produced before a backend crosses an execution boundary.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    /// The requested capability is absent from the kernel registry.
    #[error("capability is not registered: {0}")]
    CapabilityUnknown(String),
    /// The registered capability is not currently admitted.
    #[error("capability is not currently admitted: {0}")]
    CapabilityNotAdmitted(String),
    /// A capability identifier was registered more than once.
    #[error("capability is already registered: {0}")]
    CapabilityAlreadyRegistered(String),
    /// Arguments did not satisfy the immutable capability schema.
    #[error("capability arguments failed schema validation: {0}")]
    SchemaValidationFailed(String),
    /// Argument canonicalization failed before an execution identity was bound.
    #[error("could not canonicalize invocation arguments: {0}")]
    ArgumentCanonicalization(String),
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

/// The only invocation data accepted from an agent harness.
///
/// The harness chooses an admitted capability and supplies its arguments. It
/// cannot set an execution class, runtime identity, route, admission, policy,
/// digest, grant, or backend.
#[derive(Debug, Clone, PartialEq)]
pub struct InvocationRequest {
    /// Identifier of the registered capability to invoke.
    pub capability_id: String,
    /// Untrusted arguments that the kernel validates against the descriptor.
    pub args: Json,
    /// Optional trace correlation identifier with no authority semantics.
    pub trace_id: Option<String>,
}

/// Immutable data registered for a capability before any harness invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDefinition {
    /// Stable capability identifier.
    pub capability_id: String,
    /// Monotonic generation of this registration.
    pub capability_generation: u64,
    /// Digest of the immutable registration descriptor.
    pub registration_digest: String,
    /// Kernel-owned execution classification.
    pub execution_class: ExecutionClass,
    /// Registered operation name.
    pub operation: String,
    /// Digest of the immutable registered route.
    pub route_digest: String,
    /// Current admission identifier for this capability registration.
    pub admission_id: String,
    /// Policy version associated with the current admission.
    pub policy_version: String,
    /// Policy epoch associated with the current admission.
    pub policy_epoch: String,
    /// Whether the capability is currently admitted for execution.
    pub admitted: bool,
}

impl CapabilityDefinition {
    fn identity(&self) -> CapabilityIdentity {
        CapabilityIdentity {
            capability_id: self.capability_id.clone(),
            capability_generation: self.capability_generation,
            registration_digest: self.registration_digest.clone(),
            execution_class: self.execution_class,
            operation: self.operation.clone(),
            route_digest: self.route_digest.clone(),
        }
    }
}

/// Restricted-schema validation supplied at capability registration time.
///
/// A production registry can delegate this to the same strict schema engine
/// that admitted the capability. The kernel records only the validator result;
/// it does not own a second schema language.
pub trait SchemaValidator: Send + Sync {
    /// Validate untrusted invocation arguments.
    fn validate(&self, args: &Json) -> Result<(), String>;
}

impl<F> SchemaValidator for F
where
    F: Fn(&Json) -> Result<(), String> + Send + Sync,
{
    fn validate(&self, args: &Json) -> Result<(), String> {
        self(args)
    }
}

struct RegisteredCapability {
    definition: CapabilityDefinition,
    validator: Box<dyn SchemaValidator>,
}

/// Kernel-owned registry of immutable capability definitions.
///
/// Definitions are moved into the registry at startup. A harness can resolve a
/// capability by identifier but cannot supply or alter its security semantics.
#[derive(Default)]
pub struct CapabilityRegistry {
    capabilities: HashMap<String, RegisteredCapability>,
}

impl CapabilityRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one immutable capability and its schema validator.
    pub fn register<V>(
        &mut self,
        definition: CapabilityDefinition,
        validator: V,
    ) -> Result<(), KernelError>
    where
        V: SchemaValidator + 'static,
    {
        let capability_id = definition.capability_id.clone();
        if self.capabilities.contains_key(&capability_id) {
            return Err(KernelError::CapabilityAlreadyRegistered(capability_id));
        }
        self.capabilities.insert(
            capability_id,
            RegisteredCapability {
                definition,
                validator: Box::new(validator),
            },
        );
        Ok(())
    }

    fn resolve(&self, capability_id: &str) -> Result<&RegisteredCapability, KernelError> {
        self.capabilities
            .get(capability_id)
            .ok_or_else(|| KernelError::CapabilityUnknown(capability_id.to_owned()))
    }
}

/// A request bound by the kernel after registry, schema, identity, and digest
/// checks have completed.
///
/// Its fields and constructor are deliberately private. External harnesses
/// cannot manufacture a bound request or substitute a weaker execution class
/// before backend routing.
pub struct BoundExecutionRequest {
    request: ExecutionRequest,
}

impl BoundExecutionRequest {
    fn backend_request(&self) -> &ExecutionRequest {
        &self.request
    }
}

/// Deterministic backend router owned by the Relay kernel.
///
/// This is a post-binding component, not a public harness entry point.
/// [`Kernel::invoke`] creates the opaque bound request that this router accepts.
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
    /// Route one already-bound capability invocation.
    ///
    /// This method is crate-private so a harness cannot bypass the binding
    /// kernel with a caller-constructed backend request.
    pub(crate) fn invoke_bound(
        &self,
        request: &BoundExecutionRequest,
    ) -> Result<ExecutionResult, KernelError> {
        let request = request.backend_request();
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

/// Public capability kernel entry point.
///
/// The kernel accepts only an unbound capability invocation, resolves its
/// immutable descriptor, validates its arguments, and constructs the opaque
/// request consumed by [`BackendRouter`]. Authority and execution mechanisms
/// remain external adapters.
pub struct Kernel<A, F, E> {
    runtime: RuntimeIdentity,
    registry: CapabilityRegistry,
    router: BackendRouter<A, F, E>,
}

impl<A, F, E> Kernel<A, F, E> {
    /// Construct a kernel from a trusted runtime identity, immutable registry,
    /// and external adapter router.
    pub fn new(
        runtime: RuntimeIdentity,
        registry: CapabilityRegistry,
        router: BackendRouter<A, F, E>,
    ) -> Self {
        Self {
            runtime,
            registry,
            router,
        }
    }

    fn bind(&self, invocation: &InvocationRequest) -> Result<BoundExecutionRequest, KernelError> {
        let registered = self.registry.resolve(&invocation.capability_id)?;
        if !registered.definition.admitted {
            return Err(KernelError::CapabilityNotAdmitted(
                invocation.capability_id.clone(),
            ));
        }
        registered
            .validator
            .validate(&invocation.args)
            .map_err(KernelError::SchemaValidationFailed)?;

        let canonical = serde_json_canonicalizer::to_vec(&invocation.args)
            .map_err(|error| KernelError::ArgumentCanonicalization(error.to_string()))?;
        let args_digest = sha256_hex(&canonical);
        let execution_id = Uuid::now_v7().to_string();
        let action_id = Uuid::now_v7().to_string();
        let deadline_unix_ms = chrono::Utc::now()
            .timestamp_millis()
            .saturating_add(30_000)
            .try_into()
            .unwrap_or(u64::MAX);
        let definition = &registered.definition;

        Ok(BoundExecutionRequest {
            request: ExecutionRequest {
                identity: ExecutionIdentity {
                    execution_id: execution_id.clone(),
                    invocation_id: execution_id,
                    action_id: action_id.clone(),
                    // This is an invocation-local key, not durable effect
                    // idempotency. Effect Fabric replaces it with durable
                    // state when it owns consequential execution.
                    idempotency_key: action_id,
                    runtime: self.runtime.clone(),
                    capability: definition.identity(),
                    admission_id: definition.admission_id.clone(),
                    policy_version: definition.policy_version.clone(),
                    policy_epoch: definition.policy_epoch.clone(),
                    args_digest,
                    grant_digest: None,
                    approval_reference: None,
                    deadline_unix_ms,
                },
                args: invocation.args.clone(),
                grant: None,
                trace_id: invocation.trace_id.clone(),
            },
        })
    }
}

impl<A, F, E> Kernel<A, F, E>
where
    A: AuthorityProvider,
    A::Error: std::fmt::Display,
    F: ExecutionBackend,
    E: ExecutionBackend,
{
    /// Invoke an admitted capability through the secure binding and routing
    /// boundary.
    pub fn invoke(&self, invocation: &InvocationRequest) -> Result<ExecutionResult, KernelError> {
        let request = self.bind(invocation)?;
        self.router.invoke_bound(&request)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay_authority::unstable::{AuthorityDecision, AuthorityRequest};
    use nemo_relay_executor::unstable::{EffectExecutionError, OutcomeCertainty};
    use serde_json::json;
    use std::sync::{
        Arc, Mutex,
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
        requests: Arc<Mutex<Vec<ExecutionRequest>>>,
    }

    impl ExecutionBackend for TestBackend {
        fn execute(
            &self,
            request: &ExecutionRequest,
        ) -> Result<ExecutionResult, EffectExecutionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.requests
                .lock()
                .expect("test request lock should not be poisoned")
                .push(request.clone());
            Ok(ExecutionResult {
                output: json!({"ok": true}),
                outcome_certainty: self.outcome,
                receipt_digest: None,
            })
        }
    }

    fn runtime() -> RuntimeIdentity {
        RuntimeIdentity {
            principal_id: "alice".into(),
            tenant_id: Some("tenant".into()),
            runtime_id: "runtime-1".into(),
            environment: "test".into(),
            session_id: None,
        }
    }

    fn definition(class: ExecutionClass) -> CapabilityDefinition {
        CapabilityDefinition {
            capability_id: "capability.test".into(),
            capability_generation: 7,
            registration_digest: "registration-7".into(),
            execution_class: class,
            operation: "test".into(),
            route_digest: "route-7".into(),
            admission_id: "admission-7".into(),
            policy_version: "policy-7".into(),
            policy_epoch: "epoch-7".into(),
            admitted: true,
        }
    }

    fn registry(class: ExecutionClass) -> CapabilityRegistry {
        let mut registry = CapabilityRegistry::new();
        registry
            .register(definition(class), |args: &Json| {
                args.get("value")
                    .is_some()
                    .then_some(())
                    .ok_or_else(|| "value is required".to_owned())
            })
            .expect("test capability should register");
        registry
    }

    fn backend(calls: Arc<AtomicUsize>) -> TestBackend {
        TestBackend {
            calls,
            outcome: OutcomeCertainty::ConfirmedSuccess,
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn invocation() -> InvocationRequest {
        InvocationRequest {
            capability_id: "capability.test".into(),
            args: json!({"value": 1}),
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
                backend(function_calls.clone()),
                backend(effect_calls.clone()),
            );
            let kernel = Kernel::new(runtime(), registry(class), router);
            kernel
                .invoke(&invocation())
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
                backend(Arc::new(AtomicUsize::new(0))),
                backend(effect_calls.clone()),
            );
            let kernel = Kernel::new(runtime(), registry(class), router);
            kernel
                .invoke(&invocation())
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
            backend(Arc::new(AtomicUsize::new(0))),
            backend(effect_calls.clone()),
        );
        let kernel = Kernel::new(runtime(), registry(ExecutionClass::Mutation), router);
        assert!(matches!(
            kernel.invoke(&invocation()),
            Err(KernelError::AuthorityDenied)
        ));
        assert_eq!(effect_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn public_invocation_cannot_downgrade_a_critical_registration() {
        let authority_calls = Arc::new(AtomicUsize::new(0));
        let function_calls = Arc::new(AtomicUsize::new(0));
        let effect_calls = Arc::new(AtomicUsize::new(0));
        let effect = backend(effect_calls.clone());
        let observed = effect.requests.clone();
        let router = BackendRouter::new(
            TestAuthority {
                decision: AuthorityDecision::Allow,
                calls: authority_calls.clone(),
            },
            backend(function_calls.clone()),
            effect,
        );
        let kernel = Kernel::new(runtime(), registry(ExecutionClass::Critical), router);

        // InvocationRequest intentionally has no execution-class field. The
        // immutable registry registration determines the backend route.
        kernel
            .invoke(&invocation())
            .expect("registered critical capability should execute");

        assert_eq!(authority_calls.load(Ordering::SeqCst), 1);
        assert_eq!(function_calls.load(Ordering::SeqCst), 0);
        assert_eq!(effect_calls.load(Ordering::SeqCst), 1);
        let request = observed
            .lock()
            .expect("test request lock should not be poisoned")
            .pop()
            .expect("effect backend should observe one request");
        assert_eq!(
            request.identity.capability.execution_class,
            ExecutionClass::Critical
        );
        assert_eq!(request.identity.capability.capability_generation, 7);
        assert_eq!(
            request.identity.capability.registration_digest,
            "registration-7"
        );
        assert_eq!(request.identity.capability.route_digest, "route-7");
        assert_eq!(request.identity.runtime, runtime());
        assert_eq!(request.identity.admission_id, "admission-7");
        assert_eq!(request.identity.policy_version, "policy-7");
        assert_eq!(request.identity.policy_epoch, "epoch-7");
        let canonical = serde_json_canonicalizer::to_vec(&json!({"value": 1}))
            .expect("test arguments should canonicalize");
        assert_eq!(request.identity.args_digest, sha256_hex(&canonical));
    }

    #[test]
    fn schema_validation_happens_before_authority_or_backend_execution() {
        let authority_calls = Arc::new(AtomicUsize::new(0));
        let function_calls = Arc::new(AtomicUsize::new(0));
        let effect_calls = Arc::new(AtomicUsize::new(0));
        let router = BackendRouter::new(
            TestAuthority {
                decision: AuthorityDecision::Allow,
                calls: authority_calls.clone(),
            },
            backend(function_calls.clone()),
            backend(effect_calls.clone()),
        );
        let kernel = Kernel::new(runtime(), registry(ExecutionClass::Critical), router);
        let invalid = InvocationRequest {
            capability_id: "capability.test".into(),
            args: json!({}),
            trace_id: None,
        };

        assert!(matches!(
            kernel.invoke(&invalid),
            Err(KernelError::SchemaValidationFailed(_))
        ));
        assert_eq!(authority_calls.load(Ordering::SeqCst), 0);
        assert_eq!(function_calls.load(Ordering::SeqCst), 0);
        assert_eq!(effect_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unadmitted_capabilities_never_reach_authority_or_a_backend() {
        let authority_calls = Arc::new(AtomicUsize::new(0));
        let function_calls = Arc::new(AtomicUsize::new(0));
        let effect_calls = Arc::new(AtomicUsize::new(0));
        let router = BackendRouter::new(
            TestAuthority {
                decision: AuthorityDecision::Allow,
                calls: authority_calls.clone(),
            },
            backend(function_calls.clone()),
            backend(effect_calls.clone()),
        );
        let mut registry = CapabilityRegistry::new();
        let mut definition = definition(ExecutionClass::Critical);
        definition.admitted = false;
        registry
            .register(definition, |_args: &Json| Ok(()))
            .expect("test capability should register");
        let kernel = Kernel::new(runtime(), registry, router);

        assert!(matches!(
            kernel.invoke(&invocation()),
            Err(KernelError::CapabilityNotAdmitted(_))
        ));
        assert_eq!(authority_calls.load(Ordering::SeqCst), 0);
        assert_eq!(function_calls.load(Ordering::SeqCst), 0);
        assert_eq!(effect_calls.load(Ordering::SeqCst), 0);
    }
}
