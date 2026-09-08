// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract-driven capability execution for the experimental hardening ABI.
//!
//! This module is deliberately small. Relay owns classification and routing;
//! Correct-Once, Effect Fabric, workers, and DLP implementations remain
//! external providers of the contracts defined by the hardening crates.

use std::collections::HashMap;

use nemo_relay_authority::unstable::{
    AuthorityDecision, AuthorityProvider, GrantVerifier, VerifiedGrant, request_from_identity,
};
use nemo_relay_executor::unstable::{
    CapabilityIdentity, ExecutionBackend, ExecutionClass, ExecutionIdentity, ExecutionRequest,
    ExecutionResult, ReconciliationProvider, ReconciliationResult, RuntimeIdentity,
};
use nemo_relay_ledger::unstable::{
    ActionPreparation, ActionStore, ExecutionState, PrepareActionResult, ReceiptRecord,
    ReceiptStore,
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
    /// The authority artifact could not be cryptographically verified.
    #[error("authority grant could not be verified: {0}")]
    GrantVerificationFailed(String),
    /// A cryptographically valid authority artifact did not bind to the action.
    #[error("authority grant does not bind to the exact execution request")]
    GrantBindingFailure,
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
    /// An action store failed while claiming or transitioning an effect.
    #[error("action store failed: {0}")]
    ActionStore(String),
    /// The action store already owns this exact logical action.
    #[error("action is already prepared: {0}")]
    ActionAlreadyPrepared(String),
    /// The idempotency key is bound to a different logical action.
    #[error("idempotency key conflicts with an existing action")]
    IdempotencyConflict,
    /// An effect backend completed without the authoritative receipt required for an effect.
    #[error("consequential execution completed without an authoritative receipt")]
    ReceiptMissing,
    /// An effect receipt did not bind to the exact action executed by the kernel.
    #[error("effect receipt does not bind to the exact execution request")]
    ReceiptBindingFailure,
    /// The external receipt store rejected a receipt.
    #[error("receipt store failed: {0}")]
    ReceiptStore(String),
    /// The requested action is not currently eligible for reconciliation.
    #[error("action is not in UNKNOWN state: {0}")]
    ActionNotUnknown(String),
    /// Reconciliation returned an invalid nonterminal effect state.
    #[error("reconciliation returned invalid state: {0:?}")]
    ReconciliationInvalidState(ExecutionState),
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
#[derive(Clone)]
pub struct BoundExecutionRequest {
    request: ExecutionRequest,
}

impl BoundExecutionRequest {
    fn backend_request(&self) -> &ExecutionRequest {
        &self.request
    }

    fn attach_grant(&mut self, grant: VerifiedGrant) {
        self.request.identity.grant_digest = Some(grant.digest.clone());
        self.request.grant = Some(grant.token);
    }

    fn attach_approval(&mut self, approval_reference: String) {
        self.request.identity.approval_reference = Some(approval_reference);
    }

    fn action_preparation(&self) -> ActionPreparation {
        let identity = &self.request.identity;
        let capability = &identity.capability;
        let fingerprint = serde_json::json!({
            "principal_id": identity.runtime.principal_id,
            "capability_id": capability.capability_id,
            "capability_generation": capability.capability_generation,
            "operation": capability.operation,
            "execution_class": capability.execution_class,
            "route_digest": capability.route_digest,
            "args_digest": identity.args_digest,
        });
        let bytes = serde_json_canonicalizer::to_vec(&fingerprint)
            .expect("kernel-owned action fingerprint must canonicalize");
        ActionPreparation {
            action_id: identity.action_id.clone(),
            idempotency_key: identity.idempotency_key.clone(),
            fingerprint: sha256_hex(&bytes),
            execution_id: identity.execution_id.clone(),
            capability_id: capability.capability_id.clone(),
            route_digest: capability.route_digest.clone(),
            args_digest: identity.args_digest.clone(),
        }
    }
}

/// Opaque continuation returned when authority approval is required.
///
/// The handle retains the exact bound action in memory. Durable Effect Fabric
/// implementations retain the corresponding `ActionPreparation` externally;
/// this kernel contract deliberately does not claim restart recovery itself.
pub struct PendingAction {
    request: BoundExecutionRequest,
}

impl PendingAction {
    /// Return the stable action identifier to present to the approval system.
    pub fn action_id(&self) -> &str {
        &self.request.request.identity.action_id
    }

    /// Return the stable idempotency identity for this logical action.
    pub fn idempotency_key(&self) -> &str {
        &self.request.request.identity.idempotency_key
    }
}

/// Authority approval supplied only when resuming an opaque pending action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalContinuation {
    /// Exact authority approval reference for the original action.
    pub approval_reference: String,
}

/// Outcome of beginning or resuming an invocation.
pub enum InvocationOutcome {
    /// The capability completed and returned a backend result.
    Completed(ExecutionResult),
    /// The exact bound action awaits external approval before it can execute.
    PendingApproval(PendingAction),
}

enum AuthorizationOutcome {
    FastPath,
    Granted(Box<VerifiedGrant>),
    PendingApproval,
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
    /// Evaluate authority for a bound invocation without selecting a backend.
    fn authorize_bound(
        &self,
        request: &BoundExecutionRequest,
    ) -> Result<AuthorizationOutcome, KernelError> {
        let request = request.backend_request();
        match request.identity.capability.execution_class {
            ExecutionClass::Pure | ExecutionClass::Read => Ok(AuthorizationOutcome::FastPath),
            ExecutionClass::Mutation | ExecutionClass::Critical => {
                let authority_request = request_from_identity(&request.identity);
                let decision = self
                    .authority
                    .decide(&authority_request)
                    .map_err(|error| KernelError::AuthorityUnavailable(error.to_string()))?;
                match decision {
                    AuthorityDecision::Allow(grant) => {
                        let grant = *grant;
                        self.authority
                            .verify_grant(&authority_request, &grant)
                            .map_err(|error| {
                                KernelError::GrantVerificationFailed(error.to_string())
                            })?;
                        if !grant.binds(&authority_request)
                            || (request.identity.capability.execution_class
                                == ExecutionClass::Critical
                                && grant.approval_reference.is_none())
                        {
                            return Err(KernelError::GrantBindingFailure);
                        }
                        Ok(AuthorizationOutcome::Granted(Box::new(grant)))
                    }
                    AuthorityDecision::Deny => Err(KernelError::AuthorityDenied),
                    AuthorityDecision::RequireApproval => Ok(AuthorizationOutcome::PendingApproval),
                    AuthorityDecision::Defer => Err(KernelError::AuthorityDeferred),
                    AuthorityDecision::Modify(_) => Err(KernelError::AuthorityModificationRequired),
                }
            }
        }
    }

    /// Execute a request only after the kernel completed binding and authority.
    fn execute_bound(
        &self,
        request: &BoundExecutionRequest,
    ) -> Result<ExecutionResult, KernelError> {
        match request
            .backend_request()
            .identity
            .capability
            .execution_class
        {
            ExecutionClass::Pure | ExecutionClass::Read => self
                .function_hooks
                .execute(request.backend_request())
                .map_err(|error| KernelError::FunctionBackend(error.to_string())),
            ExecutionClass::Mutation | ExecutionClass::Critical => self
                .effect_fabric
                .execute(request.backend_request())
                .map_err(KernelError::from),
        }
    }

    /// Ask the external effect implementation to reconcile an unknown action.
    fn reconcile(&self, action_id: &str) -> Result<ReconciliationResult, KernelError>
    where
        E: ReconciliationProvider,
    {
        self.effect_fabric
            .reconcile(action_id)
            .map_err(KernelError::from)
    }
}

/// Public capability kernel entry point.
///
/// The kernel accepts only an unbound capability invocation, resolves its
/// immutable descriptor, validates its arguments, and constructs the opaque
/// request consumed by [`BackendRouter`]. Authority and execution mechanisms
/// remain external adapters.
pub struct Kernel<A, F, E, S, R> {
    runtime: RuntimeIdentity,
    registry: CapabilityRegistry,
    router: BackendRouter<A, F, E>,
    action_store: S,
    receipt_store: R,
}

impl<A, F, E, S, R> Kernel<A, F, E, S, R> {
    /// Construct a kernel from a trusted runtime identity, immutable registry,
    /// and external adapter router.
    pub fn new(
        runtime: RuntimeIdentity,
        registry: CapabilityRegistry,
        router: BackendRouter<A, F, E>,
        action_store: S,
        receipt_store: R,
    ) -> Self {
        Self {
            runtime,
            registry,
            router,
            action_store,
            receipt_store,
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
                    // The action store claims this identity before any effect
                    // crosses the provider boundary. Effect Fabric owns its
                    // durable implementation and recovery semantics.
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

impl<A, F, E, S, R> Kernel<A, F, E, S, R>
where
    A: AuthorityProvider,
    <A as GrantVerifier>::Error: std::fmt::Display,
    F: ExecutionBackend,
    E: ExecutionBackend + ReconciliationProvider,
    S: ActionStore,
    S::Error: std::fmt::Display,
    R: ReceiptStore,
    R::Error: std::fmt::Display,
{
    /// Begin an admitted capability invocation through the secure kernel.
    ///
    /// Consequential actions are prepared in the supplied `ActionStore` before
    /// authority evaluation. An approval requirement returns an opaque handle
    /// that preserves the same action and idempotency identities for `resume`.
    pub fn begin(&self, invocation: &InvocationRequest) -> Result<InvocationOutcome, KernelError> {
        let mut request = self.bind(invocation)?;
        if matches!(
            request
                .backend_request()
                .identity
                .capability
                .execution_class,
            ExecutionClass::Mutation | ExecutionClass::Critical
        ) {
            self.prepare_action(&request)?;
        }
        self.authorize_and_execute(&mut request)
    }

    /// Resume an exact pending action with its authority-issued approval.
    ///
    /// A caller cannot replace its capability, arguments, route, runtime
    /// identity, action identity, or idempotency key. The authority must issue
    /// and verify a new grant bound to this same opaque request.
    pub fn resume(
        &self,
        mut pending: PendingAction,
        continuation: ApprovalContinuation,
    ) -> Result<InvocationOutcome, KernelError> {
        pending
            .request
            .attach_approval(continuation.approval_reference);
        self.authorize_and_execute(&mut pending.request)
    }

    /// Reconcile one external action already recorded as `UNKNOWN`.
    pub fn reconcile(&self, action_id: &str) -> Result<ReconciliationResult, KernelError> {
        let state = self
            .action_store
            .load_state(action_id)
            .map_err(|error| KernelError::ActionStore(error.to_string()))?;
        if state != Some(ExecutionState::Unknown) {
            return Err(KernelError::ActionNotUnknown(action_id.to_owned()));
        }
        self.action_store
            .transition(
                action_id,
                Some(ExecutionState::Unknown),
                ExecutionState::Reconciling,
            )
            .map_err(|error| KernelError::ActionStore(error.to_string()))?;
        let result = self.router.reconcile(action_id)?;
        if !matches!(
            result.state,
            ExecutionState::Committed | ExecutionState::Failed | ExecutionState::Unknown
        ) {
            return Err(KernelError::ReconciliationInvalidState(result.state));
        }
        self.action_store
            .transition(action_id, Some(ExecutionState::Reconciling), result.state)
            .map_err(|error| KernelError::ActionStore(error.to_string()))?;
        if let Some(receipt) = result.receipt.as_ref() {
            if receipt.action_id != action_id || receipt.final_state != result.state {
                return Err(KernelError::ReceiptBindingFailure);
            }
            self.receipt_store
                .store(receipt)
                .map_err(|error| KernelError::ReceiptStore(error.to_string()))?;
        }
        Ok(result)
    }

    fn authorize_and_execute(
        &self,
        request: &mut BoundExecutionRequest,
    ) -> Result<InvocationOutcome, KernelError> {
        match self.router.authorize_bound(request)? {
            AuthorizationOutcome::FastPath => Ok(InvocationOutcome::Completed(
                self.router.execute_bound(request)?,
            )),
            AuthorizationOutcome::Granted(grant) => {
                request.attach_grant(*grant);
                Ok(InvocationOutcome::Completed(self.execute_effect(request)?))
            }
            AuthorizationOutcome::PendingApproval => {
                Ok(InvocationOutcome::PendingApproval(PendingAction {
                    request: request.clone(),
                }))
            }
        }
    }

    fn prepare_action(&self, request: &BoundExecutionRequest) -> Result<(), KernelError> {
        match self
            .action_store
            .prepare_action(&request.action_preparation())
            .map_err(|error| KernelError::ActionStore(error.to_string()))?
        {
            PrepareActionResult::NewAction => Ok(()),
            PrepareActionResult::ExistingSameAction => Err(KernelError::ActionAlreadyPrepared(
                request.backend_request().identity.action_id.clone(),
            )),
            PrepareActionResult::IdempotencyConflict => Err(KernelError::IdempotencyConflict),
        }
    }

    fn execute_effect(
        &self,
        request: &BoundExecutionRequest,
    ) -> Result<ExecutionResult, KernelError> {
        let result = self.router.execute_bound(request)?;
        let receipt = result.receipt.as_ref().ok_or(KernelError::ReceiptMissing)?;
        self.verify_receipt(request.backend_request(), receipt, &result)?;
        self.receipt_store
            .store(receipt)
            .map_err(|error| KernelError::ReceiptStore(error.to_string()))?;
        Ok(result)
    }

    fn verify_receipt(
        &self,
        request: &ExecutionRequest,
        receipt: &ReceiptRecord,
        result: &ExecutionResult,
    ) -> Result<(), KernelError> {
        let identity = &request.identity;
        let capability = &identity.capability;
        let class = match capability.execution_class {
            ExecutionClass::Pure => "PURE",
            ExecutionClass::Read => "READ",
            ExecutionClass::Mutation => "MUTATION",
            ExecutionClass::Critical => "CRITICAL",
        };
        if receipt.action_id != identity.action_id
            || receipt.idempotency_key != identity.idempotency_key
            || identity.grant_digest.as_deref() != Some(receipt.grant_digest.as_str())
            || receipt.principal_id != identity.runtime.principal_id
            || receipt.capability_id != capability.capability_id
            || receipt.registration_digest != capability.registration_digest
            || receipt.operation != capability.operation
            || receipt.execution_class != class
            || receipt.args_digest != identity.args_digest
            || receipt.route_digest != capability.route_digest
            || receipt.final_state != ExecutionState::Committed
            || result.receipt_digest.as_deref() != Some(receipt.evidence_digest.as_str())
        {
            return Err(KernelError::ReceiptBindingFailure);
        }
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(all(test, any()))]
mod legacy_tests {
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

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay_authority::unstable::AuthorityRequest;
    use nemo_relay_executor::unstable::{EffectExecutionError, OutcomeCertainty};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone, Copy)]
    enum Decision {
        Allow,
        ApproveOnContinuation,
        MismatchedGrant,
    }

    #[derive(Clone)]
    struct TestAuthority {
        decision: Decision,
        calls: Arc<AtomicUsize>,
    }

    impl GrantVerifier for TestAuthority {
        type Error = String;

        fn verify_grant(
            &self,
            request: &AuthorityRequest,
            grant: &VerifiedGrant,
        ) -> Result<(), Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            grant
                .binds(request)
                .then_some(())
                .ok_or_else(|| "grant does not bind".into())
        }
    }

    impl AuthorityProvider for TestAuthority {
        fn decide(
            &self,
            request: &AuthorityRequest,
        ) -> Result<AuthorityDecision, <Self as GrantVerifier>::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(match self.decision {
                Decision::Allow => AuthorityDecision::Allow(Box::new(grant(request))),
                Decision::ApproveOnContinuation => {
                    if request.approval_reference.is_some() {
                        AuthorityDecision::Allow(Box::new(grant(request)))
                    } else {
                        AuthorityDecision::RequireApproval
                    }
                }
                Decision::MismatchedGrant => {
                    let mut grant = grant(request);
                    grant.route_digest = "wrong-route".into();
                    AuthorityDecision::Allow(Box::new(grant))
                }
            })
        }
    }

    fn grant(request: &AuthorityRequest) -> VerifiedGrant {
        VerifiedGrant {
            token: "correct-once-token".into(),
            digest: "grant-digest".into(),
            action_id: request.action_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            principal_id: request.principal_id.clone(),
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

    #[derive(Clone, Default)]
    struct TestActionStore {
        prepare_calls: Arc<AtomicUsize>,
        states: Arc<Mutex<HashMap<String, ExecutionState>>>,
    }

    impl ActionStore for TestActionStore {
        type Error = String;

        fn prepare_action(
            &self,
            action: &ActionPreparation,
        ) -> Result<PrepareActionResult, Self::Error> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            self.states
                .lock()
                .map_err(|_| "test action state lock poisoned".to_owned())?
                .insert(action.action_id.clone(), ExecutionState::Prepared);
            Ok(PrepareActionResult::NewAction)
        }

        fn load_state(&self, action_id: &str) -> Result<Option<ExecutionState>, Self::Error> {
            Ok(self
                .states
                .lock()
                .map_err(|_| "test action state lock poisoned".to_owned())?
                .get(action_id)
                .copied())
        }

        fn transition(
            &self,
            action_id: &str,
            expected: Option<ExecutionState>,
            next: ExecutionState,
        ) -> Result<(), Self::Error> {
            let mut states = self
                .states
                .lock()
                .map_err(|_| "test action state lock poisoned".to_owned())?;
            if states.get(action_id).copied() != expected {
                return Err("unexpected state transition".into());
            }
            states.insert(action_id.to_owned(), next);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct TestReceiptStore {
        receipts: Arc<Mutex<Vec<ReceiptRecord>>>,
    }

    impl ReceiptStore for TestReceiptStore {
        type Error = String;

        fn store(&self, receipt: &ReceiptRecord) -> Result<(), Self::Error> {
            self.receipts
                .lock()
                .map_err(|_| "test receipt lock poisoned".to_owned())?
                .push(receipt.clone());
            Ok(())
        }

        fn load(&self, action_id: &str) -> Result<Option<ReceiptRecord>, Self::Error> {
            Ok(self
                .receipts
                .lock()
                .map_err(|_| "test receipt lock poisoned".to_owned())?
                .iter()
                .find(|receipt| receipt.action_id == action_id)
                .cloned())
        }
    }

    #[derive(Clone, Default)]
    struct TestBackend {
        calls: Arc<AtomicUsize>,
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
            let consequential = matches!(
                request.identity.capability.execution_class,
                ExecutionClass::Mutation | ExecutionClass::Critical
            );
            let receipt = consequential.then(|| receipt(request));
            Ok(ExecutionResult {
                output: json!({"ok": true}),
                outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
                receipt_digest: receipt
                    .as_ref()
                    .map(|receipt| receipt.evidence_digest.clone()),
                receipt,
            })
        }
    }

    impl ReconciliationProvider for TestBackend {
        fn reconcile(&self, action_id: &str) -> Result<ReconciliationResult, EffectExecutionError> {
            Ok(ReconciliationResult {
                state: ExecutionState::Committed,
                receipt: Some(ReceiptRecord {
                    receipt_id: "reconciled-receipt".into(),
                    action_id: action_id.to_owned(),
                    idempotency_key: "reconciled-idempotency".into(),
                    grant_digest: "reconciled-grant".into(),
                    principal_id: "alice".into(),
                    capability_id: "capability.test".into(),
                    registration_digest: "registration-7".into(),
                    operation: "test".into(),
                    execution_class: "CRITICAL".into(),
                    args_digest: "args".into(),
                    route_digest: "route-7".into(),
                    provider_request_id: None,
                    final_state: ExecutionState::Committed,
                    started_at_unix_ms: 1,
                    finished_at_unix_ms: 2,
                    evidence_digest: "reconciled-evidence".into(),
                }),
            })
        }
    }

    fn receipt(request: &ExecutionRequest) -> ReceiptRecord {
        let identity = &request.identity;
        let capability = &identity.capability;
        ReceiptRecord {
            receipt_id: "receipt-1".into(),
            action_id: identity.action_id.clone(),
            idempotency_key: identity.idempotency_key.clone(),
            grant_digest: identity.grant_digest.clone().unwrap_or_default(),
            principal_id: identity.runtime.principal_id.clone(),
            capability_id: capability.capability_id.clone(),
            registration_digest: capability.registration_digest.clone(),
            operation: capability.operation.clone(),
            execution_class: match capability.execution_class {
                ExecutionClass::Pure => "PURE",
                ExecutionClass::Read => "READ",
                ExecutionClass::Mutation => "MUTATION",
                ExecutionClass::Critical => "CRITICAL",
            }
            .into(),
            args_digest: identity.args_digest.clone(),
            route_digest: capability.route_digest.clone(),
            provider_request_id: Some("provider-1".into()),
            final_state: ExecutionState::Committed,
            started_at_unix_ms: 1,
            finished_at_unix_ms: 2,
            evidence_digest: "receipt-evidence".into(),
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

    fn registry(class: ExecutionClass) -> CapabilityRegistry {
        let mut registry = CapabilityRegistry::new();
        registry
            .register(
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
                },
                |args: &Json| {
                    args.get("value")
                        .is_some()
                        .then_some(())
                        .ok_or_else(|| "value is required".to_owned())
                },
            )
            .expect("test capability should register");
        registry
    }

    fn invocation() -> InvocationRequest {
        InvocationRequest {
            capability_id: "capability.test".into(),
            args: json!({"value": 1}),
            trace_id: Some("trace-1".into()),
        }
    }

    type TestKernel =
        Kernel<TestAuthority, TestBackend, TestBackend, TestActionStore, TestReceiptStore>;
    type TestKernelParts = (
        TestKernel,
        TestAuthority,
        TestBackend,
        TestBackend,
        TestActionStore,
        TestReceiptStore,
    );

    fn kernel(class: ExecutionClass, decision: Decision) -> TestKernelParts {
        let authority = TestAuthority {
            decision,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let function = TestBackend::default();
        let effect = TestBackend::default();
        let actions = TestActionStore::default();
        let receipts = TestReceiptStore::default();
        let kernel = Kernel::new(
            runtime(),
            registry(class),
            BackendRouter::new(authority.clone(), function.clone(), effect.clone()),
            actions.clone(),
            receipts.clone(),
        );
        (kernel, authority, function, effect, actions, receipts)
    }

    #[test]
    fn fast_paths_bypass_authority_and_effect_stores() {
        let (kernel, authority, function, effect, actions, receipts) =
            kernel(ExecutionClass::Read, Decision::Allow);
        assert!(matches!(
            kernel.begin(&invocation()),
            Ok(InvocationOutcome::Completed(_))
        ));
        assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
        assert_eq!(function.calls.load(Ordering::SeqCst), 1);
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert_eq!(actions.prepare_calls.load(Ordering::SeqCst), 0);
        assert!(receipts.receipts.lock().unwrap().is_empty());
    }

    #[test]
    fn consequential_actions_prepare_verify_and_persist_bound_receipts() {
        let (kernel, authority, _function, effect, actions, receipts) =
            kernel(ExecutionClass::Mutation, Decision::Allow);
        assert!(matches!(
            kernel.begin(&invocation()),
            Ok(InvocationOutcome::Completed(_))
        ));
        assert_eq!(authority.calls.load(Ordering::SeqCst), 2);
        assert_eq!(actions.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);
        assert_eq!(receipts.receipts.lock().unwrap().len(), 1);
    }

    #[test]
    fn mismatched_grants_never_reach_effect_execution() {
        let (kernel, _authority, _function, effect, actions, receipts) =
            kernel(ExecutionClass::Mutation, Decision::MismatchedGrant);
        assert!(matches!(
            kernel.begin(&invocation()),
            Err(KernelError::GrantVerificationFailed(_))
        ));
        assert_eq!(actions.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert!(receipts.receipts.lock().unwrap().is_empty());
    }

    #[test]
    fn approval_resume_preserves_the_same_bound_action() {
        let (kernel, _authority, _function, effect, actions, receipts) =
            kernel(ExecutionClass::Critical, Decision::ApproveOnContinuation);
        let pending = match kernel
            .begin(&invocation())
            .expect("approval should be pending")
        {
            InvocationOutcome::PendingApproval(pending) => pending,
            InvocationOutcome::Completed(_) => panic!("critical action should await approval"),
        };
        let action_id = pending.action_id().to_owned();
        let idempotency_key = pending.idempotency_key().to_owned();
        assert_eq!(actions.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);

        let result = kernel.resume(
            pending,
            ApprovalContinuation {
                approval_reference: "approval-1".into(),
            },
        );
        assert!(matches!(result, Ok(InvocationOutcome::Completed(_))));
        let request = effect.requests.lock().unwrap().pop().unwrap();
        assert_eq!(request.identity.action_id, action_id);
        assert_eq!(request.identity.idempotency_key, idempotency_key);
        assert_eq!(
            request.identity.approval_reference.as_deref(),
            Some("approval-1")
        );
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);
        assert_eq!(receipts.receipts.lock().unwrap().len(), 1);
    }

    #[test]
    fn schema_failure_happens_before_action_preparation_or_authority() {
        let (kernel, authority, function, effect, actions, _receipts) =
            kernel(ExecutionClass::Critical, Decision::Allow);
        let invalid = InvocationRequest {
            capability_id: "capability.test".into(),
            args: json!({}),
            trace_id: None,
        };
        assert!(matches!(
            kernel.begin(&invalid),
            Err(KernelError::SchemaValidationFailed(_))
        ));
        assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
        assert_eq!(function.calls.load(Ordering::SeqCst), 0);
        assert_eq!(effect.calls.load(Ordering::SeqCst), 0);
        assert_eq!(actions.prepare_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unknown_actions_reconcile_through_external_effect_fabric() {
        let (kernel, _authority, _function, _effect, actions, receipts) =
            kernel(ExecutionClass::Critical, Decision::Allow);
        actions
            .states
            .lock()
            .unwrap()
            .insert("unknown-action".into(), ExecutionState::Unknown);
        let result = kernel
            .reconcile("unknown-action")
            .expect("unknown action should reconcile");
        assert_eq!(result.state, ExecutionState::Committed);
        assert_eq!(
            actions.load_state("unknown-action").unwrap(),
            Some(ExecutionState::Committed)
        );
        assert_eq!(receipts.receipts.lock().unwrap().len(), 1);
    }
}
