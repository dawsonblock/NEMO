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
    ReceiptStore, is_valid_transition,
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
    /// A consequential effect may have crossed the external boundary.
    #[error("effect outcome is unknown and requires reconciliation: {0}")]
    EffectUnknown(String),
    /// Durable state could not be advanced after evidence was persisted.
    #[error("durable effect state requires recovery: {0}")]
    StateRecoveryRequired(String),
    /// The kernel attempted to skip a lifecycle boundary.
    #[error("invalid effect state transition: {expected:?} -> {next:?}")]
    InvalidStateTransition {
        /// State the kernel expected to be current.
        expected: ExecutionState,
        /// State the kernel attempted to write.
        next: ExecutionState,
    },
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
    /// Optional caller retry identity. It is only an idempotency key; all
    /// security-sensitive fields remain kernel-derived.
    pub request_id: Option<String>,
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
            "tenant_id": identity.runtime.tenant_id,
            "principal_id": identity.runtime.principal_id,
            "runtime_id": identity.runtime.runtime_id,
            "capability_id": capability.capability_id,
            "capability_generation": capability.capability_generation,
            "registration_digest": capability.registration_digest,
            "operation": capability.operation,
            "execution_class": capability.execution_class,
            "route_digest": capability.route_digest,
            "args_digest": identity.args_digest,
            "admission_id": identity.admission_id,
            "policy_version": identity.policy_version,
            "policy_epoch": identity.policy_epoch,
        });
        let bytes = serde_json_canonicalizer::to_vec(&fingerprint)
            .expect("kernel-owned action fingerprint must canonicalize");
        ActionPreparation {
            action_id: identity.action_id.clone(),
            idempotency_key: identity.idempotency_key.clone(),
            fingerprint: sha256_hex(&bytes),
            execution_id: identity.execution_id.clone(),
            tenant_id: identity.runtime.tenant_id.clone(),
            principal_id: identity.runtime.principal_id.clone(),
            runtime_id: identity.runtime.runtime_id.clone(),
            capability_id: capability.capability_id.clone(),
            capability_generation: capability.capability_generation,
            registration_digest: capability.registration_digest.clone(),
            execution_class: execution_class_name(capability.execution_class).into(),
            operation: capability.operation.clone(),
            route_digest: capability.route_digest.clone(),
            args_digest: identity.args_digest.clone(),
            admission_id: identity.admission_id.clone(),
            policy_version: identity.policy_version.clone(),
            policy_epoch: identity.policy_epoch.clone(),
            grant_digest: identity.grant_digest.clone(),
            approval_reference: identity.approval_reference.clone(),
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

    fn execute_effect_bound(
        &self,
        request: &BoundExecutionRequest,
    ) -> Result<ExecutionResult, nemo_relay_executor::unstable::EffectExecutionError> {
        self.effect_fabric.execute(request.backend_request())
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
        let idempotency_key = invocation
            .request_id
            .clone()
            .unwrap_or_else(|| action_id.clone());
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
                    idempotency_key,
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
    /// Consequential actions are claimed in `PROPOSED` state before authority
    /// evaluation. `PREPARED` is written only after an exact grant exists.
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
            self.claim_action(&request)?;
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
        let action = self
            .action_store
            .load_action(action_id)
            .map_err(|error| KernelError::ActionStore(error.to_string()))?;
        if action.as_ref().map(|record| record.state) != Some(ExecutionState::Unknown) {
            return Err(KernelError::ActionNotUnknown(action_id.to_owned()));
        }
        self.action_store
            .transition(
                action_id,
                Some(ExecutionState::Unknown),
                ExecutionState::Reconciling,
            )
            .map_err(|error| KernelError::ActionStore(error.to_string()))?;
        let result = match self.router.reconcile(action_id) {
            Ok(result) => result,
            Err(error) => {
                let _ = self.action_store.transition(
                    action_id,
                    Some(ExecutionState::Reconciling),
                    ExecutionState::Unknown,
                );
                return Err(KernelError::EffectUnknown(error.to_string()));
            }
        };
        if !matches!(
            result.state,
            ExecutionState::Committed | ExecutionState::Failed | ExecutionState::Unknown
        ) {
            return Err(KernelError::ReconciliationInvalidState(result.state));
        }
        if let Some(receipt) = result.receipt.as_ref() {
            let action = action.as_ref().expect("UNKNOWN action was loaded");
            if receipt.action_id != action_id
                || receipt.final_state != result.state
                || !self.receipt_matches_action(receipt, &action.preparation)
            {
                let _ = self.action_store.transition(
                    action_id,
                    Some(ExecutionState::Reconciling),
                    ExecutionState::Unknown,
                );
                return Err(KernelError::ReceiptBindingFailure);
            }
            if let Err(error) = self.receipt_store.store(receipt) {
                let _ = self.action_store.transition(
                    action_id,
                    Some(ExecutionState::Reconciling),
                    ExecutionState::Unknown,
                );
                return Err(KernelError::ReceiptStore(error.to_string()));
            }
        }
        self.action_store
            .transition(action_id, Some(ExecutionState::Reconciling), result.state)
            .map_err(|error| KernelError::ActionStore(error.to_string()))?;
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
                let identity = &request.backend_request().identity;
                self.action_store
                    .bind_authorization(
                        &identity.action_id,
                        identity.grant_digest.as_deref().unwrap_or_default(),
                        identity.approval_reference.as_deref(),
                    )
                    .map_err(|error| KernelError::ActionStore(error.to_string()))?;
                self.transition(
                    request,
                    ExecutionState::Proposed,
                    ExecutionState::Authorized,
                )?;
                self.transition(
                    request,
                    ExecutionState::Authorized,
                    ExecutionState::Prepared,
                )?;
                self.transition(
                    request,
                    ExecutionState::Prepared,
                    ExecutionState::Dispatching,
                )?;
                Ok(InvocationOutcome::Completed(self.execute_effect(request)?))
            }
            AuthorizationOutcome::PendingApproval => {
                Ok(InvocationOutcome::PendingApproval(PendingAction {
                    request: request.clone(),
                }))
            }
        }
    }

    fn claim_action(&self, request: &BoundExecutionRequest) -> Result<(), KernelError> {
        match self
            .action_store
            .claim_action(&request.action_preparation())
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
        let result = match self.router.execute_effect_bound(request) {
            Ok(result) => result,
            Err(error) => {
                let state = nemo_relay_executor::unstable::state_for_error(&error);
                self.transition_from_dispatching(request, state)?;
                if state == ExecutionState::Unknown {
                    return Err(KernelError::EffectUnknown(error.to_string()));
                }
                return Err(KernelError::EffectBackend(error));
            }
        };
        let receipt = match result.receipt.as_ref() {
            Some(receipt) => receipt,
            None => {
                self.transition_from_dispatching(request, ExecutionState::Unknown)?;
                return Err(KernelError::ReceiptMissing);
            }
        };
        if self
            .verify_receipt(request.backend_request(), receipt, &result)
            .is_err()
        {
            self.transition_from_dispatching(request, ExecutionState::Unknown)?;
            return Err(KernelError::ReceiptBindingFailure);
        }
        if let Err(error) = self.receipt_store.store(receipt) {
            self.transition_from_dispatching(request, ExecutionState::Unknown)?;
            return Err(KernelError::ReceiptStore(error.to_string()));
        }
        self.transition_from_dispatching(request, ExecutionState::Committed)
            .map_err(|error| KernelError::StateRecoveryRequired(error.to_string()))?;
        Ok(result)
    }

    fn transition(
        &self,
        request: &BoundExecutionRequest,
        expected: ExecutionState,
        next: ExecutionState,
    ) -> Result<(), KernelError> {
        if !is_valid_transition(Some(expected), next) {
            return Err(KernelError::InvalidStateTransition { expected, next });
        }
        self.action_store
            .transition(
                &request.backend_request().identity.action_id,
                Some(expected),
                next,
            )
            .map_err(|error| KernelError::ActionStore(error.to_string()))
    }

    fn transition_from_dispatching(
        &self,
        request: &BoundExecutionRequest,
        next: ExecutionState,
    ) -> Result<(), KernelError> {
        self.transition(request, ExecutionState::Dispatching, next)
    }

    fn receipt_matches_action(&self, receipt: &ReceiptRecord, action: &ActionPreparation) -> bool {
        receipt.action_id == action.action_id
            && receipt.idempotency_key == action.idempotency_key
            && receipt.capability_id == action.capability_id
            && receipt.capability_generation == action.capability_generation
            && receipt.registration_digest == action.registration_digest
            && receipt.operation == action.operation
            && receipt.execution_class == action.execution_class
            && receipt.args_digest == action.args_digest
            && receipt.route_digest == action.route_digest
            && receipt.tenant_id == action.tenant_id
            && receipt.runtime_id == action.runtime_id
            && receipt.admission_id == action.admission_id
            && receipt.policy_version == action.policy_version
            && receipt.policy_epoch == action.policy_epoch
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
            || receipt.tenant_id != identity.runtime.tenant_id
            || receipt.runtime_id != identity.runtime.runtime_id
            || receipt.capability_id != capability.capability_id
            || receipt.capability_generation != capability.capability_generation
            || receipt.registration_digest != capability.registration_digest
            || receipt.operation != capability.operation
            || receipt.execution_class != class
            || receipt.args_digest != identity.args_digest
            || receipt.route_digest != capability.route_digest
            || receipt.admission_id != identity.admission_id
            || receipt.policy_version != identity.policy_version
            || receipt.policy_epoch != identity.policy_epoch
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

fn execution_class_name(class: ExecutionClass) -> &'static str {
    match class {
        ExecutionClass::Pure => "PURE",
        ExecutionClass::Read => "READ",
        ExecutionClass::Mutation => "MUTATION",
        ExecutionClass::Critical => "CRITICAL",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay_authority::unstable::AuthorityRequest;
    use nemo_relay_executor::unstable::{EffectExecutionError, OutcomeCertainty};
    use nemo_relay_ledger::unstable::ActionRecord;
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
            tenant_id: request.tenant_id.clone(),
            principal_id: request.principal_id.clone(),
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

    #[derive(Clone, Default)]
    struct TestActionStore {
        prepare_calls: Arc<AtomicUsize>,
        states: Arc<Mutex<HashMap<String, ExecutionState>>>,
        records: Arc<Mutex<HashMap<String, ActionRecord>>>,
    }

    impl ActionStore for TestActionStore {
        type Error = String;

        fn claim_action(
            &self,
            action: &ActionPreparation,
        ) -> Result<PrepareActionResult, Self::Error> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            let mut records = self
                .records
                .lock()
                .map_err(|_| "test action record lock poisoned".to_owned())?;
            if let Some(existing) = records
                .values()
                .find(|record| record.preparation.idempotency_key == action.idempotency_key)
            {
                return Ok(if existing.preparation.fingerprint == action.fingerprint {
                    PrepareActionResult::ExistingSameAction
                } else {
                    PrepareActionResult::IdempotencyConflict
                });
            }
            records.insert(
                action.action_id.clone(),
                ActionRecord {
                    preparation: action.clone(),
                    state: ExecutionState::Proposed,
                },
            );
            self.states
                .lock()
                .map_err(|_| "test action state lock poisoned".to_owned())?
                .insert(action.action_id.clone(), ExecutionState::Proposed);
            Ok(PrepareActionResult::NewAction)
        }

        fn load_action(&self, action_id: &str) -> Result<Option<ActionRecord>, Self::Error> {
            Ok(self
                .records
                .lock()
                .map_err(|_| "test action record lock poisoned".to_owned())?
                .get(action_id)
                .cloned()
                .or_else(|| {
                    self.states
                        .lock()
                        .ok()?
                        .get(action_id)
                        .copied()
                        .map(|state| ActionRecord {
                            preparation: ActionPreparation {
                                action_id: action_id.to_owned(),
                                idempotency_key: "reconciled-idempotency".into(),
                                fingerprint: "reconciled-fingerprint".into(),
                                execution_id: "reconciled-execution".into(),
                                tenant_id: Some("tenant".into()),
                                principal_id: "alice".into(),
                                runtime_id: "runtime-1".into(),
                                capability_id: "capability.test".into(),
                                capability_generation: 7,
                                registration_digest: "registration-7".into(),
                                execution_class: "CRITICAL".into(),
                                operation: "test".into(),
                                route_digest: "route-7".into(),
                                args_digest: "args".into(),
                                admission_id: "admission-7".into(),
                                policy_version: "policy-7".into(),
                                policy_epoch: "epoch-7".into(),
                                grant_digest: Some("reconciled-grant".into()),
                                approval_reference: None,
                            },
                            state,
                        })
                }))
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
            if let Ok(mut records) = self.records.lock() {
                if let Some(record) = records.get_mut(action_id) {
                    record.state = next;
                }
            }
            Ok(())
        }

        fn bind_authorization(
            &self,
            action_id: &str,
            grant_digest: &str,
            approval_reference: Option<&str>,
        ) -> Result<(), Self::Error> {
            let mut records = self
                .records
                .lock()
                .map_err(|_| "test action record lock poisoned".to_owned())?;
            if let Some(record) = records.get_mut(action_id) {
                record.preparation.grant_digest = Some(grant_digest.to_owned());
                record.preparation.approval_reference = approval_reference.map(ToOwned::to_owned);
            }
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
        effect_error: Arc<Mutex<Option<EffectExecutionError>>>,
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
            if consequential {
                if let Some(error) = self
                    .effect_error
                    .lock()
                    .expect("test effect error lock should not be poisoned")
                    .clone()
                {
                    return Err(error);
                }
            }
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
            if let Some(request) = self
                .requests
                .lock()
                .expect("test request lock should not be poisoned")
                .iter()
                .find(|request| request.identity.action_id == action_id)
                .cloned()
            {
                return Ok(ReconciliationResult {
                    state: ExecutionState::Committed,
                    receipt: Some(receipt(&request)),
                });
            }
            Ok(ReconciliationResult {
                state: ExecutionState::Committed,
                receipt: Some(ReceiptRecord {
                    receipt_id: "reconciled-receipt".into(),
                    action_id: action_id.to_owned(),
                    idempotency_key: "reconciled-idempotency".into(),
                    grant_digest: "reconciled-grant".into(),
                    principal_id: "alice".into(),
                    tenant_id: Some("tenant".into()),
                    runtime_id: "runtime-1".into(),
                    capability_id: "capability.test".into(),
                    capability_generation: 7,
                    registration_digest: "registration-7".into(),
                    operation: "test".into(),
                    execution_class: "CRITICAL".into(),
                    args_digest: "args".into(),
                    route_digest: "route-7".into(),
                    admission_id: "admission-7".into(),
                    policy_version: "policy-7".into(),
                    policy_epoch: "epoch-7".into(),
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
            tenant_id: identity.runtime.tenant_id.clone(),
            runtime_id: identity.runtime.runtime_id.clone(),
            capability_id: capability.capability_id.clone(),
            capability_generation: capability.capability_generation,
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
            admission_id: identity.admission_id.clone(),
            policy_version: identity.policy_version.clone(),
            policy_epoch: identity.policy_epoch.clone(),
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
            request_id: None,
        }
    }

    fn invocation_with_request_id(request_id: &str) -> InvocationRequest {
        InvocationRequest {
            request_id: Some(request_id.into()),
            ..invocation()
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
        let state = actions.states.lock().unwrap().values().copied().next();
        assert_eq!(state, Some(ExecutionState::Committed));
    }

    #[test]
    fn stable_request_id_prevents_duplicate_dispatch_after_kernel_restart() {
        let (kernel, _authority, _function, effect, actions, receipts) =
            kernel(ExecutionClass::Mutation, Decision::Allow);
        let request = invocation_with_request_id("stable-request-1");
        assert!(matches!(
            kernel.begin(&request),
            Ok(InvocationOutcome::Completed(_))
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);

        let authority = TestAuthority {
            decision: Decision::Allow,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let second_effect = TestBackend::default();
        let restarted = Kernel::new(
            runtime(),
            registry(ExecutionClass::Mutation),
            BackendRouter::new(authority, TestBackend::default(), second_effect.clone()),
            actions.clone(),
            receipts,
        );
        assert!(matches!(
            restarted.begin(&request),
            Err(KernelError::ActionAlreadyPrepared(_))
        ));
        assert_eq!(second_effect.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn stable_request_id_rejects_a_different_effect_fingerprint() {
        let (kernel, _authority, _function, effect, _actions, _receipts) =
            kernel(ExecutionClass::Mutation, Decision::Allow);
        let first = invocation_with_request_id("stable-request-2");
        assert!(matches!(
            kernel.begin(&first),
            Ok(InvocationOutcome::Completed(_))
        ));
        let conflicting = InvocationRequest {
            args: json!({"value": 2}),
            ..invocation_with_request_id("stable-request-2")
        };
        assert!(matches!(
            kernel.begin(&conflicting),
            Err(KernelError::IdempotencyConflict)
        ));
        assert_eq!(effect.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ambiguous_dispatch_is_persisted_as_unknown_then_reconciled() {
        let (kernel, _authority, _function, effect, actions, receipts) =
            kernel(ExecutionClass::Mutation, Decision::Allow);
        *effect.effect_error.lock().unwrap() = Some(EffectExecutionError {
            code: "TRANSPORT_LOST_AFTER_DISPATCH".into(),
            dispatch_state: nemo_relay_executor::unstable::DispatchState::DispatchConfirmed,
            outcome_certainty: OutcomeCertainty::Unknown,
            provider_request_id: Some("provider-unknown-1".into()),
            retryable: false,
            reconciliation_required: true,
            message: "provider response was lost".into(),
        });
        assert!(matches!(
            kernel.begin(&invocation()),
            Err(KernelError::EffectUnknown(_))
        ));
        let action_id = actions
            .records
            .lock()
            .unwrap()
            .keys()
            .next()
            .cloned()
            .expect("ambiguous action must be durable");
        assert_eq!(
            actions.load_state(&action_id).unwrap(),
            Some(ExecutionState::Unknown)
        );

        let result = kernel
            .reconcile(&action_id)
            .expect("reconciliation should consume exact stored action identity");
        assert_eq!(result.state, ExecutionState::Committed);
        assert_eq!(
            actions.load_state(&action_id).unwrap(),
            Some(ExecutionState::Committed)
        );
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
            request_id: None,
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
