// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backend-independent tests for the experimental Effect Fabric store contract.
//!
//! A durable adapter implements [`StoreConformanceHarness`] in its own test
//! crate and invokes these runners. The harness owns test-clock advancement so
//! callers never supply authoritative lease timestamps to a store operation.

use crate::unstable::*;

/// Factory and deterministic-clock adapter for store conformance tests.
pub trait StoreConformanceHarness: Sized {
    /// Action-state implementation under test.
    type Actions: ActionStore;
    /// Immutable receipt implementation under test.
    type Receipts: ReceiptStore;

    /// Construct an isolated store pair with a deterministic store clock.
    fn new_harness() -> Self;
    /// Return the action store under test.
    fn actions(&self) -> &Self::Actions;
    /// Return the receipt store under test.
    fn receipts(&self) -> &Self::Receipts;
    /// Advance the store-owned test clock.
    fn advance_store_clock(&self, duration_ms: u64);
}

/// Factory for backend-independent transactional EffectStore conformance.
///
/// The action store returned here must be the same durable action history that
/// the effect store finalizes. A production adapter uses this runner to prove
/// that receipt insertion and terminal action mutation have one observable
/// contract rather than two independently composed writes.
pub trait EffectStoreConformanceHarness: Sized {
    /// Transaction-shaped store under test.
    type Effects: EffectStore;
    /// Action store sharing the effect store's durable action history.
    type Actions: ActionStore;

    /// Construct an isolated transactional store fixture.
    fn new_harness() -> Self;
    /// Return the transactional evidence store.
    fn effects(&self) -> &Self::Effects;
    /// Return the paired action store for lifecycle setup and inspection.
    fn actions(&self) -> &Self::Actions;
}

/// Return a claimed-but-not-authorized action fixture.
pub fn fixture_action() -> ActionPreparation {
    ActionPreparation {
        action_id: "conformance-action".into(),
        idempotency_key: "conformance-idempotency".into(),
        fingerprint: "conformance-fingerprint".into(),
        execution_id: "conformance-execution".into(),
        tenant_id: Some("tenant".into()),
        principal_id: "alice".into(),
        runtime_id: "runtime".into(),
        runtime_binding_digest: "runtime-binding".into(),
        capability_id: "capability".into(),
        capability_generation: 1,
        registration_digest: "registration".into(),
        execution_class: "MUTATION".into(),
        operation: "operation".into(),
        route_digest: "route".into(),
        args_digest: "args".into(),
        admission_id: "admission".into(),
        policy_version: "policy".into(),
        policy_epoch: "epoch".into(),
        grant_digest: None,
        approval_reference: None,
    }
}

/// Return terminal receipt evidence bound to an authorized fixture action.
pub fn fixture_receipt(
    action: &ActionPreparation,
    final_state: ExecutionState,
    evidence_digest: &str,
) -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: "conformance-receipt".into(),
        action_id: action.action_id.clone(),
        idempotency_key: action.idempotency_key.clone(),
        grant_digest: action
            .grant_digest
            .clone()
            .expect("conformance receipts require an authorized action"),
        principal_id: action.principal_id.clone(),
        tenant_id: action.tenant_id.clone(),
        runtime_id: action.runtime_id.clone(),
        runtime_binding_digest: action.runtime_binding_digest.clone(),
        capability_id: action.capability_id.clone(),
        capability_generation: action.capability_generation,
        registration_digest: action.registration_digest.clone(),
        operation: action.operation.clone(),
        execution_class: action.execution_class.clone(),
        args_digest: action.args_digest.clone(),
        route_digest: action.route_digest.clone(),
        admission_id: action.admission_id.clone(),
        policy_version: action.policy_version.clone(),
        policy_epoch: action.policy_epoch.clone(),
        provider_request_id: Some("provider-request".into()),
        final_state,
        started_at_unix_ms: 1,
        finished_at_unix_ms: 2,
        evidence_digest: evidence_digest.into(),
    }
}

fn authorize_and_prepare<H>(harness: &H) -> ActionRecord
where
    H: StoreConformanceHarness,
    H::Actions: ActionStore,
    <H::Actions as ActionStore>::Error: std::fmt::Debug,
{
    let action = fixture_action();
    assert!(matches!(
        harness
            .actions()
            .claim_action(&action)
            .expect("claim action"),
        PrepareActionResult::NewAction
    ));
    assert!(
        harness
            .actions()
            .authorize_action(
                &action.action_id,
                ExecutionState::Proposed,
                "grant",
                Some("approval"),
            )
            .is_ok()
    );
    assert!(
        harness
            .actions()
            .transition(
                &action.action_id,
                Some(ExecutionState::Authorized),
                ExecutionState::Prepared,
            )
            .is_ok()
    );
    harness
        .actions()
        .load_action(&action.action_id)
        .expect("load prepared action")
        .expect("prepared action exists")
}

fn dispatch_lease<H>(harness: &H, action: &ActionRecord) -> ActionLease
where
    H: StoreConformanceHarness,
    H::Actions: ActionStore,
    <H::Actions as ActionStore>::Error: std::fmt::Debug,
{
    let lease = match harness
        .actions()
        .claim_lease(
            &action.preparation.action_id,
            ExecutionState::Prepared,
            "conformance-owner",
            Some(10),
        )
        .expect("claim lease")
    {
        LeaseAcquireResult::Acquired(lease) => lease,
        result => panic!("expected acquired lease, got {result:?}"),
    };
    harness
        .actions()
        .transition_with_lease(
            &action.preparation.action_id,
            ExecutionState::Prepared,
            &lease,
            ExecutionState::Dispatching,
        )
        .expect("dispatch under lease");
    lease
}

/// Run action-state, lease, authorization, and evidence conformance checks.
pub fn run_action_store_conformance<H>()
where
    H: StoreConformanceHarness,
    H::Actions: ActionStore,
    <H::Actions as ActionStore>::Error: std::fmt::Debug,
{
    run_claim_input_conformance::<H>();
    run_authorization_bypass_conformance::<H>();
    run_leased_evidence_conformance::<H>();
    run_action_binding_mutation_conformance::<H>();
}

fn run_claim_input_conformance<H>()
where
    H: StoreConformanceHarness,
    H::Actions: ActionStore,
    <H::Actions as ActionStore>::Error: std::fmt::Debug,
{
    let action = fixture_action();
    assert_eq!(
        ActionEvidenceBinding::try_from(&action),
        Err(EvidenceBindingError::MissingGrantDigest)
    );
    let mut empty_grant = action.clone();
    empty_grant.grant_digest = Some(" \t".into());
    assert_eq!(
        ActionEvidenceBinding::try_from(&empty_grant),
        Err(EvidenceBindingError::EmptyGrantDigest)
    );

    let invalid_claim = H::new_harness();
    let mut preauthorized = fixture_action();
    preauthorized.grant_digest = Some("smuggled-grant".into());
    assert!(
        invalid_claim
            .actions()
            .claim_action(&preauthorized)
            .is_err(),
        "claims must begin without authorization evidence"
    );
    preauthorized.grant_digest = None;
    preauthorized.approval_reference = Some("smuggled-approval".into());
    assert!(
        invalid_claim
            .actions()
            .claim_action(&preauthorized)
            .is_err(),
        "claims must begin without approval evidence"
    );

    let action_id_conflict = H::new_harness();
    let action = fixture_action();
    assert!(matches!(
        action_id_conflict
            .actions()
            .claim_action(&action)
            .expect("claim original action"),
        PrepareActionResult::NewAction
    ));
    let mut conflicting_action_id = action.clone();
    conflicting_action_id.idempotency_key = "different-idempotency".into();
    conflicting_action_id.fingerprint = "different-fingerprint".into();
    assert!(matches!(
        action_id_conflict
            .actions()
            .claim_action(&conflicting_action_id)
            .expect("detect action id collision"),
        PrepareActionResult::ActionIdConflict(existing)
            if existing.preparation == action
    ));
    assert_eq!(
        action_id_conflict
            .actions()
            .load_action(&action.action_id)
            .expect("load original action"),
        Some(ActionRecord {
            preparation: action.clone(),
            state: ExecutionState::Proposed,
            lease: None,
            lease_generation: 0,
            terminal_evidence: None,
        }),
        "an action-id collision must never overwrite durable identity"
    );
}

fn run_authorization_bypass_conformance<H>()
where
    H: StoreConformanceHarness,
    H::Actions: ActionStore,
    <H::Actions as ActionStore>::Error: std::fmt::Debug,
{
    let action = fixture_action();
    let harness = H::new_harness();
    harness
        .actions()
        .claim_action(&action)
        .expect("claim action");
    assert!(
        harness
            .actions()
            .transition(
                &action.action_id,
                Some(ExecutionState::Proposed),
                ExecutionState::Authorized,
            )
            .is_err()
    );
    assert!(
        harness
            .actions()
            .authorize_action(&action.action_id, ExecutionState::Proposed, " ", None)
            .is_err()
    );
    assert_eq!(
        harness
            .actions()
            .load_action(&action.action_id)
            .expect("load proposed action")
            .expect("action exists")
            .state,
        ExecutionState::Proposed
    );

    let harness = H::new_harness();
    let action = authorize_and_prepare(&harness);
    assert!(
        harness
            .actions()
            .transition(
                &action.preparation.action_id,
                Some(ExecutionState::Prepared),
                ExecutionState::Dispatching,
            )
            .is_err()
    );
    let lease = dispatch_lease(&harness, &action);
    assert!(matches!(
        harness
            .actions()
            .claim_lease(
                &action.preparation.action_id,
                ExecutionState::Dispatching,
                "second-owner",
                Some(10),
            )
            .expect("observe live lease"),
        LeaseAcquireResult::HeldByOther(_)
    ));

    let receipt = fixture_receipt(
        &harness
            .actions()
            .load_action(&action.preparation.action_id)
            .expect("load dispatching action")
            .expect("dispatching action exists")
            .preparation,
        ExecutionState::Committed,
        "evidence",
    );
    let evidence = TerminalEvidence::Receipt(receipt.identity());
    harness
        .actions()
        .finalize_from_evidence(
            &action.preparation.action_id,
            ExecutionState::Dispatching,
            &lease,
            &evidence,
        )
        .expect("finalize bound receipt evidence");
    let terminal = harness
        .actions()
        .load_action(&action.preparation.action_id)
        .expect("load terminal action")
        .expect("terminal action exists");
    assert_eq!(terminal.state, ExecutionState::Committed);
    assert_eq!(terminal.terminal_evidence, Some(evidence));
}

fn run_leased_evidence_conformance<H>()
where
    H: StoreConformanceHarness,
    H::Actions: ActionStore,
    <H::Actions as ActionStore>::Error: std::fmt::Debug,
{
    let harness = H::new_harness();
    let action = authorize_and_prepare(&harness);
    let lease = dispatch_lease(&harness, &action);
    let invalid_failure = TerminalEvidence::PreDispatchFailure(PreDispatchFailureEvidence {
        action_binding: ActionEvidenceBinding::try_from(&action.preparation)
            .expect("authorized action has evidence binding"),
        code: " ".into(),
        evidence_digest: " ".into(),
    });
    assert!(
        harness
            .actions()
            .finalize_from_evidence(
                &action.preparation.action_id,
                ExecutionState::Dispatching,
                &lease,
                &invalid_failure,
            )
            .is_err(),
        "empty pre-dispatch proof must not terminalize an action"
    );
}

fn run_action_binding_mutation_conformance<H>()
where
    H: StoreConformanceHarness,
    H::Actions: ActionStore,
    <H::Actions as ActionStore>::Error: std::fmt::Debug,
{
    let harness = H::new_harness();
    let action = authorize_and_prepare(&harness);
    let lease = dispatch_lease(&harness, &action);
    let prepared = harness
        .actions()
        .load_action(&action.preparation.action_id)
        .expect("load dispatching action")
        .expect("dispatching action exists");
    for field in ActionBindingField::ALL {
        let mut receipt = fixture_receipt(
            &prepared.preparation,
            ExecutionState::Committed,
            "mutation-matrix",
        );
        field.mutate(&mut receipt);
        assert!(
            harness
                .actions()
                .finalize_from_evidence(
                    &prepared.preparation.action_id,
                    ExecutionState::Dispatching,
                    &lease,
                    &TerminalEvidence::Receipt(receipt.identity()),
                )
                .is_err(),
            "mutating {} must reject terminal evidence",
            field.name()
        );
        let current = harness
            .actions()
            .load_action(&prepared.preparation.action_id)
            .expect("load unchanged action")
            .expect("action exists");
        assert_eq!(current.state, ExecutionState::Dispatching);
        assert!(current.terminal_evidence.is_none());
    }

    harness.advance_store_clock(10);
    assert!(matches!(
        harness
            .actions()
            .claim_lease(
                &prepared.preparation.action_id,
                ExecutionState::Dispatching,
                "recovery-owner",
                Some(10),
            )
            .expect("reclaim expired lease"),
        LeaseAcquireResult::ExpiredReclaimed(_)
    ));
}

/// Run immutable receipt identity and conflict-history conformance checks.
pub fn run_receipt_store_conformance<H>()
where
    H: StoreConformanceHarness,
    H::Receipts: ReceiptStore,
    <H::Receipts as ReceiptStore>::Error: std::fmt::Debug,
{
    let harness = H::new_harness();
    let mut action = fixture_action();
    action.grant_digest = Some("grant".into());
    let committed = fixture_receipt(&action, ExecutionState::Committed, "evidence-a");

    let mut non_terminal = committed.clone();
    non_terminal.final_state = ExecutionState::Unknown;
    assert!(
        harness.receipts().finalize(&non_terminal).is_err(),
        "non-terminal evidence must not occupy the immutable receipt slot"
    );
    let mut empty_evidence = committed.clone();
    empty_evidence.evidence_digest = " \t".into();
    assert!(
        harness.receipts().finalize(&empty_evidence).is_err(),
        "empty evidence digest must not become immutable proof"
    );
    let mut empty_identity = committed.clone();
    empty_identity.grant_digest = "".into();
    assert!(
        harness.receipts().finalize(&empty_identity).is_err(),
        "structurally incomplete receipt identity must be rejected"
    );
    assert!(matches!(
        harness
            .receipts()
            .finalize(&committed)
            .expect("finalize receipt"),
        FinalizeResult::Finalized(_)
    ));
    let mut replay = committed.clone();
    replay.receipt_id = "different-local-receipt".into();
    replay.started_at_unix_ms = 99;
    replay.finished_at_unix_ms = 100;
    assert!(matches!(
        harness
            .receipts()
            .finalize(&replay)
            .expect("replay receipt"),
        FinalizeResult::AlreadyFinalized(_)
    ));
    for mutation in ReceiptIdentityMutation::ALL {
        let mut conflicting = committed.clone();
        mutation.mutate(&mut conflicting);
        assert!(matches!(
            harness
                .receipts()
                .finalize(&conflicting)
                .expect("record conflicting receipt"),
            FinalizeResult::FinalizationConflict(_) | FinalizeResult::ConflictAlreadyRecorded(_)
        ));
    }
    assert_eq!(
        harness
            .receipts()
            .load(&committed.action_id)
            .expect("load original receipt"),
        Some(committed)
    );
    assert_eq!(
        harness
            .receipts()
            .load_conflicts("conformance-action")
            .expect("load durable conflicts")
            .len(),
        ReceiptIdentityMutation::ALL.len()
    );
}

/// Run transactional receipt/action finalization conformance checks.
pub fn run_effect_store_conformance<H>()
where
    H: EffectStoreConformanceHarness,
    H::Effects: EffectStore,
    H::Actions: ActionStore,
    <H::Effects as EffectStore>::Error: std::fmt::Debug,
    <H::Actions as ActionStore>::Error: std::fmt::Debug,
{
    let harness = H::new_harness();
    let action = fixture_action();
    assert!(matches!(
        harness
            .actions()
            .claim_action(&action)
            .expect("claim effect action"),
        PrepareActionResult::NewAction
    ));
    harness
        .actions()
        .authorize_action(&action.action_id, ExecutionState::Proposed, "grant", None)
        .expect("authorize effect action");
    harness
        .actions()
        .transition(
            &action.action_id,
            Some(ExecutionState::Authorized),
            ExecutionState::Prepared,
        )
        .expect("prepare effect action");
    let lease = match harness
        .actions()
        .claim_lease(
            &action.action_id,
            ExecutionState::Prepared,
            "effect-store-conformance",
            Some(10),
        )
        .expect("claim dispatch lease")
    {
        LeaseAcquireResult::Acquired(lease) => lease,
        other => panic!("expected dispatch lease, got {other:?}"),
    };
    harness
        .actions()
        .transition_with_lease(
            &action.action_id,
            ExecutionState::Prepared,
            &lease,
            ExecutionState::Dispatching,
        )
        .expect("enter dispatching");
    let prepared = harness
        .actions()
        .load_action(&action.action_id)
        .expect("load dispatching action")
        .expect("action exists");
    let receipt = fixture_receipt(
        &prepared.preparation,
        ExecutionState::Committed,
        "effect-store-evidence",
    );
    assert!(matches!(
        harness
            .effects()
            .finalize_terminal_receipt(
                &action.action_id,
                ExecutionState::Dispatching,
                &lease,
                &receipt,
            )
            .expect("atomically finalize terminal receipt"),
        EffectFinalizeResult::Finalized(_)
    ));
    assert_eq!(
        harness
            .actions()
            .load_action(&action.action_id)
            .expect("load finalized action")
            .expect("finalized action exists")
            .state,
        ExecutionState::Committed
    );
    let snapshot = harness
        .effects()
        .evidence_snapshot(&action.action_id)
        .expect("read evidence snapshot");
    assert_eq!(snapshot.receipt, Some(receipt));
    assert!(snapshot.conflicts.is_empty());
    assert!(snapshot.revision > 0);
}

#[derive(Clone, Copy)]
enum ActionBindingField {
    ActionId,
    IdempotencyKey,
    GrantDigest,
    PrincipalId,
    TenantId,
    RuntimeId,
    RuntimeBindingDigest,
    CapabilityId,
    CapabilityGeneration,
    RegistrationDigest,
    Operation,
    ExecutionClass,
    ArgsDigest,
    RouteDigest,
    AdmissionId,
    PolicyVersion,
    PolicyEpoch,
}

impl ActionBindingField {
    const ALL: [Self; 17] = [
        Self::ActionId,
        Self::IdempotencyKey,
        Self::GrantDigest,
        Self::PrincipalId,
        Self::TenantId,
        Self::RuntimeId,
        Self::RuntimeBindingDigest,
        Self::CapabilityId,
        Self::CapabilityGeneration,
        Self::RegistrationDigest,
        Self::Operation,
        Self::ExecutionClass,
        Self::ArgsDigest,
        Self::RouteDigest,
        Self::AdmissionId,
        Self::PolicyVersion,
        Self::PolicyEpoch,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::ActionId => "action_id",
            Self::IdempotencyKey => "idempotency_key",
            Self::GrantDigest => "grant_digest",
            Self::PrincipalId => "principal_id",
            Self::TenantId => "tenant_id",
            Self::RuntimeId => "runtime_id",
            Self::RuntimeBindingDigest => "runtime_binding_digest",
            Self::CapabilityId => "capability_id",
            Self::CapabilityGeneration => "capability_generation",
            Self::RegistrationDigest => "registration_digest",
            Self::Operation => "operation",
            Self::ExecutionClass => "execution_class",
            Self::ArgsDigest => "args_digest",
            Self::RouteDigest => "route_digest",
            Self::AdmissionId => "admission_id",
            Self::PolicyVersion => "policy_version",
            Self::PolicyEpoch => "policy_epoch",
        }
    }

    fn mutate(self, receipt: &mut ReceiptRecord) {
        match self {
            Self::ActionId => receipt.action_id = "other-action".into(),
            Self::IdempotencyKey => receipt.idempotency_key = "other-idempotency".into(),
            Self::GrantDigest => receipt.grant_digest = "other-grant".into(),
            Self::PrincipalId => receipt.principal_id = "mallory".into(),
            Self::TenantId => receipt.tenant_id = Some("other-tenant".into()),
            Self::RuntimeId => receipt.runtime_id = "other-runtime".into(),
            Self::RuntimeBindingDigest => {
                receipt.runtime_binding_digest = "other-runtime-binding".into()
            }
            Self::CapabilityId => receipt.capability_id = "other-capability".into(),
            Self::CapabilityGeneration => receipt.capability_generation += 1,
            Self::RegistrationDigest => receipt.registration_digest = "other-registration".into(),
            Self::Operation => receipt.operation = "other-operation".into(),
            Self::ExecutionClass => receipt.execution_class = "CRITICAL".into(),
            Self::ArgsDigest => receipt.args_digest = "other-args".into(),
            Self::RouteDigest => receipt.route_digest = "other-route".into(),
            Self::AdmissionId => receipt.admission_id = "other-admission".into(),
            Self::PolicyVersion => receipt.policy_version = "other-policy".into(),
            Self::PolicyEpoch => receipt.policy_epoch = "other-epoch".into(),
        }
    }
}

#[derive(Clone, Copy)]
enum ReceiptIdentityMutation {
    ProviderRequestId,
    FinalState,
    EvidenceDigest,
}

impl ReceiptIdentityMutation {
    const ALL: [Self; 3] = [
        Self::ProviderRequestId,
        Self::FinalState,
        Self::EvidenceDigest,
    ];

    fn mutate(self, receipt: &mut ReceiptRecord) {
        match self {
            Self::ProviderRequestId => receipt.provider_request_id = Some("other-provider".into()),
            Self::FinalState => receipt.final_state = ExecutionState::Failed,
            Self::EvidenceDigest => receipt.evidence_digest = "evidence-b".into(),
        }
    }
}
