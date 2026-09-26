// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Qualification-only executable: a real kernel and PostgreSQL effect store
//! around a persistent, deterministic external-effect simulator.

use nemo_effect_runtime::{
    DurableRuntime, EffectRuntimeConfig, EffectStoreSettings, PostgresTransport,
};
use nemo_relay::kernel::{
    CapabilityDefinition, CapabilityRegistry, InvocationOutcome, InvocationRequest,
    RecoveryDecision,
};
use nemo_relay_authority::unstable::{
    AuthorityDecision, AuthorityProvider, AuthorityRequest, GrantVerifier, VerifiedGrant,
};
use nemo_relay_executor::unstable::{
    DispatchState, EffectExecutionError, ExecutionBackend, ExecutionClass, ExecutionRequest,
    ExecutionResult, FunctionHooksExecutionBackend, OutcomeCertainty, ReconciliationProvider,
    ReconciliationRequest, ReconciliationResult, RuntimeIdentity,
};
use nemo_relay_ledger::postgres::PostgresEffectStore;
use nemo_relay_ledger::unstable::{
    ActionStore, ExecutionState, LeaseAcquireResult, LeaseConfiguration, ReceiptRecord,
};
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

const ACKNOWLEDGEMENT: &str = "NEMO_EFFECT_QUALIFICATION_ONLY";

struct QualificationAuthority;

impl GrantVerifier for QualificationAuthority {
    type Error = String;

    fn verify_grant(
        &self,
        request: &AuthorityRequest,
        grant: &VerifiedGrant,
    ) -> Result<(), Self::Error> {
        grant
            .binds(request)
            .then_some(())
            .ok_or_else(|| "qualification grant binding failed".into())
    }
}

impl AuthorityProvider for QualificationAuthority {
    fn decide(&self, request: &AuthorityRequest) -> Result<AuthorityDecision, Self::Error> {
        // This is deliberately not a real authority grant. The executable
        // refuses to run without an explicit qualification-only acknowledgement.
        Ok(AuthorityDecision::Allow(Box::new(VerifiedGrant {
            token: "qualification-only-not-a-signed-grant".into(),
            digest: "qualification-only-grant".into(),
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
        })))
    }
}

#[derive(Clone)]
struct PersistentProviderSimulator {
    connection: String,
    schema: String,
}

impl PersistentProviderSimulator {
    fn new(connection: &str, schema: &str) -> Result<Self, Box<dyn Error>> {
        let provider = Self {
            connection: connection.into(),
            schema: schema.into(),
        };
        provider.client()?.batch_execute(&format!(
            "create table if not exists \"{}\".qualification_provider_effects (\
             idempotency_key text primary key, action_id text not null unique, \
             receipt jsonb not null)",
            schema
        ))?;
        Ok(provider)
    }

    fn client(&self) -> Result<Client, postgres::Error> {
        Client::connect(&self.connection, NoTls)
    }

    fn receipt(&self, action_id: &str) -> Result<Option<ReceiptRecord>, Box<dyn Error>> {
        let row = self.client()?.query_opt(
            &format!(
                "select receipt from \"{}\".qualification_provider_effects where action_id = $1",
                self.schema
            ),
            &[&action_id],
        )?;
        row.map(|row| serde_json::from_value(row.get::<_, Value>(0)).map_err(Into::into))
            .transpose()
    }
}

fn backend_error(message: impl Into<String>) -> EffectExecutionError {
    EffectExecutionError {
        code: "QUALIFICATION_PROVIDER_ERROR".into(),
        dispatch_state: DispatchState::DispatchAttempted,
        outcome_certainty: OutcomeCertainty::Unknown,
        provider_request_id: None,
        retryable: false,
        reconciliation_required: true,
        message: message.into(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must follow the Unix epoch")
        .as_millis() as u64
}

fn bound_receipt(request: &ExecutionRequest) -> ReceiptRecord {
    let identity = &request.identity;
    let capability = &identity.capability;
    ReceiptRecord {
        receipt_id: format!("provider:{}", identity.action_id),
        action_id: identity.action_id.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        grant_digest: identity
            .grant_digest
            .clone()
            .expect("verified grant required"),
        principal_id: identity.runtime.principal_id.clone(),
        tenant_id: identity.runtime.tenant_id.clone(),
        runtime_id: identity.runtime.runtime_id.clone(),
        runtime_binding_digest: identity.runtime_binding_digest.clone(),
        capability_id: capability.capability_id.clone(),
        capability_generation: capability.capability_generation,
        registration_digest: capability.registration_digest.clone(),
        operation: capability.operation.clone(),
        execution_class: "MUTATION".into(),
        args_digest: identity.args_digest.clone(),
        route_digest: capability.route_digest.clone(),
        admission_id: identity.admission_id.clone(),
        policy_version: identity.policy_version.clone(),
        policy_epoch: identity.policy_epoch.clone(),
        provider_request_id: Some(identity.idempotency_key.clone()),
        final_state: ExecutionState::Committed,
        started_at_unix_ms: now_ms(),
        finished_at_unix_ms: now_ms(),
        evidence_digest: format!("provider-effect:{}", identity.idempotency_key),
    }
}

impl ExecutionBackend for PersistentProviderSimulator {
    fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, EffectExecutionError> {
        if request.identity.capability.execution_class != ExecutionClass::Mutation {
            return Err(backend_error("simulator accepts only registered mutations"));
        }
        let receipt = bound_receipt(request);
        let table = format!("\"{}\".qualification_provider_effects", self.schema);
        let mut client = self
            .client()
            .map_err(|error| backend_error(error.to_string()))?;
        client
            .execute(
                &format!(
                    "insert into {table} (idempotency_key, action_id, receipt) values ($1, $2, $3) \
                     on conflict (idempotency_key) do nothing"
                ),
                &[
                    &receipt.idempotency_key,
                    &receipt.action_id,
                    &serde_json::to_value(&receipt)
                        .map_err(|error| backend_error(error.to_string()))?,
                ],
            )
            .map_err(|error| backend_error(error.to_string()))?;
        let durable_receipt = self
            .receipt(&receipt.action_id)
            .map_err(|error| backend_error(error.to_string()))?
            .ok_or_else(|| {
                backend_error("provider idempotency identity conflicts with another action")
            })?;
        if std::env::var("NEMO_EFFECT_CRASH_AFTER_PROVIDER_COMMIT").as_deref() == Ok("1") {
            std::process::abort();
        }
        Ok(ExecutionResult {
            output: json!({"provider_applied": true}),
            outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
            receipt_digest: Some(durable_receipt.evidence_digest.clone()),
            receipt: Some(durable_receipt),
        })
    }
}

impl ReconciliationProvider for PersistentProviderSimulator {
    fn reconcile(
        &self,
        request: &ReconciliationRequest,
    ) -> Result<ReconciliationResult, EffectExecutionError> {
        let receipt = self
            .receipt(&request.action_id)
            .map_err(|error| backend_error(error.to_string()))?;
        Ok(ReconciliationResult {
            state: if receipt.is_some() {
                ExecutionState::Committed
            } else {
                ExecutionState::Unknown
            },
            receipt,
        })
    }
}

fn fast_hook(request: &ExecutionRequest) -> Result<ExecutionResult, EffectExecutionError> {
    Ok(ExecutionResult {
        output: json!({"value": request.args["value"]}),
        outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
        receipt_digest: None,
        receipt: None,
    })
}

fn registry() -> CapabilityRegistry {
    let mut registry = CapabilityRegistry::new();
    for (id, class, route) in [
        ("math.add", ExecutionClass::Pure, "function-hooks-v1"),
        (
            "counter.increment",
            ExecutionClass::Mutation,
            "effect-fabric-v1",
        ),
    ] {
        registry
            .register(
                CapabilityDefinition {
                    capability_id: id.into(),
                    capability_generation: 1,
                    registration_digest: format!("qualification-registration:{id}:1"),
                    execution_class: class,
                    operation: id.into(),
                    route_digest: route.into(),
                    admission_id: "qualification-admission".into(),
                    policy_version: "qualification-policy-v1".into(),
                    policy_epoch: "qualification-epoch-1".into(),
                    admitted: true,
                },
                |args: &Value| {
                    args.get("value")
                        .and_then(Value::as_i64)
                        .map(|_| ())
                        .ok_or_else(|| "value must be an integer".into())
                },
            )
            .expect("fixed qualification registry must be valid");
    }
    registry
}

fn valid_schema(schema: &str) -> bool {
    let mut bytes = schema.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && schema.len() <= 63
}

fn run() -> Result<(), Box<dyn Error>> {
    if std::env::var(ACKNOWLEDGEMENT).as_deref() != Ok("1") {
        return Err("qualification-only executable requires explicit acknowledgement".into());
    }
    let mut arguments = std::env::args().skip(1);
    let mode = arguments.next().ok_or("missing mode")?;
    let schema = arguments.next().ok_or("missing schema")?;
    let runtime_id = arguments.next().ok_or("missing stable runtime ID")?;
    if !valid_schema(&schema) || runtime_id.trim().is_empty() {
        return Err("invalid qualification schema or runtime ID".into());
    }
    let connection = std::env::var("NEMO_RELAY_TEST_POSTGRES_URL")?;
    // Qualification owns schema setup. The runtime itself only verifies a
    // migrated schema, mirroring the separate production migrator role.
    let migrator = PostgresEffectStore::connect_insecure_local_for_tests(
        &connection,
        &schema,
        LeaseConfiguration::default(),
        4,
    )?;
    migrator.migrate()?;
    let provider = PersistentProviderSimulator::new(&connection, &schema)?;
    let runtime = DurableRuntime::bootstrap(
        EffectRuntimeConfig::qualification(
            RuntimeIdentity {
                principal_id: "qualification-principal".into(),
                tenant_id: Some("qualification-tenant".into()),
                runtime_id,
                environment: "qualification".into(),
                session_id: None,
            },
            EffectStoreSettings {
                database_url: connection,
                schema,
                maximum_pool_size: 4,
                lease_configuration: LeaseConfiguration::default(),
                operation_budgets: Default::default(),
                database_transport: PostgresTransport::InsecureLoopbackForTests,
            },
        )?,
        registry(),
        QualificationAuthority,
        FunctionHooksExecutionBackend::new(fast_hook),
        provider,
    )?;
    let kernel = runtime.kernel();
    match mode.as_str() {
        "invoke" | "invoke-fast" => {
            let request_id = arguments.next().ok_or("missing request ID")?;
            let invocation = InvocationRequest {
                capability_id: if mode == "invoke-fast" {
                    "math.add"
                } else {
                    "counter.increment"
                }
                .into(),
                args: json!({"value": 1}),
                trace_id: None,
                request_id: Some(request_id),
            };
            match kernel.begin(&invocation)? {
                InvocationOutcome::Completed(result) => {
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "outcome": "completed",
                            "output": result.output,
                        }))?
                    );
                }
                InvocationOutcome::ExistingAction(action) => {
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "outcome": "existing_action",
                            "action_id": action.action_id,
                            "state": format!("{:?}", action.state).to_uppercase(),
                        }))?
                    );
                }
                InvocationOutcome::PendingApproval(action) => {
                    // A failed dispatch-marker write leaves the action prepared
                    // rather than unknown. Reporting that as a distinct outcome
                    // is what lets a caller tell an ordinary pre-dispatch
                    // failure apart from external ambiguity.
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "outcome": "pending",
                            "action_id": action.action_id(),
                            "state": "PREPARED",
                        }))?
                    );
                }
            }
        }
        "prepare-dispatching" => {
            // Model a worker that durably persisted the dispatch boundary and
            // then died before touching any provider.
            let store = runtime.effect_store();
            let action = nemo_relay_ledger::conformance::fixture_action();
            ActionStore::claim_action(store, &action)?;
            ActionStore::authorize_action(
                store,
                &action.action_id,
                ExecutionState::Proposed,
                "qualification-grant",
                None,
            )?;
            ActionStore::transition(
                store,
                &action.action_id,
                Some(ExecutionState::Authorized),
                ExecutionState::Prepared,
            )?;
            let lease = match ActionStore::claim_lease(
                store,
                &action.action_id,
                ExecutionState::Prepared,
                "qualification-pre-dispatch-worker",
                Some(60_000),
            )? {
                LeaseAcquireResult::Acquired(lease) => lease,
                other => return Err(format!("expected a pre-dispatch lease, got {other:?}").into()),
            };
            ActionStore::transition_with_lease(
                store,
                &action.action_id,
                ExecutionState::Prepared,
                &lease,
                ExecutionState::Dispatching,
            )?;
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "outcome": "dispatching",
                    "action_id": action.action_id,
                }))?
            );
        }
        "recover" => {
            for action_id in runtime.effect_store().recoverable_action_ids(64)? {
                let decision = kernel.recover(&action_id)?;
                let mut report = json!({
                    "action_id": action_id,
                    "recovery": match &decision {
                        RecoveryDecision::RecoverUnknown(_) => "recover_unknown",
                        RecoveryDecision::HeldByOther(_) => "held_by_other",
                        RecoveryDecision::RecoverCommitted(_) => "recover_committed",
                        RecoveryDecision::RecoverFailed(_) => "recover_failed",
                        RecoveryDecision::RecoverCancelled(_) => "recover_cancelled",
                        RecoveryDecision::RecoverRetry(_) => "recover_retry",
                        RecoveryDecision::ContradictoryEvidence { .. } => {
                            "contradictory_evidence"
                        }
                    },
                });
                if matches!(decision, RecoveryDecision::RecoverUnknown(_)) {
                    // An indeterminate reconciliation is a legitimate outcome,
                    // not a fixture failure: the action stays unknown and a
                    // later reconciliation can still resolve it.
                    match kernel.reconcile(&action_id) {
                        Ok(result) => {
                            report["reconciled_state"] =
                                json!(format!("{:?}", result.state).to_uppercase());
                        }
                        Err(error) => {
                            report["reconcile_error"] = json!(error.to_string());
                        }
                    }
                }
                println!("{}", serde_json::to_string(&report)?);
            }
        }
        _ => return Err("unknown qualification fixture mode".into()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("qualification fixture failed: {error}");
        std::process::exit(1);
    }
}
