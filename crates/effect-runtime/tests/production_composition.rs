// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Production composition ownership and registry sealing.
//!
//! The decisive property is structural: a production kernel cannot be composed
//! with anything other than the durable effect store, and a running kernel
//! cannot have its capability registrations mutated afterwards.

use nemo_relay::kernel::{CapabilityDefinition, CapabilityRegistry, Kernel, KernelError};
use nemo_relay_authority::unstable::{
    AuthorityDecision, AuthorityProvider, AuthorityRequest, GrantVerifier, VerifiedGrant,
};
use nemo_relay_executor::unstable::{
    EffectExecutionError, ExecutionBackend, ExecutionClass, ExecutionRequest, ExecutionResult,
    ReconciliationProvider, ReconciliationRequest, ReconciliationResult, RuntimeIdentity,
};
use nemo_relay_ledger::postgres::PostgresEffectStore;
use nemo_relay_ledger::unstable::{LeaseConfiguration, ProductionEffectStore};
use postgres::NoTls;
use serde_json::{Value, json};

struct TestAuthority;

impl GrantVerifier for TestAuthority {
    type Error = String;

    fn verify_grant(
        &self,
        request: &AuthorityRequest,
        grant: &VerifiedGrant,
    ) -> Result<(), Self::Error> {
        grant
            .binds(request)
            .then_some(())
            .ok_or_else(|| "grant binding failed".into())
    }
}

impl AuthorityProvider for TestAuthority {
    fn decide(&self, request: &AuthorityRequest) -> Result<AuthorityDecision, Self::Error> {
        Ok(AuthorityDecision::Allow(Box::new(VerifiedGrant {
            token: "composition-test-grant".into(),
            digest: "composition-test-grant".into(),
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

#[derive(Default, Clone)]
struct TestBackend;

impl ExecutionBackend for TestBackend {
    fn execute(
        &self,
        _request: &ExecutionRequest,
    ) -> Result<ExecutionResult, EffectExecutionError> {
        Ok(ExecutionResult {
            output: json!({"applied": false}),
            outcome_certainty: nemo_relay_executor::unstable::OutcomeCertainty::ConfirmedSuccess,
            receipt_digest: None,
            receipt: None,
        })
    }
}

impl ReconciliationProvider for TestBackend {
    fn reconcile(
        &self,
        _request: &ReconciliationRequest,
    ) -> Result<ReconciliationResult, EffectExecutionError> {
        Ok(ReconciliationResult {
            state: nemo_relay_ledger::unstable::ExecutionState::Unknown,
            receipt: None,
        })
    }
}

fn registry(classes: &[ExecutionClass]) -> CapabilityRegistry {
    let mut registry = CapabilityRegistry::new();
    for (index, class) in classes.iter().enumerate() {
        let id = format!("composition.test.{index}");
        registry
            .register(
                CapabilityDefinition {
                    capability_id: id.clone(),
                    capability_generation: 1,
                    registration_digest: format!("composition-registration:{id}:1"),
                    execution_class: *class,
                    operation: id,
                    route_digest: "effect-fabric-v1".into(),
                    admission_id: "composition-admission".into(),
                    policy_version: "composition-policy-v1".into(),
                    policy_epoch: "composition-epoch-1".into(),
                    admitted: true,
                },
                |args: &Value| {
                    args.get("value")
                        .and_then(Value::as_i64)
                        .map(|_| ())
                        .ok_or_else(|| "value must be an integer".into())
                },
            )
            .expect("register composition capability");
    }
    registry
}

fn runtime(environment: &str) -> RuntimeIdentity {
    RuntimeIdentity {
        principal_id: "composition-principal".into(),
        tenant_id: Some("composition-tenant".into()),
        runtime_id: "composition-runtime".into(),
        environment: environment.into(),
        session_id: None,
    }
}

// -- Architectural boundary --------------------------------------------------

/// Constructors that may only appear outside production code.
const NON_PRODUCTION_CONSTRUCTORS: &[&str] = &["new_unchecked_for_tests"];

/// The file that defines the raw constructor, and therefore may mention it.
const CONSTRUCTOR_DEFINITION: &str = "crates/core/src/kernel.rs";

fn production_sources() -> Vec<(String, String)> {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let mut sources = Vec::new();
    // Crates that ship to users. Tests are excluded: a test is allowed to
    // compose a development kernel.
    for crate_name in ["cli", "python", "node", "ffi"] {
        let root = workspace.join("crates").join(crate_name).join("src");
        collect_rust_sources(&root, &workspace, &mut sources);
    }
    sources
}

fn collect_rust_sources(
    directory: &std::path::Path,
    workspace: &std::path::Path,
    into: &mut Vec<(String, String)>,
) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, workspace, into);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(workspace)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let source = std::fs::read_to_string(&path).unwrap_or_default();
            into.push((relative, source));
        }
    }
}

#[test]
fn production_crates_cannot_reach_a_non_production_constructor() {
    let sources = production_sources();
    assert!(
        !sources.is_empty(),
        "architectural check found no production sources to inspect"
    );
    for (path, source) in &sources {
        // Comments are allowed to mention the constructor; code is not.
        let code: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for constructor in NON_PRODUCTION_CONSTRUCTORS {
            assert!(
                !code.contains(constructor),
                "{path} uses {constructor}, which bypasses production composition"
            );
        }
    }
}

#[test]
fn no_crate_reaches_the_unchecked_test_constructor() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let mut offenders = Vec::new();
    for crate_entry in std::fs::read_dir(workspace.join("crates")).expect("read crates") {
        let crate_entry = crate_entry.expect("crate entry");
        if !crate_entry.path().is_dir() {
            continue;
        }
        let mut sources = Vec::new();
        collect_rust_sources(&crate_entry.path().join("src"), &workspace, &mut sources);
        for (path, source) in sources {
            // The definition site and its development wrapper are core's own
            // business; what matters is who *calls* the raw constructor.
            if path == CONSTRUCTOR_DEFINITION {
                continue;
            }
            let calls = source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .any(|line| line.contains("Kernel::new_unchecked_for_tests("));
            if calls {
                offenders.push(path);
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "no crate may compose a kernel through the unchecked test constructor, found: {offenders:?}"
    );
}

// -- Sealing -----------------------------------------------------------------

#[test]
fn sealing_consumes_the_builder_and_fixes_the_registry_digest() {
    let sealed = registry(&[ExecutionClass::Mutation])
        .seal()
        .expect("seal registry");
    assert_eq!(sealed.len(), 1);
    assert!(!sealed.is_empty());
    let digest = sealed.digest().to_owned();
    assert_eq!(digest.len(), 64);

    // The digest is stable across separately built but identical registries.
    let again = registry(&[ExecutionClass::Mutation])
        .seal()
        .expect("seal registry");
    assert_eq!(again.digest(), digest);

    // Any security-relevant field change produces a different digest, so a
    // sealed registry identity cannot silently describe different semantics.
    let mut changed = registry(&[ExecutionClass::Mutation]);
    changed
        .register(
            CapabilityDefinition {
                capability_id: "composition.test.extra".into(),
                capability_generation: 1,
                registration_digest: "composition-registration:extra:1".into(),
                execution_class: ExecutionClass::Mutation,
                operation: "composition.test.extra".into(),
                route_digest: "effect-fabric-v1".into(),
                admission_id: "composition-admission".into(),
                policy_version: "composition-policy-v1".into(),
                policy_epoch: "composition-epoch-1".into(),
                admitted: true,
            },
            |_: &Value| Ok(()),
        )
        .expect("register extra capability");
    assert_ne!(changed.seal().expect("seal").digest(), digest);
}

#[test]
fn an_empty_registry_seals_with_a_stable_digest() {
    let sealed = CapabilityRegistry::new()
        .seal()
        .expect("seal empty registry");
    assert!(sealed.is_empty());
    assert_eq!(sealed.len(), 0);
    assert_eq!(
        sealed.digest(),
        CapabilityRegistry::new()
            .seal()
            .expect("seal empty registry")
            .digest()
    );
}

// -- Production composition --------------------------------------------------

struct CompositionFixture {
    connection: String,
    schema: String,
    runtime_url: String,
    role: String,
}

impl CompositionFixture {
    fn create() -> Option<Self> {
        let connection = std::env::var("NEMO_RELAY_TEST_POSTGRES_URL").ok()?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        let schema = format!("nemo_composition_{}_{}", std::process::id(), nanos);
        let role = format!("nemo_composition_runtime_{}", std::process::id());

        let migrator = PostgresEffectStore::connect_insecure_local_for_tests(
            &connection,
            &schema,
            LeaseConfiguration::default(),
            4,
        )
        .expect("connect composition migrator");
        migrator.migrate().expect("migrate composition schema");

        let mut admin = postgres::Client::connect(&connection, NoTls).expect("admin connection");
        admin
            .batch_execute(&format!(
                "create role \"{role}\" login password 'composition-only';
                 grant usage on schema \"{schema}\" to \"{role}\";
                 grant select, insert, update, delete on all tables in schema \"{schema}\" to \"{role}\";
                 revoke insert, update, delete, truncate on \"{schema}\".effect_schema_migrations from \"{role}\";
                 revoke insert, update, delete, truncate on \"{schema}\".effect_schema_state from \"{role}\";
                 revoke create on schema \"{schema}\" from \"{role}\"",
            ))
            .ok()?;

        let runtime_url = format!(
            "postgresql://{role}:composition-only@{}",
            connection.rsplit('@').next().expect("host in test URL")
        );
        Some(Self {
            connection,
            schema,
            runtime_url,
            role,
        })
    }

    fn runtime_store(&self) -> PostgresEffectStore {
        PostgresEffectStore::connect_insecure_local_for_tests(
            &self.runtime_url,
            &self.schema,
            LeaseConfiguration::default(),
            4,
        )
        .expect("connect composition runtime store")
    }

    fn owner_store(&self) -> PostgresEffectStore {
        PostgresEffectStore::connect_insecure_local_for_tests(
            &self.connection,
            &self.schema,
            LeaseConfiguration::default(),
            4,
        )
        .expect("connect composition owner store")
    }

    /// Build the runtime store over a transport that may attest readiness.
    ///
    /// The fixture's own connection is the explicitly local test transport,
    /// which is correct for creating the schema and the roles and can never
    /// attest production readiness. Verified TLS is the transport a CI database
    /// can actually serve, so this reads its trust root from
    /// `NEMO_RELAY_TEST_POSTGRES_TLS_CA` and returns `None` when it is absent.
    fn verified_runtime_store(&self) -> Option<PostgresEffectStore> {
        let ca_path = std::env::var("NEMO_RELAY_TEST_POSTGRES_TLS_CA").ok()?;
        let root_ca_pem = std::fs::read(ca_path).ok()?;
        Some(
            PostgresEffectStore::connect_verified_tls_with_budgets(
                &self.runtime_url,
                &self.schema,
                LeaseConfiguration::default(),
                4,
                &root_ca_pem,
                nemo_relay_ledger::postgres::PostgresOperationBudgets::default(),
            )
            .expect("connect verified TLS runtime store"),
        )
    }
}

impl Drop for CompositionFixture {
    fn drop(&mut self) {
        if let Ok(mut admin) = postgres::Client::connect(&self.connection, NoTls) {
            let _ = admin.batch_execute(&format!(
                "drop schema if exists \"{}\" cascade",
                self.schema
            ));
            let _ = admin.batch_execute(&format!("drop owned by \"{}\" cascade", self.role));
            let _ = admin.batch_execute(&format!("drop role if exists \"{}\"", self.role));
        }
    }
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn a_verified_transport_composes_a_production_kernel() {
    let Some(fixture) = CompositionFixture::create() else {
        eprintln!("skipping: NEMO_RELAY_TEST_POSTGRES_URL or role creation unavailable");
        return;
    };
    let Some(store) = fixture.verified_runtime_store() else {
        eprintln!(
            "skipping: set NEMO_RELAY_TEST_POSTGRES_TLS_CA to a trust root the server \
             presents, so the transport can attest production readiness"
        );
        return;
    };

    // The negative cases prove a bad production composition is rejected. This
    // one proves the path still exists at all: without it the suite would stay
    // green if production startup became impossible in every configuration.
    let kernel = Kernel::new_production(
        runtime("production"),
        registry(&[ExecutionClass::Mutation])
            .seal()
            .expect("seal registry"),
        nemo_relay::kernel::BackendRouter::new(TestAuthority, TestBackend, TestBackend),
        store,
    )
    .expect("a verified transport with a ready durable store must compose");
    assert_eq!(kernel.registry_digest().len(), 64);
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn production_composition_rejects_a_test_transport_store() {
    let Some(fixture) = CompositionFixture::create() else {
        eprintln!("skipping: NEMO_RELAY_TEST_POSTGRES_URL or role creation unavailable");
        return;
    };

    // The fixture's own transport is the explicitly local test transport: it is
    // correct for creating the schema and the runtime role, and it can never
    // attest production readiness. Every store carries the sealed
    // `ProductionEffectStore` bound regardless of how it was opened, so without
    // this check a production kernel could be composed around a connection that
    // was never verified.
    let result = Kernel::new_production(
        runtime("production"),
        registry(&[ExecutionClass::Mutation])
            .seal()
            .expect("seal registry"),
        nemo_relay::kernel::BackendRouter::new(TestAuthority, TestBackend, TestBackend),
        fixture.runtime_store(),
    );
    assert!(
        matches!(
            result,
            Err(KernelError::EffectStoreNotProductionReady(ref detail))
                if detail.contains("test-only plaintext transport")
        ),
        "the test transport must not attest production readiness"
    );
}

#[test]
#[ignore = "requires NEMO_RELAY_TEST_POSTGRES_URL"]
fn production_composition_is_fail_closed() {
    let Some(fixture) = CompositionFixture::create() else {
        eprintln!("skipping: NEMO_RELAY_TEST_POSTGRES_URL or role creation unavailable");
        return;
    };

    // Wrong environment: a production kernel cannot be composed in a
    // development or qualification identity.
    let result = Kernel::new_production(
        runtime("qualification"),
        registry(&[ExecutionClass::Mutation]).seal().expect("seal"),
        nemo_relay::kernel::BackendRouter::new(TestAuthority, TestBackend, TestBackend),
        fixture.runtime_store(),
    );
    assert!(matches!(
        result,
        Err(KernelError::ProductionEnvironmentMismatch)
    ));

    // No consequential capability: a production kernel must not be composed
    // with only PURE/READ routes, because that would make the durable path
    // optional for whatever registers later.
    let result = Kernel::new_production(
        runtime("production"),
        registry(&[ExecutionClass::Pure, ExecutionClass::Read])
            .seal()
            .expect("seal"),
        nemo_relay::kernel::BackendRouter::new(TestAuthority, TestBackend, TestBackend),
        fixture.runtime_store(),
    );
    assert!(matches!(
        result,
        Err(KernelError::ProductionRequiresConsequentialCapability)
    ));

    // A schema-owning credential cannot compose a production kernel, but this
    // fixture cannot reach that check: its transport is the test-only one, so
    // the transport gate fires first. The privilege check itself is covered by
    // `verify_runtime_privileges` in the ledger suite, which uses the test
    // transport directly.
    let result = Kernel::new_production(
        runtime("production"),
        registry(&[ExecutionClass::Mutation]).seal().expect("seal"),
        nemo_relay::kernel::BackendRouter::new(TestAuthority, TestBackend, TestBackend),
        fixture.owner_store(),
    );
    assert!(
        matches!(
            result,
            Err(KernelError::EffectStoreNotProductionReady(ref detail))
                if detail.contains("test-only plaintext transport")
        ),
        "the transport gate must fire before any credential check"
    );
}

#[test]
fn the_production_store_trait_is_sealed() {
    // The sealed trait is the load-bearing bound. It is implemented for the
    // durable adapter, and this assertion documents that the trait is reachable
    // as a bound while its supertrait is not nameable outside the ledger crate.
    fn assert_bound<S: ProductionEffectStore>() {}
    assert_bound::<PostgresEffectStore>();
}
