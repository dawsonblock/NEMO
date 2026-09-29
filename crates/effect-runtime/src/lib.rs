// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validated composition of the NEMO kernel with a PostgreSQL effect store.
//!
//! This crate deliberately does not implement Correct-Once or an external
//! provider. Deployments supply those adapters, while this boundary ensures a
//! production kernel cannot be assembled before its stable runtime identity,
//! secure database transport, and versioned durable schema are verified.

use nemo_relay::kernel::{BackendRouter, CapabilityRegistry, Kernel, KernelError};
use nemo_relay_executor::unstable::{ExecutionBackend, RuntimeIdentity, RuntimeIdentityError};
use nemo_relay_ledger::postgres::{
    PostgresEffectStore, PostgresEffectStoreError, PostgresMutualTlsCredentials,
    PostgresOperationBudgets,
};
use nemo_relay_ledger::unstable::LeaseConfiguration;

/// Deployment profile that governs durable-store admission at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    /// Local development may use an explicitly local test transport.
    Development,
    /// Qualification runs may use an explicitly local test transport.
    Qualification,
    /// Production requires a local Unix socket or verified TLS transport.
    Production,
}

/// PostgreSQL transport material supplied by deployment configuration.
#[derive(Clone, PartialEq, Eq)]
pub enum PostgresTransport {
    /// Same-host PostgreSQL reached through a Unix domain socket.
    LocalSocket,
    /// Verified network TLS with deployment-provided trust roots.
    VerifiedTls {
        /// PEM-encoded trusted CA certificates.
        root_ca_pem: Vec<u8>,
    },
    /// Verified network TLS with a PKCS #12 client identity.
    MutualTls {
        /// PEM-encoded trusted CA certificates.
        root_ca_pem: Vec<u8>,
        /// PKCS #12 client certificate and private key.
        client_identity_pkcs12: Vec<u8>,
        /// Password for the client identity.
        client_identity_password: String,
    },
    /// Plaintext loopback PostgreSQL reserved for development and qualification.
    InsecureLoopbackForTests,
}

impl std::fmt::Debug for PostgresTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocalSocket => formatter.write_str("LocalSocket"),
            Self::VerifiedTls { .. } => {
                formatter.write_str("VerifiedTls { credentials: [redacted] }")
            }
            Self::MutualTls { .. } => formatter.write_str("MutualTls { credentials: [redacted] }"),
            Self::InsecureLoopbackForTests => formatter.write_str("InsecureLoopbackForTests"),
        }
    }
}

/// Store connection, policy, and transport settings.
///
/// These fields do not decide the deployment profile, so they stay public and
/// callers can name them at the construction site. The transport is the one
/// exception in spirit: a profile that requires verified transport rejects the
/// local test transport. That check belongs to the profile constructor, which
/// is why this value is not validated on its own.
#[derive(Clone, PartialEq, Eq)]
pub struct EffectStoreSettings {
    /// PostgreSQL connection target. Credentials must come from secret storage.
    pub database_url: String,
    /// Effect-store schema owned by the deployment.
    pub schema: String,
    /// Maximum bounded PostgreSQL connection pool size.
    pub maximum_pool_size: u32,
    /// Store-owned effect lease policy.
    pub lease_configuration: LeaseConfiguration,
    /// Bounded PostgreSQL operation budgets.
    pub operation_budgets: PostgresOperationBudgets,
    /// Verified or local-only transport selection.
    pub database_transport: PostgresTransport,
}

impl std::fmt::Debug for EffectStoreSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectStoreSettings")
            .field("database_url", &"[redacted]")
            .field("schema", &self.schema)
            .field("maximum_pool_size", &self.maximum_pool_size)
            .field("lease_configuration", &self.lease_configuration)
            .field("operation_budgets", &self.operation_budgets)
            .field("database_transport", &self.database_transport)
            .finish()
    }
}

/// Immutable settings required to construct one durable NEMO runtime.
///
/// The profile is private and is fixed by the constructor that produced this
/// value. The deployment profile decides which admission checks apply, so a
/// caller must not be able to hold production evidence while declaring a
/// profile that skips them. The only ways to build a configuration are the
/// constructors below, and each one pairs a profile with the evidence that
/// justifies it. The profile is therefore *derived* from the evidence rather
/// than asserted next to it, and a contradictory combination is
/// unrepresentable instead of merely rejected later.
#[derive(Clone, PartialEq, Eq)]
pub struct EffectRuntimeConfig {
    /// Deployment profile, fixed by the constructor that produced this value.
    mode: RuntimeMode,
    /// Stable host-authenticated identity bound into durable action records.
    runtime_identity: RuntimeIdentity,
    /// Store connection, policy, and transport settings.
    settings: EffectStoreSettings,
}

impl std::fmt::Debug for EffectRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectRuntimeConfig")
            .field("mode", &self.mode)
            .field("runtime_identity", &self.runtime_identity)
            .field("settings", &self.settings)
            .finish()
    }
}

/// Readiness failures that prevent consequential traffic from starting.
#[derive(Debug)]
pub enum RuntimeReadinessError {
    /// The trusted host identity is not canonical enough for durable bindings.
    RuntimeIdentity(RuntimeIdentityError),
    /// Production must use a production runtime identity environment.
    ProductionEnvironmentMismatch,
    /// A development or qualification profile must not claim the production
    /// environment.
    DevelopmentEnvironmentMismatch,
    /// Production cannot use an insecure loopback database transport.
    InsecureProductionTransport,
    /// Runtime configuration omitted a required value.
    MissingConfiguration(&'static str),
    /// The durable schema or database connection was not ready.
    Store(PostgresEffectStoreError),
    /// The kernel rejected the validated composition.
    Kernel(KernelError),
    /// This target cannot use Unix-domain sockets.
    LocalSocketUnsupported,
}

impl std::fmt::Display for RuntimeReadinessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuntimeIdentity(error) => write!(formatter, "invalid runtime identity: {error}"),
            Self::ProductionEnvironmentMismatch => {
                write!(
                    formatter,
                    "production mode requires runtime environment production"
                )
            }
            Self::DevelopmentEnvironmentMismatch => {
                write!(
                    formatter,
                    "development and qualification modes require a non-production runtime environment"
                )
            }
            Self::InsecureProductionTransport => {
                write!(
                    formatter,
                    "production mode cannot use plaintext loopback PostgreSQL"
                )
            }
            Self::MissingConfiguration(field) => {
                write!(
                    formatter,
                    "required durable runtime configuration is missing: {field}"
                )
            }
            Self::Store(error) => write!(formatter, "durable effect store is not ready: {error}"),
            Self::Kernel(error) => write!(formatter, "kernel composition failed: {error}"),
            Self::LocalSocketUnsupported => {
                write!(
                    formatter,
                    "local PostgreSQL sockets are unsupported on this target"
                )
            }
        }
    }
}

impl std::error::Error for RuntimeReadinessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RuntimeIdentity(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Kernel(error) => Some(error),
            Self::ProductionEnvironmentMismatch
            | Self::DevelopmentEnvironmentMismatch
            | Self::InsecureProductionTransport
            | Self::MissingConfiguration(_)
            | Self::LocalSocketUnsupported => None,
        }
    }
}

impl EffectRuntimeConfig {
    /// Compose a production configuration from production evidence.
    ///
    /// Both forms of evidence are required: a `production` runtime identity and
    /// a transport that is not the explicitly local test transport. Neither is
    /// a formality, so a deployment cannot reach the production profile while
    /// holding only one of them.
    pub fn production(
        runtime_identity: RuntimeIdentity,
        settings: EffectStoreSettings,
    ) -> Result<Self, RuntimeReadinessError> {
        if runtime_identity.environment != "production" {
            return Err(RuntimeReadinessError::ProductionEnvironmentMismatch);
        }
        if matches!(
            settings.database_transport,
            PostgresTransport::InsecureLoopbackForTests
        ) {
            return Err(RuntimeReadinessError::InsecureProductionTransport);
        }
        Ok(Self::assemble(
            RuntimeMode::Production,
            runtime_identity,
            settings,
        ))
    }

    /// Compose a qualification configuration from local-only evidence.
    ///
    /// Qualification runs against the explicitly local test transport and must
    /// declare a non-production identity, so a deployment cannot relaunch
    /// production traffic under a profile that skips production admission.
    pub fn qualification(
        runtime_identity: RuntimeIdentity,
        settings: EffectStoreSettings,
    ) -> Result<Self, RuntimeReadinessError> {
        Self::local(RuntimeMode::Qualification, runtime_identity, settings)
    }

    /// Compose a development configuration from local-only evidence.
    pub fn development(
        runtime_identity: RuntimeIdentity,
        settings: EffectStoreSettings,
    ) -> Result<Self, RuntimeReadinessError> {
        Self::local(RuntimeMode::Development, runtime_identity, settings)
    }

    fn local(
        mode: RuntimeMode,
        runtime_identity: RuntimeIdentity,
        settings: EffectStoreSettings,
    ) -> Result<Self, RuntimeReadinessError> {
        if runtime_identity.environment == "production" {
            return Err(RuntimeReadinessError::DevelopmentEnvironmentMismatch);
        }
        Ok(Self::assemble(mode, runtime_identity, settings))
    }

    fn assemble(
        mode: RuntimeMode,
        runtime_identity: RuntimeIdentity,
        settings: EffectStoreSettings,
    ) -> Self {
        Self {
            mode,
            runtime_identity,
            settings,
        }
    }

    /// Return the profile this configuration was built for.
    pub const fn mode(&self) -> RuntimeMode {
        self.mode
    }

    /// Validate the remaining deployment policy before any database connection
    /// is attempted.
    ///
    /// The profile and its evidence are not re-checked here. The private fields
    /// and the constructors above already make a contradictory configuration
    /// unrepresentable, so a check would be dead code.
    pub fn validate(&self) -> Result<(), RuntimeReadinessError> {
        self.runtime_identity
            .validate()
            .map_err(RuntimeReadinessError::RuntimeIdentity)?;
        if self.settings.database_url.trim().is_empty() {
            return Err(RuntimeReadinessError::MissingConfiguration("database_url"));
        }
        if self.settings.schema.trim().is_empty() {
            return Err(RuntimeReadinessError::MissingConfiguration("schema"));
        }
        if self.settings.maximum_pool_size == 0 {
            return Err(RuntimeReadinessError::MissingConfiguration(
                "maximum_pool_size",
            ));
        }
        Ok(())
    }

    /// Connect to the configured durable store without applying migrations.
    ///
    /// A migration role must apply the versioned migrations separately. This
    /// prevents normal worker credentials from acquiring DDL authority.
    pub fn connect_store(&self) -> Result<PostgresEffectStore, RuntimeReadinessError> {
        self.validate()?;
        let store = match &self.settings.database_transport {
            PostgresTransport::InsecureLoopbackForTests => {
                PostgresEffectStore::connect_insecure_local_for_tests_with_budgets(
                    &self.settings.database_url,
                    &self.settings.schema,
                    self.settings.lease_configuration,
                    self.settings.maximum_pool_size,
                    self.settings.operation_budgets.clone(),
                )
            }
            #[cfg(unix)]
            PostgresTransport::LocalSocket => {
                PostgresEffectStore::connect_local_socket_with_budgets(
                    &self.settings.database_url,
                    &self.settings.schema,
                    self.settings.lease_configuration,
                    self.settings.maximum_pool_size,
                    self.settings.operation_budgets.clone(),
                )
            }
            #[cfg(not(unix))]
            PostgresTransport::LocalSocket => {
                return Err(RuntimeReadinessError::LocalSocketUnsupported);
            }
            PostgresTransport::VerifiedTls { root_ca_pem } => {
                PostgresEffectStore::connect_verified_tls_with_budgets(
                    &self.settings.database_url,
                    &self.settings.schema,
                    self.settings.lease_configuration,
                    self.settings.maximum_pool_size,
                    root_ca_pem,
                    self.settings.operation_budgets.clone(),
                )
            }
            PostgresTransport::MutualTls {
                root_ca_pem,
                client_identity_pkcs12,
                client_identity_password,
            } => PostgresEffectStore::connect_mutual_tls_with_budgets(
                &self.settings.database_url,
                &self.settings.schema,
                self.settings.lease_configuration,
                self.settings.maximum_pool_size,
                PostgresMutualTlsCredentials {
                    root_ca_pem: root_ca_pem.clone(),
                    client_identity_pkcs12: client_identity_pkcs12.clone(),
                    client_identity_password: client_identity_password.clone(),
                },
                self.settings.operation_budgets.clone(),
            ),
        }
        .map_err(RuntimeReadinessError::Store)?;
        // Physical schema verification, not just ledger verification. A
        // database whose migration ledger is intact but whose tables, columns,
        // constraints, indexes, or triggers have drifted must not start.
        store
            .verify_schema()
            .map_err(RuntimeReadinessError::Store)?;
        if self.mode == RuntimeMode::Production {
            // Production additionally requires a data-only credential and the
            // database settings that govern durability and waiting. A runtime
            // credential that can rewrite the ledger it just trusted can hide
            // drift from every later verification.
            store
                .verify_database_readiness()
                .map_err(RuntimeReadinessError::Store)?;
        }
        Ok(store)
    }
}

/// A ready kernel whose only consequential durable authority is PostgreSQL.
pub struct DurableRuntime<A, F, E> {
    kernel: Kernel<A, F, E, PostgresEffectStore>,
    effect_store: PostgresEffectStore,
    mode: RuntimeMode,
}

impl<A, F, E> DurableRuntime<A, F, E>
where
    A: Send + Sync,
    F: ExecutionBackend,
    E: ExecutionBackend,
{
    /// Connect, verify the schema, and construct the durable kernel.
    pub fn bootstrap(
        config: EffectRuntimeConfig,
        registry: CapabilityRegistry,
        authority: A,
        function_hooks: F,
        effect_fabric: E,
    ) -> Result<Self, RuntimeReadinessError> {
        // Boot order: verify the durable substrate, then compose the kernel.
        // Every profile goes through a checked constructor, so no profile can
        // assemble a kernel by skipping admission: production additionally
        // requires a ready store behind the sealed `ProductionEffectStore`
        // trait, and the development constructor still validates the runtime
        // identity and seals the registry.
        let store = config.connect_store()?;
        let kernel = match config.mode {
            RuntimeMode::Production => {
                let sealed = registry.seal().map_err(RuntimeReadinessError::Kernel)?;
                Kernel::new_production(
                    config.runtime_identity,
                    sealed,
                    BackendRouter::new(authority, function_hooks, effect_fabric),
                    store.clone(),
                )
            }
            RuntimeMode::Development | RuntimeMode::Qualification => Kernel::new_development(
                config.runtime_identity,
                registry,
                BackendRouter::new(authority, function_hooks, effect_fabric),
                store.clone(),
            ),
        }
        .map_err(RuntimeReadinessError::Kernel)?;
        Ok(Self {
            kernel,
            effect_store: store,
            mode: config.mode,
        })
    }

    /// Return the ready kernel. The caller still owns its authority and provider adapters.
    pub const fn kernel(&self) -> &Kernel<A, F, E, PostgresEffectStore> {
        &self.kernel
    }

    /// Return the one authoritative durable effect store used by this runtime.
    pub const fn effect_store(&self) -> &PostgresEffectStore {
        &self.effect_store
    }

    /// Return the active deployment profile.
    pub const fn mode(&self) -> RuntimeMode {
        self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(environment: &str) -> RuntimeIdentity {
        RuntimeIdentity {
            principal_id: "runtime-principal".into(),
            tenant_id: Some("runtime-tenant".into()),
            runtime_id: "deployment-runtime".into(),
            environment: environment.into(),
            session_id: Some("process-session".into()),
        }
    }

    fn settings(transport: PostgresTransport) -> EffectStoreSettings {
        EffectStoreSettings {
            database_url: "host=127.0.0.1 user=nemo".into(),
            schema: "nemo_effects".into(),
            maximum_pool_size: 4,
            lease_configuration: LeaseConfiguration::default(),
            operation_budgets: PostgresOperationBudgets::default(),
            database_transport: transport,
        }
    }

    fn production(
        environment: &str,
        transport: PostgresTransport,
    ) -> Result<EffectRuntimeConfig, RuntimeReadinessError> {
        EffectRuntimeConfig::production(identity(environment), settings(transport))
    }

    fn qualification(
        transport: PostgresTransport,
    ) -> Result<EffectRuntimeConfig, RuntimeReadinessError> {
        EffectRuntimeConfig::qualification(identity("qualification"), settings(transport))
    }

    #[test]
    fn production_requires_production_evidence() {
        assert!(matches!(
            production("production", PostgresTransport::InsecureLoopbackForTests),
            Err(RuntimeReadinessError::InsecureProductionTransport)
        ));

        assert!(matches!(
            production(
                "qualification",
                PostgresTransport::VerifiedTls {
                    root_ca_pem: b"certificate".to_vec(),
                }
            ),
            Err(RuntimeReadinessError::ProductionEnvironmentMismatch)
        ));

        let ready = production(
            "production",
            PostgresTransport::VerifiedTls {
                root_ca_pem: b"certificate".to_vec(),
            },
        )
        .expect("production evidence composes");
        assert_eq!(ready.mode(), RuntimeMode::Production);
    }

    #[test]
    fn local_profiles_cannot_claim_the_production_environment() {
        // The profile is fixed by constructor, so the contradiction is
        // rejected where the configuration is built rather than where it is
        // used, and no field can drift afterwards.
        for profile in [
            EffectRuntimeConfig::development(
                identity("production"),
                settings(PostgresTransport::InsecureLoopbackForTests),
            ),
            EffectRuntimeConfig::qualification(
                identity("production"),
                settings(PostgresTransport::InsecureLoopbackForTests),
            ),
        ] {
            assert!(matches!(
                profile,
                Err(RuntimeReadinessError::DevelopmentEnvironmentMismatch)
            ));
        }

        // An honest non-production identity still composes and validates.
        let local =
            qualification(PostgresTransport::InsecureLoopbackForTests).expect("local evidence");
        assert_eq!(local.mode(), RuntimeMode::Qualification);
        assert!(local.validate().is_ok());
    }

    #[test]
    fn configuration_rejects_ambiguous_runtime_identity_before_connecting() {
        let mut ambiguous = identity("qualification");
        ambiguous.tenant_id = Some(" ".into());
        let configured = EffectRuntimeConfig::qualification(
            ambiguous,
            settings(PostgresTransport::InsecureLoopbackForTests),
        )
        .expect("the profile constrains only the environment");
        assert!(matches!(
            configured.validate(),
            Err(RuntimeReadinessError::RuntimeIdentity(_))
        ));
    }

    #[test]
    fn runtime_configuration_redacts_connection_and_tls_material() {
        let configured = EffectRuntimeConfig::qualification(
            identity("qualification"),
            EffectStoreSettings {
                database_url: "postgresql://nemo:database-password-secret@db.example/nemo".into(),
                database_transport: PostgresTransport::MutualTls {
                    root_ca_pem: b"root-ca-secret".to_vec(),
                    client_identity_pkcs12: b"client-identity-secret".to_vec(),
                    client_identity_password: "client-password-secret".into(),
                },
                ..settings(PostgresTransport::InsecureLoopbackForTests)
            },
        )
        .expect("qualification configuration");
        let debug = format!("{configured:?}");
        for secret in [
            "database-password-secret",
            "root-ca-secret",
            "client-identity-secret",
            "client-password-secret",
        ] {
            assert!(!debug.contains(secret));
        }
    }
}
