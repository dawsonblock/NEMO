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

/// Immutable settings required to construct one durable NEMO runtime.
#[derive(Clone, PartialEq, Eq)]
pub struct EffectRuntimeConfig {
    /// Deployment profile.
    pub mode: RuntimeMode,
    /// Stable host-authenticated identity bound into durable action records.
    pub runtime_identity: RuntimeIdentity,
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

impl std::fmt::Debug for EffectRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectRuntimeConfig")
            .field("mode", &self.mode)
            .field("runtime_identity", &self.runtime_identity)
            .field("database_url", &"[redacted]")
            .field("schema", &self.schema)
            .field("maximum_pool_size", &self.maximum_pool_size)
            .field("lease_configuration", &self.lease_configuration)
            .field("operation_budgets", &self.operation_budgets)
            .field("database_transport", &self.database_transport)
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
            | Self::InsecureProductionTransport
            | Self::MissingConfiguration(_)
            | Self::LocalSocketUnsupported => None,
        }
    }
}

impl EffectRuntimeConfig {
    /// Validate deployment policy before any database connection is attempted.
    pub fn validate(&self) -> Result<(), RuntimeReadinessError> {
        self.runtime_identity
            .validate()
            .map_err(RuntimeReadinessError::RuntimeIdentity)?;
        if self.database_url.trim().is_empty() {
            return Err(RuntimeReadinessError::MissingConfiguration("database_url"));
        }
        if self.schema.trim().is_empty() {
            return Err(RuntimeReadinessError::MissingConfiguration("schema"));
        }
        if self.maximum_pool_size == 0 {
            return Err(RuntimeReadinessError::MissingConfiguration(
                "maximum_pool_size",
            ));
        }
        if self.mode == RuntimeMode::Production {
            if self.runtime_identity.environment != "production" {
                return Err(RuntimeReadinessError::ProductionEnvironmentMismatch);
            }
            if matches!(
                self.database_transport,
                PostgresTransport::InsecureLoopbackForTests
            ) {
                return Err(RuntimeReadinessError::InsecureProductionTransport);
            }
        }
        Ok(())
    }

    /// Connect to the configured durable store without applying migrations.
    ///
    /// A migration role must apply the versioned migrations separately. This
    /// prevents normal worker credentials from acquiring DDL authority.
    pub fn connect_store(&self) -> Result<PostgresEffectStore, RuntimeReadinessError> {
        self.validate()?;
        let store = match &self.database_transport {
            PostgresTransport::InsecureLoopbackForTests => {
                PostgresEffectStore::connect_insecure_local_for_tests_with_budgets(
                    &self.database_url,
                    &self.schema,
                    self.lease_configuration,
                    self.maximum_pool_size,
                    self.operation_budgets.clone(),
                )
            }
            #[cfg(unix)]
            PostgresTransport::LocalSocket => {
                PostgresEffectStore::connect_local_socket_with_budgets(
                    &self.database_url,
                    &self.schema,
                    self.lease_configuration,
                    self.maximum_pool_size,
                    self.operation_budgets.clone(),
                )
            }
            #[cfg(not(unix))]
            PostgresTransport::LocalSocket => {
                return Err(RuntimeReadinessError::LocalSocketUnsupported);
            }
            PostgresTransport::VerifiedTls { root_ca_pem } => {
                PostgresEffectStore::connect_verified_tls_with_budgets(
                    &self.database_url,
                    &self.schema,
                    self.lease_configuration,
                    self.maximum_pool_size,
                    root_ca_pem,
                    self.operation_budgets.clone(),
                )
            }
            PostgresTransport::MutualTls {
                root_ca_pem,
                client_identity_pkcs12,
                client_identity_password,
            } => PostgresEffectStore::connect_mutual_tls_with_budgets(
                &self.database_url,
                &self.schema,
                self.lease_configuration,
                self.maximum_pool_size,
                PostgresMutualTlsCredentials {
                    root_ca_pem: root_ca_pem.clone(),
                    client_identity_pkcs12: client_identity_pkcs12.clone(),
                    client_identity_password: client_identity_password.clone(),
                },
                self.operation_budgets.clone(),
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
        // Boot order: verify the durable substrate, then seal the capability
        // registry, then compose the kernel. The kernel cannot be constructed
        // before both, because the production constructor requires a sealed
        // registry and a store that attested readiness.
        let store = config.connect_store()?;
        let sealed = registry.seal().map_err(RuntimeReadinessError::Kernel)?;
        let kernel = match config.mode {
            RuntimeMode::Production => Kernel::new_production(
                config.runtime_identity,
                sealed,
                BackendRouter::new(authority, function_hooks, effect_fabric),
                store.clone(),
            ),
            RuntimeMode::Development | RuntimeMode::Qualification => {
                // Non-production profiles may compose without a production
                // runtime environment, but still receive a sealed registry and
                // a store that passed the same schema verification.
                Ok(Kernel::new_unchecked_for_tests(
                    config.runtime_identity,
                    sealed,
                    BackendRouter::new(authority, function_hooks, effect_fabric),
                    store.clone(),
                ))
            }
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

    fn config(mode: RuntimeMode, transport: PostgresTransport) -> EffectRuntimeConfig {
        EffectRuntimeConfig {
            mode,
            runtime_identity: RuntimeIdentity {
                principal_id: "runtime-principal".into(),
                tenant_id: Some("runtime-tenant".into()),
                runtime_id: "deployment-runtime".into(),
                environment: if mode == RuntimeMode::Production {
                    "production"
                } else {
                    "qualification"
                }
                .into(),
                session_id: Some("process-session".into()),
            },
            database_url: "host=127.0.0.1 user=nemo".into(),
            schema: "nemo_effects".into(),
            maximum_pool_size: 4,
            lease_configuration: LeaseConfiguration::default(),
            operation_budgets: PostgresOperationBudgets::default(),
            database_transport: transport,
        }
    }

    #[test]
    fn production_rejects_plaintext_transport_and_nonproduction_identity() {
        let insecure = config(
            RuntimeMode::Production,
            PostgresTransport::InsecureLoopbackForTests,
        );
        assert!(matches!(
            insecure.validate(),
            Err(RuntimeReadinessError::InsecureProductionTransport)
        ));

        let mut mismatched = config(
            RuntimeMode::Production,
            PostgresTransport::VerifiedTls {
                root_ca_pem: b"certificate".to_vec(),
            },
        );
        mismatched.runtime_identity.environment = "qualification".into();
        assert!(matches!(
            mismatched.validate(),
            Err(RuntimeReadinessError::ProductionEnvironmentMismatch)
        ));
    }

    #[test]
    fn configuration_rejects_ambiguous_runtime_identity_before_connecting() {
        let mut invalid = config(
            RuntimeMode::Qualification,
            PostgresTransport::InsecureLoopbackForTests,
        );
        invalid.runtime_identity.tenant_id = Some(" ".into());
        assert!(matches!(
            invalid.validate(),
            Err(RuntimeReadinessError::RuntimeIdentity(_))
        ));
    }

    #[test]
    fn runtime_configuration_redacts_connection_and_tls_material() {
        let mut configured = config(
            RuntimeMode::Qualification,
            PostgresTransport::MutualTls {
                root_ca_pem: b"root-ca-secret".to_vec(),
                client_identity_pkcs12: b"client-identity-secret".to_vec(),
                client_identity_password: "client-password-secret".into(),
            },
        );
        configured.database_url =
            "postgresql://nemo:database-password-secret@db.example/nemo".into();
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
