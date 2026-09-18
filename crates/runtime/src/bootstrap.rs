// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime composition bootstrap.

use crate::config::{DatabaseConfig, DatabaseTransport, RuntimeConfig};
use crate::health::{RuntimeLiveness, RuntimeReadiness};
use crate::identity::resolve_runtime_identity;
use nemo_relay_executor::unstable::RuntimeIdentity;
use nemo_relay_ledger::postgres::{PostgresEffectStore, PostgresEffectStoreError};
use nemo_relay_ledger::unstable::LeaseConfiguration;
use thiserror::Error;

/// Ready-to-run runtime graph.
#[derive(Clone)]
pub struct RuntimeComposition {
    /// Host-authenticated runtime identity.
    pub runtime_identity: RuntimeIdentity,
    /// Durable effect store when durability is enabled.
    pub durable_store: Option<PostgresEffectStore>,
    /// Readiness view captured at startup.
    pub readiness: RuntimeReadiness,
    /// Liveness view captured at startup.
    pub liveness: RuntimeLiveness,
}

/// Bootstrap runtime composition and enforce profile guardrails.
pub fn bootstrap(config: &RuntimeConfig) -> Result<RuntimeComposition, BootstrapError> {
    config.validate().map_err(BootstrapError::Config)?;
    let runtime_identity = resolve_runtime_identity(config);

    let durable_store = match (&config.database, config.durability_enabled) {
        (Some(database), true) => Some(connect_store(database)?),
        (None, true) => {
            return Err(BootstrapError::Config(crate::config::ConfigError::Invalid(
                "durability_enabled requires database configuration".to_owned(),
            )));
        }
        (_, false) => None,
    };

    if let Some(store) = durable_store.as_ref() {
        if config
            .database
            .as_ref()
            .is_some_and(|db| db.allow_migrations)
        {
            store.migrate()?;
        }
        store.ensure_schema_compatible_exact()?;
    }

    Ok(RuntimeComposition {
        readiness: RuntimeReadiness {
            database_connected: !config.durability_enabled || durable_store.is_some(),
            schema_compatible: true,
            runtime_identity_valid: !runtime_identity.runtime_id.is_empty(),
            provider_configuration_valid: true,
        },
        liveness: RuntimeLiveness { running: true },
        runtime_identity,
        durable_store,
    })
}

fn connect_store(config: &DatabaseConfig) -> Result<PostgresEffectStore, BootstrapError> {
    let lease = LeaseConfiguration {
        default_duration_ms: 30_000,
        maximum_duration_ms: 300_000,
        renewal_enabled: true,
    };
    let store = match &config.transport {
        DatabaseTransport::InsecureLocal => PostgresEffectStore::connect_insecure_local_for_tests(
            &config.connection_string,
            &config.schema,
            lease,
            config.pool_size,
        )?,
        DatabaseTransport::LocalSocket => {
            #[cfg(unix)]
            {
                PostgresEffectStore::connect_local_socket(
                    &config.connection_string,
                    &config.schema,
                    lease,
                    config.pool_size,
                )?
            }
            #[cfg(not(unix))]
            {
                return Err(BootstrapError::Config(crate::config::ConfigError::Invalid(
                    "local socket transport requires unix host".to_owned(),
                )));
            }
        }
        DatabaseTransport::VerifiedTls { ca_path } => {
            let ca = std::fs::read(ca_path)?;
            PostgresEffectStore::connect_verified_tls(
                &config.connection_string,
                &config.schema,
                lease,
                config.pool_size,
                &ca,
            )?
        }
        DatabaseTransport::MutualTls {
            ca_path,
            client_identity_path,
            client_identity_password,
        } => {
            let ca = std::fs::read(ca_path)?;
            let identity = std::fs::read(client_identity_path)?;
            PostgresEffectStore::connect_mutual_tls(
                &config.connection_string,
                &config.schema,
                lease,
                config.pool_size,
                &ca,
                &identity,
                client_identity_password,
            )?
        }
    };
    Ok(store)
}

/// Bootstrap failure.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Runtime configuration failed validation.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// Durable store bootstrap failed.
    #[error(transparent)]
    Store(#[from] PostgresEffectStoreError),
    /// TLS asset loading failed.
    #[error("bootstrap I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
