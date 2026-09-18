// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime bootstrap configuration.

use serde::{Deserialize, Serialize};

/// Supported runtime profile modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfile {
    /// Local developer profile.
    Development,
    /// Test profile.
    Test,
    /// Qualification profile.
    Qualification,
    /// Production profile.
    Production,
}

impl RuntimeProfile {
    /// Return whether this profile enforces production guardrails.
    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

/// PostgreSQL transport mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseTransport {
    /// Local-only Unix socket transport.
    LocalSocket,
    /// Verified TLS transport.
    VerifiedTls {
        /// Path to PEM trust roots.
        ca_path: String,
    },
    /// Mutual TLS transport.
    MutualTls {
        /// Path to PEM trust roots.
        ca_path: String,
        /// Path to PKCS #12 client identity.
        client_identity_path: String,
        /// Password for PKCS #12 identity.
        client_identity_password: String,
    },
    /// Explicitly local plaintext transport for tests.
    InsecureLocal,
}

/// Runtime durable-database configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// PostgreSQL connection string.
    pub connection_string: String,
    /// Target schema name.
    pub schema: String,
    /// Maximum connection pool size.
    pub pool_size: u32,
    /// Database transport policy.
    pub transport: DatabaseTransport,
    /// Allow startup migration execution.
    pub allow_migrations: bool,
}

/// Runtime identity configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeIdentityConfig {
    /// Stable runtime identity. Must be set in production.
    pub runtime_id: Option<String>,
    /// Authenticated principal identifier.
    pub principal_id: String,
    /// Optional tenant identifier.
    pub tenant_id: Option<String>,
    /// Optional session identifier.
    pub session_id: Option<String>,
}

/// Top-level runtime composition config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Active profile.
    pub profile: RuntimeProfile,
    /// Enable durable mutation paths.
    pub durability_enabled: bool,
    /// Database config for durable mode.
    pub database: Option<DatabaseConfig>,
    /// Runtime identity config.
    pub identity: RuntimeIdentityConfig,
}

impl RuntimeConfig {
    /// Validate production profile invariants before startup.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.profile.is_production() {
            if !self.durability_enabled {
                return Err(ConfigError::Invalid(
                    "production requires durability_enabled=true".to_owned(),
                ));
            }
            if self
                .identity
                .runtime_id
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(ConfigError::Invalid(
                    "production requires a stable runtime identity".to_owned(),
                ));
            }
            let database = self.database.as_ref().ok_or_else(|| {
                ConfigError::Invalid("production requires durable postgres config".to_owned())
            })?;
            if matches!(database.transport, DatabaseTransport::InsecureLocal) {
                return Err(ConfigError::Invalid(
                    "production forbids insecure postgres transport".to_owned(),
                ));
            }
            if database.pool_size == 0 {
                return Err(ConfigError::Invalid(
                    "production requires pool_size > 0".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Runtime bootstrap config error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Invalid setting combination.
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid runtime config: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> RuntimeConfig {
        RuntimeConfig {
            profile: RuntimeProfile::Development,
            durability_enabled: false,
            database: None,
            identity: RuntimeIdentityConfig {
                runtime_id: None,
                principal_id: "principal".into(),
                tenant_id: None,
                session_id: None,
            },
        }
    }

    #[test]
    fn production_requires_durable_database_and_identity() {
        let mut config = base();
        config.profile = RuntimeProfile::Production;
        assert!(config.validate().is_err());

        config.durability_enabled = true;
        config.database = Some(DatabaseConfig {
            connection_string: "host=/tmp dbname=postgres".into(),
            schema: "nemo_effects".into(),
            pool_size: 8,
            transport: DatabaseTransport::LocalSocket,
            allow_migrations: false,
        });
        assert!(config.validate().is_err());

        config.identity.runtime_id = Some("runtime-production".into());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn production_rejects_whitespace_runtime_identity() {
        let mut config = base();
        config.profile = RuntimeProfile::Production;
        config.durability_enabled = true;
        config.database = Some(DatabaseConfig {
            connection_string: "host=/tmp dbname=postgres".into(),
            schema: "nemo_effects".into(),
            pool_size: 8,
            transport: DatabaseTransport::LocalSocket,
            allow_migrations: false,
        });
        config.identity.runtime_id = Some("   ".into());

        assert!(config.validate().is_err());
    }
}
