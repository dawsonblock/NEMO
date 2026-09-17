// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Production runtime entrypoint.

use nemo_relay_runtime::bootstrap::bootstrap;
use nemo_relay_runtime::config::{
    DatabaseConfig, DatabaseTransport, RuntimeConfig, RuntimeIdentityConfig, RuntimeProfile,
};
use std::process::ExitCode;

fn main() -> ExitCode {
    let profile =
        std::env::var("NEMO_RELAY_RUNTIME_PROFILE").unwrap_or_else(|_| "development".to_owned());
    let profile = match profile.as_str() {
        "development" => RuntimeProfile::Development,
        "test" => RuntimeProfile::Test,
        "qualification" => RuntimeProfile::Qualification,
        "production" => RuntimeProfile::Production,
        _ => {
            eprintln!("invalid NEMO_RELAY_RUNTIME_PROFILE");
            return ExitCode::from(2);
        }
    };

    let durability_enabled = std::env::var("NEMO_RELAY_DURABILITY_ENABLED")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let database = std::env::var("NEMO_RELAY_POSTGRES_URL")
        .ok()
        .map(|connection_string| DatabaseConfig {
            connection_string,
            schema: std::env::var("NEMO_RELAY_POSTGRES_SCHEMA")
                .unwrap_or_else(|_| "nemo_effects".to_owned()),
            pool_size: std::env::var("NEMO_RELAY_POSTGRES_POOL_SIZE")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(8),
            transport: std::env::var("NEMO_RELAY_POSTGRES_TRANSPORT")
                .ok()
                .as_deref()
                .map(database_transport)
                .unwrap_or(DatabaseTransport::InsecureLocal),
            allow_migrations: std::env::var("NEMO_RELAY_ALLOW_MIGRATIONS")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        });

    let config = RuntimeConfig {
        profile,
        durability_enabled,
        database,
        identity: RuntimeIdentityConfig {
            runtime_id: std::env::var("NEMO_RELAY_RUNTIME_ID").ok(),
            principal_id: std::env::var("NEMO_RELAY_PRINCIPAL_ID")
                .unwrap_or_else(|_| "nemo-runtime".to_owned()),
            tenant_id: std::env::var("NEMO_RELAY_TENANT_ID").ok(),
            session_id: None,
        },
    };

    match bootstrap(&config) {
        Ok(runtime) if runtime.readiness.is_ready() && runtime.liveness.is_live() => {
            ExitCode::SUCCESS
        }
        Ok(_) => ExitCode::from(3),
        Err(error) => {
            eprintln!("runtime bootstrap failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn database_transport(value: &str) -> DatabaseTransport {
    match value {
        "local_socket" => DatabaseTransport::LocalSocket,
        "verified_tls" => DatabaseTransport::VerifiedTls {
            ca_path: std::env::var("NEMO_RELAY_POSTGRES_TLS_CA").unwrap_or_default(),
        },
        "mutual_tls" => DatabaseTransport::MutualTls {
            ca_path: std::env::var("NEMO_RELAY_POSTGRES_TLS_CA").unwrap_or_default(),
            client_identity_path: std::env::var("NEMO_RELAY_POSTGRES_TLS_CLIENT_IDENTITY")
                .unwrap_or_default(),
            client_identity_password: std::env::var("NEMO_RELAY_POSTGRES_TLS_CLIENT_PASSWORD")
                .unwrap_or_default(),
        },
        _ => DatabaseTransport::InsecureLocal,
    }
}
