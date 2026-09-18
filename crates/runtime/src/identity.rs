// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime identity resolution.

use crate::config::{RuntimeConfig, RuntimeProfile};
use nemo_relay_executor::unstable::RuntimeIdentity;

/// Resolve host-authenticated runtime identity for kernel composition.
pub fn resolve_runtime_identity(config: &RuntimeConfig) -> RuntimeIdentity {
    let runtime_id = match (&config.identity.runtime_id, config.profile) {
        (Some(runtime_id), _) if !runtime_id.trim().is_empty() => runtime_id.clone(),
        (_, RuntimeProfile::Production) => {
            unreachable!("runtime config validation must enforce production runtime identity")
        }
        _ => format!("runtime-{}", uuid::Uuid::now_v7()),
    };

    RuntimeIdentity {
        principal_id: config.identity.principal_id.clone(),
        tenant_id: config.identity.tenant_id.clone(),
        runtime_id,
        environment: match config.profile {
            RuntimeProfile::Development => "development",
            RuntimeProfile::Test => "test",
            RuntimeProfile::Qualification => "qualification",
            RuntimeProfile::Production => "production",
        }
        .to_owned(),
        session_id: config.identity.session_id.clone(),
    }
}
