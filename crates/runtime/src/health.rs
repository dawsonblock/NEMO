// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime health status model.

/// Startup readiness projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReadiness {
    /// Database connectivity is available.
    pub database_connected: bool,
    /// Database schema is compatible with this runtime binary.
    pub schema_compatible: bool,
    /// Runtime identity is configured and valid.
    pub runtime_identity_valid: bool,
    /// Required provider configuration is present.
    pub provider_configuration_valid: bool,
}

impl RuntimeReadiness {
    /// Return whether the runtime is ready to accept mutation traffic.
    pub const fn is_ready(&self) -> bool {
        self.database_connected
            && self.schema_compatible
            && self.runtime_identity_valid
            && self.provider_configuration_valid
    }
}

/// Runtime liveness projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLiveness {
    /// Process is still operational.
    pub running: bool,
}

impl RuntimeLiveness {
    /// Return whether liveness is satisfied.
    pub const fn is_live(&self) -> bool {
        self.running
    }
}
