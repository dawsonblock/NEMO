// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Typed Windows refusal for the native plugin process boundary.

use std::path::PathBuf;
use std::time::Duration;

use nemo_relay_plugin_protocol::{MAX_FRAME_BYTES, PluginHostBuild, PluginHostReadCapability};

use crate::error::PluginHostError;

/// The Windows implementation reports process-hosted native plugins as unsupported.
#[derive(Debug)]
pub struct ProcessPluginHost;

impl ProcessPluginHost {
    /// Start a native plugin host, refusing because Windows IPC is not implemented.
    pub fn start(_config: PluginHostSupervisorConfig) -> Result<Self, PluginHostError> {
        Err(PluginHostError::UnsupportedPlatform {
            feature: "native plugin process isolation",
            platform: "windows",
        })
    }

    /// This unsupported backend never has a child process.
    pub fn process_id(&self) -> Option<u32> {
        None
    }
}

/// Configuration shape shared with the Unix supervisor for binding parity.
#[derive(Debug, Clone)]
pub struct PluginHostSupervisorConfig {
    /// The executable expected to host native plugins.
    pub executable: PathBuf,
    /// The host build the runtime expects.
    pub expected_host_build: PluginHostBuild,
    /// Runtime identity bound to this host session.
    pub runtime_binding_digest: String,
    /// State the host may read from the kernel.
    pub offered_read_capabilities: Vec<PluginHostReadCapability>,
    /// Largest protocol frame accepted by either side.
    pub maximum_frame_bytes: u32,
    /// Process limits requested for the host.
    pub limits: crate::limits::PluginHostLimits,
    /// Requested host confinement level.
    pub isolation: crate::isolation_policy::NativeIsolationPolicy,
    /// Maximum time to wait for host startup.
    pub startup_timeout: Duration,
}

impl PluginHostSupervisorConfig {
    /// Resolve the expected sibling executable path without starting it.
    pub fn beside_this_executable(runtime_binding_digest: impl Into<String>) -> Self {
        let executable = std::env::var_os(EXECUTABLE_ENV)
            .map(PathBuf::from)
            .or_else(|| {
                std::env::current_exe().ok().and_then(|path| {
                    path.parent()
                        .map(|directory| directory.join("nemo-plugin-host.exe"))
                })
            })
            .unwrap_or_else(|| PathBuf::from("nemo-plugin-host.exe"));
        Self {
            executable,
            expected_host_build: PluginHostBuild::expected(env!("CARGO_PKG_VERSION")),
            runtime_binding_digest: runtime_binding_digest.into(),
            offered_read_capabilities: Vec::new(),
            maximum_frame_bytes: MAX_FRAME_BYTES,
            limits: crate::limits::PluginHostLimits::default(),
            isolation: crate::isolation_policy::NativeIsolationPolicy::default(),
            startup_timeout: Duration::from_secs(10),
        }
    }
}

/// Environment variable naming the shipped host executable.
pub const EXECUTABLE_ENV: &str = "NEMO_RELAY_PLUGIN_HOST";

/// Compute the runtime identity used by the Unix host protocol.
pub fn plugin_runtime_binding(implementation: &str) -> String {
    crate::host_location::plugin_runtime_binding(implementation)
}
