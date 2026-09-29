// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows exports the shared activation contract and an explicit unsupported
//! backend. It does not compile the Unix socket supervisor or callback transport.

pub mod unsupported_backend;

use nemo_relay_plugin_protocol::{PluginComponentConfiguration, PluginProtocolError};

/// Native plugins cannot be hosted by this platform backend.
#[derive(Debug)]
pub struct ProcessLoadedPlugins;

impl ProcessLoadedPlugins {
    /// Refuse native plugin startup with the platform's typed error.
    pub async fn load<I, J>(
        _config: crate::supervisor::PluginHostSupervisorConfig,
        _registration_cap_millis: u64,
        _observability: crate::off_path::ObservabilityPolicy,
        _specs: I,
        _components: J,
    ) -> Result<Self, PluginProtocolError>
    where
        I: IntoIterator<Item = (String, String)>,
        J: IntoIterator<Item = PluginComponentConfiguration>,
    {
        Err(PluginProtocolError::new(
            nemo_relay_plugin_protocol::PluginFailureCode::Unavailable,
            crate::error::PluginHostError::UnsupportedPlatform {
                feature: "native plugin process isolation",
                platform: "windows",
            }
            .to_string(),
        ))
    }

    /// No native backend can exist on Windows.
    pub fn backend(&self) -> &unsupported_backend::ProcessPluginHost {
        unreachable!("Windows never constructs ProcessLoadedPlugins")
    }
}
