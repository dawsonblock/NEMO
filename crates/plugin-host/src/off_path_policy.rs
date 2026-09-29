// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Platform-neutral bounds for plugin work performed beside a managed call.

/// How much a runtime asks of plugins beside the calls it makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservabilityPolicy {
    /// Longest off-path operation may take.
    pub budget_millis: u64,
    /// Maximum number of off-path operations in flight.
    pub max_in_flight: usize,
}

impl ObservabilityPolicy {
    /// Refuse a policy that states no time or capacity.
    pub fn validate(&self) -> Result<(), nemo_relay_plugin_protocol::PluginProtocolError> {
        use nemo_relay_plugin_protocol::{PluginFailureCode, PluginProtocolError};

        if self.budget_millis == 0 {
            return Err(PluginProtocolError::new(
                PluginFailureCode::Rejected,
                "an observability budget of zero milliseconds would refuse every off-path operation"
                    .to_string(),
            ));
        }
        if self.max_in_flight == 0 {
            return Err(PluginProtocolError::new(
                PluginFailureCode::Rejected,
                "an in-flight limit of zero would refuse every off-path operation".to_string(),
            ));
        }
        Ok(())
    }
}
