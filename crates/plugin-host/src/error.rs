// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Typed errors for platform capabilities of the process-host boundary.

/// A requested native plugin host capability is unavailable on this platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginHostError {
    /// The current build cannot provide the requested process boundary.
    UnsupportedPlatform {
        /// The feature the caller requested.
        feature: &'static str,
        /// The platform that cannot provide it.
        platform: &'static str,
    },
}

impl std::fmt::Display for PluginHostError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform { feature, platform } => {
                write!(formatter, "{feature} is unsupported on {platform}")
            }
        }
    }
}

impl std::error::Error for PluginHostError {}
