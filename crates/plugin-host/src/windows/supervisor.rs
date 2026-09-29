// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows supervisor surface, backed by a typed unsupported-platform refusal.

pub use crate::windows::unsupported_backend::{
    EXECUTABLE_ENV, PluginHostSupervisorConfig, ProcessPluginHost, plugin_runtime_binding,
};
