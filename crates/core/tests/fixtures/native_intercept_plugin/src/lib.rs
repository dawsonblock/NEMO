// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A native fixture that registers exactly one class.
//!
//! The other fixture registers on every surface the ABI exposes, which is what a
//! completeness test wants and what a *qualification* test cannot use: a kernel
//! that can proxy one class must refuse a plugin registering sixteen, so a test
//! that drives one registration through a real process needs a plugin that made
//! exactly one.
//!
//! What it does is deliberately trivial — it marks the arguments — because what
//! is being qualified is the path, not the callback.

use nemo_relay_plugin::{
    ConfigDiagnostic, Json, NativePlugin, PluginContext, Result, nemo_relay_plugin,
};
use serde_json::{Map, json};

/// Marker the rewrite adds, so a caller can see the callback ran.
pub const REWRITE_MARKER: &str = "native_intercept";

struct InterceptPlugin;

impl NativePlugin for InterceptPlugin {
    fn plugin_kind(&self) -> &str {
        "fixture_intercept"
    }

    fn validate(&self, _config: &Map<String, Json>) -> Vec<ConfigDiagnostic> {
        Vec::new()
    }

    fn register(&mut self, _config: &Map<String, Json>, ctx: &mut PluginContext<'_>) -> Result<()> {
        ctx.register_tool_request_intercept(
            "fixture_intercept_rewrite",
            0,
            false,
            |_name, mut args| {
                Box::pin(async move {
                    if let Json::Object(object) = &mut args {
                        object.insert(REWRITE_MARKER.into(), json!(true));
                    }
                    Ok(args)
                })
            },
        )
    }
}

nemo_relay_plugin!(nemo_relay_native_intercept_fixture, || InterceptPlugin);
