// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A native fixture that registers exactly the classes a kernel can serve.
//!
//! The other fixture registers on every surface the ABI exposes, which is what a
//! completeness test wants and what a *qualification* test cannot use: a kernel
//! that can proxy two classes must refuse a plugin registering sixteen, so a test
//! that drives the servable classes through a real process needs a plugin that
//! made exactly those registrations and no others. It grows with the kernel''s
//! proxy coverage, which is the point: a plugin whose registrations are all
//! servable is a plugin that can be isolated.
//!
//! What it does is deliberately trivial — it marks the arguments — because what
//! is being qualified is the path, not the callback.

use nemo_relay_plugin::{
    ConfigDiagnostic, Json, LlmRequestInterceptOutcome, NativePlugin, PluginContext, Result,
    nemo_relay_plugin,
};
use serde_json::{Map, json};

/// Marker the rewrite adds, so a caller can see the callback ran.
pub const REWRITE_MARKER: &str = "native_intercept";

/// Marker the LLM rewrite adds.
pub const LLM_MARKER: &str = "native_llm_intercept";

/// Marker a sanitized request payload carries.
pub const SANITIZE_REQUEST_MARKER: &str = "native_tool_request_sanitize";

/// Marker a sanitized response payload carries.
pub const SANITIZE_RESPONSE_MARKER: &str = "native_tool_response_sanitize";

struct InterceptPlugin;

impl NativePlugin for InterceptPlugin {
    fn plugin_kind(&self) -> &str {
        "fixture_intercept"
    }

    fn validate(&self, _config: &Map<String, Json>) -> Vec<ConfigDiagnostic> {
        Vec::new()
    }

    fn register(&mut self, config: &Map<String, Json>, ctx: &mut PluginContext<'_>) -> Result<()> {
        // The two sanitize directions. They change what an event publishes and
        // never what the tool does, which is the invariant a test can see from
        // outside: the call's own result comes back untouched while the copy the
        // event carries is the sanitized one.
        ctx.register_tool_sanitize_request_guardrail(
            "fixture_intercept_sanitize_request",
            0,
            |_name, value| async move {
                Ok(serde_json::json!({
                    "value": value,
                    SANITIZE_REQUEST_MARKER: true,
                }))
            },
        )?;
        ctx.register_tool_sanitize_response_guardrail(
            "fixture_intercept_sanitize_response",
            0,
            |_name, value| async move {
                Ok(serde_json::json!({
                    "value": value,
                    SANITIZE_RESPONSE_MARKER: true,
                }))
            },
        )?;
        // An additive observer: it answers with metadata to insert, and nothing
        // it returns can change the call that produced the event.
        ctx.register_event_metadata_injector(
            "fixture_intercept_metadata",
            0,
            |_event| async move {
                let mut additions = std::collections::BTreeMap::new();
                additions.insert("native_injected".to_string(), Json::Bool(true));
                Ok(additions)
            },
        )?;
        // A decision, which is the class that can stop a call: this one allows
        // everything except the tool named below, so a test can see both halves
        // of the decision cross the boundary.
        ctx.register_tool_conditional_execution_guardrail(
            "fixture_intercept_conditional",
            0,
            |name, _args| async move {
                if name == "rejected_tool" {
                    Ok(Some("the fixture refuses this tool".to_string()))
                } else {
                    Ok(None)
                }
            },
        )?;
        // The LLM half of the same decision.
        ctx.register_llm_conditional_execution_guardrail(
            "fixture_intercept_llm_conditional",
            0,
            |request| async move {
                if request
                    .content
                    .get("model")
                    .and_then(|model| model.as_str())
                    == Some("rejected-model")
                {
                    Ok(Some("the fixture refuses this model".to_string()))
                } else {
                    Ok(None)
                }
            },
        )?;
        // A guardrail that refuses to sanitize. It runs after the one above (a
        // later priority) so the sanitized copy is published first and this
        // failure is what a record of a sanitizer failure has to carry: a payload
        // nobody could sanitize is not published unsanitized, and the reason
        // would otherwise be a log line.
        ctx.register_tool_sanitize_request_guardrail(
            "fixture_intercept_sanitize_never",
            10,
            |_name, _value| async move { Err("the fixture refuses to sanitize".into()) },
        )?;
        // An observer, which is the third class a kernel can serve. What it saw
        // is written where the caller can read it, because a subscriber in
        // another process has no other way to witness that an event arrived: its
        // own runtime's subscribers are not the caller's.
        if let Some(log) = config.get("observer_log").and_then(|value| value.as_str()) {
            let log = log.to_string();
            ctx.register_subscriber("fixture_intercept_observer", move |event| {
                use std::io::Write;
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log)
                {
                    let _ = writeln!(file, "{}", event.name());
                }
            })?;
        }
        ctx.register_llm_request_intercept(
            "fixture_intercept_llm_rewrite",
            0,
            false,
            |_name, mut request, annotated| async move {
                if let Json::Object(content) = &mut request.content {
                    content.insert(LLM_MARKER.into(), json!(true));
                }
                Ok(LlmRequestInterceptOutcome::new(request, annotated))
            },
        )?;
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
