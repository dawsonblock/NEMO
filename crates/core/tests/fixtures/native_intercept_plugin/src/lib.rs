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
    CategoryProfile, ConfigDiagnostic, EventCategory, EventSanitizeFields, Json,
    LlmRequestInterceptOutcome, NativePlugin, PendingMarkSpec, PluginContext, Result,
    ToolExecutionInterceptOutcome, ToolExecutionResult, nemo_relay_plugin,
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

/// Marker the execution intercept adds to the arguments it passes downstream.
pub const EXECUTION_REQUEST_MARKER: &str = "native_intercept_execution_request";

/// Marker the execution intercept adds to the result the call returned.
pub const EXECUTION_MARKER: &str = "native_intercept_execution";

/// Marker the LLM execution intercept adds to the request it passes downstream.
pub const LLM_EXECUTION_REQUEST_MARKER: &str = "native_intercept_llm_execution_request";

/// Marker the LLM execution intercept adds to the response the call returned.
pub const LLM_EXECUTION_MARKER: &str = "native_intercept_llm_execution";

/// The mark the execution intercept asks the call's owner to emit.
pub const EXECUTION_PENDING_MARK: &str = "fixture.intercept.tool_execution.mark";

/// The metadata key the first mark sanitizer adds.
///
/// Three mark sanitizers rather than one because the property these fixtures exist
/// for is *which* registration ran: a family that is invoked whole would leave all
/// three markers on the answer, and a chain that stopped at the first would leave
/// one.
pub const MARK_A_MARKER: &str = "fixture_mark_a";

/// The metadata key the second mark sanitizer adds.
pub const MARK_B_MARKER: &str = "fixture_mark_b";

/// The metadata key the third mark sanitizer adds.
pub const MARK_C_MARKER: &str = "fixture_mark_c";

/// The metadata key the scope-start sanitizer adds.
pub const SCOPE_START_MARKER: &str = "fixture_scope_start_sanitize";

/// The metadata key the scope-end sanitizer adds.
pub const SCOPE_END_MARKER: &str = "fixture_scope_end_sanitize";

/// How much padding the answer of the oversized sanitizer carries.
///
/// Larger than any response budget the suite states, and small enough to stay
/// inside the frame the transport allows: what has to trip is the operation's own
/// budget rather than the frame limit.
const OVERSIZED_PADDING_BYTES: usize = 8 * 1024;

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
        // The class that wraps the call rather than answering one. It marks the
        // arguments it passes downstream and the result that comes back, so both
        // halves of a continuation are visible from the caller: the request
        // marker proves the rewritten arguments reached the downstream call, and
        // the result marker proves the downstream answer came back to the plugin.
        ctx.register_tool_execution_intercept("fixture_intercept_execution", 0, {
            |_name, args, next| {
                Box::pin(async move {
                    let mut args = args;
                    if let Json::Object(object) = &mut args {
                        object.insert(EXECUTION_REQUEST_MARKER.into(), json!(true));
                    }
                    // Three shapes the boundary has to carry, chosen by the
                    // caller rather than by the fixture: an intercept that
                    // replaces the call, one that runs it twice, and one that
                    // runs it and then fails.
                    let replace = args
                        .get("skip_next")
                        .and_then(Json::as_bool)
                        .unwrap_or(false);
                    let concurrent = args
                        .get("use_concurrent_next")
                        .and_then(Json::as_bool)
                        .unwrap_or(false);
                    let fail_after = args
                        .get("fail_after_next")
                        .and_then(Json::as_bool)
                        .unwrap_or(false);
                    let mut result = if replace {
                        // No continuation at all: the plugin decided the result
                        // itself, and nothing downstream is entered.
                        ToolExecutionResult::new(json!({ "replaced_by_plugin": true }))
                    } else if concurrent {
                        let first_next = next.clone();
                        let (first, second) =
                            tokio::join!(first_next.call(args.clone()), next.call(args));
                        first?;
                        second?
                    } else {
                        next.call(args).await?
                    };
                    if fail_after {
                        return Err("the fixture fails after its continuation".into());
                    }
                    if let Json::Object(object) = &mut result.result {
                        object.insert(EXECUTION_MARKER.into(), json!(true));
                    }
                    // A mark the intercept asks the *call's* owner to emit, rather
                    // than one it emits itself: the call lives in the kernel, so
                    // the request has to travel back with the outcome.
                    Ok(ToolExecutionInterceptOutcome::from(result).with_pending_mark(
                        PendingMarkSpec::builder()
                            .name(EXECUTION_PENDING_MARK)
                            .category(EventCategory::custom())
                            .category_profile(CategoryProfile {
                                subtype: Some("fixture.intercept.tool_execution".into()),
                                ..CategoryProfile::default()
                            })
                            .data(json!({ "source": "fixture_intercept_execution" }))
                            .build(),
                    ))
                })
            }
        })?;
        // The provider half of the same class. What differs from the tool one is
        // only the shape that travels — a request down, a response back — so it is
        // the same continuation machinery on the other side.
        ctx.register_llm_execution_intercept("fixture_intercept_llm_execution", 0, {
            |_name, mut request, next| {
                Box::pin(async move {
                    if let Json::Object(content) = &mut request.content {
                        content.insert(LLM_EXECUTION_REQUEST_MARKER.into(), json!(true));
                    }
                    let replace = request
                        .content
                        .get("skip_next")
                        .and_then(Json::as_bool)
                        .unwrap_or(false);
                    let mut response = if replace {
                        // No continuation: the plugin decided the answer itself.
                        json!({ "replaced_by_plugin": true })
                    } else {
                        next.call(request).await?
                    };
                    if let Json::Object(object) = &mut response {
                        object.insert(LLM_EXECUTION_MARKER.into(), json!(true));
                    }
                    Ok(response)
                })
            }
        })?;
        // The three event sanitize families, and only when a test asks for them.
        //
        // This fixture registers exactly the classes a kernel can serve, which is
        // what a qualification run needs; the event sanitizers are not servable
        // yet, so registering them by default would make every composition test
        // refuse the plugin whole. Gating them behind a config key keeps the
        // default set honest while the Layer 2 gate is written against the shape
        // the classes will have.
        if config
            .get("event_sanitizers")
            .and_then(Json::as_bool)
            .unwrap_or(false)
        {
            let log = config
                .get("sanitizer_log")
                .and_then(Json::as_str)
                .map(str::to_owned);
            register_event_sanitizers(ctx, log)?;
        }
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

/// Register one sanitizer per family, three of them in one family.
///
/// The three mark sanitizers differ only in the marker they add and the order they
/// declare, because that is what the property needs: a call naming one of them has
/// to leave that one's marker and neither neighbour's, and an answer that carries
/// two markers is a family that ran rather than a registration that answered.
///
/// The last two are the failure shapes: one registration that refuses, and one that
/// answers correctly with more bytes than the operation was allowed to receive.
///
/// When a test hands over a log path, every registration appends its own local name
/// to it as it runs. A marker in an answer says which registration *answered*; the
/// log says which registrations *ran*, and "B ran once while A and C did not run at
/// all" is a claim only the second can make — a host that ran B twice would satisfy
/// the first.
pub fn register_event_sanitizers(ctx: &mut PluginContext<'_>, log: Option<String>) -> Result<()> {
    ctx.register_mark_sanitize_guardrail("fixture_mark_a", 0, {
        let log = log.clone();
        move |_event, fields| {
            let log = log.clone();
            async move {
                log_run(log.as_deref(), "fixture_mark_a");
                Ok(marked_fields(fields, MARK_A_MARKER))
            }
        }
    })?;
    ctx.register_mark_sanitize_guardrail("fixture_mark_b", 10, {
        let log = log.clone();
        move |_event, fields| {
            let log = log.clone();
            async move {
                log_run(log.as_deref(), "fixture_mark_b");
                Ok(marked_fields(fields, MARK_B_MARKER))
            }
        }
    })?;
    ctx.register_mark_sanitize_guardrail("fixture_mark_c", 20, {
        let log = log.clone();
        move |_event, fields| {
            let log = log.clone();
            async move {
                log_run(log.as_deref(), "fixture_mark_c");
                Ok(marked_fields(fields, MARK_C_MARKER))
            }
        }
    })?;
    ctx.register_scope_sanitize_start_guardrail("fixture_scope_start_sanitize", 0, {
        let log = log.clone();
        move |_event, fields| {
            let log = log.clone();
            async move {
                log_run(log.as_deref(), "fixture_scope_start_sanitize");
                Ok(marked_fields(fields, SCOPE_START_MARKER))
            }
        }
    })?;
    // A second sanitizer of one family, so "the family does not run" is a claim
    // about a neighbour rather than about the only registration there is.
    ctx.register_scope_sanitize_start_guardrail("fixture_scope_start_other", 10, {
        let log = log.clone();
        move |_event, fields| {
            let log = log.clone();
            async move {
                log_run(log.as_deref(), "fixture_scope_start_other");
                Ok(marked_fields(fields, "fixture_scope_start_other"))
            }
        }
    })?;
    ctx.register_scope_sanitize_end_guardrail("fixture_scope_end_sanitize", 0, {
        let log = log.clone();
        move |_event, fields| {
            let log = log.clone();
            async move {
                log_run(log.as_deref(), "fixture_scope_end_sanitize");
                Ok(marked_fields(fields, SCOPE_END_MARKER))
            }
        }
    })?;
    // A sanitizer that refuses. What it does *not* do is answer with the payload it
    // was given, which is the difference between a withheld payload and a published
    // one.
    ctx.register_mark_sanitize_guardrail("fixture_mark_refuses", 30, {
        let log = log.clone();
        move |_event, _fields| {
            let log = log.clone();
            async move {
                log_run(log.as_deref(), "fixture_mark_refuses");
                Err("the fixture refuses to sanitize".into())
            }
        }
    })?;
    // A callback that throws rather than refusing. The two are different findings —
    // a sanitizer that said no and a sanitizer that fell over — and a host that
    // reported them the same way would make one of them invisible.
    ctx.register_mark_sanitize_guardrail("fixture_mark_panics", 35, {
        let log = log.clone();
        move |_event, _fields| {
            let log = log.clone();
            async move {
                log_run(log.as_deref(), "fixture_mark_panics");
                panic!("the fixture's mark sanitizer panics")
            }
        }
    })?;
    // A valid answer, far larger than a small response budget. The padding is
    // written here rather than by the caller so the size of the answer is the
    // fixture's and the budget is the operation's.
    ctx.register_mark_sanitize_guardrail("fixture_mark_oversized", 40, {
        let log = log.clone();
        move |_event, mut fields| {
            let log = log.clone();
            async move {
                log_run(log.as_deref(), "fixture_mark_oversized");
                let mut metadata = match fields.metadata.take() {
                    Some(Json::Object(object)) => object,
                    _ => Map::new(),
                };
                metadata.insert(
                    "fixture_mark_oversized".into(),
                    Json::String("x".repeat(OVERSIZED_PADDING_BYTES)),
                );
                fields.metadata = Some(Json::Object(metadata));
                Ok(fields)
            }
        }
    })
}

/// Append one registration's local name to the log a test handed over.
///
/// A log that cannot be written is not a plugin failure: the fixture is
/// qualification scaffolding, and a missing witness must not change the behaviour
/// being witnessed.
fn log_run(log: Option<&str>, name: &str) {
    use std::io::Write;
    let Some(path) = log else {
        return;
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{name}");
    }
}

/// Add one marker to an event's metadata, leaving every other field alone.
///
/// A sanitizer's job is to change what observers see, so what it adds is visible
/// and what it was handed is carried through: a fixture that dropped the payload it
/// was given could not tell a sanitizer that ran from one that published nothing.
fn marked_fields(mut fields: EventSanitizeFields, marker: &str) -> EventSanitizeFields {
    let mut metadata = match fields.metadata.take() {
        Some(Json::Object(object)) => object,
        _ => Map::new(),
    };
    metadata.insert(marker.to_string(), Json::Bool(true));
    fields.metadata = Some(Json::Object(metadata));
    fields
}

nemo_relay_plugin!(nemo_relay_native_intercept_fixture, || InterceptPlugin);
