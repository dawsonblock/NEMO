// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The exact-registration doors for the LLM sanitize pair.
//!
//! These are the doors a host runs a plugin's registration through, so what they do —
//! which registration runs, what the answer is, and what happens when there is none — is
//! a contract rather than an implementation detail. The tests follow the same two rules
//! the event doors' tests do: a registration that would change what other suites see is
//! made scope-local, and every test takes the crate's runtime lock.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::api::llm::{
    LlmRequest, invoke_llm_sanitize_request_registration, invoke_llm_sanitize_response_registration,
};
use crate::api::registry::{
    register_llm_sanitize_request_guardrail, scope_register_llm_sanitize_request_guardrail,
    scope_register_llm_sanitize_response_guardrail,
};
use crate::api::runtime::{LlmCodecIdentity, LlmSanitizeRequestFn, LlmSanitizeResponseFn};
use crate::api::scope::{PopScopeParams, PushScopeParams, ScopeType, pop_scope, push_scope};
use crate::error::FlowError;

fn lock_runtime() -> std::sync::MutexGuard<'static, ()> {
    crate::shared_runtime::runtime_owner_test_mutex()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn request() -> LlmRequest {
    LlmRequest {
        headers: serde_json::Map::new(),
        content: serde_json::json!({ "model": "example" }),
    }
}

/// A sanitizer that counts its own calls and answers with the payload unchanged.
fn counting_request_sanitizer() -> (Arc<AtomicUsize>, LlmSanitizeRequestFn) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let sanitizer: LlmSanitizeRequestFn = Arc::new(move |request, _context| {
        let counter = Arc::clone(&counter);
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(Some(request))
        })
    });
    (calls, sanitizer)
}

fn counting_response_sanitizer() -> (Arc<AtomicUsize>, LlmSanitizeResponseFn) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let sanitizer: LlmSanitizeResponseFn = Arc::new(move |response, _context| {
        let counter = Arc::clone(&counter);
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(Some(response))
        })
    });
    (calls, sanitizer)
}

fn calls(counter: &Arc<AtomicUsize>) -> usize {
    counter.load(Ordering::SeqCst)
}

/// A pushed scope that pops when it is dropped, so a failing assertion cannot leave the
/// stack holding one for the tests that run after it in this process.
struct TestScope {
    uuid: uuid::Uuid,
}

impl TestScope {
    fn push(name: &str) -> Self {
        let handle = push_scope(
            PushScopeParams::builder()
                .name(name)
                .scope_type(ScopeType::Agent)
                .build(),
        )
        .expect("a scope");
        Self { uuid: handle.uuid }
    }

    fn uuid(&self) -> &uuid::Uuid {
        &self.uuid
    }
}

impl Drop for TestScope {
    fn drop(&mut self) {
        let _ = pop_scope(PopScopeParams::builder().handle_uuid(&self.uuid).build());
    }
}

/// The request door runs exactly the registration it names, and its neighbours in the
/// same family do not run.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn the_request_door_runs_exactly_the_registration_it_names() {
    let _guard = lock_runtime();
    let scope = TestScope::push("llm-sanitize-door-scope");
    let names = [
        "llm-sanitize-door-a",
        "llm-sanitize-door-b",
        "llm-sanitize-door-c",
    ];
    let mut counters = Vec::new();
    for (priority, name) in names.iter().enumerate() {
        let (counter, sanitizer) = counting_request_sanitizer();
        scope_register_llm_sanitize_request_guardrail(
            scope.uuid(),
            name,
            priority as i32,
            sanitizer,
        )
        .expect("registered");
        counters.push(counter);
    }

    let outcome = invoke_llm_sanitize_request_registration(
        "llm-sanitize-door-b",
        request(),
        crate::api::runtime::LlmSanitizeRequestContext::with_identity(LlmCodecIdentity::None),
    )
    .await
    .expect("the named registration");
    assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
    assert!(outcome.request.is_some(), "the sanitizer answered");
    assert_eq!(
        counters.iter().map(calls).collect::<Vec<_>>(),
        [0, 1, 0],
        "the family has three registrations and exactly the named one ran"
    );

    // A name nothing holds is not a registration.
    let refused = invoke_llm_sanitize_request_registration(
        "llm-sanitize-door-nothing",
        request(),
        crate::api::runtime::LlmSanitizeRequestContext::with_identity(LlmCodecIdentity::None),
    )
    .await
    .expect_err("a name nothing registered");
    assert!(matches!(refused, FlowError::NotFound(_)), "{refused:?}");
    assert_eq!(
        counters.iter().map(calls).collect::<Vec<_>>(),
        [0, 1, 0],
        "a refused name ran nothing"
    );
}

/// A sanitizer that did not answer omits the payload — that is the family's rule — and
/// the door reports the reason, which is what a caller running the registration for
/// another process needs.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn a_sanitizer_that_did_not_answer_omits_the_payload_and_reports_it() {
    let _guard = lock_runtime();
    let scope = TestScope::push("llm-sanitize-failure-scope");
    let failing: LlmSanitizeRequestFn = Arc::new(|_request, _context| {
        Box::pin(async move { Err(FlowError::Internal("no".into())) })
    });
    let panicking: LlmSanitizeRequestFn =
        Arc::new(|_request, _context| Box::pin(async move { panic!("expected sanitizer panic") }));
    for (name, sanitizer) in [
        ("llm-sanitize-request-fails", failing),
        ("llm-sanitize-request-panics", panicking),
    ] {
        scope_register_llm_sanitize_request_guardrail(scope.uuid(), name, 0, sanitizer)
            .expect("registered");
        let outcome = invoke_llm_sanitize_request_registration(
            name,
            request(),
            crate::api::runtime::LlmSanitizeRequestContext::with_identity(LlmCodecIdentity::None),
        )
        .await
        .expect("the named registration");
        assert!(
            outcome.request.is_none(),
            "a request nobody could sanitize is not published"
        );
        let failure = outcome
            .failure
            .expect("a sanitizer that did not answer is reported");
        assert!(
            !failure.is_empty(),
            "the reason travels rather than only the fact"
        );
    }
}

/// The response door is the request door's twin, and the two families do not share a
/// door: a name only the request family holds is not reachable through the response one.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn the_response_door_runs_exactly_the_registration_it_names() {
    let _guard = lock_runtime();
    let scope = TestScope::push("llm-sanitize-response-scope");
    let (request_counter, request_sanitizer) = counting_request_sanitizer();
    scope_register_llm_sanitize_request_guardrail(
        scope.uuid(),
        "llm-sanitize-shared-name",
        0,
        request_sanitizer,
    )
    .expect("registered");
    let (response_a, sanitizer) = counting_response_sanitizer();
    scope_register_llm_sanitize_response_guardrail(
        scope.uuid(),
        "llm-sanitize-response-a",
        0,
        sanitizer,
    )
    .expect("registered");
    let (response_b, sanitizer) = counting_response_sanitizer();
    scope_register_llm_sanitize_response_guardrail(
        scope.uuid(),
        "llm-sanitize-response-b",
        1,
        sanitizer,
    )
    .expect("registered");

    let outcome = invoke_llm_sanitize_response_registration(
        "llm-sanitize-response-b",
        serde_json::json!({ "ok": true }),
        crate::api::runtime::LlmSanitizeResponseContext::with_identity(LlmCodecIdentity::None),
    )
    .await
    .expect("the named registration");
    assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
    assert!(outcome.response.is_some());
    assert_eq!(
        (
            calls(&response_a),
            calls(&response_b),
            calls(&request_counter)
        ),
        (0, 1, 0),
        "the response door ran its own registration and nothing else"
    );

    // The request family's name is not in the response family.
    let refused = invoke_llm_sanitize_response_registration(
        "llm-sanitize-shared-name",
        serde_json::json!({ "ok": true }),
        crate::api::runtime::LlmSanitizeResponseContext::with_identity(LlmCodecIdentity::None),
    )
    .await
    .expect_err("a name only the other family holds");
    assert!(matches!(refused, FlowError::NotFound(_)), "{refused:?}");
    assert_eq!(
        (
            calls(&response_a),
            calls(&response_b),
            calls(&request_counter)
        ),
        (0, 1, 0),
        "the refusal reached no registration"
    );
}

/// The door hands the sanitizer the context it was given.
///
/// This is the property the codec capability protocol rests on: a caller that can state
/// the codec identity is the caller that decides what the sanitizer may resolve, and a
/// door that manufactured its own context would be deciding that for itself.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn the_door_hands_the_sanitizer_the_context_it_was_given() {
    use std::sync::Mutex;

    let _guard = lock_runtime();
    let scope = TestScope::push("llm-sanitize-context-scope");
    let seen: Arc<Mutex<Vec<(LlmCodecIdentity, bool)>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = {
        let seen = Arc::clone(&seen);
        Arc::new(
            move |request: LlmRequest, context: crate::api::runtime::LlmSanitizeRequestContext| {
                let seen = Arc::clone(&seen);
                Box::pin(async move {
                    seen.lock()
                        .expect("the record")
                        .push((context.codec().clone(), context.resolve_codec().is_some()));
                    Ok(Some(request))
                })
                    as std::pin::Pin<
                        Box<
                            dyn std::future::Future<
                                    Output = crate::error::Result<Option<LlmRequest>>,
                                > + Send,
                        >,
                    >
            },
        ) as LlmSanitizeRequestFn
    };
    scope_register_llm_sanitize_request_guardrail(
        scope.uuid(),
        "llm-sanitize-context",
        0,
        recorder,
    )
    .expect("registered");

    let identity = LlmCodecIdentity::Runtime("runtime-chat".into());
    let outcome = invoke_llm_sanitize_request_registration(
        "llm-sanitize-context",
        request(),
        crate::api::runtime::LlmSanitizeRequestContext::with_identity(identity.clone()),
    )
    .await
    .expect("the named registration");
    assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
    assert_eq!(
        seen.lock().expect("the record").as_slice(),
        [(identity, false)],
        "the sanitizer saw the caller's identity, and an identity-only context resolves no codec"
    );

    // And the same door with a global registration: the rule is about the name, not about
    // where the registration was made.
    let (calls_made, sanitizer) = counting_request_sanitizer();
    let _ = crate::api::registry::deregister_llm_sanitize_request_guardrail("llm-sanitize-global");
    register_llm_sanitize_request_guardrail("llm-sanitize-global", 0, sanitizer)
        .expect("registered");
    let outcome = invoke_llm_sanitize_request_registration(
        "llm-sanitize-global",
        request(),
        crate::api::runtime::LlmSanitizeRequestContext::with_identity(LlmCodecIdentity::None),
    )
    .await
    .expect("the global registration");
    assert!(outcome.request.is_some());
    assert_eq!(calls(&calls_made), 1);
    let _ = crate::api::registry::deregister_llm_sanitize_request_guardrail("llm-sanitize-global");
}
