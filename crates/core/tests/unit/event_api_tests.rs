// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The exact-registration doors for the three event sanitize classes.
//!
//! These are the doors a host runs a plugin's registration through, so what they do
//! — which registration they run, what they do with the answer, and what they do when
//! there is no answer — is a contract rather than an implementation detail.
//!
//! Two rules shape how these tests are written, because the registries they use are
//! process-global and a suite that poisons its neighbours is worse than no suite:
//!
//! - A registration that *rewrites* an event is made scope-local, where only the task
//!   inside that scope is affected. A global sanitizer that changed the fields would
//!   change every other suite's events for as long as this module's tests run.
//! - A registration that has to be global — the ones that pin global lookup and
//!   local-versus-global precedence — counts its own calls and changes nothing. Which
//!   registration ran is a number the test owns, not a payload the whole process sees.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::api::event::{
    BaseEvent, Event, MarkEvent, ScopeCategory, ScopeEvent, invoke_mark_sanitize_registration,
    invoke_scope_sanitize_end_registration, invoke_scope_sanitize_start_registration,
};
use crate::api::registry::{
    register_mark_sanitize_guardrail, register_scope_sanitize_end_guardrail,
    register_scope_sanitize_start_guardrail, scope_register_mark_sanitize_guardrail,
};
use crate::api::runtime::EventSanitizeFn;
use crate::api::scope::{PopScopeParams, PushScopeParams, ScopeType, pop_scope, push_scope};
use crate::error::FlowError;

/// The crate's runtime lock, which the suites that touch process-global runtime state
/// take.
///
/// These tests register sanitizers and push scopes, and both are visible to every
/// other test in the process: a registration is in every chain, and a pushed scope
/// emits an event to every subscriber. Holding the runtime lock is what keeps them
/// from running beside the suites that assert on exactly those things — the same lock,
/// and the same reason, as `llm_api_tests`.
fn lock_runtime() -> std::sync::MutexGuard<'static, ()> {
    crate::shared_runtime::runtime_owner_test_mutex()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn mark_event(name: &str) -> Event {
    Event::Mark(MarkEvent::new(
        BaseEvent::builder()
            .name(name)
            .data_opt(Some(serde_json::json!({ "payload": "value" })))
            .metadata_opt(Some(serde_json::json!({ "key": "value" })))
            .build(),
        None,
        None,
    ))
}

fn scope_event(name: &str, category: ScopeCategory) -> Event {
    Event::Scope(ScopeEvent::new(
        BaseEvent::builder().name(name).build(),
        category,
        Vec::new(),
        crate::api::event::EventCategory::custom(),
        None,
    ))
}

/// A sanitizer that counts its own calls and leaves the fields alone.
fn counting() -> (Arc<AtomicUsize>, EventSanitizeFn) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let sanitizer: EventSanitizeFn = Arc::new(move |_event, fields| {
        let counter = Arc::clone(&counter);
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(fields)
        })
    });
    (calls, sanitizer)
}

/// A sanitizer that adds one metadata marker, for the tests that need to see the
/// answer applied to the published event. Registered scope-locally, always.
fn marker(name: &'static str) -> EventSanitizeFn {
    Arc::new(move |_event, mut fields| {
        Box::pin(async move {
            let mut metadata = match fields.metadata.take() {
                Some(crate::json::Json::Object(object)) => object,
                _ => serde_json::Map::new(),
            };
            metadata.insert(name.to_string(), crate::json::Json::Bool(true));
            fields.metadata = Some(crate::json::Json::Object(metadata));
            Ok(fields)
        })
    })
}

/// The markers an answer carries, for reading which registration ran.
fn markers(event: &Event) -> Vec<String> {
    event
        .metadata()
        .and_then(|metadata| metadata.as_object())
        .map(|metadata| {
            metadata
                .iter()
                .filter(|(_, value)| value.as_bool() == Some(true))
                .map(|(key, _)| key.clone())
                .filter(|key| key.starts_with("event-api-"))
                .collect()
        })
        .unwrap_or_default()
}

fn calls(counter: &Arc<AtomicUsize>) -> usize {
    counter.load(Ordering::SeqCst)
}

/// A pushed scope that pops when it is dropped.
///
/// A failing assertion must not leave this process's scope stack holding a scope for
/// the tests that run after it, and a scope-local registration must not outlive the
/// scope it was made in — which is one of the things tested here.
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

/// The mark door runs exactly the registration it names, and its neighbours in the
/// same family do not run.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn the_mark_door_runs_exactly_the_registration_it_names() {
    let _guard = lock_runtime();
    let names = ["event-api-mark-a", "event-api-mark-b", "event-api-mark-c"];
    for name in names {
        let _ = crate::api::registry::deregister_mark_sanitize_guardrail(name);
    }
    let mut counters = Vec::new();
    for (priority, name) in names.iter().enumerate() {
        let (counter, sanitizer) = counting();
        register_mark_sanitize_guardrail(name, priority as i32, sanitizer).expect("registered");
        counters.push(counter);
    }

    let outcome = invoke_mark_sanitize_registration("event-api-mark-b", mark_event("example.mark"))
        .await
        .expect("the named registration");
    assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
    assert_eq!(
        counters.iter().map(calls).collect::<Vec<_>>(),
        [0, 1, 0],
        "the family has three registrations and exactly the named one ran"
    );
    assert_eq!(
        outcome.event.name(),
        "example.mark",
        "a sanitizer changes what observers see, not what the event is"
    );

    for name in names {
        let _ = crate::api::registry::deregister_mark_sanitize_guardrail(name);
    }
}

/// The two scope directions are their own doors, and each runs exactly the
/// registration it names.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn the_scope_doors_run_exactly_the_registration_they_name() {
    let _guard = lock_runtime();
    let starts = ["event-api-start-a", "event-api-start-b"];
    let ends = ["event-api-end-a"];
    for name in starts {
        let _ = crate::api::registry::deregister_scope_sanitize_start_guardrail(name);
    }
    for name in ends {
        let _ = crate::api::registry::deregister_scope_sanitize_end_guardrail(name);
    }
    let (start_a, sanitizer) = counting();
    register_scope_sanitize_start_guardrail("event-api-start-a", 0, sanitizer).expect("registered");
    let (start_b, sanitizer) = counting();
    register_scope_sanitize_start_guardrail("event-api-start-b", 1, sanitizer).expect("registered");
    let (end_a, sanitizer) = counting();
    register_scope_sanitize_end_guardrail("event-api-end-a", 0, sanitizer).expect("registered");

    let started = invoke_scope_sanitize_start_registration(
        "event-api-start-b",
        scope_event("example.scope", ScopeCategory::Start),
    )
    .await
    .expect("the named start registration");
    assert!(started.failure.is_none(), "{:?}", started.failure);
    assert_eq!(
        (calls(&start_a), calls(&start_b), calls(&end_a)),
        (0, 1, 0),
        "the start door ran its own registration and neither neighbour"
    );

    let ended = invoke_scope_sanitize_end_registration(
        "event-api-end-a",
        scope_event("example.scope", ScopeCategory::End),
    )
    .await
    .expect("the named end registration");
    assert!(ended.failure.is_none(), "{:?}", ended.failure);
    assert_eq!(
        (calls(&start_a), calls(&start_b), calls(&end_a)),
        (0, 1, 1),
        "the end door ran its own registration only"
    );

    for name in starts {
        let _ = crate::api::registry::deregister_scope_sanitize_start_guardrail(name);
    }
    for name in ends {
        let _ = crate::api::registry::deregister_scope_sanitize_end_guardrail(name);
    }
}

/// A scope-local registration is visible to the door while its scope is active and is
/// not reachable at all once the scope that owns it is gone.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn a_scope_local_registration_is_reachable_by_its_name() {
    let _guard = lock_runtime();
    let scope = TestScope::push("event-api-scope");
    let (calls_made, sanitizer) = counting();
    scope_register_mark_sanitize_guardrail(scope.uuid(), "event-api-local", 0, sanitizer)
        .expect("a scope-local registration");

    let outcome = invoke_mark_sanitize_registration("event-api-local", mark_event("example.mark"))
        .await
        .expect("the scope-local registration");
    assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
    assert_eq!(calls(&calls_made), 1);

    drop(scope);
    let refused = invoke_mark_sanitize_registration("event-api-local", mark_event("example.mark"))
        .await
        .expect_err("a registration whose scope has closed");
    assert!(
        matches!(refused, FlowError::NotFound(_)),
        "a scope-local registration does not outlive its scope: {refused:?}"
    );
}

/// What the registration answers with is what the event is published with.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn the_answer_is_what_the_event_is_published_with() {
    let _guard = lock_runtime();
    let scope = TestScope::push("event-api-answer-scope");
    scope_register_mark_sanitize_guardrail(
        scope.uuid(),
        "event-api-answer",
        0,
        marker("event-api-answer"),
    )
    .expect("a scope-local registration");

    let outcome = invoke_mark_sanitize_registration("event-api-answer", mark_event("example.mark"))
        .await
        .expect("the named registration");
    assert_eq!(markers(&outcome.event), ["event-api-answer"]);
    assert_eq!(
        outcome.event.data(),
        Some(&serde_json::json!({ "payload": "value" })),
        "a sanitizer that changed nothing else left the payload alone"
    );
}

/// When one name is held twice, the door runs the entry the chain would run first.
///
/// A name is unique *within* a registry — a second registration under a name a
/// registry already holds is refused — so two entries can share a name only across
/// registries, and the rule is the merge's: ascending priority.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn a_name_held_twice_goes_to_the_entry_the_chain_would_run_first() {
    let _guard = lock_runtime();
    let _ = crate::api::registry::deregister_mark_sanitize_guardrail("event-api-twice");
    let (global, sanitizer) = counting();
    register_mark_sanitize_guardrail("event-api-twice", 10, sanitizer).expect("registered");
    let scope = TestScope::push("event-api-twice-scope");
    let (local, sanitizer) = counting();
    scope_register_mark_sanitize_guardrail(scope.uuid(), "event-api-twice", 1, sanitizer)
        .expect("registered");

    let outcome = invoke_mark_sanitize_registration("event-api-twice", mark_event("example.mark"))
        .await
        .expect("the name");
    assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
    assert_eq!(
        (calls(&local), calls(&global)),
        (1, 0),
        "the lower priority is the one the chain would run first"
    );

    drop(scope);
    let _ = crate::api::registry::deregister_mark_sanitize_guardrail("event-api-twice");
}

/// The tie: one name, one priority, two registries. The merge appends the globals
/// first and sorts stably, so the global registration is the one the chain would run
/// first, and the door agrees with the chain rather than with whichever order a merged
/// vector happened to be built in.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn a_name_held_twice_at_one_priority_goes_to_the_global_registration() {
    let _guard = lock_runtime();
    let _ = crate::api::registry::deregister_mark_sanitize_guardrail("event-api-tie");
    let (global, sanitizer) = counting();
    register_mark_sanitize_guardrail("event-api-tie", 5, sanitizer).expect("registered");
    let scope = TestScope::push("event-api-tie-scope");
    let (local, sanitizer) = counting();
    scope_register_mark_sanitize_guardrail(scope.uuid(), "event-api-tie", 5, sanitizer)
        .expect("registered");

    let outcome = invoke_mark_sanitize_registration("event-api-tie", mark_event("example.mark"))
        .await
        .expect("the name");
    assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
    assert_eq!(
        (calls(&global), calls(&local)),
        (1, 0),
        "on a tie the global registration is the one the chain would run first"
    );

    drop(scope);
    let _ = crate::api::registry::deregister_mark_sanitize_guardrail("event-api-tie");
}

/// A sanitizer that did not answer clears the observability fields — the family's
/// rule, unchanged — and the door says what happened, which is what a caller running
/// the registration for another process needs.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn a_sanitizer_that_did_not_answer_clears_the_fields_and_reports_it() {
    let _guard = lock_runtime();
    let scope = TestScope::push("event-api-failure-scope");
    let failing: EventSanitizeFn =
        Arc::new(|_event, _fields| Box::pin(async move { Err(FlowError::Internal("no".into())) }));
    let panicking: EventSanitizeFn =
        Arc::new(|_event, _fields| Box::pin(async move { panic!("expected sanitizer panic") }));
    for (name, sanitizer) in [
        ("event-api-mark-fails", failing),
        ("event-api-mark-panics", panicking),
    ] {
        scope_register_mark_sanitize_guardrail(scope.uuid(), name, 0, sanitizer)
            .expect("registered");
        let outcome = invoke_mark_sanitize_registration(name, mark_event("example.mark"))
            .await
            .expect("the named registration");
        let failure = outcome
            .failure
            .expect("a sanitizer that did not answer is reported");
        assert!(
            !failure.is_empty(),
            "the reason travels rather than only the fact"
        );
        let fields = outcome.event.sanitize_fields();
        assert!(
            fields.data.is_none() && fields.metadata.is_none() && fields.category_profile.is_none(),
            "a payload nobody could sanitize is not published: {fields:?}"
        );
        assert_eq!(
            outcome.event.name(),
            "example.mark",
            "the identity fields are untouched by a failure"
        );
    }
}

/// The class is the door: a registration of one family is not reachable through
/// another's, and a name nothing registered is not a registration.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn a_registration_is_reachable_only_through_its_own_class() {
    let _guard = lock_runtime();
    let _ = crate::api::registry::deregister_scope_sanitize_start_guardrail("event-api-class");
    let _ = crate::api::registry::deregister_mark_sanitize_guardrail("event-api-class");
    let (started, sanitizer) = counting();
    register_scope_sanitize_start_guardrail("event-api-class", 0, sanitizer).expect("registered");
    let (marked, sanitizer) = counting();
    register_mark_sanitize_guardrail("event-api-class", 0, sanitizer).expect("registered");

    // Each door runs its own registration under a name the other family also holds.
    let start = invoke_scope_sanitize_start_registration(
        "event-api-class",
        scope_event("example.scope", ScopeCategory::Start),
    )
    .await
    .expect("the start registration");
    assert!(start.failure.is_none(), "{:?}", start.failure);
    let mark = invoke_mark_sanitize_registration("event-api-class", mark_event("example.mark"))
        .await
        .expect("the mark registration");
    assert!(mark.failure.is_none(), "{:?}", mark.failure);
    assert_eq!((calls(&started), calls(&marked)), (1, 1));

    // And each door refuses what the other family holds, without running anything.
    for refused in [
        invoke_scope_sanitize_end_registration(
            "event-api-class",
            scope_event("example.scope", ScopeCategory::End),
        )
        .await,
        invoke_mark_sanitize_registration("event-api-class-nothing", mark_event("example.mark"))
            .await,
    ] {
        let error = refused.expect_err("a registration this door does not hold");
        assert!(
            matches!(error, FlowError::NotFound(_)),
            "a registration this class does not hold is not found: {error:?}"
        );
    }
    assert_eq!(
        (calls(&started), calls(&marked)),
        (1, 1),
        "a refused name ran nothing"
    );

    let _ = crate::api::registry::deregister_scope_sanitize_start_guardrail("event-api-class");
    let _ = crate::api::registry::deregister_mark_sanitize_guardrail("event-api-class");
}

/// A mark the runtime raises about a plugin's own failure is not offered to the event
/// sanitizers.
///
/// The rule matters because the record of a failure *is* a mark: if the chain that
/// failed is asked about the record, a sanitizer that cannot answer fails on it, the
/// runtime records that, and the record is a mark again. What these records carry is a
/// registration name and a reason the runtime wrote, so there is nothing in one for a
/// sanitizer to decide — and what a plugin emits is still published through the
/// ordinary path, shown to the sanitizers like any other mark.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn a_record_the_runtime_raises_is_not_offered_to_the_event_sanitizers() {
    let _guard = lock_runtime();
    // Both the sanitizer and the subscriber are scope-local: an emitting test that
    // registered either process-globally would publish into other suites' assertions.
    let scope = TestScope::push("event-api-record-scope");
    let (seen, sanitizer) = counting();
    scope_register_mark_sanitize_guardrail(scope.uuid(), "event-api-record", 0, sanitizer)
        .expect("a scope-local registration");
    crate::api::subscriber::scope_register_subscriber(
        scope.uuid(),
        "event-api-record-witness",
        Arc::new(|_event: &Event| {}),
    )
    .expect("a scope-local subscriber");

    // An ordinary mark: the sanitizer is shown it.
    crate::api::scope::event(
        crate::api::scope::EmitMarkEventParams::builder()
            .name("event-api-mark-ordinary")
            .build(),
    )
    .expect("an emitted mark");
    crate::api::subscriber::flush_subscribers().expect("a flush");
    assert_eq!(
        calls(&seen),
        1,
        "an ordinary mark is offered to the mark sanitizers"
    );

    // A runtime record: it is not.
    crate::api::scope::runtime_mark(
        crate::api::scope::EmitMarkEventParams::builder()
            .name("nemo.plugin.sanitize.failed")
            .data_opt(Some(serde_json::json!({ "registration": "example" })))
            .build(),
    )
    .expect("a runtime mark");
    crate::api::subscriber::flush_subscribers().expect("a flush");
    assert_eq!(
        calls(&seen),
        1,
        "the runtime's own record is not offered to the chain that failed"
    );
}

/// The doors claim the process the way every other entry point does.
///
/// The check is what keeps a second binding from running a registration in a process
/// another binding owns, so the door has to make it *before* it resolves anything: a
/// door that reached the registry first would have run in the wrong process. This
/// authors the refused state directly — a published owner and a different current
/// binding — and puts the process back the moment the call returns, which is why it
/// takes this module's lock and the owner lock: a process-global state a neighbouring
/// test could observe is worth holding for as short a time as possible. The suite runs
/// one test per process in CI for the same reason.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes access to global runtime state.
async fn a_door_refuses_a_process_owned_by_another_binding() {
    let _guard = lock_runtime();
    let major = env!("CARGO_PKG_VERSION")
        .split('.')
        .next()
        .expect("a version");
    let refused = {
        crate::shared_runtime::reset_runtime_owner_for_tests();
        unsafe {
            std::env::set_var(
                crate::shared_runtime::OWNER_TOKEN_ENV,
                format!(
                    "pid={};binding=python;version={major}.0.0",
                    std::process::id()
                ),
            );
            std::env::set_var(crate::shared_runtime::BINDING_KIND_ENV, "node");
        }
        let refused =
            invoke_mark_sanitize_registration("event-api-mark-a", mark_event("example.mark"))
                .await
                .expect_err("a door in a process another binding owns");
        unsafe {
            std::env::remove_var(crate::shared_runtime::OWNER_TOKEN_ENV);
            std::env::remove_var(crate::shared_runtime::BINDING_KIND_ENV);
        }
        crate::shared_runtime::reset_runtime_owner_for_tests();
        refused
    };
    assert!(
        matches!(refused, FlowError::InvalidArgument(_)),
        "the owner check refuses before the registry is read: {refused:?}"
    );
    assert!(
        refused
            .to_string()
            .contains("multiple bindings in one process"),
        "{refused}"
    );
}
