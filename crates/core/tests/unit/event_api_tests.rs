// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The exact-registration doors for the three event sanitize classes.
//!
//! These are the doors a host runs a plugin's registration through, so what they do
//! when the registration answers and when it does not is a contract rather than an
//! implementation detail: the event comes back as it should be published, and the
//! second thing the door reports is whether a sanitizer actually sanitized it.

use std::sync::Arc;

use crate::api::event::{
    BaseEvent, Event, MarkEvent, ScopeCategory, ScopeEvent, invoke_mark_sanitize_registration,
    invoke_scope_sanitize_end_registration, invoke_scope_sanitize_start_registration,
};
use crate::api::registry::{
    register_mark_sanitize_guardrail, register_scope_sanitize_start_guardrail,
};
use crate::api::runtime::EventSanitizeFn;

/// The registries are process-global, so these tests take turns rather than
/// observing each other's registrations.
static EVENT_SANITIZE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

/// A sanitizer that adds one metadata marker and leaves everything else alone.
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

/// The door the caller names is the registration that runs, and the answer is what
/// the event is published with.
#[tokio::test]
async fn the_mark_door_runs_exactly_the_registration_it_names() {
    let _guard = EVENT_SANITIZE_TEST_LOCK.lock().await;
    for name in ["event-api-mark-a", "event-api-mark-b", "event-api-mark-c"] {
        let _ = crate::api::registry::deregister_mark_sanitize_guardrail(name);
    }
    register_mark_sanitize_guardrail("event-api-mark-a", 0, marker("mark_a")).expect("registered");
    register_mark_sanitize_guardrail("event-api-mark-b", 1, marker("mark_b")).expect("registered");
    register_mark_sanitize_guardrail("event-api-mark-c", 2, marker("mark_c")).expect("registered");

    let outcome = invoke_mark_sanitize_registration("event-api-mark-b", mark_event("example.mark"))
        .await
        .expect("the named registration");
    assert!(
        outcome.failure.is_none(),
        "the sanitizer answered: {:?}",
        outcome.failure
    );
    let metadata = outcome
        .event
        .metadata()
        .and_then(|metadata| metadata.as_object())
        .expect("the marker's metadata");
    assert_eq!(
        metadata.get("mark_b"),
        Some(&crate::json::Json::Bool(true)),
        "{metadata:?}"
    );
    for neighbour in ["mark_a", "mark_c"] {
        assert!(
            metadata.get(neighbour).is_none(),
            "the door ran {neighbour} as well, which is the family rather than the \
             registration: {metadata:?}"
        );
    }
    assert_eq!(
        outcome.event.name(),
        "example.mark",
        "a sanitizer changes what observers see, not what the event is"
    );

    for name in ["event-api-mark-a", "event-api-mark-b", "event-api-mark-c"] {
        let _ = crate::api::registry::deregister_mark_sanitize_guardrail(name);
    }
}

/// A sanitizer that did not answer clears the observability fields — that is the
/// family's rule and it does not change — and the door says what happened, which is
/// what a caller running the registration for another process needs.
#[tokio::test]
async fn a_sanitizer_that_did_not_answer_clears_the_fields_and_reports_it() {
    let _guard = EVENT_SANITIZE_TEST_LOCK.lock().await;
    let failing: EventSanitizeFn = Arc::new(|_event, _fields| {
        Box::pin(async move { Err(crate::error::FlowError::Internal("no".into())) })
    });
    let panicking: EventSanitizeFn =
        Arc::new(|_event, _fields| Box::pin(async move { panic!("expected sanitizer panic") }));
    for (name, sanitizer) in [
        ("event-api-mark-fails", failing),
        ("event-api-mark-panics", panicking),
    ] {
        let _ = crate::api::registry::deregister_mark_sanitize_guardrail(name);
        register_mark_sanitize_guardrail(name, 0, sanitizer).expect("registered");

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
        let _ = crate::api::registry::deregister_mark_sanitize_guardrail(name);
    }
}

/// The class is the door: a registration of one family is not reachable through
/// another's, and a name nothing registered is not a registration.
#[tokio::test]
async fn a_registration_is_reachable_only_through_its_own_class() {
    let _guard = EVENT_SANITIZE_TEST_LOCK.lock().await;
    let _ =
        crate::api::registry::deregister_scope_sanitize_start_guardrail("event-api-scope-start");
    register_scope_sanitize_start_guardrail("event-api-scope-start", 0, marker("scope_start"))
        .expect("registered");

    // Its own door answers.
    let outcome = invoke_scope_sanitize_start_registration(
        "event-api-scope-start",
        scope_event("example.scope", ScopeCategory::Start),
    )
    .await
    .expect("the named registration");
    assert!(outcome.failure.is_none(), "{:?}", outcome.failure);

    // The mark door does not know it, and neither do the end direction or a name
    // nothing registered.
    for refused in [
        invoke_mark_sanitize_registration("event-api-scope-start", mark_event("example.mark"))
            .await,
        invoke_scope_sanitize_end_registration(
            "event-api-scope-start",
            scope_event("example.scope", ScopeCategory::End),
        )
        .await,
        invoke_mark_sanitize_registration("event-api-mark-nothing", mark_event("example.mark"))
            .await,
    ] {
        let error = refused.expect_err("a door this registration is not behind");
        assert!(
            matches!(error, crate::error::FlowError::NotFound(_)),
            "a registration this class does not hold is not found: {error:?}"
        );
    }

    let _ =
        crate::api::registry::deregister_scope_sanitize_start_guardrail("event-api-scope-start");
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
async fn a_record_the_runtime_raises_is_not_offered_to_the_event_sanitizers() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let _guard = EVENT_SANITIZE_TEST_LOCK.lock().await;
    let seen = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&seen);
    let counting: EventSanitizeFn = Arc::new(move |_event, fields| {
        let counted = Arc::clone(&counted);
        Box::pin(async move {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(fields)
        })
    });
    let _ = crate::api::registry::deregister_mark_sanitize_guardrail("event-api-mark-counting");
    register_mark_sanitize_guardrail("event-api-mark-counting", 0, counting).expect("registered");
    // An event with no subscriber is dropped before it is sanitized, so a subscriber
    // is what makes the chain run at all.
    let _ =
        crate::api::subscriber::deregister_subscriber("event-api-mark-witness").unwrap_or(false);
    crate::api::subscriber::register_subscriber(
        "event-api-mark-witness",
        Arc::new(|_event: &Event| {}),
    )
    .expect("a subscriber");

    // An ordinary mark: the sanitizer is shown it.
    crate::api::scope::event(
        crate::api::scope::EmitMarkEventParams::builder()
            .name("event-api-mark-ordinary")
            .build(),
    )
    .expect("an emitted mark");
    crate::api::subscriber::flush_subscribers().expect("a flush");
    assert_eq!(
        seen.load(Ordering::SeqCst),
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
        seen.load(Ordering::SeqCst),
        1,
        "the runtime's own record is not offered to the chain that failed"
    );

    let _ = crate::api::subscriber::deregister_subscriber("event-api-mark-witness");
    let _ = crate::api::registry::deregister_mark_sanitize_guardrail("event-api-mark-counting");
}
