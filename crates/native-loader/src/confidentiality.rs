// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A sentinel in every observable field, and the assertion the failure paths owe.
//!
//! A sanitizer decides what other people may see. When it refuses, fails, or
//! answers with something unreadable, the property that has to hold is not "the
//! proxy returned an error" — it is that *the data it was asked to sanitize cannot
//! reach anything the runtime publishes afterwards*. An error and a withheld
//! payload are different facts, and only the second is the security property.
//!
//! So these helpers plant an unmistakable value in every field a sanitizer can see
//! — the event name, the payload, the metadata, the category profile, and a scope
//! event's attributes — force one failure path, and then look for those values in
//! everything the runtime could publish: the fields the answer carried, the refusal
//! that came back, the event the chain would emit. A test asserting only `is_err()`
//! would pass while the payload travelled back in the error's own text.
//!
//! The suites that need this sit on both sides of the boundary: the host's own
//! invocation tests are in this crate, and the process-boundary qualification runs
//! from `tests/`, which can only see public API. It is public for the same reason
//! [`crate::conformance`] is — two suites that must not drift.

use std::sync::atomic::{AtomicU64, Ordering};

use nemo_relay::api::event::Event;
use nemo_relay_plugin_protocol::{
    EventSanitizeFields, PluginEventSanitizeCall, PluginEventSanitizeClass, PluginExecutionOutcome,
};

/// The prefix every planted value carries.
///
/// The values are the assertion, but the prefix is the net: a test finds a planted
/// value by name, and finds a field that was *transformed* on its way to somewhere
/// observable by the marker it still carries.
pub const SENTINEL_MARKER: &str = "SECRET_NEMO";

/// Distinguishes one call's sentinels from the next, so a test that runs one path
/// after another cannot read an earlier path's value as its own leak.
fn next_nonce() -> u64 {
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

/// The exact values one call planted, and the assertion over them.
///
/// The assertion is deliberately not "the call failed". It is that none of these
/// values — nor the marker they carry — appears in anything a runtime could
/// publish, which is a claim about the payload rather than about the control flow.
pub struct ConfidentialitySentinel {
    values: Vec<String>,
}

impl ConfidentialitySentinel {
    /// The exact strings this call planted.
    pub fn planted(&self) -> &[String] {
        &self.values
    }

    /// Everything in `text` that must not have been there.
    ///
    /// A planted value is one leak. The bare marker is another: a field the runtime
    /// transformed rather than dropped still says where it came from.
    pub fn leaked_into(&self, text: &str) -> Vec<String> {
        let mut leaked: Vec<String> = self
            .values
            .iter()
            .filter(|value| text.contains(value.as_str()))
            .cloned()
            .collect();
        if leaked.is_empty() && text.contains(SENTINEL_MARKER) {
            leaked.push(format!("{SENTINEL_MARKER} without a planted value"));
        }
        leaked
    }

    /// Assert that nothing observable in `text` carries a sentinel.
    ///
    /// # Panics
    /// Panics with the leaked values when anything a caller could publish still
    /// carries one, because that is the security property and not a style rule.
    pub fn assert_absent(&self, what: &str, text: &str) {
        let leaked = self.leaked_into(text);
        assert!(
            leaked.is_empty(),
            "{} carried sanitizer input to something publishable: {leaked:?}\n\
             planted: {:?}",
            what,
            self.values
        );
    }

    /// The same assertion over an event, whole.
    pub fn assert_event_absent(&self, what: &str, event: &Event) {
        self.assert_absent(what, &observable_of_event(event));
    }

    /// The same assertion over the fields a sanitizer answered with.
    pub fn assert_fields_absent(&self, what: &str, fields: &EventSanitizeFields) {
        self.assert_absent(what, &observable_of_fields(fields));
    }

    /// The same assertion over a value of any shape.
    pub fn assert_value_absent(&self, what: &str, value: &serde_json::Value) {
        self.assert_absent(what, &value.to_string());
    }

    /// The same assertion over one invocation's outcome, as the kernel reads it.
    ///
    /// The whole outcome rather than its success case: a refusal carries text, and
    /// text is where a payload that was supposed to be withheld comes back.
    pub fn assert_outcome_absent(&self, what: &str, outcome: &PluginExecutionOutcome) {
        self.assert_absent(
            what,
            &serde_json::to_string(outcome).unwrap_or_else(|_| format!("{outcome:?}")),
        );
    }
}

/// Everything about an event that a runtime could publish.
fn observable_of_event(event: &Event) -> String {
    event.to_json_value().to_string()
}

/// Everything about the fields a sanitizer answered with.
fn observable_of_fields(fields: &EventSanitizeFields) -> String {
    serde_json::to_value(fields)
        .map(|value| value.to_string())
        .unwrap_or_else(|error| format!("the fields did not serialize: {error}"))
}

/// The sentinels one event carries, planted in every field a sanitizer can see.
///
/// Mark and scope events differ in one field — a scope event carries its phase —
/// so the two builders below share this rather than describing the same fields
/// twice.
struct Planting {
    nonce: u64,
    values: Vec<String>,
}

impl Planting {
    fn new() -> Self {
        Self {
            nonce: next_nonce(),
            values: Vec::new(),
        }
    }

    /// A value that says what it is and which call planted it.
    fn plant(&mut self, field: &str) -> String {
        let value = format!("{SENTINEL_MARKER}_{field}_{}", self.nonce);
        self.values.push(value.clone());
        value
    }

    /// The observability fields, sentinel in every one of them.
    fn fields(&mut self) -> EventSanitizeFields {
        let data_a = self.plant("FIELD_A_DATA");
        let data_b = self.plant("FIELD_B_DATA");
        let metadata_b = self.plant("FIELD_B_METADATA");
        let profile_a = self.plant("FIELD_A_PROFILE");
        EventSanitizeFields {
            data: Some(serde_json::json!({
                "field_a": data_a,
                "nested": { "field_b": data_b },
            })),
            category_profile: Some(nemo_relay::api::event::CategoryProfile {
                subtype: Some(profile_a.clone()),
                extra: std::collections::BTreeMap::from([(
                    "field_a".to_string(),
                    serde_json::Value::String(profile_a),
                )]),
                ..Default::default()
            }),
            metadata: Some(serde_json::json!({ "field_b": metadata_b })),
        }
    }

    fn finish(self) -> ConfidentialitySentinel {
        ConfidentialitySentinel {
            values: self.values,
        }
    }
}

/// A mark event with a sentinel in every field a sanitizer can see.
pub fn sentinel_mark_event() -> (Event, ConfidentialitySentinel) {
    let mut planting = Planting::new();
    let name = planting.plant("EVENT_NAME");
    let fields = planting.fields();
    let mut event = Event::Mark(nemo_relay::api::event::MarkEvent::new(
        nemo_relay::api::event::BaseEvent::builder()
            .name(name)
            .data_opt(fields.data.clone())
            .metadata_opt(fields.metadata.clone())
            .build(),
        None,
        fields.category_profile.clone(),
    ));
    // The event's own fields are the projection's; keeping them identical is what
    // makes "the sentinel cannot be published" a statement about the same data the
    // sanitizer was shown.
    event.apply_sanitize_fields(fields);
    (event, planting.finish())
}

/// A scope event with a sentinel in every field a sanitizer can see.
///
/// The phase is planted as well, because for these classes it is part of the
/// identity a sanitizer decides on rather than a field it may rewrite.
pub fn sentinel_scope_event(
    scope_category: nemo_relay::api::event::ScopeCategory,
) -> (Event, ConfidentialitySentinel) {
    use nemo_relay::api::event::{BaseEvent, ScopeEvent};

    let mut planting = Planting::new();
    let name = planting.plant("EVENT_NAME");
    let scope = planting.plant("SCOPE");
    let fields = planting.fields();
    let mut event = Event::Scope(ScopeEvent::new(
        BaseEvent::builder()
            .name(name)
            .data_opt(fields.data.clone())
            .metadata_opt(fields.metadata.clone())
            .build(),
        scope_category,
        vec![scope.clone()],
        nemo_relay::api::event::EventCategory::custom(),
        fields.category_profile.clone(),
    ));
    event.apply_sanitize_fields(fields);
    (event, planting.finish())
}

/// The mutable observability fields, with a sentinel in every one of them.
///
/// This is what a sanitizer may *rewrite*, which is narrower than what it is shown:
/// an event's name and its scope phase are identity rather than payload, so a value
/// planted there is published by the runtime whatever the sanitizer decides. A test
/// asserting that a failure cannot publish its input wants these fields, and a test
/// asserting that a sanitizer cannot rename an event wants the projection.
pub fn sentinel_fields() -> (EventSanitizeFields, ConfidentialitySentinel) {
    let mut planting = Planting::new();
    let fields = planting.fields();
    (fields, planting.finish())
}

/// The projection a kernel sends for one of the three classes, sentinel in every
/// field it carries.
///
/// This is what the host is handed and what a plugin's callback is shown, so it is
/// the shape a failure path has to keep from reaching the runtime.
///
/// The phase is not one of those fields even though it is on the wire: it is
/// derived from the class — the class *is* the capability, and the string states the
/// same fact for a reader — so a projection carrying a planted value there would be
/// describing a phase that does not exist, and the host refuses it before anything
/// runs.
pub fn sentinel_sanitize_call(
    class: PluginEventSanitizeClass,
) -> (PluginEventSanitizeCall, ConfidentialitySentinel) {
    let mut planting = Planting::new();
    let name = planting.plant("EVENT_NAME");
    let fields = planting.fields();
    (
        PluginEventSanitizeCall {
            class,
            name,
            // Written as the runtime names it rather than as a second copy of the
            // spelling: one place decides what a phase is called on the wire.
            scope_category: class.scope_category().and_then(|category| {
                serde_json::to_value(category)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
            }),
            // The two read-only discriminators are named rather than planted: they are
            // what a sanitizer decides *with*, so a value planted in one would be a
            // decision the test invented, and a plugin that branched on it would be
            // branching on the test rather than on the event. A category that exists
            // (and no data schema, which is the ordinary case) is what a sanitizer is
            // shown.
            category: Some(nemo_relay::api::event::EventCategory::llm()),
            data_schema: None,
            fields,
        },
        planting.finish(),
    )
}

/// Fields that are valid and far larger than any small response budget: the shape a
/// sanitizer is refused for answering with, with a sentinel inside it so the
/// refusal can be checked for it.
///
/// The padding is what makes the answer oversized, and the sentinel is what makes
/// "the answer was refused" different from "the answer was cut down and sent".
pub fn oversized_fields(padding_bytes: usize) -> (EventSanitizeFields, ConfidentialitySentinel) {
    let mut planting = Planting::new();
    let marker = planting.plant("OVERSIZED");
    let filler = format!("{marker}{}", "x".repeat(padding_bytes));
    let fields = EventSanitizeFields {
        data: Some(serde_json::json!({ "padding": filler })),
        metadata: Some(serde_json::json!({ "padding": marker })),
        ..Default::default()
    };
    (fields, planting.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The helper has to be able to fail, or every assertion written with it is a
    /// comment. This is the negative check: the same assertion over a value that
    /// does carry a planted sentinel, and over one that carries the marker alone.
    #[test]
    fn the_sentinel_assertion_refuses_a_leak_and_accepts_a_withheld_payload() {
        let (_, sentinel) = sentinel_mark_event();
        let planted = sentinel.planted().first().expect("a planted value").clone();

        let leaked = sentinel.leaked_into(&format!("a refusal mentioning {planted}"));
        assert_eq!(leaked.as_slice(), std::slice::from_ref(&planted));
        let transformed = sentinel.leaked_into("a field that says SECRET_NEMO_but_was_reshaped");
        assert_eq!(transformed.len(), 1, "{transformed:?}");
        assert!(
            sentinel.leaked_into("the payload was withheld").is_empty(),
            "a withheld payload is the answer the property wants"
        );

        let panic = std::panic::catch_unwind(|| {
            sentinel.assert_absent("the published event", &format!("carries {planted}"))
        });
        assert!(panic.is_err(), "the assertion must fail on a leak");
    }

    /// Every planted value is distinguishable from every other, at both levels:
    /// the event's fields and the projection's own fields.
    #[test]
    fn every_observable_field_carries_its_own_sentinel() {
        let (event, sentinel) = sentinel_mark_event();
        let observable = observable_of_event(&event);
        for value in sentinel.planted() {
            assert!(
                observable.contains(value.as_str()),
                "the event should carry {value}"
            );
        }
        let (call, call_sentinel) = sentinel_sanitize_call(PluginEventSanitizeClass::ScopeStart);
        let carried = serde_json::to_string(&call).expect("a serializable projection");
        for value in call_sentinel.planted() {
            assert!(
                carried.contains(value.as_str()),
                "the projection should carry {value}"
            );
        }
        assert!(
            call.scope_category.is_some(),
            "a scope class carries its phase, because that is identity rather than a field"
        );
    }
}
