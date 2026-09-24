// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Event types for Agent Trajectory Observability Format (ATOF) runtime events.

use std::borrow::Cow;

pub use nemo_relay_types::api::event::*;
use nemo_relay_types::api::llm::LlmRequest;
use nemo_relay_types::codec::request::AnnotatedLlmRequest;
use nemo_relay_types::codec::response::AnnotatedLlmResponse;

use crate::api::registry::RuntimeRegistrationKind;
use crate::codec::resolve;

pub(crate) fn is_valid_event_metadata_attribute_key(key: &str) -> bool {
    key.split('.').all(|segment| {
        !segment.is_empty()
            && segment.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
    })
}

/// Core-only normalized LLM accessors for ATOF events.
///
/// These helpers use built-in codec resolution, so they live in the runtime
/// crate rather than the shared DTO crate.
pub trait EventNormalizationExt {
    /// Normalized LLM request: the codec annotation when present, otherwise a
    /// best-effort decode of the start-event input payload.
    ///
    /// The fallback decode requires the start-event input to be the serialized
    /// [`LlmRequest`] wire shape (`{headers, content}`) emitted by the managed
    /// LLM pipeline; events whose input is a bare payload or a non-LLM shape
    /// yield `None`.
    #[must_use]
    fn normalized_llm_request(&self) -> Option<Cow<'_, AnnotatedLlmRequest>>;

    /// Normalized LLM response: the codec annotation when present, otherwise a
    /// best-effort decode of the end-event output payload.
    #[must_use]
    fn normalized_llm_response(&self) -> Option<Cow<'_, AnnotatedLlmResponse>>;
}

impl EventNormalizationExt for Event {
    fn normalized_llm_request(&self) -> Option<Cow<'_, AnnotatedLlmRequest>> {
        if let Some(annotated) = self.annotated_request() {
            return Some(Cow::Borrowed(annotated.as_ref()));
        }
        let request: LlmRequest = serde_json::from_value(self.input()?.clone()).ok()?;
        // Managed LLM events use the provider route as the event name (for
        // example, "anthropic.messages"), which doubles as the codec hint for
        // shape-identical request bodies.
        resolve::normalize_request_with_hint(&request, Some(self.name())).map(Cow::Owned)
    }

    fn normalized_llm_response(&self) -> Option<Cow<'_, AnnotatedLlmResponse>> {
        if let Some(annotated) = self.annotated_response() {
            return Some(Cow::Borrowed(annotated.as_ref()));
        }
        resolve::normalize_response(self.output()?).map(Cow::Owned)
    }
}

/// Run exactly one mark sanitize guardrail, named by its registration.
///
/// A sanitize guardrail changes what observers see and never what the runtime does:
/// the chain it belongs to rewrites the fields an event would carry, and the call
/// itself is untouched. That is why a host can be asked to run one without being
/// trusted with the call.
///
/// The registration is chosen *here*, by an identity the kernel owns. A plugin has
/// no say in which guardrail of its class runs: it registers under names, the chain
/// holds one proxy per registration, and this runs exactly the one the proxy names.
/// Running the family instead would ask several guardrails the same question and
/// apply every answer.
pub async fn invoke_mark_sanitize_registration(
    registration: &str,
    event: Event,
) -> crate::error::Result<Event> {
    invoke_event_sanitize_registration(
        registration,
        event,
        RuntimeRegistrationKind::MarkSanitizeGuardrail,
    )
    .await
}

/// The scope-start direction of [`invoke_mark_sanitize_registration`].
pub async fn invoke_scope_sanitize_start_registration(
    registration: &str,
    event: Event,
) -> crate::error::Result<Event> {
    invoke_event_sanitize_registration(
        registration,
        event,
        RuntimeRegistrationKind::ScopeSanitizeStartGuardrail,
    )
    .await
}

/// The scope-end direction of [`invoke_mark_sanitize_registration`].
pub async fn invoke_scope_sanitize_end_registration(
    registration: &str,
    event: Event,
) -> crate::error::Result<Event> {
    invoke_event_sanitize_registration(
        registration,
        event,
        RuntimeRegistrationKind::ScopeSanitizeEndGuardrail,
    )
    .await
}

/// What the three event sanitize classes share: resolution and execution.
///
/// What is *not* shared is the class. Each public entry above names its own, so the
/// chain a proxy belongs to stays the chain whose event it is, and calling one
/// through another's door is not something the type system has to be trusted to
/// prevent.
async fn invoke_event_sanitize_registration(
    registration: &str,
    event: Event,
    kind: RuntimeRegistrationKind,
) -> crate::error::Result<Event> {
    let scope_stack = crate::api::runtime::current_scope_stack();
    let locals = scope_stack
        .read()
        .expect("scope stack lock poisoned")
        .snapshot_scope_local_registries(|registries| match kind {
            RuntimeRegistrationKind::MarkSanitizeGuardrail => &registries.mark_sanitize_guardrails,
            RuntimeRegistrationKind::ScopeSanitizeStartGuardrail => {
                &registries.scope_sanitize_start_guardrails
            }
            RuntimeRegistrationKind::ScopeSanitizeEndGuardrail => {
                &registries.scope_sanitize_end_guardrails
            }
            _ => unreachable!("this entry point serves the three event sanitize classes"),
        });
    let local_refs = locals.iter().collect::<Vec<_>>();
    let context = crate::api::runtime::global_context();
    let state = context
        .read()
        .map_err(|error| crate::error::FlowError::Internal(error.to_string()))?
        .registry_snapshot(&[kind]);
    let entries = crate::api::runtime::state::NemoRelayContextState::event_sanitize_entries(
        match kind {
            RuntimeRegistrationKind::MarkSanitizeGuardrail => &state.mark_sanitize_guardrails,
            RuntimeRegistrationKind::ScopeSanitizeStartGuardrail => {
                &state.scope_sanitize_start_guardrails
            }
            RuntimeRegistrationKind::ScopeSanitizeEndGuardrail => {
                &state.scope_sanitize_end_guardrails
            }
            _ => unreachable!("this entry point serves the three event sanitize classes"),
        },
        &local_refs,
        kind,
    );
    let entry = entries
        .into_iter()
        .find(|entry| entry.name == registration)
        .ok_or_else(|| {
            crate::error::FlowError::NotFound(format!(
                "no event sanitize guardrail of this class is registered as '{registration}'"
            ))
        })?;
    Ok(
        crate::api::runtime::state::NemoRelayContextState::event_sanitize_snapshot_chain(
            event,
            &[entry],
        )
        .await,
    )
}
