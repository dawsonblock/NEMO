// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::api::runtime::EventSubscriberFn;
use crate::api::runtime::NemoRelayContextState;
use crate::api::runtime::current_scope_stack;
use crate::api::runtime::flush_subscribers as flush_runtime_subscribers;
use crate::api::runtime::global_context;
use crate::api::shared::ensure_runtime_owner;
use crate::error::{FlowError, Result};
use crate::json::Json;
use std::sync::Arc;

/// Run exactly one event subscriber, named by its registration.
///
/// The runtime's own dispatch runs every subscriber for an event, which is what
/// the runtime needs and what a host cannot use: a host holds one plugin's
/// registrations and has to run *that* subscriber when the kernel asks, or the
/// kernel's subscriber list — which holds one proxy per registration — would run
/// the plugin's whole set once per proxy.
///
/// A subscriber that panics is reported as an error rather than unwinding into
/// the caller, for the same reason the runtime's dispatcher catches it: an
/// observer that fails may not take down the work it was watching.
///
/// # Errors
/// `NotFound` when nothing is registered under that name, which is what a caller
/// needs to refuse the delivery rather than appearing to have delivered it.
pub fn invoke_subscriber_registration(
    registration: &str,
    event: &crate::api::event::Event,
) -> Result<()> {
    ensure_runtime_owner()?;
    let subscriber = {
        let context = global_context();
        let state = context
            .read()
            .map_err(|error| FlowError::Internal(error.to_string()))?;
        state.event_subscribers.get(registration).cloned()
    };
    let Some(subscriber) = subscriber else {
        return Err(FlowError::NotFound(format!(
            "no event subscriber is registered as '{registration}'"
        )));
    };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| subscriber(event)))
        .map_err(|_| FlowError::Internal(format!("subscriber '{registration}' panicked")))
}

/// Run exactly one event metadata injector, named by its registration.
///
/// An injector is *additive*: it answers with the metadata keys it wants added,
/// and the runtime inserts them. Its failure rule follows from that — the runtime's
/// own injector chain says so in a comment, and it is worth repeating here because
/// it is the opposite of the sanitizer's: **an injector that cannot answer
/// preserves the event and continues without injection**. A sanitizer withholds a
/// payload it could not sanitize; an injector adds nothing it could not compute.
///
/// # Errors
/// `NotFound` when nothing is registered under that name, which is what a caller
/// needs to refuse the delivery rather than appear to have injected nothing.
pub async fn invoke_event_metadata_injector_registration(
    registration: &str,
    event: &crate::api::event::Event,
) -> Result<std::collections::BTreeMap<String, Json>> {
    ensure_runtime_owner()?;
    let entry = {
        let scope_stack = current_scope_stack();
        let scope_locals = scope_stack
            .read()
            .expect("scope stack lock poisoned")
            .snapshot_scope_local_registries(|registries| &registries.event_metadata_injectors);
        let scope_local_refs = scope_locals.iter().collect::<Vec<_>>();
        let context = global_context();
        let state = context
            .read()
            .map_err(|error| FlowError::Internal(error.to_string()))?;
        NemoRelayContextState::event_metadata_injector_entries(
            &state.event_metadata_injectors,
            &scope_local_refs,
        )
        .into_iter()
        .find(|entry| entry.name == registration)
    };
    let Some(entry) = entry else {
        return Err(FlowError::NotFound(format!(
            "no event metadata injector is registered as '{registration}'"
        )));
    };
    let payload = Arc::new(event.clone());
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (entry.payload)(Arc::clone(&payload))
    })) {
        Ok(future) => future.await,
        Err(_) => Err(FlowError::Internal(format!(
            "metadata injector '{registration}' panicked"
        ))),
    }
}

/// Register a global lifecycle event subscriber.
///
/// The subscriber is added to the process-wide registry and receives every
/// emitted scope, tool, LLM, and mark event until it is deregistered.
///
/// # Parameters
/// - `name`: Unique subscriber name in the global registry.
/// - `callback`: Subscriber callback invoked for each emitted event.
///
/// # Returns
/// A [`Result`] that is `Ok(())` when the subscriber was registered.
///
/// # Errors
/// Returns [`FlowError::AlreadyExists`] when another global subscriber is
/// already registered under the same name.
///
/// # Notes
/// Global subscribers remain active across scopes until explicitly removed.
/// Native event-producing APIs enqueue subscriber work and return without
/// waiting for callbacks.
pub fn register_subscriber(name: &str, callback: EventSubscriberFn) -> Result<()> {
    ensure_runtime_owner()?;
    let context = global_context();
    let mut state = context
        .write()
        .map_err(|error| FlowError::Internal(error.to_string()))?;
    if state.event_subscribers.contains_key(name) {
        return Err(FlowError::AlreadyExists(format!(
            "{name} subscriber already exists"
        )));
    }
    state.event_subscribers.insert(name.to_string(), callback);
    Ok(())
}

/// Deregister a global lifecycle event subscriber.
///
/// This removes the named subscriber from the process-wide registry.
///
/// # Parameters
/// - `name`: Global subscriber name to remove.
///
/// # Returns
/// A [`Result`] containing `true` when a subscriber was removed and `false`
/// when the name was not registered.
///
/// # Errors
/// Returns an error when the global registry lock cannot be acquired safely.
///
/// # Notes
/// Deregistration affects only future event delivery. Already emitted events
/// carry a subscriber snapshot, so queued callbacks from that snapshot may
/// still run after deregistration.
pub fn deregister_subscriber(name: &str) -> Result<bool> {
    ensure_runtime_owner()?;
    let context = global_context();
    let mut state = context
        .write()
        .map_err(|error| FlowError::Internal(error.to_string()))?;
    Ok(state.event_subscribers.remove(name).is_some())
}

/// Wait for all subscriber callbacks and managed terminal publications
/// registered before this call to finish, including publications emitted
/// transitively by those callbacks.
///
/// A direct re-entrant call from queued publication middleware returns without
/// waiting. Publication middleware must not move such a flush into
/// `tokio::spawn`, `tokio::task::spawn_blocking`, or another unmarked task or
/// thread because the publication cannot complete while awaiting that flush.
///
/// Native targets deliver subscriber callbacks on a background dispatcher so
/// event-producing APIs do not wait for observer work. Call this helper from
/// tests, shutdown paths, or exporter lifecycle code when callers need a
/// deterministic observation barrier.
pub fn flush_subscribers() -> Result<()> {
    ensure_runtime_owner()?;
    flush_runtime_subscribers()
}

/// Register a scope-local lifecycle event subscriber.
///
/// The subscriber remains active only while the target scope is still present
/// on the active scope stack.
///
/// # Parameters
/// - `scope_uuid`: UUID of the owning scope.
/// - `name`: Unique subscriber name within the owning scope.
/// - `callback`: Subscriber callback invoked for events emitted under that
///   scope hierarchy.
///
/// # Returns
/// A [`Result`] that is `Ok(())` when the subscriber was registered.
///
/// # Errors
/// Returns [`FlowError::NotFound`] when the scope does not exist on the active
/// stack and [`FlowError::AlreadyExists`] when the scope already owns a
/// subscriber with the same name.
///
/// # Notes
/// Scope-local subscribers are removed automatically when the owning scope is
/// popped. Native event-producing APIs enqueue subscriber work and return
/// without waiting for callbacks.
pub fn scope_register_subscriber(
    scope_uuid: &uuid::Uuid,
    name: &str,
    callback: EventSubscriberFn,
) -> Result<()> {
    ensure_runtime_owner()?;
    let scope_stack = current_scope_stack();
    let mut guard = scope_stack.write().expect("scope stack lock poisoned");
    let registries = guard
        .local_registries_mut(scope_uuid)
        .ok_or_else(|| FlowError::NotFound(format!("scope {scope_uuid} not found")))?;
    if registries.event_subscribers.contains_key(name) {
        return Err(FlowError::AlreadyExists(format!(
            "{name} subscriber already exists"
        )));
    }
    registries
        .event_subscribers
        .insert(name.to_string(), callback);
    Ok(())
}

// Internal best-effort variant used by async subscriber callbacks such as the
// ATIF dispatcher. Those callbacks may run after the observed root scope has
// already closed, or while the scope stack is locked by event-producing code,
// so this returns a normal error instead of blocking or panicking.
pub(crate) fn try_scope_register_subscriber(
    scope_uuid: &uuid::Uuid,
    name: &str,
    callback: EventSubscriberFn,
) -> Result<()> {
    ensure_runtime_owner()?;
    let scope_stack = current_scope_stack();
    let mut guard = scope_stack
        .try_write()
        .map_err(|error| FlowError::Internal(format!("scope stack lock unavailable: {error}")))?;
    let registries = guard
        .local_registries_mut(scope_uuid)
        .ok_or_else(|| FlowError::NotFound(format!("scope {scope_uuid} not found")))?;
    if registries.event_subscribers.contains_key(name) {
        return Err(FlowError::AlreadyExists(format!(
            "{name} subscriber already exists"
        )));
    }
    registries
        .event_subscribers
        .insert(name.to_string(), callback);
    Ok(())
}

// Matching non-blocking teardown path for async callbacks that must not wait on
// the scope-stack write lock during subscriber shutdown.
pub(crate) fn try_scope_deregister_subscriber(scope_uuid: &uuid::Uuid, name: &str) -> Result<bool> {
    ensure_runtime_owner()?;
    let scope_stack = current_scope_stack();
    let mut guard = scope_stack
        .try_write()
        .map_err(|error| FlowError::Internal(format!("scope stack lock unavailable: {error}")))?;
    let registries = guard
        .local_registries_mut(scope_uuid)
        .ok_or_else(|| FlowError::NotFound(format!("scope {scope_uuid} not found")))?;
    Ok(registries.event_subscribers.remove(name).is_some())
}

/// Deregister a scope-local lifecycle event subscriber.
///
/// This removes the named subscriber from the registry attached to a specific
/// active scope.
///
/// # Parameters
/// - `scope_uuid`: UUID of the owning scope.
/// - `name`: Scope-local subscriber name to remove.
///
/// # Returns
/// A [`Result`] containing `true` when a subscriber was removed and `false`
/// when the name was not registered on that scope.
///
/// # Errors
/// Returns [`FlowError::NotFound`] when the scope does not exist on the active
/// stack.
///
/// # Notes
/// Deregistration affects only future event delivery for that scope. Already
/// emitted events carry a subscriber snapshot, so queued callbacks from that
/// snapshot may still run after deregistration.
pub fn scope_deregister_subscriber(scope_uuid: &uuid::Uuid, name: &str) -> Result<bool> {
    ensure_runtime_owner()?;
    let scope_stack = current_scope_stack();
    let mut guard = scope_stack.write().expect("scope stack lock poisoned");
    let registries = guard
        .local_registries_mut(scope_uuid)
        .ok_or_else(|| FlowError::NotFound(format!("scope {scope_uuid} not found")))?;
    Ok(registries.event_subscribers.remove(name).is_some())
}
