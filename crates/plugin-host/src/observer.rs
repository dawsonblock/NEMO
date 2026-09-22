// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION. ALL rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Delivering this runtime's events to observers that live in another process.
//!
//! A subscriber in the host process watches this runtime's events. The runtime's
//! own dispatch calls subscribers synchronously, on the thread that delivers
//! every event to every observer, so a proxy that waited on an RPC there would
//! make one plugin's latency everyone's. Delivery is therefore queued and
//! performed by a task of its own, and three rules are what the queue exists to
//! keep.
//!
//! **An observer is never fatal.** A delivery that fails is recorded and stops
//! there. This is not a new rule: the in-process dispatcher already catches a
//! panicking subscriber and logs it, because an observer watches work rather than
//! permitting it. The record is a mark in this runtime's own stream, so a failure
//! cannot be silent just because it was harmless.
//!
//! **An observer is bounded, explicitly.** A delivery runs under the observer
//! budget the runtime states, and a runtime that states none cannot have remote
//! observers at all — the alternative to a stated limit is an invented one.
//!
//! **A full queue drops, loudly.** Blocking the dispatcher until a plugin caught
//! up would put that plugin in the runtime's event path; a drop is recorded once
//! per saturation rather than once per event, so the record cannot become the
//! flood it is reporting.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use nemo_relay::api::scope::EmitMarkEventParams;
use nemo_relay::plugin::execution::PluginManager;
use nemo_relay_plugin_protocol::{
    MAX_FRAME_BYTES, PROTOCOL_VERSION, PluginExecutionContext, PluginFailureCode, PluginHandle,
    PluginInvokeRequest, PluginObservedEvent, PluginProtocolError, PluginSuccess, Uuid,
};
use tokio::sync::mpsc::error::TrySendError;

use crate::operation_scopes::OperationScopes;

/// Events that may wait for one observer before the runtime starts dropping.
///
/// Bounded rather than unbounded because the alternative to a drop is unbounded
/// memory held on behalf of a plugin that is not keeping up.
pub(crate) const OBSERVER_QUEUE_CAPACITY: usize = 256;

/// The mark this runtime emits when an observer's delivery failed.
///
/// A name rather than a log line: a failure to deliver an event to an observer is
/// something a subscriber of this runtime can react to, and the runtime's own
/// stream is where it belongs.
pub const OBSERVER_FAILURE_MARK: &str = "nemo.plugin.observer.failed";

/// One observer's delivery task, ended when its registration is removed.
pub(crate) struct ObserverDelivery {
    sender: tokio::sync::mpsc::Sender<PluginObservedEvent>,
    /// Whether the queue is already known to be full, so one saturation is
    /// recorded once.
    saturated: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ObserverDelivery {
    fn drop(&mut self) {
        // The registration is going away, so there is nothing left to deliver
        // to and nobody to deliver to it.
        self.task.abort();
    }
}

impl ObserverDelivery {
    /// Start delivering to one registration.
    ///
    /// Needs a runtime to deliver on: a proxy installed outside one would have a
    /// queue and nobody to drain it, which is a refusal rather than a silent
    /// backlog.
    pub(crate) fn start(
        manager: Arc<PluginManager>,
        runtime_binding_digest: String,
        handle: PluginHandle,
        registration_id: String,
        budget_millis: u64,
        operation_scopes: Option<Arc<OperationScopes>>,
    ) -> Result<Self, PluginProtocolError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            PluginProtocolError::new(
                PluginFailureCode::Rejected,
                "an observer proxy needs a runtime to deliver on".to_string(),
            )
        })?;
        let (sender, mut receiver) =
            tokio::sync::mpsc::channel::<PluginObservedEvent>(OBSERVER_QUEUE_CAPACITY);
        let task = runtime.spawn(async move {
            while let Some(observed) = receiver.recv().await {
                let reason = deliver(
                    &manager,
                    &runtime_binding_digest,
                    &handle,
                    &registration_id,
                    budget_millis,
                    operation_scopes.as_ref(),
                    observed,
                )
                .await;
                if let Err(reason) = reason {
                    record_failure(&registration_id, &reason);
                }
            }
        });
        Ok(Self {
            sender,
            saturated: Arc::new(AtomicBool::new(false)),
            task,
        })
    }

    /// Hand one event to the queue, or record that the queue was full.
    pub(crate) fn offer(&self, observed: PluginObservedEvent, registration_id: &str) {
        match self.sender.try_send(observed) {
            Ok(()) => {
                // Draining again: the next saturation is a new fact.
                self.saturated.store(false, Ordering::SeqCst);
            }
            Err(TrySendError::Full(_)) => {
                if !self.saturated.swap(true, Ordering::SeqCst) {
                    record_failure(
                        registration_id,
                        "the observer's queue is full, so this event was dropped",
                    );
                }
            }
            // The delivery task ended with the registration; dropping is what
            // that means, and the registration's removal is the record of it.
            Err(TrySendError::Closed(_)) => {}
        }
    }
}

/// Deliver one event to one observer, or say why it could not be delivered.
#[allow(clippy::too_many_arguments)]
async fn deliver(
    manager: &Arc<PluginManager>,
    runtime_binding_digest: &str,
    handle: &PluginHandle,
    registration_id: &str,
    budget_millis: u64,
    operation_scopes: Option<&Arc<OperationScopes>>,
    observed: PluginObservedEvent,
) -> Result<(), String> {
    let arguments = serde_json::to_string(&observed)
        .map_err(|error| format!("the observed event could not be encoded: {error}"))?;
    let context = PluginExecutionContext {
        operation_request_id: Uuid::now_v7().to_string(),
        protocol_version: PROTOCOL_VERSION,
        runtime_binding_digest: runtime_binding_digest.to_owned(),
        deadline_unix_ms: nemo_relay::api::runtime::budget_now_unix_ms()
            .saturating_add(budget_millis),
        remaining_budget_millis: budget_millis,
        max_response_bytes: MAX_FRAME_BYTES,
    };
    // An observer's delivery is not part of the action that emitted the event,
    // so it does not inherit that action's budget: it carries the one this
    // runtime states for observers. The scope is registered all the same, because
    // a mark the observer raises has to be attributed to something.
    let _in_flight = operation_scopes.map(|scopes| {
        scopes.enter(
            &context.operation_request_id,
            nemo_relay::api::runtime::current_scope_stack(),
        )
    });
    let request = PluginInvokeRequest {
        handle: handle.clone(),
        registration_id: registration_id.to_owned(),
        arguments,
        budget_millis,
    };
    let outcome = manager
        .invoke(request, context)
        .await
        .map_err(|error| error.failure.message)?;
    match outcome.result {
        // A subscriber answers with nothing; the answer is only that it ran.
        Ok(PluginSuccess::Invoked(_)) => Ok(()),
        Ok(other) => Err(format!("a subscriber answered with {}", other_name(&other))),
        Err(failure) => Err(failure.message),
    }
}

/// Record one observer failure in this runtime's own stream.
fn record_failure(registration: &str, reason: &str) {
    let _ = nemo_relay::api::scope::event(
        EmitMarkEventParams::builder()
            .name(OBSERVER_FAILURE_MARK)
            .data_opt(Some(serde_json::json!({
                "registration": registration,
                "reason": reason,
            })))
            .build(),
    );
}

/// The name of a success a subscriber cannot have sent.
fn other_name(success: &PluginSuccess) -> &'static str {
    match success {
        PluginSuccess::Handshake(_) => "a handshake",
        PluginSuccess::Loaded(_) => "a load",
        PluginSuccess::Unloaded => "an unload",
        PluginSuccess::Invoked(_) => "an invocation",
        PluginSuccess::Inspected(_) => "an inspection",
        PluginSuccess::Health(_) => "a health report",
    }
}
