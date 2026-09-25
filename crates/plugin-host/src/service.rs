// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The plugin host's side of the boundary.
//!
//! This is what the `nemo-plugin-host` process serves: the kernel's lifecycle
//! operations, converted at the edge and dispatched to whichever backend the
//! host runs. The host is the less-trusted side, so everything arriving is
//! converted before it is used and every answer is a structured outcome rather
//! than a transport status — a refusal the kernel can read is not a channel
//! failure, and the two call for different responses.
//!
//! The host enforces the session it established: a request naming another
//! session, or arriving before the handshake, is refused rather than served.

use std::sync::{Arc, Mutex};

use nemo_relay::plugin::execution::PluginExecutionBackend;
use nemo_relay_plugin_proto::convert::{
    activate_outcome_to_wire, activate_request_from_wire, attach_outcome_to_wire,
    attach_request_from_wire, cancel_outcome_to_wire, execution_outcome_to_wire,
    handshake_outcome_to_wire, handshake_request_from_wire, health_outcome_to_wire,
    inspect_outcome_to_wire, inspect_request_from_wire, invoke_request_from_wire,
    load_outcome_to_wire, load_request_from_wire, operation_envelope_from_wire,
    session_close_outcome_to_wire, unload_outcome_to_wire, unload_request_from_wire,
};
use nemo_relay_plugin_proto::v1;
use nemo_relay_plugin_protocol::{
    LifecycleOutcome, PROTOCOL_VERSION, PluginProtocolError, PluginRegistrationOperation,
    PluginSessionIdentity, Uuid, check_protocol_version,
};
use tonic::{Request, Response, Status};

/// How the host was configured by whoever started it.
#[derive(Debug, Clone)]
pub struct PluginHostConfig {
    /// Protocol version this host speaks.
    pub protocol_version: u16,
    /// Digest of the runtime identity the kernel expects to be bound to.
    pub runtime_binding_digest: String,
    /// Credential the supervisor passed out of band, so knowing the socket path
    /// is not enough to present as the kernel.
    pub session_credential: String,
    /// Largest frame this host will accept.
    pub maximum_frame_bytes: u32,
}

impl Default for PluginHostConfig {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: String::new(),
            session_credential: String::new(),
            maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        }
    }
}

/// The state of this host's one session.
///
/// A host serves one session and then it is done. That is not a limitation to
/// work around later: the supervisor spawns a process per session, so a second
/// handshake on the same process would be a session nobody owns, and allowing it
/// would make "which session is this?" a question with two answers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostSession {
    /// Before the handshake.
    New,
    /// Serving a session.
    Active {
        /// What the handshake established. Held whole because an attach hands it
        /// back rather than recomputing it: the parameters an attach reports are
        /// the session's, not the attaching caller's.
        identity: nemo_relay_plugin_protocol::PluginSessionIdentity,
        /// Registration classes the kernel can install a proxy for.
        supported_registration_operations: Vec<PluginRegistrationOperation>,
        /// What every operation on this session's transports has to present.
        ///
        /// The credential authorises establishing the session; this authorises
        /// using it. Without it, naming the session would be enough to call it,
        /// and a session's name is what an attach announces.
        capability: crate::capability::SessionCapability,
    },
    /// After the session closed. Every later request is refused, including a
    /// handshake that would start another one.
    Closed,
}

/// The `PluginHost` service.
pub struct PluginHostService {
    backend: Arc<dyn PluginExecutionBackend>,
    config: PluginHostConfig,
    /// Identity of this host process.
    host_instance_id: String,
    /// The session this host established, if any.
    session: Mutex<HostSession>,
    /// Where the marks this host's plugins raise are sent, when this host was
    /// given a kernel to send them to.
    mark_forwarding: Option<MarkForwardingSender>,
    /// The kernel this host may call back into, when one started it.
    ///
    /// Needed by the classes that wrap a call: their continuation is the
    /// kernel's remainder of the chain, so a plugin's `next` is a call this side
    /// makes.
    kernel: Option<crate::runtime_service::KernelCallbacks>,
    /// The session channel this host pulls its plugins' downstream streams over.
    ///
    /// Created when the first streaming registration needs it, because a host
    /// that never serves one has no reason to hold a channel open.
    session_channel:
        tokio::sync::Mutex<Option<std::sync::Arc<crate::session_channel::SessionChannel>>>,
}

/// This host's end of the channel its forwarded marks travel on.
///
/// Bounded rather than unbounded, because the marks come from a plugin and the
/// drain comes from a socket: a plugin that raises marks faster than the kernel
/// reads them would otherwise grow this process's heap without limit, and the
/// process separation that contains its crashes would not contain that. The
/// capacity is whoever starts the host's decision, so how much a host may buffer
/// is configuration rather than a constant buried in the execution path.
pub type MarkForwardingSender = tokio::sync::mpsc::Sender<ForwardedStep>;

/// One step on the path a forwarded mark takes back to the kernel.
///
/// The marks and the flush travel on one channel so they cannot overtake each
/// other: a flush that arrived before the marks it waits for would report
/// success while they were still queued.
#[derive(Debug)]
pub enum ForwardedStep {
    /// Send this mark to the kernel that owns the event stream.
    Mark {
        /// The session the mark belongs to.
        session_id: String,
        /// The mark itself, boxed so the flush arm is not dwarfed by it: the
        /// arms travel on one channel, and a size difference between them is
        /// paid by every message.
        mark: Box<nemo_relay_plugin_protocol::PluginMarkEmit>,
    },
    /// Everything sent before this arrived; answer on `done`.
    Flush {
        /// Receives the first delivery failure since the last flush, if any.
        done: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

/// Closes a call's mark window when it goes out of scope.
///
/// A guard rather than a call per exit path, for the reason the activation guard
/// is one: an invocation can end in more ways than it can start, and a window left
/// open is a window a later mark can be attributed through.
struct ClosedOnDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for ClosedOnDrop {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The sink a plugin's callback raises marks into.
struct ForwardingSink {
    sender: MarkForwardingSender,
    session_id: String,
    /// The operation this host is running, which every mark belongs to.
    operation_request_id: String,
    /// Whether the invocation this window was opened for is over.
    ///
    /// A window is opened around one call, and the work of that call may keep a
    /// task of its own running after the call returned — a streaming callback's
    /// returned stream is polled long afterwards. Once the invocation is over, a
    /// window that is still held is a *stale* window: attributing its marks to the
    /// operation would be attributing them to whatever holds that identity now, so
    /// the mark is refused instead.
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// A distinct identity per mark, minted here because a callback can raise
    /// several marks within one operation.
    host_calls: std::sync::atomic::AtomicU64,
}

impl nemo_relay::plugin::execution::MarkForwarder for ForwardingSink {
    fn forward(
        &self,
        mark: &nemo_relay::plugin::execution::ForwardedMark,
    ) -> nemo_relay::error::Result<()> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(nemo_relay::error::FlowError::Internal(format!(
                "the invocation '{}' this mark belongs to has ended",
                self.operation_request_id
            )));
        }
        let host_call_id = format!(
            "{}-{}",
            self.operation_request_id,
            self.host_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        );
        self.sender
            .try_send(ForwardedStep::Mark {
                session_id: self.session_id.clone(),
                mark: Box::new(nemo_relay_plugin_protocol::PluginMarkEmit {
                    operation_request_id: self.operation_request_id.clone(),
                    host_call_id,
                    name: mark.name.clone(),
                    data_json: mark.data_json.clone(),
                    parent: mark.parent,
                    metadata_json: mark.metadata_json.clone(),
                    data_schema: mark.data_schema.clone(),
                    severity: mark.severity,
                    timestamp_unix_micros: mark.timestamp_unix_micros,
                }),
            })
            // Both refusals are the same fact to the caller: this mark did not
            // leave, so the invocation cannot be reported as having produced the
            // evidence it says it produced. A full queue is a host that is not
            // keeping up with its plugin, and dropping the mark quietly would
            // make the kernel's view of the invocation wrong rather than late.
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    nemo_relay::error::FlowError::Internal(
                        "the kernel this host forwards marks to is not keeping up with this \
                         plugin's marks"
                            .to_string(),
                    )
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    nemo_relay::error::FlowError::Internal(
                        "the kernel this host forwards marks to is no longer reachable".to_string(),
                    )
                }
            })
    }
}

impl PluginHostService {
    /// Serve lifecycle operations for one backend.
    pub fn new(backend: Arc<dyn PluginExecutionBackend>, config: PluginHostConfig) -> Self {
        Self {
            backend,
            config,
            host_instance_id: Uuid::now_v7().to_string(),
            session: Mutex::new(HostSession::New),
            mark_forwarding: None,
            kernel: None,
            session_channel: tokio::sync::Mutex::new(None),
        }
    }

    /// Forward the marks this host's plugins raise to the kernel.
    ///
    /// The sender is this host's end of one channel; whoever holds the other end
    /// has the connection back to the kernel. Without one, a mark a plugin raises
    /// is emitted into this process's own runtime, where the kernel's subscribers
    /// cannot see it.
    pub fn with_mark_forwarding(mut self, sender: MarkForwardingSender) -> Self {
        self.mark_forwarding = Some(sender);
        self
    }

    /// Give this host the kernel it may call back into.
    ///
    /// A host without one serves the classes that answer a call; the classes
    /// that wrap one are refused, because their continuation would have nowhere
    /// to run.
    pub fn with_kernel_callbacks(
        mut self,
        kernel: crate::runtime_service::KernelCallbacks,
    ) -> Self {
        self.kernel = Some(kernel);
        self
    }

    /// Run one registration for a validated invocation.
    ///
    /// Split out of the service method so the window in which a plugin's marks
    /// are forwarded can be wrapped around exactly this work.
    async fn serve_invocation(
        &self,
        wire: v1::InvokeRequest,
        presented: Option<&str>,
    ) -> Result<nemo_relay_plugin_protocol::PluginExecutionOutcome, PluginProtocolError> {
        let outcome: Result<
            nemo_relay_plugin_protocol::PluginExecutionOutcome,
            PluginProtocolError,
        > =
            async {
                if let Err(error) = self.established(&wire.session_id) {
                    return Ok(refusal(error.failure.message));
                }
                let context = self.prepare(&wire.session_id, presented, wire.context.as_ref())?;
                let request = invoke_request_from_wire(&wire, &context)?;

                // Which registration this is comes from the host's own record of
                // what the plugin registered, not from what the caller says: a
                // caller that could name an arbitrary operation against a
                // registration would be choosing the semantics of a call it did not
                // make.
                let operation = self.registration_operation(&request, &context).await?;
                match operation {
                // The first class that crosses the boundary. Its payload is the
                // tool name and the arguments to rewrite; the callback runs in
                // this process, through the runtime this host links.
                nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolRequestIntercept => {
                    let payload: serde_json::Value = serde_json::from_str(&request.arguments)
                        .map_err(|error| {
                            refused(format!(
                                "a tool request intercept payload must be JSON: {error}"
                            ))
                        })?;
                    let tool = payload
                        .get("tool")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| refused("a tool request intercept payload names no tool"))?
                        .to_string();
                    let args = payload.get("args").cloned().ok_or_else(|| {
                        refused("a tool request intercept payload carries no arguments")
                    })?;
                    let rewritten =
                        nemo_relay::api::tool::invoke_tool_request_intercept_registration(
                            &request.registration_id,
                            &tool,
                            args,
                        )
                        .await;
                    Ok(match rewritten {
                        Ok(value) => success(serde_json::to_string(&value).map_err(|error| {
                            refused(format!(
                                "the rewritten arguments could not be serialized: {error}"
                            ))
                        })?),
                        // A registration that refused did not dispatch anything
                        // anywhere else: this hook runs before the call.
                        Err(error) => refusal(error.to_string()),
                    })
                }
                // The second class, and the same shape as the first: the
                // kernel sends the invocation the chain holds, this process runs
                // the one registration the kernel named, and the outcome travels
                // back whole — including the marks the callback scheduled and any
                // evidence it recorded, because an invocation that dropped those
                // would not be the invocation the kernel's chain makes.
                nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmRequestIntercept => {
                    let invocation: nemo_relay::api::llm::LlmRequestInterceptInvocation =
                        serde_json::from_str(&request.arguments).map_err(|error| {
                            refused(format!(
                                "an LLM request intercept payload must be an invocation: {error}"
                            ))
                        })?;
                    let rewritten =
                        nemo_relay::api::llm::invoke_llm_request_intercept_registration(
                            &request.registration_id,
                            invocation,
                        )
                        .await;
                    Ok(match rewritten {
                        Ok(outcome) => success(serde_json::to_string(&outcome).map_err(|error| {
                            refused(format!(
                                "the rewritten request could not be serialized: {error}"
                            ))
                        })?),
                        // A registration that refused did not dispatch anything
                        // anywhere else: this hook runs before the call.
                        Err(error) => refusal(error.to_string()),
                    })
                }
                // The first observer class. A subscriber answers with nothing:
                // it watched, and what it does with what it saw is its own
                // business. Its failure is reported as a refusal so the kernel
                // can record it, and never as an outcome that changes the work
                // it was watching.
                nemo_relay_plugin_protocol::PluginRegistrationOperation::Subscriber => {
                    let observed: nemo_relay_plugin_protocol::PluginObservedEvent =
                        serde_json::from_str(&request.arguments).map_err(|error| {
                            refused(format!(
                                "a subscriber payload must be an observed event: {error}"
                            ))
                        })?;
                    match nemo_relay::api::subscriber::invoke_subscriber_registration(
                        &request.registration_id,
                        &observed.event,
                    ) {
                        Ok(()) => Ok(success(String::new())),
                        Err(error) => Ok(refusal(error.to_string())),
                    }
                }
                // The two tool sanitize directions. What crosses is the payload
                // an event would carry, and what comes back is the copy the event
                // should publish: a sanitizer changes what observers see and
                // never what the tool does. A refusal — including the chain
                // omitting the payload — is reported as one, so the kernel omits
                // it the same way it would in process.
                nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolSanitizeRequestGuardrail => {
                    sanitized_tool_payload(&request, false).await
                }
                nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolSanitizeResponseGuardrail => {
                    sanitized_tool_payload(&request, true).await
                }
                // The first decision class. A conditional guardrail can refuse
                // the call, so what crosses is its decision: a reason the kernel
                // reports as a rejection, or nothing at all for permission.
                nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolConditionalExecutionGuardrail => {
                    let payload: serde_json::Value =
                        serde_json::from_str(&request.arguments).map_err(|error| {
                            refused(format!(
                                "a conditional guardrail payload must be JSON: {error}"
                            ))
                        })?;
                    let tool = payload
                        .get("tool")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| refused("a conditional guardrail payload names no tool"))?
                        .to_string();
                    let args = payload.get("args").cloned().ok_or_else(|| {
                        refused("a conditional guardrail payload carries no arguments")
                    })?;
                    match nemo_relay::api::tool::invoke_tool_conditional_execution_registration(
                        &request.registration_id,
                        &tool,
                        args,
                    )
                    .await
                    {
                        Ok(decision) => Ok(success(
                            serde_json::to_string(&decision).map_err(|error| {
                                refused(format!("the decision could not be serialized: {error}"))
                            })?,
                        )),
                        Err(error) => Ok(refusal(error.to_string())),
                    }
                }
                // The LLM decision, over the request the chain holds.
                nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmConditionalExecutionGuardrail => {
                    let request_json: serde_json::Value = serde_json::from_str(&request.arguments)
                        .map_err(|error| {
                            refused(format!(
                                "an LLM conditional payload must be JSON: {error}"
                            ))
                        })?;
                    match nemo_relay::api::llm::invoke_llm_conditional_execution_registration(
                        &request.registration_id,
                        request_json,
                    )
                    .await
                    {
                        Ok(decision) => Ok(success(
                            serde_json::to_string(&decision).map_err(|error| {
                                refused(format!("the decision could not be serialized: {error}"))
                            })?,
                        )),
                        Err(error) => Ok(refusal(error.to_string())),
                    }
                }
                // The additive observer class. Its answer is the metadata it
                // wants added, and the kernel inserts it; a failure here means
                // nothing is added, which is what an injector's failure means in
                // process too.
                nemo_relay_plugin_protocol::PluginRegistrationOperation::EventMetadataInjector => {
                    let observed: nemo_relay_plugin_protocol::PluginObservedEvent =
                        serde_json::from_str(&request.arguments).map_err(|error| {
                            refused(format!(
                                "a metadata injector payload must be an observed event: {error}"
                            ))
                        })?;
                    match nemo_relay::api::subscriber::invoke_event_metadata_injector_registration(
                        &request.registration_id,
                        &observed.event,
                    )
                    .await
                    {
                        Ok(additions) => Ok(success(
                            serde_json::to_string(&additions).map_err(|error| {
                                refused(format!(
                                    "the injected metadata could not be serialized: {error}"
                                ))
                            })?,
                        )),
                        Err(error) => Ok(refusal(error.to_string())),
                    }
                }
                // The three event sanitize families. What crosses is the projection
                // rather than the runtime's own event: the name a sanitizer decides
                // on, the phase when it is a scope event, and the mutable fields it
                // may change. What comes back is those fields and nothing else, so
                // the class, the registration, the operation and the envelope stay
                // the kernel's.
                nemo_relay_plugin_protocol::PluginRegistrationOperation::MarkSanitizeGuardrail
                | nemo_relay_plugin_protocol::PluginRegistrationOperation::ScopeSanitizeStartGuardrail
                | nemo_relay_plugin_protocol::PluginRegistrationOperation::ScopeSanitizeEndGuardrail => {
                    sanitized_event_fields(&request, operation).await
                }
                // The class whose sanitizer is given the call's codec. What crosses is a
                // request, the codec's identity, and a reference: the codec itself stays in
                // the kernel, and the plugin's callback reaches it through this host.
                nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmSanitizeRequestGuardrail => {
                    sanitized_llm_request(
                        &request,
                        self.kernel.clone(),
                        &wire.session_id,
                        &context.operation_request_id,
                    )
                    .await
                }
                // The first class that wraps a call rather than answering one.
                // The plugin's callback decides *when* the rest of the chain
                // runs, and the rest of the chain is the kernel's, so the
                // continuation the callback calls is a call this process makes
                // back into the kernel with the arguments the callback settled
                // on. What comes back is the downstream result, which is what
                // the callback is waiting for.
                nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolExecutionIntercept => {
                    let Some(kernel) = self.kernel.clone() else {
                        // Refused rather than run without a continuation: a
                        // callback whose `next` goes nowhere would either hang or
                        // silently skip the call it was meant to wrap.
                        return Ok(refusal(
                            "this host has no kernel to continue a wrapped call through, so an execution \
                             intercept cannot be served here",
                        ));
                    };
                    let payload: serde_json::Value = serde_json::from_str(&request.arguments)
                        .map_err(|error| {
                            refused(format!(
                                "a tool execution intercept payload must be JSON: {error}"
                            ))
                        })?;
                    let tool = payload
                        .get("tool")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            refused("a tool execution intercept payload names no tool")
                        })?
                        .to_string();
                    let args = payload.get("args").cloned().ok_or_else(|| {
                        refused("a tool execution intercept payload carries no arguments")
                    })?;
                    let session_id = wire.session_id.clone();
                    let operation_request_id = context.operation_request_id.clone();
                    let calls = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                    // Each call mints its own identity: the ABI lets an intercept
                    // call its continuation more than once — retries and fan-out
                    // are what the isolated context per call exists for — so the
                    // kernel is told which call it is answering, not merely that
                    // one arrived.
                    let next: nemo_relay::api::runtime::ToolExecutionNextFn =
                        std::sync::Arc::new(move |args: serde_json::Value| {
                            let kernel = kernel.clone();
                            let session_id = session_id.clone();
                            let operation_request_id = operation_request_id.clone();
                            let calls = std::sync::Arc::clone(&calls);
                            Box::pin(async move {
                                let host_call_id = format!(
                                    "{operation_request_id}-{}",
                                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                                );
                                let answered = kernel
                                    .run_continuation(
                                        &session_id,
                                        &operation_request_id,
                                        &host_call_id,
                                        &args.to_string(),
                                    )
                                    .await;
                                match answered {
                                    Ok(outcome) => match outcome.result {
                                        Ok(value) => serde_json::from_str(&value).map_err(|error| {
                                            nemo_relay::error::FlowError::Internal(format!(
                                                "the kernel's continuation answered with something that is not a tool \
                                                 result: {error}"
                                            ))
                                        }),
                                        // The kernel's chain failed. The ABI carries an
                                        // intercept's continuation error as text, so what
                                        // travels back is the kernel's own words and the
                                        // code it refused with — not a registration this
                                        // process could have named.
                                        Err(failure) => Err(
                                            nemo_relay::error::FlowError::Internal(format!(
                                                "the wrapped call failed: {} ({:?})",
                                                failure.message, failure.code
                                            )),
                                        ),
                                    },
                                    Err(error) => Err(nemo_relay::error::FlowError::Internal(format!(
                                        "the wrapped call could not be continued: {error}"
                                    ))),
                                }
                            })
                        });
                    match nemo_relay::api::tool::invoke_tool_execution_intercept_registration(
                        &request.registration_id,
                        &tool,
                        args,
                        next,
                    )
                    .await
                    {
                        Ok(outcome) => Ok(success(serde_json::to_string(&outcome).map_err(
                            |error| {
                                refused(format!(
                                    "the execution intercept's outcome could not be serialized: {error}"
                                ))
                            },
                        )?)),
                        Err(error) => Ok(refusal(error.to_string())),
                    }
                }
                // The tool execution intercept's twin, one layer up: the
                // plugin decides when the provider call runs, and the call is the
                // kernel's, so `next` is a call back into it. What travels is the
                // provider request down and the provider response back.
                nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmExecutionIntercept => {
                    let Some(kernel) = self.kernel.clone() else {
                        return Ok(refusal(
                            "this host has no kernel to continue a wrapped call through, so an \
                             execution intercept cannot be served here",
                        ));
                    };
                    let payload: serde_json::Value = serde_json::from_str(&request.arguments)
                        .map_err(|error| {
                            refused(format!(
                                "an LLM execution intercept payload must be JSON: {error}"
                            ))
                        })?;
                    let name = payload
                        .get("name")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            refused("an LLM execution intercept payload names no provider")
                        })?
                        .to_owned();
                    let request_json = payload.get("request").cloned().ok_or_else(|| {
                        refused("an LLM execution intercept payload carries no request")
                    })?;
                    let provider_request: nemo_relay::api::llm::LlmRequest =
                        serde_json::from_value(request_json).map_err(|error| {
                            refused(format!(
                                "an LLM execution intercept payload carries something that is \
                                 not a request: {error}"
                            ))
                        })?;
                    let session_id = wire.session_id.clone();
                    let operation_request_id = context.operation_request_id.clone();
                    let calls = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                    let next: nemo_relay::api::runtime::LlmExecutionNextFn =
                        std::sync::Arc::new(move |request| {
                            let kernel = kernel.clone();
                            let session_id = session_id.clone();
                            let operation_request_id = operation_request_id.clone();
                            let calls = std::sync::Arc::clone(&calls);
                            Box::pin(async move {
                                let host_call_id = format!(
                                    "{operation_request_id}-{}",
                                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                                );
                                let sent = serde_json::to_string(&request).map_err(|error| {
                                    nemo_relay::error::FlowError::Internal(format!(
                                        "the request could not be serialized: {error}"
                                    ))
                                })?;
                                let answered = kernel
                                    .run_continuation(
                                        &session_id,
                                        &operation_request_id,
                                        &host_call_id,
                                        &sent,
                                    )
                                    .await;
                                match answered {
                                    Ok(outcome) => match outcome.result {
                                        Ok(value) => {
                                            serde_json::from_str(&value).map_err(|error| {
                                                nemo_relay::error::FlowError::Internal(format!(
                                                    "the kernel's continuation answered with \
                                                     something that is not a response: {error}"
                                                ))
                                            })
                                        }
                                        Err(failure) => Err(
                                            nemo_relay::error::FlowError::Internal(format!(
                                                "the wrapped call failed: {} ({:?})",
                                                failure.message, failure.code
                                            )),
                                        ),
                                    },
                                    Err(error) => Err(nemo_relay::error::FlowError::Internal(
                                        format!("the wrapped call could not be continued: {error}"),
                                    )),
                                }
                            })
                        });
                    match nemo_relay::api::llm::invoke_llm_execution_intercept_registration(
                        &request.registration_id,
                        &name,
                        provider_request,
                        next,
                    )
                    .await
                    {
                        Ok(response) => Ok(success(serde_json::to_string(&response).map_err(
                            |error| {
                                refused(format!(
                                    "the execution intercept's response could not be \
                                     serialized: {error}"
                                ))
                            },
                        )?)),
                        Err(error) => Ok(refusal(error.to_string())),
                    }
                }
                // Every other class is refused by name rather than answered as
                // an empty success, because a caller cannot tell the two apart
                // and would read one as the other.
                other => Ok(refusal(format!(
                    "this host does not serve {} invocations yet",
                    other.as_str()
                ))),
            }
            }
            .await;
        outcome
    }

    /// Validate the session every later request has to name.
    fn established(&self, session_id: &str) -> Result<(), PluginProtocolError> {
        let session = self
            .session
            .lock()
            .map_err(|error| refused(format!("the session lock was poisoned: {error}")))?;
        match &*session {
            HostSession::Active { identity, .. } if identity.session_id == session_id => Ok(()),
            HostSession::Active { .. } => Err(refused(
                "this request names a session this host did not establish",
            )),
            HostSession::New => Err(refused("this host has not established a session yet")),
            HostSession::Closed => Err(refused(
                "this host has already served its session and will not serve another",
            )),
        }
    }

    /// The registration classes this session's kernel can install proxies for.
    fn supported_operations(
        &self,
    ) -> Result<Vec<PluginRegistrationOperation>, PluginProtocolError> {
        let session = self
            .session
            .lock()
            .map_err(|error| refused(format!("the session lock was poisoned: {error}")))?;
        match &*session {
            HostSession::Active {
                supported_registration_operations,
                ..
            } => Ok(supported_registration_operations.clone()),
            _ => Err(refused("this host has not established a session yet")),
        }
    }

    /// Refuse a plugin whose registrations this session cannot serve.
    ///
    /// Failing closed means failing without a half-loaded plugin: the backend has
    /// loaded it by the time this runs, so the caller unloads it rather than
    /// leaving registrations the kernel will never call.
    fn unsupported_registrations(
        &self,
        descriptor: &nemo_relay_plugin_protocol::PluginDescriptor,
    ) -> Result<(), PluginProtocolError> {
        let supported = self.supported_operations()?;
        let unsupported: Vec<&str> = descriptor
            .registrations
            .iter()
            .map(|registration| registration.operation)
            .filter(|operation| !supported.contains(operation))
            .map(|operation| operation.as_str())
            .collect();
        if unsupported.is_empty() {
            return Ok(());
        }
        let supported: Vec<&str> = supported
            .iter()
            .map(|operation| operation.as_str())
            .collect();
        Err(refused(format!(
            "plugin {} registers {unsupported:?}, and this session can serve {supported:?}",
            descriptor.plugin_id
        )))
    }
}

/// A registration ran and its answer is the output.
///
/// `NotDispatched` is the truth for the classes a host serves today: they run
/// before any call, so nothing was reached that could have happened elsewhere.
fn success(output: String) -> nemo_relay_plugin_protocol::PluginExecutionOutcome {
    use nemo_relay_plugin_protocol::{DispatchState, OutcomeCertainty, PluginExecutionOutcome};
    PluginExecutionOutcome {
        dispatch: DispatchState::NotDispatched,
        certainty: OutcomeCertainty::ConfirmedSuccess,
        result: Ok(nemo_relay_plugin_protocol::PluginSuccess::Invoked(
            nemo_relay_plugin_protocol::PluginInvokeResponse { output },
        )),
    }
}

/// A registration refused, or the invocation never reached one.
fn refusal(message: impl Into<String>) -> nemo_relay_plugin_protocol::PluginExecutionOutcome {
    refusal_with(
        nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
        message,
    )
}

/// A refusal that carries the code the host refused the invocation with.
///
/// The reason a call was refused is part of the answer, not decoration: a
/// response that broke the operation's budget is a different finding from a
/// callback that refused, and a caller reading the code has to be able to tell
/// them apart.
fn refusal_with(
    code: nemo_relay_plugin_protocol::PluginFailureCode,
    message: impl Into<String>,
) -> nemo_relay_plugin_protocol::PluginExecutionOutcome {
    use nemo_relay_plugin_protocol::{DispatchState, OutcomeCertainty, PluginExecutionOutcome};
    PluginExecutionOutcome {
        dispatch: DispatchState::NotDispatched,
        certainty: OutcomeCertainty::ConfirmedFailure,
        result: Err(nemo_relay_plugin_protocol::PluginFailure {
            code,
            message: message.into(),
        }),
    }
}

/// A refusal the kernel can read.
fn refused(message: impl Into<String>) -> PluginProtocolError {
    PluginProtocolError::new(
        nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
        message,
    )
}

/// The capability a request presents, as its own value.
///
/// Owned rather than borrowed because the message it arrived with is taken apart
/// immediately afterwards: the capability belongs to the transport, and reading
/// it before the payload keeps the two from being confused for each other.
fn presented_capability<T>(request: &Request<T>) -> Option<String> {
    request
        .metadata()
        .get(crate::capability::SESSION_CAPABILITY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The frames one streaming invocation's returned stream produces.
///
/// One frame per poll, which is what keeps the upstream path lazy: the kernel
/// reading a frame is what asks this process to produce the next one, so a plugin
/// whose returned stream would produce without bound is bounded by its consumer
/// rather than by a queue somewhere in between.
struct PluginFrames {
    stream: nemo_relay::api::runtime::LlmJsonStream,
    operation_request_id: String,
    /// The frame that ends this call, held until the call's marks are delivered.
    ///
    /// The terminal frame is the kernel's proof that the invocation is over, so it
    /// may not cross before the marks that belong to the invocation: a mark the
    /// kernel reads after the call ended is one it cannot attribute, and one whose
    /// window it will refuse.
    ending: Option<v1::StreamChunk>,
    /// The delivery of those marks, while it is in flight.
    flushing: Option<MarkDelivery>,
    /// Whether the frame that ends this call has been sent, so the stream ends once.
    ended: bool,
    /// The channel this call's marks go to, when the host has one.
    marks: Option<MarkForwardingSender>,
    /// The window this call opened, closed when these frames go with it.
    closed: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl Drop for PluginFrames {
    fn drop(&mut self) {
        // The consumer is gone, so this call is over: nothing may be attributed to
        // it any more, whichever task of the plugin is still holding its window.
        if let Some(closed) = &self.closed {
            closed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// One call's marks being delivered, and whether they were.
///
/// Answered rather than assumed: a call whose marks could not be delivered
/// produced evidence this kernel will never see, so the frame that ends it is a
/// failure rather than the end the plugin asked for.
type MarkDelivery = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>;

fn flush_marks(sender: MarkForwardingSender) -> MarkDelivery {
    Box::pin(async move {
        let (done, delivered) = tokio::sync::oneshot::channel();
        sender
            .send(ForwardedStep::Flush { done })
            .await
            .map_err(|_| "this host can no longer reach the kernel".to_string())?;
        delivered.await.map_err(|_| {
            "this host stopped forwarding before the call's marks were delivered".to_string()
        })?
    })
}

impl tokio_stream::Stream for PluginFrames {
    type Item = Result<v1::StreamChunk, tonic::Status>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;

        loop {
            let this = self.as_mut().get_mut();
            if this.ended {
                return Poll::Ready(None);
            }
            // The end of the call waits for the marks of the call.
            if let Some(ending) = this.ending.take() {
                if let Some(mut flushing) = this.flushing.take() {
                    match flushing.as_mut().poll(context) {
                        Poll::Pending => {
                            this.ending = Some(ending);
                            this.flushing = Some(flushing);
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(error)) => {
                            this.ended = true;
                            if let Some(closed) = &this.closed {
                                closed.store(true, std::sync::atomic::Ordering::SeqCst);
                            }
                            return Poll::Ready(Some(Ok(v1::StreamChunk {
                                operation_request_id: this.operation_request_id.clone(),
                                chunk: Some(v1::stream_chunk::Chunk::Failure(v1::PluginFailure {
                                    code: nemo_relay_plugin_proto::v1::FailureCode::Rejected as i32,
                                    message: format!(
                                        "the marks this call raised could not be delivered: {error}"
                                    ),
                                    ..Default::default()
                                })),
                                dispatch_state:
                                    nemo_relay_plugin_protocol::DispatchState::DispatchAttempted
                                        as i32,
                                outcome_certainty:
                                    nemo_relay_plugin_protocol::OutcomeCertainty::Unknown as i32,
                            })));
                        }
                    }
                }
                this.ended = true;
                return Poll::Ready(Some(Ok(ending)));
            }
            let ending = match std::pin::Pin::new(&mut this.stream).poll_next(context) {
                Poll::Ready(Some(Ok(chunk))) => {
                    return Poll::Ready(Some(Ok(v1::StreamChunk {
                        operation_request_id: this.operation_request_id.clone(),
                        chunk: Some(v1::stream_chunk::Chunk::Data(chunk.to_string())),
                        // A frame that is not terminal carries no certainty about
                        // the call; what it does carry is that the plugin produced it.
                        dispatch_state: nemo_relay_plugin_protocol::DispatchState::DispatchAttempted
                            as i32,
                        outcome_certainty: nemo_relay_plugin_protocol::OutcomeCertainty::Unknown
                            as i32,
                    })));
                }
                Poll::Ready(Some(Err(error))) => v1::StreamChunk {
                    operation_request_id: this.operation_request_id.clone(),
                    chunk: Some(v1::stream_chunk::Chunk::Failure(v1::PluginFailure {
                        code: nemo_relay_plugin_proto::v1::FailureCode::Rejected as i32,
                        message: error.to_string(),
                        ..Default::default()
                    })),
                    // The plugin produced something before failing, so whether
                    // the work happened is not this frame's to say.
                    dispatch_state: nemo_relay_plugin_protocol::DispatchState::DispatchAttempted
                        as i32,
                    outcome_certainty: nemo_relay_plugin_protocol::OutcomeCertainty::Unknown as i32,
                },
                Poll::Ready(None) => v1::StreamChunk {
                    operation_request_id: this.operation_request_id.clone(),
                    chunk: Some(v1::stream_chunk::Chunk::End(true)),
                    dispatch_state: nemo_relay_plugin_protocol::DispatchState::DispatchAttempted
                        as i32,
                    outcome_certainty:
                        nemo_relay_plugin_protocol::OutcomeCertainty::ConfirmedSuccess as i32,
                },
                Poll::Pending => return Poll::Pending,
            };
            // The marks this call raised leave before the frame that ends it, and
            // the window this call opened closes with those frames.
            this.ending = Some(ending);
            this.flushing = this.marks.clone().map(flush_marks);
            if let Some(closed) = &this.closed {
                closed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
}

/// The lifetime of one activation's registrations.
///
/// Activation runs a plugin's register callbacks, so the callbacks live in this
/// process from the moment it returns. Whoever installed them has to take them
/// back down, and a teardown written as one call per exit path is a teardown
/// that the exit paths which do not call it skip — which is how inspection came
/// to leave a plugin registered while reporting itself read-only.
///
/// This makes the teardown a property of the activation's lifetime instead. The
/// guard clears whatever is active when it drops, so success, refusal and every
/// early return roll back the same way, and only a session that means to serve
/// what it activated says so before it returns.
struct ActivationGuard {
    /// Whether this activation's registrations are kept.
    committed: bool,
}

impl ActivationGuard {
    fn new() -> Self {
        Self { committed: false }
    }

    /// Keep what this activation installed: this session serves it.
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for ActivationGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Best effort, and a no-op when nothing is active, so a guard that drops
        // after a failed activation is not a second failure of its own.
        let _ = nemo_relay::plugin::clear_plugin_configuration();
    }
}

#[tonic::async_trait]
impl v1::plugin_host_server::PluginHost for PluginHostService {
    async fn handshake(
        &self,
        request: Request<v1::HandshakeRequest>,
    ) -> Result<Response<v1::HandshakeOutcome>, Status> {
        let presented = presented_capability(&request);
        let request = match handshake_request_from_wire(&request.into_inner()) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::new(handshake_outcome_to_wire(
                    LifecycleOutcome::Failed(error.failure),
                )));
            }
        };

        // The credential is checked first: knowing where the socket is must not
        // be enough to be treated as the kernel.
        if request.session_credential != self.config.session_credential {
            return Ok(Response::new(handshake_outcome_to_wire(
                LifecycleOutcome::Failed(
                    refused("the session credential is not the one this host was started with")
                        .failure,
                ),
            )));
        }
        if let Err(error) = check_protocol_version(request.protocol_version) {
            return Ok(Response::new(handshake_outcome_to_wire(
                LifecycleOutcome::Failed(error.failure),
            )));
        }
        if request.runtime_binding_digest != self.config.runtime_binding_digest {
            // A host started under one runtime must not be retained by another.
            return Ok(Response::new(handshake_outcome_to_wire(
                LifecycleOutcome::Failed(
                    refused("the runtime binding is not the one this host was started with")
                        .failure,
                ),
            )));
        }
        // The capability the kernel minted, which every operation after this one
        // has to present. A session established without one would be a session
        // any peer that learned its name could use.
        let Some(capability) = crate::capability::SessionCapability::parse(presented.as_deref())
        else {
            return Ok(Response::new(handshake_outcome_to_wire(
                LifecycleOutcome::Failed(
                    refused(
                        "the handshake presented no session capability, so the session it asks \
                         for would not be one this host can authorise",
                    )
                    .failure,
                ),
            )));
        };

        let session_id = Uuid::now_v7().to_string();
        // One limit for both directions, and it is the smaller of what this host
        // will accept and what the kernel asked for. Reporting only this host's
        // own limit would let a kernel configured for a smaller frame be answered
        // with a larger one, and a session's frame limit has to be a size both
        // sides have agreed they can carry.
        let negotiated_frame_limit = self
            .config
            .maximum_frame_bytes
            .min(request.maximum_frame_bytes);
        let identity = PluginSessionIdentity {
            protocol_version: self.config.protocol_version,
            session_id: session_id.clone(),
            host_instance_id: self.host_instance_id.clone(),
            host_nonce: Uuid::now_v7().to_string(),
            maximum_frame_bytes: negotiated_frame_limit,
            supported_features: Vec::new(),
            // The host accepts what it is offered. It cannot ask for more, and
            // an offer it does not need is none of its business.
            accepted_read_capabilities: request.offered_read_capabilities.clone(),
        };
        match self.session.lock() {
            Ok(mut session) => match &*session {
                HostSession::New => {
                    *session = HostSession::Active {
                        identity: identity.clone(),
                        supported_registration_operations: request
                            .supported_registration_operations
                            .clone(),
                        capability,
                    };
                }
                HostSession::Active { .. } => {
                    return Ok(Response::new(handshake_outcome_to_wire(
                        LifecycleOutcome::Failed(
                            refused("this host has already established a session").failure,
                        ),
                    )));
                }
                HostSession::Closed => {
                    return Ok(Response::new(handshake_outcome_to_wire(
                        LifecycleOutcome::Failed(
                            refused("this host has already served its session").failure,
                        ),
                    )));
                }
            },
            Err(error) => {
                return Ok(Response::new(handshake_outcome_to_wire(
                    LifecycleOutcome::Failed(
                        refused(format!("the session lock was poisoned: {error}")).failure,
                    ),
                )));
            }
        }
        Ok(Response::new(handshake_outcome_to_wire(
            LifecycleOutcome::Completed(identity),
        )))
    }

    async fn attach(
        &self,
        request: Request<v1::AttachRequest>,
    ) -> Result<Response<v1::AttachOutcome>, Status> {
        let refused_attach = |failure: nemo_relay_plugin_protocol::PluginFailure| {
            Response::new(attach_outcome_to_wire(LifecycleOutcome::Failed(failure)))
        };
        let presented = presented_capability(&request);
        let request = match attach_request_from_wire(&request.into_inner()) {
            Ok(request) => request,
            Err(error) => return Ok(refused_attach(error.failure)),
        };
        // The credential first, as at handshake: an attach that could be made
        // without it would make the socket path the authorisation, and a second
        // transport is not a lesser one.
        if request.session_credential != self.config.session_credential {
            return Ok(refused_attach(
                refused("the session credential is not the one this host was started with").failure,
            ));
        }
        if let Err(error) = check_protocol_version(request.protocol_version) {
            return Ok(refused_attach(error.failure));
        }
        if request.runtime_binding_digest != self.config.runtime_binding_digest {
            return Ok(refused_attach(
                refused("the runtime binding is not the one this host was started with").failure,
            ));
        }

        // Then the session, because an attach joins one rather than making one.
        // Everything it answers comes from the state the handshake established:
        // a caller that could supply a frame limit, a registration set or a
        // capability set could supply weaker ones.
        let attached = {
            let session = match self.session.lock() {
                Ok(session) => session,
                Err(error) => {
                    return Ok(refused_attach(
                        refused(format!("the session lock was poisoned: {error}")).failure,
                    ));
                }
            };
            match &*session {
                HostSession::Active {
                    identity,
                    supported_registration_operations,
                    capability,
                } => {
                    if request.session_id != identity.session_id {
                        return Ok(refused_attach(
                            refused("this host did not establish that session").failure,
                        ));
                    }
                    // The credential proved which host this is; the capability
                    // proves this transport is one of the session's. An attach
                    // that could be made with the credential alone would let
                    // anyone who could start a host use one it did not start.
                    if !capability.matches(presented.as_deref()) {
                        return Ok(refused_attach(
                            refused(
                                "the attaching transport did not present this session's \
                                 capability",
                            )
                            .failure,
                        ));
                    }
                    if request.protocol_version != identity.protocol_version {
                        return Ok(refused_attach(
                            refused(
                                "the attaching client speaks a protocol version this session \
                                 did not establish",
                            )
                            .failure,
                        ));
                    }
                    nemo_relay_plugin_protocol::PluginAttachedSession {
                        session_id: identity.session_id.clone(),
                        negotiated_frame_limit: identity.maximum_frame_bytes,
                        supported_registration_operations: supported_registration_operations
                            .clone(),
                        accepted_read_capabilities: identity.accepted_read_capabilities.clone(),
                        runtime_binding_digest: self.config.runtime_binding_digest.clone(),
                    }
                }
                HostSession::New => {
                    return Ok(refused_attach(
                        refused("this host has no session to attach to").failure,
                    ));
                }
                HostSession::Closed => {
                    return Ok(refused_attach(
                        refused(
                            "this host has already served its session and will not serve another",
                        )
                        .failure,
                    ));
                }
            }
        };
        Ok(Response::new(attach_outcome_to_wire(
            LifecycleOutcome::Completed(attached),
        )))
    }

    async fn load(
        &self,
        request: Request<v1::LoadRequest>,
    ) -> Result<Response<v1::LoadOutcome>, Status> {
        let presented = presented_capability(&request);
        let wire = request.into_inner();
        let outcome = async {
            let context = self.prepare(
                &wire.session_id,
                presented.as_deref(),
                wire.context.as_ref(),
            )?;
            let request = load_request_from_wire(&wire)?;
            let response = self.backend.load(request, context.clone()).await?;
            // A load that cannot be served in full is a load that does not
            // happen: the backend has already loaded the plugin, so the refusal
            // takes it back down rather than leaving registrations the kernel
            // will never call.
            if let Err(error) = self.unsupported_registrations(&response.descriptor) {
                let unloaded = self
                    .backend
                    .unload(
                        nemo_relay_plugin_protocol::PluginUnloadRequest {
                            handle: response.handle.clone(),
                        },
                        context,
                    )
                    .await;
                return Err(match unloaded {
                    Ok(()) => error,
                    Err(unload_error) => refused(format!(
                        "{}; unloading it again failed: {}",
                        error.failure.message, unload_error.failure.message
                    )),
                });
            }
            Ok(response)
        }
        .await;
        Ok(Response::new(load_outcome_to_wire(
            LifecycleOutcome::from_result(outcome.map_err(|error| error.failure)),
        )))
    }

    async fn unload(
        &self,
        request: Request<v1::UnloadRequest>,
    ) -> Result<Response<v1::UnloadOutcome>, Status> {
        let presented = presented_capability(&request);
        let wire = request.into_inner();
        let outcome = async {
            let context = self.prepare(
                &wire.session_id,
                presented.as_deref(),
                wire.context.as_ref(),
            )?;
            let request = unload_request_from_wire(&wire)?;
            self.backend.unload(request, context).await
        }
        .await;
        Ok(Response::new(unload_outcome_to_wire(
            LifecycleOutcome::from_result(outcome.map_err(|error| error.failure)),
        )))
    }

    async fn inspect(
        &self,
        request: Request<v1::InspectRequest>,
    ) -> Result<Response<v1::InspectOutcome>, Status> {
        let presented = presented_capability(&request);
        let wire = request.into_inner();
        let outcome = async {
            let context = self.prepare(
                &wire.session_id,
                presented.as_deref(),
                wire.context.as_ref(),
            )?;
            let request = inspect_request_from_wire(&wire)?;
            self.backend.inspect(request, context).await
        }
        .await;
        Ok(Response::new(inspect_outcome_to_wire(
            LifecycleOutcome::from_result(outcome.map_err(|error| error.failure)),
        )))
    }

    async fn activate(
        &self,
        request: Request<v1::ActivateRequest>,
    ) -> Result<Response<v1::ActivateOutcome>, Status> {
        let presented = presented_capability(&request);
        let wire = request.into_inner();
        let outcome = async {
            let context = self.prepare(
                &wire.session_id,
                presented.as_deref(),
                wire.context.as_ref(),
            )?;
            let activation = activate_request_from_wire(&wire)?;

            // Everything this activation installs is this guard's, until the
            // session says it will serve it. A discovery session never does, so
            // the guard is what makes inspection leave the process as it found
            // it — on the reporting path, on the refusal path, and on the error
            // paths, rather than on whichever of them remembers to clean up.
            let mut guard = ActivationGuard::new();

            // Activation runs the plugin's register callbacks in *this*
            // process: the configuration comes from the kernel, the callbacks
            // are the plugin's, and what they register is only observable here.
            let mut config = nemo_relay::plugin::PluginConfig::default();
            for component in &activation.components {
                let parsed: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_str(&component.config_json).map_err(|error| {
                        refused(format!(
                            "component '{}' configuration is not a JSON object: {error}",
                            component.kind
                        ))
                    })?;
                config
                    .components
                    .push(nemo_relay::plugin::PluginComponentSpec {
                        kind: component.kind.clone(),
                        enabled: true,
                        config: parsed,
                    });
            }
            nemo_relay::plugin::initialize_plugins_exact(config)
                .await
                .map_err(|error| {
                    refused(format!("the components could not be activated: {error}"))
                })?;

            // What the plugin registered is reported to the kernel, which is
            // what it needs to install a proxy per registration.
            let descriptors = self
                .backend
                .inspect(
                    nemo_relay_plugin_protocol::PluginInspectRequest { handle: None },
                    context,
                )
                .await?;

            // An inspecting session reports what a plugin registered, unsupported
            // classes included, because those are what it is looking for. A
            // serving session refuses instead, and the reason is the same in both
            // directions: one wants to know what it cannot serve, the other must
            // not appear to serve it. The host reports and the kernel decides, so
            // the flag changes what is reported — and, through the guard, whether
            // what was activated outlives the call at all.
            if activation.discovery {
                return Ok(descriptors);
            }

            // A plugin that registered something this session cannot serve is
            // refused here — after activation, where registrations first exist,
            // rather than at load, where they do not yet.
            let mut unsupported = Vec::new();
            for descriptor in &descriptors {
                if let Err(error) = self.unsupported_registrations(descriptor) {
                    unsupported.push(error.failure.message);
                }
            }
            if !unsupported.is_empty() {
                // Fail closed without leaving anything registered: the guard
                // takes back down the callbacks this activation installed.
                return Err(refused(unsupported.join("; ")));
            }
            // This session serves what it activated, so the registrations are
            // its to hold until the session ends.
            guard.commit();
            Ok(descriptors)
        }
        .await;
        Ok(Response::new(activate_outcome_to_wire(
            LifecycleOutcome::from_result(outcome.map_err(|error| error.failure)),
        )))
    }

    async fn invoke(
        &self,
        request: Request<v1::InvokeRequest>,
    ) -> Result<Response<v1::InvokeOutcome>, Status> {
        let presented = presented_capability(&request);
        let wire = request.into_inner();
        // Every answer names the invocation it answers, so a request that
        // carries no operation to name is refused at the transport level: an
        // outcome nobody could attribute to this call is not an answer, and
        // sending one in this message's shape would invite the kernel to read it
        // as one.
        let named = wire
            .context
            .as_ref()
            .map(|context| context.operation_request_id.trim().to_owned())
            .filter(|operation_request_id| !operation_request_id.is_empty());
        let Some(operation_request_id) = named else {
            return Err(Status::invalid_argument(
                "an invocation must carry a context naming the operation it belongs to",
            ));
        };
        // The budget the operation chose, read before the request is consumed by
        // the call it governs: it is the answer's to satisfy, and it has to
        // outlive the call to be checked against what the call produced.
        let response_budget = wire
            .context
            .as_ref()
            .map(|context| context.max_response_bytes);
        // The window in which a plugin's callback runs is the window in which
        // its marks belong to the kernel rather than to this process, so the
        // forwarder is installed around exactly that call.
        let outcome = match &self.mark_forwarding {
            Some(sender) => {
                let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let sink = std::sync::Arc::new(ForwardingSink {
                    sender: sender.clone(),
                    session_id: wire.session_id.clone(),
                    operation_request_id: operation_request_id.clone(),
                    closed: std::sync::Arc::clone(&closed),
                    host_calls: std::sync::atomic::AtomicU64::new(0),
                });
                // The window is open for the call and no longer: what closes it is
                // this guard, on every way out of the invocation.
                let _window = ClosedOnDrop(closed);
                let answered = nemo_relay::plugin::execution::with_mark_forwarder(
                    sink,
                    self.serve_invocation(wire, presented.as_deref()),
                )
                .await;
                // What the invocation raised is delivered before the answer that
                // ends it. A mark that could not be delivered is not a lost log
                // line: the invocation produced evidence this kernel will never
                // see, so the answer it would have given is not one the kernel
                // may read as complete.
                let (done, delivered) = tokio::sync::oneshot::channel();
                // Waiting for room rather than refusing: the flush is what makes
                // the marks ahead of it accounted for, so a flush that could not
                // be queued would report the invocation complete while its
                // evidence was still here. A kernel that stopped reading is
                // reached by the operation's own deadline instead.
                if sender.send(ForwardedStep::Flush { done }).await.is_err() {
                    return Err(Status::unavailable(
                        "this host can no longer reach the kernel its plugins' marks belong to",
                    ));
                }
                match delivered.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        return Err(Status::unavailable(format!(
                            "the marks this invocation raised could not be delivered: {error}"
                        )));
                    }
                    Err(_) => {
                        return Err(Status::unavailable(
                            "this host stopped forwarding before this invocation's marks were \
                             delivered",
                        ));
                    }
                }
                answered
            }
            None => self.serve_invocation(wire, presented.as_deref()).await,
        };

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => refusal(error.failure.message),
        };
        let outcome = execution_outcome_to_wire(&outcome, &operation_request_id)
            .map_err(|error| Status::internal(error.failure.message))?;
        // A budget nobody measures is advice. The transport's frame limit is not
        // the same limit: an answer that fits the frame can still be far larger
        // than the operation was allowed to return, so the host measures what it
        // is about to send and refuses here, where the kernel can read the reason
        // rather than having the answer truncated somewhere below it.
        if let Some(budget) = response_budget
            && let Err(oversized) =
                nemo_relay_plugin_proto::convert::check_invoke_outcome_budget(&outcome, budget)
        {
            let refusal = execution_outcome_to_wire(
                &refusal_with(oversized.failure.code, oversized.failure.message),
                &operation_request_id,
            )
            .map_err(|error| Status::internal(error.failure.message))?;
            return Ok(Response::new(refusal));
        }
        Ok(Response::new(outcome))
    }

    async fn cancel_operation(
        &self,
        _request: Request<v1::CancelOperationRequest>,
    ) -> Result<Response<v1::CancelOperationOutcome>, Status> {
        // Nothing to authorise: this answer is the same for every caller, and
        // there is no session state behind it for a capability to protect.
        Ok(Response::new(cancel_outcome_to_wire(
            LifecycleOutcome::Failed(nemo_relay_plugin_protocol::PluginFailure {
                code: nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
                message: "this host has no cancellable operations".to_string(),
            }),
        )))
    }

    async fn health(
        &self,
        request: Request<v1::HealthRequest>,
    ) -> Result<Response<v1::HealthOutcome>, Status> {
        let presented = presented_capability(&request);
        let wire = request.into_inner();
        let outcome = async {
            let context = self.prepare(
                &wire.session_id,
                presented.as_deref(),
                wire.context.as_ref(),
            )?;
            self.backend.health(context).await
        }
        .await;
        Ok(Response::new(health_outcome_to_wire(
            LifecycleOutcome::from_result(outcome.map_err(|error| error.failure)),
        )))
    }

    type InvokeStreamStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<v1::StreamChunk, Status>> + Send>>;

    async fn invoke_stream(
        &self,
        request: Request<v1::InvokeRequest>,
    ) -> Result<Response<Self::InvokeStreamStream>, Status> {
        let refusal = |operation_request_id: String, message: String| -> Self::InvokeStreamStream {
            // A refusal travels as a terminal frame rather than as a transport
            // status, because a stream that simply stopped would be a truncation
            // the kernel cannot distinguish from a host that died mid-answer.
            Box::pin(tokio_stream::iter(vec![Ok(v1::StreamChunk {
                // Named when the caller named one: a terminal frame that belongs
                // to no operation is not a terminal frame.
                operation_request_id,
                chunk: Some(v1::stream_chunk::Chunk::Failure(v1::PluginFailure {
                    code: nemo_relay_plugin_proto::v1::FailureCode::Rejected as i32,
                    message,
                    ..Default::default()
                })),
                dispatch_state: nemo_relay_plugin_protocol::DispatchState::NotDispatched as i32,
                outcome_certainty: nemo_relay_plugin_protocol::OutcomeCertainty::ConfirmedFailure
                    as i32,
            })]))
        };

        let capability = presented_capability(&request);
        let wire = request.into_inner();
        let operation_request_id = wire
            .context
            .as_ref()
            .map(|context| context.operation_request_id.trim().to_owned())
            .unwrap_or_default();
        let context = match self.prepare(
            &wire.session_id,
            capability.as_deref(),
            wire.context.as_ref(),
        ) {
            Ok(context) => context,
            Err(error) => {
                return Ok(Response::new(refusal(
                    operation_request_id,
                    error.failure.message,
                )));
            }
        };
        let invocation = match invoke_request_from_wire(&wire, &context) {
            Ok(invocation) => invocation,
            Err(error) => {
                return Ok(Response::new(refusal(
                    operation_request_id,
                    error.failure.message,
                )));
            }
        };
        // The class this RPC carries is the one whose answer is a stream. A
        // registration of another class is refused rather than run: its answer
        // would be a value, and a value sent as the first frame of a stream is an
        // answer nobody asked for in that shape.
        match self.registration_operation(&invocation, &context).await {
            Ok(nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmStreamExecutionIntercept) => {}
            Ok(other) => {
                return Ok(Response::new(refusal(
                    operation_request_id,
                    format!("this host serves streaming invocations for one class, not {}", other.as_str()),
                )))
            }
            Err(error) => {
                return Ok(Response::new(refusal(operation_request_id, error.failure.message)))
            }
        }

        let Some(kernel) = self.kernel.clone() else {
            return Ok(Response::new(refusal(
                operation_request_id,
                "this host has no kernel to pull a wrapped stream from, so a streaming intercept \
                 cannot be served here"
                    .to_string(),
            )));
        };
        let session = match self.session(&kernel, &wire.session_id).await {
            Ok(session) => session,
            Err(message) => return Ok(Response::new(refusal(operation_request_id, message))),
        };

        let payload: serde_json::Value = match serde_json::from_str(&invocation.arguments) {
            Ok(payload) => payload,
            Err(error) => {
                return Ok(Response::new(refusal(
                    operation_request_id,
                    format!("a streaming intercept payload must be JSON: {error}"),
                )));
            }
        };
        let Some(name) = payload.get("name").and_then(|value| value.as_str()) else {
            return Ok(Response::new(refusal(
                operation_request_id,
                "a streaming intercept payload names no provider".to_string(),
            )));
        };
        let name = name.to_owned();
        let request_json = payload.get("request").cloned().unwrap_or_default();
        let provider_request: nemo_relay::api::llm::LlmRequest = match serde_json::from_value(
            request_json,
        ) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::new(refusal(
                    operation_request_id,
                    format!(
                        "a streaming intercept payload carries something that is not a request: {error}"
                    ),
                )));
            }
        };

        // The continuation the plugin pulls its downstream stream through. Each
        // call opens the stream the kernel is producing for this operation, so a
        // callback that pulls late — inside its own returned stream, which is
        // what a lazy adapter does — still reaches the same chain position.
        let operation = context.operation_request_id.clone();
        let pulled = std::sync::Arc::clone(&session);
        let next: nemo_relay::api::runtime::LlmStreamExecutionNextFn =
            std::sync::Arc::new(move |request| {
                let session = std::sync::Arc::clone(&pulled);
                let operation = operation.clone();
                Box::pin(async move {
                    session
                        .open_stream(&operation, &request)
                        .await
                        // The managed stream the callback receives: the same
                        // value an in-process plugin is handed, so a callback
                        // written against the ABI does not know the difference.
                        .map(crate::session_channel::PullStream::into_managed)
                        .map_err(|error| {
                            nemo_relay::error::FlowError::Internal(format!(
                                "the wrapped stream could not be opened: {error}"
                            ))
                        })
                })
            });

        // The window this call's marks belong to, opened for as long as the call's
        // work runs. A streaming callback's work outlives this call — the stream it
        // returns is polled long afterwards — so the window is not a scope around
        // the call: it is a handle the callback's own task carries, and it stays
        // open until the call's frames are done with.
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marks = self.mark_forwarding.clone();
        let answered = match &marks {
            Some(sender) => {
                let sink = std::sync::Arc::new(ForwardingSink {
                    sender: sender.clone(),
                    session_id: wire.session_id.clone(),
                    operation_request_id: context.operation_request_id.clone(),
                    closed: std::sync::Arc::clone(&closed),
                    host_calls: std::sync::atomic::AtomicU64::new(0),
                });
                nemo_relay::plugin::execution::with_mark_forwarder(
                    sink,
                    nemo_relay::api::llm::invoke_llm_stream_execution_intercept_registration(
                        &invocation.registration_id,
                        &name,
                        provider_request,
                        next,
                    ),
                )
                .await
            }
            None => {
                nemo_relay::api::llm::invoke_llm_stream_execution_intercept_registration(
                    &invocation.registration_id,
                    &name,
                    provider_request,
                    next,
                )
                .await
            }
        };
        let stream = match answered {
            Ok(stream) => stream,
            Err(error) => {
                return Ok(Response::new(refusal(
                    operation_request_id,
                    error.to_string(),
                )));
            }
        };

        Ok(Response::new(Box::pin(PluginFrames {
            stream,
            operation_request_id: context.operation_request_id.clone(),
            ending: None,
            flushing: None,
            ended: false,
            marks,
            closed: Some(closed),
        })))
    }

    async fn session_close(
        &self,
        request: Request<v1::SessionCloseRequest>,
    ) -> Result<Response<v1::SessionCloseOutcome>, Status> {
        let presented = presented_capability(&request);
        let wire = request.into_inner();
        // A refusal travels as an outcome rather than as a transport status: a
        // session that is already gone is a result, and a channel failure is a
        // different event that the kernel has to read differently.
        let established = self
            .established(&wire.session_id)
            .and_then(|()| self.capability_admitted(presented.as_deref()));
        if let Err(error) = established {
            return Ok(Response::new(session_close_outcome_to_wire(
                LifecycleOutcome::Failed(error.failure),
            )));
        }
        match self.session.lock() {
            // Closing is a state change the host makes: the session is gone
            // afterwards, so every later request is refused by the same check
            // that refuses one naming no session.
            Ok(mut session) => *session = HostSession::Closed,
            Err(error) => {
                return Ok(Response::new(session_close_outcome_to_wire(
                    LifecycleOutcome::Failed(
                        refused(format!("the session lock was poisoned: {error}")).failure,
                    ),
                )));
            }
        }
        Ok(Response::new(session_close_outcome_to_wire(
            LifecycleOutcome::Completed(()),
        )))
    }
}

impl PluginHostService {
    /// The operation a registration was made at, from the host's own record.
    ///
    /// An invocation naming a registration this host does not hold is refused
    /// rather than mapped to whichever registration happens to be close: the
    /// kernel installs one proxy per registration, and a proxy that ran another
    /// one would be a different call than the one it stands for.
    async fn registration_operation(
        &self,
        request: &nemo_relay_plugin_protocol::PluginInvokeRequest,
        context: &nemo_relay_plugin_protocol::PluginExecutionContext,
    ) -> Result<nemo_relay_plugin_protocol::PluginRegistrationOperation, PluginProtocolError> {
        let descriptors = self
            .backend
            .inspect(
                nemo_relay_plugin_protocol::PluginInspectRequest {
                    handle: Some(request.handle.clone()),
                },
                context.clone(),
            )
            .await?;
        let descriptor = descriptors.first().ok_or_else(|| {
            PluginProtocolError::new(
                nemo_relay_plugin_protocol::PluginFailureCode::UnknownPlugin,
                format!("plugin {} is not loaded", request.handle.plugin_id),
            )
        })?;
        descriptor
            .registrations
            .iter()
            .find(|registration| registration.registration_id == request.registration_id)
            .map(|registration| registration.operation)
            .ok_or_else(|| {
                refused(format!(
                    "plugin {} has no registration named '{}'",
                    descriptor.plugin_id, request.registration_id
                ))
            })
    }

    /// The channel a streaming invocation pulls its downstream stream over.
    ///
    /// One per host, created on first use: the kernel serves one session, so a
    /// second channel would be a second reader of the same session's answers.
    async fn session(
        &self,
        kernel: &crate::runtime_service::KernelCallbacks,
        session_id: &str,
    ) -> Result<std::sync::Arc<crate::session_channel::SessionChannel>, String> {
        let mut slot = self.session_channel.lock().await;
        if let Some(session) = slot.as_ref() {
            return Ok(std::sync::Arc::clone(session));
        }
        let session = std::sync::Arc::new(kernel.open_session(session_id).await?);
        *slot = Some(std::sync::Arc::clone(&session));
        Ok(session)
    }

    /// Validate the session and context of one operation.
    fn prepare(
        &self,
        session_id: &str,
        capability: Option<&str>,
        context: Option<&v1::PluginExecutionContext>,
    ) -> Result<nemo_relay_plugin_protocol::PluginExecutionContext, PluginProtocolError> {
        self.established(session_id)?;
        self.capability_admitted(capability)?;
        let envelope = operation_envelope_from_wire(session_id, context)?;
        // The host checks the context against this session itself rather than
        // trusting the kernel to have done it: a peer that reaches this service
        // could send a structurally valid context that is bound to another
        // runtime, carries no budget, or is already out of time.
        nemo_relay_plugin_protocol::check_execution_context(
            &envelope.context,
            &self.config.runtime_binding_digest,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_millis() as u64)
                .unwrap_or(0),
        )?;
        Ok(envelope.context)
    }

    /// Refuse an operation that did not present the session's capability.
    ///
    /// The session's identity says which session a request means; this says the
    /// request may use it. A peer that learned the identity — an attach
    /// announces it — is not therefore a peer that established the session, and
    /// this is where those two stop being the same thing.
    fn capability_admitted(&self, presented: Option<&str>) -> Result<(), PluginProtocolError> {
        let session = self
            .session
            .lock()
            .map_err(|error| refused(format!("the session lock was poisoned: {error}")))?;
        match &*session {
            HostSession::Active { capability, .. } if capability.matches(presented) => Ok(()),
            HostSession::Active { .. } => Err(refused(
                "the request did not present the capability this session requires",
            )),
            // A host that is not serving refuses everything, and a request that
            // presented no capability is refused by the same rule as one that
            // presented the wrong one.
            _ => Err(refused("this host has not established a session")),
        }
    }
}

/// Run one tool sanitize guardrail over the payload a tool call would publish.
///
/// The payload is the class's own shape — the tool's name and the JSON an event
/// would carry — and the answer is either the sanitized copy or a refusal, which
/// is how the chain's "omit the payload" reaches the kernel.
async fn sanitized_tool_payload(
    request: &nemo_relay_plugin_protocol::PluginInvokeRequest,
    response_direction: bool,
) -> Result<nemo_relay_plugin_protocol::PluginExecutionOutcome, PluginProtocolError> {
    let payload: serde_json::Value = serde_json::from_str(&request.arguments)
        .map_err(|error| refused(format!("a tool sanitize payload must be JSON: {error}")))?;
    let tool = payload
        .get("tool")
        .and_then(|value| value.as_str())
        .ok_or_else(|| refused("a tool sanitize payload names no tool"))?
        .to_string();
    let value = payload
        .get("value")
        .cloned()
        .ok_or_else(|| refused("a tool sanitize payload carries no value"))?;
    let sanitized = if response_direction {
        nemo_relay::api::tool::invoke_tool_sanitize_response_registration(
            &request.registration_id,
            &tool,
            value,
        )
        .await
    } else {
        nemo_relay::api::tool::invoke_tool_sanitize_request_registration(
            &request.registration_id,
            &tool,
            value,
        )
        .await
    };
    match sanitized {
        Ok(Some(sanitized)) => Ok(success(serde_json::to_string(&sanitized).map_err(
            |error| {
                refused(format!(
                    "the sanitized payload could not be serialized: {error}"
                ))
            },
        )?)),
        // A payload that could not be sanitized is not published unsanitized: the
        // chain omits it, and a refusal is what tells the kernel to do the same.
        Ok(None) => Ok(refusal(
            "the guardrail omitted the payload rather than publishing it unsanitized",
        )),
        Err(error) => Ok(refusal(error.to_string())),
    }
}

/// Run one LLM request sanitize registration over the payload a call would publish.
///
/// Three things cross: the request, the codec's *identity* — which is what a sanitizer
/// decides with — and a *reference* it may spend on this invocation. The codec itself does
/// not cross, because it cannot: it is a live object the kernel holds, and the reference is
/// how the plugin asks for work to be done with it. The host's part is to build the context
/// the plugin's callback sees, which is the same context it would see in process — an
/// identity it can read, and a handle that reaches the object where the object lives.
///
/// A payload that names a codec without a reference, or a call that names a codec when this
/// host has no kernel to resolve it with, is refused rather than served with a context whose
/// handle would fail later: a sanitizer that cannot use the codec its call is running under
/// is a sanitizer that has been misled about what it is sanitizing.
async fn sanitized_llm_request(
    request: &nemo_relay_plugin_protocol::PluginInvokeRequest,
    kernel: Option<crate::runtime_service::KernelCallbacks>,
    session_id: &str,
    operation_request_id: &str,
) -> Result<nemo_relay_plugin_protocol::PluginExecutionOutcome, PluginProtocolError> {
    let payload: serde_json::Value = serde_json::from_str(&request.arguments).map_err(|error| {
        refused(format!(
            "an LLM request sanitize payload must be JSON: {error}"
        ))
    })?;
    let sanitize_request: nemo_relay::api::llm::LlmRequest = serde_json::from_value(
        payload
            .get("request")
            .cloned()
            .ok_or_else(|| refused("an LLM request sanitize payload carries no request"))?,
    )
    .map_err(|error| refused(format!("the request to sanitize is not a request: {error}")))?;
    let call_context = payload
        .get("context")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let kind = call_context
        .get("codec_kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("none");
    let id = call_context
        .get("codec_id")
        .and_then(serde_json::Value::as_str);
    let identity = crate::codec_context::identity_from_wire(kind, id)
        .map_err(|error| refused(error.to_string()))?;

    let sanitize_context = match identity {
        // No codec was active for this call, and the sanitizer is told exactly that: its
        // handle resolves nothing, which is what the identity says.
        nemo_relay_plugin_protocol::LlmCodecIdentity::None => {
            nemo_relay::api::runtime::LlmSanitizeRequestContext::with_identity(
                nemo_relay_plugin_protocol::LlmCodecIdentity::None,
            )
        }
        identity => {
            let Some(kernel) = kernel else {
                return Err(refused(
                    "this host has no kernel to resolve the call's codec with, so an LLM \
                     request sanitizer cannot be served the codec its call is running under",
                ));
            };
            let Some(reference) = call_context
                .get("codec_reference")
                .and_then(serde_json::Value::as_str)
            else {
                return Err(refused(
                    "an LLM request sanitize payload names a codec without the capability \
                     reference that would let a sanitizer use it",
                ));
            };
            nemo_relay::api::runtime::LlmSanitizeRequestContext::for_request_codec(Some(
                std::sync::Arc::new(crate::codec_context::KernelRequestCodec::new(
                    kernel,
                    session_id,
                    operation_request_id,
                    identity,
                    reference,
                )),
            ))
        }
    };

    match nemo_relay::api::llm::invoke_llm_sanitize_request_registration(
        &request.registration_id,
        sanitize_request,
        sanitize_context,
    )
    .await
    {
        Ok(outcome) => match (outcome.request, outcome.failure) {
            (Some(request), _) => Ok(success(serde_json::to_string(&request).map_err(
                |error| {
                    refused(format!(
                        "the sanitized request could not be serialized: {error}"
                    ))
                },
            )?)),
            // A sanitizer that did not answer, and one that answered with nothing, are the
            // family's omission either way: the payload is not published, and a refusal is
            // what tells the kernel to omit it too.
            (None, Some(reason)) => Ok(refusal(format!("the sanitizer did not answer: {reason}"))),
            (None, None) => Ok(refusal(
                "the sanitizer omitted the payload rather than publishing it unsanitized",
            )),
        },
        Err(error) => Ok(refusal(error.to_string())),
    }
}

/// Run one event sanitize registration over the projection a kernel sent.
///
/// The class is part of the capability, so two things are checked before anything
/// runs: that the projection names a class this registration is, and that the
/// projection states the phase its class sanitizes. Both are refusals rather than
/// coercions — three families share one serialization, and a structurally valid
/// projection for another family is exactly the confusion the check exists for.
///
/// What the runtime's chain is given is a *synthetic* event built from the
/// projection: the name the sanitizer decides on, the phase of its class, and the
/// mutable fields. The sanitizer is not shown the kernel's event because the
/// kernel's event never left the kernel, which is why nothing it answers with can
/// rename, re-parent or re-time the event it sanitized.
async fn sanitized_event_fields(
    request: &nemo_relay_plugin_protocol::PluginInvokeRequest,
    operation: nemo_relay_plugin_protocol::PluginRegistrationOperation,
) -> Result<nemo_relay_plugin_protocol::PluginExecutionOutcome, PluginProtocolError> {
    use nemo_relay_plugin_protocol::{
        PluginEventSanitizeCall, PluginEventSanitizeClass, PluginRegistrationOperation,
    };

    let call: PluginEventSanitizeCall =
        serde_json::from_str(&request.arguments).map_err(|error| {
            refused(format!(
                "an event sanitize payload must be a sanitizer projection: {error}"
            ))
        })?;
    let expected = match operation {
        PluginRegistrationOperation::MarkSanitizeGuardrail => PluginEventSanitizeClass::Mark,
        PluginRegistrationOperation::ScopeSanitizeStartGuardrail => {
            PluginEventSanitizeClass::ScopeStart
        }
        PluginRegistrationOperation::ScopeSanitizeEndGuardrail => {
            PluginEventSanitizeClass::ScopeEnd
        }
        other => {
            return Err(refused(format!(
                "this host has no event sanitize runner for {}",
                other.as_str()
            )));
        }
    };
    if call.class != expected {
        return Err(refused(format!(
            "registration '{}' is a {expected:?} sanitizer and the projection is for {:?}",
            request.registration_id, call.class
        )));
    }
    let event = call
        .into_event()
        .map_err(|error| refused(error.failure.message))?;
    let sanitized = match operation {
        PluginRegistrationOperation::MarkSanitizeGuardrail => {
            nemo_relay::api::event::invoke_mark_sanitize_registration(
                &request.registration_id,
                event,
            )
            .await
        }
        PluginRegistrationOperation::ScopeSanitizeStartGuardrail => {
            nemo_relay::api::event::invoke_scope_sanitize_start_registration(
                &request.registration_id,
                event,
            )
            .await
        }
        _ => {
            nemo_relay::api::event::invoke_scope_sanitize_end_registration(
                &request.registration_id,
                event,
            )
            .await
        }
    };
    match sanitized {
        // Only the mutable fields go back. The chain here applied the answer to the
        // synthetic event, and what the kernel publishes is those fields applied to
        // *its* event — so the answer's identity fields, whatever they are, are never
        // read.
        Ok(sanitized) if sanitized.failure.is_none() => Ok(success(
            serde_json::to_string(&sanitized.event.sanitize_fields()).map_err(|error| {
                refused(format!(
                    "the sanitized fields could not be serialized: {error}"
                ))
            })?,
        )),
        // A sanitizer that did not answer is a refusal rather than a payload that was
        // cleared: the fields really are cleared either way, and the kernel is the
        // side that has to record *why*, because the log line for it is in this
        // process and the kernel's stream is where a plugin's failures belong.
        Ok(sanitized) => Ok(refusal(format!(
            "the {} sanitizer did not answer: {}",
            operation.as_str(),
            sanitized.failure.unwrap_or_default()
        ))),
        Err(error) => Ok(refusal(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay_plugin_proto::convert::{handshake_outcome_from_wire, mark_request_from_wire};
    use nemo_relay_plugin_protocol::{
        PluginDescriptor, PluginFailure, PluginFailureCode, PluginHandle, PluginHostReadCapability,
        PluginLoadResponse,
    };
    use tonic::Request;
    use v1::plugin_host_server::PluginHost;

    /// The credential the kernel half of the streaming test is started with.
    const KERNEL_CREDENTIAL: &str = "stream-test-kernel-credential";

    /// A kernel serving one session, with a downstream stream parked for
    /// `operation-stream`.
    ///
    /// The host's half of the boundary is what is under test, so this is the
    /// smallest kernel that can answer it: one stream for one operation, and the
    /// session channel that carries the plugin's pulls.
    async fn serve_kernel_with_stream(
        session_id: &str,
        chunks: Vec<serde_json::Value>,
    ) -> (std::path::PathBuf, tokio::task::JoinHandle<()>) {
        serve_kernel_with_producer(
            session_id,
            "operation-stream",
            chunks,
            KernelProducer::watching(),
        )
        .await
    }

    /// What a kernel's producer says about its own lifetime.
    ///
    /// A cancellation is only proved by the last step of the cascade: the work
    /// behind the consumer stops. A test that watched the session channel would
    /// see a message about stopping rather than the effect, so the producer
    /// reports when it was created and when it was dropped, and — for the window
    /// no amount of timing can hit twice — parks where a test can see it and
    /// continues when the test says so.
    #[derive(Clone)]
    struct KernelProducer {
        /// Set once the kernel has created a producer for a stream.
        produced: Arc<std::sync::atomic::AtomicBool>,
        /// Set when that producer is dropped.
        dropped: Arc<std::sync::atomic::AtomicBool>,
        /// A pause the kernel takes before it creates the producer.
        gate: Option<Arc<KernelGate>>,
    }

    impl KernelProducer {
        /// A producer that says when it was made and when it was dropped.
        fn watching() -> Self {
            Self {
                produced: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                gate: None,
            }
        }

        /// The same producer, with the kernel parking as it opens.
        ///
        /// The consumer walking away while the open is in flight is a race the
        /// scheduler decides unless the kernel is held in it: this is what makes
        /// it the state the test names.
        fn gated() -> Self {
            Self {
                gate: Some(Arc::new(KernelGate {
                    entered: tokio::sync::Notify::new(),
                    release: tokio::sync::Notify::new(),
                })),
                ..Self::watching()
            }
        }

        /// Wait until the kernel has created its producer.
        async fn await_produced(&self) {
            self.await_flag(&self.produced, "the kernel created a producer")
                .await;
        }

        /// Wait until the kernel is inside the open it was asked for.
        async fn await_open_in_flight(&self) {
            let gate = self
                .gate
                .as_ref()
                .expect("only a gated producer opens in flight");
            tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
                .await
                .expect("the kernel reaches the open it was asked for");
        }

        /// Let the kernel finish the open it is parked in.
        fn release_open(&self) {
            if let Some(gate) = &self.gate {
                gate.release.notify_one();
            }
        }

        /// Wait until the kernel's producer is gone.
        async fn await_dropped(&self, when: &str) {
            self.await_flag(
                &self.dropped,
                &format!("the kernel dropped its producer {when}"),
            )
            .await;
        }

        async fn await_flag(&self, flag: &std::sync::atomic::AtomicBool, what: &str) {
            let reached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !flag.load(std::sync::atomic::Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await;
            assert!(reached.is_ok(), "{what}");
        }
    }

    /// A pause the kernel takes before it creates a producer.
    struct KernelGate {
        /// Fires as the kernel parks, so a test knows the open is in flight.
        entered: tokio::sync::Notify,
        /// Released by the test to let the kernel create the producer.
        release: tokio::sync::Notify,
    }

    /// The kernel with a producer whose lifetime the test can observe.
    async fn serve_kernel_with_producer(
        session_id: &str,
        operation: &str,
        chunks: Vec<serde_json::Value>,
        producer: KernelProducer,
    ) -> (std::path::PathBuf, tokio::task::JoinHandle<()>) {
        serve_kernel_with_producers(session_id, vec![(operation, chunks)], producer).await
    }

    /// The same kernel, serving one stream per operation.
    ///
    /// The matrix needs two operations in flight at once and one host talking to
    /// both, which is what a kernel is: one session, several streams, each of them
    /// producing for its own operation.
    async fn serve_kernel_with_producers(
        session_id: &str,
        operations: Vec<(&str, Vec<serde_json::Value>)>,
        producer: KernelProducer,
    ) -> (std::path::PathBuf, tokio::task::JoinHandle<()>) {
        use nemo_relay_plugin_proto::v1::relay_runtime_server::RelayRuntimeServer;
        use tonic::transport::Server;

        let continuations = Arc::new(crate::continuations::Continuations::new());
        for (operation, chunks) in operations {
            let producer = producer.clone();
            let stream: nemo_relay::api::runtime::LlmStreamExecutionNextFn =
                Arc::new(move |_request| {
                    let chunks = chunks.clone();
                    let producer = producer.clone();
                    Box::pin(async move {
                        /// A producer that says when it is gone.
                        struct Watched {
                            items: std::vec::IntoIter<serde_json::Value>,
                            dropped: Arc<std::sync::atomic::AtomicBool>,
                        }
                        impl tokio_stream::Stream for Watched {
                            type Item =
                                Result<nemo_relay::json::Json, nemo_relay::error::FlowError>;
                            fn poll_next(
                                mut self: std::pin::Pin<&mut Self>,
                                _context: &mut std::task::Context<'_>,
                            ) -> std::task::Poll<Option<Self::Item>> {
                                std::task::Poll::Ready(self.items.next().map(Ok))
                            }
                        }
                        impl Drop for Watched {
                            fn drop(&mut self) {
                                self.dropped
                                    .store(true, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                        if let Some(gate) = &producer.gate {
                            gate.entered.notify_one();
                            gate.release.notified().await;
                        }
                        producer
                            .produced
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        Ok(nemo_relay::api::runtime::LlmJsonStream::new(Watched {
                            items: chunks.into_iter(),
                            dropped: Arc::clone(&producer.dropped),
                        }))
                    })
                });
            // Held for the test's lifetime: the kernel's session outlives this call.
            std::mem::forget(continuations.hold_llm_stream(
                operation,
                "registration-stream",
                stream,
            ));
        }

        let runtime = crate::runtime_service::RelayRuntimeService::new(
            crate::runtime_service::RelayRuntimeConfig {
                session_id: session_id.to_owned(),
                session_credential: KERNEL_CREDENTIAL.into(),
                protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
                runtime_binding_digest: "binding".into(),
                operation_scopes: Arc::new(crate::operation_scopes::OperationScopes::new()),
                continuations,
                codecs: Arc::new(crate::codec_capability::CodecCapabilities::new()),
            },
        );
        let directory =
            std::env::temp_dir().join(format!("nemo-stream-kernel-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&directory).expect("a socket directory");
        let endpoint = directory.join("k");
        let listener = tokio::net::UnixListener::bind(&endpoint).expect("a kernel socket");
        let serving = tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(RelayRuntimeServer::new(runtime))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
                .await;
        });
        (endpoint, serving)
    }

    fn service() -> (PluginHostService, PluginHostConfig) {
        let backend = Arc::new(crate::InProcessPluginBackend::new());
        let config = PluginHostConfig {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        };
        (PluginHostService::new(backend, config.clone()), config)
    }

    /// The capability the tests' requests present.
    ///
    /// A fixed value rather than a minted one, so a test can say which request
    /// presents which capability — including a request that presents another
    /// session's.
    const TEST_CAPABILITY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A request presenting `capability`.
    fn with_capability<T>(message: T, capability: &str) -> Request<T> {
        let mut request = Request::new(message);
        request.metadata_mut().insert(
            crate::capability::SESSION_CAPABILITY_HEADER,
            capability
                .parse()
                .expect("a test capability is a header value"),
        );
        request
    }

    /// A request presenting the capability every established session is given.
    fn capable<T>(message: T) -> Request<T> {
        with_capability(message, TEST_CAPABILITY)
    }

    fn handshake_request(config: &PluginHostConfig) -> v1::HandshakeRequest {
        v1::HandshakeRequest {
            protocol_version: u32::from(PROTOCOL_VERSION),
            runtime_binding_digest: config.runtime_binding_digest.clone(),
            client_nonce: "nonce".into(),
            session_credential: config.session_credential.clone(),
            maximum_frame_bytes: config.maximum_frame_bytes,
            supported_features: Vec::new(),
            offered_read_capabilities: vec![
                nemo_relay_plugin_proto::convert::read_capability_to_wire(
                    PluginHostReadCapability::RuntimeDiagnostics,
                ),
            ],
            supported_registration_operations: vec![
                nemo_relay_plugin_proto::convert::registration_operation_to_wire(
                    nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolRequestIntercept,
                ),
            ],
        }
    }

    fn context() -> v1::PluginExecutionContext {
        nemo_relay_plugin_proto::convert::context_to_wire(
            &nemo_relay_plugin_protocol::PluginExecutionContext {
                operation_request_id: "operation-1".into(),
                protocol_version: PROTOCOL_VERSION,
                runtime_binding_digest: "binding".into(),
                deadline_unix_ms: u64::MAX,
                remaining_budget_millis: 1_000,
                max_response_bytes: 1024,
            },
        )
    }

    /// The same context, with the response budget this test is about.
    fn context_with_budget(max_response_bytes: u32) -> v1::PluginExecutionContext {
        let mut wire = context();
        wire.max_response_bytes = max_response_bytes;
        wire
    }

    /// The single-registration fixture, and the manifest written to describe it.
    ///
    /// This fixture registers exactly the classes a kernel can serve, so a
    /// session that supports everything can activate it. That is what makes it
    /// the right fixture for asking what activation itself did: a refused
    /// activation would be a statement about the registration set rather than
    /// about the activation.
    fn intercept_fixture() -> Option<(std::path::PathBuf, String)> {
        let library = std::env::var_os("NEMO_RELAY_TEST_NATIVE_INTERCEPT_PLUGIN")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
                    "../../target/test-plugin-fixtures/debug/\
                     libnemo_relay_native_intercept_fixture.dylib",
                )
            });
        if !library.exists() {
            return None;
        }
        let manifest_dir =
            std::env::temp_dir().join(format!("nemo-ph-intercept-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&manifest_dir).expect("a manifest directory");
        let manifest = manifest_dir.join("relay-plugin.toml");
        std::fs::write(
            &manifest,
            format!(
                "manifest_version = 1\n\n[plugin]\nid = \"fixture_intercept\"\nkind = \
                 \"rust_dynamic\"\n\n[compat]\nrelay = \"={}\"\nnative_api = \
                 \"1\"\n\n[defaults]\nenabled = false\n\n[capabilities]\nitems = \
                 [\"plugin_native\"]\n\n[load]\nlibrary = \"{}\"\nsymbol = \
                 \"nemo_relay_native_intercept_fixture\"\n",
                env!("CARGO_PKG_VERSION"),
                library.display()
            ),
        )
        .expect("write the manifest");
        Some((manifest_dir, manifest.to_string_lossy().into_owned()))
    }

    /// A host serving one session, with the single-registration fixture loaded.
    ///
    /// The session supports every registration class, so activation is decided
    /// by what the plugin registered rather than by what the session can proxy.
    struct FixtureSession {
        service: PluginHostService,
        session_id: String,
        handle: nemo_relay_plugin_protocol::PluginHandle,
        manifest_dir: std::path::PathBuf,
    }

    impl FixtureSession {
        async fn start(maximum_frame_bytes: u32, offered_frame_bytes: u32) -> Option<Self> {
            let (manifest_dir, artifact) = intercept_fixture()?;
            let backend = Arc::new(crate::InProcessPluginBackend::new());
            let config = PluginHostConfig {
                protocol_version: PROTOCOL_VERSION,
                runtime_binding_digest: "binding".into(),
                session_credential: "credential".into(),
                maximum_frame_bytes,
            };
            let service = PluginHostService::new(backend, config.clone());
            let mut request = handshake_request(&config);
            request.maximum_frame_bytes = offered_frame_bytes;
            request.supported_registration_operations = EVERY_REGISTRATION_OPERATION
                .iter()
                .map(|operation| {
                    nemo_relay_plugin_proto::convert::registration_operation_to_wire(*operation)
                })
                .collect();
            let session_id = handshake_outcome_from_wire(
                &service
                    .handshake(capable(request))
                    .await
                    .expect("a served handshake")
                    .into_inner(),
            )
            .expect("a converted handshake")
            .into_result()
            .expect("an established session")
            .session_id;

            let (manifest_sha256, library_sha256) =
                nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact)
                    .expect("the fixture's identity");
            let loaded = service
                .load(capable(v1::LoadRequest {
                    session_id: session_id.clone(),
                    context: Some(context()),
                    plugin_id: "fixture_intercept".into(),
                    artifact,
                    manifest_digest: manifest_sha256,
                    library_digest: library_sha256,
                }))
                .await
                .expect("a served load")
                .into_inner();
            let handle = nemo_relay_plugin_proto::convert::load_outcome_from_wire(&loaded)
                .expect("a converted load")
                .into_result()
                .expect("a load")
                .handle;
            Some(Self {
                service,
                session_id,
                handle,
                manifest_dir,
            })
        }

        /// Activate the loaded plugin, reporting or serving what it registered.
        async fn activate(&self, discovery: bool) -> v1::ActivateOutcome {
            self.service
                .activate(capable(v1::ActivateRequest {
                    session_id: self.session_id.clone(),
                    context: Some(context()),
                    discovery,
                    components: vec![v1::ComponentConfiguration {
                        kind: "fixture_intercept".into(),
                        config_json: "{}".into(),
                    }],
                }))
                .await
                .expect("a served activation")
                .into_inner()
        }

        /// Activate the loaded plugin with the configuration a test chooses.
        ///
        /// The same call as [`Self::activate`] with the one difference this suite
        /// needs: the fixture registers the classes a kernel can proxy by default,
        /// and the event sanitizers are asked for by configuration until the kernel
        /// can proxy them, so the classes under test are the test's decision rather
        /// than the fixture's default set.
        async fn activate_with(&self, config_json: &str) -> v1::ActivateOutcome {
            self.service
                .activate(capable(v1::ActivateRequest {
                    session_id: self.session_id.clone(),
                    context: Some(context()),
                    discovery: false,
                    components: vec![v1::ComponentConfiguration {
                        kind: "fixture_intercept".into(),
                        config_json: config_json.to_owned(),
                    }],
                }))
                .await
                .expect("a served activation")
                .into_inner()
        }

        /// One registration the activation reported, found by its local name.
        ///
        /// The runtime qualifies a plugin's names with the component namespace, so
        /// what a test writes is a suffix of the identity a kernel would install a
        /// proxy under. Reading it back from the report is what keeps a test from
        /// spelling the qualification out by hand and drifting from it.
        fn registration_named(&self, outcome: &v1::ActivateOutcome, local_name: &str) -> String {
            let suffix = format!(":{local_name}");
            let Some(v1::activate_outcome::Result::Activated(response)) = &outcome.result else {
                panic!("the fixture's registrations are reported: {outcome:?}");
            };
            response
                .descriptors
                .iter()
                .flat_map(|descriptor| descriptor.registrations.iter())
                .find(|registration| registration.registration_id.ends_with(&suffix))
                .unwrap_or_else(|| {
                    panic!(
                        "the fixture registered no '{local_name}': is the fixture built with the \
                         registrations this suite is about? {outcome:?}"
                    )
                })
                .registration_id
                .clone()
        }

        /// Invoke one registration with the arguments and the response budget given.
        async fn invoke_arguments(
            &self,
            registration: &str,
            arguments: &str,
            max_response_bytes: u32,
        ) -> nemo_relay_plugin_protocol::PluginExecutionOutcome {
            let answer = self
                .service
                .invoke(capable(v1::InvokeRequest {
                    session_id: self.session_id.clone(),
                    context: Some(context_with_budget(max_response_bytes)),
                    handle: Some(nemo_relay_plugin_proto::convert::handle_to_wire(
                        &self.handle,
                    )),
                    registration_id: registration.to_owned(),
                    arguments: arguments.to_owned(),
                }))
                .await
                .expect("a served invocation")
                .into_inner();
            nemo_relay_plugin_proto::convert::execution_outcome_from_wire(&answer)
                .expect("a converted invocation")
        }

        /// The registration a report names, as the kernel would proxy it.
        fn tool_request_intercept(&self, outcome: &v1::ActivateOutcome) -> String {
            let Some(v1::activate_outcome::Result::Activated(response)) = &outcome.result else {
                panic!("the fixture's registrations are reported: {outcome:?}");
            };
            response
                .descriptors
                .iter()
                .flat_map(|descriptor| descriptor.registrations.iter())
                .find(|registration| {
                    registration.operation
                        == nemo_relay_plugin_proto::convert::registration_operation_to_wire(
                            nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolRequestIntercept,
                        )
                })
                .expect("the fixture registers a tool request intercept")
                .registration_id
                .clone()
        }

        /// Run one tool request intercept, with the response budget given.
        async fn invoke(
            &self,
            registration: &str,
            max_response_bytes: u32,
        ) -> nemo_relay_plugin_protocol::PluginExecutionOutcome {
            let answer = self
                .service
                .invoke(capable(v1::InvokeRequest {
                    session_id: self.session_id.clone(),
                    context: Some(context_with_budget(max_response_bytes)),
                    handle: Some(nemo_relay_plugin_proto::convert::handle_to_wire(
                        &self.handle,
                    )),
                    registration_id: registration.to_owned(),
                    arguments: serde_json::json!({"tool": "fixture_tool", "args": {"input": true}})
                        .to_string(),
                }))
                .await
                .expect("a served invocation")
                .into_inner();
            nemo_relay_plugin_proto::convert::execution_outcome_from_wire(&answer)
                .expect("a converted invocation")
        }
    }

    impl Drop for FixtureSession {
        fn drop(&mut self) {
            // Activation installs callbacks into this process's registries, so a
            // test that served them takes them back down rather than leaving them
            // for whichever test runs next.
            let _ = nemo_relay::plugin::clear_plugin_configuration();
            let _ = std::fs::remove_dir_all(&self.manifest_dir);
        }
    }

    async fn establish(service: &PluginHostService, config: &PluginHostConfig) -> String {
        let outcome = service
            .handshake(capable(handshake_request(config)))
            .await
            .expect("a served handshake")
            .into_inner();
        handshake_outcome_from_wire(&outcome)
            .expect("a converted handshake")
            .into_result()
            .expect("an established session")
            .session_id
    }

    /// The attach request helper: the three facts a handshake proves plus the
    /// session being joined.
    fn attach_request(config: &PluginHostConfig, session_id: &str) -> v1::AttachRequest {
        v1::AttachRequest {
            session_id: session_id.to_owned(),
            session_credential: config.session_credential.clone(),
            runtime_binding_digest: config.runtime_binding_digest.clone(),
            protocol_version: u32::from(PROTOCOL_VERSION),
        }
    }

    /// Attach and read what it joined, or read the refusal.
    async fn attach(
        service: &PluginHostService,
        request: v1::AttachRequest,
    ) -> nemo_relay_plugin_protocol::LifecycleOutcome<
        nemo_relay_plugin_protocol::PluginAttachedSession,
    > {
        let outcome = service
            .attach(capable(request))
            .await
            .expect("a served attach")
            .into_inner();
        nemo_relay_plugin_proto::convert::attach_outcome_from_wire(&outcome)
            .expect("a converted attach")
    }

    #[tokio::test]
    async fn an_attach_joins_the_established_session_and_creates_nothing() {
        let (service, config) = service();
        let session_id = establish(&service, &config).await;
        let before = service
            .inspect(capable(v1::InspectRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                handle: None,
            }))
            .await
            .expect("a served inspection")
            .into_inner();

        let joined = match attach(&service, attach_request(&config, &session_id)).await {
            nemo_relay_plugin_protocol::LifecycleOutcome::Completed(joined) => joined,
            nemo_relay_plugin_protocol::LifecycleOutcome::Failed(failure) => {
                panic!("an attach to the established session: {failure:?}")
            }
        };
        assert_eq!(joined.session_id, session_id, "the same session");
        assert_eq!(
            joined.negotiated_frame_limit, config.maximum_frame_bytes,
            "the frame limit the session negotiated, not one the caller offered"
        );
        assert_eq!(
            joined.accepted_read_capabilities,
            vec![PluginHostReadCapability::RuntimeDiagnostics],
            "the capabilities the session accepted"
        );
        assert_eq!(joined.runtime_binding_digest, config.runtime_binding_digest);
        assert_eq!(
            joined.supported_registration_operations,
            vec![nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolRequestIntercept],
            "the classes the session can serve"
        );

        // Attaching twice is two transports for one session, not two sessions.
        let again = match attach(&service, attach_request(&config, &session_id)).await {
            nemo_relay_plugin_protocol::LifecycleOutcome::Completed(joined) => joined,
            nemo_relay_plugin_protocol::LifecycleOutcome::Failed(failure) => {
                panic!("a second attach to the same session: {failure:?}")
            }
        };
        assert_eq!(again.session_id, session_id);

        // And the session is still the handshake's: a second handshake is refused
        // exactly as it was before an attach existed.
        let refused = service
            .handshake(capable(handshake_request(&config)))
            .await
            .expect("a served handshake")
            .into_inner();
        assert!(
            !matches!(
                handshake_outcome_from_wire(&refused).expect("a converted handshake"),
                nemo_relay_plugin_protocol::LifecycleOutcome::Completed(_)
            ),
            "an attach must not make room for a second session"
        );

        // Nothing about the loaded set changed, because nothing was loaded.
        let after = service
            .inspect(capable(v1::InspectRequest {
                session_id,
                context: Some(context()),
                handle: None,
            }))
            .await
            .expect("a served inspection")
            .into_inner();
        let before_loaded =
            match nemo_relay_plugin_proto::convert::inspect_outcome_from_wire(&before)
                .expect("a converted inspection")
                .into_result()
            {
                Ok(descriptors) => descriptors.len(),
                Err(failure) => panic!("the session should serve an inspection: {failure:?}"),
            };
        let after_loaded = match nemo_relay_plugin_proto::convert::inspect_outcome_from_wire(&after)
            .expect("a converted inspection")
            .into_result()
        {
            Ok(descriptors) => descriptors.len(),
            Err(failure) => panic!("the session should still serve an inspection: {failure:?}"),
        };
        assert_eq!(
            after_loaded, before_loaded,
            "an attach changes no plugin state"
        );
    }

    #[tokio::test]
    async fn an_attach_that_does_not_prove_the_session_is_refused() {
        let (service, config) = service();
        let session_id = establish(&service, &config).await;

        let refusal = |outcome: nemo_relay_plugin_protocol::LifecycleOutcome<
            nemo_relay_plugin_protocol::PluginAttachedSession,
        >| match outcome {
            nemo_relay_plugin_protocol::LifecycleOutcome::Failed(failure) => failure,
            nemo_relay_plugin_protocol::LifecycleOutcome::Completed(joined) => {
                panic!("this attach should have been refused: {joined:?}")
            }
        };

        let wrong_credential = v1::AttachRequest {
            session_credential: "another-credential".into(),
            ..attach_request(&config, &session_id)
        };
        assert!(
            refusal(attach(&service, wrong_credential).await)
                .message
                .contains("credential")
        );

        let wrong_session = attach_request(&config, "another-session");
        assert!(
            refusal(attach(&service, wrong_session).await)
                .message
                .contains("did not establish")
        );

        let wrong_binding = v1::AttachRequest {
            runtime_binding_digest: "another-binding".into(),
            ..attach_request(&config, &session_id)
        };
        assert!(
            refusal(attach(&service, wrong_binding).await)
                .message
                .contains("runtime binding")
        );

        let wrong_protocol = v1::AttachRequest {
            protocol_version: u32::from(PROTOCOL_VERSION) + 1,
            ..attach_request(&config, &session_id)
        };
        assert!(
            refusal(attach(&service, wrong_protocol).await)
                .message
                .contains("protocol version")
        );

        // And a request that names nothing is refused as an envelope rather than
        // judged as a session.
        let unnamed = v1::AttachRequest {
            session_id: String::new(),
            ..attach_request(&config, &session_id)
        };
        assert!(
            refusal(attach(&service, unnamed).await)
                .message
                .contains("naming no session")
        );
    }

    #[tokio::test]
    async fn an_attach_before_a_session_or_after_it_closed_is_refused() {
        let (service, config) = service();

        // Before: there is nothing to join. A host that attached here would be
        // inventing a session for a caller that never established one.
        let early = attach(&service, attach_request(&config, "any-session")).await;
        assert!(matches!(
            early,
            nemo_relay_plugin_protocol::LifecycleOutcome::Failed(ref failure)
                if failure.message.contains("no session to attach to")
        ));

        let session_id = establish(&service, &config).await;
        let closed = service
            .session_close(capable(v1::SessionCloseRequest {
                session_id: session_id.clone(),
            }))
            .await
            .expect("a served close")
            .into_inner();
        assert!(matches!(
            nemo_relay_plugin_proto::convert::session_close_outcome_from_wire(&closed)
                .expect("a converted close"),
            nemo_relay_plugin_protocol::LifecycleOutcome::Completed(_)
        ));

        // After: a closed session is not joined, for the same reason a handshake
        // cannot start another one.
        let late = attach(&service, attach_request(&config, &session_id)).await;
        assert!(matches!(
            late,
            nemo_relay_plugin_protocol::LifecycleOutcome::Failed(ref failure)
                if failure.message.contains("already served its session")
        ));
    }

    #[tokio::test]
    async fn a_host_refuses_a_credential_or_binding_it_was_not_started_with() {
        let (service, config) = service();

        // Knowing where the socket is must not be enough to be treated as the
        // kernel, so the credential is checked before anything else.
        let mut request = handshake_request(&config);
        request.session_credential = "another-credential".into();
        let outcome = service
            .handshake(capable(request))
            .await
            .expect("a served handshake")
            .into_inner();
        let failure = handshake_outcome_from_wire(&outcome)
            .expect("a converted handshake")
            .into_result()
            .expect_err("a wrong credential");
        assert_eq!(failure.code, PluginFailureCode::Rejected);

        // And a binding the host was not started with is refused rather than
        // adopted, so one runtime cannot retain another's host.
        let mut request = handshake_request(&config);
        request.runtime_binding_digest = "another-binding".into();
        let outcome = service
            .handshake(capable(request))
            .await
            .expect("a served handshake")
            .into_inner();
        assert!(
            handshake_outcome_from_wire(&outcome)
                .expect("a converted handshake")
                .into_result()
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_host_accepts_the_read_capabilities_it_was_offered_and_no_others() {
        let (service, config) = service();
        let outcome = service
            .handshake(capable(handshake_request(&config)))
            .await
            .expect("a served handshake")
            .into_inner();
        let identity = handshake_outcome_from_wire(&outcome)
            .expect("a converted handshake")
            .into_result()
            .expect("an established session");

        assert_eq!(
            identity.accepted_read_capabilities,
            vec![PluginHostReadCapability::RuntimeDiagnostics]
        );
        assert!(identity.accepted_within(&[PluginHostReadCapability::RuntimeDiagnostics]));
    }

    #[tokio::test]
    async fn an_operation_before_or_outside_the_session_is_refused() {
        let (service, config) = service();
        let load = |session_id: &str| v1::LoadRequest {
            session_id: session_id.into(),
            context: Some(context()),
            plugin_id: "absent".into(),
            artifact: "/nonexistent/relay-plugin.toml".into(),
            manifest_digest: "a".repeat(64),
            library_digest: "b".repeat(64),
        };
        let refused = |outcome: v1::LoadOutcome| {
            nemo_relay_plugin_proto::convert::load_outcome_from_wire(&outcome)
                .expect("a converted load")
                .into_result()
                .is_err()
        };

        // Before a session exists, nothing is served.
        let outcome = service
            .load(capable(load("unknown")))
            .await
            .expect("a served load")
            .into_inner();
        assert!(refused(outcome));

        // And a request naming a session this host did not establish is refused
        // rather than served.
        let session_id = establish(&service, &config).await;
        let outcome = service
            .load(capable(load("another-session")))
            .await
            .expect("a served load")
            .into_inner();
        assert!(refused(outcome));

        // The established session is served, and the answer comes from the
        // backend rather than from the session check: an inspection of an empty
        // host is an empty list.
        let outcome = service
            .inspect(capable(v1::InspectRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                handle: None,
            }))
            .await
            .expect("a served inspection")
            .into_inner();
        assert!(
            nemo_relay_plugin_proto::convert::inspect_outcome_from_wire(&outcome)
                .expect("a converted inspection")
                .into_result()
                .expect("an answer from the backend")
                .is_empty()
        );

        // A close naming another session is a refusal, and it reports itself as
        // one rather than as a broken channel.
        let outcome = service
            .session_close(capable(v1::SessionCloseRequest {
                session_id: "another-session".into(),
            }))
            .await
            .expect("a served close")
            .into_inner();
        assert!(
            nemo_relay_plugin_proto::convert::session_close_outcome_from_wire(&outcome)
                .expect("a converted close")
                .into_result()
                .is_err()
        );
        let _ = session_id;
    }

    #[tokio::test]
    async fn a_host_serves_one_session_and_refuses_a_second() {
        let (service, config) = service();
        let session_id = establish(&service, &config).await;

        // A second handshake would be a session nobody owns: the supervisor
        // spawns a process per session, so a host that accepted another would
        // make "which session is this?" a question with two answers.
        let outcome = service
            .handshake(capable(handshake_request(&config)))
            .await
            .expect("a served handshake")
            .into_inner();
        assert!(
            handshake_outcome_from_wire(&outcome)
                .expect("a converted handshake")
                .into_result()
                .is_err()
        );

        // Closing ends it, and nothing is served afterwards — including another
        // handshake.
        let outcome = service
            .session_close(capable(v1::SessionCloseRequest {
                session_id: session_id.clone(),
            }))
            .await
            .expect("a served close")
            .into_inner();
        assert_eq!(
            nemo_relay_plugin_proto::convert::session_close_outcome_from_wire(&outcome)
                .expect("a converted close")
                .into_result(),
            Ok(())
        );
        let outcome = service
            .inspect(capable(v1::InspectRequest {
                session_id,
                context: Some(context()),
                handle: None,
            }))
            .await
            .expect("a served inspection")
            .into_inner();
        assert!(
            nemo_relay_plugin_proto::convert::inspect_outcome_from_wire(&outcome)
                .expect("a converted inspection")
                .into_result()
                .is_err()
        );
        let outcome = service
            .handshake(capable(handshake_request(&config)))
            .await
            .expect("a served handshake")
            .into_inner();
        assert!(
            handshake_outcome_from_wire(&outcome)
                .expect("a converted handshake")
                .into_result()
                .is_err(),
            "a host that served its session does not start another"
        );
    }

    /// A backend that loads a plugin registering classes this session cannot
    /// serve, and refuses to unload it quietly.
    struct RegisteringBackend {
        unloaded: Arc<Mutex<Vec<String>>>,
        operations: Vec<nemo_relay_plugin_protocol::PluginRegistrationOperation>,
    }

    impl PluginExecutionBackend for RegisteringBackend {
        fn invoke<'a>(
            &'a self,
            _request: nemo_relay_plugin_protocol::PluginInvokeRequest,
            _context: nemo_relay_plugin_protocol::PluginExecutionContext,
        ) -> nemo_relay::plugin::execution::PluginExecutionFuture<
            'a,
            nemo_relay_plugin_protocol::PluginExecutionOutcome,
        > {
            Box::pin(async move {
                Err(nemo_relay_plugin_protocol::PluginProtocolError::new(
                    nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
                    "this test backend serves no invocations",
                ))
            })
        }

        fn load<'a>(
            &'a self,
            request: nemo_relay_plugin_protocol::PluginLoadRequest,
            _context: nemo_relay_plugin_protocol::PluginExecutionContext,
        ) -> nemo_relay::plugin::execution::PluginExecutionFuture<'a, PluginLoadResponse> {
            let operations = self.operations.clone();
            Box::pin(async move {
                Ok(PluginLoadResponse {
                    handle: PluginHandle {
                        plugin_id: request.plugin_id.clone(),
                        generation: 1,
                    },
                    descriptor: PluginDescriptor {
                        plugin_id: request.plugin_id,
                        plugin_version: None,
                        negotiated_abi_version: None,
                        manifest_digest: None,
                        registration_kinds: Vec::new(),
                        registrations: operations
                            .into_iter()
                            .map(|operation| {
                                nemo_relay_plugin_protocol::PluginRegistrationDescriptor {
                                    registration_id: "nemo-relay-plugin.v1.example:1:run".into(),
                                    component_kind: "example".into(),
                                    operation,
                                    ordering:
                                        nemo_relay_plugin_protocol::PluginRegistrationOrdering {
                                            priority: None,
                                            may_break_chain: None,
                                        },
                                    shape: nemo_relay_plugin_protocol::registration_shape(
                                        operation,
                                    ),
                                    gated_registration: None,
                                    config_keys: Vec::new(),
                                    declared_digest: None,
                                }
                            })
                            .collect(),
                        capabilities: Vec::new(),
                    },
                })
            })
        }

        fn unload<'a>(
            &'a self,
            request: nemo_relay_plugin_protocol::PluginUnloadRequest,
            _context: nemo_relay_plugin_protocol::PluginExecutionContext,
        ) -> nemo_relay::plugin::execution::PluginExecutionFuture<'a, ()> {
            let unloaded = self.unloaded.clone();
            Box::pin(async move {
                unloaded
                    .lock()
                    .expect("the log")
                    .push(request.handle.plugin_id);
                Ok(())
            })
        }

        fn inspect<'a>(
            &'a self,
            _request: nemo_relay_plugin_protocol::PluginInspectRequest,
            _context: nemo_relay_plugin_protocol::PluginExecutionContext,
        ) -> nemo_relay::plugin::execution::PluginExecutionFuture<'a, Vec<PluginDescriptor>>
        {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn health<'a>(
            &'a self,
            _context: nemo_relay_plugin_protocol::PluginExecutionContext,
        ) -> nemo_relay::plugin::execution::PluginExecutionFuture<
            'a,
            nemo_relay_plugin_protocol::PluginHostHealth,
        > {
            Box::pin(async move {
                Ok(nemo_relay_plugin_protocol::PluginHostHealth {
                    protocol_version: PROTOCOL_VERSION,
                    accepting_work: true,
                    loaded: Vec::new(),
                })
            })
        }
    }

    #[tokio::test]
    async fn a_plugin_whose_registrations_cannot_be_served_is_refused_whole() {
        use nemo_relay_plugin_protocol::PluginRegistrationOperation;

        let unloaded = Arc::new(Mutex::new(Vec::new()));
        let backend = Arc::new(RegisteringBackend {
            unloaded: unloaded.clone(),
            operations: vec![
                PluginRegistrationOperation::ToolRequestIntercept,
                // The session was offered support for the first class only.
                PluginRegistrationOperation::LlmStreamExecutionIntercept,
            ],
        });
        let config = PluginHostConfig {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        };
        let service = PluginHostService::new(backend, config.clone());
        let session_id = establish(&service, &config).await;

        let outcome = service
            .load(capable(v1::LoadRequest {
                session_id,
                context: Some(context()),
                plugin_id: "example".into(),
                artifact: "relay-plugin.toml".into(),
                manifest_digest: "a".repeat(64),
                library_digest: "b".repeat(64),
            }))
            .await
            .expect("a served load")
            .into_inner();
        let failure = nemo_relay_plugin_proto::convert::load_outcome_from_wire(&outcome)
            .expect("a converted load")
            .into_result()
            .expect_err("a plugin registering what this session cannot serve");

        // The refusal names both sides, so an operator reads what the plugin
        // needs and what the session can do rather than a bare rejection.
        assert!(
            failure.message.contains("llm_stream_execution_intercept"),
            "{failure:?}"
        );
        assert!(
            failure.message.contains("tool_request_intercept"),
            "{failure:?}"
        );
        // And the plugin is not left half-loaded for the kernel never to call.
        assert_eq!(unloaded.lock().expect("the log").as_slice(), ["example"]);
    }

    /// Core's plugin configuration is process-global, so tests that activate a
    /// real plugin take turns: two activations in one process replace each
    /// other's registrations, which is not what either test means to observe.
    static PLUGIN_ACTIVATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Every attachment point the ABI exposes.
    const EVERY_REGISTRATION_OPERATION: &[PluginRegistrationOperation] = &[
        PluginRegistrationOperation::Subscriber,
        PluginRegistrationOperation::EventMetadataInjector,
        PluginRegistrationOperation::MarkSanitizeGuardrail,
        PluginRegistrationOperation::ScopeSanitizeStartGuardrail,
        PluginRegistrationOperation::ScopeSanitizeEndGuardrail,
        PluginRegistrationOperation::ToolSanitizeRequestGuardrail,
        PluginRegistrationOperation::ToolSanitizeResponseGuardrail,
        PluginRegistrationOperation::ToolConditionalExecutionGuardrail,
        PluginRegistrationOperation::ToolRequestIntercept,
        PluginRegistrationOperation::ToolExecutionIntercept,
        PluginRegistrationOperation::LlmSanitizeRequestGuardrail,
        PluginRegistrationOperation::LlmSanitizeResponseGuardrail,
        PluginRegistrationOperation::LlmConditionalExecutionGuardrail,
        PluginRegistrationOperation::LlmRequestIntercept,
        PluginRegistrationOperation::LlmExecutionIntercept,
        PluginRegistrationOperation::LlmStreamExecutionIntercept,
    ];

    /// The load-and-activate path a kernel drives, against the real fixture.
    ///
    /// Registration is config-driven, so this is where a plugin's registrations
    /// first exist: load reports none of them, and activation is the call that
    /// makes them observable. What the kernel needs before it can install a
    /// proxy per registration is exactly this list.
    #[tokio::test]
    async fn activation_reports_the_registrations_the_plugin_made() {
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((manifest_dir, artifact)) = nemo_relay_plugin_host_fixture() else {
            eprintln!("the native fixture is missing; skipping the activation case");
            return;
        };

        let backend = Arc::new(crate::InProcessPluginBackend::new());
        let config = PluginHostConfig {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        };
        let service = PluginHostService::new(backend, config.clone());

        // A session that can serve every class the ABI exposes, so nothing is
        // refused and the descriptors are the whole truth about the plugin.
        let mut request = handshake_request(&config);
        request.supported_registration_operations = EVERY_REGISTRATION_OPERATION
            .iter()
            .map(|operation| {
                nemo_relay_plugin_proto::convert::registration_operation_to_wire(*operation)
            })
            .collect();
        let outcome = service
            .handshake(capable(request))
            .await
            .expect("a served handshake")
            .into_inner();
        let session_id = handshake_outcome_from_wire(&outcome)
            .expect("a converted handshake")
            .into_result()
            .expect("an established session")
            .session_id;

        let (manifest_sha256, library_sha256) =
            nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact)
                .expect("the fixture's identity");
        service
            .load(capable(v1::LoadRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                plugin_id: "fixture_native".into(),
                artifact,
                manifest_digest: manifest_sha256,
                library_digest: library_sha256,
            }))
            .await
            .expect("a served load")
            .into_inner();

        let outcome = service
            .activate(capable(v1::ActivateRequest {
                session_id,
                context: Some(context()),
                components: vec![v1::ComponentConfiguration {
                    kind: "fixture_native".into(),
                    config_json: "{}".into(),
                }],
                discovery: false,
            }))
            .await
            .expect("a served activation")
            .into_inner();
        let descriptors = nemo_relay_plugin_proto::convert::activate_outcome_from_wire(&outcome)
            .expect("a converted activation")
            .into_result()
            .expect("an activation this session can serve");

        let reported: std::collections::BTreeSet<_> = descriptors
            .iter()
            .flat_map(|descriptor| descriptor.registrations.iter())
            .map(|registration| registration.operation)
            .collect();
        assert_eq!(
            reported.len(),
            EVERY_REGISTRATION_OPERATION.len(),
            "the fixture registers on every surface, and activation reports what it registered: {reported:?}"
        );

        let _ = std::fs::remove_dir_all(&manifest_dir);
    }

    /// A session that can serve nothing, so activation of a real plugin must
    /// fail closed on whatever it registers.
    /// A discovery session reports what a serving one refuses — and the same
    /// plugin, in the same host, tells both stories truthfully.
    #[tokio::test]
    async fn a_discovery_activation_reports_what_a_serving_one_refuses() {
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((_, artifact)) = nemo_relay_plugin_host_fixture() else {
            eprintln!("the native fixture is missing; skipping the discovery case");
            return;
        };
        let backend = Arc::new(crate::InProcessPluginBackend::new());
        let config = PluginHostConfig {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        };
        let service = PluginHostService::new(backend, config.clone());
        let session_id = establish(&service, &config).await;
        let (manifest_sha256, library_sha256) =
            nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact)
                .expect("the fixture's identity");
        service
            .load(capable(v1::LoadRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                plugin_id: "fixture_native".into(),
                artifact: artifact.clone(),
                manifest_digest: manifest_sha256,
                library_digest: library_sha256,
            }))
            .await
            .expect("a served load");

        let activate = |discovery: bool| {
            service.activate(capable(v1::ActivateRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                components: vec![v1::ComponentConfiguration {
                    kind: "fixture_native".into(),
                    config_json: "{}".into(),
                }],
                discovery,
            }))
        };

        // Serving: this session cannot proxy everything the fixture registers, so
        // activation is refused whole rather than half-served.
        let serving = activate(false)
            .await
            .expect("a served activation")
            .into_inner();
        let serving = nemo_relay_plugin_proto::convert::activate_outcome_from_wire(&serving)
            .expect("converted");
        assert!(
            serving.into_result().is_err(),
            "a serving session refuses what it cannot serve"
        );

        // Inspecting: the same plugin, reported in full, so the classes this
        // kernel cannot serve are visible as what they are. This is the second
        // activation against one loaded instance — the serving attempt above was
        // the first — so it also proves the description is the registrations the
        // plugin *has* rather than a log of everything it ever made: a log would
        // report each of these twice here, and the conversion refuses a
        // duplicate at one attachment point.
        let discovery = activate(true)
            .await
            .expect("a served activation")
            .into_inner();
        let descriptors = nemo_relay_plugin_proto::convert::activate_outcome_from_wire(&discovery)
            .expect("a converted activation")
            .into_result()
            .expect("a discovery session reports rather than refuses");
        let serveable = crate::ProcessPluginBackend::supported_registration_operations();
        let reported: Vec<nemo_relay_plugin_protocol::PluginRegistrationOperation> = descriptors
            .iter()
            .flat_map(|descriptor| descriptor.registrations.iter())
            .map(|registration| registration.operation)
            .collect();
        // Every registration the plugin holds, described once each. Two
        // registrations may share a class — this fixture has two subscribers —
        // so what must not repeat is the attachment point, which is the name.
        let ids: Vec<&str> = descriptors
            .iter()
            .flat_map(|descriptor| descriptor.registrations.iter())
            .map(|registration| registration.registration_id.as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            ids.len(),
            "an instance that has registered twice describes each attachment point once: {ids:?}"
        );
        assert!(
            !reported.is_empty(),
            "the report is the plugin's actual registrations"
        );
        assert!(
            reported
                .iter()
                .any(|operation| !serveable.contains(operation)),
            "including the ones this kernel cannot serve, which is the point: \
             otherwise a plugin could never be measured as blocked — reported {reported:?}"
        );
        // And the report is the plugin's own set: seventeen attachment points
        // across the sixteen classes the ABI exposes.
        assert_eq!(
            reported.len(),
            17,
            "the sixteen-surface fixture registers seventeen attachment points: {reported:?}"
        );
    }

    #[tokio::test]
    async fn an_activation_that_registers_what_this_session_cannot_serve_is_refused_whole() {
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let fixture = nemo_relay_plugin_host_fixture();
        let Some((manifest_dir, artifact)) = fixture else {
            // The fixture is built by `just build-test-plugin-fixtures`; a run
            // without it says so rather than passing for the wrong reason.
            eprintln!("the native fixture is missing; skipping the activation case");
            return;
        };

        let backend = Arc::new(crate::InProcessPluginBackend::new());
        let config = PluginHostConfig {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        };
        let service = PluginHostService::new(backend, config.clone());
        let session_id = establish(&service, &config).await;

        // A load needs the identity the kernel approved, and the fixture is what
        // is loaded; activation is where the plugin's registrations appear.
        let (manifest_sha256, library_sha256) =
            nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact)
                .expect("the fixture's identity");
        service
            .load(capable(v1::LoadRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                plugin_id: "fixture_native".into(),
                artifact: artifact.clone(),
                manifest_digest: manifest_sha256,
                library_digest: library_sha256,
            }))
            .await
            .expect("a served load")
            .into_inner();

        let outcome = service
            .activate(capable(v1::ActivateRequest {
                discovery: false,
                session_id,
                context: Some(context()),
                components: vec![v1::ComponentConfiguration {
                    kind: "fixture_native".into(),
                    config_json: "{}".into(),
                }],
            }))
            .await
            .expect("a served activation")
            .into_inner();

        // The fixture registers on every surface the ABI exposes, and this
        // session can serve one class, so activation is refused — and the
        // refusal names what was registered against what could be served.
        let failure = nemo_relay_plugin_proto::convert::activate_outcome_from_wire(&outcome)
            .expect("a converted activation")
            .into_result()
            .expect_err("a plugin registering classes this session cannot serve");
        assert!(failure.message.contains("registers"), "{failure:?}");

        let _ = std::fs::remove_dir_all(&manifest_dir);
    }

    /// A real native fixture's manifest, when the fixture has been built.
    fn nemo_relay_plugin_host_fixture() -> Option<(std::path::PathBuf, String)> {
        let library = std::env::var_os("NEMO_RELAY_TEST_NATIVE_PLUGIN")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
                    "../../target/test-plugin-fixtures/debug/libnemo_relay_plugin_fixture.dylib",
                )
            });
        if !library.exists() {
            return None;
        }
        let manifest_dir =
            std::env::temp_dir().join(format!("nemo-ph-service-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&manifest_dir).expect("a manifest directory");
        let manifest = manifest_dir.join("relay-plugin.toml");
        std::fs::write(
            &manifest,
            format!(
                "manifest_version = 1\n\n[plugin]\nid = \"fixture_native\"\nkind = \"rust_dynamic\"\n\n[compat]\nrelay = \"={}\"\nnative_api = \"1\"\n\n[defaults]\nenabled = false\n\n[capabilities]\nitems = [\"plugin_native\"]\n\n[load]\nlibrary = \"{}\"\nsymbol = \"nemo_relay_fixture_native_plugin\"\n",
                env!("CARGO_PKG_VERSION"),
                library.display()
            ),
        )
        .expect("write the manifest");
        Some((manifest_dir, manifest.to_string_lossy().into_owned()))
    }

    /// The first class across the boundary, end to end at the service: the
    /// kernel asks a host to activate a plugin, then asks it to run one of the
    /// registrations it reported, and gets the rewritten arguments back.
    #[tokio::test]
    async fn an_invocation_runs_the_registration_the_kernel_named() {
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((manifest_dir, artifact)) = nemo_relay_plugin_host_fixture() else {
            eprintln!("the native fixture is missing; skipping the invocation case");
            return;
        };

        let backend = Arc::new(crate::InProcessPluginBackend::new());
        let config = PluginHostConfig {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        };
        let service = PluginHostService::new(backend, config.clone());
        let mut request = handshake_request(&config);
        request.supported_registration_operations = EVERY_REGISTRATION_OPERATION
            .iter()
            .map(|operation| {
                nemo_relay_plugin_proto::convert::registration_operation_to_wire(*operation)
            })
            .collect();
        let session_id = handshake_outcome_from_wire(
            &service
                .handshake(capable(request))
                .await
                .expect("a served handshake")
                .into_inner(),
        )
        .expect("a converted handshake")
        .into_result()
        .expect("an established session")
        .session_id;

        let (manifest_sha256, library_sha256) =
            nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact)
                .expect("the fixture's identity");
        let load = service
            .load(capable(v1::LoadRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                plugin_id: "fixture_native".into(),
                artifact,
                manifest_digest: manifest_sha256,
                library_digest: library_sha256,
            }))
            .await
            .expect("a served load")
            .into_inner();
        let handle = nemo_relay_plugin_proto::convert::load_outcome_from_wire(&load)
            .expect("a converted load")
            .into_result()
            .expect("a load")
            .handle;

        let activated = service
            .activate(capable(v1::ActivateRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                discovery: false,
                components: vec![v1::ComponentConfiguration {
                    kind: "fixture_native".into(),
                    config_json: "{}".into(),
                }],
            }))
            .await
            .expect("a served activation")
            .into_inner();
        let descriptors = nemo_relay_plugin_proto::convert::activate_outcome_from_wire(&activated)
            .expect("a converted activation")
            .into_result()
            .expect("an activation this session can serve");

        // The registration the kernel would install a proxy under, from what the
        // host itself reported.
        let registration = descriptors
            .iter()
            .flat_map(|descriptor| descriptor.registrations.iter())
            .find(|registration| {
                registration.operation
                    == nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolRequestIntercept
            })
            .expect("the fixture registers a tool request intercept")
            .registration_id
            .clone();

        let invoked = service
            .invoke(capable(v1::InvokeRequest {
                session_id,
                context: Some(context()),
                handle: Some(nemo_relay_plugin_proto::convert::handle_to_wire(&handle)),
                registration_id: registration.clone(),
                arguments: serde_json::json!({"tool": "fixture_tool", "args": {"input": true}})
                    .to_string(),
            }))
            .await
            .expect("a served invocation")
            .into_inner();
        let outcome = nemo_relay_plugin_proto::convert::execution_outcome_from_wire(&invoked)
            .expect("a converted invocation");
        assert_eq!(
            invoked.operation_request_id, "operation-1",
            "the answer names the invocation the host accepted"
        );
        assert_eq!(
            outcome.dispatch,
            nemo_relay_plugin_protocol::DispatchState::NotDispatched
        );
        let output = outcome.result.expect("the registration's answer").clone();
        let nemo_relay_plugin_protocol::PluginSuccess::Invoked(response) = output else {
            panic!("an invocation answers with output");
        };
        let args: serde_json::Value = serde_json::from_str(&response.output).expect("JSON");
        assert_eq!(args["native_plugin"], true, "{args}");

        // A registration this host does not hold is refused rather than mapped
        // to whichever one happens to be close.
        let unknown = service
            .invoke(capable(v1::InvokeRequest {
                session_id: "session-1".into(),
                context: Some(context()),
                handle: Some(nemo_relay_plugin_proto::convert::handle_to_wire(&handle)),
                registration_id: "nemo-relay-plugin.v1.fixture_native:1:no_such_registration"
                    .into(),
                arguments: serde_json::json!({"tool": "fixture_tool", "args": {}}).to_string(),
            }))
            .await
            .expect("a served invocation")
            .into_inner();
        let outcome = nemo_relay_plugin_proto::convert::execution_outcome_from_wire(&unknown)
            .expect("a converted invocation");
        assert!(outcome.result.is_err(), "{outcome:?}");
        assert_eq!(
            unknown.operation_request_id, "operation-1",
            "a refusal names the invocation it refuses, so the kernel can attribute it"
        );

        let _ = std::fs::remove_dir_all(&manifest_dir);
    }

    /// The whole wrapped-call loop: the kernel's chain, the child's callback, the
    /// downstream stream it pulls, and the upstream stream it returns.
    ///
    /// This is the streaming class end to end at the host: the kernel asked for a
    /// registration whose answer is a stream, the plugin's callback pulled the
    /// downstream stream the kernel is producing for that operation, marked each
    /// chunk, and returned a stream of its own — which the kernel then read back
    /// frame by frame. Both halves of the boundary are in this one call, which is
    /// why it is the test the class is judged on.
    #[tokio::test]
    async fn a_streaming_intercept_pulls_downstream_and_answers_with_frames() {
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((manifest_dir, artifact)) = nemo_relay_plugin_host_fixture() else {
            eprintln!("the native fixture is missing; skipping the streaming case");
            return;
        };

        let backend = Arc::new(crate::InProcessPluginBackend::new());
        let config = PluginHostConfig {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        };
        // The session comes first, because the kernel that answers this host's
        // pulls has to be serving *that* session: a host names the session it
        // established in every message it sends, and a kernel serving another one
        // ends the channel rather than answering it.
        let service = PluginHostService::new(backend, config.clone());
        // The session serves every class, because this is the fixture that
        // registers every class: what is being tested is the streaming path, not
        // the served set.
        let mut handshake = handshake_request(&config);
        handshake.supported_registration_operations = EVERY_REGISTRATION_OPERATION
            .iter()
            .map(|operation| {
                nemo_relay_plugin_proto::convert::registration_operation_to_wire(*operation)
            })
            .collect();
        let session_id = handshake_outcome_from_wire(
            &service
                .handshake(capable(handshake))
                .await
                .expect("a served handshake")
                .into_inner(),
        )
        .expect("a converted handshake")
        .into_result()
        .expect("an established session")
        .session_id;

        // Now the kernel, serving the session the host established and holding
        // one downstream stream for the operation the invocation will name.
        let (endpoint, kernel) = serve_kernel_with_stream(
            &session_id,
            vec![
                serde_json::json!({"chunk": 1}),
                serde_json::json!({"chunk": 2}),
            ],
        )
        .await;
        let callbacks = crate::runtime_service::KernelCallbacks::new(
            crate::runtime_service::connect_to_kernel(
                &endpoint,
                nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
            )
            .await
            .expect("a kernel client"),
            KERNEL_CREDENTIAL,
        )
        .expect("the kernel credential");
        let service = service.with_kernel_callbacks(callbacks);

        let (manifest_sha256, library_sha256) =
            nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact)
                .expect("the fixture's identity");
        service
            .load(capable(v1::LoadRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                plugin_id: "fixture_native".into(),
                artifact,
                manifest_digest: manifest_sha256,
                library_digest: library_sha256,
            }))
            .await
            .expect("a served load");
        let activated = service
            .activate(capable(v1::ActivateRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                discovery: false,
                components: vec![v1::ComponentConfiguration {
                    kind: "fixture_native".into(),
                    config_json: "{}".into(),
                }],
            }))
            .await
            .expect("a served activation")
            .into_inner();
        nemo_relay_plugin_proto::convert::activate_outcome_from_wire(&activated)
            .expect("a converted activation")
            .into_result()
            .expect("the session serves every class this fixture registers");

        // The registration the kernel would proxy, from what the host reported.
        let descriptors = service
            .inspect(capable(v1::InspectRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                handle: None,
            }))
            .await
            .expect("a served inspection")
            .into_inner();
        let descriptors = nemo_relay_plugin_proto::convert::inspect_outcome_from_wire(&descriptors)
            .expect("a converted inspection")
            .into_result()
            .expect("an inspection");
        let registration = descriptors
            .iter()
            .flat_map(|descriptor| descriptor.registrations.iter())
            .find(|registration| {
                registration.operation
                    == nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmStreamExecutionIntercept
            })
            .expect("the fixture registers a streaming intercept")
            .registration_id
            .clone();

        let mut streaming_context = context();
        streaming_context.operation_request_id = "operation-stream".into();
        let answer = service
            .invoke_stream(capable(v1::InvokeRequest {
                session_id: session_id.clone(),
                context: Some(streaming_context),
                handle: Some(nemo_relay_plugin_proto::convert::handle_to_wire(
                    &nemo_relay_plugin_protocol::PluginHandle {
                        plugin_id: "fixture_native".into(),
                        generation: 1,
                    },
                )),
                registration_id: registration,
                arguments: serde_json::json!({
                    "name": "fixture_provider",
                    "request": {"headers": {}, "content": {"model": "fixture-model"}},
                })
                .to_string(),
            }))
            .await
            .expect("a served streaming invocation")
            .into_inner();

        let frames: Vec<v1::StreamChunk> = {
            use tokio_stream::StreamExt;
            let mut frames = answer;
            let mut collected = Vec::new();
            while let Some(frame) = frames.next().await {
                collected.push(frame.expect("a frame"));
            }
            collected
        };

        // Two chunks the kernel produced, each marked by the plugin on its way
        // back, and then the terminal frame.
        let data: Vec<serde_json::Value> = frames
            .iter()
            .filter_map(|frame| match &frame.chunk {
                Some(v1::stream_chunk::Chunk::Data(data)) => {
                    Some(serde_json::from_str(data).expect("JSON"))
                }
                _ => None,
            })
            .collect();
        assert_eq!(data.len(), 2, "both chunks crossed back: {frames:?}");
        for (index, chunk) in data.iter().enumerate() {
            assert_eq!(
                chunk["native_plugin_llm_stream_execution"],
                true,
                "chunk {} was transformed by the plugin: {chunk}",
                index + 1
            );
            assert_eq!(chunk["chunk"], index + 1, "{chunk}");
        }
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame.chunk, Some(v1::stream_chunk::Chunk::End(true)))),
            "the stream ends with a terminal frame rather than by stopping: {frames:?}"
        );

        kernel.abort();
        let _ = std::fs::remove_dir_all(&manifest_dir);
    }

    /// A host with two operations in flight and the marks they raise, as forwarded.
    async fn matrix_service(
        artifact: &str,
    ) -> (
        Arc<PluginHostService>,
        String,
        tokio::sync::mpsc::Receiver<ForwardedStep>,
    ) {
        let (mark_sender, mark_steps) = tokio::sync::mpsc::channel::<ForwardedStep>(64);
        let backend = Arc::new(crate::InProcessPluginBackend::new());
        let config = PluginHostConfig {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        };
        let service =
            PluginHostService::new(backend, config.clone()).with_mark_forwarding(mark_sender);
        let session_id = establish_session(&service, &config).await;

        // One stream per operation, one chunk each: exactly the four positions a
        // mark can be raised in, so a count that is wrong is wrong for a reason.
        let (endpoint, kernel) = serve_kernel_with_producers(
            &session_id,
            vec![
                ("operation-A", vec![serde_json::json!({"chunk": "A"})]),
                ("operation-B", vec![serde_json::json!({"chunk": "B"})]),
            ],
            KernelProducer::watching(),
        )
        .await;
        // Kept for the test's lifetime, so the kernel's listener outlives the call.
        std::mem::forget(kernel);
        let service = Arc::new(load_and_activate(service, &endpoint, &session_id, artifact).await);
        (service, session_id, mark_steps)
    }

    /// Establish a session on `service`, answering its identity.
    async fn establish_session(service: &PluginHostService, config: &PluginHostConfig) -> String {
        let mut handshake = handshake_request(config);
        handshake.supported_registration_operations = EVERY_REGISTRATION_OPERATION
            .iter()
            .map(|operation| {
                nemo_relay_plugin_proto::convert::registration_operation_to_wire(*operation)
            })
            .collect();
        handshake_outcome_from_wire(
            &service
                .handshake(capable(handshake))
                .await
                .expect("a served handshake")
                .into_inner(),
        )
        .expect("a converted handshake")
        .into_result()
        .expect("an established session")
        .session_id
    }

    /// Point `service` at the kernel at `endpoint`, load the fixture and activate it.
    async fn load_and_activate(
        service: PluginHostService,
        endpoint: &std::path::Path,
        session_id: &str,
        artifact: &str,
    ) -> PluginHostService {
        let callbacks = crate::runtime_service::KernelCallbacks::new(
            crate::runtime_service::connect_to_kernel(
                endpoint,
                nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
            )
            .await
            .expect("a kernel client"),
            KERNEL_CREDENTIAL,
        )
        .expect("the kernel credential");
        let service = service.with_kernel_callbacks(callbacks);
        let (manifest_sha256, library_sha256) =
            nemo_relay::plugin::dynamic::plugin_artifact_identity(artifact)
                .expect("the fixture's identity");
        service
            .load(capable(v1::LoadRequest {
                session_id: session_id.to_owned(),
                context: Some(context()),
                plugin_id: "fixture_native".into(),
                artifact: artifact.to_owned(),
                manifest_digest: manifest_sha256,
                library_digest: library_sha256,
            }))
            .await
            .expect("a served load");
        let activated = service
            .activate(capable(v1::ActivateRequest {
                session_id: session_id.to_owned(),
                context: Some(context()),
                discovery: false,
                components: vec![v1::ComponentConfiguration {
                    kind: "fixture_native".into(),
                    config_json: "{}".into(),
                }],
            }))
            .await
            .expect("a served activation")
            .into_inner();
        nemo_relay_plugin_proto::convert::activate_outcome_from_wire(&activated)
            .expect("a converted activation")
            .into_result()
            .expect("the session serves every class this fixture registers");
        service
    }

    /// Every mark two concurrent streams raised, in the order they were forwarded.
    ///
    /// The schedule says which stream may take its next step, one at a time, so the
    /// interleaving is the test's rather than the runtime's; the marks themselves
    /// are read from the host's forwarder, which is where a mark that reached the
    /// kernel would have to appear.
    async fn marks_under_schedule(
        artifact: &str,
        generation: u64,
        schedule: &[&str],
    ) -> Vec<(String, String, String)> {
        let (service, session_id, mut steps) = matrix_service(artifact).await;
        let seen: Arc<std::sync::Mutex<Vec<(String, String, String)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let recording = Arc::clone(&seen);
        let forwarding = tokio::spawn(async move {
            while let Some(step) = steps.recv().await {
                match step {
                    ForwardedStep::Mark { mark, .. } => {
                        let data: serde_json::Value = mark
                            .data_json
                            .as_deref()
                            .and_then(|data| serde_json::from_str(data).ok())
                            .unwrap_or(serde_json::Value::Null);
                        recording.lock().unwrap().push((
                            mark.operation_request_id.clone(),
                            data["stream"].as_str().unwrap_or_default().to_owned(),
                            data["position"].as_str().unwrap_or_default().to_owned(),
                        ));
                    }
                    ForwardedStep::Flush { done } => {
                        let _ = done.send(Ok(()));
                    }
                }
            }
        });

        // Both invocations run at once, and neither returns until the schedule lets
        // its callback open the downstream stream.
        let starting = |operation: &'static str, content: serde_json::Value| {
            let service = Arc::clone(&service);
            let session_id = session_id.clone();
            tokio::spawn(async move {
                invoke_stream_frames(&service, &session_id, operation, content).await
            })
        };
        // Both invocations carry the schedule, and each stream waits its turn
        // before raising its next mark: the interleaving is the test's rather than
        // the scheduler's.
        let named = |stream: &str| {
            serde_json::json!({
                "model": "fixture-model",
                "fixture_stream": stream,
                "fixture_schedule": schedule,
                "fixture_generation": generation,
            })
        };
        let first = starting("operation-A", named("A"));
        let second = starting("operation-B", named("B"));

        let mut frames = first.await.expect("stream A's invocation");
        let mut other = second.await.expect("stream B's invocation");
        for frames in [&mut frames, &mut other] {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                use tokio_stream::StreamExt;
                while let Some(frame) = frames.next().await {
                    let frame = frame.expect("a frame");
                    if matches!(
                        frame.chunk,
                        Some(v1::stream_chunk::Chunk::End(_))
                            | Some(v1::stream_chunk::Chunk::Failure(_))
                    ) {
                        break;
                    }
                }
            })
            .await;
        }

        forwarding.abort();
        seen.lock().unwrap().clone()
    }

    /// A panic in a streaming callback fails the call and not the session.
    ///
    /// The mark the callback raised before it panicked still belongs to the call —
    /// the window was open when it was raised — and the call itself fails: a plugin
    /// that panics must not answer, and must not take the session with it, so the
    /// next invocation on the same session is served.
    #[tokio::test]
    async fn a_callback_that_panics_fails_the_call_and_not_the_session() {
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((manifest_dir, artifact)) = nemo_relay_plugin_host_fixture() else {
            eprintln!("the native fixture is missing; skipping the panic case");
            return;
        };
        let ((service, session_id), steps) =
            streaming_service_with_marks(&artifact, KernelProducer::watching(), true).await;
        let _marks = CollectedMarks::start(steps);

        let mut frames = invoke_stream_frames(
            &service,
            &session_id,
            "operation-stream",
            serde_json::json!({"model": "fixture-model", "fixture_stream_shape": "panic-in-callback"}),
        )
        .await;
        let crossed = drain_frames(&mut frames).await;
        assert!(
            crossed
                .iter()
                .any(|frame| matches!(frame, v1::stream_chunk::Chunk::Failure(_))),
            "a callback that panicked answers with a failure: {crossed:?}"
        );
        assert!(
            !crossed
                .iter()
                .take(crossed.len().saturating_sub(1))
                .any(|frame| matches!(frame, v1::stream_chunk::Chunk::End(true))),
            "and never with a clean end before it: {crossed:?}"
        );

        // The session survives: the same host serves a second invocation, which is
        // the part a panic in one plugin's callback must not decide.
        drop(frames);
        let mut again = invoke_stream_frames(
            &service,
            &session_id,
            "operation-stream",
            serde_json::json!({"model": "fixture-model"}),
        )
        .await;
        let crossed = drain_frames(&mut again).await;
        assert!(
            crossed
                .iter()
                .any(|frame| matches!(frame, v1::stream_chunk::Chunk::End(true))),
            "the session serves the invocation that follows: {crossed:?}"
        );
        let _ = manifest_dir;
    }

    /// A returned stream that panics while being polled fails its call.
    ///
    /// The other place plugin code runs: after the callback has answered, while the
    /// stream it handed back is being read. The ownership lifetimes differ — the
    /// callback's future is gone by then — and the outcome has to be the same: a
    /// failure rather than a stream that stops as if it had finished.
    #[tokio::test]
    async fn a_stream_that_panics_while_being_polled_fails_the_call() {
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((manifest_dir, artifact)) = nemo_relay_plugin_host_fixture() else {
            eprintln!("the native fixture is missing; skipping the panic case");
            return;
        };
        let ((service, session_id), steps) =
            streaming_service_with_marks(&artifact, KernelProducer::watching(), true).await;
        let _marks = CollectedMarks::start(steps);

        let mut frames = invoke_stream_frames(
            &service,
            &session_id,
            "operation-stream",
            serde_json::json!({"model": "fixture-model", "fixture_stream_shape": "panic-in-stream"}),
        )
        .await;
        let crossed = drain_frames(&mut frames).await;
        assert!(
            crossed
                .iter()
                .any(|frame| matches!(frame, v1::stream_chunk::Chunk::Failure(_))),
            "a stream that panicked answers with a failure: {crossed:?}"
        );
        let _ = manifest_dir;
    }

    /// Two continuations of one callback stay attributed to the call they belong to.
    ///
    /// An intercept may run the rest of its chain more than once, and each run is a
    /// call of its own: the plugin opens the downstream stream twice, raises a mark
    /// for each, and both marks belong to the operation whose callback raised them
    /// — the continuation is an identity of the *call*, not of the mark's owner.
    #[tokio::test]
    async fn two_continuations_of_one_callback_stay_attributed_to_their_call() {
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((manifest_dir, artifact)) = nemo_relay_plugin_host_fixture() else {
            eprintln!("the native fixture is missing; skipping the continuation case");
            return;
        };
        let ((service, session_id), steps) =
            streaming_service_with_marks(&artifact, KernelProducer::watching(), true).await;
        let marks = CollectedMarks::start(steps);

        let mut frames = invoke_stream_frames(
            &service,
            &session_id,
            "operation-stream",
            serde_json::json!({
                "model": "fixture-model",
                "fixture_stream_shape": "two-continuations",
            }),
        )
        .await;
        let crossed = drain_frames(&mut frames).await;
        // Both continuations produced, and both marks belong to the one operation.
        let data = crossed
            .iter()
            .filter(|frame| matches!(frame, v1::stream_chunk::Chunk::Data(_)))
            .count();
        assert_eq!(
            data, 4,
            "both continuations ran, each producing the producer's two chunks: {crossed:?}"
        );
        let marks = marks.marks();
        let mut positions: Vec<&str> = marks
            .iter()
            .filter(|(_, _, position)| position.ends_with("continuation"))
            .map(|(operation, _, position)| {
                assert_eq!(
                    operation, "operation-stream",
                    "a continuation's mark belongs to the call, not to the continuation"
                );
                position.as_str()
            })
            .collect();
        positions.sort();
        assert_eq!(
            positions,
            ["first-continuation", "second-continuation"],
            "each continuation's mark arrived once: {marks:?}"
        );
        let _ = manifest_dir;
    }

    /// The supervisor's half of the mark path, running while a call does its work.
    ///
    /// A call's marks are delivered before the frame that ends it, so a test that
    /// reads the frames without forwarding them is a test whose call never ends: the
    /// collector stands in for the host's own forwarding loop.
    struct CollectedMarks {
        marks: Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
        forwarding: tokio::task::JoinHandle<()>,
    }

    impl CollectedMarks {
        fn start(mut steps: tokio::sync::mpsc::Receiver<ForwardedStep>) -> Self {
            let marks = Arc::new(std::sync::Mutex::new(Vec::new()));
            let recording = Arc::clone(&marks);
            let forwarding = tokio::spawn(async move {
                while let Some(step) = steps.recv().await {
                    match step {
                        ForwardedStep::Mark { mark, .. } => {
                            let data: serde_json::Value = mark
                                .data_json
                                .as_deref()
                                .and_then(|data| serde_json::from_str(data).ok())
                                .unwrap_or(serde_json::Value::Null);
                            recording.lock().unwrap().push((
                                mark.operation_request_id.clone(),
                                data["stream"].as_str().unwrap_or_default().to_owned(),
                                data["position"].as_str().unwrap_or_default().to_owned(),
                            ));
                        }
                        ForwardedStep::Flush { done } => {
                            let _ = done.send(Ok(()));
                        }
                    }
                }
            });
            Self { marks, forwarding }
        }

        /// What was forwarded so far.
        ///
        /// Complete once the call's frames have reached their end, because the end
        /// waits for the marks ahead of it.
        fn marks(&self) -> Vec<(String, String, String)> {
            self.marks.lock().unwrap().clone()
        }
    }

    impl Drop for CollectedMarks {
        fn drop(&mut self) {
            self.forwarding.abort();
        }
    }

    /// Every frame a streaming invocation produced, up to the one that ends it.
    async fn drain_frames(
        frames: &mut <PluginHostService as v1::plugin_host_server::PluginHost>::InvokeStreamStream,
    ) -> Vec<v1::stream_chunk::Chunk> {
        use tokio_stream::StreamExt;

        let mut crossed = Vec::new();
        while let Some(frame) =
            tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
                .await
                .expect("a frame or an end")
        {
            let frame = frame.expect("a frame");
            let Some(chunk) = frame.chunk else { continue };
            let terminal = matches!(
                chunk,
                v1::stream_chunk::Chunk::End(_) | v1::stream_chunk::Chunk::Failure(_)
            );
            crossed.push(chunk);
            if terminal {
                break;
            }
        }
        crossed
    }

    /// A mark belongs to the operation whose callback raised it, in whatever order
    /// the two streams reach their marks.
    ///
    /// The property is attribution rather than delivery: eight marks arriving would
    /// say nothing about whether each one belonged to the operation that raised it,
    /// which is what two streams interleaved three ways is here to prove — each run
    /// with the schedule the test chose rather than the one the scheduler produced.
    /// Within a stream the order is the callback's, and between the two streams
    /// there is no order to require, so none is.
    #[tokio::test]
    async fn a_mark_belongs_to_the_operation_whose_callback_raised_it() {
        const POSITIONS: [&str; 4] = [
            "before-downstream",
            "downstream-active",
            "between-frames",
            "before-terminal",
        ];

        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((manifest_dir, artifact)) = nemo_relay_plugin_host_fixture() else {
            eprintln!("the native fixture is missing; skipping the matrix case");
            return;
        };
        for (generation, schedule) in [
            // Alternating; then one stream ahead and back; then the other first.
            ["A", "B", "A", "B", "A", "B", "A", "B"],
            ["A", "A", "B", "B", "B", "A", "B", "A"],
            ["B", "A", "B", "A", "A", "B", "A", "B"],
        ]
        .into_iter()
        .enumerate()
        {
            let marks = marks_under_schedule(&artifact, generation as u64 + 1, &schedule).await;

            // No cross-attribution: a mark raised by one stream's callback belongs
            // to that stream's operation and never to the other's.
            for (operation, stream, position) in &marks {
                let expected = if stream == "A" {
                    "operation-A"
                } else {
                    "operation-B"
                };
                assert_eq!(
                    operation, expected,
                    "the mark stream {stream} raised at '{position}' belongs to \
                     {expected} under {schedule:?}: {marks:?}"
                );
            }

            // No missing marks and no duplicates: each stream raises each of the
            // four positions exactly once.
            let mut raised: Vec<(String, String)> = marks
                .iter()
                .map(|(_, stream, position)| (stream.clone(), position.clone()))
                .collect();
            raised.sort();
            let mut expected: Vec<(String, String)> = Vec::new();
            for stream in ["A", "B"] {
                for position in POSITIONS {
                    expected.push((stream.to_string(), position.to_string()));
                }
            }
            expected.sort();
            assert_eq!(
                raised, expected,
                "every position of both streams arrived once under {schedule:?}: {marks:?}"
            );

            // Within a stream, the order is the order the callback reaches the
            // positions in. Between the streams there is none, so none is asserted.
            for stream in ["A", "B"] {
                let order: Vec<&str> = marks
                    .iter()
                    .filter(|(_, raised_by, _)| raised_by == stream)
                    .map(|(_, _, position)| position.as_str())
                    .collect();
                assert_eq!(
                    order,
                    POSITIONS.to_vec(),
                    "stream {stream} raised its marks in the callback's order under \
                     {schedule:?}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&manifest_dir);
    }

    /// A mark a streaming callback raises reaches the host's forwarder.
    ///
    /// The mark window is the host's, opened around the callback it invokes; the
    /// work that raises the mark runs on an executor task of the plugin's own, so
    /// the window has to be captured where it is open and carried across that
    /// boundary. This is the first position a streaming call can raise a mark in —
    /// before the plugin opens the downstream stream — and it is the one the
    /// fixture raises today.
    #[tokio::test]
    async fn a_streaming_callback_s_mark_reaches_the_host_s_forwarder() {
        use tokio_stream::StreamExt;

        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((manifest_dir, artifact)) = nemo_relay_plugin_host_fixture() else {
            eprintln!("the native fixture is missing; skipping the mark case");
            return;
        };
        let ((service, session_id), mut steps) =
            streaming_service_with_marks(&artifact, KernelProducer::watching(), true).await;
        // The supervisor's half: the marks a callback raises are forwarded on, and
        // the call's end waits for them, so something has to deliver them while the
        // frames are being read.
        let seen: Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let recording = Arc::clone(&seen);
        let forwarding = tokio::spawn(async move {
            while let Some(step) = steps.recv().await {
                match step {
                    ForwardedStep::Mark { mark, .. } => {
                        recording.lock().unwrap().push((
                            mark.name.clone(),
                            mark.operation_request_id.clone(),
                            mark.data_json
                                .as_deref()
                                .and_then(|data| serde_json::from_str(data).ok())
                                .unwrap_or(serde_json::Value::Null),
                        ));
                    }
                    ForwardedStep::Flush { done } => {
                        let _ = done.send(Ok(()));
                    }
                }
            }
        });

        let mut frames = invoke_stream_frames(
            &service,
            &session_id,
            "operation-stream",
            serde_json::json!({"model": "fixture-model"}),
        )
        .await;
        while let Some(frame) =
            tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
                .await
                .expect("a frame or an end")
        {
            let frame = frame.expect("a frame");
            if matches!(
                frame.chunk,
                Some(v1::stream_chunk::Chunk::End(_)) | Some(v1::stream_chunk::Chunk::Failure(_))
            ) {
                break;
            }
        }
        drop(frames);
        forwarding.abort();

        let seen = seen.lock().unwrap().clone();
        let raised = seen
            .iter()
            .find(|(name, _, _)| name == "fixture.native.llm_stream.mark")
            .unwrap_or_else(|| {
                panic!("the mark the streaming callback raised crossed to the forwarder: {seen:?}")
            });
        assert_eq!(
            raised.1, "operation-stream",
            "the window says which operation the mark belongs to, and the plugin cannot change it"
        );
        assert_eq!(
            raised.2["position"],
            serde_json::json!("before-downstream"),
            "the position the plugin named is the position that arrived"
        );
        let _ = std::fs::remove_dir_all(&manifest_dir);
    }

    /// Cancelling the outer consumer reaches the kernel's producer.
    ///
    /// The whole point of a boundary is that a caller who walks away takes the
    /// work with them. This walks the cascade the streaming path is supposed to
    /// have — the kernel's consumer dropped, the host stops polling, the plugin's
    /// returned stream dropped, the session channel closed, the kernel told, and
    /// the producer the kernel was running for that stream dropped — and observes
    /// the *last* step, because that is the one that says the work stopped rather
    /// than that a message was sent.
    ///
    /// Every state a consumer can walk away in is covered, because they are
    /// different ownership states rather than different timings: the plugin's
    /// downstream stream is open and nothing has been read from it, the open is
    /// still in flight so the kernel is producing a stream the host has not been
    /// told the name of, and a frame has already crossed. A leak in any of them
    /// is the kind that only shows up in production.
    #[tokio::test]
    async fn dropping_the_consumer_reaches_the_kernels_producer() {
        the_cascade_holds_when_the_consumer_leaves(Leaving::BeforeAnyFrame).await;
        the_cascade_holds_when_the_consumer_leaves(Leaving::WhileTheOpenIsInFlight).await;
        the_cascade_holds_when_the_consumer_leaves(Leaving::AfterAFrame).await;
    }

    /// When the consumer walks away, relative to the stream behind it.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Leaving {
        /// The downstream stream is open and unpolled.
        BeforeAnyFrame,
        /// The kernel is opening: it has been asked for a stream and has not
        /// answered yet, so its name does not exist on this side.
        WhileTheOpenIsInFlight,
        /// A frame has crossed and a consumer is reading.
        AfterAFrame,
    }

    impl Leaving {
        /// How a failure names the state it was in.
        fn describe(self) -> &'static str {
            match self {
                Self::BeforeAnyFrame => "with the stream open and unpolled",
                Self::WhileTheOpenIsInFlight => "with the open still in flight",
                Self::AfterAFrame => "after a frame crossed",
            }
        }
    }

    /// One point in that race, driven end to end against a real plugin.
    ///
    /// The fixture is a real native plugin over a real socket to a real kernel,
    /// so the cascade is the one production has; only the moment the consumer
    /// leaves is chosen by the test.
    async fn the_cascade_holds_when_the_consumer_leaves(leaving: Leaving) {
        use tokio_stream::StreamExt;

        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((manifest_dir, artifact)) = nemo_relay_plugin_host_fixture() else {
            eprintln!("the native fixture is missing; skipping the cancellation case");
            return;
        };
        let producer = match leaving {
            Leaving::WhileTheOpenIsInFlight => KernelProducer::gated(),
            _ => KernelProducer::watching(),
        };
        let (service, session_id) = streaming_service(&artifact, producer.clone()).await;
        let mut frames = invoke_stream_frames(
            &service,
            &session_id,
            "operation-stream",
            serde_json::json!({"model": "fixture-model"}),
        )
        .await;

        match leaving {
            // Waiting for the producer is what makes this the state the test
            // names: the stream behind the consumer exists, and the consumer has
            // read nothing from it.
            Leaving::BeforeAnyFrame => producer.await_produced().await,
            // The kernel is held in the open, so the consumer leaves before the
            // stream it is opening has a name on this side of the boundary.
            Leaving::WhileTheOpenIsInFlight => producer.await_open_in_flight().await,
            Leaving::AfterAFrame => {
                assert!(
                    frames.next().await.is_some(),
                    "a frame crossed before the consumer walked away"
                );
            }
        }

        // The consumer walks away. Everything behind it should follow.
        drop(frames);
        producer.release_open();

        producer.await_dropped(leaving.describe()).await;
        let _ = std::fs::remove_dir_all(&manifest_dir);
    }

    /// A host service that serves every class, with the fixture activated, and a
    /// kernel whose producer reports when it is dropped.
    async fn streaming_service(
        artifact: &str,
        producer: KernelProducer,
    ) -> (PluginHostService, String) {
        streaming_service_with_marks(artifact, producer, false)
            .await
            .0
    }

    /// The same service, with the marks its callback raises readable as steps.
    ///
    /// A host only forwards a plugin's marks when it has somewhere to forward
    /// them, which in production is the channel to the kernel: this is that
    /// channel, so a test can see what crossed it.
    async fn streaming_service_with_marks(
        artifact: &str,
        producer: KernelProducer,
        forward_marks: bool,
    ) -> (
        (PluginHostService, String),
        tokio::sync::mpsc::Receiver<ForwardedStep>,
    ) {
        let (mark_sender, mark_steps) = tokio::sync::mpsc::channel::<ForwardedStep>(64);
        let backend = Arc::new(crate::InProcessPluginBackend::new());
        let config = PluginHostConfig {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        };
        let mut service = PluginHostService::new(backend, config.clone());
        if forward_marks {
            service = service.with_mark_forwarding(mark_sender);
        }
        let mut handshake = handshake_request(&config);
        handshake.supported_registration_operations = EVERY_REGISTRATION_OPERATION
            .iter()
            .map(|operation| {
                nemo_relay_plugin_proto::convert::registration_operation_to_wire(*operation)
            })
            .collect();
        let session_id = handshake_outcome_from_wire(
            &service
                .handshake(capable(handshake))
                .await
                .expect("a served handshake")
                .into_inner(),
        )
        .expect("a converted handshake")
        .into_result()
        .expect("an established session")
        .session_id;

        let (endpoint, kernel) = serve_kernel_with_producer(
            &session_id,
            "operation-stream",
            vec![
                serde_json::json!({"chunk": 1}),
                serde_json::json!({"chunk": 2}),
            ],
            producer,
        )
        .await;
        // Kept for the test's lifetime, so the kernel's listener outlives the call.
        std::mem::forget(kernel);
        let callbacks = crate::runtime_service::KernelCallbacks::new(
            crate::runtime_service::connect_to_kernel(
                &endpoint,
                nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
            )
            .await
            .expect("a kernel client"),
            KERNEL_CREDENTIAL,
        )
        .expect("the kernel credential");
        let service = service.with_kernel_callbacks(callbacks);

        let (manifest_sha256, library_sha256) =
            nemo_relay::plugin::dynamic::plugin_artifact_identity(artifact)
                .expect("the fixture's identity");
        service
            .load(capable(v1::LoadRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                plugin_id: "fixture_native".into(),
                artifact: artifact.to_owned(),
                manifest_digest: manifest_sha256,
                library_digest: library_sha256,
            }))
            .await
            .expect("a served load");
        let activated = service
            .activate(capable(v1::ActivateRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                discovery: false,
                components: vec![v1::ComponentConfiguration {
                    kind: "fixture_native".into(),
                    config_json: "{}".into(),
                }],
            }))
            .await
            .expect("a served activation")
            .into_inner();
        nemo_relay_plugin_proto::convert::activate_outcome_from_wire(&activated)
            .expect("a converted activation")
            .into_result()
            .expect("the session serves every class this fixture registers");
        ((service, session_id), mark_steps)
    }

    /// Start the streaming invocation the cancellation cases drop.
    async fn invoke_stream_frames(
        service: &PluginHostService,
        session_id: &str,
        operation: &str,
        content: serde_json::Value,
    ) -> <PluginHostService as v1::plugin_host_server::PluginHost>::InvokeStreamStream {
        let descriptors = service
            .inspect(capable(v1::InspectRequest {
                session_id: session_id.to_owned(),
                context: Some(context()),
                handle: None,
            }))
            .await
            .expect("a served inspection")
            .into_inner();
        let descriptors = nemo_relay_plugin_proto::convert::inspect_outcome_from_wire(&descriptors)
            .expect("a converted inspection")
            .into_result()
            .expect("an inspection");
        let registration = descriptors
            .iter()
            .flat_map(|descriptor| descriptor.registrations.iter())
            .find(|registration| {
                registration.operation
                    == nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmStreamExecutionIntercept
            })
            .expect("the fixture registers a streaming intercept")
            .registration_id
            .clone();

        let mut streaming_context = context();
        streaming_context.operation_request_id = operation.to_owned();
        service
            .invoke_stream(capable(v1::InvokeRequest {
                session_id: session_id.to_owned(),
                context: Some(streaming_context),
                handle: Some(nemo_relay_plugin_proto::convert::handle_to_wire(
                    &nemo_relay_plugin_protocol::PluginHandle {
                        plugin_id: "fixture_native".into(),
                        generation: 1,
                    },
                )),
                registration_id: registration,
                arguments: serde_json::json!({
                    "name": "fixture_provider",
                    "request": {"headers": {}, "content": content},
                })
                .to_string(),
            }))
            .await
            .expect("a served streaming invocation")
            .into_inner()
    }

    #[tokio::test]
    async fn an_invocation_that_names_no_operation_is_not_answered() {
        // The host cannot attribute an outcome it cannot name, so it refuses the
        // request at the transport level rather than answering in the shape of a
        // result. A kernel that received such an answer could not tell whether it
        // belonged to the invocation it sent, and would have to treat its own
        // record as evidence about work nobody can account for.
        let (service, config) = service();
        let session_id = establish(&service, &config).await;
        let handle = nemo_relay_plugin_proto::convert::handle_to_wire(
            &nemo_relay_plugin_protocol::PluginHandle {
                plugin_id: "fixture_native".into(),
                generation: 1,
            },
        );
        let invocation = |context: Option<v1::PluginExecutionContext>| v1::InvokeRequest {
            session_id: session_id.clone(),
            context,
            handle: Some(handle.clone()),
            registration_id: "registration-1".into(),
            arguments: "{}".into(),
        };

        let absent = service
            .invoke(capable(invocation(None)))
            .await
            .expect_err("an invocation with no context has no operation to name");
        assert_eq!(absent.code(), tonic::Code::InvalidArgument, "{absent:?}");

        let mut unnamed = context();
        unnamed.operation_request_id = "  ".into();
        let blank = service
            .invoke(capable(invocation(Some(unnamed))))
            .await
            .expect_err("an invocation whose context names no operation");
        assert_eq!(blank.code(), tonic::Code::InvalidArgument, "{blank:?}");
    }

    #[test]
    fn a_mark_carries_its_session_and_every_field() {
        // The host converts the kernel's message before using it, so a mark that
        // lost a field would be a different event than the one that was sent.
        let wire = v1::EmitMarkRequest {
            session_id: "session-1".into(),
            operation_request_id: "operation-1".into(),
            host_call_id: "call-1".into(),
            name: "example.mark".into(),
            data_json: Some(r#"{"value":1}"#.into()),
            parent: None,
            metadata_json: None,
            data_schema: None,
            severity: None,
            timestamp_unix_micros: None,
        };
        let mark = mark_request_from_wire(&wire).expect("a mark");
        assert_eq!(mark.name, "example.mark");
        assert_eq!(mark.data_json.as_deref(), Some(r#"{"value":1}"#));
    }

    #[test]
    fn a_failure_is_never_read_as_a_channel_problem() {
        // The distinction the boundary exists to preserve, stated as a test: a
        // structured failure is a result, and only the transport can produce the
        // other kind.
        let failure = PluginFailure {
            code: PluginFailureCode::Rejected,
            message: "the host refused".into(),
        };
        let outcome: LifecycleOutcome<()> = LifecycleOutcome::from_result(Err(failure));
        assert!(matches!(outcome, LifecycleOutcome::Failed(_)));
    }

    /// A window that has been closed refuses the marks of whatever still holds it.
    ///
    /// This is capability non-reuse rather than cleanup: a plugin task that outlives
    /// its call still holds that call's window, and the operation identity the window
    /// carries is one the kernel has already settled. Attributing a late mark
    /// through it would attribute the mark to whatever holds that identity now, so
    /// the window refuses instead — and nothing reaches the channel the kernel is
    /// served from.
    #[tokio::test]
    async fn a_closed_window_refuses_a_late_mark() {
        use nemo_relay::plugin::execution::{ForwardedMark, MarkForwarder};

        let (sender, mut steps) = tokio::sync::mpsc::channel(4);
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink = ForwardingSink {
            sender,
            session_id: "session-1".into(),
            operation_request_id: "operation-1".into(),
            closed: std::sync::Arc::clone(&closed),
            host_calls: std::sync::atomic::AtomicU64::new(0),
        };
        let mark = ForwardedMark {
            name: "example.mark".into(),
            parent: None,
            data_json: None,
            metadata_json: None,
            data_schema: None,
            severity: None,
            timestamp_unix_micros: None,
        };

        // While the call is running, the window takes marks.
        sink.forward(&mark).expect("a mark of a running call");
        assert!(
            steps.try_recv().is_ok(),
            "and it reaches the channel the kernel is served from"
        );

        // Once the call is over the same window refuses the same mark: the work
        // that still holds it is work nobody is waiting for.
        closed.store(true, std::sync::atomic::Ordering::SeqCst);
        let refused = sink
            .forward(&mark)
            .expect_err("a late mark is refused rather than attributed");
        assert!(
            refused.to_string().contains("has ended"),
            "the refusal says the call the window belonged to is over: {refused}"
        );
        assert!(steps.try_recv().is_err(), "and nothing crossed for it");
    }

    /// A plugin's telemetry is bounded, and the bound is what refuses it.
    ///
    /// Marks come from a callback and leave over a socket, so the queue between
    /// them is the buffer between two speeds the host does not control. Filling
    /// it has to fail the mark rather than grow this process: an unbounded queue
    /// would let one plugin that emits faster than the kernel reads decide how
    /// much memory the host process is allowed to use.
    #[tokio::test]
    async fn a_full_mark_queue_refuses_the_mark_rather_than_buffering_it() {
        use nemo_relay::plugin::execution::{ForwardedMark, MarkForwarder};

        let capacity = 4;
        let (sender, mut steps) = tokio::sync::mpsc::channel(capacity);
        let sink = ForwardingSink {
            sender,
            session_id: "session-1".into(),
            operation_request_id: "operation-1".into(),
            closed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            host_calls: std::sync::atomic::AtomicU64::new(0),
        };
        let mark = ForwardedMark {
            name: "example.mark".into(),
            parent: None,
            data_json: None,
            metadata_json: None,
            data_schema: None,
            severity: None,
            timestamp_unix_micros: None,
        };

        for raised in 0..capacity {
            sink.forward(&mark)
                .unwrap_or_else(|error| panic!("mark {raised} has room: {error}"));
        }
        let refused = sink
            .forward(&mark)
            .expect_err("a queue with no room refuses the mark");
        assert!(
            refused.to_string().contains("not keeping up"),
            "the refusal says why the mark did not leave: {refused}"
        );

        // The marks that were accepted are the marks that arrive, in order, and
        // nothing was silently dropped to make room.
        let mut delivered = 0;
        while let Ok(step) = steps.try_recv() {
            if let ForwardedStep::Mark { mark, .. } = step {
                assert_eq!(mark.name, "example.mark");
                delivered += 1;
            }
        }
        assert_eq!(
            delivered, capacity as i64,
            "the accepted marks are the ones the kernel will see"
        );
    }

    /// Establish a session against a host configured for `host_limit`, offered
    /// `offered`, and report the frame limit the session came back with.
    async fn negotiated_frame_limit(host_limit: u32, offered: u32) -> u32 {
        let backend = Arc::new(crate::InProcessPluginBackend::new());
        let config = PluginHostConfig {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: host_limit,
        };
        let service = PluginHostService::new(backend, config.clone());
        let mut request = handshake_request(&config);
        request.maximum_frame_bytes = offered;
        let outcome = service
            .handshake(capable(request))
            .await
            .expect("a served handshake")
            .into_inner();
        handshake_outcome_from_wire(&outcome)
            .expect("a converted handshake")
            .into_result()
            .expect("an established session")
            .maximum_frame_bytes
    }

    /// One limit for both directions, and it is the smaller of the two.
    ///
    /// A host that reported its own limit regardless of what the kernel offered
    /// would open a session at a size the kernel never agreed to carry, and every
    /// transport built from that session would inherit it.
    #[tokio::test]
    async fn a_session_negotiates_the_smaller_of_the_two_frame_limits() {
        let megabyte = 1024 * 1024;
        assert_eq!(
            negotiated_frame_limit(2 * megabyte, megabyte).await,
            megabyte,
            "the kernel's smaller offer is what the session carries"
        );
        assert_eq!(
            negotiated_frame_limit(megabyte, 2 * megabyte).await,
            megabyte,
            "the host's smaller limit is what the session carries"
        );
        assert_eq!(
            negotiated_frame_limit(2 * megabyte, 2 * megabyte).await,
            2 * megabyte,
            "two sides that agree keep what they agreed on"
        );
        assert_eq!(
            negotiated_frame_limit(
                nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
                nemo_relay_plugin_protocol::MAX_FRAME_BYTES
            )
            .await,
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
            "and the protocol's ceiling is a size like any other"
        );
    }

    /// A handshake that would carry no frame at all is refused rather than
    /// negotiated down to nothing.
    #[tokio::test]
    async fn a_session_cannot_be_established_on_no_frame_at_all() {
        let backend = Arc::new(crate::InProcessPluginBackend::new());
        let config = PluginHostConfig {
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        };
        let service = PluginHostService::new(backend, config.clone());
        let mut request = handshake_request(&config);
        request.maximum_frame_bytes = 0;
        let outcome = service
            .handshake(capable(request))
            .await
            .expect("a served handshake")
            .into_inner();
        let outcome = handshake_outcome_from_wire(&outcome).expect("a converted handshake");
        assert!(
            outcome.into_result().is_err(),
            "a session that accepts no frame is not a session"
        );
    }

    /// Inspection reports what activation produced and keeps nothing of it.
    ///
    /// The contract discovery exists to keep is that asking what a plugin would
    /// register is not the same as registering it. A session that answered with
    /// the descriptors and left the callbacks installed would answer questions
    /// about a process that had been changed by the question.
    #[tokio::test]
    async fn a_discovery_activation_leaves_the_process_as_it_found_it() {
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some(session) = FixtureSession::start(
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        )
        .await
        else {
            eprintln!("the intercept fixture is missing; skipping the discovery case");
            return;
        };
        // From a known baseline rather than from whatever ran before this: what
        // is being asserted is the state this call leaves behind.
        let _ = nemo_relay::plugin::clear_plugin_configuration();
        assert!(
            nemo_relay::plugin::active_plugin_report().is_none(),
            "the test starts with no active configuration"
        );

        let inspected = session.activate(true).await;
        let registration = session.tool_request_intercept(&inspected);
        assert!(
            nemo_relay::plugin::active_plugin_report().is_none(),
            "an inspection that reported registrations left none of them behind"
        );

        // And the registration the report named is not one this process can run:
        // the callbacks went away with the inspection that made them.
        let after_discovery = session.invoke(&registration, 64 * 1024).await;
        assert!(
            after_discovery.result.is_err(),
            "nothing is registered after an inspection: {after_discovery:?}"
        );

        // The same registration is reachable once a session means to serve it,
        // which is what makes the refusal above a statement about the inspection
        // rather than about the fixture.
        let served = session.activate(false).await;
        let served_registration = session.tool_request_intercept(&served);
        assert!(
            nemo_relay::plugin::active_plugin_report().is_some(),
            "a serving activation is an active configuration"
        );
        let after_serving = session.invoke(&served_registration, 64 * 1024).await;
        assert!(
            after_serving.result.is_ok(),
            "a serving activation runs the registration: {after_serving:?}"
        );
    }

    /// Inspecting twice reports the same thing twice.
    ///
    /// The second report is the one that shows the first left nothing behind: an
    /// inspection that installed its callbacks would answer the second call from
    /// a process the first call had already changed.
    #[tokio::test]
    async fn a_discovery_activation_reports_the_same_registrations_twice() {
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some(session) = FixtureSession::start(
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        )
        .await
        else {
            eprintln!("the intercept fixture is missing; skipping the discovery case");
            return;
        };
        let registration_ids = |outcome: &v1::ActivateOutcome| {
            let Some(v1::activate_outcome::Result::Activated(response)) = &outcome.result else {
                panic!("the fixture's registrations are reported: {outcome:?}");
            };
            response
                .descriptors
                .iter()
                .flat_map(|descriptor| descriptor.registrations.iter())
                .map(|registration| registration.registration_id.clone())
                .collect::<std::collections::BTreeSet<_>>()
        };

        let first = session.activate(true).await;
        let second = session.activate(true).await;
        assert_eq!(
            registration_ids(&first),
            registration_ids(&second),
            "one artifact inspected twice reports the same registrations"
        );
        assert!(
            nemo_relay::plugin::active_plugin_report().is_none(),
            "and neither inspection left a configuration behind"
        );
    }

    /// The budget an operation carries is the size of the answer it may receive.
    ///
    /// Measured at the boundary: the answer at the budget is served, the answer
    /// one byte above it is refused, and the refusal says that is what happened
    /// rather than looking like a callback that declined to run.
    #[tokio::test]
    async fn an_answer_larger_than_the_operations_budget_is_refused() {
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some(session) = FixtureSession::start(
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        )
        .await
        else {
            eprintln!("the intercept fixture is missing; skipping the budget case");
            return;
        };
        let served = session.activate(false).await;
        let registration = session.tool_request_intercept(&served);

        let answered = session.invoke(&registration, 64 * 1024).await;
        assert!(answered.result.is_ok(), "the registration answers");
        let wire =
            nemo_relay_plugin_proto::convert::execution_outcome_to_wire(&answered, "operation-1")
                .expect("the answer's wire form");
        let size = nemo_relay_plugin_proto::convert::invoke_outcome_encoded_len(&wire) as u32;
        assert!(size > 1, "an answer is at least a message: {size}");

        let at_budget = session.invoke(&registration, size).await;
        assert!(
            at_budget.result.is_ok(),
            "an answer exactly at its operation's budget is served: {at_budget:?}"
        );

        let above_budget = session.invoke(&registration, size - 1).await;
        match above_budget.result {
            Err(failure) => assert!(
                matches!(failure.code, PluginFailureCode::OversizedFrame { .. }),
                "the refusal names the budget that was exceeded: {failure:?}"
            ),
            Ok(_) => panic!("an answer one byte above its budget is refused"),
        }

        let below_budget = session.invoke(&registration, size + 1).await;
        assert!(
            below_budget.result.is_ok(),
            "and one byte of headroom is enough: {below_budget:?}"
        );
    }

    /// The credential authorises establishing a session; the capability
    /// authorises using it.
    ///
    /// The operations that follow a handshake used to be authorised by naming
    /// the session, and a session's name is what an attach announces. This is
    /// the case that closes that: a peer that knows the socket, the credential's
    /// disposition and the session's identity still may not call the session's
    /// operations.
    #[tokio::test]
    async fn an_operation_that_presents_no_capability_is_refused() {
        let (service, config) = service();
        let session_id = establish(&service, &config).await;
        let inspection = |capability: Option<&str>| {
            let message = v1::InspectRequest {
                session_id: session_id.clone(),
                context: Some(context()),
                handle: None,
            };
            match capability {
                Some(capability) => with_capability(message, capability),
                None => Request::new(message),
            }
        };

        // A request that presents nothing is refused, and refused as a result
        // rather than as a channel failure: the kernel has to be able to read it.
        let unnamed = service
            .inspect(inspection(None))
            .await
            .expect("a served inspection")
            .into_inner();
        let outcome = nemo_relay_plugin_proto::convert::inspect_outcome_from_wire(&unnamed)
            .expect("a converted inspection");
        assert!(
            outcome.into_result().is_err(),
            "an operation that presents no capability is refused"
        );

        // Another session's capability is not this session's, and the length of
        // the value is not what makes it one: a well-formed value from elsewhere
        // is refused for being the wrong value.
        let elsewhere = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let stranger = service
            .inspect(inspection(Some(elsewhere)))
            .await
            .expect("a served inspection")
            .into_inner();
        let outcome = nemo_relay_plugin_proto::convert::inspect_outcome_from_wire(&stranger)
            .expect("a converted inspection");
        assert!(
            outcome.into_result().is_err(),
            "an operation presenting another capability is refused"
        );

        // And the session's own capability is what the operation wanted.
        let admitted = service
            .inspect(inspection(Some(TEST_CAPABILITY)))
            .await
            .expect("a served inspection")
            .into_inner();
        let outcome = nemo_relay_plugin_proto::convert::inspect_outcome_from_wire(&admitted)
            .expect("a converted inspection");
        let admitted = outcome.into_result();
        assert!(
            admitted.is_ok(),
            "the session's own capability is admitted: {admitted:?}"
        );
    }

    /// A session cannot be established on a capability the kernel did not mint.
    ///
    /// A host that accepted a handshake with no capability would open a session
    /// that nobody could authorise calls on, which is the state this exists to
    /// make impossible.
    #[tokio::test]
    async fn a_handshake_without_a_capability_establishes_nothing() {
        let (service, config) = service();
        let refused = service
            .handshake(Request::new(handshake_request(&config)))
            .await
            .expect("a served handshake")
            .into_inner();
        let outcome = handshake_outcome_from_wire(&refused).expect("a converted handshake");
        assert!(
            outcome.into_result().is_err(),
            "a handshake that presents no capability is refused"
        );

        // A value that is not the shape a capability is gets the same answer, so
        // a peer cannot pick its own strength by sending a shorter value.
        let short = service
            .handshake(with_capability(handshake_request(&config), "0f"))
            .await
            .expect("a served handshake")
            .into_inner();
        let outcome = handshake_outcome_from_wire(&short).expect("a converted handshake");
        assert!(outcome.into_result().is_err(), "a short value is refused");

        // The host served no session, so nothing else can be asked of it either.
        let after = service
            .inspect(capable(v1::InspectRequest {
                session_id: "session-1".into(),
                context: Some(context()),
                handle: None,
            }))
            .await
            .expect("a served inspection")
            .into_inner();
        let outcome = nemo_relay_plugin_proto::convert::inspect_outcome_from_wire(&after)
            .expect("a converted inspection")
            .into_result();
        assert!(outcome.is_err(), "{outcome:?}");
    }

    /// A second transport is authorised the way the first one was.
    ///
    /// The attach presents the credential, so it already has to come from
    /// whoever started the host. It presents the capability too, because a
    /// transport that could join a session with the credential alone would make
    /// the capability a property of the handshake rather than of the session.
    #[tokio::test]
    async fn an_attach_that_presents_no_capability_is_refused() {
        let (service, config) = service();
        let session_id = establish(&service, &config).await;
        let attach = |capability: Option<&str>| {
            let message = attach_request(&config, &session_id);
            match capability {
                Some(capability) => with_capability(message, capability),
                None => Request::new(message),
            }
        };

        for capability in [
            None,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdff"),
        ] {
            let refused = service
                .attach(attach(capability))
                .await
                .expect("a served attach")
                .into_inner();
            let outcome = nemo_relay_plugin_proto::convert::attach_outcome_from_wire(&refused)
                .expect("a converted attach");
            assert!(
                outcome.into_result().is_err(),
                "an attach presenting {capability:?} is refused"
            );
        }

        let admitted = service
            .attach(attach(Some(TEST_CAPABILITY)))
            .await
            .expect("a served attach")
            .into_inner();
        let attached = nemo_relay_plugin_proto::convert::attach_outcome_from_wire(&admitted)
            .expect("a converted attach")
            .into_result();
        assert!(
            attached.is_ok(),
            "the session's own capability attaches: {attached:?}"
        );
    }

    // -- The Layer 2 gate: the three event sanitize families ---------------------
    //
    // The classes under test are the mark, scope-start and scope-end sanitizers:
    // three families that share one serialization, and cross the boundary as a
    // *projection* — the identity a sanitizer decides on (the event's name, and the
    // phase when it is a scope event) plus the mutable observability fields it may
    // change. The kernel keeps the event, the class it asked under, the registration
    // identity, the operation identity and the publication decision.
    //
    // What is here is the host's half: exactly one registration runs, the class it
    // runs is the registration's own, and every failure is a failure rather than an
    // unsanitized answer. What is deliberately not here is the kernel's half — the
    // proxy that builds the projection, sends it beside the call and applies what
    // comes back — because a sanitize proxy's answer arrives over the composition's
    // own transport, so a test of it is a test with a host process in it. That
    // qualification is the process-boundary suite's, and it reuses the sentinel
    // assertion below.
    //
    // Every failure case also asserts the confidentiality property directly: a
    // sentinel in every observable field, and an assertion that none of it reaches
    // anything the answer carries. "The invocation was refused" is a weaker claim
    // than "the payload cannot be published", and only the second is the property.

    use nemo_relay_plugin_protocol::{
        EventSanitizeFields, PluginEventSanitizeCall, PluginEventSanitizeClass, PluginSuccess,
    };

    use crate::confidentiality;

    /// The fixture's three mark sanitizers, and the marker each one adds.
    const MARK_SANITIZERS: [(&str, &str); 3] = [
        ("fixture_mark_a", "fixture_mark_a"),
        ("fixture_mark_b", "fixture_mark_b"),
        ("fixture_mark_c", "fixture_mark_c"),
    ];

    /// Every marker the fixture's sanitizers can leave, by family.
    const EVERY_MARKER: [(&str, &str); 6] = [
        ("fixture_mark_a", "fixture_mark_a"),
        ("fixture_mark_b", "fixture_mark_b"),
        ("fixture_mark_c", "fixture_mark_c"),
        (
            "fixture_scope_start_sanitize",
            "fixture_scope_start_sanitize",
        ),
        ("fixture_scope_start_other", "fixture_scope_start_other"),
        ("fixture_scope_end_sanitize", "fixture_scope_end_sanitize"),
    ];

    /// The configuration that asks the fixture for its failure shapes.
    ///
    /// The well-behaved registrations are part of the fixture's default set now that
    /// the kernel serves the class; a sanitizer that refuses, one that throws and one
    /// that answers oversized are behaviours a test asks for, because they would
    /// otherwise change every other event the suite publishes.
    ///
    /// A value rather than a string of JSON, because it is handed to the activation as
    /// one: a string of JSON here would be a JSON string on the wire, which the host
    /// refuses as a configuration that is not an object.
    fn event_sanitizer_failures() -> serde_json::Value {
        serde_json::json!({ "event_sanitizer_failures": true })
    }

    /// The response budget a success case states: above the fixture's payloads and
    /// below the transport's frame limit, which is a different limit.
    const EVENT_SANITIZE_BUDGET: u32 = 64 * 1024;

    /// A host serving one session, with the fixture asked for the three families.
    ///
    /// The configuration is the caller's because two of these tests need a witness
    /// rather than an answer: the fixture appends every registration it runs to a
    /// log file when it is given one, and "the call ran exactly this registration" is
    /// a claim about what ran rather than about what came back.
    async fn event_sanitize_session() -> Option<(FixtureSession, v1::ActivateOutcome)> {
        event_sanitize_session_with(serde_json::json!({})).await
    }

    async fn event_sanitize_session_with(
        config: serde_json::Value,
    ) -> Option<(FixtureSession, v1::ActivateOutcome)> {
        let session = FixtureSession::start(
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        )
        .await?;
        let activated = session.activate_with(&config.to_string()).await;
        assert!(
            matches!(
                activated.result,
                Some(v1::activate_outcome::Result::Activated(_))
            ),
            "the fixture's event sanitizers should activate: {activated:?}"
        );
        Some((session, activated))
    }

    /// A fresh log for one invocation, and its path.
    fn sanitizer_log() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nemo-event-sanitize-{}.log",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// The registrations that ran, in the order they ran.
    fn ran(log: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The projection the kernel sends, serialized.
    fn payload(call: &PluginEventSanitizeCall) -> String {
        serde_json::to_string(call).expect("a serializable projection")
    }

    /// The fields an invocation answered with, or a panic naming what it answered.
    fn answered_fields(
        outcome: &nemo_relay_plugin_protocol::PluginExecutionOutcome,
        what: &str,
    ) -> EventSanitizeFields {
        match &outcome.result {
            Ok(PluginSuccess::Invoked(response)) => serde_json::from_str(&response.output)
                .unwrap_or_else(|error| {
                    panic!("{what} answered with something that is not fields: {error}")
                }),
            other => panic!("{what} should have answered with fields, and answered {other:?}"),
        }
    }

    /// The metadata an answer carries.
    fn answered_metadata(
        fields: &EventSanitizeFields,
    ) -> serde_json::Map<String, serde_json::Value> {
        match fields.metadata.clone() {
            Some(serde_json::Value::Object(metadata)) => metadata,
            other => panic!("the answer carries metadata rather than {other:?}"),
        }
    }

    /// Assert an answer is a refusal and that it carried none of the payload.
    fn assert_refused(
        outcome: &nemo_relay_plugin_protocol::PluginExecutionOutcome,
        what: &str,
        sentinel: &confidentiality::ConfidentialitySentinel,
    ) {
        match &outcome.result {
            Err(failure) => assert!(
                !failure.message.trim().is_empty(),
                "a refusal carries its reason"
            ),
            Ok(success) => panic!("{what} should have been refused, and answered {success:?}"),
        }
        // The assertion that matters: an error is not the property, a payload that
        // cannot be published is. The whole outcome is searched, because a refusal
        // carries text.
        sentinel.assert_outcome_absent(what, outcome);
    }

    /// The control every negative case carries: this class is served at all.
    ///
    /// Without it a refusal test passes for the wrong reason — a host that refuses
    /// every invocation of a class refuses the case under test as well — and the
    /// suite would be green before the class it is about can be served. It also
    /// pins the shape a served answer has, so "refused" and "answered something
    /// else entirely" cannot be confused for each other.
    async fn assert_the_family_is_served(
        session: &FixtureSession,
        activated: &v1::ActivateOutcome,
    ) {
        let registration = session.registration_named(activated, "fixture_mark_a");
        let (call, _sentinel) =
            confidentiality::sentinel_sanitize_call(PluginEventSanitizeClass::Mark);
        let outcome = session
            .invoke_arguments(&registration, &payload(&call), EVENT_SANITIZE_BUDGET)
            .await;
        let _fields = answered_fields(&outcome, "the control case");
    }

    /// Property A, the exact registration.
    ///
    /// The normal event sanitizer mechanism is *chain*-oriented: every visible
    /// registration of a class runs in priority order, and each answer is applied to
    /// the event the next one is shown. A host serving one named registration must
    /// not fall back to that. Three mark sanitizers are registered with distinct
    /// markers, one is named, and the answer has to carry that one's marker and
    /// neither neighbour's — and the fixture's own log has to show that exactly that
    /// one ran, once, because a marker says who answered rather than who ran.
    #[tokio::test]
    async fn a_sanitize_invocation_runs_exactly_the_registration_the_call_names() {
        // Core's plugin configuration is process-global, so a test that activates
        // a real plugin takes its turn.
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        for (name, marker) in MARK_SANITIZERS {
            let log = sanitizer_log();
            let config = serde_json::json!({
                "event_sanitizers": true,
                "sanitizer_log": log.to_string_lossy(),
            });
            let Some((session, activated)) = event_sanitize_session_with(config).await else {
                eprintln!("the intercept fixture is missing; skipping the exact-registration case");
                return;
            };
            let registration = session.registration_named(&activated, name);
            let (call, _sentinel) =
                confidentiality::sentinel_sanitize_call(PluginEventSanitizeClass::Mark);
            let outcome = session
                .invoke_arguments(&registration, &payload(&call), EVENT_SANITIZE_BUDGET)
                .await;
            let fields = answered_fields(&outcome, name);
            let metadata = answered_metadata(&fields);
            assert_eq!(
                metadata.get(marker).cloned(),
                Some(serde_json::json!(true)),
                "invoking {name} should run it: {metadata:?}"
            );
            for (neighbour, neighbour_marker) in MARK_SANITIZERS {
                if neighbour == name {
                    continue;
                }
                assert!(
                    metadata.get(neighbour_marker).is_none(),
                    "invoking {name} ran {neighbour} as well, which is the family rather than \
                     the registration: {metadata:?}"
                );
            }
            assert_eq!(
                ran(&log),
                vec![name.to_string()],
                "invoking {name} should run it once and run nothing else"
            );
            let _ = std::fs::remove_file(&log);
            // The payload itself survives on this path, and that is the point of
            // the distinction: a sanitizer that ran *sanitized* the payload, so what
            // it chose to keep is publishable. The sentinel assertions belong to the
            // failure cases, where nothing may be.
        }
    }

    /// Property B, the same-family and same-shape neighbours.
    ///
    /// The scope families share the event shape with the mark family — the
    /// projection differs in one field — so each family's own registration is
    /// invoked and its answer is required to carry exactly one marker: its own.
    #[tokio::test]
    async fn a_sanitizers_neighbours_are_not_invoked_by_its_call() {
        // Core's plugin configuration is process-global, so a test that activates
        // a real plugin takes its turn.
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let log = sanitizer_log();
        let config = serde_json::json!({
            "event_sanitizers": true,
            "sanitizer_log": log.to_string_lossy(),
        });
        let Some((session, activated)) = event_sanitize_session_with(config).await else {
            eprintln!("the intercept fixture is missing; skipping the isolation case");
            return;
        };
        assert_the_family_is_served(&session, &activated).await;

        for (name, marker, class) in [
            (
                "fixture_mark_b",
                "fixture_mark_b",
                PluginEventSanitizeClass::Mark,
            ),
            (
                "fixture_scope_start_sanitize",
                "fixture_scope_start_sanitize",
                PluginEventSanitizeClass::ScopeStart,
            ),
            (
                "fixture_scope_end_sanitize",
                "fixture_scope_end_sanitize",
                PluginEventSanitizeClass::ScopeEnd,
            ),
        ] {
            let registration = session.registration_named(&activated, name);
            let (call, _sentinel) = confidentiality::sentinel_sanitize_call(class);
            let before = ran(&log);
            let outcome = session
                .invoke_arguments(&registration, &payload(&call), EVENT_SANITIZE_BUDGET)
                .await;
            let metadata = answered_metadata(&answered_fields(&outcome, name));
            assert_eq!(
                metadata.get(marker).cloned(),
                Some(serde_json::json!(true)),
                "invoking {name} should run it: {metadata:?}"
            );
            for (neighbour, neighbour_marker) in EVERY_MARKER {
                if neighbour == name {
                    continue;
                }
                assert!(
                    metadata.get(neighbour_marker).is_none(),
                    "invoking {name} ran {neighbour}, which shares the shape but not the \
                     capability: {metadata:?}"
                );
            }
            let mut expected = before;
            expected.push(name.to_string());
            assert_eq!(
                ran(&log),
                expected,
                "invoking {name} should run it once and nothing else"
            );
        }
        let _ = std::fs::remove_file(&log);
    }

    /// Property C, the wrong class.
    ///
    /// The three families share an event serialization, which makes class confusion
    /// easier rather than safer: a structurally valid call for one class delivered
    /// to a registration of another is refused, in both directions, because the class
    /// is part of the capability rather than a field inside the payload.
    #[tokio::test]
    async fn a_call_whose_class_is_not_the_registrations_class_is_refused() {
        // Core's plugin configuration is process-global, so a test that activates
        // a real plugin takes its turn.
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((session, activated)) = event_sanitize_session().await else {
            eprintln!("the intercept fixture is missing; skipping the wrong-class case");
            return;
        };
        assert_the_family_is_served(&session, &activated).await;

        for (name, class) in [
            (
                "fixture_scope_start_sanitize",
                PluginEventSanitizeClass::Mark,
            ),
            ("fixture_scope_end_sanitize", PluginEventSanitizeClass::Mark),
            ("fixture_mark_a", PluginEventSanitizeClass::ScopeStart),
            ("fixture_mark_b", PluginEventSanitizeClass::ScopeEnd),
        ] {
            let registration = session.registration_named(&activated, name);
            let (call, sentinel) = confidentiality::sentinel_sanitize_call(class);
            assert_eq!(call.class, class, "the payload says which class it is for");
            let outcome = session
                .invoke_arguments(&registration, &payload(&call), EVENT_SANITIZE_BUDGET)
                .await;
            assert_refused(
                &outcome,
                &format!("a {class:?} call naming {name}"),
                &sentinel,
            );
            if let Err(failure) = &outcome.result {
                assert!(
                    failure.code == nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
                    "a class mismatch is a refusal: {failure:?}"
                );
            }
        }
    }

    /// Property D, an explicit refusal.
    ///
    /// A sanitizer that says no withholds the payload: the answer is a refusal, and
    /// no part of what it was shown can be published from it.
    #[tokio::test]
    async fn a_refused_sanitization_is_a_refusal_rather_than_an_unsanitized_answer() {
        // Core's plugin configuration is process-global, so a test that activates
        // a real plugin takes its turn.
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((session, activated)) =
            event_sanitize_session_with(event_sanitizer_failures()).await
        else {
            eprintln!("the intercept fixture is missing; skipping the refusal case");
            return;
        };
        assert_the_family_is_served(&session, &activated).await;

        let registration = session.registration_named(&activated, "fixture_mark_refuses");
        let (call, sentinel) =
            confidentiality::sentinel_sanitize_call(PluginEventSanitizeClass::Mark);
        let outcome = session
            .invoke_arguments(&registration, &payload(&call), EVENT_SANITIZE_BUDGET)
            .await;
        assert_refused(&outcome, "a sanitizer that refused", &sentinel);
    }

    /// Property E, a plugin that throws.
    ///
    /// The same rule, reached a different way: a callback that panicked did not
    /// decide, and an answer it did not decide on is not published.
    #[tokio::test]
    async fn a_sanitizer_that_throws_is_a_failure_rather_than_an_unsanitized_answer() {
        // Core's plugin configuration is process-global, so a test that activates
        // a real plugin takes its turn.
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((session, activated)) =
            event_sanitize_session_with(event_sanitizer_failures()).await
        else {
            eprintln!("the intercept fixture is missing; skipping the panic case");
            return;
        };
        assert_the_family_is_served(&session, &activated).await;

        let registration = session.registration_named(&activated, "fixture_mark_panics");
        let (call, sentinel) =
            confidentiality::sentinel_sanitize_call(PluginEventSanitizeClass::Mark);
        let outcome = session
            .invoke_arguments(&registration, &payload(&call), EVENT_SANITIZE_BUDGET)
            .await;
        assert_refused(&outcome, "a sanitizer that threw", &sentinel);
    }

    /// Property F, a malformed call.
    ///
    /// The projection is a wire type, so a peer can send anything: an empty object,
    /// a class outside the closed set, or a projection missing the fields it must
    /// carry. Each is refused at conversion, and the sentinel inside it is not
    /// echoed.
    #[tokio::test]
    async fn a_malformed_sanitize_call_is_refused() {
        // Core's plugin configuration is process-global, so a test that activates
        // a real plugin takes its turn.
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((session, activated)) = event_sanitize_session().await else {
            eprintln!("the intercept fixture is missing; skipping the malformed case");
            return;
        };
        assert_the_family_is_served(&session, &activated).await;

        let registration = session.registration_named(&activated, "fixture_mark_a");
        let (call, sentinel) =
            confidentiality::sentinel_sanitize_call(PluginEventSanitizeClass::Mark);
        let mut with_unknown_class =
            serde_json::to_value(&call).expect("a serializable projection");
        with_unknown_class["class"] = serde_json::json!("a_class_that_is_not_in_the_set");
        // The malformed shapes carry the call's own sentinel name, so "the refusal
        // did not echo the payload" is a claim about this payload rather than about
        // an empty one.
        let with_broken_fields = serde_json::json!({
            "class": "mark",
            "name": call.name,
            "fields": "not an object",
        });
        let with_no_fields = serde_json::json!({
            "class": "mark",
            "name": call.name,
        });
        for (what, payload) in [
            ("an empty payload", "{}".to_string()),
            (
                "a class outside the closed set",
                with_unknown_class.to_string(),
            ),
            (
                "a projection whose fields are not fields",
                with_broken_fields.to_string(),
            ),
            ("a projection with no fields", with_no_fields.to_string()),
        ] {
            let outcome = session
                .invoke_arguments(&registration, &payload, EVENT_SANITIZE_BUDGET)
                .await;
            assert_refused(&outcome, what, &sentinel);
        }
    }

    /// Property G, the response budget.
    ///
    /// A valid answer that is larger than the operation was allowed to return is
    /// refused before it can be published, and the refusal is where the payload must
    /// not reappear: an oversized answer that was truncated and sent would satisfy
    /// "the invocation failed" while publishing the part that fitted.
    #[tokio::test]
    async fn an_answer_above_the_operations_budget_is_refused() {
        // Core's plugin configuration is process-global, so a test that activates
        // a real plugin takes its turn.
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((session, activated)) =
            event_sanitize_session_with(event_sanitizer_failures()).await
        else {
            eprintln!("the intercept fixture is missing; skipping the budget case");
            return;
        };
        assert_the_family_is_served(&session, &activated).await;

        let registration = session.registration_named(&activated, "fixture_mark_oversized");
        let (mut call, call_sentinel) =
            confidentiality::sentinel_sanitize_call(PluginEventSanitizeClass::Mark);
        let (fields, fields_sentinel) = confidentiality::oversized_fields(8 * 1024);
        call.fields = fields;
        let outcome = session
            .invoke_arguments(&registration, &payload(&call), 1024)
            .await;
        match &outcome.result {
            Err(failure) => assert!(
                matches!(
                    failure.code,
                    nemo_relay_plugin_protocol::PluginFailureCode::OversizedFrame { .. }
                ),
                "an oversized answer is refused as one: {failure:?}"
            ),
            other => panic!("an oversized answer is refused, and this answered {other:?}"),
        }
        // Both what the fixture added and what it was handed:
        fields_sentinel.assert_outcome_absent("an oversized sanitizer's refusal", &outcome);
        call_sentinel.assert_outcome_absent("an oversized sanitizer's refusal", &outcome);
    }

    /// Property H, the identities.
    ///
    /// The two read-only discriminators are what a sanitizer decides *with*. They are
    /// kernel-owned, so the host neither invents them nor checks them beyond carrying
    /// them into the synthetic event — and a sanitizer that branches on them is the
    /// reason they are in the projection at all. This is the same shape as the PII
    /// redaction component's decision: a metric mark by its data schema, everything
    /// else by category.
    #[tokio::test]
    async fn a_sanitizer_decides_with_the_category_and_data_schema_it_is_shown() {
        use nemo_relay::api::event::{
            DataSchema, EventCategory, METRIC_DATA_SCHEMA_NAME, METRIC_DATA_SCHEMA_VERSION,
        };

        // Core's plugin configuration is process-global, so a test that activates
        // a real plugin takes its turn.
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((session, activated)) = event_sanitize_session().await else {
            eprintln!("the intercept fixture is missing; skipping the discriminator case");
            return;
        };

        let metric = DataSchema::builder()
            .name(METRIC_DATA_SCHEMA_NAME)
            .version(METRIC_DATA_SCHEMA_VERSION)
            .build();
        for (class, name, category, schema, expected) in [
            (
                PluginEventSanitizeClass::Mark,
                "fixture_mark_route",
                EventCategory::llm(),
                None,
                "llm",
            ),
            (
                PluginEventSanitizeClass::Mark,
                "fixture_mark_route",
                EventCategory::tool(),
                None,
                "tool",
            ),
            (
                PluginEventSanitizeClass::Mark,
                "fixture_mark_route",
                EventCategory::custom(),
                None,
                "other",
            ),
            (
                PluginEventSanitizeClass::Mark,
                "fixture_mark_route",
                EventCategory::tool(),
                Some(metric.clone()),
                "metric",
            ),
            (
                PluginEventSanitizeClass::ScopeStart,
                "fixture_scope_start_route",
                EventCategory::llm(),
                None,
                "llm",
            ),
            (
                PluginEventSanitizeClass::ScopeStart,
                "fixture_scope_start_route",
                EventCategory::tool(),
                Some(metric),
                "metric",
            ),
        ] {
            let registration = session.registration_named(&activated, name);
            let (mut call, _sentinel) = confidentiality::sentinel_sanitize_call(class);
            call.category = Some(category.clone());
            call.data_schema = schema.clone();
            let outcome = session
                .invoke_arguments(&registration, &payload(&call), EVENT_SANITIZE_BUDGET)
                .await;
            let metadata = answered_metadata(&answered_fields(&outcome, name));
            assert_eq!(
                metadata.get("fixture_route").cloned(),
                Some(serde_json::json!(expected)),
                "a {class:?} sanitizer shown category {category:?} and schema {schema:?} took the \
                 {expected} path: {metadata:?}"
            );
            // And the discriminators themselves are the kernel's: they are not in the
            // answer, because the answer is the mutable fields.
            assert!(
                !metadata.contains_key("category") && !metadata.contains_key("data_schema"),
                "an answer carries fields, not the values it decided with: {metadata:?}"
            );
        }
    }

    /// Property H, the identities.
    ///
    /// The registration identity and the operation identity belong to the kernel, so
    /// the host is asked to run *that* registration under *that* operation. A call
    /// naming a registration this plugin does not have, a session this host did not
    /// establish, or a runtime this host is not bound to is refused, and a refusal is
    /// not an answer: nothing the caller sent comes back through it.
    ///
    /// What is pinned here is that the host takes none of the three from the caller's
    /// word. The fourth — that an answer naming another *operation* is refused — is
    /// the transport's, and the client that pairs a request with its answer is where
    /// it lives, so the session suite is where it is pinned.
    #[tokio::test]
    async fn a_call_naming_another_registration_session_or_runtime_is_refused() {
        // Core's plugin configuration is process-global, so a test that activates
        // a real plugin takes its turn.
        let _guard = PLUGIN_ACTIVATION_LOCK.lock().await;
        let Some((session, activated)) = event_sanitize_session().await else {
            eprintln!("the intercept fixture is missing; skipping the identity case");
            return;
        };
        assert_the_family_is_served(&session, &activated).await;

        let registration = session.registration_named(&activated, "fixture_mark_a");
        let (call, sentinel) =
            confidentiality::sentinel_sanitize_call(PluginEventSanitizeClass::Mark);
        let arguments = payload(&call);

        // A registration this plugin does not have.
        let unknown = format!("{registration}_that_does_not_exist");
        let outcome = session
            .invoke_arguments(&unknown, &arguments, EVENT_SANITIZE_BUDGET)
            .await;
        assert_refused(&outcome, "a call naming another registration", &sentinel);

        // A session this host did not establish.
        let answer = session
            .service
            .invoke(capable(v1::InvokeRequest {
                session_id: "a-session-this-host-did-not-establish".into(),
                context: Some(context_with_budget(EVENT_SANITIZE_BUDGET)),
                handle: Some(nemo_relay_plugin_proto::convert::handle_to_wire(
                    &session.handle,
                )),
                registration_id: registration.clone(),
                arguments: arguments.clone(),
            }))
            .await
            .expect("a served invocation")
            .into_inner();
        let outcome = nemo_relay_plugin_proto::convert::execution_outcome_from_wire(&answer)
            .expect("a converted invocation");
        assert_refused(&outcome, "a call naming another session", &sentinel);

        // An operation bound to another runtime, which is a message from another
        // session wearing this one's identity.
        let mut elsewhere = context_with_budget(EVENT_SANITIZE_BUDGET);
        elsewhere.runtime_binding_digest = "another-runtime".into();
        let answer = session
            .service
            .invoke(capable(v1::InvokeRequest {
                session_id: session.session_id.clone(),
                context: Some(elsewhere),
                handle: Some(nemo_relay_plugin_proto::convert::handle_to_wire(
                    &session.handle,
                )),
                registration_id: registration,
                arguments,
            }))
            .await
            .expect("a served invocation")
            .into_inner();
        let outcome = nemo_relay_plugin_proto::convert::execution_outcome_from_wire(&answer)
            .expect("a converted invocation");
        assert_refused(&outcome, "a call bound to another runtime", &sentinel);
    }
}
