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

/// The sink a plugin's callback raises marks into.
struct ForwardingSink {
    sender: MarkForwardingSender,
    session_id: String,
    /// The operation this host is running, which every mark belongs to.
    operation_request_id: String,
    /// A distinct identity per mark, minted here because a callback can raise
    /// several marks within one operation.
    host_calls: std::sync::atomic::AtomicU64,
}

impl nemo_relay::plugin::execution::MarkForwarder for ForwardingSink {
    fn forward(
        &self,
        mark: &nemo_relay::plugin::execution::ForwardedMark,
    ) -> nemo_relay::error::Result<()> {
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
                let sink = std::sync::Arc::new(ForwardingSink {
                    sender: sender.clone(),
                    session_id: wire.session_id.clone(),
                    operation_request_id: operation_request_id.clone(),
                    host_calls: std::sync::atomic::AtomicU64::new(0),
                });
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
        // No stream is produced, and the stream says so: a stream that simply
        // stopped would be a truncation the kernel cannot distinguish from a
        // host that died mid-answer.
        //
        // Like `cancel_operation`, this answer does not depend on the caller, so
        // there is nothing here a capability would be protecting.
        let refusal = v1::StreamChunk {
            // Named when the caller named one, for the same reason a unary
            // answer names its invocation: a terminal frame that belongs to no
            // operation is not a terminal frame.
            operation_request_id: request
                .into_inner()
                .context
                .map(|context| context.operation_request_id)
                .unwrap_or_default(),
            chunk: Some(v1::stream_chunk::Chunk::Failure(v1::PluginFailure {
                code: nemo_relay_plugin_proto::v1::FailureCode::Rejected as i32,
                message: "this host does not serve streaming invocations".to_string(),
                ..Default::default()
            })),
            dispatch_state: nemo_relay_plugin_protocol::DispatchState::NotDispatched as i32,
            outcome_certainty: nemo_relay_plugin_protocol::OutcomeCertainty::ConfirmedFailure
                as i32,
        };
        Ok(Response::new(Box::pin(tokio_stream::iter(vec![Ok(
            refusal,
        )]))))
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
        // kernel cannot serve are visible as what they are. Read from the wire
        // rather than through the conversion, because this fixture registers one
        // injector name twice and the conversion refuses a duplicate registration
        // — a real finding of its own, and one that means the sixteen-surface
        // fixture cannot be activated *over the boundary* until it is fixed. The
        // report is what this test is about, and it is visible before conversion.
        let discovery = activate(true)
            .await
            .expect("a served activation")
            .into_inner();
        let Some(v1::activate_outcome::Result::Activated(response)) = discovery.result else {
            panic!("a discovery session reports rather than refuses: {discovery:?}");
        };
        let serveable: Vec<i32> = crate::ProcessPluginBackend::supported_registration_operations()
            .iter()
            .map(|operation| {
                nemo_relay_plugin_proto::convert::registration_operation_to_wire(*operation)
            })
            .collect();
        let reported: Vec<i32> = response
            .descriptors
            .iter()
            .flat_map(|descriptor| descriptor.registrations.iter())
            .map(|registration| registration.operation)
            .collect();
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
}
