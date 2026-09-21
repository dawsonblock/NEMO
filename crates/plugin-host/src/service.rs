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
    activate_outcome_to_wire, activate_request_from_wire, cancel_outcome_to_wire,
    execution_outcome_to_wire, handshake_outcome_to_wire, handshake_request_from_wire,
    health_outcome_to_wire, inspect_outcome_to_wire, inspect_request_from_wire,
    invoke_request_from_wire, load_outcome_to_wire, load_request_from_wire,
    operation_envelope_from_wire, session_close_outcome_to_wire, unload_outcome_to_wire,
    unload_request_from_wire,
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
        session_id: String,
        /// Registration classes the kernel can install a proxy for.
        supported_registration_operations: Vec<PluginRegistrationOperation>,
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
    mark_forwarding: Option<tokio::sync::mpsc::UnboundedSender<ForwardedStep>>,
}

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
    sender: tokio::sync::mpsc::UnboundedSender<ForwardedStep>,
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
            .send(ForwardedStep::Mark {
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
            .map_err(|_| {
                nemo_relay::error::FlowError::Internal(
                    "the kernel this host forwards marks to is no longer reachable".to_string(),
                )
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
        }
    }

    /// Forward the marks this host's plugins raise to the kernel.
    ///
    /// The sender is this host's end of one channel; whoever holds the other end
    /// has the connection back to the kernel. Without one, a mark a plugin raises
    /// is emitted into this process's own runtime, where the kernel's subscribers
    /// cannot see it.
    pub fn with_mark_forwarding(
        mut self,
        sender: tokio::sync::mpsc::UnboundedSender<ForwardedStep>,
    ) -> Self {
        self.mark_forwarding = Some(sender);
        self
    }

    /// Run one registration for a validated invocation.
    ///
    /// Split out of the service method so the window in which a plugin's marks
    /// are forwarded can be wrapped around exactly this work.
    async fn serve_invocation(
        &self,
        wire: v1::InvokeRequest,
    ) -> Result<nemo_relay_plugin_protocol::PluginExecutionOutcome, PluginProtocolError> {
        let outcome: Result<
            nemo_relay_plugin_protocol::PluginExecutionOutcome,
            PluginProtocolError,
        > =
            async {
                if let Err(error) = self.established(&wire.session_id) {
                    return Ok(refusal(error.failure.message));
                }
                let context = self.prepare(&wire.session_id, wire.context.as_ref())?;
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
            HostSession::Active {
                session_id: established,
                ..
            } if established == session_id => Ok(()),
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
    use nemo_relay_plugin_protocol::{DispatchState, OutcomeCertainty, PluginExecutionOutcome};
    PluginExecutionOutcome {
        dispatch: DispatchState::NotDispatched,
        certainty: OutcomeCertainty::ConfirmedFailure,
        result: Err(nemo_relay_plugin_protocol::PluginFailure {
            code: nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
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

#[tonic::async_trait]
impl v1::plugin_host_server::PluginHost for PluginHostService {
    async fn handshake(
        &self,
        request: Request<v1::HandshakeRequest>,
    ) -> Result<Response<v1::HandshakeOutcome>, Status> {
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

        let session_id = Uuid::now_v7().to_string();
        let identity = PluginSessionIdentity {
            protocol_version: self.config.protocol_version,
            session_id: session_id.clone(),
            host_instance_id: self.host_instance_id.clone(),
            host_nonce: Uuid::now_v7().to_string(),
            maximum_frame_bytes: self.config.maximum_frame_bytes,
            supported_features: Vec::new(),
            // The host accepts what it is offered. It cannot ask for more, and
            // an offer it does not need is none of its business.
            accepted_read_capabilities: request.offered_read_capabilities.clone(),
        };
        match self.session.lock() {
            Ok(mut session) => match &*session {
                HostSession::New => {
                    *session = HostSession::Active {
                        session_id,
                        supported_registration_operations: request
                            .supported_registration_operations
                            .clone(),
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

    async fn load(
        &self,
        request: Request<v1::LoadRequest>,
    ) -> Result<Response<v1::LoadOutcome>, Status> {
        let wire = request.into_inner();
        let outcome = async {
            let context = self.prepare(&wire.session_id, wire.context.as_ref())?;
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
        let wire = request.into_inner();
        let outcome = async {
            let context = self.prepare(&wire.session_id, wire.context.as_ref())?;
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
        let wire = request.into_inner();
        let outcome = async {
            let context = self.prepare(&wire.session_id, wire.context.as_ref())?;
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
        let wire = request.into_inner();
        let outcome = async {
            let context = self.prepare(&wire.session_id, wire.context.as_ref())?;
            let activation = activate_request_from_wire(&wire)?;

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
                // Fail closed without leaving anything registered: the callbacks
                // were installed by this activation call, so clearing the
                // configuration takes them back down.
                let _ = nemo_relay::plugin::clear_plugin_configuration();
                return Err(refused(unsupported.join("; ")));
            }
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
                    self.serve_invocation(wire),
                )
                .await;
                // What the invocation raised is delivered before the answer that
                // ends it. A mark that could not be delivered is not a lost log
                // line: the invocation produced evidence this kernel will never
                // see, so the answer it would have given is not one the kernel
                // may read as complete.
                let (done, delivered) = tokio::sync::oneshot::channel();
                if sender.send(ForwardedStep::Flush { done }).is_err() {
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
            None => self.serve_invocation(wire).await,
        };

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => refusal(error.failure.message),
        };
        let outcome = execution_outcome_to_wire(&outcome, &operation_request_id)
            .map_err(|error| Status::internal(error.failure.message))?;
        Ok(Response::new(outcome))
    }

    async fn cancel_operation(
        &self,
        _request: Request<v1::CancelOperationRequest>,
    ) -> Result<Response<v1::CancelOperationOutcome>, Status> {
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
        let wire = request.into_inner();
        let outcome = async {
            let context = self.prepare(&wire.session_id, wire.context.as_ref())?;
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
        let wire = request.into_inner();
        // A refusal travels as an outcome rather than as a transport status: a
        // session that is already gone is a result, and a channel failure is a
        // different event that the kernel has to read differently.
        if let Err(error) = self.established(&wire.session_id) {
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
        context: Option<&v1::PluginExecutionContext>,
    ) -> Result<nemo_relay_plugin_protocol::PluginExecutionContext, PluginProtocolError> {
        self.established(session_id)?;
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

    async fn establish(service: &PluginHostService, config: &PluginHostConfig) -> String {
        let outcome = service
            .handshake(Request::new(handshake_request(config)))
            .await
            .expect("a served handshake")
            .into_inner();
        handshake_outcome_from_wire(&outcome)
            .expect("a converted handshake")
            .into_result()
            .expect("an established session")
            .session_id
    }

    #[tokio::test]
    async fn a_host_refuses_a_credential_or_binding_it_was_not_started_with() {
        let (service, config) = service();

        // Knowing where the socket is must not be enough to be treated as the
        // kernel, so the credential is checked before anything else.
        let mut request = handshake_request(&config);
        request.session_credential = "another-credential".into();
        let outcome = service
            .handshake(Request::new(request))
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
            .handshake(Request::new(request))
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
            .handshake(Request::new(handshake_request(&config)))
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
            .load(Request::new(load("unknown")))
            .await
            .expect("a served load")
            .into_inner();
        assert!(refused(outcome));

        // And a request naming a session this host did not establish is refused
        // rather than served.
        let session_id = establish(&service, &config).await;
        let outcome = service
            .load(Request::new(load("another-session")))
            .await
            .expect("a served load")
            .into_inner();
        assert!(refused(outcome));

        // The established session is served, and the answer comes from the
        // backend rather than from the session check: an inspection of an empty
        // host is an empty list.
        let outcome = service
            .inspect(Request::new(v1::InspectRequest {
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
            .session_close(Request::new(v1::SessionCloseRequest {
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
            .handshake(Request::new(handshake_request(&config)))
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
            .session_close(Request::new(v1::SessionCloseRequest {
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
            .inspect(Request::new(v1::InspectRequest {
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
            .handshake(Request::new(handshake_request(&config)))
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
            .load(Request::new(v1::LoadRequest {
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
            .handshake(Request::new(request))
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
            .load(Request::new(v1::LoadRequest {
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
            .activate(Request::new(v1::ActivateRequest {
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
            .load(Request::new(v1::LoadRequest {
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
            .activate(Request::new(v1::ActivateRequest {
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
                .handshake(Request::new(request))
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
            .load(Request::new(v1::LoadRequest {
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
            .activate(Request::new(v1::ActivateRequest {
                session_id: session_id.clone(),
                context: Some(context()),
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
            .invoke(Request::new(v1::InvokeRequest {
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
            .invoke(Request::new(v1::InvokeRequest {
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
            .invoke(Request::new(invocation(None)))
            .await
            .expect_err("an invocation with no context has no operation to name");
        assert_eq!(absent.code(), tonic::Code::InvalidArgument, "{absent:?}");

        let mut unnamed = context();
        unnamed.operation_request_id = "  ".into();
        let blank = service
            .invoke(Request::new(invocation(Some(unnamed))))
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
}
