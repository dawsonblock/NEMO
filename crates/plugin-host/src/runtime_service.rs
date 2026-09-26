// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The kernel's side of the boundary: what a running plugin's host calls back.
//!
//! The forward direction is the kernel asking the host for lifecycle operations.
//! This is the other one: a native plugin runs in another process, and its host
//! functions — emitting a mark, reading the scope stack, resolving a codec — have
//! to reach *this* runtime, because a mark a plugin emits belongs to the kernel's
//! event stream and not to the child's copy of it.
//!
//! The service is per session, on a socket inside the directory the supervisor
//! already owns. The kernel serves one session per listener, so the session is a
//! property of the listener rather than a value a caller chooses, and the
//! credential the child was given out of band is what makes a caller the host of
//! that session. Knowing the path is not enough here either.
//!
//! Refusals are transport statuses rather than structured outcomes: the answer to
//! an emitted mark is an empty acknowledgement, so a refused operation has no
//! message to carry the refusal, and inventing one would be a second vocabulary
//! for facts the status already names.

use std::path::Path;
use std::sync::Arc;

use crate::operation_scopes::OperationScopes;
use futures_util::FutureExt;
use futures_util::StreamExt;
use nemo_relay::api::scope::EmitMarkEventParams;
use nemo_relay_plugin_proto::v1;
use nemo_relay_plugin_proto::v1::relay_runtime_client::RelayRuntimeClient;
use nemo_relay_plugin_proto::v1::relay_runtime_server::RelayRuntime;
use nemo_relay_plugin_protocol::{CodecRef, PluginHostCallOutcome, PluginMarkEmit};
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

/// How many answers may be queued for one session channel.
///
/// A session channel answers what it is asked, so the queue is between the
/// driver that produced an answer and the transport that sends it. Bounded
/// because an unbounded one would let a host that stopped reading grow this
/// process, which is the same rule the mark queue follows.
const SESSION_CHANNEL_CAPACITY: usize = 64;

/// Metadata header the host presents on every call back into the kernel.
///
/// A header rather than a message field: the credential belongs to the channel
/// rather than to the payload, and a field would travel with whatever a handler
/// later decided to log as data.
pub const SESSION_CREDENTIAL_HEADER: &str = "x-nemo-relay-plugin-credential";

/// Dial the socket a kernel serves for this session.
///
/// This is what a host uses to call back: the endpoint is the path it was given
/// in its environment, and every call it makes has to carry the credential it
/// was given with it. Both are needed — the path says where, the credential says
/// who — and neither alone is enough to be served.
pub async fn connect_to_kernel(
    endpoint: &Path,
    maximum_frame_bytes: u32,
) -> Result<RelayRuntimeClient<Channel>, String> {
    let path = std::sync::Arc::new(endpoint.to_path_buf());
    let dialed = Endpoint::try_from("http://[::]:50051").map_err(|error| error.to_string())?;
    let channel = dialed
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                tokio::net::UnixStream::connect(&*path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .map_err(|error| error.to_string())?;
    Ok(RelayRuntimeClient::new(channel)
        .max_decoding_message_size(maximum_frame_bytes as usize)
        .max_encoding_message_size(maximum_frame_bytes as usize))
}

/// The kernel this host calls back into.
///
/// The calls a plugin makes that are *not* answers to anything: a mark it
/// raised, and — the reason this type exists — the continuation of a call it is
/// wrapping. An execution intercept decides when the rest of the chain runs, and
/// the rest of the chain lives in the kernel, so the plugin's `next` is a call
/// this side makes rather than a function it holds.
///
/// A host started without one can still serve the classes that answer a call,
/// and cannot serve the classes that wrap one: there would be no chain to
/// resume, and a plugin that called `next` would be waiting for a result nobody
/// could produce.
#[derive(Clone)]
pub struct KernelCallbacks {
    client: RelayRuntimeClient<Channel>,
    credential: MetadataValue<Ascii>,
    /// How to reach the kernel again, when a caller needs a connection of its own.
    ///
    /// A client's connection tasks belong to the runtime that opened them, so a *second*
    /// caller — the bridge a plugin's synchronous codec call goes through, which runs on a
    /// thread of its own — cannot block on this client: the answer would have to arrive on a
    /// runtime no thread of the caller's owns. Remembering the endpoint is what lets that
    /// caller open its own connection on the runtime that will wait for it.
    reconnect: Option<(std::path::PathBuf, u32)>,
}

impl std::fmt::Debug for KernelCallbacks {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The credential is not printed, and neither is the channel: what a
        // reader needs is whether this host has a kernel, not how to reach it.
        formatter
            .debug_struct("KernelCallbacks")
            .finish_non_exhaustive()
    }
}

impl KernelCallbacks {
    /// The calls this host may make, with the credential they must carry.
    ///
    /// # Errors
    /// Returns an error when the credential cannot be a metadata value, which
    /// means it could not have been the credential this session was given.
    pub fn new(client: RelayRuntimeClient<Channel>, credential: &str) -> Result<Self, String> {
        let credential = credential
            .parse()
            .map_err(|error| format!("the kernel credential is not a header value: {error}"))?;
        Ok(Self {
            client,
            credential,
            reconnect: None,
        })
    }

    /// Remember how to reach the kernel, so a caller on another runtime can connect again.
    pub fn with_reconnect(
        mut self,
        endpoint: std::path::PathBuf,
        maximum_frame_bytes: u32,
    ) -> Self {
        self.reconnect = Some((endpoint, maximum_frame_bytes));
        self
    }

    /// A connection to the same kernel, opened on the runtime that calls this.
    ///
    /// A caller that has to wait for the answer on a runtime of its own needs this rather
    /// than the client it was handed: the handed client's tasks live where it was built.
    /// A host that never remembered an endpoint serves the caller with the client it has,
    /// which is right for a caller that *is* on that runtime.
    ///
    /// # Errors
    /// Returns the transport's words when the kernel cannot be reached again.
    pub async fn connect_again(&self) -> Result<Self, String> {
        let Some((endpoint, maximum_frame_bytes)) = self.reconnect.as_ref() else {
            return Ok(Self {
                client: self.client.clone(),
                credential: self.credential.clone(),
                reconnect: None,
            });
        };
        let client = connect_to_kernel(endpoint, *maximum_frame_bytes).await?;
        Ok(Self {
            client,
            credential: self.credential.clone(),
            reconnect: self.reconnect.clone(),
        })
    }

    /// The client these calls travel on.
    pub(crate) fn client(&self) -> &RelayRuntimeClient<Channel> {
        &self.client
    }

    /// The credential every call has to carry.
    pub(crate) fn credential(&self) -> &MetadataValue<Ascii> {
        &self.credential
    }

    /// Ask the kernel to run the rest of a chain this host is holding a position in.
    ///
    /// # Errors
    /// Returns the kernel's own words when it refuses — a chain position that is
    /// no longer held, a session that is not this one, a credential that is not
    /// this session's — and the transport's when the kernel cannot be reached.
    pub async fn run_continuation(
        &self,
        session_id: &str,
        operation_request_id: &str,
        host_call_id: &str,
        invocation_json: &str,
    ) -> Result<PluginHostCallOutcome, String> {
        let wire = nemo_relay_plugin_proto::v1::ContinuationRequest {
            session_id: session_id.to_owned(),
            operation_request_id: operation_request_id.to_owned(),
            host_call_id: host_call_id.to_owned(),
            invocation_json: invocation_json.to_owned(),
        };
        let mut request = Request::new(wire);
        request
            .metadata_mut()
            .insert(SESSION_CREDENTIAL_HEADER, self.credential.clone());
        let outcome = self
            .client
            .clone()
            .r#continue(request)
            .await
            .map_err(|status| status.to_string())?
            .into_inner();
        nemo_relay_plugin_proto::convert::continuation_outcome_from_wire(&outcome)
            .map_err(|error| error.failure.message)
    }

    /// Ask the kernel to run one codec operation for a capability it issued.
    ///
    /// The host does not hold a codec and never will: what it holds is the reference the
    /// kernel issued for the sanitize invocation it is serving, and the work happens on
    /// the side that holds the object. A refusal is the kernel's own words — the reference
    /// is not for this call, the direction is wrong, the codec is not the one it issued —
    /// and it reaches the plugin as the codec call's failure rather than as a transport
    /// error, because that is what it is.
    ///
    /// # Errors
    /// Returns the kernel's refusal, or the transport's when the kernel cannot be reached.
    pub async fn resolve_codec(
        &self,
        session_id: &str,
        operation_request_id: &str,
        operation: nemo_relay_plugin_proto::v1::CodecOperation,
        payload_json: &str,
        codec_reference: &str,
    ) -> Result<String, String> {
        let wire = nemo_relay_plugin_proto::v1::ResolveCodecRequest {
            session_id: session_id.to_owned(),
            operation_request_id: operation_request_id.to_owned(),
            host_call_id: nemo_relay_plugin_protocol::Uuid::now_v7().to_string(),
            operation: operation as i32,
            payload_json: payload_json.to_owned(),
            codec_reference: codec_reference.to_owned(),
        };
        let mut request = Request::new(wire);
        request
            .metadata_mut()
            .insert(SESSION_CREDENTIAL_HEADER, self.credential.clone());
        let answer = self
            .client
            .clone()
            .resolve_codec(request)
            .await
            .map_err(|status| status.to_string())?
            .into_inner();
        match answer.result {
            Some(nemo_relay_plugin_proto::v1::resolve_codec_response::Result::Output(output)) => {
                Ok(output)
            }
            Some(nemo_relay_plugin_proto::v1::resolve_codec_response::Result::Failure(failure)) => {
                Err(failure.message)
            }
            // Neither arm is not an answer: a kernel that says nothing has not said the
            // codec work was done, and reading it as one would be this side's guess.
            None => Err(
                "the kernel answered a codec call with neither a result nor a refusal".to_string(),
            ),
        }
    }
}

/// Configuration for the kernel's side of one plugin session.
#[derive(Debug, Clone)]
pub struct RelayRuntimeConfig {
    /// The session this listener serves.
    pub session_id: String,
    /// The credential the child was given for this session.
    pub session_credential: String,
    /// Protocol version this kernel speaks.
    pub protocol_version: u16,
    /// Digest of the runtime identity this session is bound to.
    pub runtime_binding_digest: String,
    /// The scope stack each in-flight operation belongs to.
    pub operation_scopes: Arc<OperationScopes>,
    /// The continuations this kernel is holding for the plugins it is running.
    ///
    /// A plugin whose intercept wraps a call asks the kernel to run the rest of
    /// the chain; this is where the kernel keeps the position it is being asked
    /// to resume.
    pub continuations: Arc<crate::continuations::Continuations>,
    /// The codec capabilities this kernel has issued and not yet taken back.
    ///
    /// A plugin's sanitizer is given a reference for the call's codec; the codec object
    /// stays here, and this is the record that decides whether a reference means
    /// anything. It is the same record the proxy issues into, because a capability issued
    /// somewhere else would be a capability this side could not check.
    pub codecs: Arc<crate::codec_capability::CodecCapabilities>,
}

/// Serves the calls a plugin's host makes back into the kernel.
pub struct RelayRuntimeService {
    config: RelayRuntimeConfig,
}

impl RelayRuntimeService {
    /// Serve one session's calls.
    pub fn new(config: RelayRuntimeConfig) -> Self {
        Self { config }
    }

    /// Require the credential this session was started with.
    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let presented = request
            .metadata()
            .get(SESSION_CREDENTIAL_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if presented != self.config.session_credential {
            return Err(Status::permission_denied(
                "a call back into the kernel must carry this session's credential",
            ));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl RelayRuntime for RelayRuntimeService {
    async fn emit_mark(
        &self,
        request: Request<v1::EmitMarkRequest>,
    ) -> Result<Response<v1::EmitMarkResponse>, Status> {
        self.authenticate(&request)?;
        let wire = request.into_inner();
        // One session per listener, so a request naming another session is
        // addressed to the wrong kernel rather than carrying a payload this one
        // should judge.
        if wire.session_id != self.config.session_id {
            return Err(Status::permission_denied(
                "this kernel serves one session, and the request names another",
            ));
        }
        let mark = nemo_relay_plugin_proto::convert::mark_request_from_wire(&wire)
            .map_err(|error| Status::invalid_argument(error.failure.message))?;
        // A scope the host process names is a scope identity from *that*
        // process, and this kernel cannot resolve it to one of its own. Refusing
        // is the only honest answer: attaching the mark to a guessed scope would
        // be a different event than the one that was asked for, and dropping the
        // name would attach it to the invocation's scope without saying so.
        if mark.parent.is_some() {
            return Err(Status::failed_precondition(
                "a mark naming a scope cannot be attributed: a scope identity from the host \
                 process means nothing to this kernel until scope operations cross the boundary",
            ));
        }
        // The invocation's own scope, not the server task's: the mark belongs to
        // the call that raised it, and a mark with no invocation in flight is
        // refused rather than attached to whatever this task happens to be in.
        let stack = self
            .config
            .operation_scopes
            .stack_for(&mark.operation_request_id)
            .ok_or_else(|| {
                Status::failed_precondition(
                    "no invocation of that operation is in flight in this kernel, so the mark \
                     cannot be attributed to one",
                )
            })?;
        nemo_relay::api::runtime::with_scope_stack(stack, || emit(&mark))
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        Ok(Response::new(v1::EmitMarkResponse {}))
    }

    // The rest of the reverse direction is refused by name rather than answered
    // as an empty success: a plugin's host that asked the kernel to read its
    // scope stack, resolve a codec, or continue a chain would otherwise be told
    // it had been served. Each of these arrives with the piece that serves it —
    // the scope and codec reads with the read capabilities, the continuation and
    // the duplex channel with the session driver.

    async fn scope_stack(
        &self,
        _request: Request<v1::ScopeStackRequest>,
    ) -> Result<Response<v1::ScopeStackResponse>, Status> {
        Err(Status::unimplemented(
            "this kernel does not serve scope-stack reads yet",
        ))
    }

    async fn resolve_codec(
        &self,
        request: Request<v1::ResolveCodecRequest>,
    ) -> Result<Response<v1::ResolveCodecResponse>, Status> {
        self.authenticate(&request)?;
        let wire = request.into_inner();
        if wire.session_id != self.config.session_id {
            return Err(Status::permission_denied(
                "this kernel serves one session, and the codec call names another",
            ));
        }
        // The operation is this side's vocabulary: an unknown one is refused rather than
        // guessed, because the direction it implies is what a capability is checked
        // against.
        let operation = crate::codec_context::CodecOperation::from_wire(wire.operation)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        // Shape first, then the record. A reference that is not shaped like one was never
        // issued by this side and is refused for what it is; a well-formed one is refused
        // only if the record does not hold it.
        let reference = CodecRef::from_opaque(wire.codec_reference)
            .map_err(|error| Status::invalid_argument(error.failure.message))?;
        let payload: nemo_relay::json::Json =
            serde_json::from_str(&wire.payload_json).map_err(|error| {
                Status::invalid_argument(format!("a codec operation payload must be JSON: {error}"))
            })?;
        let identity = crate::codec_context::identity_from_payload(&payload)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let direction = if operation.is_request() {
            nemo_relay_plugin_protocol::CodecDirection::Request
        } else {
            nemo_relay_plugin_protocol::CodecDirection::Response
        };
        // Every refusal here is one fact: this kernel did not issue *this* capability for
        // *this* call. The refusal's own name says which check found that out, and the
        // caller is told no.
        let handle = self
            .config
            .codecs
            .resolve(&reference, &wire.operation_request_id, direction, &identity)
            .map_err(|refusal| {
                Status::permission_denied(format!(
                    "this kernel did not issue that codec capability for this call ({})",
                    refusal.as_str()
                ))
            })?;
        // The work happens here, against the codec object this side holds: the plugin
        // asked for a decode, not for the codec. A codec that cannot read what it was
        // given is a failure the plugin sees as one, not a transport error.
        match crate::codec_context::run_codec_operation(operation, &handle, &payload) {
            Ok(output) => Ok(Response::new(v1::ResolveCodecResponse {
                result: Some(v1::resolve_codec_response::Result::Output(output)),
            })),
            Err(error) => Ok(Response::new(v1::ResolveCodecResponse {
                result: Some(v1::resolve_codec_response::Result::Failure(
                    nemo_relay_plugin_proto::convert::failure_to_wire(
                        &nemo_relay_plugin_protocol::PluginFailure {
                            code: nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
                            message: error.to_string(),
                        },
                    ),
                )),
            })),
        }
    }

    async fn r#continue(
        &self,
        request: Request<v1::ContinuationRequest>,
    ) -> Result<Response<v1::ContinuationOutcome>, Status> {
        self.authenticate(&request)?;
        let wire = request.into_inner();
        if wire.session_id != self.config.session_id {
            return Err(Status::permission_denied(
                "this kernel serves one session, and the continuation names another",
            ));
        }
        // Validated before the lookup, so a malformed request is refused for what
        // it is rather than reported as "no such continuation".
        let continuation = nemo_relay_plugin_proto::convert::continuation_request_from_wire(&wire)
            .map_err(|error| Status::invalid_argument(error.failure.message))?;

        // The position the plugin is asking to resume. Absent means the kernel is
        // not running an intercept that asked for one: either the operation is
        // not in flight, or the intercept that owned the continuation has already
        // settled — and a chain position whose call has returned is not one the
        // kernel may resume.
        let parked = self
            .config
            .continuations
            .parked(&continuation.operation_request_id)
            .ok_or_else(|| {
                Status::failed_precondition(
                    "this kernel is not holding a continuation for that operation: nothing it is \
                     running asked for one",
                )
            })?;

        let args: nemo_relay::json::Json = serde_json::from_str(&continuation.invocation_json)
            .map_err(|error| {
                Status::invalid_argument(format!("a continuation must carry JSON: {error}"))
            })?;

        // Run it under the context captured where the chain was: the downstream
        // call belongs to the operation's scope and budget, not to whichever task
        // this request happened to arrive on. Each call gets its own snapshot of
        // the scope stack, because the ABI lets an intercept run its continuation
        // more than once and two branches must not share one stack.
        let context = parked.context.isolated().map_err(|error| {
            Status::internal(format!(
                "the continuation's context could not be isolated: {error}"
            ))
        })?;
        // The call's own budget, narrowed to what is left of it: the resumed
        // chain belongs to the call it is part of, so a registration down there
        // sees the managed budget the call had — and a plugin that held its
        // continuation cannot enlarge it.
        let now_unix_ms = nemo_relay::api::runtime::budget_now_unix_ms();
        // What the plugin settled on, in the shape its family takes: a tool call
        // resumes with argument JSON, a provider call with a request. The entry
        // knows which, so the wire does not have to say.
        let resume = |context: nemo_relay::api::runtime::MiddlewareContinuationContext| {
            let budget = parked
                .budget
                .map(|budget| budget.narrowed_to(u64::MAX, now_unix_ms));
            let chain = parked.chain.clone();
            let args = args.clone();
            async move {
                // One shape out of the entry: the answer as JSON, or why there is
                // none. Which family produced it is the entry's business, not the
                // caller's.
                let running = async move {
                    // No `?` in here: this block is what the answer comes out
                    // of, so each arm produces the answer or the reason there is
                    // none rather than returning early.
                    let answered = match chain {
                        crate::continuations::ParkedChain::Tool(next) => {
                            match context.invoke(move || next(args)).await {
                                Ok(result) => serde_json::to_value(result).map_err(|error| {
                                    nemo_relay::error::FlowError::Internal(format!(
                                        "the tool result could not be serialized: {error}"
                                    ))
                                }),
                                Err(error) => Err(error),
                            }
                        }
                        crate::continuations::ParkedChain::Llm(next) => {
                            match serde_json::from_value::<nemo_relay::api::llm::LlmRequest>(args) {
                                Ok(request) => context.invoke(move || next(request)).await,
                                Err(error) => {
                                    Err(nemo_relay::error::FlowError::InvalidArgument(format!(
                                        "a provider continuation must carry a request: {error}"
                                    )))
                                }
                            }
                        }
                        // A stream is resumed by pulling it, one message at a
                        // time, on the session channel: one answer cannot be the
                        // whole of it, so a unary resume addressed here is
                        // refused with that reason rather than answered with the
                        // first chunk.
                        crate::continuations::ParkedChain::LlmStream(_) => {
                            Err(nemo_relay::error::FlowError::InvalidArgument(
                                "this position is a stream: it is resumed by pulling it rather \
                                 than by one answer"
                                    .to_string(),
                            ))
                        }
                    };
                    answered.map_err(|error| error.to_string())
                };
                match budget {
                    Some(budget) => {
                        nemo_relay::api::runtime::with_execution_budget(budget, running).await
                    }
                    None => running.await,
                }
            }
        };
        // A panic anywhere in the resumed chain is this request's failure rather
        // than a task that vanishes: the host is waiting for an answer, and none
        // would ever come.
        let answer = match std::panic::AssertUnwindSafe(resume(context))
            .catch_unwind()
            .await
        {
            Ok(Ok(result)) => Ok(serde_json::to_string(&result).map_err(|error| {
                Status::internal(format!(
                    "the continuation's result could not be serialized: {error}"
                ))
            })?),
            Ok(Err(message)) => Err(nemo_relay_plugin_protocol::PluginFailure {
                code: nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
                message,
            }),
            Err(payload) => {
                let message = payload
                    .downcast_ref::<&str>()
                    .map(|text| (*text).to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "a continuation panicked".to_string());
                Err(nemo_relay_plugin_protocol::PluginFailure {
                    code: nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
                    message: format!("the wrapped call panicked: {message}"),
                })
            }
        };
        Ok(Response::new(
            nemo_relay_plugin_proto::convert::continuation_outcome_to_wire(
                &nemo_relay_plugin_protocol::PluginHostCallOutcome { result: answer },
            ),
        ))
    }

    type SessionStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<v1::PluginSessionMessage, Status>> + Send>,
    >;

    async fn session(
        &self,
        request: Request<tonic::Streaming<v1::PluginSessionMessage>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        // The channel a host opens to pull the streams its plugins are wrapping.
        // The credential is the session's, checked as it is on every other call a
        // host makes back: a channel that carries streams is not a lesser one.
        self.authenticate(&request)?;
        let mut inbound = request.into_inner();
        let session_id = self.config.session_id.clone();
        let continuations = Arc::clone(&self.config.continuations);
        let (answers, outbound) = tokio::sync::mpsc::channel(SESSION_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            // The writer: one task owns what reaches the plugin. Actors and the
            // dispatcher hand it messages rather than writing to the transport
            // themselves, so a host that has stopped reading its answers cannot
            // hold up the reception of its own messages — and the transport's own
            // buffer is still what paces a host that reads slowly.
            let (writes, mut written) = tokio::sync::mpsc::unbounded_channel::<
                nemo_relay_plugin_proto::v1::PluginSessionMessage,
            >();
            let writing = tokio::spawn(async move {
                while let Some(message) = written.recv().await {
                    if answers.send(message).await.is_err() {
                        return;
                    }
                }
            });

            let mut driver = crate::session_driver::SessionDriver::new(
                session_id.clone(),
                continuations,
                writes,
            );
            while let Some(message) = inbound.next().await {
                let Ok(message) = message else {
                    // The host's side of the channel broke; nothing is owed to a
                    // session that is no longer there.
                    break;
                };
                let message =
                    match nemo_relay_plugin_proto::convert::session_message_from_wire(&message) {
                        Ok(message) => message,
                        Err(_) => {
                            // A message the conversion refuses is one this kernel
                            // cannot attribute to this session, and the two sides no
                            // longer agree about what the channel is: it ends rather
                            // than continuing with one side's picture of it.
                            break;
                        }
                    };
                if message.session_id != session_id {
                    break;
                }
                // A refused message ends the channel: the state machine says the
                // session is no longer the one this host thinks it has, and
                // answering anyway would be guessing on its behalf.
                if driver.handle(message).is_err() {
                    break;
                }
            }

            // The session is over. Dropping the dispatcher closes every actor's
            // commands, so every actor stops and drops its producer; the writer
            // ends the response once the last of them has let go of it. Waiting
            // for that is what makes a session's shutdown the producers' shutdown
            // rather than a hope about scheduling.
            drop(driver);
            let _ = writing.await;
        });

        // The channel's answers are messages, not failures: a refusal the plugin
        // can read is a message, and a transport error here would be the kernel
        // telling the host that the session broke while it is still serving it.
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(outbound).map(Ok),
        )))
    }
}

/// Emit one forwarded mark into this runtime.
///
/// The fields are the ones the ABI carries, in the shape this runtime's own mark
/// entry point takes. A parent is resolved against *this* process's scope stack:
/// a plugin holds a scope identity, and an identity this stack does not contain
/// is refused rather than dropped or re-parented, because a mark attached to the
/// wrong scope is a different event than the one that was asked for.
fn emit(mark: &PluginMarkEmit) -> nemo_relay::error::Result<()> {
    // The caller has already refused a named parent and put this emit inside the
    // invocation's scope, so the mark attaches to that scope rather than to one
    // the host process named.
    let parent: Option<nemo_relay::api::scope::ScopeHandle> = None;
    let json = |text: &str, what: &str| -> nemo_relay::error::Result<nemo_relay::json::Json> {
        serde_json::from_str(text).map_err(|error| {
            nemo_relay::error::FlowError::InvalidArgument(format!("{what} is not JSON: {error}"))
        })
    };
    let data = mark
        .data_json
        .as_deref()
        .map(|text| json(text, "mark data"))
        .transpose()?;
    let metadata = mark
        .metadata_json
        .as_deref()
        .map(|text| json(text, "mark metadata"))
        .transpose()?;
    let timestamp = mark
        .timestamp_unix_micros
        .map(|micros| {
            i64::try_from(micros)
                .ok()
                .and_then(chrono::DateTime::from_timestamp_micros)
                .ok_or_else(|| {
                    nemo_relay::error::FlowError::InvalidArgument(
                        "the mark's timestamp is outside the range this runtime can order".into(),
                    )
                })
        })
        .transpose()?;
    nemo_relay::api::scope::event(
        EmitMarkEventParams::builder()
            .name(&mark.name)
            .parent_opt(parent.as_ref())
            .data_opt(data)
            .metadata_opt(metadata)
            .data_schema_opt(mark.data_schema.clone())
            .severity_opt(mark.severity)
            .timestamp_opt(timestamp)
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay::api::event::Event;
    use nemo_relay::api::subscriber::{
        deregister_subscriber, flush_subscribers, register_subscriber,
    };
    use nemo_relay_plugin_proto::v1::relay_runtime_server::RelayRuntimeServer;
    use std::sync::{Arc, Mutex};
    use tonic::metadata::MetadataValue;
    use tonic::transport::Server;

    /// Core's registries are process-global, so the tests that install into them
    /// take turns. The lock is this module's, so a test here cannot interleave
    /// with another in the same file; the names are unique so a suite running
    /// beside this one cannot be mistaken for it.
    static RUNTIME_SERVICE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    const SESSION_ID: &str = "runtime-service-session";
    const CREDENTIAL: &str = "runtime-service-credential";

    fn service() -> (RelayRuntimeService, Arc<OperationScopes>) {
        let scopes = Arc::new(OperationScopes::new());
        let service = RelayRuntimeService::new(RelayRuntimeConfig {
            session_id: SESSION_ID.into(),
            session_credential: CREDENTIAL.into(),
            protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
            runtime_binding_digest: "runtime-service-binding".into(),
            operation_scopes: Arc::clone(&scopes),
            continuations: Arc::new(crate::continuations::Continuations::new()),
            codecs: Arc::new(crate::codec_capability::CodecCapabilities::new()),
        });
        (service, scopes)
    }

    fn request() -> v1::EmitMarkRequest {
        v1::EmitMarkRequest {
            session_id: SESSION_ID.into(),
            operation_request_id: "operation-1".into(),
            host_call_id: "call-1".into(),
            name: "native.mark".into(),
            data_json: Some("{\"value\":7}".into()),
            parent: None,
            metadata_json: None,
            data_schema: None,
            severity: None,
            timestamp_unix_micros: None,
        }
    }

    fn authenticated(wire: v1::EmitMarkRequest) -> Request<v1::EmitMarkRequest> {
        let mut request = Request::new(wire);
        request.metadata_mut().insert(
            SESSION_CREDENTIAL_HEADER,
            MetadataValue::try_from(CREDENTIAL).expect("a header value"),
        );
        request
    }

    fn continuation(operation_request_id: &str) -> v1::ContinuationRequest {
        v1::ContinuationRequest {
            session_id: SESSION_ID.into(),
            operation_request_id: operation_request_id.into(),
            host_call_id: "host-call-1".into(),
            invocation_json: "{\"input\":true}".into(),
        }
    }

    fn authenticated_continuation(
        wire: v1::ContinuationRequest,
    ) -> Request<v1::ContinuationRequest> {
        let mut request = Request::new(wire);
        request.metadata_mut().insert(
            SESSION_CREDENTIAL_HEADER,
            MetadataValue::try_from(CREDENTIAL).expect("a header value"),
        );
        request
    }

    /// A request codec that answers with a recognizable annotation.
    struct TestRequestCodec;

    impl nemo_relay::codec::traits::LlmCodec for TestRequestCodec {
        fn codec_identity(&self) -> nemo_relay_plugin_protocol::LlmCodecIdentity {
            nemo_relay_plugin_protocol::LlmCodecIdentity::BuiltIn(
                nemo_relay_plugin_protocol::BuiltinLlmCodec::OpenAiChat,
            )
        }

        fn decode(
            &self,
            request: &nemo_relay::api::llm::LlmRequest,
        ) -> nemo_relay::error::Result<nemo_relay::codec::request::AnnotatedLlmRequest> {
            Ok(nemo_relay::codec::request::AnnotatedLlmRequest {
                model: request
                    .content
                    .get("model")
                    .and_then(nemo_relay::json::Json::as_str)
                    .map(str::to_string),
                ..Default::default()
            })
        }

        fn encode(
            &self,
            _annotated: &nemo_relay::codec::request::AnnotatedLlmRequest,
            original: &nemo_relay::api::llm::LlmRequest,
        ) -> nemo_relay::error::Result<nemo_relay::api::llm::LlmRequest> {
            Ok(original.clone())
        }
    }

    /// A codec call with a reference this kernel issued for that invocation.
    fn codec_call(
        reference: &str,
        operation_request_id: &str,
        operation: v1::CodecOperation,
    ) -> Request<v1::ResolveCodecRequest> {
        let mut request = Request::new(v1::ResolveCodecRequest {
            session_id: SESSION_ID.into(),
            operation_request_id: operation_request_id.into(),
            host_call_id: "host-call-1".into(),
            operation: operation as i32,
            payload_json: serde_json::json!({
                "codec_kind": "builtin",
                "codec_id": "openai_chat",
                "request": { "headers": {}, "content": { "model": "example" } }
            })
            .to_string(),
            codec_reference: reference.into(),
        });
        request.metadata_mut().insert(
            SESSION_CREDENTIAL_HEADER,
            MetadataValue::try_from(CREDENTIAL).expect("a header value"),
        );
        request
    }

    /// The kernel serves codec work for the invocation a capability was issued to, and for
    /// nothing else.
    ///
    /// This is the RPC that was refused as unimplemented until the capability record
    /// existed: what makes it safe to serve is not that the caller is the host — the host
    /// is the untrusted side — but that the reference it presents is one this kernel issued
    /// for the invocation it names.
    #[tokio::test]
    async fn a_codec_call_is_served_for_the_invocation_its_capability_was_issued_to() {
        let (service, _scopes) = service();
        let (reference, guard) = service
            .config
            .codecs
            .issue_request("operation-1", Arc::new(TestRequestCodec));

        let served = service
            .resolve_codec(codec_call(
                reference.as_str(),
                "operation-1",
                v1::CodecOperation::LlmRequestDecode,
            ))
            .await
            .expect("a served codec call")
            .into_inner();
        match served.result {
            Some(v1::resolve_codec_response::Result::Output(output)) => {
                let annotated: serde_json::Value =
                    serde_json::from_str(&output).expect("an annotated request");
                assert_eq!(annotated["model"], serde_json::json!("example"));
            }
            other => panic!("the kernel answered with codec work: {other:?}"),
        }

        // Another invocation cannot borrow it, and neither can another direction.
        let elsewhere = service
            .resolve_codec(codec_call(
                reference.as_str(),
                "operation-2",
                v1::CodecOperation::LlmRequestDecode,
            ))
            .await
            .expect_err("another call's codec work");
        assert_eq!(elsewhere.code(), tonic::Code::PermissionDenied);
        assert!(
            elsewhere.message().contains("wrong_operation"),
            "the refusal says which check found it out: {}",
            elsewhere.message()
        );
        let wrong_direction = service
            .resolve_codec(codec_call(
                reference.as_str(),
                "operation-1",
                v1::CodecOperation::LlmResponseDecode,
            ))
            .await
            .expect_err("a response decode with a request capability");
        assert_eq!(wrong_direction.code(), tonic::Code::PermissionDenied);
        assert!(
            wrong_direction.message().contains("wrong_direction"),
            "{}",
            wrong_direction.message()
        );

        // An identity the capability was not issued for is refused as what it is.
        let mut wrong_codec = codec_call(
            reference.as_str(),
            "operation-1",
            v1::CodecOperation::LlmRequestDecode,
        );
        wrong_codec.get_mut().payload_json = serde_json::json!({
            "codec_kind": "runtime",
            "codec_id": "runtime-chat",
            "request": { "headers": {}, "content": {} }
        })
        .to_string();
        let refused = service
            .resolve_codec(wrong_codec)
            .await
            .expect_err("a capability used as another codec");
        assert!(
            refused.message().contains("wrong_kind"),
            "{}",
            refused.message()
        );

        // And the capability does not outlive its invocation.
        drop(guard);
        let after = service
            .resolve_codec(codec_call(
                reference.as_str(),
                "operation-1",
                v1::CodecOperation::LlmRequestDecode,
            ))
            .await
            .expect_err("a capability whose invocation ended");
        assert!(
            after.message().contains("unknown"),
            "a forgotten capability is unknown rather than expired: {}",
            after.message()
        );
    }

    /// A reference this side never issued, a session that is not this one, and a call with
    /// no credential are each refused for what they are.
    #[tokio::test]
    async fn a_codec_call_this_kernel_cannot_authorize_is_refused() {
        let (service, _scopes) = service();
        let never_issued = nemo_relay_plugin_protocol::CodecRef::issue();

        let unknown = service
            .resolve_codec(codec_call(
                never_issued.as_str(),
                "operation-1",
                v1::CodecOperation::LlmRequestDecode,
            ))
            .await
            .expect_err("a reference nothing issued");
        assert_eq!(unknown.code(), tonic::Code::PermissionDenied);
        assert!(
            unknown.message().contains("unknown"),
            "{}",
            unknown.message()
        );

        let mut another_session = codec_call(
            never_issued.as_str(),
            "operation-1",
            v1::CodecOperation::LlmRequestDecode,
        );
        another_session.get_mut().session_id = "another-session".into();
        let refused = service
            .resolve_codec(another_session)
            .await
            .expect_err("a session this kernel did not establish");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);

        let mut unauthenticated = Request::new(
            codec_call(
                never_issued.as_str(),
                "operation-1",
                v1::CodecOperation::LlmRequestDecode,
            )
            .into_inner(),
        );
        unauthenticated
            .metadata_mut()
            .remove(SESSION_CREDENTIAL_HEADER);
        let refused = service
            .resolve_codec(unauthenticated)
            .await
            .expect_err("a call with no credential");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);

        // A credential that is not this session's is refused the same way, before any
        // lookup: the reference being unknown is not the interesting part of this call.
        let mut wrong_credential = codec_call(
            never_issued.as_str(),
            "operation-1",
            v1::CodecOperation::LlmRequestDecode,
        );
        wrong_credential.metadata_mut().insert(
            SESSION_CREDENTIAL_HEADER,
            MetadataValue::try_from("another-session-credential").expect("a header value"),
        );
        let refused = service
            .resolve_codec(wrong_credential)
            .await
            .expect_err("a call with another session's credential");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);

        // A reference that is not shaped like one was never issued here, and is refused
        // for what it is rather than looked up.
        let refused = service
            .resolve_codec(codec_call(
                "not-a-reference",
                "operation-1",
                v1::CodecOperation::LlmRequestDecode,
            ))
            .await
            .expect_err("a value that is not a reference");
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);

        // An operation this side does not define is refused rather than guessed, because
        // the direction it implies is what the capability is checked against.
        let refused = service
            .resolve_codec(codec_call(
                never_issued.as_str(),
                "operation-1",
                v1::CodecOperation::Unspecified,
            ))
            .await
            .expect_err("an operation this side does not define");
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
    }

    /// Park a continuation for one operation, with a chain that answers `result`.
    fn park(
        service: &RelayRuntimeService,
        operation_request_id: &str,
        next: nemo_relay::api::runtime::ToolExecutionNextFn,
    ) -> crate::continuations::ContinuationGuard {
        service
            .config
            .continuations
            .hold_tool(operation_request_id, "registration-1", next)
    }

    /// A continuation names a chain position, and the kernel runs the one it is
    /// holding — the rest of the call, with the arguments the plugin settled on.
    #[tokio::test]
    async fn a_continuation_runs_the_chain_the_kernel_is_holding() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let seen: Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let next: nemo_relay::api::runtime::ToolExecutionNextFn = Arc::new(move |args| {
            let recorder = Arc::clone(&recorder);
            Box::pin(async move {
                recorder.lock().unwrap().push(args.clone());
                Ok(nemo_relay::api::tool::ToolExecutionResult::new(
                    serde_json::json!({ "downstream": true }),
                ))
            })
        });
        let _held = park(&service, "operation-continue", next);

        let outcome = service
            .r#continue(authenticated_continuation(continuation(
                "operation-continue",
            )))
            .await
            .expect("a served continuation")
            .into_inner();
        let answer = nemo_relay_plugin_proto::convert::continuation_outcome_from_wire(&outcome)
            .expect("a converted outcome");
        let value = answer.result.expect("the chain answered");
        let value: serde_json::Value = serde_json::from_str(&value).expect("JSON");
        // The wire carries the whole result, not just its payload: the annotation
        // is part of what the plugin's `next` hands back.
        assert_eq!(value["result"]["downstream"], true, "{value}");
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            [serde_json::json!({"input": true})],
            "the arguments the plugin settled on are the ones the chain received"
        );
    }

    /// A chain that fails answers with the failure, not with an empty success: a
    /// plugin waiting on a result it will never get is the one outcome it cannot
    /// recover from.
    #[tokio::test]
    async fn a_continuation_that_fails_answers_with_the_failure() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let next: nemo_relay::api::runtime::ToolExecutionNextFn = Arc::new(|_args| {
            Box::pin(async {
                Err(nemo_relay::error::FlowError::NotFound(
                    "the wrapped call has nothing to run".to_string(),
                ))
            })
        });
        let _held = park(&service, "operation-fails", next);

        let outcome = service
            .r#continue(authenticated_continuation(continuation("operation-fails")))
            .await
            .expect("a served continuation")
            .into_inner();
        let answer = nemo_relay_plugin_proto::convert::continuation_outcome_from_wire(&outcome)
            .expect("a converted outcome");
        let failure = answer.result.expect_err("the chain's failure");
        assert!(
            failure.message.contains("nothing to run"),
            "the kernel's own words reach the plugin: {failure:?}"
        );
    }

    /// A continuation for an operation nothing is holding is refused.
    ///
    /// Two facts wear the same refusal, and they are the same fact: the operation
    /// was never in flight here, or the intercept that owned the position has
    /// already settled. Either way the chain position is not one this kernel may
    /// resume — and answering as if it had been resumed would run the *wrong*
    /// call.
    #[tokio::test]
    async fn a_continuation_for_an_unheld_operation_is_refused() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let refused = service
            .r#continue(authenticated_continuation(continuation(
                "operation-nobody-holds",
            )))
            .await
            .expect_err("a continuation the kernel is not holding");
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(
            refused.message().contains("not holding a continuation"),
            "{refused:?}"
        );

        // And a position that *was* held stops being held when the intercept
        // settles: the same request is refused afterwards.
        let next: nemo_relay::api::runtime::ToolExecutionNextFn = Arc::new(|args| {
            Box::pin(async move { Ok(nemo_relay::api::tool::ToolExecutionResult::new(args)) })
        });
        let held = park(&service, "operation-settled", next);
        drop(held);
        let refused = service
            .r#continue(authenticated_continuation(continuation(
                "operation-settled",
            )))
            .await
            .expect_err("a continuation whose intercept has settled");
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    }

    /// A resumed chain runs under the call's own budget, narrowed to what is
    /// left of it.
    ///
    /// The chain runs on this kernel's server task, which has no budget of its
    /// own. Without the call's budget the downstream registration would refuse
    /// for having none, and without narrowing it a plugin could hold its
    /// continuation to buy the call more time than the action granted.
    #[tokio::test]
    async fn a_continuation_runs_under_the_calls_remaining_budget() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let seen: Arc<std::sync::Mutex<Vec<Option<nemo_relay::api::runtime::ExecutionBudget>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let next: nemo_relay::api::runtime::ToolExecutionNextFn = Arc::new(move |args| {
            let recorder = Arc::clone(&recorder);
            Box::pin(async move {
                recorder
                    .lock()
                    .unwrap()
                    .push(nemo_relay::api::runtime::current_execution_budget());
                Ok(nemo_relay::api::tool::ToolExecutionResult::new(args))
            })
        });

        // Parked inside a managed call, as the proxy parks it, and resumed from a
        // task that has no budget at all — which is the whole point.
        let deadline = nemo_relay::api::runtime::budget_now_unix_ms() + 30_000;
        let budget = nemo_relay::api::runtime::ExecutionBudget::new(deadline, 30_000);
        let held = nemo_relay::api::runtime::with_execution_budget(budget, async {
            park(&service, "operation-budget", next)
        })
        .await;

        assert!(
            nemo_relay::api::runtime::current_execution_budget().is_none(),
            "this task has no budget of its own, so the continuation cannot inherit one \
             from where it runs"
        );
        let outcome = service
            .r#continue(authenticated_continuation(continuation("operation-budget")))
            .await
            .expect("a served continuation")
            .into_inner();
        nemo_relay_plugin_proto::convert::continuation_outcome_from_wire(&outcome)
            .expect("a converted outcome")
            .result
            .expect("the chain answered");

        let seen = seen.lock().unwrap().clone();
        let inherited = seen
            .first()
            .copied()
            .flatten()
            .expect("the chain ran under the call's budget");
        assert_eq!(
            inherited.deadline_unix_ms,
            Some(deadline),
            "the resumed chain keeps the call's deadline"
        );
        assert!(
            inherited.remaining_budget_millis <= budget.remaining_budget_millis,
            "and only what is left of it: {} of {}",
            inherited.remaining_budget_millis,
            budget.remaining_budget_millis
        );
        drop(held);
    }

    /// A panic while resuming is this request's failure, not a task that
    /// disappears: the host is waiting for an answer and would wait forever.
    #[tokio::test]
    async fn a_continuation_that_panics_answers_with_a_failure() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let next: nemo_relay::api::runtime::ToolExecutionNextFn =
            Arc::new(|_args| Box::pin(async move { panic!("the wrapped call panicked") }));
        let _held = park(&service, "operation-panics", next);

        let outcome = service
            .r#continue(authenticated_continuation(continuation("operation-panics")))
            .await
            .expect("a served continuation")
            .into_inner();
        let answer = nemo_relay_plugin_proto::convert::continuation_outcome_from_wire(&outcome)
            .expect("a converted outcome");
        let failure = answer.result.expect_err("the panic as a failure");
        assert!(
            failure.message.contains("panicked"),
            "the answer says what happened: {failure:?}"
        );
    }

    /// The provider half resumes the chain it parked, and the entry decides
    /// which shape the request has.
    ///
    /// The wire carries one unary resume for every family; what differs is what
    /// the parked position accepts and answers. This is that: a request shaped
    /// for a provider call resumes a provider position, and one shaped for a tool
    /// call is refused by the entry rather than by a discriminator on the wire.
    #[tokio::test]
    async fn a_provider_continuation_resumes_a_provider_position() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let seen: Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let next: nemo_relay::api::runtime::LlmExecutionNextFn = Arc::new(move |request| {
            let recorder = Arc::clone(&recorder);
            Box::pin(async move {
                recorder.lock().unwrap().push(request.content.clone());
                Ok(serde_json::json!({ "downstream": true }))
            })
        });
        let _held =
            service
                .config
                .continuations
                .hold_llm("operation-provider", "registration-1", next);

        let mut wire = continuation("operation-provider");
        wire.invocation_json =
            serde_json::json!({"headers": {}, "content": {"model": "fixture"}}).to_string();
        let outcome = service
            .r#continue(authenticated_continuation(wire))
            .await
            .expect("a served continuation")
            .into_inner();
        let answer = nemo_relay_plugin_proto::convert::continuation_outcome_from_wire(&outcome)
            .expect("a converted outcome");
        let value = answer.result.expect("the chain answered");
        let value: serde_json::Value = serde_json::from_str(&value).expect("JSON");
        assert_eq!(value["downstream"], true, "{value}");
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            [serde_json::json!({"model": "fixture"})],
            "the request the plugin settled on is the one the chain received"
        );
    }

    /// A resume that carries the wrong family's shape is refused by the position
    /// it addresses rather than guessed at.
    #[tokio::test]
    async fn a_continuation_of_the_wrong_shape_is_refused() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let next: nemo_relay::api::runtime::LlmExecutionNextFn = Arc::new(|request| {
            Box::pin(
                async move { Ok(serde_json::to_value(request).expect("a request serializes")) },
            )
        });
        let _held =
            service
                .config
                .continuations
                .hold_llm("operation-shape", "registration-1", next);

        // Tool-shaped arguments, addressed to a provider position.
        let mut wire = continuation("operation-shape");
        wire.invocation_json = serde_json::json!({"input": true}).to_string();
        let outcome = service
            .r#continue(authenticated_continuation(wire))
            .await
            .expect("a served continuation")
            .into_inner();
        let answer = nemo_relay_plugin_proto::convert::continuation_outcome_from_wire(&outcome)
            .expect("a converted outcome");
        let failure = answer.result.expect_err("the refusal");
        assert!(
            failure.message.contains("must carry a request"),
            "the refusal says what the position expected: {failure:?}"
        );
    }

    /// A stream position is not resumed by one answer, and says so.
    ///
    /// The shape rule the unary path enforces: a tool position takes arguments,
    /// a provider position takes a request, and a stream is resumed by pulling it
    /// one message at a time — so a unary resume addressed to a stream is refused
    /// with that reason rather than answered with its first chunk.
    #[tokio::test]
    async fn a_stream_position_does_not_answer_a_unary_resume() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let stream: nemo_relay::api::runtime::LlmStreamExecutionNextFn = Arc::new(|_request| {
            Box::pin(async move {
                Err(nemo_relay::error::FlowError::Internal(
                    "this test does not produce a stream".to_string(),
                ))
            })
        });
        let _held = service.config.continuations.hold_llm_stream(
            "operation-stream",
            "registration-1",
            stream,
        );

        let outcome = service
            .r#continue(authenticated_continuation(continuation("operation-stream")))
            .await
            .expect("a served continuation")
            .into_inner();
        let answer = nemo_relay_plugin_proto::convert::continuation_outcome_from_wire(&outcome)
            .expect("a converted outcome");
        let failure = answer.result.expect_err("the refusal");
        assert!(
            failure.message.contains("is a stream"),
            "the refusal says what the position is: {failure:?}"
        );
    }

    /// A continuation that names another session is refused before anything is
    /// looked up: this kernel serves one session, and a position in another
    /// kernel's chain is not this one's to resume.
    #[tokio::test]
    async fn a_continuation_for_another_session_is_refused() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let next: nemo_relay::api::runtime::ToolExecutionNextFn = Arc::new(|args| {
            Box::pin(async move { Ok(nemo_relay::api::tool::ToolExecutionResult::new(args)) })
        });
        let _held = park(&service, "operation-other-session", next);

        let mut wire = continuation("operation-other-session");
        wire.session_id = "another-session".into();
        let refused = service
            .r#continue(authenticated_continuation(wire))
            .await
            .expect_err("a continuation naming another session");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    }

    /// A continuation that carries nothing to run, or belongs to no operation, is
    /// refused for what it is rather than reported as a missing position.
    #[tokio::test]
    async fn a_malformed_continuation_is_refused_as_malformed() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        for wire in [
            v1::ContinuationRequest {
                operation_request_id: "  ".into(),
                ..continuation("operation-1")
            },
            v1::ContinuationRequest {
                host_call_id: String::new(),
                ..continuation("operation-1")
            },
            v1::ContinuationRequest {
                invocation_json: String::new(),
                ..continuation("operation-1")
            },
        ] {
            let refused = service
                .r#continue(authenticated_continuation(wire))
                .await
                .expect_err("a malformed continuation");
            assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        }
    }

    /// Serve the kernel's side of one session on a real socket.
    ///
    /// The driver's own tests call it directly; this is about everything around
    /// it, which only exists over a channel: the credential, the conversion, the
    /// session check, and answers that arrive as messages rather than as
    /// failures.
    async fn serve_session_channel(
        service: RelayRuntimeService,
    ) -> (std::path::PathBuf, tokio::task::JoinHandle<()>) {
        let directory = std::env::temp_dir().join(format!(
            "nemo-session-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&directory).expect("a socket directory");
        let endpoint = directory.join("k");
        let listener = tokio::net::UnixListener::bind(&endpoint).expect("a kernel socket");
        let serving = tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(RelayRuntimeServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
                .await;
            let _ = std::fs::remove_dir_all(&directory);
        });
        (endpoint, serving)
    }

    /// A host pulls a wrapped stream over the session channel, and the answers
    /// come back as messages.
    #[tokio::test]
    async fn a_wrapped_stream_is_pulled_over_the_session_channel() {
        use nemo_relay_plugin_protocol::{
            PluginSessionMessage, PluginSessionPayload, PluginStreamOpenRequest,
            PluginStreamPullRequest,
        };

        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let stream: nemo_relay::api::runtime::LlmStreamExecutionNextFn = Arc::new(|_request| {
            Box::pin(async move {
                Ok(nemo_relay::api::runtime::LlmJsonStream::new(
                    tokio_stream::iter(vec![
                        Ok(serde_json::json!({"chunk": 1})),
                        Ok(serde_json::json!({"chunk": 2})),
                    ]),
                ))
            })
        });
        // Parked through the same registry the service will drive: the guard
        // borrows it, so the service takes the shared handle rather than the
        // registry itself.
        let continuations = Arc::clone(&service.config.continuations);
        let _held = continuations.hold_llm_stream("operation-1", "registration-1", stream);
        let (endpoint, serving) = serve_session_channel(service).await;

        let mut client = connect_to_kernel(&endpoint, nemo_relay_plugin_protocol::MAX_FRAME_BYTES)
            .await
            .expect("a client");
        let (outbound, inbound) = tokio::sync::mpsc::channel(8);
        let credential = CREDENTIAL.parse().expect("a header value");
        let mut request = Request::new(tokio_stream::wrappers::ReceiverStream::new(inbound));
        request
            .metadata_mut()
            .insert(SESSION_CREDENTIAL_HEADER, credential);
        let mut answers = client
            .session(request)
            .await
            .expect("a served session channel")
            .into_inner();

        let message = |payload: PluginSessionPayload| PluginSessionMessage {
            session_id: SESSION_ID.into(),
            message: payload,
        };
        outbound
            .send(nemo_relay_plugin_proto::convert::session_message_to_wire(
                &message(PluginSessionPayload::StreamOpen(PluginStreamOpenRequest {
                    host_call_id: "call-1".into(),
                    operation_request_id: "operation-1".into(),
                    request_json: serde_json::json!({"headers": {}, "content": {}}).to_string(),
                })),
            ))
            .await
            .expect("a sent open");
        let opened = answers.next().await.expect("an answer").expect("a message");
        let opened = nemo_relay_plugin_proto::convert::session_message_from_wire(&opened)
            .expect("a converted answer");
        let PluginSessionPayload::StreamOpened(opened) = opened.message else {
            panic!("the kernel opens the stream: {opened:?}");
        };
        let stream_id = opened.stream_id;

        for expected in [1, 2] {
            outbound
                .send(nemo_relay_plugin_proto::convert::session_message_to_wire(
                    &message(PluginSessionPayload::StreamPull(PluginStreamPullRequest {
                        host_call_id: format!("pull-{expected}"),
                        stream_id: stream_id.clone(),
                    })),
                ))
                .await
                .expect("a sent pull");
            let item = answers.next().await.expect("an answer").expect("a message");
            let item = nemo_relay_plugin_proto::convert::session_message_from_wire(&item)
                .expect("a converted answer");
            let PluginSessionPayload::StreamItem(item) = item.message else {
                panic!("a pull is answered with the next item: {item:?}");
            };
            assert_eq!(
                item.chunk_json,
                serde_json::json!({"chunk": expected}).to_string()
            );
        }

        outbound
            .send(nemo_relay_plugin_proto::convert::session_message_to_wire(
                &message(PluginSessionPayload::StreamPull(PluginStreamPullRequest {
                    host_call_id: "pull-3".into(),
                    stream_id: stream_id.clone(),
                })),
            ))
            .await
            .expect("a sent pull");
        let end = answers.next().await.expect("an answer").expect("a message");
        let end = nemo_relay_plugin_proto::convert::session_message_from_wire(&end)
            .expect("a converted answer");
        assert!(
            matches!(end.message, PluginSessionPayload::StreamEnd(_)),
            "the third pull learns the stream is over: {end:?}"
        );

        drop(outbound);
        serving.abort();
    }

    /// A session keeps answering while a producer is parked.
    ///
    /// The driver's own tests prove the dispatcher routes rather than produces.
    /// This is the same property through everything around it — the credential,
    /// the conversion, the writer task and the transport — because a wait
    /// anywhere on that path would be head-of-line blocking by another name.
    #[tokio::test]
    async fn a_session_channel_answers_while_a_producer_is_blocked() {
        use nemo_relay_plugin_protocol::{
            PluginSessionMessage, PluginSessionPayload, PluginStreamOpenRequest,
            PluginStreamPullRequest,
        };

        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let parked: nemo_relay::api::runtime::LlmStreamExecutionNextFn = Arc::new(|_request| {
            Box::pin(async move {
                Ok(nemo_relay::api::runtime::LlmJsonStream::new(
                    tokio_stream::pending(),
                ))
            })
        });
        let serving: nemo_relay::api::runtime::LlmStreamExecutionNextFn = Arc::new(|_request| {
            Box::pin(async move {
                Ok(nemo_relay::api::runtime::LlmJsonStream::new(
                    tokio_stream::iter(vec![Ok(serde_json::json!({"chunk": 1}))]),
                ))
            })
        });
        let continuations = Arc::clone(&service.config.continuations);
        let _parked = continuations.hold_llm_stream("operation-parked", "registration-1", parked);
        let _serving =
            continuations.hold_llm_stream("operation-serving", "registration-1", serving);
        let (endpoint, serving_task) = serve_session_channel(service).await;

        let mut client = connect_to_kernel(&endpoint, nemo_relay_plugin_protocol::MAX_FRAME_BYTES)
            .await
            .expect("a client");
        let (outbound, inbound) = tokio::sync::mpsc::channel(8);
        let mut request = Request::new(tokio_stream::wrappers::ReceiverStream::new(inbound));
        request.metadata_mut().insert(
            SESSION_CREDENTIAL_HEADER,
            CREDENTIAL.parse().expect("a header value"),
        );
        let mut answers = client
            .session(request)
            .await
            .expect("a served session channel")
            .into_inner();

        async fn send(
            outbound: &tokio::sync::mpsc::Sender<nemo_relay_plugin_proto::v1::PluginSessionMessage>,
            payload: PluginSessionPayload,
        ) -> Result<
            (),
            tokio::sync::mpsc::error::SendError<nemo_relay_plugin_proto::v1::PluginSessionMessage>,
        > {
            let message = PluginSessionMessage {
                session_id: SESSION_ID.into(),
                message: payload,
            };
            outbound
                .send(nemo_relay_plugin_proto::convert::session_message_to_wire(
                    &message,
                ))
                .await
        }
        let mut opened = Vec::new();
        for (call, operation) in [
            ("call-1", "operation-parked"),
            ("call-2", "operation-serving"),
        ] {
            send(
                &outbound,
                PluginSessionPayload::StreamOpen(PluginStreamOpenRequest {
                    host_call_id: call.into(),
                    operation_request_id: operation.into(),
                    request_json: serde_json::json!({"headers": {}, "content": {}}).to_string(),
                }),
            )
            .await
            .expect("a sent open");
        }
        for _ in 0..2 {
            let answer = answers.next().await.expect("an answer").expect("a message");
            let answer = nemo_relay_plugin_proto::convert::session_message_from_wire(&answer)
                .expect("a converted answer");
            let PluginSessionPayload::StreamOpened(opened_stream) = answer.message else {
                panic!("the kernel opens both streams: {answer:?}");
            };
            opened.push(opened_stream);
        }
        let parked = opened
            .iter()
            .find(|stream| stream.host_call_id == "call-1")
            .expect("the parked stream")
            .stream_id
            .clone();
        let serving = opened
            .iter()
            .find(|stream| stream.host_call_id == "call-2")
            .expect("the serving stream")
            .stream_id
            .clone();

        // The parked pull is routed and its producer parks: nothing answers it,
        // because nothing has been produced.
        send(
            &outbound,
            PluginSessionPayload::StreamPull(PluginStreamPullRequest {
                host_call_id: "pull-parked".into(),
                stream_id: parked.clone(),
            }),
        )
        .await
        .expect("a sent pull");

        // The stream beside it is served while that pull is outstanding, which is
        // what a blocked producer must not be able to cost.
        send(
            &outbound,
            PluginSessionPayload::StreamPull(PluginStreamPullRequest {
                host_call_id: "pull-serving".into(),
                stream_id: serving.clone(),
            }),
        )
        .await
        .expect("a sent pull");
        let answer = answers.next().await.expect("an answer").expect("a message");
        let answer = nemo_relay_plugin_proto::convert::session_message_from_wire(&answer)
            .expect("a converted answer");
        let PluginSessionPayload::StreamItem(item) = answer.message else {
            panic!("the stream that can produce answers: {answer:?}");
        };
        assert_eq!(item.stream_id, serving);

        // The cancellation of the parked stream is served without the producer
        // yielding, and the session keeps serving messages afterwards: the open
        // after it is answered.
        send(
            &outbound,
            PluginSessionPayload::StreamCancel(nemo_relay_plugin_protocol::PluginStreamControl {
                host_call_id: "cancel-parked".into(),
                stream_id: parked,
            }),
        )
        .await
        .expect("a sent cancel");
        send(
            &outbound,
            PluginSessionPayload::StreamOpen(PluginStreamOpenRequest {
                host_call_id: "call-3".into(),
                operation_request_id: "operation-parked".into(),
                request_json: serde_json::json!({"headers": {}, "content": {}}).to_string(),
            }),
        )
        .await
        .expect("a sent open");
        let answer = answers.next().await.expect("an answer").expect("a message");
        let answer = nemo_relay_plugin_proto::convert::session_message_from_wire(&answer)
            .expect("a converted answer");
        assert!(
            matches!(answer.message, PluginSessionPayload::StreamOpened(_)),
            "the session serves the next open after a cancellation: {answer:?}"
        );

        drop(outbound);
        serving_task.abort();
    }

    /// A session that ends takes the producers it was serving with it.
    ///
    /// The host's end of the channel closing is how a session ends. What has to
    /// follow is the work: every actor stops, every producer is dropped, and the
    /// answer stream ends because there is nothing left to say it with — which is
    /// also why an answer stream that has ended is the observable proof that the
    /// producers are gone.
    #[tokio::test]
    async fn a_session_that_ends_drops_the_producers_it_was_serving() {
        use nemo_relay_plugin_protocol::{
            PluginSessionMessage, PluginSessionPayload, PluginStreamOpenRequest,
            PluginStreamPullRequest,
        };

        /// A producer that never produces and says when it is gone.
        struct Watched(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl tokio_stream::Stream for Watched {
            type Item = Result<nemo_relay::json::Json, nemo_relay::error::FlowError>;
            fn poll_next(
                self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                std::task::Poll::Pending
            }
        }
        impl Drop for Watched {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stream: nemo_relay::api::runtime::LlmStreamExecutionNextFn = {
            let dropped = Arc::clone(&dropped);
            Arc::new(move |_request| {
                let dropped = Arc::clone(&dropped);
                Box::pin(async move {
                    Ok(nemo_relay::api::runtime::LlmJsonStream::new(Watched(
                        dropped,
                    )))
                })
            })
        };
        let continuations = Arc::clone(&service.config.continuations);
        let _held = continuations.hold_llm_stream("operation-1", "registration-1", stream);
        let (endpoint, serving_task) = serve_session_channel(service).await;

        let mut client = connect_to_kernel(&endpoint, nemo_relay_plugin_protocol::MAX_FRAME_BYTES)
            .await
            .expect("a client");
        let (outbound, inbound) = tokio::sync::mpsc::channel(8);
        let mut request = Request::new(tokio_stream::wrappers::ReceiverStream::new(inbound));
        request.metadata_mut().insert(
            SESSION_CREDENTIAL_HEADER,
            CREDENTIAL.parse().expect("a header value"),
        );
        let mut answers = client
            .session(request)
            .await
            .expect("a served session channel")
            .into_inner();

        let message = |payload| PluginSessionMessage {
            session_id: SESSION_ID.into(),
            message: payload,
        };
        outbound
            .send(nemo_relay_plugin_proto::convert::session_message_to_wire(
                &message(PluginSessionPayload::StreamOpen(PluginStreamOpenRequest {
                    host_call_id: "call-1".into(),
                    operation_request_id: "operation-1".into(),
                    request_json: serde_json::json!({"headers": {}, "content": {}}).to_string(),
                })),
            ))
            .await
            .expect("a sent open");
        let answer = answers.next().await.expect("an answer").expect("a message");
        let answer = nemo_relay_plugin_proto::convert::session_message_from_wire(&answer)
            .expect("a converted answer");
        let PluginSessionPayload::StreamOpened(opened) = answer.message else {
            panic!("the kernel opens the stream: {answer:?}");
        };
        outbound
            .send(nemo_relay_plugin_proto::convert::session_message_to_wire(
                &message(PluginSessionPayload::StreamPull(PluginStreamPullRequest {
                    host_call_id: "pull-1".into(),
                    stream_id: opened.stream_id,
                })),
            ))
            .await
            .expect("a sent pull");

        // The host lets go of its end while the kernel is parked in the
        // producer.
        drop(outbound);
        assert!(
            answers.next().await.is_none(),
            "the session's answers end when the session does"
        );
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "the producer the session was serving is dropped with it"
        );
        serving_task.abort();
    }

    /// A session channel without the credential is refused at the door, like
    /// every other call a host makes back.
    #[tokio::test]
    async fn a_session_channel_needs_this_session_s_credential() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();
        let (endpoint, serving) = serve_session_channel(service).await;

        let mut client = connect_to_kernel(&endpoint, nemo_relay_plugin_protocol::MAX_FRAME_BYTES)
            .await
            .expect("a client");
        let (_outbound, inbound) = tokio::sync::mpsc::channel(8);
        let refused = client
            .session(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                inbound,
            )))
            .await
            .expect_err("a session channel with no credential");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);

        serving.abort();
    }

    #[tokio::test]
    async fn a_call_back_into_the_kernel_needs_this_session_s_credential() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, _scopes) = service();

        // Knowing where the socket is, and even which session it serves, is not
        // being the host of that session.
        let anonymous = service
            .emit_mark(Request::new(request()))
            .await
            .expect_err("a call with no credential");
        assert_eq!(anonymous.code(), tonic::Code::PermissionDenied);

        let mut wrong = Request::new(request());
        wrong.metadata_mut().insert(
            SESSION_CREDENTIAL_HEADER,
            MetadataValue::try_from("not-the-credential").expect("a header value"),
        );
        let refused = service
            .emit_mark(wrong)
            .await
            .expect_err("a call with another credential");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);

        // The credential buys this session, not another one.
        let mut elsewhere = request();
        elsewhere.session_id = "another-session".into();
        let misdirected = service
            .emit_mark(authenticated(elsewhere))
            .await
            .expect_err("a call naming another session");
        assert_eq!(misdirected.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn a_mark_a_plugin_emits_reaches_this_runtime_s_subscribers() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let seen: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        register_subscriber(
            "runtime-service-mark-subscriber",
            Arc::new(move |event: &Event| {
                if event.name() == "native.mark" {
                    recorded.lock().unwrap().push(event.clone());
                }
            }),
        )
        .expect("a subscriber");

        let (service, scopes) = service();
        // The kernel registers the operation while it is in flight; the mark is
        // attributed to that scope rather than to the server task's.
        let _in_flight = scopes.enter(
            "operation-1",
            nemo_relay::api::runtime::create_scope_stack(),
        );
        service
            .emit_mark(authenticated(request()))
            .await
            .expect("an accepted mark");
        flush_subscribers().expect("a flush");

        let captured = seen.lock().unwrap().clone();
        assert_eq!(captured.len(), 1, "one mark arrived");
        assert_eq!(captured[0].data().unwrap()["value"], 7);

        // A payload that is not what it claims to be is refused rather than
        // emitted as something else, and the refusal is a status because an
        // acknowledgement has no room for a structured one.
        let mut broken = request();
        broken.data_json = Some("not json".into());
        let refused = service
            .emit_mark(authenticated(broken))
            .await
            .expect_err("a mark whose payload is not JSON");
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);

        let mut unnamed = request();
        unnamed.name.clear();
        let refused = service
            .emit_mark(authenticated(unnamed))
            .await
            .expect_err("a mark with no name");
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);

        deregister_subscriber("runtime-service-mark-subscriber").expect("a deregistration");
    }

    #[tokio::test]
    async fn a_mark_that_cannot_be_attributed_is_refused() {
        let _guard = RUNTIME_SERVICE_LOCK.lock().await;
        let (service, scopes) = service();

        // Nothing is running this operation in this kernel, so the mark has no
        // invocation to belong to. Attaching it to whatever scope the server task
        // happens to be in would be an event nobody asked for.
        let unknown = service
            .emit_mark(authenticated(request()))
            .await
            .expect_err("a mark for an operation nothing is running");
        assert_eq!(unknown.code(), tonic::Code::FailedPrecondition);

        let _in_flight = scopes.enter(
            "operation-1",
            nemo_relay::api::runtime::create_scope_stack(),
        );

        // A parent is a scope identity from the host process, which this kernel
        // cannot resolve: refusing says so, and ignoring the name would attach
        // the mark somewhere the plugin did not ask for.
        let mut orphaned = request();
        orphaned.parent = Some(v1::ScopeReference {
            scope_id: nemo_relay_plugin_protocol::Uuid::now_v7().to_string(),
        });
        let refused = service
            .emit_mark(authenticated(orphaned))
            .await
            .expect_err("a mark naming a scope from the host process");
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    }

    /// The wire form the tests above send is the one a host would send.
    #[test]
    fn the_mark_request_round_trips_through_the_wire_form() {
        let wire = request();
        let mark = nemo_relay_plugin_proto::convert::mark_request_from_wire(&wire)
            .expect("a converted mark");
        assert_eq!(mark.name, "native.mark");
        assert_eq!(mark.host_call_id, wire.host_call_id);
        assert_eq!(mark.data_json, wire.data_json);
        assert_eq!(mark.operation_request_id, wire.operation_request_id);
    }
}
