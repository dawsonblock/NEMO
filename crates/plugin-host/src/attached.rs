// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A second transport attached to a session the kernel already established.
//!
//! Off-path work — the callbacks the dispatcher runs beside a call rather than on
//! the call's own path — needs a transport whose tasks live on the runtime that
//! drives it. Moving the *work* to a dedicated runtime was not enough: the
//! connection still belonged to the composition, and on a single-threaded caller
//! that runtime is the thread waiting for the answer, so the reply had nowhere to
//! arrive.
//!
//! This is that transport, and nothing else: it attaches, it invokes, and it
//! refuses everything a second transport has no business doing. Routing off-path
//! families through it is the next step; landing the transport on its own first is
//! what makes that step small, because the piece that failed twice was the piece
//! that both attached *and* rerouted at the same time.
//!
//! It attaches rather than handshaking: the session, the plugins loaded into it
//! and the proxies installed for them belong to the session the handshake
//! established, and a second session would be a second runtime's worth of state.
//! The attach is also what proves this transport is allowed — it presents the
//! credential, and the host answers with the session's own parameters rather than
//! accepting any this side supplies.

use std::path::PathBuf;

use nemo_relay_plugin_proto::v1::plugin_host_client::PluginHostClient;
use nemo_relay_plugin_proto::{convert, v1};
use nemo_relay_plugin_protocol::{
    MAX_FRAME_BYTES, PROTOCOL_VERSION, PluginExecutionContext, PluginExecutionOutcome,
    PluginInvocationError, PluginInvocationPhase, PluginProtocolError,
};
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

/// Everything a second transport needs to attach to an established session.
///
/// The credential rather than the socket path is what makes this a transport the
/// host will serve, and the session identity is what says which session it joins.
/// The negotiated limits travel with it so the attaching side can check what it
/// was told against what the session says.
#[derive(Debug, Clone)]
pub struct ConnectionDescriptor {
    /// Path of the host's socket.
    pub endpoint: PathBuf,
    /// The credential the host was started with.
    pub session_credential: String,
    /// Digest of the runtime identity the session is bound to.
    pub runtime_binding_digest: String,
    /// The session being joined.
    pub session_id: String,
    /// Frame limit the session negotiated.
    pub maximum_frame_bytes: u32,
    /// What this session's operations have to present.
    ///
    /// The credential says which host this is; the capability says this
    /// transport may use the session. Both travel together because a second
    /// transport is not a lesser one: it is authorised the same way the first
    /// one was.
    pub capability: String,
}

impl ConnectionDescriptor {
    /// A descriptor for a session whose frame limit this side does not know yet.
    ///
    /// The limit is the maximum this side speaks; the attach answers with the
    /// session's own, and a mismatch is refused rather than negotiated.
    pub fn with_default_frame_limit(mut self) -> Self {
        self.maximum_frame_bytes = MAX_FRAME_BYTES;
        self
    }
}

/// A request carrying the capability this session's operations have to present.
///
/// A second transport presents the same capability the first one did, in the
/// same place: the header is read before the message, so a request that named a
/// session in its body could not also claim one in its metadata.
fn capable<T>(message: T, capability: &str) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request.metadata_mut().insert(
        crate::capability::SESSION_CAPABILITY_HEADER,
        tonic::metadata::MetadataValue::try_from(capability)
            .expect("a capability is ASCII hex, and so is a valid header value"),
    );
    request
}

/// A transport attached to a session, and the invocations it can serve.
pub struct AttachedClient {
    client: PluginHostClient<Channel>,
    descriptor: ConnectionDescriptor,
}

impl std::fmt::Debug for AttachedClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttachedClient")
            .field("session_id", &self.descriptor.session_id)
            .finish()
    }
}

impl AttachedClient {
    /// Connect to the host and attach to the session in `descriptor`.
    ///
    /// Both the connection and the client are created *here*, so whatever runtime
    /// calls this owns the transport: a channel created elsewhere and handed over
    /// would keep its tasks where it was made, which is the bug this exists to
    /// remove.
    pub async fn connect(descriptor: ConnectionDescriptor) -> Result<Self, PluginProtocolError> {
        let channel = connect(&descriptor.endpoint).await?;
        let mut client = PluginHostClient::new(channel)
            .max_decoding_message_size(descriptor.maximum_frame_bytes as usize)
            .max_encoding_message_size(descriptor.maximum_frame_bytes as usize);
        let outcome = client
            .attach(capable(
                v1::AttachRequest {
                    session_id: descriptor.session_id.clone(),
                    session_credential: descriptor.session_credential.clone(),
                    runtime_binding_digest: descriptor.runtime_binding_digest.clone(),
                    protocol_version: u32::from(PROTOCOL_VERSION),
                },
                &descriptor.capability,
            ))
            .await
            .map_err(|status| {
                unavailable(format!("the off-path transport did not attach: {status}"))
            })?
            .into_inner();
        let joined = convert::attach_outcome_from_wire(&outcome)?
            .into_result()
            .map_err(|failure| PluginProtocolError { failure })?;
        // The session's parameters, checked against what this side was told: an
        // attach that accepted a different session, a different frame limit or a
        // different binding is not the attachment this descriptor describes.
        if joined.session_id != descriptor.session_id {
            return Err(refused(
                "the host attached this transport to a different session than the one it named",
            ));
        }
        if joined.negotiated_frame_limit != descriptor.maximum_frame_bytes {
            return Err(refused(
                "the session's frame limit is not the one this transport was told",
            ));
        }
        if joined.runtime_binding_digest != descriptor.runtime_binding_digest {
            return Err(refused(
                "the session's runtime binding is not the one this transport was told",
            ));
        }
        Ok(Self { client, descriptor })
    }

    /// The descriptor this transport attached with.
    pub fn descriptor(&self) -> &ConnectionDescriptor {
        &self.descriptor
    }

    /// Invoke one registration over this transport.
    ///
    /// The same rules as the primary path: the deadline is checked before anything
    /// is sent, the answer has to name the invocation it answers, and a failure
    /// that came back after the transport was entered keeps its uncertainty rather
    /// than being reported as a definite negative. The error type is
    /// `PluginInvocationError` rather than `PluginProtocolError` for that last
    /// reason — flattening the phase into a message is the regression an earlier
    /// commit removed.
    pub async fn invoke(
        &self,
        request: nemo_relay_plugin_protocol::PluginInvokeRequest,
        context: PluginExecutionContext,
    ) -> Result<PluginExecutionOutcome, PluginInvocationError> {
        let now = nemo_relay::api::runtime::budget_now_unix_ms();
        if nemo_relay_plugin_protocol::deadline_expired(context.deadline_unix_ms, now) {
            return Err(PluginInvocationError {
                failure: nemo_relay_plugin_protocol::PluginFailure {
                    code: nemo_relay_plugin_protocol::PluginFailureCode::DeadlineExceeded,
                    message: "the operation's deadline had already passed".to_string(),
                },
                phase: PluginInvocationPhase::RefusedBeforeBackend,
            });
        }
        let budget = context
            .deadline_unix_ms
            .saturating_sub(now)
            .min(context.remaining_budget_millis);
        // The session, not the operation: the request has to name the session it
        // belongs to, and the operation travels in the context.
        let wire = convert::invoke_request_to_wire(&request, &self.descriptor.session_id, &context);
        let mut client = self.client.clone();
        let sent = tokio::time::timeout(
            std::time::Duration::from_millis(budget),
            client.invoke(capable(wire, &self.descriptor.capability)),
        )
        .await;
        match sent {
            Ok(Ok(answer)) => convert::invocation_answer_from_wire(
                &answer.into_inner(),
                &context.operation_request_id,
            )
            .map_err(|error| PluginInvocationError {
                failure: error.failure,
                // The transport answered; the answer was unusable. Nothing about
                // that says the plugin did not run.
                phase: PluginInvocationPhase::BackendEntered,
            }),
            Ok(Err(status)) => Err(PluginInvocationError {
                failure: nemo_relay_plugin_protocol::PluginFailure {
                    code: nemo_relay_plugin_protocol::PluginFailureCode::Unavailable,
                    message: format!("the off-path transport did not answer: {status}"),
                },
                phase: PluginInvocationPhase::BackendEntered,
            }),
            Err(_) => Err(PluginInvocationError {
                failure: nemo_relay_plugin_protocol::PluginFailure {
                    code: nemo_relay_plugin_protocol::PluginFailureCode::DeadlineExceeded,
                    message: "the off-path transport exceeded the operation's budget".to_string(),
                },
                phase: PluginInvocationPhase::BackendEntered,
            }),
        }
    }
}

/// Dial the host's socket.
async fn connect(socket: &std::path::Path) -> Result<Channel, PluginProtocolError> {
    let path: std::sync::Arc<PathBuf> = std::sync::Arc::new(socket.to_path_buf());
    let endpoint = Endpoint::try_from("http://[::]:50051").map_err(|error| {
        unavailable(format!("the off-path endpoint could not be built: {error}"))
    })?;
    endpoint
        .connect_with_connector(service_fn(move |_| {
            let path = std::sync::Arc::clone(&path);
            async move {
                tokio::net::UnixStream::connect(&*path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .map_err(|error| unavailable(format!("the off-path transport could not connect: {error}")))
}

fn refused(message: &str) -> PluginProtocolError {
    PluginProtocolError::new(
        nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
        message.to_string(),
    )
}

fn unavailable(message: String) -> PluginProtocolError {
    PluginProtocolError::new(
        nemo_relay_plugin_protocol::PluginFailureCode::Unavailable,
        message,
    )
}
