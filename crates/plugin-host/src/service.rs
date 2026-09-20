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
    cancel_outcome_to_wire, execution_outcome_to_wire, handshake_outcome_to_wire,
    handshake_request_from_wire, health_outcome_to_wire, inspect_outcome_to_wire,
    inspect_request_from_wire, load_outcome_to_wire, load_request_from_wire,
    operation_envelope_from_wire, unload_outcome_to_wire, unload_request_from_wire,
};
use nemo_relay_plugin_proto::v1;
use nemo_relay_plugin_protocol::{
    LifecycleOutcome, PROTOCOL_VERSION, PluginHostReadCapability, PluginProtocolError,
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

/// The `PluginHost` service.
pub struct PluginHostService {
    backend: Arc<dyn PluginExecutionBackend>,
    config: PluginHostConfig,
    /// Identity of this host process.
    host_instance_id: String,
    /// The session this host established, if any.
    session: Mutex<Option<String>>,
}

impl PluginHostService {
    /// Serve lifecycle operations for one backend.
    pub fn new(backend: Arc<dyn PluginExecutionBackend>, config: PluginHostConfig) -> Self {
        Self {
            backend,
            config,
            host_instance_id: Uuid::now_v7().to_string(),
            session: Mutex::new(None),
        }
    }

    /// Validate the session every later request has to name.
    fn established(&self, session_id: &str) -> Result<(), PluginProtocolError> {
        let session = self
            .session
            .lock()
            .map_err(|error| refused(format!("the session lock was poisoned: {error}")))?;
        match session.as_ref() {
            Some(established) if established == session_id => Ok(()),
            Some(_) => Err(refused(
                "this request names a session this host did not establish",
            )),
            None => Err(refused("this host has not established a session yet")),
        }
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
            Ok(mut session) => *session = Some(session_id),
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
            self.backend.load(request, context).await
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

    async fn invoke(
        &self,
        _request: Request<v1::InvokeRequest>,
    ) -> Result<Response<v1::InvokeOutcome>, Status> {
        // Nothing asks a host to invoke yet: a loaded plugin registers into the
        // runtime's own machinery rather than exposing an endpoint, so there is
        // nothing here to dispatch to. A structured refusal keeps that visible
        // rather than looking like an empty success.
        let outcome =
            execution_outcome_to_wire(&nemo_relay_plugin_protocol::PluginExecutionOutcome {
                dispatch: nemo_relay_plugin_protocol::DispatchState::NotDispatched,
                certainty: nemo_relay_plugin_protocol::OutcomeCertainty::ConfirmedFailure,
                result: Err(nemo_relay_plugin_protocol::PluginFailure {
                    code: nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
                    message: "this host does not serve invocations".to_string(),
                }),
            })
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
        _request: Request<v1::InvokeRequest>,
    ) -> Result<Response<Self::InvokeStreamStream>, Status> {
        // No stream is produced, and the stream says so: a stream that simply
        // stopped would be a truncation the kernel cannot distinguish from a
        // host that died mid-answer.
        let refusal = v1::StreamChunk {
            operation_request_id: String::new(),
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
    ) -> Result<Response<v1::SessionCloseResponse>, Status> {
        let wire = request.into_inner();
        if let Err(error) = self.established(&wire.session_id) {
            return Err(Status::failed_precondition(error.failure.message));
        }
        // Closing is a state change the host makes, not a message it answers
        // with a failure: the session is gone afterwards, so every later request
        // is refused by the same check that refuses one naming no session.
        match self.session.lock() {
            Ok(mut session) => *session = None,
            Err(error) => return Err(Status::internal(error.to_string())),
        }
        Ok(Response::new(v1::SessionCloseResponse {}))
    }
}

impl PluginHostService {
    /// Validate the session and context of one operation.
    fn prepare(
        &self,
        session_id: &str,
        context: Option<&v1::PluginExecutionContext>,
    ) -> Result<nemo_relay_plugin_protocol::PluginExecutionContext, PluginProtocolError> {
        self.established(session_id)?;
        let envelope = operation_envelope_from_wire(session_id, context)?;
        Ok(envelope.context)
    }
}

/// The read capabilities a host accepted, for a kernel that wants to check them.
pub fn accepted_capabilities(identity: &PluginSessionIdentity) -> Vec<PluginHostReadCapability> {
    identity.accepted_read_capabilities.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay_plugin_proto::convert::{handshake_outcome_from_wire, mark_request_from_wire};
    use nemo_relay_plugin_protocol::{PluginFailureCode, PluginHostReadCapability};
    use tonic::Request;

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
        }
    }

    async fn establish(service: &PluginHostService, config: &PluginHostConfig) -> String {
        use v1::plugin_host_server::PluginHost;
        let outcome = service
            .handshake(Request::new(handshake_request(config)))
            .await
            .expect("a served handshake")
            .into_inner();
        let identity = handshake_outcome_from_wire(&outcome)
            .expect("a converted handshake")
            .into_result()
            .expect("an established session");
        identity.session_id
    }

    #[tokio::test]
    async fn a_host_refuses_a_credential_it_was_not_started_with() {
        use v1::plugin_host_server::PluginHost;
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
        use v1::plugin_host_server::PluginHost;
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
        use v1::plugin_host_server::PluginHost;
        let (service, config) = service();
        let request = || v1::LoadRequest {
            session_id: "unknown".into(),
            context: Some(nemo_relay_plugin_proto::convert::context_to_wire(
                &nemo_relay_plugin_protocol::PluginExecutionContext {
                    operation_request_id: "operation-1".into(),
                    protocol_version: PROTOCOL_VERSION,
                    runtime_binding_digest: "binding".into(),
                    deadline_unix_ms: u64::MAX,
                    remaining_budget_millis: 1_000,
                    max_response_bytes: 1024,
                },
            )),
            plugin_id: "absent".into(),
            artifact: "/nonexistent/relay-plugin.toml".into(),
            manifest_digest: "a".repeat(64),
            library_digest: "b".repeat(64),
        };

        // Before a session exists, nothing is served.
        let outcome = service
            .load(Request::new(request()))
            .await
            .expect("a served load")
            .into_inner();
        assert!(
            nemo_relay_plugin_proto::convert::load_outcome_from_wire(&outcome)
                .expect("a converted load")
                .into_result()
                .is_err()
        );

        // And a request naming a session this host did not establish is refused
        // rather than served.
        let session_id = establish(&service, &config).await;
        let mut wire = request();
        wire.session_id = "another-session".into();
        let outcome = service
            .load(Request::new(wire))
            .await
            .expect("a served load")
            .into_inner();
        assert!(
            nemo_relay_plugin_proto::convert::load_outcome_from_wire(&outcome)
                .expect("a converted load")
                .into_result()
                .is_err()
        );

        // The established session is served, and the answer comes from the
        // backend rather than from the session check: an inspection of an empty
        // host is an empty list, not a refusal.
        let outcome = service
            .inspect(Request::new(v1::InspectRequest {
                session_id: session_id.clone(),
                context: request().context,
                handle: None,
            }))
            .await
            .expect("a served inspection")
            .into_inner();
        let descriptors = nemo_relay_plugin_proto::convert::inspect_outcome_from_wire(&outcome)
            .expect("a converted inspection")
            .into_result()
            .expect("an answer from the backend");
        assert!(descriptors.is_empty());

        // And a load through that session reaches the loader: the manifest does
        // not exist, so it is refused — by the loader, not by the session.
        let mut wire = request();
        wire.session_id = session_id;
        let outcome = service
            .load(Request::new(wire))
            .await
            .expect("a served load")
            .into_inner();
        assert!(
            nemo_relay_plugin_proto::convert::load_outcome_from_wire(&outcome)
                .expect("a converted load")
                .into_result()
                .is_err()
        );

        // A closing session stops serving, and later requests are refused by the
        // same check that refused the one naming no session.
        service
            .session_close(Request::new(v1::SessionCloseRequest {
                session_id: "closed".into(),
            }))
            .await
            .expect_err("a session this host did not establish");
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
}
