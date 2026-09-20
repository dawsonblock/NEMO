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
}

impl PluginHostService {
    /// Serve lifecycle operations for one backend.
    pub fn new(backend: Arc<dyn PluginExecutionBackend>, config: PluginHostConfig) -> Self {
        Self {
            backend,
            config,
            host_instance_id: Uuid::now_v7().to_string(),
            session: Mutex::new(HostSession::New),
        }
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
