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
use nemo_relay::api::scope::EmitMarkEventParams;
use nemo_relay_plugin_proto::v1;
use nemo_relay_plugin_proto::v1::relay_runtime_client::RelayRuntimeClient;
use nemo_relay_plugin_proto::v1::relay_runtime_server::RelayRuntime;
use nemo_relay_plugin_protocol::PluginMarkEmit;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

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
        _request: Request<v1::ResolveCodecRequest>,
    ) -> Result<Response<v1::ResolveCodecResponse>, Status> {
        Err(Status::unimplemented(
            "this kernel does not serve codec resolution yet",
        ))
    }

    async fn r#continue(
        &self,
        _request: Request<v1::ContinuationRequest>,
    ) -> Result<Response<v1::ContinuationOutcome>, Status> {
        Err(Status::unimplemented(
            "this kernel does not serve continuations yet",
        ))
    }

    type SessionStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<v1::PluginSessionMessage, Status>> + Send>,
    >;

    async fn session(
        &self,
        _request: Request<tonic::Streaming<v1::PluginSessionMessage>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        Err(Status::unimplemented(
            "this kernel does not serve the duplex session yet",
        ))
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
    use std::sync::{Arc, Mutex};
    use tonic::metadata::MetadataValue;

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
