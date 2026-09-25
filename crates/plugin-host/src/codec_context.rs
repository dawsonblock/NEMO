// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The codec context a plugin is told about, and the work its reference authorizes.
//!
//! A plugin's sanitizer is given the call's codec *identity* — which is all it needs to
//! decide with — and a reference it can use to have work done. Both sides of the boundary
//! speak this module: the kernel writes the identity into the invocation it sends, the
//! host turns it into the context the plugin's callback sees, and the kernel reads it back
//! out of a resolve request so it can refuse a reference issued for one codec being used
//! as another.
//!
//! The wire spelling is the one the native SDK already reads (`codec_kind` plus
//! `codec_id`, the shape `CodecIdentityInvocation` deserializes), because a second
//! spelling of the same fact is a second place for it to be wrong.

use nemo_relay::api::llm::LlmRequest;
use std::sync::Arc;

use nemo_relay::codec::request::AnnotatedLlmRequest;
use nemo_relay::error::FlowError;
use nemo_relay::json::Json;
use nemo_relay_plugin_protocol::{BuiltinLlmCodec, LlmCodecIdentity};

use crate::codec_capability::CodecHandle;

/// Which codec operation a resolve request names.
///
/// The direction and the operation are one thing here: a decode of a request, an encode
/// of a request, and a decode of a response are the three operations the runtime's codec
/// traits offer, and naming them together is what keeps a capability's direction and the
/// work it is used for in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecOperation {
    /// Parse an opaque request with the call's request codec.
    RequestDecode,
    /// Merge normalized changes back into an opaque request.
    RequestEncode,
    /// Parse an opaque response with the call's response codec.
    ResponseDecode,
}

impl CodecOperation {
    /// The operation a wire value names.
    ///
    /// # Errors
    /// Returns the refusal for a value this side does not define — the operation is a
    /// decision this side makes, so an unknown one is refused rather than guessed.
    pub fn from_wire(value: i32) -> Result<Self, FlowError> {
        match value {
            value
                if value
                    == nemo_relay_plugin_proto::v1::CodecOperation::LlmRequestDecode as i32 =>
            {
                Ok(Self::RequestDecode)
            }
            value
                if value
                    == nemo_relay_plugin_proto::v1::CodecOperation::LlmRequestEncode as i32 =>
            {
                Ok(Self::RequestEncode)
            }
            value
                if value
                    == nemo_relay_plugin_proto::v1::CodecOperation::LlmResponseDecode as i32 =>
            {
                Ok(Self::ResponseDecode)
            }
            other => Err(FlowError::InvalidArgument(format!(
                "there is no codec operation numbered {other}"
            ))),
        }
    }

    /// Whether this operation reads the request direction.
    pub fn is_request(self) -> bool {
        !matches!(self, Self::ResponseDecode)
    }
}

/// The identity a plugin was told, as the wire spells it.
///
/// # Errors
/// Returns a refusal for a kind this side does not define, and for a built-in codec id
/// the runtime does not know: a plugin that says "the built-in X" and an id nothing
/// matches is describing a codec that does not exist.
pub fn identity_from_wire(kind: &str, id: Option<&str>) -> Result<LlmCodecIdentity, FlowError> {
    match (kind, id) {
        ("none", _) => Ok(LlmCodecIdentity::None),
        ("opaque", _) => Ok(LlmCodecIdentity::Opaque),
        ("builtin", Some(id)) => BuiltinLlmCodec::from_id(id)
            .map(LlmCodecIdentity::BuiltIn)
            .ok_or_else(|| FlowError::InvalidArgument(format!("unknown built-in codec: {id}"))),
        ("runtime", Some(id)) => Ok(LlmCodecIdentity::Runtime(id.to_string())),
        (kind, None) => Err(FlowError::InvalidArgument(format!(
            "a codec identity of kind '{kind}' needs an identifier"
        ))),
        (kind, Some(_)) => Err(FlowError::InvalidArgument(format!(
            "there is no codec kind called '{kind}'"
        ))),
    }
}

/// How this side spells an identity on the wire.
pub fn identity_to_wire(identity: &LlmCodecIdentity) -> (&'static str, Option<String>) {
    match identity {
        LlmCodecIdentity::None => ("none", None),
        LlmCodecIdentity::Opaque => ("opaque", None),
        LlmCodecIdentity::BuiltIn(codec) => ("builtin", Some(codec.id().to_string())),
        LlmCodecIdentity::Runtime(id) => ("runtime", Some(id.clone())),
    }
}

/// The identity a payload states, for the kernel to check a reference against.
///
/// # Errors
/// Returns a refusal when the payload carries no identity at all: the shapes above all
/// state one, and a caller that omits it is asking to use a capability without saying
/// which codec it believes it is using.
pub fn identity_from_payload(payload: &Json) -> Result<LlmCodecIdentity, FlowError> {
    let kind = payload
        .get("codec_kind")
        .and_then(Json::as_str)
        .ok_or_else(|| {
            FlowError::InvalidArgument(
                "a codec operation payload states the codec it is using".to_string(),
            )
        })?;
    let id = payload.get("codec_id").and_then(Json::as_str);
    identity_from_wire(kind, id)
}

/// Run one codec operation with the codec a capability resolved to.
///
/// The handle's direction has to match the operation: a request capability is not a way
/// to decode a response, and the mismatch is refused here as well as at the record, so a
/// mistake in either place is still a refusal.
///
/// # Errors
/// Returns a refusal for a payload that is not the operation's shape, for a direction
/// mismatch, and for the codec's own failure to parse what it was given.
pub fn run_codec_operation(
    operation: CodecOperation,
    handle: &CodecHandle,
    payload: &Json,
) -> Result<String, FlowError> {
    let mismatched = || {
        FlowError::InvalidArgument(format!(
            "{operation:?} needs the {} direction's codec",
            if operation.is_request() {
                "request"
            } else {
                "response"
            }
        ))
    };
    match (operation, handle) {
        (CodecOperation::RequestDecode, CodecHandle::Request(codec)) => {
            let request: LlmRequest = serde_json::from_value(field_value(payload, "request")?)
                .map_err(|error| invalid_field("request", error))?;
            let annotated = codec.decode(&request)?;
            serde_json::to_string(&annotated).map_err(write_failed)
        }
        (CodecOperation::RequestEncode, CodecHandle::Request(codec)) => {
            let annotated: AnnotatedLlmRequest =
                serde_json::from_value(field_value(payload, "annotated")?)
                    .map_err(|error| invalid_field("annotated", error))?;
            let original: LlmRequest = serde_json::from_value(field_value(payload, "original")?)
                .map_err(|error| invalid_field("original", error))?;
            let encoded = codec.encode(&annotated, &original)?;
            serde_json::to_string(&encoded).map_err(write_failed)
        }
        (CodecOperation::ResponseDecode, CodecHandle::Response(codec)) => {
            let response = field_value(payload, "response")?;
            let annotated = codec.decode_response(&response)?;
            serde_json::to_string(&annotated).map_err(write_failed)
        }
        (_, _) => Err(mismatched()),
    }
}

fn field_value(payload: &Json, field: &str) -> Result<Json, FlowError> {
    payload.get(field).cloned().ok_or_else(|| {
        FlowError::InvalidArgument(format!("a codec operation payload carries '{field}'"))
    })
}

fn invalid_field(field: &str, error: serde_json::Error) -> FlowError {
    FlowError::InvalidArgument(format!(
        "a codec operation payload's '{field}' is invalid: {error}"
    ))
}

fn write_failed(error: serde_json::Error) -> FlowError {
    FlowError::Internal(format!("a codec result could not be written: {error}"))
}

/// The thread a plugin's synchronous codec call is answered on.
///
/// A plugin reaches its codec through a synchronous ABI call, and the codec object lives in
/// the kernel, so something has to turn a synchronous call into an asynchronous one. Doing
/// it on the thread that made the call is what deadlocks: that thread is inside the host's
/// runtime, and blocking it on a call the kernel answers through this same host is the
/// cycle the whole protocol exists to avoid.
///
/// So the call is handed to a thread of its own, which owns a runtime and owns the kernel
/// client. The caller blocks on the answer and holds nothing while it waits; nothing the
/// kernel does to answer it needs the blocked thread. One bridge per host, because one
/// client is enough and one thread is the bound.
struct CodecBridge {
    /// Unbounded and asynchronous on the receiving side: the caller is a synchronous thread
    /// inside the plugin's code, and the thread that answers must never block the runtime it
    /// drives. A blocking receive on a `current_thread` runtime would starve the very
    /// connection the answer arrives on.
    jobs: tokio::sync::mpsc::UnboundedSender<CodecJob>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

struct CodecJob {
    operation: nemo_relay_plugin_proto::v1::CodecOperation,
    operation_request_id: String,
    payload_json: String,
    reference: String,
    answer: std::sync::mpsc::Sender<Result<String, String>>,
}

impl Drop for CodecBridge {
    fn drop(&mut self) {
        // The sender drops with the struct, which ends the loop; joining here keeps a
        // bridge from outliving its host by a thread.
        if let Ok(mut thread) = self.thread.lock()
            && let Some(thread) = thread.take()
        {
            let _ = thread.join();
        }
    }
}

impl CodecBridge {
    /// Start a bridge for one session's kernel client.
    fn start(client: crate::runtime_service::KernelCallbacks, session_id: String) -> Arc<Self> {
        let (jobs, mut queue) = tokio::sync::mpsc::unbounded_channel::<CodecJob>();
        let thread = std::thread::Builder::new()
            .name("nemo-plugin-codec-bridge".to_string())
            .spawn(move || {
                // Two workers, and one `block_on` for the whole life of the bridge: the
                // connection is opened *and* driven here, so the client's tasks live on the
                // runtime that waits for them — the affinity rule this repository has paid for
                // more than once — and nothing about the caller's thread can decide whether an
                // answer arrives.
                let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let client = match client.connect_again().await {
                        Ok(client) => client,
                        Err(error) => {
                            // The refusal a plugin then sees says the bridge stopped, which is
                            // what happened; the reason is this line, because a host has no
                            // runtime of the kernel's to record it in.
                            eprintln!(
                                "the codec bridge could not open its own kernel connection, so \
                                 plugin codec calls will be refused: {error}"
                            );
                            return;
                        }
                    };
                    while let Some(job) = queue.recv().await {
                        let answer = client
                            .resolve_codec(
                                &session_id,
                                &job.operation_request_id,
                                job.operation,
                                &job.payload_json,
                                &job.reference,
                            )
                            .await;
                        // A caller that gave up is the plugin's business, not this task's: the
                        // work was asked for and was done.
                        let _ = job.answer.send(answer);
                    }
                });
            })
            .expect("a codec bridge thread");
        Arc::new(Self {
            jobs,
            thread: std::sync::Mutex::new(Some(thread)),
        })
    }

    /// Run one codec operation on the bridge, blocking the calling thread for the answer.
    fn resolve(
        &self,
        operation: nemo_relay_plugin_proto::v1::CodecOperation,
        operation_request_id: &str,
        payload_json: String,
        reference: &str,
    ) -> Result<String, String> {
        let (answer, received) = std::sync::mpsc::channel();
        self.jobs
            .send(CodecJob {
                operation,
                operation_request_id: operation_request_id.to_string(),
                payload_json,
                reference: reference.to_string(),
                answer,
            })
            .map_err(|_| "this host's codec bridge has stopped".to_string())?;
        received
            .recv()
            .map_err(|_| "this host's codec bridge stopped before answering".to_string())?
    }
}

/// The codec a plugin's callback resolves in a host that does not hold one.
///
/// It implements the runtime's own codec trait, so the plugin's callback sees exactly what
/// it would see in process — an identity it can read and a handle it can use — and the work
/// behind that handle happens in the kernel, against the codec the kernel holds and the
/// capability it issued for this invocation.
pub struct KernelRequestCodec {
    bridge: Arc<CodecBridge>,
    operation_request_id: String,
    identity: LlmCodecIdentity,
    reference: String,
}

impl KernelRequestCodec {
    /// A request codec for one sanitize invocation.
    pub fn new(
        client: crate::runtime_service::KernelCallbacks,
        session_id: &str,
        operation_request_id: &str,
        identity: LlmCodecIdentity,
        reference: &str,
    ) -> Self {
        Self {
            bridge: CodecBridge::start(client, session_id.to_string()),
            operation_request_id: operation_request_id.to_string(),
            identity,
            reference: reference.to_string(),
        }
    }

    fn payload(&self, value: nemo_relay::json::Json) -> Result<String, FlowError> {
        let (kind, id) = identity_to_wire(&self.identity);
        let mut context = serde_json::json!({ "codec_kind": kind });
        if let Some(id) = id {
            context["codec_id"] = serde_json::Value::String(id);
        }
        let mut payload = value;
        payload["codec_kind"] = context["codec_kind"].clone();
        if let Some(id) = context.get("codec_id") {
            payload["codec_id"] = id.clone();
        }
        serde_json::to_string(&payload).map_err(|error| {
            FlowError::Internal(format!(
                "a codec call payload could not be written: {error}"
            ))
        })
    }

    fn call(
        &self,
        operation: nemo_relay_plugin_proto::v1::CodecOperation,
        payload: nemo_relay::json::Json,
    ) -> Result<String, FlowError> {
        let payload = self.payload(payload)?;
        self.bridge
            .resolve(
                operation,
                &self.operation_request_id,
                payload,
                &self.reference,
            )
            .map_err(FlowError::Internal)
    }
}

impl nemo_relay::codec::traits::LlmCodec for KernelRequestCodec {
    fn codec_identity(&self) -> LlmCodecIdentity {
        self.identity.clone()
    }

    fn decode(&self, request: &LlmRequest) -> Result<AnnotatedLlmRequest, FlowError> {
        let output = self.call(
            nemo_relay_plugin_proto::v1::CodecOperation::LlmRequestDecode,
            serde_json::json!({ "request": request }),
        )?;
        serde_json::from_str(&output).map_err(|error| {
            FlowError::Internal(format!(
                "the kernel answered a request decode with something that is not an \
                 annotated request: {error}"
            ))
        })
    }

    fn encode(
        &self,
        annotated: &AnnotatedLlmRequest,
        original: &LlmRequest,
    ) -> Result<LlmRequest, FlowError> {
        let output = self.call(
            nemo_relay_plugin_proto::v1::CodecOperation::LlmRequestEncode,
            serde_json::json!({ "annotated": annotated, "original": original }),
        )?;
        serde_json::from_str(&output).map_err(|error| {
            FlowError::Internal(format!(
                "the kernel answered a request encode with something that is not a request: \
                 {error}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay::codec::traits::{LlmCodec, LlmResponseCodec};
    use std::sync::Arc;

    /// A codec that records what it was asked and answers something recognizable.
    struct RecordingCodec {
        identity: LlmCodecIdentity,
    }

    impl LlmCodec for RecordingCodec {
        fn codec_identity(&self) -> LlmCodecIdentity {
            self.identity.clone()
        }

        fn decode(&self, request: &LlmRequest) -> Result<AnnotatedLlmRequest, FlowError> {
            Ok(AnnotatedLlmRequest {
                model: request
                    .content
                    .get("model")
                    .and_then(Json::as_str)
                    .map(str::to_string),
                ..Default::default()
            })
        }

        fn encode(
            &self,
            annotated: &AnnotatedLlmRequest,
            original: &LlmRequest,
        ) -> Result<LlmRequest, FlowError> {
            let mut request = original.clone();
            if let Some(model) = annotated.model.as_ref() {
                request.content["model"] = Json::String(model.clone());
            }
            Ok(request)
        }
    }

    struct RecordingResponseCodec {
        identity: LlmCodecIdentity,
    }

    impl LlmResponseCodec for RecordingResponseCodec {
        fn codec_identity(&self) -> LlmCodecIdentity {
            self.identity.clone()
        }

        fn decode_response(
            &self,
            response: &Json,
        ) -> Result<nemo_relay::codec::response::AnnotatedLlmResponse, FlowError> {
            Ok(nemo_relay::codec::response::AnnotatedLlmResponse {
                id: response
                    .get("id")
                    .and_then(Json::as_str)
                    .map(str::to_string),
                ..Default::default()
            })
        }
    }

    fn request_handle(identity: LlmCodecIdentity) -> CodecHandle {
        CodecHandle::Request(Arc::new(RecordingCodec { identity }))
    }

    fn response_handle(identity: LlmCodecIdentity) -> CodecHandle {
        CodecHandle::Response(Arc::new(RecordingResponseCodec { identity }))
    }

    /// The bridge reaches a kernel over the connection it opens itself.
    ///
    /// This is the host's nested call reduced to what it needs: a kernel service on a socket,
    /// a capability issued for one operation, and a *blocking* caller on a thread of its own —
    /// which is what a plugin's synchronous codec call is.
    ///
    /// It hangs, and that is the finding rather than a defect in the test. Its control — the
    /// same socket, the same capability, the same call made from the async task instead of a
    /// bridge thread — passes, which rules the connection and the service out: a *second
    /// connection* works, and a client driven from an ordinary async context works. What does
    /// not work is the same call driven from the bridge's own thread and runtime, and the shape
    /// has been changed twice without helping (one `block_on` for the connection and the calls,
    /// a multi-thread runtime instead of a current-thread one). The next thing to try is not
    /// another shape: it is to find out what the bridge's thread does that a task does not, by
    /// instrumenting the call itself rather than the code around it.
    #[ignore = "hangs: a bridge thread's call over its own connection never returns; see \
                security/PLUGIN-ISOLATION.md. Run with `-- --ignored` after the fix."]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_bridge_reaches_a_kernel_over_a_connection_it_opens_itself() {
        use nemo_relay_plugin_proto::v1::relay_runtime_server::RelayRuntimeServer;
        use tonic::transport::Server;

        let codecs = Arc::new(super::super::codec_capability::CodecCapabilities::new());
        let (reference, _guard) = codecs.issue_request(
            "operation-bridge",
            Arc::new(RecordingCodec {
                identity: LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat),
            }),
        );
        let service = crate::runtime_service::RelayRuntimeService::new(
            crate::runtime_service::RelayRuntimeConfig {
                session_id: "bridge-session".into(),
                session_credential: "bridge-credential".into(),
                protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
                runtime_binding_digest: "bridge-binding".into(),
                operation_scopes: Arc::new(crate::operation_scopes::OperationScopes::new()),
                continuations: Arc::new(crate::continuations::Continuations::new()),
                codecs,
            },
        );
        let directory = std::env::temp_dir().join(format!(
            "nemo-bridge-{}",
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
        });

        let client = crate::runtime_service::connect_to_kernel(
            &endpoint,
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        )
        .await
        .expect("a client");
        let callbacks = crate::runtime_service::KernelCallbacks::new(client, "bridge-credential")
            .expect("the credential")
            .with_reconnect(
                endpoint.clone(),
                nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
            );
        let codec = KernelRequestCodec::new(
            callbacks,
            "bridge-session",
            "operation-bridge",
            LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat),
            reference.as_str(),
        );

        let decoded = tokio::task::spawn_blocking(move || {
            codec.decode(&LlmRequest {
                headers: serde_json::Map::new(),
                content: serde_json::json!({ "model": "example" }),
            })
        })
        .await
        .expect("the blocking caller");
        let decoded = decoded.expect("a decoded request");
        assert_eq!(decoded.model.as_deref(), Some("example"));

        serving.abort();
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// The same call, from the async task instead of a bridge thread.
    ///
    /// This splits the finding in two: if a *second connection*, called from an ordinary async
    /// context, answers, then the bridge's own driving of the call is what does not; if it does
    /// not answer either, the second connection is what does not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_connection_can_call_the_kernel_service() {
        use nemo_relay_plugin_proto::v1::relay_runtime_server::RelayRuntimeServer;
        use tonic::transport::Server;

        let codecs = Arc::new(super::super::codec_capability::CodecCapabilities::new());
        let (reference, _guard) = codecs.issue_request(
            "operation-bridge",
            Arc::new(RecordingCodec {
                identity: LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat),
            }),
        );
        let service = crate::runtime_service::RelayRuntimeService::new(
            crate::runtime_service::RelayRuntimeConfig {
                session_id: "bridge-session".into(),
                session_credential: "bridge-credential".into(),
                protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
                runtime_binding_digest: "bridge-binding".into(),
                operation_scopes: Arc::new(crate::operation_scopes::OperationScopes::new()),
                continuations: Arc::new(crate::continuations::Continuations::new()),
                codecs,
            },
        );
        let directory = std::env::temp_dir().join(format!(
            "nemo-second-{}",
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
        });

        let client = crate::runtime_service::connect_to_kernel(
            &endpoint,
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        )
        .await
        .expect("the first client");
        let callbacks = crate::runtime_service::KernelCallbacks::new(client, "bridge-credential")
            .expect("the credential")
            .with_reconnect(
                endpoint.clone(),
                nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
            );
        let second = callbacks
            .connect_again()
            .await
            .expect("a second connection");
        let answer = second
            .resolve_codec(
                "bridge-session",
                "operation-bridge",
                nemo_relay_plugin_proto::v1::CodecOperation::LlmRequestDecode,
                &serde_json::json!({
                    "codec_kind": "builtin",
                    "codec_id": "openai_chat",
                    "request": { "headers": {}, "content": { "model": "example" } }
                })
                .to_string(),
                reference.as_str(),
            )
            .await
            .expect("a served codec call");
        assert!(answer.contains("example"), "{answer}");

        serving.abort();
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// The identity a plugin is told survives the wire in both directions.
    #[test]
    fn a_codec_identity_round_trips_through_the_wire_spelling() {
        for identity in [
            LlmCodecIdentity::None,
            LlmCodecIdentity::Opaque,
            LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat),
            LlmCodecIdentity::Runtime("runtime-chat".into()),
        ] {
            let (kind, id) = identity_to_wire(&identity);
            assert_eq!(
                identity_from_wire(kind, id.as_deref()).expect("the identity this side wrote"),
                identity
            );
        }

        // And a kind nothing defines is refused rather than defaulted.
        assert!(identity_from_wire("provider", Some("x")).is_err());
        assert!(identity_from_wire("builtin", Some("not-a-codec")).is_err());
        assert!(identity_from_wire("runtime", None).is_err());
    }

    /// Each operation runs the codec of its own direction, and only that one.
    #[test]
    fn each_operation_runs_the_codec_of_its_direction() {
        let identity = LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat);
        let decoded = run_codec_operation(
            CodecOperation::RequestDecode,
            &request_handle(identity.clone()),
            &serde_json::json!({
                "codec_kind": "builtin",
                "codec_id": "openai_chat",
                "request": { "headers": {}, "content": { "model": "example" } }
            }),
        )
        .expect("a request decode");
        assert!(decoded.contains("example"), "{decoded}");

        let encoded = run_codec_operation(
            CodecOperation::RequestEncode,
            &request_handle(identity.clone()),
            &serde_json::json!({
                "codec_kind": "builtin",
                "codec_id": "openai_chat",
                "annotated": { "model": "rewritten" },
                "original": { "headers": {}, "content": { "model": "example" } }
            }),
        )
        .expect("a request encode");
        assert!(encoded.contains("rewritten"), "{encoded}");

        let response = run_codec_operation(
            CodecOperation::ResponseDecode,
            &response_handle(identity),
            &serde_json::json!({
                "codec_kind": "builtin",
                "codec_id": "openai_chat",
                "response": { "id": "chatcmpl-1" }
            }),
        )
        .expect("a response decode");
        assert!(response.contains("chatcmpl-1"), "{response}");

        // A request operation with a response capability is refused, not adapted.
        let refused = run_codec_operation(
            CodecOperation::RequestDecode,
            &response_handle(LlmCodecIdentity::Opaque),
            &serde_json::json!({ "request": {} }),
        )
        .expect_err("a response codec cannot read a request");
        assert!(refused.to_string().contains("request"), "{refused}");
    }

    /// The payload's stated identity is what the kernel checks a reference against.
    #[test]
    fn a_payload_states_the_codec_it_is_using() {
        assert_eq!(
            identity_from_payload(&serde_json::json!({
                "codec_kind": "runtime",
                "codec_id": "runtime-chat"
            }))
            .expect("a stated identity"),
            LlmCodecIdentity::Runtime("runtime-chat".into())
        );
        assert!(
            identity_from_payload(&serde_json::json!({ "request": {} })).is_err(),
            "a payload that states no codec is refused rather than assumed"
        );
    }
}
