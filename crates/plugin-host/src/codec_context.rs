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
use nemo_relay::api::runtime::ExecutionBudget;
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
pub struct CodecBridge {
    /// Bounded, and asynchronous on the receiving side: the caller is a synchronous thread
    /// inside the plugin's code, and the thread that answers must never block the runtime it
    /// drives. A blocking receive on a `current_thread` runtime would starve the very
    /// connection the answer arrives on.
    ///
    /// Bounded because the work is a plugin's: a sanitizer that asks for codecs faster than
    /// the kernel answers would otherwise grow this queue without limit, and the bound is
    /// what makes that a refusal the plugin's callback sees rather than memory nobody chose.
    ///
    /// `Option` so the drop below can give the sender up *before* it waits: the thread's
    /// `recv` returns nothing only once no sender is left, and joining first is a hang of the
    /// dropper's own making — which is exactly what this cost once.
    jobs: Option<tokio::sync::mpsc::Sender<CodecJob>>,
    /// The real bound: one permit per codec call that may exist at once.
    ///
    /// The channel bounds what is *waiting to be received*, which is not the same
    /// number, and that was the defect an audit found here: the consumer receives as
    /// fast as it can and hands each job to a task, so a slow kernel could leave a
    /// full queue behind and any number of running calls behind that. A permit is
    /// taken at admission and travels with the job, so it is released when the call
    /// *ends* rather than when it starts — which is what "calls in flight" has to
    /// mean for the refusal to be a bound rather than a coincidence.
    in_flight: Arc<tokio::sync::Semaphore>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

struct CodecJob {
    operation: nemo_relay_plugin_proto::v1::CodecOperation,
    operation_request_id: String,
    payload_json: String,
    reference: String,
    /// What is left of the invocation that asked for this codec call.
    ///
    /// Carried on the job rather than read when the job runs, because the job
    /// waits its turn: the budget belongs to the call that asked, not to the
    /// moment a thread got to it.
    budget: ExecutionBudget,
    answer: std::sync::mpsc::Sender<Result<String, String>>,
    /// Held from admission until the answer is sent, so the call counts as in flight.
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for CodecBridge {
    fn drop(&mut self) {
        // Give the sender up first: that is what ends the loop, and joining before it is a
        // hang the dropper builds for itself. Then join, so a bridge cannot outlive its host
        // by a thread.
        drop(self.jobs.take());
        if let Ok(mut thread) = self.thread.lock()
            && let Some(thread) = thread.take()
        {
            let _ = thread.join();
        }
    }
}

impl CodecBridge {
    /// Start a bridge for one session's kernel client.
    ///
    /// Fallible rather than infallible, because the thread and the runtime it
    /// owns can be refused by the operating system, and a host that cannot create
    /// them has to say so: the caller is a plugin's callback, and a panic here
    /// would take the host down with a plugin's codec call.
    pub fn start(
        client: crate::runtime_service::KernelCallbacks,
        session_id: String,
    ) -> Result<Arc<Self>, String> {
        let (jobs, mut queue) = tokio::sync::mpsc::channel::<CodecJob>(CODEC_BRIDGE_QUEUE_CAPACITY);
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
                        // Each call is a *task* rather than the future this `block_on` is
                        // driving. Two reasons, and the second is the one that was measured:
                        // two plugin callbacks can want the codec at once, and a call driven as
                        // the `block_on` future itself did not come back, while the same call
                        // driven from a task does.
                        let client = client.clone();
                        let session_id = session_id.clone();
                        tokio::spawn(async move {
                            // Bounded by what the plugin's own call had left, for the
                            // reason the whole boundary is bounded: the kernel is asked to
                            // do work on behalf of a call that may already be over, and a
                            // kernel that does not answer is not an answer. The remaining
                            // budget is read here rather than taken from the job unchanged,
                            // because the time this job spent queued is time the call spent.
                            let now = nemo_relay::api::runtime::budget_now_unix_ms();
                            let remaining = job
                                .budget
                                .narrowed_to(u64::MAX, now)
                                .remaining_budget_millis;
                            let answer = match tokio::time::timeout(
                                std::time::Duration::from_millis(remaining),
                                client.resolve_codec(
                                    &session_id,
                                    &job.operation_request_id,
                                    job.operation,
                                    &job.payload_json,
                                    &job.reference,
                                ),
                            )
                            .await
                            {
                                Ok(answer) => answer,
                                Err(_) => Err(
                                    "the kernel did not answer this codec call within what was \
                                     left of the operation's budget"
                                        .to_string(),
                                ),
                            };
                            // A caller that gave up is the plugin's business, not this task's:
                            // the work was asked for and was done.
                            let _ = job.answer.send(answer);
                        });
                    }
                });
            })
            .map_err(|error| format!("the codec bridge thread could not start: {error}"))?;
        Ok(Arc::new(Self {
            jobs: Some(jobs),
            in_flight: Arc::new(tokio::sync::Semaphore::new(CODEC_BRIDGE_QUEUE_CAPACITY)),
            thread: std::sync::Mutex::new(Some(thread)),
        }))
    }

    /// Take one in-flight permit, or refuse the call by name.
    ///
    /// The refusal names the bound rather than the transport, because the two are
    /// different facts to a plugin: a full bridge is this host asking the plugin to
    /// slow down, and a stopped bridge is this host telling it that nothing will be
    /// answered.
    fn try_admit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, String> {
        Arc::clone(&self.in_flight)
            .try_acquire_owned()
            .map_err(|_| {
                format!(
                    "this host's codec bridge is at its limit of {} calls in flight, so this \
                     plugin's codec call was refused rather than queued",
                    CODEC_BRIDGE_QUEUE_CAPACITY
                )
            })
    }

    /// Run one codec operation on the bridge, blocking the calling thread for the answer.
    fn resolve(
        &self,
        operation: nemo_relay_plugin_proto::v1::CodecOperation,
        operation_request_id: &str,
        payload_json: String,
        reference: &str,
        budget: ExecutionBudget,
    ) -> Result<String, String> {
        // Refused before it is queued, and refused by name: a codec call that
        // arrives with nothing left is not a transport failure and not a bad
        // reference, it is work for a call the kernel has stopped waiting for.
        // Sending it would ask the kernel to do it anyway, which is the thing the
        // inherited budget exists to prevent.
        let now = nemo_relay::api::runtime::budget_now_unix_ms();
        let deadline = budget.deadline_unix_ms.unwrap_or(u64::MAX);
        if nemo_relay_plugin_protocol::deadline_expired(deadline, now) {
            return Err(
                "the operation's deadline had already passed, so this codec call was refused \
                 rather than sent"
                    .to_string(),
            );
        }
        let (answer, received) = std::sync::mpsc::channel();
        // Admission is the bound, and it happens before the job exists: a call that
        // cannot be admitted is refused to the plugin's callback rather than queued
        // for a thread that is already as busy as it is allowed to be.
        let permit = self.try_admit()?;
        let Some(jobs) = self.jobs.as_ref() else {
            return Err("this host's codec bridge has stopped".to_string());
        };
        jobs.try_send(CodecJob {
            operation,
            operation_request_id: operation_request_id.to_string(),
            payload_json,
            reference: reference.to_string(),
            budget,
            answer,
            _permit: permit,
        })
        .map_err(|error| match error {
            tokio::sync::mpsc::error::TrySendError::Full(_) => format!(
                "this host's codec bridge is at its limit of {} calls in flight, so this \
                 plugin's codec call was refused rather than queued",
                CODEC_BRIDGE_QUEUE_CAPACITY
            ),
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                "this host's codec bridge has stopped".to_string()
            }
        })?;
        received
            .recv()
            .map_err(|_| "this host's codec bridge stopped before answering".to_string())?
    }
}

/// How many codec calls one host may have in flight at once.
///
/// The number a plugin's own callback concurrency is bounded by, chosen the way
/// the activation queue was: large enough for a busy host's ordinary overlap, and
/// small enough that "a plugin asked for more" is a refusal rather than a queue
/// this process grows for it.
pub(crate) const CODEC_BRIDGE_QUEUE_CAPACITY: usize = 16;

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
    /// What is left of the invocation this codec belongs to.
    budget: ExecutionBudget,
}

impl KernelRequestCodec {
    /// A request codec for one sanitize invocation, on the host's own bridge.
    ///
    /// The bridge is passed in rather than started here: it owns a thread, a
    /// runtime and a kernel connection, and a host that started one per sanitize
    /// invocation would hold as many of those as it has concurrent sanitizers —
    /// under load, hundreds of threads for work that one bridge answers.
    pub fn new(
        bridge: Arc<CodecBridge>,
        operation_request_id: &str,
        identity: LlmCodecIdentity,
        reference: &str,
        budget: ExecutionBudget,
    ) -> Self {
        Self {
            bridge,
            operation_request_id: operation_request_id.to_string(),
            identity,
            reference: reference.to_string(),
            budget,
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
                self.budget,
            )
            .map_err(FlowError::Internal)
    }
}

/// The response direction's twin: the codec a plugin resolves in a host that holds none.
///
/// The two directions are different traits on this side, and this is the other one: a response
/// codec decodes and does not encode, so a capability issued for a request is not a weaker
/// capability here — it is a different one, and the kernel checks that rather than assuming it.
pub struct KernelResponseCodec {
    bridge: Arc<CodecBridge>,
    operation_request_id: String,
    identity: LlmCodecIdentity,
    reference: String,
    /// What is left of the invocation this codec belongs to.
    budget: ExecutionBudget,
}

impl KernelResponseCodec {
    /// A response codec for one sanitize invocation.
    pub fn new(
        bridge: Arc<CodecBridge>,
        operation_request_id: &str,
        identity: LlmCodecIdentity,
        reference: &str,
        budget: ExecutionBudget,
    ) -> Self {
        Self {
            bridge,
            operation_request_id: operation_request_id.to_string(),
            identity,
            reference: reference.to_string(),
            budget,
        }
    }
}

impl nemo_relay::codec::traits::LlmResponseCodec for KernelResponseCodec {
    fn codec_identity(&self) -> LlmCodecIdentity {
        self.identity.clone()
    }

    fn decode_response(
        &self,
        response: &nemo_relay::json::Json,
    ) -> Result<nemo_relay::codec::response::AnnotatedLlmResponse, FlowError> {
        let (kind, id) = identity_to_wire(&self.identity);
        let mut payload = serde_json::json!({ "response": response, "codec_kind": kind });
        if let Some(id) = id {
            payload["codec_id"] = serde_json::Value::String(id);
        }
        let payload = serde_json::to_string(&payload).map_err(|error| {
            FlowError::Internal(format!(
                "a codec call payload could not be written: {error}"
            ))
        })?;
        let output = self
            .bridge
            .resolve(
                nemo_relay_plugin_proto::v1::CodecOperation::LlmResponseDecode,
                &self.operation_request_id,
                payload,
                &self.reference,
                self.budget,
            )
            .map_err(FlowError::Internal)?;
        serde_json::from_str(&output).map_err(|error| {
            FlowError::Internal(format!(
                "the kernel answered a response decode with something that is not an \
                 annotated response: {error}"
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

    /// A budget with time left in it, for the tests that are not about time.
    fn live_budget() -> ExecutionBudget {
        let now = nemo_relay::api::runtime::budget_now_unix_ms();
        ExecutionBudget::new(now + 30_000, 30_000)
    }

    /// A request codec that answers the way `RecordingCodec` does, after taking
    /// longer about it than the budget a caller states.
    struct SlowRequestCodec {
        identity: LlmCodecIdentity,
        takes: std::time::Duration,
    }

    impl LlmCodec for SlowRequestCodec {
        fn codec_identity(&self) -> LlmCodecIdentity {
            self.identity.clone()
        }

        fn decode(&self, _request: &LlmRequest) -> Result<AnnotatedLlmRequest, FlowError> {
            std::thread::sleep(self.takes);
            Ok(AnnotatedLlmRequest::default())
        }

        fn encode(
            &self,
            _annotated: &AnnotatedLlmRequest,
            original: &LlmRequest,
        ) -> Result<LlmRequest, FlowError> {
            Ok(original.clone())
        }
    }

    /// A deadline no test here outlives, for issuing a capability a test is not
    /// about the lifetime of.
    const LIVE: u64 = u64::MAX;

    fn response_handle(identity: LlmCodecIdentity) -> CodecHandle {
        CodecHandle::Response(Arc::new(RecordingResponseCodec { identity }))
    }

    /// The bridge reaches a kernel over the connection it opens itself.
    ///
    /// This is the host's nested call reduced to what it needs: a kernel service on a socket,
    /// a capability issued for one operation, and a *blocking* caller on a thread of its own —
    /// which is what a plugin's synchronous codec call is.
    ///
    /// It hung, and finding out why is what this pair of tests is for. Its control — the same
    /// socket, the same capability, the same call made from the async task instead of a bridge
    /// thread — passed, which ruled out the connection, the service and the codec. Instrumenting
    /// the call itself then showed the whole round trip completing, which left only the code
    /// *around* it: `CodecBridge::drop` joined the thread before giving up the sender, so the
    /// thread's `recv` never ended and the dropper waited on a thread waiting on the dropper.
    /// The bridge passed every call and hung on its own teardown, and the sanitize invocation
    /// that was waiting for the answer read that as a timeout. The drop now gives the sender up
    /// first, and this test is the regression for it.
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
            LIVE,
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
            CodecBridge::start(callbacks, "bridge-session".to_string()).expect("a bridge"),
            "operation-bridge",
            LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat),
            reference.as_str(),
            live_budget(),
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

    /// A codec call is bounded by what the invocation had left, and the bound is
    /// the bridge's rather than the caller's: the connection, the service and the
    /// codec are all live here — the codec deliberately takes longer than the
    /// budget — and what the plugin's callback gets back is the deadline rather
    /// than an answer that arrived when nobody was waiting for it.
    ///
    /// The socket is the same shape as the pair above, which is what makes this a
    /// test of the budget rather than of the transport: the round trip works, and
    /// it works for longer than the call it belongs to.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_codec_call_that_outlives_its_invocations_budget_is_refused() {
        use nemo_relay_plugin_proto::v1::relay_runtime_server::RelayRuntimeServer;
        use tonic::transport::Server;

        let codecs = Arc::new(super::super::codec_capability::CodecCapabilities::new());
        let (reference, _guard) = codecs.issue_request(
            "operation-bridge",
            Arc::new(SlowRequestCodec {
                identity: LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat),
                takes: std::time::Duration::from_millis(300),
            }),
            LIVE,
        );
        let service = crate::runtime_service::RelayRuntimeService::new(
            crate::runtime_service::RelayRuntimeConfig {
                session_id: "slow-bridge-session".into(),
                session_credential: "slow-bridge-credential".into(),
                protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
                runtime_binding_digest: "slow-bridge-binding".into(),
                operation_scopes: Arc::new(crate::operation_scopes::OperationScopes::new()),
                continuations: Arc::new(crate::continuations::Continuations::new()),
                codecs,
            },
        );
        let directory = std::env::temp_dir().join(format!(
            "nemo-slow-bridge-{}",
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
        let callbacks =
            crate::runtime_service::KernelCallbacks::new(client, "slow-bridge-credential")
                .expect("the credential")
                .with_reconnect(
                    endpoint.clone(),
                    nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
                );
        let millis = 50_u64;
        let now = nemo_relay::api::runtime::budget_now_unix_ms();
        let codec = KernelRequestCodec::new(
            CodecBridge::start(callbacks, "slow-bridge-session".to_string()).expect("a bridge"),
            "operation-bridge",
            LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat),
            reference.as_str(),
            ExecutionBudget::new(now + millis, millis),
        );

        let refused = tokio::task::spawn_blocking(move || {
            codec.decode(&LlmRequest {
                headers: serde_json::Map::new(),
                content: serde_json::json!({ "model": "example" }),
            })
        })
        .await
        .expect("the blocking caller")
        .expect_err("a call the operation had no time left to wait for");
        let message = refused.to_string();
        assert!(
            message.contains("within what was left of the operation's budget"),
            "the refusal does not name the budget: {message}"
        );

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
            LIVE,
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

    /// The bridge admits a bounded number of calls and refuses the rest.
    ///
    /// A codec call is part of the invocation that asked for it, so one that
    /// arrives with nothing left of that invocation's budget is refused here:
    /// before it is queued, and before the kernel is asked to do anything.
    ///
    /// The bridge's consumer is dropped, and that is what makes "before" the thing
    /// being checked rather than a claim: a call that reached the queue would come
    /// back with the bridge's own refusal instead of the deadline's, and this test
    /// would read as the opposite of what it says.
    #[test]
    fn a_codec_call_with_no_budget_left_is_refused_before_it_is_sent() {
        let (jobs, consumer) = tokio::sync::mpsc::channel::<CodecJob>(CODEC_BRIDGE_QUEUE_CAPACITY);
        drop(consumer);
        let bridge = CodecBridge {
            jobs: Some(jobs),
            in_flight: Arc::new(tokio::sync::Semaphore::new(CODEC_BRIDGE_QUEUE_CAPACITY)),
            thread: std::sync::Mutex::new(None),
        };

        let refused = bridge
            .resolve(
                nemo_relay_plugin_proto::v1::CodecOperation::LlmRequestDecode,
                "operation-1",
                "{}".to_string(),
                "reference",
                ExecutionBudget::expired(),
            )
            .expect_err("a call with no time left is refused");

        assert!(
            refused.contains("deadline had already passed"),
            "the refusal does not name the deadline: {refused}"
        );
    }

    /// The bridge admits a bounded number of calls, and the bound is the calls
    /// themselves rather than the queue they pass through.
    ///
    /// This is the property an audit found to be false: the channel was bounded, but
    /// its consumer received as fast as it could and handed each job to a task, so a
    /// slow kernel could leave a full queue behind and any number of running calls
    /// behind that. Admission is what `resolve` does before it builds a job, so
    /// holding the permits here is the same state a slow kernel produces — sixteen
    /// calls in flight, and a seventeenth that has to be refused rather than queued.
    #[test]
    fn the_codec_bridge_admits_only_its_bound_worth_of_calls() {
        let (jobs, _never_drained) =
            tokio::sync::mpsc::channel::<CodecJob>(CODEC_BRIDGE_QUEUE_CAPACITY);
        let bridge = CodecBridge {
            jobs: Some(jobs),
            in_flight: Arc::new(tokio::sync::Semaphore::new(CODEC_BRIDGE_QUEUE_CAPACITY)),
            thread: std::sync::Mutex::new(None),
        };

        let held: Vec<_> = (0..CODEC_BRIDGE_QUEUE_CAPACITY)
            .map(|_| bridge.try_admit().expect("within the bound"))
            .collect();
        let refused = bridge
            .try_admit()
            .expect_err("one more than the bound is refused");
        assert!(
            refused.contains(&format!(
                "limit of {CODEC_BRIDGE_QUEUE_CAPACITY} calls in flight"
            )),
            "the refusal does not name the bound: {refused}"
        );

        // A call that finishes gives its permit back, so the next one is admitted:
        // the bound is a limit on concurrency rather than a budget for a lifetime.
        drop(held);
        let _ = bridge.try_admit().expect("a finished call makes room");
    }

    /// The bound holds across the boundary the real path crosses.
    ///
    /// The property is not only that one thread can count to sixteen: a call's permit
    /// is taken on the plugin's thread and lives until the *task* that answers it
    /// finishes, so the assertion has to survive the permit being moved to another
    /// thread and held there. This is the deterministic shape of that, and it is what
    /// the slow-kernel qualification would show if a harness could hold the window
    /// open: see the note in the milestone document for why that one is not here yet.
    #[test]
    fn the_admission_bound_survives_the_task_boundary() {
        let (jobs, _never_drained) =
            tokio::sync::mpsc::channel::<CodecJob>(CODEC_BRIDGE_QUEUE_CAPACITY);
        let bridge = CodecBridge {
            jobs: Some(jobs),
            in_flight: Arc::new(tokio::sync::Semaphore::new(CODEC_BRIDGE_QUEUE_CAPACITY)),
            thread: std::sync::Mutex::new(None),
        };

        let held: Vec<_> = (0..CODEC_BRIDGE_QUEUE_CAPACITY)
            .map(|_| bridge.try_admit().expect("within the bound"))
            .collect();
        // The bridge's consumer hands each permit to the task that answers the call, on
        // its own runtime. Handing them to a thread of this test's own is the same move
        // without the kernel: what crosses is the permit, and the bound crosses with it.
        let held = std::thread::spawn(move || held)
            .join()
            .expect("the permits moved to another thread and back");
        assert_eq!(
            bridge.in_flight.available_permits(),
            0,
            "sixteen live calls must hold every permit"
        );
        assert!(
            bridge.try_admit().is_err(),
            "a seventeenth call is refused while sixteen permits are held elsewhere"
        );

        drop(held);
        let _ = bridge.try_admit().expect("a finished call makes room");
    }

    /// A consumer that drains the channel does not remove the bound.
    ///
    /// This is the v13 defect in one test, without a kernel. The old bridge bounded a
    /// channel and then received as fast as it could, handing each job to a task — so
    /// the channel's capacity said nothing about how many calls were running, and a slow
    /// kernel could leave the queue empty and any number of calls behind it. The consumer
    /// here does exactly that: it drains every job and *holds* it, which is the state the
    /// old design could not survive. Sixteen calls are admitted and wait, the seventeenth
    /// is refused, and the refusal comes back immediately — a call that was admitted
    /// instead would block here, and the receive below is what says it did not.
    ///
    /// The end-to-end variant — a real kernel whose codec answers slowly — was attempted
    /// and is recorded in the milestone document rather than committed: its two
    /// instruments contradicted each other, and this shape tests the same property
    /// without depending on which of them was wrong.
    #[test]
    fn a_consumer_that_drains_the_channel_does_not_remove_the_bound() {
        let (jobs, mut queue) = tokio::sync::mpsc::channel::<CodecJob>(CODEC_BRIDGE_QUEUE_CAPACITY);
        let bridge = Arc::new(CodecBridge {
            jobs: Some(jobs),
            in_flight: Arc::new(tokio::sync::Semaphore::new(CODEC_BRIDGE_QUEUE_CAPACITY)),
            thread: std::sync::Mutex::new(None),
        });
        let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let consumer = {
            let received = Arc::clone(&received);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut held = Vec::new();
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    match queue.try_recv() {
                        Ok(job) => {
                            received.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            held.push(job);
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                // Dropped here rather than returned: a thread's return value lives in its
                // `JoinHandle` until somebody joins it, and a caller waiting on an answer
                // would wait for that too. Dropping the jobs *in* the thread is what makes
                // the release independent of when the test gets around to joining.
                drop(held);
            })
        };

        let callers: Vec<_> = (0..CODEC_BRIDGE_QUEUE_CAPACITY)
            .map(|_| {
                let bridge = Arc::clone(&bridge);
                std::thread::spawn(move || {
                    bridge.resolve(
                        nemo_relay_plugin_proto::v1::CodecOperation::LlmRequestDecode,
                        "operation-drained",
                        "{}".to_string(),
                        "reference",
                        live_budget(),
                    )
                })
            })
            .collect();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while received.load(std::sync::atomic::Ordering::SeqCst) < CODEC_BRIDGE_QUEUE_CAPACITY
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(
            received.load(std::sync::atomic::Ordering::SeqCst),
            CODEC_BRIDGE_QUEUE_CAPACITY,
            "the consumer did not take the whole bound"
        );
        assert_eq!(
            bridge.in_flight.available_permits(),
            0,
            "sixteen held jobs must hold every permit"
        );

        let (outcome_tx, outcome_rx) = std::sync::mpsc::channel();
        {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || {
                let outcome = bridge.resolve(
                    nemo_relay_plugin_proto::v1::CodecOperation::LlmRequestDecode,
                    "operation-drained",
                    "{}".to_string(),
                    "reference",
                    live_budget(),
                );
                let _ = outcome_tx.send(outcome);
            });
        }
        let outcome = outcome_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("a call beyond the bound is refused rather than made to wait");
        let refused = outcome.expect_err("a call beyond the bound is refused");
        assert!(
            refused.contains(&format!(
                "limit of {CODEC_BRIDGE_QUEUE_CAPACITY} calls in flight"
            )),
            "the refusal does not name the bound: {refused}"
        );

        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for caller in callers {
            let joined = caller.join().expect("a joined caller");
            assert!(
                joined.is_err(),
                "a call whose consumer let go must fail rather than answer: {joined:?}"
            );
        }
        let _ = consumer.join();
    }

    /// The queue is bounded too, and by the same number.
    ///
    /// This is the weaker of the two: it proves the channel's capacity, which is not
    /// the property the bridge claims — see the admission test above for that. It is
    /// kept because the two bounds are separate facts and a future change could keep
    /// one while losing the other.
    #[test]
    fn the_codec_bridge_queue_is_bounded() {
        let (jobs, _never_drained) =
            tokio::sync::mpsc::channel::<CodecJob>(CODEC_BRIDGE_QUEUE_CAPACITY);
        let bridge = CodecBridge {
            jobs: Some(jobs),
            in_flight: Arc::new(tokio::sync::Semaphore::new(CODEC_BRIDGE_QUEUE_CAPACITY)),
            thread: std::sync::Mutex::new(None),
        };
        // The jobs carry permits this test hands out generously: the property here is
        // the channel's capacity, and admission is the test above's subject.
        let permits = Arc::new(tokio::sync::Semaphore::new(CODEC_BRIDGE_QUEUE_CAPACITY + 1));
        let job = |operation_request_id: &str| {
            let (answer, _received) = std::sync::mpsc::channel();
            CodecJob {
                operation: nemo_relay_plugin_proto::v1::CodecOperation::LlmRequestDecode,
                operation_request_id: operation_request_id.to_string(),
                payload_json: "{}".to_string(),
                reference: "reference".to_string(),
                budget: live_budget(),
                answer,
                _permit: Arc::clone(&permits)
                    .try_acquire_owned()
                    .expect("a permit for the test's own bookkeeping"),
            }
        };

        for index in 0..CODEC_BRIDGE_QUEUE_CAPACITY {
            bridge
                .jobs
                .as_ref()
                .expect("a bridge")
                .try_send(job(&format!("call-{index}")))
                .expect("the queue has room up to its capacity");
        }
        let refused = bridge
            .jobs
            .as_ref()
            .expect("a bridge")
            .try_send(job("one-too-many"))
            .expect_err("the queue is full");
        assert!(
            matches!(refused, tokio::sync::mpsc::error::TrySendError::Full(_)),
            "the queue refused for a reason other than being full"
        );
    }
}
