// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stable contract for executing native plugins outside the kernel process.
//!
//! Native plugins are loaded by an unsafe dynamic loader, and that loader holds
//! almost all of the kernel's `unsafe`. Moving it into another crate inside the
//! same process would reorganise the source without moving the trust boundary: a
//! memory-corruption bug in the loader would still corrupt the kernel. The
//! destination is therefore a separate process reached through this contract —
//! the kernel owns the interface, the runtime supplies the implementation, and
//! dynamic loading happens on the far side of the boundary.
//!
//! This crate is the vocabulary only. It defines the operations, the identities
//! they act on, the structured failures, and the version handshake that lets a
//! mismatch fail closed. It deliberately ships no loader, no transport, and no
//! `unsafe`: the implementation stays where it is until the increment that moves
//! it can be reviewed on its own.
//!
//! The kernel depends on this crate, and on it only as an interface: the plugin
//! execution module names these types and enforces the deadline rule in front of
//! every backend, while the loader and the transport stay behind the boundary.

use serde::{Deserialize, Serialize};

pub use nemo_relay_types::api::event::{DataSchema, LogSeverity};
pub use nemo_relay_types::api::scope::ScopeType;
pub use nemo_relay_types::execution::{DispatchState, OutcomeCertainty};
pub use uuid::Uuid;

/// The exact attachment point a registration installs itself at.
///
/// This is the runtime's own vocabulary rather than a second enum of the same
/// sixteen values. Two lists describing one set of attachment points would drift,
/// and the drift would appear as a proxy installed at the wrong point — the
/// failure this field exists to make impossible. Re-exporting also means the
/// loader can report what it registered without this crate having to describe
/// the runtime to it.
pub use nemo_relay_types::api::registry::RuntimeRegistrationKind as PluginRegistrationOperation;

/// Version of the wire contract.
///
/// Bumped whenever any type below changes shape, because the two sides of the
/// boundary are separate processes that may be deployed independently.
pub const PROTOCOL_VERSION: u16 = 1;

/// Largest framed message either side will accept.
///
/// A hostile or broken peer must not be able to make the other side allocate
/// without bound, so the limit is part of the contract rather than a transport
/// detail.
pub const MAX_FRAME_BYTES: u32 = 8 * 1024 * 1024;

/// Stable identity of one loaded plugin instance.
///
/// `generation` exists for the same reason leases carry one: a handle from a
/// previous load must not be able to address a later instance that reused the
/// identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginHandle {
    /// Deployment-chosen identifier for the plugin.
    pub plugin_id: String,
    /// Monotonic generation, incremented on every load of this plugin.
    pub generation: u64,
}

/// What a plugin declares about itself once loaded.
///
/// Every field that the host may genuinely not know is optional rather than
/// defaulted. An empty string is a claim; `None` is the truth, and the
/// difference matters because these values feed capability identity. The
/// negotiated ABI version in particular is what the loaded library declared,
/// never the host's maximum supported version — reporting the maximum would
/// invent a guarantee the plugin never made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginDescriptor {
    /// Deployment-chosen identifier the plugin was loaded under.
    pub plugin_id: String,
    /// Version the plugin reports for itself, when it reports one.
    pub plugin_version: Option<String>,
    /// ABI version negotiated with the loaded library, when it declared one.
    pub negotiated_abi_version: Option<u16>,
    /// Digest of the manifest the plugin was loaded from, when one was read.
    pub manifest_digest: Option<String>,
    /// Plugin kinds the host registered on the plugin's behalf.
    pub registration_kinds: Vec<String>,
    /// What each registration installs, so a proxy can be built from it.
    pub registrations: Vec<PluginRegistrationDescriptor>,
    /// Capabilities the plugin offers.
    pub capabilities: Vec<PluginCapability>,
}

/// How a registration sits relative to others in its class.
///
/// Both fields are optional because the native ABI declares them for some
/// registrations and not others: a subscriber carries no priority, and only the
/// intercept and middleware hooks say whether a callback may break its chain. A
/// default here would be a claim nobody made, and this descriptor exists so the
/// side building a proxy knows what the plugin actually declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRegistrationOrdering {
    /// Lower runs first, when the registration declares an order.
    pub priority: Option<i32>,
    /// Whether it may stop the chain it is part of, when that is declared.
    pub may_break_chain: Option<bool>,
}

/// Whether a registration answers once or streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginExecutionShape {
    /// One request, one response.
    Unary,
    /// One request, a sequence of responses.
    Streaming,
}

/// The shape a registration at this attachment point has.
///
/// Derived rather than asserted, because the shape is a property of the
/// attachment point: exactly one attachment point streams today, and a host
/// reporting a streaming callback anywhere else would be describing something
/// the runtime does not have.
pub fn registration_shape(operation: PluginRegistrationOperation) -> PluginExecutionShape {
    use PluginRegistrationOperation as Operation;
    match operation {
        Operation::Subscriber
        | Operation::EventMetadataInjector
        | Operation::MarkSanitizeGuardrail
        | Operation::ScopeSanitizeStartGuardrail
        | Operation::ScopeSanitizeEndGuardrail
        | Operation::ToolSanitizeRequestGuardrail
        | Operation::ToolSanitizeResponseGuardrail
        | Operation::ToolConditionalExecutionGuardrail
        | Operation::ToolRequestIntercept
        | Operation::ToolExecutionIntercept
        | Operation::LlmSanitizeRequestGuardrail
        | Operation::LlmSanitizeResponseGuardrail
        | Operation::LlmConditionalExecutionGuardrail
        | Operation::LlmRequestIntercept
        | Operation::LlmExecutionIntercept => PluginExecutionShape::Unary,
        Operation::LlmStreamExecutionIntercept => PluginExecutionShape::Streaming,
    }
}

/// Everything the kernel needs to re-create one registration as a proxy.
///
/// A loaded plugin is not a single thing the kernel invokes: it registers
/// components that the runtime then calls, and each installs itself at an exact
/// attachment point with an order and a shape of its own. A process host cannot
/// hand back local objects, so it hands back this description and the runtime
/// builds a proxy from it. "It registered a guardrail" is not enough to build
/// anything: without the attachment point the kernel knows that something
/// exists but not where to install it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRegistrationDescriptor {
    /// Identity of this registration in the runtime's namespace.
    ///
    /// The qualified name rather than the name the plugin authored: the runtime
    /// qualifies plugin-local names with the component namespace so two
    /// components of one plugin cannot collide, and the qualified name is what
    /// gates match and ordering applies to.
    pub registration_id: String,
    /// Component kind that made this registration.
    pub component_kind: String,
    /// The exact attachment point this registration installs itself at.
    pub operation: PluginRegistrationOperation,
    /// Where it sits relative to others, as far as it declares.
    pub ordering: PluginRegistrationOrdering,
    /// Whether its callback answers once or streams.
    pub shape: PluginExecutionShape,
    /// The registration this one gates, when it is a gate.
    ///
    /// A conditional middleware guardrail is not a component at an attachment
    /// point: it decides whether another registration runs. The name is the one
    /// the plugin supplied, which the runtime matches against the qualified
    /// registration name, so a gate whose target does not exist matches nothing
    /// rather than installing nothing. Describing a gate without its target
    /// would leave a proxy that gates nothing.
    pub gated_registration: Option<String>,
    /// Configuration keys the component reads.
    pub config_keys: Vec<String>,
    /// Digest the plugin declares, when it declares one.
    pub declared_digest: Option<String>,
}

/// One capability a plugin offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginCapability {
    /// Capability identifier.
    pub id: String,
    /// What kind of runtime work this capability performs.
    pub kind: PluginCapabilityKind,
    /// Digest of the capability's declared shape, when the plugin supplies one.
    ///
    /// A digest that the plugin supplies proves only that the plugin has not
    /// changed its claim since it was loaded. Deriving it from a canonical
    /// descriptor on the kernel side is a later concern, and this field is
    /// deliberately named so that is not mistaken for something it is not.
    pub declared_digest: Option<String>,
}

/// Kind of runtime work a capability performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapabilityKind {
    /// Intercepts or provides a tool.
    Tool,
    /// Intercepts or provides an LLM call.
    Llm,
    /// Observes events without changing them.
    Subscriber,
}

/// First message either side sends, carrying the version it speaks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginHandshake {
    /// Protocol version the sender implements.
    pub protocol_version: u16,
}

/// The session a handshake established.
///
/// Returned rather than asserted, because the host is the only party that knows
/// which process it is and the kernel is the only party that can check the
/// frame limit it offers. Nothing here is a claim the kernel simply adopts:
/// `host_instance_id` and `host_nonce` exist so that a restarted host cannot be
/// mistaken for the one an open session belongs to, and `maximum_frame_bytes`
/// is compared against the kernel's own limit before it is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSessionIdentity {
    /// Protocol version the session was established at.
    pub protocol_version: u16,
    /// The session every later operation names.
    pub session_id: String,
    /// Which host process this session belongs to.
    pub host_instance_id: String,
    /// Per-session nonce the host chose.
    pub host_nonce: String,
    /// Largest frame the host will accept.
    pub maximum_frame_bytes: u32,
    /// Features both sides agreed on.
    pub supported_features: Vec<String>,
    /// Kernel-held state this host may read, and nothing else.
    ///
    /// Empty is the default and means the host reads nothing: granting is a
    /// decision the kernel makes, and reading these in process is not a reason
    /// for another process to read them.
    pub read_capabilities: Vec<PluginHostReadCapability>,
}

/// Kernel-held state a plugin host may be allowed to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginHostReadCapability {
    /// The runtime's own diagnostics snapshot.
    RuntimeDiagnostics,
    /// The runtime's global registration inventory.
    RegistrationInventory,
}

/// What a host asks for when it establishes a session.
///
/// The request is a request: what the host may read is what the kernel granted
/// in the session it established, never what it asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginHandshakeRequest {
    /// Protocol version the host speaks.
    pub protocol_version: u16,
    /// Digest of the runtime identity the host expects to be bound to.
    pub runtime_binding_digest: String,
    /// Nonce the host chose for this session.
    pub client_nonce: String,
    /// Credential the supervisor passed out of band.
    pub session_credential: String,
    /// Largest frame the host will accept.
    pub maximum_frame_bytes: u32,
    /// Features the host offers.
    pub supported_features: Vec<String>,
    /// Kernel-held state the host asks to read.
    pub requested_read_capabilities: Vec<PluginHostReadCapability>,
}

/// A scope named by its canonical identity.
///
/// The UUID, not a name and not an opaque token: a name is not unique, and a
/// token would have to be resolved before it meant anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginScopeReference {
    /// The scope's UUID.
    pub scope_id: Uuid,
}

impl PluginScopeReference {
    /// Parse a scope identity from its canonical text.
    ///
    /// Canonical means the hyphenated form: `Uuid` also accepts simple, braced
    /// and URN spellings of the same value, and accepting those would give the
    /// boundary several spellings of one identity, so a log, a gate or a
    /// comparison that used the text rather than the value would disagree with
    /// itself.
    pub fn from_canonical(text: &str) -> Result<Self, PluginProtocolError> {
        let text = text.trim();
        let scope_id = Uuid::parse_str(text).map_err(|_| {
            PluginProtocolError::new(
                PluginFailureCode::MalformedResponse,
                format!("a scope identity that is not a UUID: {text:?}"),
            )
        })?;
        if scope_id.hyphenated().to_string() != text {
            return Err(PluginProtocolError::new(
                PluginFailureCode::MalformedResponse,
                format!("a scope identity that is not in canonical form: {text:?}"),
            ));
        }
        Ok(Self { scope_id })
    }
}

/// The complete payload of a mark.
///
/// Every field the ABI may omit is optional here rather than defaulted: the
/// parent scope, metadata, data schema and severity all change the event a
/// subscriber sees, and a default would be an event nobody asked for. The name
/// is the minimum, because a mark without one addresses nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginMarkEmit {
    /// Correlation identifier for the operation that emitted it.
    pub operation_request_id: String,
    /// Identity of this call, distinct from the operation it belongs to.
    pub host_call_id: String,
    /// The mark's name.
    pub name: String,
    /// The mark's payload, when it has one.
    pub data_json: Option<String>,
    /// The scope the mark belongs to, when it has one.
    pub parent: Option<PluginScopeReference>,
    /// Metadata attached to the mark, when it has any.
    pub metadata_json: Option<String>,
    /// The schema the payload is written against, when it declares one.
    pub data_schema: Option<DataSchema>,
    /// How severe the mark is, when it declares that.
    pub severity: Option<LogSeverity>,
    /// Microseconds since the Unix epoch, when the caller supplies a time.
    pub timestamp_unix_micros: Option<u64>,
}

/// What a caller wants done with the scope stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginScopeOperation {
    /// Read the current scope.
    Current,
    /// Push a new scope.
    Push,
    /// Pop a scope.
    Pop,
    /// Create an isolated stack.
    CreateIsolated,
    /// Release an isolated stack.
    ReleaseIsolated,
}

impl PluginScopeOperation {
    /// Whether this operation carries a payload.
    ///
    /// Push and pop describe a scope; the others name one that already exists
    /// or needs no description. A payload on the wrong one is a request that
    /// says two things, and the two cannot both be true.
    pub const fn carries_payload(self) -> bool {
        matches!(self, Self::Push | Self::Pop)
    }
}

/// One call against the scope stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginScopeStackRequest {
    /// Correlation identifier for the operation it belongs to.
    pub operation_request_id: String,
    /// Identity of this call.
    pub host_call_id: String,
    /// What to do.
    pub operation: PluginScopeOperation,
    /// What to do it with, when the operation carries one.
    pub payload_json: Option<String>,
}

/// Which codec operation is being asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCodecOperation {
    /// Decode an LLM request.
    LlmRequestDecode,
    /// Encode an annotated LLM request.
    LlmRequestEncode,
    /// Decode an LLM response.
    LlmResponseDecode,
}

/// One codec resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginResolveCodecRequest {
    /// Correlation identifier for the operation it belongs to.
    pub operation_request_id: String,
    /// Identity of this call.
    pub host_call_id: String,
    /// What to do.
    pub operation: PluginCodecOperation,
    /// What to do it with.
    pub payload_json: String,
}

/// One chunk of a stream the runtime produces for a callback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginContinuationChunk {
    /// The continuation call this chunk belongs to.
    pub host_call_id: String,
    /// One-based order within that call.
    pub sequence: u64,
    /// The chunk.
    pub chunk_json: String,
}

/// What a plugin decided about the chunk it received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginChunkDecision {
    /// Produce the next chunk.
    Continue,
    /// Stop producing.
    Stop,
}

/// The plugin's answer about one chunk.
///
/// The runtime does not produce the next chunk until this arrives, which is what
/// makes the in-process callback's return value mean the same thing here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginContinuationDisposition {
    /// The continuation call this answers.
    pub host_call_id: String,
    /// Which chunk it answers, so an answer cannot be applied to whichever
    /// chunk happened to be outstanding.
    pub sequence: u64,
    /// Whether to continue, or the failure that ended the stream.
    pub disposition: Result<PluginChunkDecision, PluginFailure>,
}

/// The result of one lifecycle operation.
///
/// Distinct from a transport failure, and from a malformed message. The peer
/// answered coherently and the answer says either that the operation completed
/// or that it failed for a reason this contract defines. Collapsing those into
/// a transport error would lose the difference between "the host told me this
/// plugin is already loaded" and "I could not reach the host".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleOutcome<T> {
    /// The operation completed.
    Completed(T),
    /// The peer answered, and the answer is a structured failure.
    Failed(PluginFailure),
}

/// Identity of the artifact a load was approved against.
///
/// The runtime approves this; whatever performs the load verifies it
/// immediately before opening the library. A reference alone is not enough,
/// because a reference can be verified and then left in place while the file
/// behind it is replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginArtifactIdentity {
    /// SHA-256 of the manifest, which decides what is loaded and how.
    pub manifest_sha256: String,
    /// SHA-256 of the library the manifest names.
    pub library_sha256: String,
}

/// Load a plugin into the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginLoadRequest {
    /// Deployment-chosen identifier to load under.
    pub plugin_id: String,
    /// Host-specific location of the plugin artifact.
    pub artifact: String,
    /// What the runtime approved, for the loader to verify before opening.
    pub identity: PluginArtifactIdentity,
}

/// Remove a loaded plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginUnloadRequest {
    /// Instance to unload.
    pub handle: PluginHandle,
}

/// Invoke one capability on a loaded plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginInvokeRequest {
    /// Instance to invoke.
    pub handle: PluginHandle,
    /// Capability to invoke.
    pub capability_id: String,
    /// Canonical JSON arguments.
    pub arguments: String,
    /// Milliseconds the kernel will wait before it stops waiting.
    ///
    /// This is a deadline for the caller, not a promise about the plugin: a
    /// plugin that ignores it is killed by the host, and the result is an
    /// outcome the kernel cannot observe rather than a failure it can assume.
    pub budget_millis: u64,
}

/// Result of one invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginInvokeResponse {
    /// Canonical JSON result.
    pub output: String,
}

/// Ask the host what it currently holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginInspectRequest {
    /// Instance to describe, or `None` for every loaded instance.
    pub handle: Option<PluginHandle>,
}

/// Liveness and resource state of the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginHostHealth {
    /// Protocol version the host speaks.
    pub protocol_version: u16,
    /// Whether the host is accepting work.
    pub accepting_work: bool,
    /// Instances the host currently holds.
    pub loaded: Vec<PluginHandle>,
}

/// Identity, binding, and budget for one operation.
///
/// Every operation carries one of these, and the implementation is not free to
/// invent its own: a process backend that derived its own deadline or frame
/// budget from somewhere else would be enforcing a different contract than the
/// in-process one, and the two would drift the first time either changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginExecutionContext {
    /// Correlation identifier for this operation.
    ///
    /// Host calls made by the plugin while it runs carry the same identifier, so
    /// a call belongs to exactly one operation even when several are in flight.
    /// It is named for the operation rather than for the request because each
    /// callback needs its own identity within it.
    pub operation_request_id: String,
    /// Protocol version the caller speaks.
    pub protocol_version: u16,
    /// Digest of the runtime identity this operation is bound to.
    pub runtime_binding_digest: String,
    /// Wall-clock deadline in milliseconds since the Unix epoch.
    ///
    /// Absolute, so it survives logging and audit: a duration means nothing
    /// once the message has been sitting in a queue.
    pub deadline_unix_ms: u64,
    /// What is actually left of the budget, for enforcement.
    ///
    /// The host enforces this one. It is derived from the trusted action budget
    /// rather than chosen by the caller, and both forms travel because the
    /// absolute deadline answers "when" for an auditor while this answers "how
    /// long" for a timer.
    pub remaining_budget_millis: u64,
    /// Largest response the caller will accept.
    pub max_response_bytes: u32,
}

/// The session and context every host operation carries.
///
/// Validated before the payload is looked at, so a message that names no
/// session, or carries no context, or carries one this side cannot use, is
/// refused as an envelope rather than while half of a payload has already been
/// converted. The context is what the operation's budget comes from, so a
/// request without one has no deadline at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginOperationEnvelope {
    /// The session the operation belongs to.
    pub session_id: String,
    /// Identity, binding and budget for the operation.
    pub context: PluginExecutionContext,
}

/// A request to continue the interceptor chain.
///
/// A plugin's interceptor that rewrites a request and then continues is asking
/// the runtime to run everything after it: the other interceptors, then the
/// call itself. In process that work is the runtime's, so the request crosses;
/// the operation identity is what lets the runtime resume the right chain
/// position rather than starting a new one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginContinuationRequest {
    /// Correlation identifier for the operation being continued.
    pub operation_request_id: String,
    /// Identity of this call, distinct from the operation it belongs to.
    pub host_call_id: String,
    /// The invocation to continue with, after any rewriting.
    pub invocation_json: String,
}

/// The answer to a host call that returns a value or a structured failure.
///
/// One type rather than one per call: the shape is the same for every host call
/// that answers with a payload, and a second copy would be a second place for
/// "the peer refused" to be represented differently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginHostCallOutcome {
    /// The answer, or the failure that replaced it.
    pub result: Result<String, PluginFailure>,
}

/// One frame of a streaming invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginStreamChunk {
    /// The operation the stream belongs to.
    pub operation_request_id: String,
    /// What this frame carries.
    pub chunk: PluginStreamChunkKind,
    /// Whether the plugin may have reached an external system.
    pub dispatch: DispatchState,
    /// What the runtime can prove about the outcome.
    pub certainty: OutcomeCertainty,
}

/// What one frame of a streaming invocation carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginStreamChunkKind {
    /// One frame of output.
    Data(String),
    /// The stream ended because the plugin finished.
    End,
    /// The stream ended because the plugin failed.
    Failed(PluginFailure),
}

/// One message on the duplex channel between the kernel and a plugin host.
///
/// This channel carries the two families of call that one request and one
/// answer cannot express: a completion the plugin settles after the callback
/// that produced it has returned, and a downstream stream the plugin opens,
/// paces one pull at a time, and may cancel or release while a pull is
/// outstanding. Everything else — operations, marks, scope stack, codec
/// resolution, registration — keeps its own single representation as a typed
/// request; a second way to perform one of those would be a second thing that
/// can disagree with the first.
///
/// The session is part of every message rather than of the channel, so a peer
/// that receives a message from a session it no longer holds can say so instead
/// of acting on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSessionMessage {
    /// The session this message belongs to.
    pub session_id: String,
    /// What the message is.
    pub message: PluginSessionPayload,
}

/// The messages a session carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "message")]
pub enum PluginSessionPayload {
    /// Open a downstream stream for one operation.
    StreamOpen(PluginStreamOpenRequest),
    /// The stream the kernel opened.
    StreamOpened(PluginStreamOpened),
    /// The kernel refused to open it.
    StreamOpenFailed(PluginStreamOpenFailed),
    /// Pull the next item.
    StreamPull(PluginStreamPullRequest),
    /// One item.
    StreamItem(PluginStreamItem),
    /// The stream produced everything it had.
    StreamEnd(PluginStreamEnd),
    /// The stream failed.
    StreamFailed(PluginStreamFailed),
    /// Stop producing.
    StreamCancel(PluginStreamControl),
    /// Drop the plugin's reference to the stream.
    StreamRelease(PluginStreamControl),
    /// Settle a callback that returned before its result existed.
    CompletionSettle(PluginCompletionSettlement),
    /// The kernel's answer to a settlement.
    CompletionOutcome(PluginCompletionOutcome),
    /// The awaiting runtime cancelled a pending completion.
    CompletionCancelled(PluginCompletionCancelled),
    /// One chunk of a stream the runtime produces for a callback.
    ContinuationChunk(PluginContinuationChunk),
    /// The plugin's answer about one chunk.
    ContinuationDisposition(PluginContinuationDisposition),
}

/// A request to open a downstream stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginStreamOpenRequest {
    /// Identity of this call, distinct from the operation it belongs to.
    pub host_call_id: String,
    /// The operation the stream is opened for.
    pub operation_request_id: String,
    /// The request to send downstream.
    pub request_json: String,
}

/// The stream the kernel opened, addressed by identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginStreamOpened {
    /// Identity of the open call being answered.
    pub host_call_id: String,
    /// Identity of the stream every later message names.
    pub stream_id: String,
}

/// A refusal to open a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginStreamOpenFailed {
    /// Identity of the open call being answered.
    pub host_call_id: String,
    /// Why it was refused.
    pub failure: PluginFailure,
}

/// A request for the next item of a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginStreamPullRequest {
    /// Identity of this call.
    pub host_call_id: String,
    /// The stream to pull from.
    pub stream_id: String,
}

/// One item of a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginStreamItem {
    /// Identity of the pull being answered.
    pub host_call_id: String,
    /// The stream it belongs to.
    pub stream_id: String,
    /// The item.
    pub chunk_json: String,
}

/// Clean completion of a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginStreamEnd {
    /// Identity of the pull being answered.
    pub host_call_id: String,
    /// The stream that ended.
    pub stream_id: String,
}

/// Failed completion of a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginStreamFailed {
    /// Identity of the pull being answered.
    pub host_call_id: String,
    /// The stream that failed.
    pub stream_id: String,
    /// Why it failed.
    pub failure: PluginFailure,
}

/// A stream control message that names only the call and the stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginStreamControl {
    /// Identity of this call.
    pub host_call_id: String,
    /// The stream to act on.
    pub stream_id: String,
}

/// A settlement of a callback that returned before its result existed.
///
/// The value and the failure share a `Result` rather than two fields, because a
/// settlement that carried both would describe two outcomes for one callback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginCompletionSettlement {
    /// Identity of the completion being settled.
    pub completion_id: String,
    /// The operation the callback belonged to.
    pub operation_request_id: String,
    /// The settled value, or the failure that replaced it.
    pub result: Result<String, PluginFailure>,
}

/// The kernel's answer to a settlement.
///
/// `Ok(())` means the settlement was taken. A failure means it was refused —
/// because the completion was already settled or already cancelled — and the
/// plugin has to learn that rather than assume its result arrived, since
/// nothing else is waiting on that callback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginCompletionOutcome {
    /// Identity of the completion this answers.
    pub completion_id: String,
    /// Whether the settlement was taken.
    pub result: Result<(), PluginFailure>,
}

/// Notification that the runtime awaiting a callback cancelled it.
///
/// The plugin is under no obligation to stop — the kernel does not trust a
/// plugin to honour cancellation, and enforces its own deadline regardless —
/// but a plugin that knows can release what it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginCompletionCancelled {
    /// Identity of the cancelled completion.
    pub completion_id: String,
}

/// Result of one operation together with what is known about dispatch.
///
/// A failure alone is not enough to decide what happens next. If a plugin that
/// performs a consequential external operation dies after dispatch, the effect
/// may have happened, and the runtime has to record `UNKNOWN` rather than
/// `FAILED`. Reporting dispatch alongside the result keeps that decision
/// available instead of collapsing it into the failure enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginExecutionOutcome {
    /// Whether the plugin may have reached an external system.
    pub dispatch: DispatchState,
    /// Certainty about the outcome.
    pub certainty: OutcomeCertainty,
    /// The response, or the structured failure that replaced it.
    pub result: Result<PluginSuccess, PluginFailure>,
}

/// Result of loading a plugin.
///
/// The handle is returned rather than left for the caller to derive: only the
/// backend knows the generation it assigned, and a handle without one would
/// address nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginLoadResponse {
    /// Identity of the loaded instance.
    pub handle: PluginHandle,
    /// What the plugin declares about itself.
    pub descriptor: PluginDescriptor,
}

/// A successful response across the boundary.
///
/// There is deliberately no `Failed` variant. A failure travels as
/// [`PluginFailure`] in the error channel, so a result can never say both
/// "succeeded, and the answer is a failure" and "failed", which are the same
/// event described two ways and would eventually disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum PluginSuccess {
    /// Version negotiation reply.
    Handshake(PluginHandshake),
    /// A plugin is loaded.
    Loaded(PluginLoadResponse),
    /// A plugin is unloaded.
    Unloaded,
    /// An invocation produced output.
    Invoked(PluginInvokeResponse),
    /// Descriptions of loaded plugins.
    Inspected(Vec<PluginDescriptor>),
    /// Host liveness.
    Health(PluginHostHealth),
}

/// Structured failure returned across the boundary, or raised before it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginFailure {
    /// Machine-readable classification.
    pub code: PluginFailureCode,
    /// Human-readable detail. Never parsed.
    pub message: String,
}

/// Why a plugin operation did not produce a result.
///
/// The variants are the cases the kernel has to reason about. A plugin that
/// hangs, crashes, or answers with something unreadable is not the same as a
/// plugin that answered with a refusal, and the caller cannot treat them alike.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PluginFailureCode {
    /// The peer speaks a different protocol version.
    VersionMismatch {
        /// Version this side implements.
        expected: u16,
        /// Version the peer sent.
        received: u16,
    },
    /// The plugin's own ABI does not match what the host supports.
    AbiMismatch {
        /// ABI version the host supports.
        supported: u16,
        /// ABI version the plugin reported.
        reported: u16,
    },
    /// No loaded instance matches the handle.
    UnknownPlugin,
    /// The handle names a generation that is no longer the loaded one.
    ///
    /// Distinct from `UnknownPlugin`: the plugin exists, but a handle from
    /// before a reload must not be able to address the instance that replaced
    /// it, and a caller needs to be able to tell those apart.
    StaleHandle,
    /// Another request is already loading this plugin.
    AlreadyLoading,
    /// The plugin is already loaded.
    AlreadyLoaded,
    /// The operation was cancelled before it produced a result.
    Cancelled,
    /// The monotonic generation counter cannot advance.
    GenerationExhausted,
    /// The plugin answered, and the answer was refused.
    Rejected,
    /// A frame exceeded [`MAX_FRAME_BYTES`].
    OversizedFrame {
        /// Bytes the peer announced or sent.
        observed: u64,
        /// Limit in force.
        limit: u32,
    },
    /// The caller's deadline elapsed before a result arrived.
    DeadlineExceeded,
    /// The host process died.
    HostCrashed,
    /// The peer's response could not be decoded.
    MalformedResponse,
    /// The boundary itself is unavailable.
    Unavailable,
}

/// Failure raised while talking to a plugin host.
#[derive(Debug, thiserror::Error)]
#[error("plugin host failure: {failure:?}")]
pub struct PluginProtocolError {
    /// Structured cause.
    pub failure: PluginFailure,
}

impl PluginProtocolError {
    /// Build an error carrying `code` and `message`.
    pub fn new(code: PluginFailureCode, message: impl Into<String>) -> Self {
        Self {
            failure: PluginFailure {
                code,
                message: message.into(),
            },
        }
    }
}

/// Check the peer's protocol version, failing closed on any mismatch.
///
/// Negotiation is deliberately not "use the lower of the two": the two sides
/// are separately deployed processes, and a mismatch means one of them is
/// interpreting fields the other does not send. Guessing is worse than
/// refusing.
pub fn check_protocol_version(received: u16) -> Result<(), PluginProtocolError> {
    if received == PROTOCOL_VERSION {
        return Ok(());
    }
    Err(PluginProtocolError::new(
        PluginFailureCode::VersionMismatch {
            expected: PROTOCOL_VERSION,
            received,
        },
        format!("peer speaks protocol version {received}, this side speaks {PROTOCOL_VERSION}"),
    ))
}

/// Return whether `deadline_unix_ms` has passed at `now_unix_ms`.
pub const fn deadline_expired(deadline_unix_ms: u64, now_unix_ms: u64) -> bool {
    now_unix_ms >= deadline_unix_ms
}

/// Check a deadline against a supplied instant.
///
/// Split from the clock-reading form so the rule itself is testable. The
/// boundary is inclusive at the deadline: at the deadline there is no time left,
/// so the operation is refused rather than started and abandoned.
pub fn check_deadline_at(
    deadline_unix_ms: u64,
    now_unix_ms: u64,
) -> Result<(), PluginProtocolError> {
    if !deadline_expired(deadline_unix_ms, now_unix_ms) {
        return Ok(());
    }
    Err(PluginProtocolError::new(
        PluginFailureCode::DeadlineExceeded,
        format!(
            "the operation deadline ({deadline_unix_ms} ms since the epoch) had already \
             passed at {now_unix_ms} ms"
        ),
    ))
}

/// Check a deadline against the wall clock.
///
/// The caller is expected to refuse the operation without invoking the backend
/// when this fails, because an operation that is already out of time cannot
/// produce a result anyone is still waiting for.
pub fn check_deadline(deadline_unix_ms: u64) -> Result<(), PluginProtocolError> {
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(u64::MAX);
    check_deadline_at(deadline_unix_ms, now_unix_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_this_crate_declares_survives_its_own_serialization() {
        // The vocabulary is `Serialize` so bindings and stored state can carry
        // it. A tagged enum whose arm is not a map, or a field whose type does
        // not round-trip, would fail here rather than at a boundary where the
        // failure looks like a peer sending nonsense.
        let messages = [
            PluginSessionMessage {
                session_id: "session-1".into(),
                message: PluginSessionPayload::StreamItem(PluginStreamItem {
                    host_call_id: "call-1".into(),
                    stream_id: "stream-1".into(),
                    chunk_json: r#"{"delta":"hi"}"#.into(),
                }),
            },
            PluginSessionMessage {
                session_id: "session-1".into(),
                message: PluginSessionPayload::CompletionSettle(PluginCompletionSettlement {
                    completion_id: "completion-1".into(),
                    operation_request_id: "operation-1".into(),
                    result: Err(PluginFailure {
                        code: PluginFailureCode::Cancelled,
                        message: "the awaiting runtime cancelled it".into(),
                    }),
                }),
            },
            PluginSessionMessage {
                session_id: "session-1".into(),
                message: PluginSessionPayload::ContinuationDisposition(
                    PluginContinuationDisposition {
                        host_call_id: "call-1".into(),
                        sequence: 2,
                        disposition: Ok(PluginChunkDecision::Stop),
                    },
                ),
            },
        ];

        for message in messages {
            let text = serde_json::to_string(&message).expect("serialize a session message");
            let back: PluginSessionMessage =
                serde_json::from_str(&text).expect("deserialize a session message");
            assert_eq!(back, message);
        }

        // The mark carries types this crate re-exports, so their serialized
        // form is part of this crate's promise too.
        let mark = PluginMarkEmit {
            operation_request_id: "operation-1".into(),
            host_call_id: "call-1".into(),
            name: "example.mark".into(),
            data_json: Some(r#"{"value":1}"#.into()),
            parent: Some(
                PluginScopeReference::from_canonical("018f0b3c-5f5a-7c3e-9a2b-1c2d3e4f5a6b")
                    .expect("a canonical scope"),
            ),
            metadata_json: None,
            data_schema: Some(DataSchema {
                name: "example".into(),
                version: "1".into(),
            }),
            severity: Some(LogSeverity::Warn),
            timestamp_unix_micros: Some(1_700_000_000_000_000),
        };
        let text = serde_json::to_string(&mark).expect("serialize a mark");
        assert!(
            text.contains("\"warn\""),
            "severity writes its canonical name: {text}"
        );
        assert_eq!(
            serde_json::from_str::<PluginMarkEmit>(&text).expect("deserialize a mark"),
            mark
        );
    }

    #[test]
    fn a_scope_identity_has_one_spelling() {
        let canonical = "018f0b3c-5f5a-7c3e-9a2b-1c2d3e4f5a6b";
        let reference = PluginScopeReference::from_canonical(canonical).expect("a UUID");
        assert_eq!(reference.scope_id.to_string(), canonical);

        for other in [
            "018f0b3c5f5a7c3e9a2b1c2d3e4f5a6b",
            "{018f0b3c-5f5a-7c3e-9a2b-1c2d3e4f5a6b}",
            "urn:uuid:018f0b3c-5f5a-7c3e-9a2b-1c2d3e4f5a6b",
            "not-a-uuid",
        ] {
            assert!(
                PluginScopeReference::from_canonical(other).is_err(),
                "{other} is the same value written differently"
            );
        }
    }

    #[test]
    fn a_deadline_is_refused_at_the_boundary_and_before_it() {
        // At the deadline there is no time left, so the operation must not
        // start. A comparison that allowed equality would start work that is
        // already out of time.
        assert!(check_deadline_at(1_000, 1_000).is_err());
        assert!(check_deadline_at(1_000, 1_001).is_err());
        assert!(check_deadline_at(1_000, 999).is_ok());
    }

    #[test]
    fn an_expired_deadline_is_reported_as_a_deadline_and_not_a_crash() {
        // A host killed because the deadline passed is still a deadline. Losing
        // that distinction would make a timeout indistinguishable from a
        // process that died on its own.
        let failure = check_deadline_at(1_000, 1_000).expect_err("expired");
        assert_eq!(failure.failure.code, PluginFailureCode::DeadlineExceeded);
        assert_ne!(failure.failure.code, PluginFailureCode::HostCrashed);
    }

    #[test]
    fn dispatch_certainty_travels_with_the_result() {
        let outcome = PluginExecutionOutcome {
            dispatch: DispatchState::DispatchAttempted,
            certainty: OutcomeCertainty::Unknown,
            result: Err(PluginFailure {
                code: PluginFailureCode::HostCrashed,
                message: "the plugin host exited during dispatch".into(),
            }),
        };

        let encoded = serde_json::to_string(&outcome).expect("encode outcome");
        let decoded: PluginExecutionOutcome = serde_json::from_str(&encoded).expect("decode");

        assert_eq!(decoded, outcome);
        // The point of the envelope: the failure is not reported as a definite
        // outcome, so a caller cannot turn it into FAILED.
        assert_eq!(decoded.certainty, OutcomeCertainty::Unknown);
        assert_eq!(decoded.dispatch, DispatchState::DispatchAttempted);
    }

    #[test]
    fn the_contract_speaks_one_version_and_accepts_it() {
        assert!(check_protocol_version(PROTOCOL_VERSION).is_ok());
    }

    #[test]
    fn a_protocol_version_mismatch_fails_closed_in_both_directions() {
        for peer_version in [PROTOCOL_VERSION + 1, PROTOCOL_VERSION - 1] {
            let failure = check_protocol_version(peer_version)
                .expect_err("a mismatch must not be negotiated around");
            let PluginFailureCode::VersionMismatch { expected, received } = failure.failure.code
            else {
                panic!("unexpected failure code: {:?}", failure.failure.code);
            };
            assert_eq!(expected, PROTOCOL_VERSION);
            // Against the peer's version, not against itself. The earlier form
            // destructured into a name that shadowed the loop variable, so the
            // assertion was true whatever the code returned.
            assert_eq!(received, peer_version);
        }
    }

    #[test]
    fn a_failure_travels_in_the_error_channel_and_nowhere_else() {
        // One representation only: a result that says both "succeeded" and
        // "the answer is a failure" is the same event described twice, and the
        // two descriptions eventually disagree.
        let failure = PluginFailure {
            code: PluginFailureCode::DeadlineExceeded,
            message: "plugin did not answer within the action budget".into(),
        };
        let outcome = PluginExecutionOutcome {
            dispatch: DispatchState::DispatchAttempted,
            certainty: OutcomeCertainty::Unknown,
            result: Err(failure.clone()),
        };

        let encoded = serde_json::to_string(&outcome).expect("encode outcome");
        let decoded: PluginExecutionOutcome =
            serde_json::from_str(&encoded).expect("decode outcome");

        assert_eq!(decoded, outcome);
        assert!(matches!(decoded.result, Err(ref carried) if carried == &failure));
    }
}
