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
//! Nothing in the kernel depends on this crate yet. Adding the dependency is the
//! next increment, and it belongs to the kernel only as an interface.

use serde::{Deserialize, Serialize};

pub use nemo_relay_types::execution::{DispatchState, OutcomeCertainty};

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
    /// Capabilities the plugin offers.
    pub capabilities: Vec<PluginCapability>,
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

/// Load a plugin into the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginLoadRequest {
    /// Deployment-chosen identifier to load under.
    pub plugin_id: String,
    /// Host-specific location of the plugin artifact.
    pub artifact: String,
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
    pub deadline_unix_ms: u64,
    /// Largest response the caller will accept.
    pub max_response_bytes: u32,
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
        for received in [PROTOCOL_VERSION + 1, PROTOCOL_VERSION - 1] {
            let failure = check_protocol_version(received)
                .expect_err("a mismatch must not be negotiated around");
            let PluginFailureCode::VersionMismatch { expected, received } = failure.failure.code
            else {
                panic!("unexpected failure code: {:?}", failure.failure.code);
            };
            assert_eq!(expected, PROTOCOL_VERSION);
            assert_eq!(received, received);
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
