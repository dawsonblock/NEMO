// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Conversion between the wire schema and the domain vocabulary.
//!
//! Protobuf is permissive by design: every field is optional, every enum has an
//! `UNSPECIFIED` zero value, and an unknown enum value decodes to a plain
//! integer. The domain types are not permissive at all — `PluginFailureCode`
//! carries its detail with it, so a `VersionMismatch` without both versions is
//! not constructible in Rust.
//!
//! That gap is the whole point of this module. The host is less trusted than the
//! kernel, so anything it sends is decoded here and either becomes a valid
//! domain value or is refused. Without it, protobuf's looseness would be
//! silently laundered into domain state that core believes it can rely on.

use nemo_relay_plugin_protocol::{
    DataSchema, DispatchState, LifecycleOutcome, LogSeverity, MAX_FRAME_BYTES, OutcomeCertainty,
    PluginArtifactIdentity, PluginCapability, PluginCapabilityKind, PluginChunkDecision,
    PluginCodecOperation, PluginCompletionCancelled, PluginCompletionOutcome,
    PluginCompletionSettlement, PluginContinuationChunk, PluginContinuationDisposition,
    PluginContinuationRequest, PluginDescriptor, PluginExecutionContext, PluginExecutionOutcome,
    PluginExecutionShape, PluginFailure, PluginFailureCode, PluginHandle, PluginHandshakeRequest,
    PluginHostCallOutcome, PluginHostHealth, PluginHostReadCapability, PluginInspectRequest,
    PluginInvokeRequest, PluginInvokeResponse, PluginLoadRequest, PluginLoadResponse,
    PluginMarkEmit, PluginOperationEnvelope, PluginOutputCredit, PluginProtocolError,
    PluginRegistrationDescriptor, PluginRegistrationOperation, PluginRegistrationOrdering,
    PluginResolveCodecRequest, PluginScopeOperation, PluginScopeReference, PluginScopeStackRequest,
    PluginSessionIdentity, PluginSessionMessage, PluginSessionPayload, PluginStreamChunk,
    PluginStreamChunkKind, PluginStreamControl, PluginStreamEnd, PluginStreamFailed,
    PluginStreamItem, PluginStreamOpenFailed, PluginStreamOpenRequest, PluginStreamOpened,
    PluginStreamPullRequest, PluginSuccess, PluginUnloadRequest, registration_shape,
};

use crate::v1;

// Each lifecycle operation has meaningful failures of its own — a plugin
// already loaded, a handle from a previous generation, a version the host does
// not speak — and each of those is a result rather than a channel error. The
// functions below keep that distinction: a failure arm becomes
// `LifecycleOutcome::Failed`, and only a message carrying neither arm is an
// error, because then the peer said nothing rather than reporting something.

/// Read the session a handshake established.
///
/// The version is converted, not judged: whether it is one this side speaks is
/// a policy decision the kernel makes at the boundary, and judging it here as
/// well would give version policy two homes.
pub fn handshake_outcome_from_wire(
    wire: &v1::HandshakeOutcome,
) -> Result<LifecycleOutcome<PluginSessionIdentity>, PluginProtocolError> {
    match wire.result.as_ref() {
        Some(v1::handshake_outcome::Result::Established(established)) => Ok(
            LifecycleOutcome::Completed(session_identity_from_wire(established)?),
        ),
        Some(v1::handshake_outcome::Result::Failure(failure)) => {
            Ok(LifecycleOutcome::Failed(failure_from_wire(failure)?))
        }
        None => Err(malformed(
            "a handshake outcome that is neither a session nor a failure",
        )),
    }
}

/// Read the result of a load.
pub fn load_outcome_from_wire(
    wire: &v1::LoadOutcome,
) -> Result<LifecycleOutcome<PluginLoadResponse>, PluginProtocolError> {
    match wire.result.as_ref() {
        Some(v1::load_outcome::Result::Loaded(loaded)) => Ok(LifecycleOutcome::Completed(
            load_response_from_wire(loaded)?,
        )),
        Some(v1::load_outcome::Result::Failure(failure)) => {
            Ok(LifecycleOutcome::Failed(failure_from_wire(failure)?))
        }
        None => Err(malformed(
            "a load outcome that is neither a plugin nor a failure",
        )),
    }
}

/// Read the result of an unload.
///
/// The success arm carries no payload of its own, which is what the wire's
/// empty `UnloadResponse` already said.
pub fn unload_outcome_from_wire(
    wire: &v1::UnloadOutcome,
) -> Result<LifecycleOutcome<()>, PluginProtocolError> {
    match wire.result.as_ref() {
        Some(v1::unload_outcome::Result::Unloaded(response)) => Ok(LifecycleOutcome::Completed(
            unload_response_from_wire(response)?,
        )),
        Some(v1::unload_outcome::Result::Failure(failure)) => {
            Ok(LifecycleOutcome::Failed(failure_from_wire(failure)?))
        }
        None => Err(malformed(
            "an unload outcome that is neither an acknowledgement nor a failure",
        )),
    }
}

/// Read the result of an inspection.
pub fn inspect_outcome_from_wire(
    wire: &v1::InspectOutcome,
) -> Result<LifecycleOutcome<Vec<PluginDescriptor>>, PluginProtocolError> {
    match wire.result.as_ref() {
        Some(v1::inspect_outcome::Result::Inspected(inspected)) => Ok(LifecycleOutcome::Completed(
            inspect_response_from_wire(inspected)?,
        )),
        Some(v1::inspect_outcome::Result::Failure(failure)) => {
            Ok(LifecycleOutcome::Failed(failure_from_wire(failure)?))
        }
        None => Err(malformed(
            "an inspection outcome that is neither a description nor a failure",
        )),
    }
}

/// Read the host's reported health.
pub fn health_outcome_from_wire(
    wire: &v1::HealthOutcome,
) -> Result<LifecycleOutcome<PluginHostHealth>, PluginProtocolError> {
    match wire.result.as_ref() {
        Some(v1::health_outcome::Result::Health(health)) => Ok(LifecycleOutcome::Completed(
            health_response_from_wire(health)?,
        )),
        Some(v1::health_outcome::Result::Failure(failure)) => {
            Ok(LifecycleOutcome::Failed(failure_from_wire(failure)?))
        }
        None => Err(malformed(
            "a health outcome that is neither a report nor a failure",
        )),
    }
}

/// Read the result of a cancellation.
///
/// An accepted cancellation says the host took the request, not that anything
/// stopped: what became of the cancelled operation is reported separately, and
/// it may not have reached the plugin at all.
pub fn cancel_outcome_from_wire(
    wire: &v1::CancelOperationOutcome,
) -> Result<LifecycleOutcome<()>, PluginProtocolError> {
    match wire.result.as_ref() {
        Some(v1::cancel_operation_outcome::Result::Cancelled(response)) => Ok(
            LifecycleOutcome::Completed(cancel_response_from_wire(response)?),
        ),
        Some(v1::cancel_operation_outcome::Result::Failure(failure)) => {
            Ok(LifecycleOutcome::Failed(failure_from_wire(failure)?))
        }
        None => Err(malformed(
            "a cancellation outcome that is neither an acknowledgement nor a failure",
        )),
    }
}

/// Validate the session a handshake established.
///
/// The session identity is what every later operation names, so an empty or
/// absent one would leave "which session?" without an answer. The frame limit
/// is checked against this side's own maximum because a host reporting a larger
/// limit than it enforces would be describing a session that does not exist.
fn session_identity_from_wire(
    wire: &v1::HandshakeResponse,
) -> Result<PluginSessionIdentity, PluginProtocolError> {
    for (value, what) in [
        (&wire.session_id, "a session with no identity"),
        (
            &wire.host_instance_id,
            "a session that does not say which host it belongs to",
        ),
        (&wire.host_nonce, "a session with no nonce"),
    ] {
        if value.trim().is_empty() {
            return Err(malformed(what));
        }
    }
    if wire.maximum_frame_bytes == 0 {
        return Err(malformed("a session that will not accept a frame at all"));
    }
    if wire.maximum_frame_bytes > MAX_FRAME_BYTES {
        return Err(malformed(format!(
            "a session offering a frame limit of {} bytes, above the {} this side speaks",
            wire.maximum_frame_bytes, MAX_FRAME_BYTES
        )));
    }
    let protocol_version = u16::try_from(wire.protocol_version).map_err(|_| {
        malformed("a session at a protocol version outside the range this code speaks")
    })?;
    Ok(PluginSessionIdentity {
        protocol_version,
        session_id: wire.session_id.clone(),
        host_instance_id: wire.host_instance_id.clone(),
        host_nonce: wire.host_nonce.clone(),
        maximum_frame_bytes: wire.maximum_frame_bytes,
        supported_features: wire.supported_features.clone(),
        // What the host accepted. The kernel compares this against what it
        // offered, so a session that accepted something nobody offered is
        // caught rather than used.
        accepted_read_capabilities: read_capabilities_from_wire(
            &wire.accepted_read_capabilities,
            "a session",
        )?,
    })
}

fn unload_response_from_wire(_wire: &v1::UnloadResponse) -> Result<(), PluginProtocolError> {
    Ok(())
}

fn cancel_response_from_wire(
    _wire: &v1::CancelOperationResponse,
) -> Result<(), PluginProtocolError> {
    Ok(())
}

fn inspect_response_from_wire(
    wire: &v1::InspectResponse,
) -> Result<Vec<PluginDescriptor>, PluginProtocolError> {
    wire.descriptors.iter().map(descriptor_from_wire).collect()
}

fn health_response_from_wire(
    wire: &v1::HealthResponse,
) -> Result<PluginHostHealth, PluginProtocolError> {
    let mut loaded = Vec::with_capacity(wire.loaded.len());
    for handle in &wire.loaded {
        if handle.plugin_id.trim().is_empty() {
            return Err(malformed(
                "a health report naming a plugin with no identity",
            ));
        }
        if handle.generation == 0 {
            // The same rule the load response follows: generation zero is the
            // protobuf default and no load produces it, so a host reporting one
            // is describing an instance that never existed.
            return Err(malformed(
                "a health report naming a handle at generation zero",
            ));
        }
        loaded.push(PluginHandle {
            plugin_id: handle.plugin_id.clone(),
            generation: handle.generation,
        });
    }
    Ok(PluginHostHealth {
        protocol_version: u16::try_from(wire.protocol_version).map_err(|_| {
            malformed("a health report with a protocol version outside the range this code speaks")
        })?,
        accepting_work: wire.accepting_work,
        loaded,
    })
}

/// Build the wire form of a load request.
///
/// The session and the context travel with it: the host has to enforce the
/// budget, and a value it cannot see is a value it cannot enforce. The approved
/// digests travel too, because they are the runtime's statement of what it
/// approved — the side performing the load confirms an identity rather than
/// deciding one.
pub fn load_request_to_wire(
    request: &PluginLoadRequest,
    session_id: &str,
    context: &PluginExecutionContext,
) -> v1::LoadRequest {
    v1::LoadRequest {
        session_id: session_id.to_owned(),
        context: Some(context_to_wire(context)),
        plugin_id: request.plugin_id.clone(),
        artifact: request.artifact.clone(),
        manifest_digest: request.identity.manifest_sha256.clone(),
        library_digest: request.identity.library_sha256.clone(),
    }
}

/// Build the wire form of an unload request.
pub fn unload_request_to_wire(
    request: &PluginUnloadRequest,
    session_id: &str,
    context: &PluginExecutionContext,
) -> v1::UnloadRequest {
    v1::UnloadRequest {
        session_id: session_id.to_owned(),
        context: Some(context_to_wire(context)),
        handle: Some(handle_to_wire(&request.handle)),
    }
}

/// Build the wire form of an inspection request.
pub fn inspect_request_to_wire(
    request: &PluginInspectRequest,
    session_id: &str,
    context: &PluginExecutionContext,
) -> v1::InspectRequest {
    v1::InspectRequest {
        session_id: session_id.to_owned(),
        context: Some(context_to_wire(context)),
        handle: request.handle.as_ref().map(handle_to_wire),
    }
}

/// Validate the wire form of a load request.
pub fn load_request_from_wire(
    wire: &v1::LoadRequest,
) -> Result<PluginLoadRequest, PluginProtocolError> {
    if wire.plugin_id.trim().is_empty() {
        return Err(malformed("a load request with no plugin identity"));
    }
    if wire.artifact.trim().is_empty() {
        return Err(malformed("a load request with no artifact reference"));
    }
    // Both digests are required. A load request without them would let whoever
    // performs the load decide for itself what the reference points at, which
    // is the hole the identity exists to close.
    if wire.manifest_digest.trim().is_empty() {
        return Err(malformed("a load request with no approved manifest digest"));
    }
    if wire.library_digest.trim().is_empty() {
        return Err(malformed("a load request with no approved library digest"));
    }
    Ok(PluginLoadRequest {
        plugin_id: wire.plugin_id.clone(),
        artifact: wire.artifact.clone(),
        identity: PluginArtifactIdentity {
            manifest_sha256: wire.manifest_digest.clone(),
            library_sha256: wire.library_digest.clone(),
        },
    })
}

/// Build the wire form of an execution context.
///
/// Total and lossless: every domain field has a wire counterpart, which is why
/// `remaining_budget_millis` was added to the domain type rather than left as a
/// wire-only field the two sides could disagree about.
pub fn context_to_wire(context: &PluginExecutionContext) -> v1::PluginExecutionContext {
    v1::PluginExecutionContext {
        operation_request_id: context.operation_request_id.clone(),
        protocol_version: u32::from(context.protocol_version),
        runtime_binding_digest: context.runtime_binding_digest.clone(),
        deadline_unix_ms: context.deadline_unix_ms,
        remaining_budget_millis: context.remaining_budget_millis,
        max_response_bytes: context.max_response_bytes,
    }
}

/// Validate the wire form of an execution context.
pub fn context_from_wire(
    wire: &v1::PluginExecutionContext,
) -> Result<PluginExecutionContext, PluginProtocolError> {
    if wire.operation_request_id.trim().is_empty() {
        return Err(malformed("an operation with no identity"));
    }
    if wire.runtime_binding_digest.trim().is_empty() {
        return Err(malformed("an operation with no runtime binding"));
    }
    // A version above `u16` cannot be one this code speaks, so refusing here is
    // more honest than truncating it into something that might match.
    let protocol_version = u16::try_from(wire.protocol_version)
        .map_err(|_| malformed("a protocol version outside the range this code speaks"))?;
    Ok(PluginExecutionContext {
        operation_request_id: wire.operation_request_id.clone(),
        protocol_version,
        runtime_binding_digest: wire.runtime_binding_digest.clone(),
        deadline_unix_ms: wire.deadline_unix_ms,
        remaining_budget_millis: wire.remaining_budget_millis,
        max_response_bytes: wire.max_response_bytes,
    })
}

/// Build the wire form of a structured failure.
pub fn failure_to_wire(failure: &PluginFailure) -> v1::PluginFailure {
    let mut wire = v1::PluginFailure {
        code: failure_code_to_wire(&failure.code),
        message: failure.message.clone(),
        ..Default::default()
    };
    match &failure.code {
        PluginFailureCode::VersionMismatch { expected, received } => {
            wire.expected_version = Some(u32::from(*expected));
            wire.received_version = Some(u32::from(*received));
        }
        PluginFailureCode::AbiMismatch {
            supported,
            reported,
        } => {
            wire.expected_version = Some(u32::from(*supported));
            wire.received_version = Some(u32::from(*reported));
        }
        PluginFailureCode::OversizedFrame { observed, limit } => {
            wire.observed = Some(*observed);
            wire.limit = Some(*limit);
        }
        _ => {}
    }
    wire
}

/// Validate the wire form of a structured failure.
///
/// The flattened wire shape permits combinations the domain cannot represent —
/// a version mismatch without versions, a crash carrying a size limit — so each
/// code is checked against exactly the detail it requires. Anything else is a
/// malformed message from a peer, not a failure core should act on.
pub fn failure_from_wire(wire: &v1::PluginFailure) -> Result<PluginFailure, PluginProtocolError> {
    let code = failure_code_from_wire(wire.code)?;
    let detail_is_absent = wire.observed.is_none()
        && wire.limit.is_none()
        && wire.expected_version.is_none()
        && wire.received_version.is_none();

    let code = match code {
        PluginFailureCode::VersionMismatch {
            expected: _,
            received: _,
        } => {
            let (Some(expected), Some(received)) = (wire.expected_version, wire.received_version)
            else {
                return Err(malformed(
                    "a version mismatch without both versions, which cannot describe a mismatch",
                ));
            };
            if wire.observed.is_some() || wire.limit.is_some() {
                return Err(malformed("a version mismatch carrying frame-size detail"));
            }
            PluginFailureCode::VersionMismatch {
                expected: u16::try_from(expected).map_err(|_| {
                    malformed("an expected version outside the range this code speaks")
                })?,
                received: u16::try_from(received).map_err(|_| {
                    malformed("a received version outside the range this code speaks")
                })?,
            }
        }
        PluginFailureCode::OversizedFrame {
            observed: _,
            limit: _,
        } => {
            let (Some(observed), Some(limit)) = (wire.observed, wire.limit) else {
                return Err(malformed(
                    "an oversized frame without both the observed size and the limit",
                ));
            };
            if wire.expected_version.is_some() || wire.received_version.is_some() {
                return Err(malformed("an oversized frame carrying version detail"));
            }
            PluginFailureCode::OversizedFrame { observed, limit }
        }
        PluginFailureCode::AbiMismatch {
            supported: _,
            reported: _,
        } => {
            let (Some(supported), Some(reported)) = (wire.expected_version, wire.received_version)
            else {
                return Err(malformed("an ABI mismatch without both versions"));
            };
            // The same exclusivity the other detailed codes enforce. Without
            // it a message could claim an ABI mismatch and carry frame sizes,
            // which describes nothing the domain can represent.
            if wire.observed.is_some() || wire.limit.is_some() {
                return Err(malformed("an ABI mismatch carrying frame-size detail"));
            }
            PluginFailureCode::AbiMismatch {
                supported: u16::try_from(supported)
                    .map_err(|_| malformed("a supported ABI outside the range this code speaks"))?,
                reported: u16::try_from(reported)
                    .map_err(|_| malformed("a reported ABI outside the range this code speaks"))?,
            }
        }
        plain => {
            if !detail_is_absent {
                return Err(malformed(
                    "a failure carrying detail its code does not define",
                ));
            }
            plain
        }
    };

    Ok(PluginFailure {
        code,
        message: wire.message.clone(),
    })
}

/// Validate a loaded plugin's description.
pub fn descriptor_from_wire(
    wire: &v1::PluginDescriptor,
) -> Result<PluginDescriptor, PluginProtocolError> {
    if wire.plugin_id.trim().is_empty() {
        return Err(malformed("a descriptor with no plugin identity"));
    }
    let mut capabilities = Vec::with_capacity(wire.capabilities.len());
    for capability in &wire.capabilities {
        if capability.id.trim().is_empty() {
            return Err(malformed("a capability with no identity"));
        }
        if capabilities
            .iter()
            .any(|existing: &PluginCapability| existing.id == capability.id)
        {
            // Two capabilities with one identity describe different things
            // under one name, and a caller that resolved either would get
            // whichever it happened to find first.
            return Err(malformed(format!(
                "a capability named {} twice",
                capability.id
            )));
        }
        capabilities.push(PluginCapability {
            id: capability.id.clone(),
            kind: capability_kind_from_wire(capability.kind)?,
            declared_digest: capability.declared_digest.clone(),
        });
    }
    let mut registrations = Vec::with_capacity(wire.registrations.len());
    for registration in &wire.registrations {
        let registration = registration_from_wire(registration)?;
        if registrations
            .iter()
            .any(|existing: &PluginRegistrationDescriptor| {
                existing.registration_id == registration.registration_id
                    && existing.operation == registration.operation
            })
        {
            return Err(malformed(format!(
                "a registration named {} twice at the same attachment point",
                registration.registration_id
            )));
        }
        registrations.push(registration);
    }
    Ok(PluginDescriptor {
        plugin_id: wire.plugin_id.clone(),
        plugin_version: wire.plugin_version.clone(),
        negotiated_abi_version: match wire.negotiated_abi_version {
            None => None,
            Some(version) => {
                Some(u16::try_from(version).map_err(|_| {
                    malformed("a negotiated ABI outside the range this code speaks")
                })?)
            }
        },
        manifest_digest: wire.manifest_digest.clone(),
        registration_kinds: wire.registration_kinds.clone(),
        registrations,
        capabilities,
    })
}

// The outbound half. A host answers with these, so they are total: every domain
// value has exactly one wire form, and only the *inbound* direction can fail,
// because only that direction can be handed something that means nothing.

/// Build the wire form of a plugin handle.
pub fn handle_to_wire(handle: &PluginHandle) -> v1::PluginHandle {
    v1::PluginHandle {
        plugin_id: handle.plugin_id.clone(),
        generation: handle.generation,
    }
}

/// Build the wire form of a capability.
pub fn capability_to_wire(capability: &PluginCapability) -> v1::PluginCapability {
    v1::PluginCapability {
        id: capability.id.clone(),
        kind: capability_kind_to_wire(capability.kind) as i32,
        declared_digest: capability.declared_digest.clone(),
    }
}

/// Build the wire form of one registration description.
pub fn registration_to_wire(
    registration: &PluginRegistrationDescriptor,
) -> v1::PluginRegistrationDescriptor {
    v1::PluginRegistrationDescriptor {
        registration_id: registration.registration_id.clone(),
        component_kind: registration.component_kind.clone(),
        ordering: Some(v1::PluginRegistrationOrdering {
            priority: registration.ordering.priority,
            may_break_chain: registration.ordering.may_break_chain,
        }),
        shape: shape_to_wire(registration.shape),
        config_keys: registration.config_keys.clone(),
        declared_digest: registration.declared_digest.clone(),
        operation: registration_operation_to_wire(registration.operation),
        gated_registration: registration.gated_registration.clone(),
    }
}

/// Build the wire form of a plugin description.
pub fn descriptor_to_wire(descriptor: &PluginDescriptor) -> v1::PluginDescriptor {
    v1::PluginDescriptor {
        plugin_id: descriptor.plugin_id.clone(),
        plugin_version: descriptor.plugin_version.clone(),
        negotiated_abi_version: descriptor.negotiated_abi_version.map(u32::from),
        manifest_digest: descriptor.manifest_digest.clone(),
        registration_kinds: descriptor.registration_kinds.clone(),
        registrations: descriptor
            .registrations
            .iter()
            .map(registration_to_wire)
            .collect(),
        capabilities: descriptor
            .capabilities
            .iter()
            .map(capability_to_wire)
            .collect(),
    }
}

/// Build the wire form of a host health report.
pub fn health_to_wire(health: &PluginHostHealth) -> v1::HealthResponse {
    v1::HealthResponse {
        protocol_version: u32::from(health.protocol_version),
        accepting_work: health.accepting_work,
        loaded: health.loaded.iter().map(handle_to_wire).collect(),
    }
}

/// Build the wire form of an established session.
pub fn session_identity_to_wire(identity: &PluginSessionIdentity) -> v1::HandshakeResponse {
    v1::HandshakeResponse {
        protocol_version: u32::from(identity.protocol_version),
        session_id: identity.session_id.clone(),
        host_instance_id: identity.host_instance_id.clone(),
        host_nonce: identity.host_nonce.clone(),
        maximum_frame_bytes: identity.maximum_frame_bytes,
        supported_features: identity.supported_features.clone(),
        accepted_read_capabilities: identity
            .accepted_read_capabilities
            .iter()
            .map(|capability| read_capability_to_wire(*capability))
            .collect(),
    }
}

/// Build the wire form of a lifecycle outcome.
pub fn handshake_outcome_to_wire(
    outcome: LifecycleOutcome<PluginSessionIdentity>,
) -> v1::HandshakeOutcome {
    v1::HandshakeOutcome {
        result: Some(match outcome {
            LifecycleOutcome::Completed(identity) => {
                v1::handshake_outcome::Result::Established(session_identity_to_wire(&identity))
            }
            LifecycleOutcome::Failed(failure) => {
                v1::handshake_outcome::Result::Failure(failure_to_wire(&failure))
            }
        }),
    }
}

/// Build the wire form of a load outcome.
pub fn load_outcome_to_wire(outcome: LifecycleOutcome<PluginLoadResponse>) -> v1::LoadOutcome {
    v1::LoadOutcome {
        result: Some(match outcome {
            LifecycleOutcome::Completed(response) => {
                v1::load_outcome::Result::Loaded(v1::LoadResponse {
                    handle: Some(handle_to_wire(&response.handle)),
                    descriptor: Some(descriptor_to_wire(&response.descriptor)),
                })
            }
            LifecycleOutcome::Failed(failure) => {
                v1::load_outcome::Result::Failure(failure_to_wire(&failure))
            }
        }),
    }
}

/// Build the wire form of an unload outcome.
pub fn unload_outcome_to_wire(outcome: LifecycleOutcome<()>) -> v1::UnloadOutcome {
    v1::UnloadOutcome {
        result: Some(match outcome {
            LifecycleOutcome::Completed(()) => {
                v1::unload_outcome::Result::Unloaded(v1::UnloadResponse {})
            }
            LifecycleOutcome::Failed(failure) => {
                v1::unload_outcome::Result::Failure(failure_to_wire(&failure))
            }
        }),
    }
}

/// Build the wire form of an inspection outcome.
pub fn inspect_outcome_to_wire(
    outcome: LifecycleOutcome<Vec<PluginDescriptor>>,
) -> v1::InspectOutcome {
    v1::InspectOutcome {
        result: Some(match outcome {
            LifecycleOutcome::Completed(descriptors) => {
                v1::inspect_outcome::Result::Inspected(v1::InspectResponse {
                    descriptors: descriptors.iter().map(descriptor_to_wire).collect(),
                })
            }
            LifecycleOutcome::Failed(failure) => {
                v1::inspect_outcome::Result::Failure(failure_to_wire(&failure))
            }
        }),
    }
}

/// Build the wire form of a cancellation outcome.
pub fn cancel_outcome_to_wire(outcome: LifecycleOutcome<()>) -> v1::CancelOperationOutcome {
    v1::CancelOperationOutcome {
        result: Some(match outcome {
            LifecycleOutcome::Completed(()) => {
                v1::cancel_operation_outcome::Result::Cancelled(v1::CancelOperationResponse {})
            }
            LifecycleOutcome::Failed(failure) => {
                v1::cancel_operation_outcome::Result::Failure(failure_to_wire(&failure))
            }
        }),
    }
}

/// Build the wire form of a health outcome.
pub fn health_outcome_to_wire(outcome: LifecycleOutcome<PluginHostHealth>) -> v1::HealthOutcome {
    v1::HealthOutcome {
        result: Some(match outcome {
            LifecycleOutcome::Completed(health) => {
                v1::health_outcome::Result::Health(health_to_wire(&health))
            }
            LifecycleOutcome::Failed(failure) => {
                v1::health_outcome::Result::Failure(failure_to_wire(&failure))
            }
        }),
    }
}

/// Build the wire form of a shape.
fn shape_to_wire(shape: PluginExecutionShape) -> i32 {
    let wire = match shape {
        PluginExecutionShape::Unary => v1::PluginExecutionShape::ShapeUnary,
        PluginExecutionShape::Streaming => v1::PluginExecutionShape::ShapeStreaming,
    };
    wire as i32
}

/// Build the wire form of a capability kind.
fn capability_kind_to_wire(kind: PluginCapabilityKind) -> v1::PluginCapabilityKind {
    match kind {
        PluginCapabilityKind::Tool => v1::PluginCapabilityKind::Tool,
        PluginCapabilityKind::Llm => v1::PluginCapabilityKind::Llm,
        PluginCapabilityKind::Subscriber => v1::PluginCapabilityKind::Subscriber,
    }
}

/// The attachment point a wire registration names.
///
/// The match is exhaustive on purpose. A registration surface the runtime gains
/// and this vocabulary has not been told about fails to compile here rather than
/// reaching a peer as a value it would have to guess at.
pub fn registration_operation_to_wire(operation: PluginRegistrationOperation) -> i32 {
    use PluginRegistrationOperation as Operation;
    let wire = match operation {
        Operation::Subscriber => v1::PluginRegistrationOperation::RegistrationOperationSubscriber,
        Operation::EventMetadataInjector => {
            v1::PluginRegistrationOperation::RegistrationOperationEventMetadataInjector
        }
        Operation::MarkSanitizeGuardrail => {
            v1::PluginRegistrationOperation::RegistrationOperationMarkSanitizeGuardrail
        }
        Operation::ScopeSanitizeStartGuardrail => {
            v1::PluginRegistrationOperation::RegistrationOperationScopeSanitizeStartGuardrail
        }
        Operation::ScopeSanitizeEndGuardrail => {
            v1::PluginRegistrationOperation::RegistrationOperationScopeSanitizeEndGuardrail
        }
        Operation::ToolSanitizeRequestGuardrail => {
            v1::PluginRegistrationOperation::RegistrationOperationToolSanitizeRequestGuardrail
        }
        Operation::ToolSanitizeResponseGuardrail => {
            v1::PluginRegistrationOperation::RegistrationOperationToolSanitizeResponseGuardrail
        }
        Operation::ToolConditionalExecutionGuardrail => {
            v1::PluginRegistrationOperation::RegistrationOperationToolConditionalExecutionGuardrail
        }
        Operation::ToolRequestIntercept => {
            v1::PluginRegistrationOperation::RegistrationOperationToolRequestIntercept
        }
        Operation::ToolExecutionIntercept => {
            v1::PluginRegistrationOperation::RegistrationOperationToolExecutionIntercept
        }
        Operation::LlmSanitizeRequestGuardrail => {
            v1::PluginRegistrationOperation::RegistrationOperationLlmSanitizeRequestGuardrail
        }
        Operation::LlmSanitizeResponseGuardrail => {
            v1::PluginRegistrationOperation::RegistrationOperationLlmSanitizeResponseGuardrail
        }
        Operation::LlmConditionalExecutionGuardrail => {
            v1::PluginRegistrationOperation::RegistrationOperationLlmConditionalExecutionGuardrail
        }
        Operation::LlmRequestIntercept => {
            v1::PluginRegistrationOperation::RegistrationOperationLlmRequestIntercept
        }
        Operation::LlmExecutionIntercept => {
            v1::PluginRegistrationOperation::RegistrationOperationLlmExecutionIntercept
        }
        Operation::LlmStreamExecutionIntercept => {
            v1::PluginRegistrationOperation::RegistrationOperationLlmStreamExecutionIntercept
        }
    };
    wire as i32
}

/// Read the attachment point a wire registration names.
pub fn registration_operation_from_wire(
    value: i32,
) -> Result<PluginRegistrationOperation, PluginProtocolError> {
    use PluginRegistrationOperation as Operation;
    let wire = v1::PluginRegistrationOperation::try_from(value)
        .map_err(|_| malformed(format!("an unknown registration operation {value}")))?;
    Ok(match wire {
        v1::PluginRegistrationOperation::Unspecified => {
            return Err(malformed("a registration with no attachment point"));
        }
        v1::PluginRegistrationOperation::RegistrationOperationSubscriber => Operation::Subscriber,
        v1::PluginRegistrationOperation::RegistrationOperationEventMetadataInjector => {
            Operation::EventMetadataInjector
        }
        v1::PluginRegistrationOperation::RegistrationOperationMarkSanitizeGuardrail => {
            Operation::MarkSanitizeGuardrail
        }
        v1::PluginRegistrationOperation::RegistrationOperationScopeSanitizeStartGuardrail => {
            Operation::ScopeSanitizeStartGuardrail
        }
        v1::PluginRegistrationOperation::RegistrationOperationScopeSanitizeEndGuardrail => {
            Operation::ScopeSanitizeEndGuardrail
        }
        v1::PluginRegistrationOperation::RegistrationOperationToolSanitizeRequestGuardrail => {
            Operation::ToolSanitizeRequestGuardrail
        }
        v1::PluginRegistrationOperation::RegistrationOperationToolSanitizeResponseGuardrail => {
            Operation::ToolSanitizeResponseGuardrail
        }
        v1::PluginRegistrationOperation::RegistrationOperationToolConditionalExecutionGuardrail => {
            Operation::ToolConditionalExecutionGuardrail
        }
        v1::PluginRegistrationOperation::RegistrationOperationToolRequestIntercept => {
            Operation::ToolRequestIntercept
        }
        v1::PluginRegistrationOperation::RegistrationOperationToolExecutionIntercept => {
            Operation::ToolExecutionIntercept
        }
        v1::PluginRegistrationOperation::RegistrationOperationLlmSanitizeRequestGuardrail => {
            Operation::LlmSanitizeRequestGuardrail
        }
        v1::PluginRegistrationOperation::RegistrationOperationLlmSanitizeResponseGuardrail => {
            Operation::LlmSanitizeResponseGuardrail
        }
        v1::PluginRegistrationOperation::RegistrationOperationLlmConditionalExecutionGuardrail => {
            Operation::LlmConditionalExecutionGuardrail
        }
        v1::PluginRegistrationOperation::RegistrationOperationLlmRequestIntercept => {
            Operation::LlmRequestIntercept
        }
        v1::PluginRegistrationOperation::RegistrationOperationLlmExecutionIntercept => {
            Operation::LlmExecutionIntercept
        }
        v1::PluginRegistrationOperation::RegistrationOperationLlmStreamExecutionIntercept => {
            Operation::LlmStreamExecutionIntercept
        }
    })
}

/// A registration the runtime cannot place is worse than a missing one, because
/// the proxy would be built and then behave unlike the plugin it stands for.
/// Every field that decides where it goes is therefore required rather than
/// defaulted, and the shape has to agree with the attachment point rather than
/// being taken on faith.
fn registration_from_wire(
    wire: &v1::PluginRegistrationDescriptor,
) -> Result<PluginRegistrationDescriptor, PluginProtocolError> {
    if wire.registration_id.trim().is_empty() {
        return Err(malformed("a registration with no identity"));
    }
    if wire.component_kind.trim().is_empty() {
        return Err(malformed("a registration with no component kind"));
    }
    let operation = registration_operation_from_wire(wire.operation)?;
    let shape = v1::PluginExecutionShape::try_from(wire.shape)
        .map_err(|_| malformed(format!("an unknown execution shape {}", wire.shape)))?;
    let shape = match shape {
        v1::PluginExecutionShape::Unspecified => {
            return Err(malformed(
                "a registration that does not say whether it answers once or streams",
            ));
        }
        v1::PluginExecutionShape::ShapeUnary => PluginExecutionShape::Unary,
        v1::PluginExecutionShape::ShapeStreaming => PluginExecutionShape::Streaming,
    };
    if shape != registration_shape(operation) {
        return Err(malformed(format!(
            "a registration at {} declaring a {} shape",
            operation.as_str(),
            match shape {
                PluginExecutionShape::Unary => "unary",
                PluginExecutionShape::Streaming => "streaming",
            }
        )));
    }
    let ordering = match wire.ordering.as_ref() {
        Some(ordering) => PluginRegistrationOrdering {
            priority: ordering.priority,
            may_break_chain: ordering.may_break_chain,
        },
        None => PluginRegistrationOrdering {
            priority: None,
            may_break_chain: None,
        },
    };
    if let Some(gated) = wire.gated_registration.as_ref()
        && gated.trim().is_empty()
    {
        // An empty target names no registration, which is a gate that decides
        // nothing rather than a gate whose target is unknown.
        return Err(malformed("a gate naming an empty registration"));
    }

    Ok(PluginRegistrationDescriptor {
        registration_id: wire.registration_id.clone(),
        component_kind: wire.component_kind.clone(),
        operation,
        ordering,
        shape,
        gated_registration: wire.gated_registration.clone(),
        config_keys: wire.config_keys.clone(),
        declared_digest: wire.declared_digest.clone(),
    })
}

/// Validate a load response.
pub fn load_response_from_wire(
    wire: &v1::LoadResponse,
) -> Result<PluginLoadResponse, PluginProtocolError> {
    let handle = wire
        .handle
        .as_ref()
        .ok_or_else(|| malformed("a load response with no handle"))?;
    if handle.plugin_id.trim().is_empty() {
        return Err(malformed("a handle with no plugin identity"));
    }
    if handle.generation == 0 {
        // Generation zero is what the default value gives, and a real load
        // never produces it: generations start at one.
        return Err(malformed(
            "a handle at generation zero, which no load produces",
        ));
    }
    let descriptor = wire
        .descriptor
        .as_ref()
        .ok_or_else(|| malformed("a load response with no descriptor"))?;
    let descriptor = descriptor_from_wire(descriptor)?;
    // Both halves describe the same loaded instance. Individually valid fields
    // that name different plugins would produce a handle which addresses one
    // plugin while carrying another's description.
    if descriptor.plugin_id != handle.plugin_id {
        return Err(malformed(format!(
            "a load response whose handle names {} and whose descriptor names {}",
            handle.plugin_id, descriptor.plugin_id
        )));
    }
    Ok(PluginLoadResponse {
        handle: PluginHandle {
            plugin_id: handle.plugin_id.clone(),
            generation: handle.generation,
        },
        descriptor,
    })
}

/// Convert a domain outcome into its wire form.
///
/// The previous form took a bare success value and manufactured `NotDispatched`
/// with `ConfirmedSuccess`, which discards precisely the dispatch information
/// the outcome model exists to preserve: a caller would learn that an operation
/// definitely did not reach an external system without anyone having
/// established that. This takes the outcome, so what travels is what was
/// actually known.
pub fn execution_outcome_to_wire(
    outcome: &PluginExecutionOutcome,
) -> Result<v1::InvokeOutcome, PluginProtocolError> {
    let result = match &outcome.result {
        Ok(PluginSuccess::Invoked(response)) => {
            v1::invoke_outcome::Result::Output(response.output.clone())
        }
        Ok(other) => {
            return Err(malformed(format!(
                "{} has no invocation outcome representation",
                success_name(other)
            )));
        }
        Err(failure) => v1::invoke_outcome::Result::Failure(failure_to_wire(failure)),
    };
    Ok(v1::InvokeOutcome {
        dispatch_state: dispatch_to_wire(outcome.dispatch) as i32,
        outcome_certainty: outcome_to_wire(outcome.certainty) as i32,
        result: Some(result),
    })
}

/// Read an invocation outcome, refusing one that erases what is known.
pub fn execution_outcome_from_wire(
    wire: &v1::InvokeOutcome,
) -> Result<PluginExecutionOutcome, PluginProtocolError> {
    let dispatch = dispatch_from_wire(wire.dispatch_state)?;
    let certainty = certainty_from_wire(wire.outcome_certainty)?;
    let result = match wire.result.as_ref() {
        Some(v1::invoke_outcome::Result::Output(output)) => {
            Ok(PluginSuccess::Invoked(PluginInvokeResponse {
                output: output.clone(),
            }))
        }
        Some(v1::invoke_outcome::Result::Failure(failure)) => Err(failure_from_wire(failure)?),
        None => {
            return Err(malformed(
                "an invocation outcome that is neither an output nor a failure",
            ));
        }
    };
    Ok(PluginExecutionOutcome {
        dispatch,
        certainty,
        result,
    })
}

/// Validate a continuation request.
///
/// The operation identity is required: a continuation without it could not be
/// resumed at the right chain position, and the runtime would have to guess
/// which chain the invocation belongs to.
pub fn continuation_request_from_wire(
    wire: &v1::ContinuationRequest,
) -> Result<PluginContinuationRequest, PluginProtocolError> {
    if wire.session_id.trim().is_empty() {
        return Err(malformed("a continuation that names no session"));
    }
    Ok(PluginContinuationRequest {
        operation_request_id: required_text(
            &wire.operation_request_id,
            "a continuation that belongs to no operation",
        )?,
        host_call_id: required_text(&wire.host_call_id, "a continuation with no call identity")?,
        invocation_json: required_text(
            &wire.invocation_json,
            "a continuation with nothing to run",
        )?,
    })
}

/// Build the wire form of a continuation request.
pub fn continuation_request_to_wire(
    request: &PluginContinuationRequest,
    session_id: &str,
) -> v1::ContinuationRequest {
    v1::ContinuationRequest {
        session_id: session_id.to_owned(),
        operation_request_id: request.operation_request_id.clone(),
        host_call_id: request.host_call_id.clone(),
        invocation_json: request.invocation_json.clone(),
    }
}

/// Validate the envelope every host operation carries.
///
/// This is the first layer: the parts of a message that are the same whatever
/// the operation is. A payload is only looked at once these hold, so a request
/// that names no session or carries no context is refused before anything is
/// converted from it.
pub fn operation_envelope_from_wire(
    session_id: &str,
    context: Option<&v1::PluginExecutionContext>,
) -> Result<PluginOperationEnvelope, PluginProtocolError> {
    let session_id = required_text(session_id, "an operation that names no session")?;
    let context = match context {
        Some(context) => context_from_wire(context)?,
        None => {
            return Err(malformed(
                "an operation with no context, and therefore no budget",
            ));
        }
    };
    Ok(PluginOperationEnvelope {
        session_id,
        context,
    })
}

/// Validate a handle a host operation names.
///
/// A handle addresses exactly one loaded instance: without an identity it names
/// nothing, and at generation zero it names an instance no load produced.
pub fn plugin_handle_from_wire(
    handle: Option<&v1::PluginHandle>,
    what: &str,
) -> Result<PluginHandle, PluginProtocolError> {
    let handle = handle.ok_or_else(|| malformed(format!("{what} with no handle")))?;
    if handle.generation == 0 {
        return Err(malformed(format!("{what} at generation zero")));
    }
    Ok(PluginHandle {
        plugin_id: required_text(
            &handle.plugin_id,
            &format!("{what} with no plugin identity"),
        )?,
        generation: handle.generation,
    })
}

/// Validate an unload request.
pub fn unload_request_from_wire(
    wire: &v1::UnloadRequest,
) -> Result<PluginUnloadRequest, PluginProtocolError> {
    Ok(PluginUnloadRequest {
        handle: plugin_handle_from_wire(wire.handle.as_ref(), "an unload")?,
    })
}

/// Validate an inspection request.
///
/// A missing handle means "everything loaded", which is a question rather than
/// a gap, so this is the one operation where an absent handle is not refused.
pub fn inspect_request_from_wire(
    wire: &v1::InspectRequest,
) -> Result<PluginInspectRequest, PluginProtocolError> {
    Ok(PluginInspectRequest {
        handle: match wire.handle.as_ref() {
            Some(handle) => Some(plugin_handle_from_wire(Some(handle), "an inspection")?),
            None => None,
        },
    })
}

/// Validate an invocation request against the context it belongs to.
///
/// The budget is not on the request: it comes from the context, which is the
/// value the kernel derives and the host enforces. Reading it from anywhere else
/// would let a caller choose its own deadline.
pub fn invoke_request_from_wire(
    wire: &v1::InvokeRequest,
    context: &PluginExecutionContext,
) -> Result<PluginInvokeRequest, PluginProtocolError> {
    Ok(PluginInvokeRequest {
        handle: plugin_handle_from_wire(wire.handle.as_ref(), "an invocation")?,
        capability_id: required_text(
            &wire.capability_id,
            "an invocation with no capability to invoke",
        )?,
        arguments: required_text(&wire.arguments, "an invocation with no arguments")?,
        budget_millis: context.remaining_budget_millis,
    })
}

/// Read a scope operation.
fn scope_operation_from_wire(value: i32) -> Result<PluginScopeOperation, PluginProtocolError> {
    let wire = v1::ScopeOperation::try_from(value)
        .map_err(|_| malformed(format!("an unknown scope operation {value}")))?;
    Ok(match wire {
        v1::ScopeOperation::Unspecified => {
            return Err(malformed("a scope call that does not say what to do"));
        }
        v1::ScopeOperation::Current => PluginScopeOperation::Current,
        v1::ScopeOperation::Push => PluginScopeOperation::Push,
        v1::ScopeOperation::Pop => PluginScopeOperation::Pop,
        v1::ScopeOperation::CreateIsolated => PluginScopeOperation::CreateIsolated,
        v1::ScopeOperation::ReleaseIsolated => PluginScopeOperation::ReleaseIsolated,
    })
}

/// Build the wire form of a scope operation.
pub fn scope_operation_to_wire(operation: PluginScopeOperation) -> i32 {
    let wire = match operation {
        PluginScopeOperation::Current => v1::ScopeOperation::Current,
        PluginScopeOperation::Push => v1::ScopeOperation::Push,
        PluginScopeOperation::Pop => v1::ScopeOperation::Pop,
        PluginScopeOperation::CreateIsolated => v1::ScopeOperation::CreateIsolated,
        PluginScopeOperation::ReleaseIsolated => v1::ScopeOperation::ReleaseIsolated,
    };
    wire as i32
}

/// Read a codec operation.
fn codec_operation_from_wire(value: i32) -> Result<PluginCodecOperation, PluginProtocolError> {
    let wire = v1::CodecOperation::try_from(value)
        .map_err(|_| malformed(format!("an unknown codec operation {value}")))?;
    Ok(match wire {
        v1::CodecOperation::Unspecified => {
            return Err(malformed("a codec call that does not say what to do"));
        }
        v1::CodecOperation::LlmRequestDecode => PluginCodecOperation::LlmRequestDecode,
        v1::CodecOperation::LlmRequestEncode => PluginCodecOperation::LlmRequestEncode,
        v1::CodecOperation::LlmResponseDecode => PluginCodecOperation::LlmResponseDecode,
    })
}

/// Build the wire form of a codec operation.
pub fn codec_operation_to_wire(operation: PluginCodecOperation) -> i32 {
    let wire = match operation {
        PluginCodecOperation::LlmRequestDecode => v1::CodecOperation::LlmRequestDecode,
        PluginCodecOperation::LlmRequestEncode => v1::CodecOperation::LlmRequestEncode,
        PluginCodecOperation::LlmResponseDecode => v1::CodecOperation::LlmResponseDecode,
    };
    wire as i32
}

/// Read a mark severity. Absence is absence; a present `UNSPECIFIED` is not.
fn severity_from_wire(value: i32) -> Result<LogSeverity, PluginProtocolError> {
    let wire = v1::MarkSeverity::try_from(value)
        .map_err(|_| malformed(format!("an unknown mark severity {value}")))?;
    Ok(match wire {
        v1::MarkSeverity::Unspecified => {
            return Err(malformed("a mark that says its severity is unspecified"));
        }
        v1::MarkSeverity::Trace => LogSeverity::Trace,
        v1::MarkSeverity::Debug => LogSeverity::Debug,
        v1::MarkSeverity::Info => LogSeverity::Info,
        v1::MarkSeverity::Warn => LogSeverity::Warn,
        v1::MarkSeverity::Error => LogSeverity::Error,
    })
}

/// Build the wire form of a mark severity.
pub fn severity_to_wire(severity: LogSeverity) -> i32 {
    let wire = match severity {
        LogSeverity::Trace => v1::MarkSeverity::Trace,
        LogSeverity::Debug => v1::MarkSeverity::Debug,
        LogSeverity::Info => v1::MarkSeverity::Info,
        LogSeverity::Warn => v1::MarkSeverity::Warn,
        LogSeverity::Error => v1::MarkSeverity::Error,
    };
    wire as i32
}

/// Read a chunk decision. `UNSPECIFIED` is refused: an answer that says nothing
/// would leave the runtime neither producing nor stopping.
fn chunk_disposition_from_wire(value: i32) -> Result<PluginChunkDecision, PluginProtocolError> {
    let wire = v1::ChunkDisposition::try_from(value)
        .map_err(|_| malformed(format!("an unknown chunk disposition {value}")))?;
    Ok(match wire {
        v1::ChunkDisposition::Unspecified => {
            return Err(malformed(
                "a chunk answer that says neither continue nor stop",
            ));
        }
        v1::ChunkDisposition::Continue => PluginChunkDecision::Continue,
        v1::ChunkDisposition::Stop => PluginChunkDecision::Stop,
    })
}

/// Build the wire form of a chunk decision.
pub fn chunk_disposition_to_wire(decision: PluginChunkDecision) -> i32 {
    let wire = match decision {
        PluginChunkDecision::Continue => v1::ChunkDisposition::Continue,
        PluginChunkDecision::Stop => v1::ChunkDisposition::Stop,
    };
    wire as i32
}

/// Read one requested or granted kernel read capability.
fn read_capability_from_wire(value: i32) -> Result<PluginHostReadCapability, PluginProtocolError> {
    let wire = v1::HostReadCapability::try_from(value)
        .map_err(|_| malformed(format!("an unknown read capability {value}")))?;
    Ok(match wire {
        v1::HostReadCapability::Unspecified => {
            return Err(malformed("a read capability that is unspecified"));
        }
        v1::HostReadCapability::RuntimeDiagnostics => PluginHostReadCapability::RuntimeDiagnostics,
        v1::HostReadCapability::RegistrationInventory => {
            PluginHostReadCapability::RegistrationInventory
        }
    })
}

/// Build the wire form of a read capability.
pub fn read_capability_to_wire(capability: PluginHostReadCapability) -> i32 {
    let wire = match capability {
        PluginHostReadCapability::RuntimeDiagnostics => v1::HostReadCapability::RuntimeDiagnostics,
        PluginHostReadCapability::RegistrationInventory => {
            v1::HostReadCapability::RegistrationInventory
        }
    };
    wire as i32
}

/// Read a list of read capabilities, refusing names this side does not know.
///
/// An unknown *offered* feature can be ignored, because ignoring it grants
/// nothing. A requested or granted capability is not an offer: it decides what a
/// less-trusted process may read, so a name this side cannot resolve is refused
/// rather than dropped.
fn read_capabilities_from_wire(
    values: &[i32],
    what: &str,
) -> Result<Vec<PluginHostReadCapability>, PluginProtocolError> {
    let mut capabilities = Vec::with_capacity(values.len());
    for value in values {
        let capability = read_capability_from_wire(*value)?;
        if capabilities.contains(&capability) {
            return Err(malformed(format!(
                "{} naming {} twice",
                what,
                capability_name(capability)
            )));
        }
        capabilities.push(capability);
    }
    Ok(capabilities)
}

fn capability_name(capability: PluginHostReadCapability) -> &'static str {
    match capability {
        PluginHostReadCapability::RuntimeDiagnostics => "runtime diagnostics",
        PluginHostReadCapability::RegistrationInventory => "registration inventory",
    }
}

/// Validate a handshake request.
pub fn handshake_request_from_wire(
    wire: &v1::HandshakeRequest,
) -> Result<PluginHandshakeRequest, PluginProtocolError> {
    if wire.runtime_binding_digest.trim().is_empty() {
        return Err(malformed("a handshake naming no runtime binding"));
    }
    if wire.client_nonce.trim().is_empty() {
        return Err(malformed("a handshake with no client nonce"));
    }
    if wire.session_credential.trim().is_empty() {
        return Err(malformed("a handshake with no session credential"));
    }
    if wire.maximum_frame_bytes == 0 {
        return Err(malformed("a handshake that will not accept a frame at all"));
    }
    if wire.maximum_frame_bytes > MAX_FRAME_BYTES {
        return Err(malformed(format!(
            "a handshake offering a frame limit of {} bytes, above the {} this side speaks",
            wire.maximum_frame_bytes, MAX_FRAME_BYTES
        )));
    }
    Ok(PluginHandshakeRequest {
        protocol_version: u16::try_from(wire.protocol_version).map_err(|_| {
            malformed("a handshake at a protocol version outside the range this code speaks")
        })?,
        runtime_binding_digest: wire.runtime_binding_digest.clone(),
        client_nonce: wire.client_nonce.clone(),
        session_credential: wire.session_credential.clone(),
        maximum_frame_bytes: wire.maximum_frame_bytes,
        supported_features: wire.supported_features.clone(),
        offered_read_capabilities: read_capabilities_from_wire(
            &wire.offered_read_capabilities,
            "a handshake request",
        )?,
    })
}

/// Validate a mark.
///
/// The optional fields stay optional, and a present-but-empty one is refused
/// rather than treated as absence: a payload that is the empty string is not a
/// payload, and a schema with no name describes nothing.
pub fn mark_request_from_wire(
    wire: &v1::EmitMarkRequest,
) -> Result<PluginMarkEmit, PluginProtocolError> {
    if wire.session_id.trim().is_empty() {
        return Err(malformed("a mark that names no session"));
    }
    let data_schema = match wire.data_schema.as_ref() {
        Some(schema) => Some(DataSchema {
            name: required_text(&schema.name, "a mark schema with no name")?,
            version: required_text(&schema.version, "a mark schema with no version")?,
        }),
        None => None,
    };
    let timestamp_unix_micros = match wire.timestamp_unix_micros {
        Some(timestamp) => Some(u64::try_from(timestamp).map_err(|_| {
            malformed("a mark timestamped before the Unix epoch, which cannot be ordered")
        })?),
        None => None,
    };
    Ok(PluginMarkEmit {
        operation_request_id: required_text(
            &wire.operation_request_id,
            "a mark that belongs to no operation",
        )?,
        host_call_id: required_text(&wire.host_call_id, "a mark with no call identity")?,
        name: required_text(&wire.name, "a mark with no name")?,
        data_json: optional_text(&wire.data_json, "a mark with an empty payload")?,
        parent: match wire.parent.as_ref() {
            Some(parent) => Some(PluginScopeReference::from_canonical(&parent.scope_id)?),
            None => None,
        },
        metadata_json: optional_text(&wire.metadata_json, "a mark with empty metadata")?,
        data_schema,
        severity: match wire.severity {
            Some(severity) => Some(severity_from_wire(severity)?),
            None => None,
        },
        timestamp_unix_micros,
    })
}

/// Validate a scope stack call.
///
/// Whether a payload belongs is a property of the operation, so a request that
/// carries one where it has no meaning, or omits one it needs, says two things
/// at once and is refused rather than resolved by preference.
pub fn scope_stack_request_from_wire(
    wire: &v1::ScopeStackRequest,
) -> Result<PluginScopeStackRequest, PluginProtocolError> {
    if wire.session_id.trim().is_empty() {
        return Err(malformed("a scope call that names no session"));
    }
    let operation = scope_operation_from_wire(wire.operation)?;
    let payload_json = optional_text(&wire.payload_json, "a scope call with an empty payload")?;
    if operation.carries_payload() != payload_json.is_some() {
        return Err(malformed(format!(
            "a scope call that {} a payload",
            if operation.carries_payload() {
                "omits"
            } else {
                "carries"
            }
        )));
    }
    Ok(PluginScopeStackRequest {
        operation_request_id: required_text(
            &wire.operation_request_id,
            "a scope call that belongs to no operation",
        )?,
        host_call_id: required_text(&wire.host_call_id, "a scope call with no call identity")?,
        operation,
        payload_json,
    })
}

/// Validate a cancellation request, returning the operation it names.
///
/// The operation identity is the whole payload: a cancellation that named
/// nothing would have to be matched to whatever was in flight.
pub fn cancel_operation_request_from_wire(
    wire: &v1::CancelOperationRequest,
) -> Result<String, PluginProtocolError> {
    required_text(
        &wire.operation_request_id,
        "a cancellation that names no operation",
    )
}

/// Read a host call's answer, refusing one that carries neither arm.
///
/// A host call that answered nothing would leave the plugin's call outstanding
/// with nothing coming, which is the one outcome it cannot recover from.
pub fn host_call_response_from_wire(
    output: Option<&String>,
    failure: Option<&v1::PluginFailure>,
    what: &str,
) -> Result<PluginHostCallOutcome, PluginProtocolError> {
    let result = match (output, failure) {
        (Some(output), None) => Ok(required_text(
            output,
            &format!("{what} with an empty answer"),
        )?),
        (None, Some(failure)) => Err(failure_from_wire(failure)?),
        (Some(_), Some(_)) => {
            return Err(malformed(format!("{what} that both answered and failed")));
        }
        (None, None) => {
            return Err(malformed(format!(
                "{what} that is neither an answer nor a failure"
            )));
        }
    };
    Ok(PluginHostCallOutcome { result })
}

/// Validate a scope stack answer.
pub fn scope_stack_response_from_wire(
    wire: &v1::ScopeStackResponse,
) -> Result<PluginHostCallOutcome, PluginProtocolError> {
    let (output, failure) = match wire.result.as_ref() {
        Some(v1::scope_stack_response::Result::Output(output)) => (Some(output), None),
        Some(v1::scope_stack_response::Result::Failure(failure)) => (None, Some(failure)),
        None => (None, None),
    };
    host_call_response_from_wire(output, failure, "a scope answer")
}

/// Validate a codec answer.
pub fn resolve_codec_response_from_wire(
    wire: &v1::ResolveCodecResponse,
) -> Result<PluginHostCallOutcome, PluginProtocolError> {
    let (output, failure) = match wire.result.as_ref() {
        Some(v1::resolve_codec_response::Result::Output(output)) => (Some(output), None),
        Some(v1::resolve_codec_response::Result::Failure(failure)) => (None, Some(failure)),
        None => (None, None),
    };
    host_call_response_from_wire(output, failure, "a codec answer")
}

/// Validate one frame of a streaming invocation.
///
/// A frame has to say what it is and what is known about it: a stream that
/// simply stops is a truncation, and the terminal frame is the only place the
/// dispatch state can be reported.
pub fn stream_chunk_from_wire(
    wire: &v1::StreamChunk,
) -> Result<PluginStreamChunk, PluginProtocolError> {
    let chunk = match wire.chunk.as_ref() {
        Some(v1::stream_chunk::Chunk::Data(data)) => {
            PluginStreamChunkKind::Data(required_text(data, "a stream frame with no data")?)
        }
        Some(v1::stream_chunk::Chunk::Failure(failure)) => {
            PluginStreamChunkKind::Failed(failure_from_wire(failure)?)
        }
        Some(v1::stream_chunk::Chunk::End(end)) if *end => PluginStreamChunkKind::End,
        Some(v1::stream_chunk::Chunk::End(_)) => {
            // `end = false` is a frame that says the stream has not ended, which
            // is what every non-terminal frame already says by carrying data.
            return Err(malformed("a stream frame that says it is not the end"));
        }
        None => return Err(malformed("a stream frame that carries nothing")),
    };
    Ok(PluginStreamChunk {
        operation_request_id: required_text(
            &wire.operation_request_id,
            "a stream frame that belongs to no operation",
        )?,
        chunk,
        dispatch: dispatch_from_wire(wire.dispatch_state)?,
        certainty: certainty_from_wire(wire.outcome_certainty)?,
    })
}

/// Validate a codec resolution.
pub fn resolve_codec_request_from_wire(
    wire: &v1::ResolveCodecRequest,
) -> Result<PluginResolveCodecRequest, PluginProtocolError> {
    if wire.session_id.trim().is_empty() {
        return Err(malformed("a codec call that names no session"));
    }
    Ok(PluginResolveCodecRequest {
        operation_request_id: required_text(
            &wire.operation_request_id,
            "a codec call that belongs to no operation",
        )?,
        host_call_id: required_text(&wire.host_call_id, "a codec call with no call identity")?,
        operation: codec_operation_from_wire(wire.operation)?,
        payload_json: required_text(&wire.payload_json, "a codec call with nothing to convert")?,
    })
}

/// Read one chunk of a continuation stream.
pub fn continuation_chunk_from_wire(
    wire: &v1::ContinuationChunk,
) -> Result<PluginContinuationChunk, PluginProtocolError> {
    if wire.sequence == 0 {
        // Sequences are one-based. Zero is what a default-constructed message
        // carries, and a chunk nobody ordered cannot be answered in order.
        return Err(malformed("a continuation chunk at sequence zero"));
    }
    Ok(PluginContinuationChunk {
        host_call_id: required_text(
            &wire.host_call_id,
            "a continuation chunk with no call identity",
        )?,
        sequence: wire.sequence,
        chunk_json: required_text(&wire.chunk_json, "a continuation chunk with no chunk")?,
    })
}

/// Read a grant of output capacity.
///
/// A grant of nothing is not a grant: it would leave the host reporting
/// backpressure forever with no way to tell that from a consumer that simply
/// stopped.
pub fn output_credit_from_wire(
    wire: &v1::OutputCredit,
) -> Result<PluginOutputCredit, PluginProtocolError> {
    if wire.items == 0 {
        return Err(malformed("a credit that grants no capacity"));
    }
    Ok(PluginOutputCredit {
        operation_request_id: required_text(
            &wire.operation_request_id,
            "a credit that belongs to no operation",
        )?,
        items: wire.items,
    })
}

/// Read a plugin's answer about one chunk.
pub fn continuation_disposition_from_wire(
    wire: &v1::ContinuationChunkDisposition,
) -> Result<PluginContinuationDisposition, PluginProtocolError> {
    if wire.sequence == 0 {
        return Err(malformed("a chunk answer at sequence zero"));
    }
    let disposition = match wire.disposition.as_ref() {
        Some(v1::continuation_chunk_disposition::Disposition::Decision(decision)) => {
            Ok(chunk_disposition_from_wire(*decision)?)
        }
        Some(v1::continuation_chunk_disposition::Disposition::Failure(failure)) => {
            Err(failure_from_wire(failure)?)
        }
        None => {
            return Err(malformed(
                "a chunk answer that says neither continue, stop, nor failure",
            ));
        }
    };
    Ok(PluginContinuationDisposition {
        host_call_id: required_text(&wire.host_call_id, "a chunk answer with no call identity")?,
        sequence: wire.sequence,
        disposition,
    })
}

/// Read a continuation outcome, refusing one that carries neither arm.
///
/// A continuation that answered nothing would leave the plugin's callback
/// waiting for a result that is never coming, which is the one outcome the
/// plugin cannot recover from.
pub fn continuation_outcome_from_wire(
    wire: &v1::ContinuationOutcome,
) -> Result<PluginHostCallOutcome, PluginProtocolError> {
    let result = match wire.result.as_ref() {
        Some(v1::continuation_outcome::Result::ValueJson(value)) => Ok(required_text(
            value,
            "a continuation that answered with nothing",
        )?),
        Some(v1::continuation_outcome::Result::Failure(failure)) => {
            Err(failure_from_wire(failure)?)
        }
        None => {
            return Err(malformed(
                "a continuation outcome that is neither a value nor a failure",
            ));
        }
    };
    Ok(PluginHostCallOutcome { result })
}

/// Build the wire form of a continuation outcome.
pub fn continuation_outcome_to_wire(outcome: &PluginHostCallOutcome) -> v1::ContinuationOutcome {
    v1::ContinuationOutcome {
        result: Some(match &outcome.result {
            Ok(value) => v1::continuation_outcome::Result::ValueJson(value.clone()),
            Err(failure) => v1::continuation_outcome::Result::Failure(failure_to_wire(failure)),
        }),
    }
}

/// Read one message from the duplex session.
///
/// The identities are the point of the channel: a stream item that named no
/// stream, or a settlement that named no completion, would have to be matched
/// to whatever was outstanding, and the side that guessed would be the trusted
/// one.
pub fn session_message_from_wire(
    wire: &v1::PluginSessionMessage,
) -> Result<PluginSessionMessage, PluginProtocolError> {
    if wire.session_id.trim().is_empty() {
        return Err(malformed("a session message naming no session"));
    }
    let message = match wire.message.as_ref() {
        Some(v1::plugin_session_message::Message::StreamOpen(open)) => {
            PluginSessionPayload::StreamOpen(PluginStreamOpenRequest {
                host_call_id: required_text(
                    &open.host_call_id,
                    "a stream open with no call identity",
                )?,
                operation_request_id: required_text(
                    &open.operation_request_id,
                    "a stream open that belongs to no operation",
                )?,
                request_json: required_text(&open.request_json, "a stream open with no request")?,
            })
        }
        Some(v1::plugin_session_message::Message::StreamOpened(opened)) => {
            PluginSessionPayload::StreamOpened(PluginStreamOpened {
                host_call_id: required_text(
                    &opened.host_call_id,
                    "an opened stream with no call identity",
                )?,
                stream_id: required_text(&opened.stream_id, "an opened stream with no identity")?,
            })
        }
        Some(v1::plugin_session_message::Message::StreamOpenFailed(failed)) => {
            PluginSessionPayload::StreamOpenFailed(PluginStreamOpenFailed {
                host_call_id: required_text(
                    &failed.host_call_id,
                    "a refused stream with no call identity",
                )?,
                failure: match failed.failure.as_ref() {
                    Some(failure) => failure_from_wire(failure)?,
                    None => return Err(malformed("a refused stream with no reason")),
                },
            })
        }
        Some(v1::plugin_session_message::Message::StreamPull(pull)) => {
            PluginSessionPayload::StreamPull(PluginStreamPullRequest {
                host_call_id: required_text(&pull.host_call_id, "a pull with no call identity")?,
                stream_id: required_text(&pull.stream_id, "a pull naming no stream")?,
            })
        }
        Some(v1::plugin_session_message::Message::StreamItem(item)) => {
            PluginSessionPayload::StreamItem(PluginStreamItem {
                host_call_id: required_text(
                    &item.host_call_id,
                    "a stream item with no call identity",
                )?,
                stream_id: required_text(&item.stream_id, "a stream item naming no stream")?,
                chunk_json: required_text(&item.chunk_json, "a stream item with no chunk")?,
            })
        }
        Some(v1::plugin_session_message::Message::StreamEnd(end)) => {
            PluginSessionPayload::StreamEnd(PluginStreamEnd {
                host_call_id: required_text(
                    &end.host_call_id,
                    "a stream end with no call identity",
                )?,
                stream_id: required_text(&end.stream_id, "a stream end naming no stream")?,
            })
        }
        Some(v1::plugin_session_message::Message::StreamFailed(failed)) => {
            PluginSessionPayload::StreamFailed(PluginStreamFailed {
                host_call_id: required_text(
                    &failed.host_call_id,
                    "a stream failure with no call identity",
                )?,
                stream_id: required_text(&failed.stream_id, "a stream failure naming no stream")?,
                failure: match failed.failure.as_ref() {
                    Some(failure) => failure_from_wire(failure)?,
                    None => return Err(malformed("a stream failure with no reason")),
                },
            })
        }
        Some(v1::plugin_session_message::Message::StreamCancel(cancel)) => {
            PluginSessionPayload::StreamCancel(PluginStreamControl {
                host_call_id: required_text(
                    &cancel.host_call_id,
                    "a stream cancel with no call identity",
                )?,
                stream_id: required_text(&cancel.stream_id, "a stream cancel naming no stream")?,
            })
        }
        Some(v1::plugin_session_message::Message::StreamRelease(release)) => {
            PluginSessionPayload::StreamRelease(PluginStreamControl {
                host_call_id: required_text(
                    &release.host_call_id,
                    "a stream release with no call identity",
                )?,
                stream_id: required_text(&release.stream_id, "a stream release naming no stream")?,
            })
        }
        Some(v1::plugin_session_message::Message::CompletionSettle(settle)) => {
            let completion_id =
                required_text(&settle.completion_id, "a settlement naming no completion")?;
            let operation_request_id = required_text(
                &settle.operation_request_id,
                "a settlement that belongs to no operation",
            )?;
            let result = match settle.result.as_ref() {
                Some(v1::completion_settle::Result::ValueJson(value)) => {
                    Ok(required_text(value, "a settlement with an empty value")?)
                }
                Some(v1::completion_settle::Result::Failure(failure)) => {
                    Err(failure_from_wire(failure)?)
                }
                None => {
                    return Err(malformed(
                        "a settlement that is neither a value nor a failure",
                    ));
                }
            };
            PluginSessionPayload::CompletionSettle(PluginCompletionSettlement {
                completion_id,
                operation_request_id,
                result,
            })
        }
        Some(v1::plugin_session_message::Message::CompletionOutcome(outcome)) => {
            let completion_id =
                required_text(&outcome.completion_id, "an outcome naming no completion")?;
            let result = match outcome.result.as_ref() {
                Some(v1::completion_outcome::Result::Accepted(_)) => Ok(()),
                Some(v1::completion_outcome::Result::Failure(failure)) => {
                    Err(failure_from_wire(failure)?)
                }
                None => {
                    return Err(malformed(
                        "a completion outcome that says neither accepted nor refused",
                    ));
                }
            };
            PluginSessionPayload::CompletionOutcome(PluginCompletionOutcome {
                completion_id,
                result,
            })
        }
        Some(v1::plugin_session_message::Message::CompletionCancelled(cancelled)) => {
            PluginSessionPayload::CompletionCancelled(PluginCompletionCancelled {
                completion_id: required_text(
                    &cancelled.completion_id,
                    "a cancellation naming no completion",
                )?,
            })
        }
        Some(v1::plugin_session_message::Message::ContinuationChunk(chunk)) => {
            PluginSessionPayload::ContinuationChunk(continuation_chunk_from_wire(chunk)?)
        }
        Some(v1::plugin_session_message::Message::ContinuationDisposition(disposition)) => {
            PluginSessionPayload::ContinuationDisposition(continuation_disposition_from_wire(
                disposition,
            )?)
        }
        Some(v1::plugin_session_message::Message::OutputCredit(credit)) => {
            PluginSessionPayload::OutputCredit(output_credit_from_wire(credit)?)
        }
        None => return Err(malformed("a session message that carries nothing")),
    };
    Ok(PluginSessionMessage {
        session_id: wire.session_id.clone(),
        message,
    })
}

/// Build the wire form of a session message.
///
/// Total: every domain variant has exactly one wire counterpart, because the
/// two vocabularies are the same vocabulary and a variant without one would
/// make a message the far side could not receive.
pub fn session_message_to_wire(message: &PluginSessionMessage) -> v1::PluginSessionMessage {
    use v1::plugin_session_message::Message as Wire;
    let wire_message = match &message.message {
        PluginSessionPayload::StreamOpen(open) => {
            Wire::StreamOpen(v1::DownstreamStreamOpenRequest {
                host_call_id: open.host_call_id.clone(),
                operation_request_id: open.operation_request_id.clone(),
                request_json: open.request_json.clone(),
            })
        }
        PluginSessionPayload::StreamOpened(opened) => {
            Wire::StreamOpened(v1::DownstreamStreamOpened {
                host_call_id: opened.host_call_id.clone(),
                stream_id: opened.stream_id.clone(),
            })
        }
        PluginSessionPayload::StreamOpenFailed(failed) => {
            Wire::StreamOpenFailed(v1::DownstreamStreamOpenFailed {
                host_call_id: failed.host_call_id.clone(),
                failure: Some(failure_to_wire(&failed.failure)),
            })
        }
        PluginSessionPayload::StreamPull(pull) => {
            Wire::StreamPull(v1::DownstreamStreamPullRequest {
                host_call_id: pull.host_call_id.clone(),
                stream_id: pull.stream_id.clone(),
            })
        }
        PluginSessionPayload::StreamItem(item) => Wire::StreamItem(v1::DownstreamStreamItem {
            host_call_id: item.host_call_id.clone(),
            stream_id: item.stream_id.clone(),
            chunk_json: item.chunk_json.clone(),
        }),
        PluginSessionPayload::StreamEnd(end) => Wire::StreamEnd(v1::DownstreamStreamEnd {
            host_call_id: end.host_call_id.clone(),
            stream_id: end.stream_id.clone(),
        }),
        PluginSessionPayload::StreamFailed(failed) => {
            Wire::StreamFailed(v1::DownstreamStreamFailed {
                host_call_id: failed.host_call_id.clone(),
                stream_id: failed.stream_id.clone(),
                failure: Some(failure_to_wire(&failed.failure)),
            })
        }
        PluginSessionPayload::StreamCancel(cancel) => {
            Wire::StreamCancel(v1::DownstreamStreamCancel {
                host_call_id: cancel.host_call_id.clone(),
                stream_id: cancel.stream_id.clone(),
            })
        }
        PluginSessionPayload::StreamRelease(release) => {
            Wire::StreamRelease(v1::DownstreamStreamRelease {
                host_call_id: release.host_call_id.clone(),
                stream_id: release.stream_id.clone(),
            })
        }
        PluginSessionPayload::CompletionSettle(settle) => {
            Wire::CompletionSettle(v1::CompletionSettle {
                completion_id: settle.completion_id.clone(),
                operation_request_id: settle.operation_request_id.clone(),
                result: Some(match &settle.result {
                    Ok(value) => v1::completion_settle::Result::ValueJson(value.clone()),
                    Err(failure) => {
                        v1::completion_settle::Result::Failure(failure_to_wire(failure))
                    }
                }),
            })
        }
        PluginSessionPayload::CompletionOutcome(outcome) => {
            Wire::CompletionOutcome(v1::CompletionOutcome {
                completion_id: outcome.completion_id.clone(),
                result: Some(match &outcome.result {
                    Ok(()) => v1::completion_outcome::Result::Accepted(v1::CompletionAccepted {}),
                    Err(failure) => {
                        v1::completion_outcome::Result::Failure(failure_to_wire(failure))
                    }
                }),
            })
        }
        PluginSessionPayload::CompletionCancelled(cancelled) => {
            Wire::CompletionCancelled(v1::CompletionCancelled {
                completion_id: cancelled.completion_id.clone(),
            })
        }
        PluginSessionPayload::ContinuationChunk(chunk) => {
            Wire::ContinuationChunk(v1::ContinuationChunk {
                host_call_id: chunk.host_call_id.clone(),
                sequence: chunk.sequence,
                chunk_json: chunk.chunk_json.clone(),
            })
        }
        PluginSessionPayload::ContinuationDisposition(disposition) => {
            Wire::ContinuationDisposition(v1::ContinuationChunkDisposition {
                host_call_id: disposition.host_call_id.clone(),
                sequence: disposition.sequence,
                disposition: Some(match &disposition.disposition {
                    Ok(decision) => v1::continuation_chunk_disposition::Disposition::Decision(
                        chunk_disposition_to_wire(*decision),
                    ),
                    Err(failure) => v1::continuation_chunk_disposition::Disposition::Failure(
                        failure_to_wire(failure),
                    ),
                }),
            })
        }
        PluginSessionPayload::OutputCredit(credit) => Wire::OutputCredit(v1::OutputCredit {
            operation_request_id: credit.operation_request_id.clone(),
            items: credit.items,
        }),
    };
    v1::PluginSessionMessage {
        session_id: message.session_id.clone(),
        message: Some(wire_message),
    }
}

/// A required identity or payload that must not be blank.
fn required_text(value: &str, what: &str) -> Result<String, PluginProtocolError> {
    if value.trim().is_empty() {
        return Err(malformed(what));
    }
    Ok(value.to_owned())
}

/// An optional payload: absent stays absent, present-but-blank is refused.
fn optional_text(
    value: &Option<String>,
    what: &str,
) -> Result<Option<String>, PluginProtocolError> {
    match value {
        Some(text) if text.trim().is_empty() => Err(malformed(what)),
        Some(text) => Ok(Some(text.clone())),
        None => Ok(None),
    }
}

fn success_name(success: &PluginSuccess) -> &'static str {
    match success {
        PluginSuccess::Handshake(_) => "a handshake",
        PluginSuccess::Loaded(_) => "a load response",
        PluginSuccess::Unloaded => "an unload response",
        PluginSuccess::Invoked(_) => "an invocation",
        PluginSuccess::Inspected(_) => "an inspection",
        PluginSuccess::Health(_) => "a health report",
    }
}

fn malformed(message: impl Into<String>) -> PluginProtocolError {
    PluginProtocolError::new(PluginFailureCode::MalformedResponse, message)
}

fn failure_code_to_wire(code: &PluginFailureCode) -> i32 {
    use PluginFailureCode as Domain;
    let wire = match code {
        Domain::VersionMismatch { .. } => v1::FailureCode::VersionMismatch,
        Domain::AbiMismatch { .. } => v1::FailureCode::AbiMismatch,
        Domain::UnknownPlugin => v1::FailureCode::UnknownPlugin,
        Domain::StaleHandle => v1::FailureCode::StaleHandle,
        Domain::AlreadyLoading => v1::FailureCode::AlreadyLoading,
        Domain::AlreadyLoaded => v1::FailureCode::AlreadyLoaded,
        Domain::Rejected => v1::FailureCode::Rejected,
        Domain::OversizedFrame { .. } => v1::FailureCode::OversizedFrame,
        Domain::DeadlineExceeded => v1::FailureCode::DeadlineExceeded,
        Domain::HostCrashed => v1::FailureCode::HostCrashed,
        Domain::MalformedResponse => v1::FailureCode::MalformedResponse,
        Domain::Unavailable => v1::FailureCode::Unavailable,
        Domain::Cancelled => v1::FailureCode::Cancelled,
        Domain::GenerationExhausted => v1::FailureCode::GenerationExhausted,
    };
    wire as i32
}

fn failure_code_from_wire(value: i32) -> Result<PluginFailureCode, PluginProtocolError> {
    let code = v1::FailureCode::try_from(value)
        .map_err(|_| malformed(format!("an unknown failure code {value}")))?;
    Ok(match code {
        v1::FailureCode::Unspecified => {
            return Err(malformed("a failure with no code"));
        }
        v1::FailureCode::VersionMismatch => PluginFailureCode::VersionMismatch {
            expected: 0,
            received: 0,
        },
        v1::FailureCode::AbiMismatch => PluginFailureCode::AbiMismatch {
            supported: 0,
            reported: 0,
        },
        v1::FailureCode::UnknownPlugin => PluginFailureCode::UnknownPlugin,
        v1::FailureCode::StaleHandle => PluginFailureCode::StaleHandle,
        v1::FailureCode::AlreadyLoading => PluginFailureCode::AlreadyLoading,
        v1::FailureCode::AlreadyLoaded => PluginFailureCode::AlreadyLoaded,
        v1::FailureCode::Rejected => PluginFailureCode::Rejected,
        v1::FailureCode::OversizedFrame => PluginFailureCode::OversizedFrame {
            observed: 0,
            limit: 0,
        },
        v1::FailureCode::DeadlineExceeded => PluginFailureCode::DeadlineExceeded,
        v1::FailureCode::HostCrashed => PluginFailureCode::HostCrashed,
        v1::FailureCode::MalformedResponse => PluginFailureCode::MalformedResponse,
        v1::FailureCode::Unavailable => PluginFailureCode::Unavailable,
        v1::FailureCode::Cancelled => PluginFailureCode::Cancelled,
        v1::FailureCode::GenerationExhausted => PluginFailureCode::GenerationExhausted,
    })
}

fn capability_kind_from_wire(value: i32) -> Result<PluginCapabilityKind, PluginProtocolError> {
    let kind = v1::PluginCapabilityKind::try_from(value)
        .map_err(|_| malformed(format!("an unknown capability kind {value}")))?;
    Ok(match kind {
        v1::PluginCapabilityKind::Unspecified => {
            return Err(malformed("a capability with no kind"));
        }
        v1::PluginCapabilityKind::Tool => PluginCapabilityKind::Tool,
        v1::PluginCapabilityKind::Llm => PluginCapabilityKind::Llm,
        v1::PluginCapabilityKind::Subscriber => PluginCapabilityKind::Subscriber,
    })
}

fn dispatch_to_wire(state: DispatchState) -> v1::DispatchState {
    match state {
        DispatchState::NotDispatched => v1::DispatchState::NotDispatched,
        DispatchState::DispatchAttempted => v1::DispatchState::DispatchAttempted,
        DispatchState::DispatchConfirmed => v1::DispatchState::DispatchConfirmed,
    }
}

fn outcome_to_wire(certainty: OutcomeCertainty) -> v1::OutcomeCertainty {
    match certainty {
        OutcomeCertainty::ConfirmedFailure => v1::OutcomeCertainty::ConfirmedFailure,
        OutcomeCertainty::ConfirmedSuccess => v1::OutcomeCertainty::ConfirmedSuccess,
        OutcomeCertainty::Unknown => v1::OutcomeCertainty::Unknown,
    }
}

/// Read dispatch certainty from the wire, refusing an unspecified value.
pub fn dispatch_from_wire(value: i32) -> Result<DispatchState, PluginProtocolError> {
    let state = v1::DispatchState::try_from(value)
        .map_err(|_| malformed(format!("an unknown dispatch state {value}")))?;
    Ok(match state {
        v1::DispatchState::Unspecified => {
            return Err(malformed(
                "an outcome that does not say whether the plugin may have dispatched",
            ));
        }
        v1::DispatchState::NotDispatched => DispatchState::NotDispatched,
        v1::DispatchState::DispatchAttempted => DispatchState::DispatchAttempted,
        v1::DispatchState::DispatchConfirmed => DispatchState::DispatchConfirmed,
    })
}

/// Read outcome certainty from the wire, refusing an unspecified value.
pub fn certainty_from_wire(value: i32) -> Result<OutcomeCertainty, PluginProtocolError> {
    let certainty = v1::OutcomeCertainty::try_from(value)
        .map_err(|_| malformed(format!("an unknown outcome certainty {value}")))?;
    Ok(match certainty {
        v1::OutcomeCertainty::Unspecified => {
            return Err(malformed(
                "an outcome that does not say what is known about the result",
            ));
        }
        v1::OutcomeCertainty::ConfirmedFailure => OutcomeCertainty::ConfirmedFailure,
        v1::OutcomeCertainty::ConfirmedSuccess => OutcomeCertainty::ConfirmedSuccess,
        v1::OutcomeCertainty::Unknown => OutcomeCertainty::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn malformed_code(error: PluginProtocolError) -> PluginFailureCode {
        error.failure.code
    }

    #[test]
    fn a_load_request_carries_the_identity_the_runtime_approved() {
        let request = PluginLoadRequest {
            plugin_id: "example".into(),
            artifact: "relay-plugin.toml".into(),
            identity: PluginArtifactIdentity {
                manifest_sha256: "a".repeat(64),
                library_sha256: "b".repeat(64),
            },
        };

        let context = PluginExecutionContext {
            operation_request_id: "operation-1".into(),
            protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            deadline_unix_ms: 1_700_000_000_000,
            remaining_budget_millis: 29_000,
            max_response_bytes: 1024,
        };
        let back = load_request_from_wire(&load_request_to_wire(&request, "session-1", &context))
            .expect("round trip");

        assert_eq!(back, request);
    }

    #[test]
    fn a_load_request_without_an_approved_identity_is_refused() {
        // Without the digests the side performing the load would decide for
        // itself what the reference points at, which is the hole the identity
        // exists to close.
        let wire = v1::LoadRequest {
            plugin_id: "example".into(),
            artifact: "relay-plugin.toml".into(),
            manifest_digest: String::new(),
            library_digest: "b".repeat(64),
            ..Default::default()
        };

        assert!(load_request_from_wire(&wire).is_err());
    }

    #[test]
    fn an_outcome_keeps_the_dispatch_certainty_it_was_given() {
        // The converter that used to live here took a bare success and
        // manufactured `NotDispatched` with `ConfirmedSuccess`. A caller would
        // have learned that an operation definitely did not reach an external
        // system without anyone having established that.
        let outcome = PluginExecutionOutcome {
            dispatch: DispatchState::DispatchAttempted,
            certainty: OutcomeCertainty::Unknown,
            result: Err(PluginFailure {
                code: PluginFailureCode::HostCrashed,
                message: "the host exited during dispatch".into(),
            }),
        };

        let wire = execution_outcome_to_wire(&outcome).expect("encode outcome");
        let back = execution_outcome_from_wire(&wire).expect("decode outcome");

        assert_eq!(back, outcome);
        assert_eq!(back.dispatch, DispatchState::DispatchAttempted);
        assert_eq!(back.certainty, OutcomeCertainty::Unknown);
    }

    #[test]
    fn an_abi_mismatch_carrying_frame_detail_is_refused() {
        let wire = v1::PluginFailure {
            code: v1::FailureCode::AbiMismatch as i32,
            message: "mismatch".into(),
            expected_version: Some(4),
            received_version: Some(3),
            observed: Some(9_000_000),
            limit: Some(8_000_000),
        };

        assert!(failure_from_wire(&wire).is_err());
    }

    #[test]
    fn a_load_response_whose_handle_and_descriptor_disagree_is_refused() {
        // Individually valid fields naming different plugins would produce a
        // handle that addresses one plugin while carrying another's
        // description.
        let wire = v1::LoadResponse {
            handle: Some(v1::PluginHandle {
                plugin_id: "plugin-a".into(),
                generation: 17,
            }),
            descriptor: Some(v1::PluginDescriptor {
                plugin_id: "plugin-b".into(),
                ..Default::default()
            }),
        };

        assert!(load_response_from_wire(&wire).is_err());
    }

    #[test]
    fn a_context_round_trips_without_losing_the_budget() {
        let context = PluginExecutionContext {
            operation_request_id: "operation-1".into(),
            protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            deadline_unix_ms: 1_700_000_000_000,
            remaining_budget_millis: 29_000,
            max_response_bytes: 1024,
        };

        let back = context_from_wire(&context_to_wire(&context)).expect("round trip");

        assert_eq!(back, context);
    }

    #[test]
    fn a_context_without_a_binding_is_refused() {
        let mut wire = context_to_wire(&PluginExecutionContext {
            operation_request_id: "operation-1".into(),
            protocol_version: 1,
            runtime_binding_digest: "binding".into(),
            deadline_unix_ms: 1,
            remaining_budget_millis: 1,
            max_response_bytes: 1,
        });
        wire.runtime_binding_digest = "  ".into();

        let error = context_from_wire(&wire).expect_err("a blank binding is not a binding");

        assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
    }

    #[test]
    fn a_version_mismatch_without_versions_is_refused() {
        // The wire can express this; the domain cannot. Refusing it here is what
        // stops protobuf's looseness becoming domain state core trusts.
        let wire = v1::PluginFailure {
            code: v1::FailureCode::VersionMismatch as i32,
            message: "mismatch".into(),
            ..Default::default()
        };

        let error = failure_from_wire(&wire).expect_err("a mismatch needs two versions");

        assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
    }

    #[test]
    fn a_failure_carrying_detail_its_code_does_not_define_is_refused() {
        let wire = v1::PluginFailure {
            code: v1::FailureCode::HostCrashed as i32,
            message: "crashed".into(),
            observed: Some(999_999),
            limit: Some(10),
            ..Default::default()
        };

        let error = failure_from_wire(&wire).expect_err("a crash has no size limit");

        assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
    }

    #[test]
    fn structured_failures_survive_a_round_trip() {
        for code in [
            PluginFailureCode::OversizedFrame {
                observed: 9_000_000,
                limit: 8_388_608,
            },
            PluginFailureCode::VersionMismatch {
                expected: 1,
                received: 2,
            },
            PluginFailureCode::DeadlineExceeded,
            PluginFailureCode::HostCrashed,
        ] {
            let failure = PluginFailure {
                code,
                message: "detail".into(),
            };

            let back = failure_from_wire(&failure_to_wire(&failure)).expect("round trip");

            assert_eq!(back, failure);
        }
    }

    #[test]
    fn an_unspecified_enum_is_refused_rather_than_defaulted() {
        let wire = v1::PluginFailure {
            code: v1::FailureCode::Unspecified as i32,
            message: String::new(),
            ..Default::default()
        };
        assert!(failure_from_wire(&wire).is_err());

        assert!(dispatch_from_wire(v1::DispatchState::Unspecified as i32).is_err());
        assert!(certainty_from_wire(v1::OutcomeCertainty::Unspecified as i32).is_err());
    }

    #[test]
    fn an_unknown_enum_value_is_refused() {
        assert!(dispatch_from_wire(9_999).is_err());
        assert!(certainty_from_wire(9_999).is_err());
    }

    #[test]
    fn a_handle_at_generation_zero_is_refused() {
        // Generation zero is the protobuf default and no real load produces it,
        // so accepting one would let a default-constructed message address an
        // instance that never existed.
        let wire = v1::LoadResponse {
            handle: Some(v1::PluginHandle {
                plugin_id: "example".into(),
                generation: 0,
            }),
            descriptor: Some(v1::PluginDescriptor {
                plugin_id: "example".into(),
                ..Default::default()
            }),
        };

        assert!(load_response_from_wire(&wire).is_err());
    }

    #[test]
    fn a_load_response_without_a_descriptor_is_refused() {
        let wire = v1::LoadResponse {
            handle: Some(v1::PluginHandle {
                plugin_id: "example".into(),
                generation: 1,
            }),
            descriptor: None,
        };

        assert!(load_response_from_wire(&wire).is_err());
    }

    fn wire_failure(code: v1::FailureCode) -> v1::PluginFailure {
        v1::PluginFailure {
            code: code as i32,
            message: "the host said so".into(),
            ..Default::default()
        }
    }

    fn reported_failure<T: std::fmt::Debug>(outcome: LifecycleOutcome<T>) -> PluginFailure {
        match outcome {
            LifecycleOutcome::Failed(failure) => failure,
            LifecycleOutcome::Completed(value) => {
                panic!("expected a reported failure, got {value:?}")
            }
        }
    }

    #[test]
    fn a_reported_failure_is_a_result_rather_than_a_transport_error() {
        // Each of these is the host answering coherently. Routing them through
        // the error channel would make "this plugin is already loaded"
        // indistinguishable from "I could not reach the host".
        let load = reported_failure(
            load_outcome_from_wire(&v1::LoadOutcome {
                result: Some(v1::load_outcome::Result::Failure(wire_failure(
                    v1::FailureCode::AlreadyLoaded,
                ))),
            })
            .expect("an answered failure is not a conversion error"),
        );
        assert_eq!(load.code, PluginFailureCode::AlreadyLoaded);

        let unload = reported_failure(
            unload_outcome_from_wire(&v1::UnloadOutcome {
                result: Some(v1::unload_outcome::Result::Failure(wire_failure(
                    v1::FailureCode::StaleHandle,
                ))),
            })
            .expect("an answered failure is not a conversion error"),
        );
        assert_eq!(unload.code, PluginFailureCode::StaleHandle);

        let inspect = reported_failure(
            inspect_outcome_from_wire(&v1::InspectOutcome {
                result: Some(v1::inspect_outcome::Result::Failure(wire_failure(
                    v1::FailureCode::UnknownPlugin,
                ))),
            })
            .expect("an answered failure is not a conversion error"),
        );
        assert_eq!(inspect.code, PluginFailureCode::UnknownPlugin);

        let health = reported_failure(
            health_outcome_from_wire(&v1::HealthOutcome {
                result: Some(v1::health_outcome::Result::Failure(wire_failure(
                    v1::FailureCode::Unavailable,
                ))),
            })
            .expect("an answered failure is not a conversion error"),
        );
        assert_eq!(health.code, PluginFailureCode::Unavailable);

        let cancel = reported_failure(
            cancel_outcome_from_wire(&v1::CancelOperationOutcome {
                result: Some(v1::cancel_operation_outcome::Result::Failure(wire_failure(
                    v1::FailureCode::Cancelled,
                ))),
            })
            .expect("an answered failure is not a conversion error"),
        );
        assert_eq!(cancel.code, PluginFailureCode::Cancelled);

        // The failure's own detail travels with it: a version mismatch that
        // arrived would be refused by `failure_from_wire`, and this one is
        // reported as the domain's two-version form.
        let handshake = reported_failure(
            handshake_outcome_from_wire(&v1::HandshakeOutcome {
                result: Some(v1::handshake_outcome::Result::Failure(v1::PluginFailure {
                    code: v1::FailureCode::VersionMismatch as i32,
                    message: "the host speaks another version".into(),
                    expected_version: Some(2),
                    received_version: Some(1),
                    ..Default::default()
                })),
            })
            .expect("an answered failure is not a conversion error"),
        );
        assert_eq!(
            handshake.code,
            PluginFailureCode::VersionMismatch {
                expected: 2,
                received: 1
            }
        );
    }

    #[test]
    fn a_lifecycle_success_carries_the_payload_it_was_given() {
        let loaded = load_outcome_from_wire(&v1::LoadOutcome {
            result: Some(v1::load_outcome::Result::Loaded(v1::LoadResponse {
                handle: Some(v1::PluginHandle {
                    plugin_id: "example".into(),
                    generation: 41,
                }),
                descriptor: Some(v1::PluginDescriptor {
                    plugin_id: "example".into(),
                    ..Default::default()
                }),
            })),
        })
        .expect("a load outcome");
        match loaded {
            LifecycleOutcome::Completed(response) => assert_eq!(response.handle.generation, 41),
            LifecycleOutcome::Failed(failure) => panic!("expected a load, got {failure:?}"),
        }

        // The two acknowledgements carry nothing, which is what the wire says.
        assert!(matches!(
            unload_outcome_from_wire(&v1::UnloadOutcome {
                result: Some(v1::unload_outcome::Result::Unloaded(v1::UnloadResponse {})),
            })
            .expect("an unload outcome"),
            LifecycleOutcome::Completed(())
        ));
        assert!(matches!(
            cancel_outcome_from_wire(&v1::CancelOperationOutcome {
                result: Some(v1::cancel_operation_outcome::Result::Cancelled(
                    v1::CancelOperationResponse {}
                )),
            })
            .expect("a cancellation outcome"),
            LifecycleOutcome::Completed(())
        ));

        let health = health_outcome_from_wire(&v1::HealthOutcome {
            result: Some(v1::health_outcome::Result::Health(v1::HealthResponse {
                protocol_version: 1,
                accepting_work: true,
                loaded: vec![v1::PluginHandle {
                    plugin_id: "example".into(),
                    generation: 41,
                }],
            })),
        })
        .expect("a health outcome");
        match health {
            LifecycleOutcome::Completed(health) => {
                assert!(health.accepting_work);
                assert_eq!(health.loaded.len(), 1);
            }
            LifecycleOutcome::Failed(failure) => {
                panic!("expected a health report, got {failure:?}")
            }
        }
    }

    #[test]
    fn a_success_arm_is_still_validated() {
        // The outcome split changes how a failure travels, not whether the
        // payload is checked: a success arm is the same message it always was.
        let error = load_outcome_from_wire(&v1::LoadOutcome {
            result: Some(v1::load_outcome::Result::Loaded(v1::LoadResponse {
                handle: Some(v1::PluginHandle {
                    plugin_id: "example".into(),
                    generation: 0,
                }),
                descriptor: Some(v1::PluginDescriptor {
                    plugin_id: "example".into(),
                    ..Default::default()
                }),
            })),
        })
        .expect_err("a handle at generation zero is not a load");

        assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
    }

    #[test]
    fn a_session_is_validated_rather_than_adopted() {
        let session = |session_id: &str, maximum_frame_bytes: u32| v1::HandshakeResponse {
            protocol_version: 1,
            session_id: session_id.into(),
            host_instance_id: "host-1".into(),
            host_nonce: "nonce".into(),
            maximum_frame_bytes,
            supported_features: vec!["streaming".into()],
            accepted_read_capabilities: Vec::new(),
        };

        let established = handshake_outcome_from_wire(&v1::HandshakeOutcome {
            result: Some(v1::handshake_outcome::Result::Established(session(
                "session-1",
                1024,
            ))),
        })
        .expect("a handshake outcome");
        match established {
            LifecycleOutcome::Completed(identity) => {
                assert_eq!(identity.session_id, "session-1");
                assert_eq!(identity.maximum_frame_bytes, 1024);
            }
            LifecycleOutcome::Failed(failure) => {
                panic!("expected an established session, got {failure:?}")
            }
        }

        // A session with no identity leaves "which session?" unanswered, and a
        // frame limit above this side's own describes a session that cannot
        // exist.
        for wire in [
            session("  ", 1024),
            session("session-1", 0),
            session("session-1", MAX_FRAME_BYTES + 1),
        ] {
            let error = handshake_outcome_from_wire(&v1::HandshakeOutcome {
                result: Some(v1::handshake_outcome::Result::Established(wire)),
            })
            .expect_err("this session is not constructible");

            assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
        }
    }

    #[test]
    fn a_health_report_is_validated_like_the_load_it_describes() {
        let report = |handle: v1::PluginHandle| v1::HealthOutcome {
            result: Some(v1::health_outcome::Result::Health(v1::HealthResponse {
                protocol_version: 1,
                accepting_work: true,
                loaded: vec![handle],
            })),
        };

        for handle in [
            v1::PluginHandle {
                plugin_id: "  ".into(),
                generation: 1,
            },
            v1::PluginHandle {
                plugin_id: "example".into(),
                generation: 0,
            },
        ] {
            let error = health_outcome_from_wire(&report(handle))
                .expect_err("a handle that addresses nothing is not health");

            assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
        }
    }

    #[test]
    fn an_outcome_with_neither_arm_is_malformed() {
        // Saying nothing is not the same as reporting a failure, and a caller
        // that treated the two alike would retry an operation nobody answered.
        let errors = [
            malformed_code(
                handshake_outcome_from_wire(&v1::HandshakeOutcome::default()).expect_err("no arm"),
            ),
            malformed_code(
                load_outcome_from_wire(&v1::LoadOutcome::default()).expect_err("no arm"),
            ),
            malformed_code(
                unload_outcome_from_wire(&v1::UnloadOutcome::default()).expect_err("no arm"),
            ),
            malformed_code(
                inspect_outcome_from_wire(&v1::InspectOutcome::default()).expect_err("no arm"),
            ),
            malformed_code(
                health_outcome_from_wire(&v1::HealthOutcome::default()).expect_err("no arm"),
            ),
            malformed_code(
                cancel_outcome_from_wire(&v1::CancelOperationOutcome::default())
                    .expect_err("no arm"),
            ),
        ];

        for code in errors {
            assert_eq!(code, PluginFailureCode::MalformedResponse);
        }
    }

    fn wire_registration(
        operation: v1::PluginRegistrationOperation,
        shape: v1::PluginExecutionShape,
    ) -> v1::PluginRegistrationDescriptor {
        v1::PluginRegistrationDescriptor {
            registration_id: "registration-1".into(),
            component_kind: "example_kind".into(),
            operation: operation as i32,
            shape: shape as i32,
            ..Default::default()
        }
    }

    #[test]
    fn every_attachment_point_survives_the_wire() {
        // The numbers are listed rather than derived so that renumbering a value
        // — which every peer would misread — fails here and not in the field.
        let operations = [
            (PluginRegistrationOperation::Subscriber, 1),
            (PluginRegistrationOperation::EventMetadataInjector, 2),
            (PluginRegistrationOperation::MarkSanitizeGuardrail, 3),
            (PluginRegistrationOperation::ScopeSanitizeStartGuardrail, 4),
            (PluginRegistrationOperation::ScopeSanitizeEndGuardrail, 5),
            (PluginRegistrationOperation::ToolSanitizeRequestGuardrail, 6),
            (
                PluginRegistrationOperation::ToolSanitizeResponseGuardrail,
                7,
            ),
            (
                PluginRegistrationOperation::ToolConditionalExecutionGuardrail,
                8,
            ),
            (PluginRegistrationOperation::ToolRequestIntercept, 9),
            (PluginRegistrationOperation::ToolExecutionIntercept, 10),
            (PluginRegistrationOperation::LlmSanitizeRequestGuardrail, 11),
            (
                PluginRegistrationOperation::LlmSanitizeResponseGuardrail,
                12,
            ),
            (
                PluginRegistrationOperation::LlmConditionalExecutionGuardrail,
                13,
            ),
            (PluginRegistrationOperation::LlmRequestIntercept, 14),
            (PluginRegistrationOperation::LlmExecutionIntercept, 15),
            (PluginRegistrationOperation::LlmStreamExecutionIntercept, 16),
        ];

        for (operation, number) in operations {
            assert_eq!(
                registration_operation_to_wire(operation),
                number,
                "{} encodes to a different number than it did",
                operation.as_str()
            );
            assert_eq!(
                registration_operation_from_wire(number).expect("a known operation"),
                operation
            );

            let shape = match registration_shape(operation) {
                PluginExecutionShape::Unary => v1::PluginExecutionShape::ShapeUnary,
                PluginExecutionShape::Streaming => v1::PluginExecutionShape::ShapeStreaming,
            };
            let wire = match operation {
                PluginRegistrationOperation::Subscriber => {
                    v1::PluginRegistrationOperation::RegistrationOperationSubscriber
                }
                PluginRegistrationOperation::EventMetadataInjector => {
                    v1::PluginRegistrationOperation::RegistrationOperationEventMetadataInjector
                }
                PluginRegistrationOperation::MarkSanitizeGuardrail => {
                    v1::PluginRegistrationOperation::RegistrationOperationMarkSanitizeGuardrail
                }
                PluginRegistrationOperation::ScopeSanitizeStartGuardrail => {
                    v1::PluginRegistrationOperation::RegistrationOperationScopeSanitizeStartGuardrail
                }
                PluginRegistrationOperation::ScopeSanitizeEndGuardrail => {
                    v1::PluginRegistrationOperation::RegistrationOperationScopeSanitizeEndGuardrail
                }
                PluginRegistrationOperation::ToolSanitizeRequestGuardrail => {
                    v1::PluginRegistrationOperation::RegistrationOperationToolSanitizeRequestGuardrail
                }
                PluginRegistrationOperation::ToolSanitizeResponseGuardrail => {
                    v1::PluginRegistrationOperation::RegistrationOperationToolSanitizeResponseGuardrail
                }
                PluginRegistrationOperation::ToolConditionalExecutionGuardrail => {
                    v1::PluginRegistrationOperation::RegistrationOperationToolConditionalExecutionGuardrail
                }
                PluginRegistrationOperation::ToolRequestIntercept => {
                    v1::PluginRegistrationOperation::RegistrationOperationToolRequestIntercept
                }
                PluginRegistrationOperation::ToolExecutionIntercept => {
                    v1::PluginRegistrationOperation::RegistrationOperationToolExecutionIntercept
                }
                PluginRegistrationOperation::LlmSanitizeRequestGuardrail => {
                    v1::PluginRegistrationOperation::RegistrationOperationLlmSanitizeRequestGuardrail
                }
                PluginRegistrationOperation::LlmSanitizeResponseGuardrail => {
                    v1::PluginRegistrationOperation::RegistrationOperationLlmSanitizeResponseGuardrail
                }
                PluginRegistrationOperation::LlmConditionalExecutionGuardrail => {
                    v1::PluginRegistrationOperation::RegistrationOperationLlmConditionalExecutionGuardrail
                }
                PluginRegistrationOperation::LlmRequestIntercept => {
                    v1::PluginRegistrationOperation::RegistrationOperationLlmRequestIntercept
                }
                PluginRegistrationOperation::LlmExecutionIntercept => {
                    v1::PluginRegistrationOperation::RegistrationOperationLlmExecutionIntercept
                }
                PluginRegistrationOperation::LlmStreamExecutionIntercept => {
                    v1::PluginRegistrationOperation::RegistrationOperationLlmStreamExecutionIntercept
                }
            };
            let descriptor =
                registration_from_wire(&wire_registration(wire, shape)).expect("a registration");

            assert_eq!(descriptor.operation, operation);
            assert_eq!(descriptor.shape, registration_shape(operation));
        }
    }

    #[test]
    fn a_registration_that_does_not_say_where_it_attaches_is_refused() {
        // Without the attachment point a kernel knows a registration exists but
        // not where to install it, which is the state this field was added to
        // end.
        for operation in [v1::PluginRegistrationOperation::Unspecified as i32, 9_999] {
            let error = registration_from_wire(&v1::PluginRegistrationDescriptor {
                operation,
                ..wire_registration(
                    v1::PluginRegistrationOperation::RegistrationOperationSubscriber,
                    v1::PluginExecutionShape::ShapeUnary,
                )
            })
            .expect_err("a registration without an attachment point is not usable");

            assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
        }
    }

    #[test]
    fn a_registration_whose_shape_contradicts_its_attachment_point_is_refused() {
        // Both fields are on the wire, so they can disagree. One of them is a
        // property of the runtime and the other is a claim, and a proxy built
        // from the claim would answer differently than the plugin it replaces.
        let error = registration_from_wire(&wire_registration(
            v1::PluginRegistrationOperation::RegistrationOperationLlmStreamExecutionIntercept,
            v1::PluginExecutionShape::ShapeUnary,
        ))
        .expect_err("the streaming attachment point does not answer once");
        assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);

        let error = registration_from_wire(&wire_registration(
            v1::PluginRegistrationOperation::RegistrationOperationToolRequestIntercept,
            v1::PluginExecutionShape::ShapeStreaming,
        ))
        .expect_err("a tool request intercept does not stream");
        assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
    }

    #[test]
    fn an_ordering_the_plugin_did_not_declare_stays_absent() {
        // Subscribers carry no priority in the ABI. Reporting zero would be a
        // claim the plugin never made, and the runtime would order by it.
        let descriptor = registration_from_wire(&wire_registration(
            v1::PluginRegistrationOperation::RegistrationOperationSubscriber,
            v1::PluginExecutionShape::ShapeUnary,
        ))
        .expect("a subscriber");
        assert_eq!(
            descriptor.ordering,
            PluginRegistrationOrdering {
                priority: None,
                may_break_chain: None
            }
        );

        let mut wire = wire_registration(
            v1::PluginRegistrationOperation::RegistrationOperationToolRequestIntercept,
            v1::PluginExecutionShape::ShapeUnary,
        );
        wire.ordering = Some(v1::PluginRegistrationOrdering {
            priority: Some(10),
            may_break_chain: None,
        });
        let descriptor = registration_from_wire(&wire).expect("a tool request intercept");
        assert_eq!(
            descriptor.ordering,
            PluginRegistrationOrdering {
                priority: Some(10),
                may_break_chain: None
            }
        );
    }

    #[test]
    fn a_gate_naming_an_empty_target_is_refused() {
        // An empty target is a gate that decides nothing rather than a gate
        // whose target is unknown, and the two call for different handling.
        let mut wire = wire_registration(
            v1::PluginRegistrationOperation::RegistrationOperationSubscriber,
            v1::PluginExecutionShape::ShapeUnary,
        );
        wire.gated_registration = Some("  ".into());

        let error = registration_from_wire(&wire).expect_err("a gate needs a target");

        assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
    }

    fn unavailable() -> PluginFailure {
        PluginFailure {
            code: PluginFailureCode::Unavailable,
            message: "the downstream provider refused".into(),
        }
    }

    fn session_payloads() -> Vec<PluginSessionPayload> {
        vec![
            PluginSessionPayload::StreamOpen(PluginStreamOpenRequest {
                host_call_id: "call-1".into(),
                operation_request_id: "operation-1".into(),
                request_json: r#"{"model":"example"}"#.into(),
            }),
            PluginSessionPayload::StreamOpened(PluginStreamOpened {
                host_call_id: "call-1".into(),
                stream_id: "stream-1".into(),
            }),
            PluginSessionPayload::StreamOpenFailed(PluginStreamOpenFailed {
                host_call_id: "call-1".into(),
                failure: unavailable(),
            }),
            PluginSessionPayload::StreamPull(PluginStreamPullRequest {
                host_call_id: "call-2".into(),
                stream_id: "stream-1".into(),
            }),
            PluginSessionPayload::StreamItem(PluginStreamItem {
                host_call_id: "call-2".into(),
                stream_id: "stream-1".into(),
                chunk_json: r#"{"delta":"hi"}"#.into(),
            }),
            PluginSessionPayload::StreamEnd(PluginStreamEnd {
                host_call_id: "call-3".into(),
                stream_id: "stream-1".into(),
            }),
            PluginSessionPayload::StreamFailed(PluginStreamFailed {
                host_call_id: "call-3".into(),
                stream_id: "stream-1".into(),
                failure: unavailable(),
            }),
            PluginSessionPayload::StreamCancel(PluginStreamControl {
                host_call_id: "call-4".into(),
                stream_id: "stream-1".into(),
            }),
            PluginSessionPayload::StreamRelease(PluginStreamControl {
                host_call_id: "call-5".into(),
                stream_id: "stream-1".into(),
            }),
            PluginSessionPayload::CompletionSettle(PluginCompletionSettlement {
                completion_id: "completion-1".into(),
                operation_request_id: "operation-1".into(),
                result: Ok(r#"{"ok":true}"#.into()),
            }),
            PluginSessionPayload::CompletionSettle(PluginCompletionSettlement {
                completion_id: "completion-1".into(),
                operation_request_id: "operation-1".into(),
                result: Err(unavailable()),
            }),
            PluginSessionPayload::CompletionOutcome(PluginCompletionOutcome {
                completion_id: "completion-1".into(),
                result: Ok(()),
            }),
            PluginSessionPayload::CompletionOutcome(PluginCompletionOutcome {
                completion_id: "completion-1".into(),
                result: Err(PluginFailure {
                    code: PluginFailureCode::Cancelled,
                    message: "the awaiting runtime cancelled it".into(),
                }),
            }),
            PluginSessionPayload::CompletionCancelled(PluginCompletionCancelled {
                completion_id: "completion-1".into(),
            }),
        ]
    }

    #[test]
    fn every_session_message_survives_the_wire() {
        for payload in session_payloads() {
            let message = PluginSessionMessage {
                session_id: "session-1".into(),
                message: payload,
            };

            let back = session_message_from_wire(&session_message_to_wire(&message))
                .expect("a session message this side built");

            assert_eq!(back, message);
        }
    }

    #[test]
    fn a_continuation_round_trips_and_refuses_to_carry_nothing() {
        let request = PluginContinuationRequest {
            operation_request_id: "operation-1".into(),
            host_call_id: "call-1".into(),
            invocation_json: r#"{"input":true}"#.into(),
        };
        assert_eq!(
            continuation_request_from_wire(&continuation_request_to_wire(&request, "session-1"))
                .expect("a continuation this side built"),
            request
        );

        // Without the operation identity the runtime could not resume the right
        // chain position, and it would have to guess which chain this belongs
        // to — a guess made by the trusted side, which is the wrong side to make
        // it.
        let mut wire = continuation_request_to_wire(&request, "session-1");
        wire.operation_request_id = "  ".into();
        assert!(continuation_request_from_wire(&wire).is_err());

        let value = PluginHostCallOutcome {
            result: Ok(r#"{"ok":true}"#.into()),
        };
        assert_eq!(
            continuation_outcome_from_wire(&continuation_outcome_to_wire(&value)).expect("a value"),
            value
        );

        let failed = PluginHostCallOutcome {
            result: Err(unavailable()),
        };
        assert_eq!(
            continuation_outcome_from_wire(&continuation_outcome_to_wire(&failed))
                .expect("a failure"),
            failed
        );

        // A continuation that answered nothing would leave the plugin's
        // callback waiting for a result that never comes.
        let error = continuation_outcome_from_wire(&v1::ContinuationOutcome { result: None })
            .expect_err("an outcome with no arm");
        assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
    }

    #[test]
    fn a_session_message_that_names_nothing_is_refused() {
        // The identities are what let several calls share one channel. A
        // message without them would have to be matched to whatever happened to
        // be outstanding, and the side that guessed would be the trusted one.
        let item = v1::PluginSessionMessage {
            session_id: "session-1".into(),
            message: Some(v1::plugin_session_message::Message::StreamItem(
                v1::DownstreamStreamItem {
                    host_call_id: "call-1".into(),
                    stream_id: String::new(),
                    chunk_json: r#"{"delta":"hi"}"#.into(),
                },
            )),
        };
        assert!(session_message_from_wire(&item).is_err());

        let no_session = v1::PluginSessionMessage {
            session_id: "  ".into(),
            message: Some(v1::plugin_session_message::Message::StreamEnd(
                v1::DownstreamStreamEnd {
                    host_call_id: "call-1".into(),
                    stream_id: "stream-1".into(),
                },
            )),
        };
        assert!(session_message_from_wire(&no_session).is_err());

        let empty = v1::PluginSessionMessage {
            session_id: "session-1".into(),
            message: Some(v1::plugin_session_message::Message::StreamEnd(
                v1::DownstreamStreamEnd {
                    host_call_id: "call-1".into(),
                    stream_id: "stream-1".into(),
                },
            )),
        };
        let mut empty_chunk = empty.clone();
        empty_chunk.message = Some(v1::plugin_session_message::Message::StreamItem(
            v1::DownstreamStreamItem {
                host_call_id: "call-1".into(),
                stream_id: "stream-1".into(),
                chunk_json: "   ".into(),
            },
        ));
        assert!(session_message_from_wire(&empty_chunk).is_err());

        // A message carrying no arm at all said nothing, which is not the same
        // as reporting something.
        let nothing = v1::PluginSessionMessage {
            session_id: "session-1".into(),
            message: None,
        };
        let error = session_message_from_wire(&nothing).expect_err("no message");
        assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
    }

    #[test]
    fn a_settlement_or_outcome_without_a_result_is_refused() {
        // Both are oneofs on the wire, so a message with neither arm is the one
        // shape that can express "no answer" — and a plugin waiting on a
        // settlement would wait forever rather than learn the truth.
        let settle = v1::PluginSessionMessage {
            session_id: "session-1".into(),
            message: Some(v1::plugin_session_message::Message::CompletionSettle(
                v1::CompletionSettle {
                    completion_id: "completion-1".into(),
                    operation_request_id: "operation-1".into(),
                    result: None,
                },
            )),
        };
        assert!(session_message_from_wire(&settle).is_err());

        let empty_value = v1::PluginSessionMessage {
            session_id: "session-1".into(),
            message: Some(v1::plugin_session_message::Message::CompletionSettle(
                v1::CompletionSettle {
                    completion_id: "completion-1".into(),
                    operation_request_id: "operation-1".into(),
                    result: Some(v1::completion_settle::Result::ValueJson(String::new())),
                },
            )),
        };
        assert!(session_message_from_wire(&empty_value).is_err());

        let outcome = v1::PluginSessionMessage {
            session_id: "session-1".into(),
            message: Some(v1::plugin_session_message::Message::CompletionOutcome(
                v1::CompletionOutcome {
                    completion_id: "completion-1".into(),
                    result: None,
                },
            )),
        };
        assert!(session_message_from_wire(&outcome).is_err());
    }

    fn wire_mark() -> v1::EmitMarkRequest {
        v1::EmitMarkRequest {
            session_id: "session-1".into(),
            operation_request_id: "operation-1".into(),
            host_call_id: "call-1".into(),
            name: "example.mark".into(),
            data_json: Some(r#"{"value":1}"#.into()),
            parent: Some(v1::ScopeReference {
                scope_id: "018f0b3c-5f5a-7c3e-9a2b-1c2d3e4f5a6b".into(),
            }),
            metadata_json: Some(r#"{"source":"fixture"}"#.into()),
            data_schema: Some(v1::MarkDataSchema {
                name: "example".into(),
                version: "1".into(),
            }),
            severity: Some(v1::MarkSeverity::Warn as i32),
            timestamp_unix_micros: Some(1_700_000_000_000_000),
        }
    }

    #[test]
    fn a_mark_keeps_every_field_the_abi_passes() {
        // The earlier shape carried a name and a payload. The parent scope,
        // metadata, schema and severity all change the event a subscriber sees,
        // so a mark that dropped them would not be the mark the plugin emitted.
        let mark = mark_request_from_wire(&wire_mark()).expect("a complete mark");

        assert_eq!(mark.name, "example.mark");
        assert_eq!(mark.data_json.as_deref(), Some(r#"{"value":1}"#));
        assert_eq!(
            mark.parent.expect("a parent scope").scope_id.to_string(),
            "018f0b3c-5f5a-7c3e-9a2b-1c2d3e4f5a6b"
        );
        assert_eq!(
            mark.metadata_json.as_deref(),
            Some(r#"{"source":"fixture"}"#)
        );
        assert_eq!(mark.data_schema.expect("a schema").name, "example");
        assert_eq!(mark.severity, Some(LogSeverity::Warn));
        assert_eq!(mark.timestamp_unix_micros, Some(1_700_000_000_000_000));

        // Absence stays absence rather than becoming a default nobody chose.
        let bare = mark_request_from_wire(&v1::EmitMarkRequest {
            data_json: None,
            parent: None,
            metadata_json: None,
            data_schema: None,
            severity: None,
            timestamp_unix_micros: None,
            ..wire_mark()
        })
        .expect("a mark with only a name");
        assert_eq!(bare.data_json, None);
        assert_eq!(bare.severity, None);
        assert_eq!(bare.timestamp_unix_micros, None);
    }

    #[test]
    fn a_mark_that_cannot_mean_what_it_says_is_refused() {
        // A scope identity has one canonical spelling; anything else is a
        // different string for the same value, and two spellings of one
        // identity eventually disagree.
        let not_canonical = [
            "not-a-uuid",
            // The same value without its hyphens.
            "018f0b3c5f5a7c3e9a2b1c2d3e4f5a6b",
            // A v4 UUID: parseable, but this fixture is a v7 and the check is
            // about the text, so a braced form of a real one is the case that
            // matters.
            "{018f0b3c-5f5a-7c3e-9a2b-1c2d3e4f5a6b}",
        ];
        for scope_id in not_canonical {
            let mut wire = wire_mark();
            wire.parent = Some(v1::ScopeReference {
                scope_id: scope_id.into(),
            });
            assert!(
                mark_request_from_wire(&wire).is_err(),
                "{scope_id} is not a canonical scope identity"
            );
        }

        // A mark cannot have happened before the epoch, and a peer that says it
        // did is writing an event the runtime cannot order.
        let mut before_epoch = wire_mark();
        before_epoch.timestamp_unix_micros = Some(-1);
        assert!(mark_request_from_wire(&before_epoch).is_err());

        // A present-but-empty payload is a claim of an empty payload, and the
        // empty string is not JSON.
        let mut empty_payload = wire_mark();
        empty_payload.data_json = Some("  ".into());
        assert!(mark_request_from_wire(&empty_payload).is_err());

        // A schema with no name describes nothing.
        let mut nameless_schema = wire_mark();
        nameless_schema.data_schema = Some(v1::MarkDataSchema {
            name: String::new(),
            version: "1".into(),
        });
        assert!(mark_request_from_wire(&nameless_schema).is_err());

        // A present severity of `UNSPECIFIED` says the severity is a severity.
        let mut unspecified = wire_mark();
        unspecified.severity = Some(v1::MarkSeverity::Unspecified as i32);
        assert!(mark_request_from_wire(&unspecified).is_err());

        // And a name is the minimum: a mark without one addresses nothing.
        let mut nameless = wire_mark();
        nameless.name = "   ".into();
        assert!(mark_request_from_wire(&nameless).is_err());
    }

    #[test]
    fn a_scope_or_codec_call_must_name_a_known_operation() {
        let scope = |operation: v1::ScopeOperation, payload: Option<&str>| v1::ScopeStackRequest {
            session_id: "session-1".into(),
            operation_request_id: "operation-1".into(),
            host_call_id: "call-1".into(),
            operation: operation as i32,
            payload_json: payload.map(str::to_owned),
        };

        let push = scope(
            v1::ScopeOperation::Push,
            Some(r#"{"name":"step","scope_type":"function"}"#),
        );
        assert_eq!(
            scope_stack_request_from_wire(&push)
                .expect("a push with a payload")
                .operation,
            PluginScopeOperation::Push
        );
        assert_eq!(
            scope_stack_request_from_wire(&scope(v1::ScopeOperation::Current, None))
                .expect("a read with nothing to describe")
                .operation,
            PluginScopeOperation::Current
        );

        // A payload is a property of the operation: carrying one where it means
        // nothing, or omitting one that needs it, says two things at once.
        assert!(
            scope_stack_request_from_wire(&scope(v1::ScopeOperation::Current, Some("{}"))).is_err()
        );
        assert!(scope_stack_request_from_wire(&scope(v1::ScopeOperation::Push, None)).is_err());

        // A peer cannot manufacture an operation by writing a new name or a
        // number this side does not know.
        for operation in [v1::ScopeOperation::Unspecified as i32, 9_999] {
            let mut wire = scope(v1::ScopeOperation::Push, Some("{}"));
            wire.operation = operation;
            assert!(scope_stack_request_from_wire(&wire).is_err());
        }

        let codec = |operation: i32| v1::ResolveCodecRequest {
            session_id: "session-1".into(),
            operation_request_id: "operation-1".into(),
            host_call_id: "call-1".into(),
            operation,
            payload_json: r#"{"model":"example"}"#.into(),
        };
        assert_eq!(
            resolve_codec_request_from_wire(&codec(v1::CodecOperation::LlmRequestDecode as i32))
                .expect("a known codec operation")
                .operation,
            PluginCodecOperation::LlmRequestDecode
        );
        for operation in [v1::CodecOperation::Unspecified as i32, 9_999] {
            assert!(resolve_codec_request_from_wire(&codec(operation)).is_err());
        }
    }

    #[test]
    fn a_grant_of_output_capacity_is_refused_when_it_grants_nothing() {
        // A grant of zero would leave the host reporting backpressure forever,
        // with no way to tell that from a consumer that stopped consuming.
        assert!(
            output_credit_from_wire(&v1::OutputCredit {
                operation_request_id: "operation-1".into(),
                items: 0,
            })
            .is_err()
        );
        assert!(
            output_credit_from_wire(&v1::OutputCredit {
                operation_request_id: "  ".into(),
                items: 1,
            })
            .is_err()
        );

        let credit = output_credit_from_wire(&v1::OutputCredit {
            operation_request_id: "operation-1".into(),
            items: 8,
        })
        .expect("a grant");
        assert_eq!(credit.items, 8);

        // And it travels as a session message like every other grant.
        let message = PluginSessionMessage {
            session_id: "session-1".into(),
            message: PluginSessionPayload::OutputCredit(credit),
        };
        assert_eq!(
            session_message_from_wire(&session_message_to_wire(&message))
                .expect("a session message this side built"),
            message
        );
    }

    #[test]
    fn a_chunk_and_its_answer_carry_the_sequence_that_binds_them() {
        let chunk = continuation_chunk_from_wire(&v1::ContinuationChunk {
            host_call_id: "call-1".into(),
            sequence: 1,
            chunk_json: r#"{"delta":"hi"}"#.into(),
        })
        .expect("a first chunk");
        assert_eq!(chunk.sequence, 1);

        // Sequences are one-based, so zero is what a default-constructed
        // message carries; a chunk nobody ordered cannot be answered in order.
        assert!(
            continuation_chunk_from_wire(&v1::ContinuationChunk {
                host_call_id: "call-1".into(),
                sequence: 0,
                chunk_json: r#"{"delta":"hi"}"#.into(),
            })
            .is_err()
        );

        let disposition = continuation_disposition_from_wire(&v1::ContinuationChunkDisposition {
            host_call_id: "call-1".into(),
            sequence: 1,
            disposition: Some(v1::continuation_chunk_disposition::Disposition::Decision(
                v1::ChunkDisposition::Stop as i32,
            )),
        })
        .expect("an answer");
        assert_eq!(disposition.sequence, 1);
        assert_eq!(disposition.disposition, Ok(PluginChunkDecision::Stop));

        // An answer that says nothing would leave the runtime neither producing
        // nor stopping.
        assert!(
            continuation_disposition_from_wire(&v1::ContinuationChunkDisposition {
                host_call_id: "call-1".into(),
                sequence: 1,
                disposition: None,
            })
            .is_err()
        );
        assert!(
            continuation_disposition_from_wire(&v1::ContinuationChunkDisposition {
                host_call_id: "call-1".into(),
                sequence: 1,
                disposition: Some(v1::continuation_chunk_disposition::Disposition::Decision(
                    v1::ChunkDisposition::Unspecified as i32
                )),
            })
            .is_err()
        );

        // And a failure arm is validated like every other failure.
        let failed = continuation_disposition_from_wire(&v1::ContinuationChunkDisposition {
            host_call_id: "call-1".into(),
            sequence: 2,
            disposition: Some(v1::continuation_chunk_disposition::Disposition::Failure(
                v1::PluginFailure {
                    code: v1::FailureCode::HostCrashed as i32,
                    message: "the consumer went away".into(),
                    ..Default::default()
                },
            )),
        })
        .expect("a failure");
        assert_eq!(
            failed.disposition,
            Err(unavailable_with(PluginFailureCode::HostCrashed))
        );
    }

    #[test]
    fn a_handshake_carries_the_read_capabilities_it_asks_for_and_gets() {
        let requested = handshake_request_from_wire(&v1::HandshakeRequest {
            protocol_version: 1,
            runtime_binding_digest: "binding".into(),
            client_nonce: "nonce".into(),
            session_credential: "credential".into(),
            maximum_frame_bytes: 1024,
            supported_features: vec!["streaming".into()],
            offered_read_capabilities: vec![v1::HostReadCapability::RuntimeDiagnostics as i32],
        })
        .expect("a request");
        assert_eq!(
            requested.offered_read_capabilities,
            vec![PluginHostReadCapability::RuntimeDiagnostics]
        );

        // A capability this side cannot resolve is refused rather than dropped:
        // it decides what a less-trusted process may read.
        for capability in [v1::HostReadCapability::Unspecified as i32, 9_999] {
            let mut wire = v1::HandshakeRequest {
                protocol_version: 1,
                runtime_binding_digest: "binding".into(),
                client_nonce: "nonce".into(),
                session_credential: "credential".into(),
                maximum_frame_bytes: 1024,
                supported_features: Vec::new(),
                offered_read_capabilities: vec![capability],
            };
            assert!(handshake_request_from_wire(&wire).is_err());

            // The same rule for what a kernel says it granted.
            wire.offered_read_capabilities = Vec::new();
            assert!(
                session_identity_from_wire(&v1::HandshakeResponse {
                    protocol_version: 1,
                    session_id: "session-1".into(),
                    host_instance_id: "host-1".into(),
                    host_nonce: "nonce".into(),
                    maximum_frame_bytes: 1024,
                    supported_features: Vec::new(),
                    accepted_read_capabilities: vec![capability],
                })
                .is_err()
            );
        }

        // And a list naming one capability twice is not a list of two.
        assert!(
            session_identity_from_wire(&v1::HandshakeResponse {
                protocol_version: 1,
                session_id: "session-1".into(),
                host_instance_id: "host-1".into(),
                host_nonce: "nonce".into(),
                maximum_frame_bytes: 1024,
                supported_features: Vec::new(),
                accepted_read_capabilities: vec![
                    v1::HostReadCapability::RegistrationInventory as i32,
                    v1::HostReadCapability::RegistrationInventory as i32,
                ],
            })
            .is_err()
        );
    }

    #[test]
    fn a_descriptor_cannot_name_one_thing_twice() {
        let capability = |id: &str| v1::PluginCapability {
            id: id.into(),
            kind: v1::PluginCapabilityKind::Tool as i32,
            declared_digest: None,
        };
        let error = descriptor_from_wire(&v1::PluginDescriptor {
            plugin_id: "example".into(),
            capabilities: vec![capability("run"), capability("run")],
            ..Default::default()
        })
        .expect_err("two capabilities under one name");
        assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);

        let registration = v1::PluginRegistrationDescriptor {
            registration_id: "nemo-relay-plugin.v1.example:1:run".into(),
            component_kind: "example".into(),
            operation: v1::PluginRegistrationOperation::RegistrationOperationToolRequestIntercept
                as i32,
            shape: v1::PluginExecutionShape::ShapeUnary as i32,
            ..Default::default()
        };
        let error = descriptor_from_wire(&v1::PluginDescriptor {
            plugin_id: "example".into(),
            registrations: vec![registration.clone(), registration],
            ..Default::default()
        })
        .expect_err("one registration named twice at one attachment point");
        assert_eq!(malformed_code(error), PluginFailureCode::MalformedResponse);
    }

    #[test]
    fn an_operation_envelope_is_validated_before_its_payload() {
        let context = PluginExecutionContext {
            operation_request_id: "operation-1".into(),
            protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            deadline_unix_ms: u64::MAX,
            remaining_budget_millis: 2_500,
            max_response_bytes: 1024,
        };

        // An operation with no session, or with no context, has no budget, and
        // the kernel does not start work it cannot time out.
        assert!(operation_envelope_from_wire("  ", Some(&context_to_wire(&context))).is_err());
        assert!(operation_envelope_from_wire("session-1", None).is_err());
        assert_eq!(
            operation_envelope_from_wire("session-1", Some(&context_to_wire(&context)))
                .expect("an envelope")
                .session_id,
            "session-1"
        );
    }

    #[test]
    fn a_handle_is_validated_when_a_request_names_one() {
        let handle = v1::PluginHandle {
            plugin_id: "example".into(),
            generation: 7,
        };

        // A handle addresses one instance: without an identity, or at
        // generation zero, it addresses nothing.
        assert!(unload_request_from_wire(&v1::UnloadRequest::default()).is_err());
        assert!(
            unload_request_from_wire(&v1::UnloadRequest {
                handle: Some(v1::PluginHandle {
                    plugin_id: "example".into(),
                    generation: 0,
                }),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            unload_request_from_wire(&v1::UnloadRequest {
                handle: Some(v1::PluginHandle {
                    plugin_id: "  ".into(),
                    generation: 7,
                }),
                ..Default::default()
            })
            .is_err()
        );
        assert_eq!(
            unload_request_from_wire(&v1::UnloadRequest {
                handle: Some(handle.clone()),
                ..Default::default()
            })
            .expect("an unload")
            .handle,
            PluginHandle {
                plugin_id: "example".into(),
                generation: 7
            }
        );

        // An inspection with no handle asks about everything loaded, which is a
        // question rather than a gap.
        assert_eq!(
            inspect_request_from_wire(&v1::InspectRequest {
                handle: None,
                ..Default::default()
            })
            .expect("an inspection of everything")
            .handle,
            None
        );
        assert_eq!(
            inspect_request_from_wire(&v1::InspectRequest {
                handle: Some(handle),
                ..Default::default()
            })
            .expect("an inspection of one")
            .handle
            .expect("a handle")
            .generation,
            7
        );
    }

    #[test]
    fn an_invocation_takes_its_budget_from_the_context() {
        let context = PluginExecutionContext {
            operation_request_id: "operation-1".into(),
            protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            deadline_unix_ms: u64::MAX,
            remaining_budget_millis: 2_500,
            max_response_bytes: 1024,
        };
        let invoke = invoke_request_from_wire(
            &v1::InvokeRequest {
                handle: Some(v1::PluginHandle {
                    plugin_id: "example".into(),
                    generation: 7,
                }),
                capability_id: "run".into(),
                arguments: r#"{"input":true}"#.into(),
                ..Default::default()
            },
            &context,
        )
        .expect("an invocation");

        // A caller that could choose its own deadline could choose an infinite
        // one, so the budget comes from the context the kernel derives.
        assert_eq!(invoke.budget_millis, 2_500);
        assert!(
            invoke_request_from_wire(
                &v1::InvokeRequest {
                    capability_id: "run".into(),
                    arguments: "  ".into(),
                    ..Default::default()
                },
                &context
            )
            .is_err()
        );
    }

    #[test]
    fn a_cancellation_that_names_no_operation_is_refused() {
        assert!(
            cancel_operation_request_from_wire(&v1::CancelOperationRequest {
                operation_request_id: String::new(),
                ..Default::default()
            })
            .is_err()
        );
        assert_eq!(
            cancel_operation_request_from_wire(&v1::CancelOperationRequest {
                operation_request_id: "operation-4".into(),
                ..Default::default()
            })
            .expect("a cancellation"),
            "operation-4"
        );
    }

    #[test]
    fn a_host_call_answer_is_an_answer_or_a_failure() {
        // Neither arm is a message that says nothing, and both at once says two
        // things.
        let empty = host_call_response_from_wire(None, None, "an answer")
            .expect_err("an answer with no arm");
        assert_eq!(malformed_code(empty), PluginFailureCode::MalformedResponse);

        let failure = v1::PluginFailure {
            code: v1::FailureCode::Unavailable as i32,
            message: "the runtime is not serving codecs".into(),
            ..Default::default()
        };
        assert!(
            scope_stack_response_from_wire(&v1::ScopeStackResponse {
                result: Some(v1::scope_stack_response::Result::Failure(failure.clone())),
            })
            .expect("a failure is an answer")
            .result
            .is_err()
        );
        assert_eq!(
            resolve_codec_response_from_wire(&v1::ResolveCodecResponse {
                result: Some(v1::resolve_codec_response::Result::Output(
                    r#"{"model":"example"}"#.into()
                )),
            })
            .expect("an answer")
            .result,
            Ok(r#"{"model":"example"}"#.to_owned())
        );
        assert!(
            resolve_codec_response_from_wire(&v1::ResolveCodecResponse {
                result: Some(v1::resolve_codec_response::Result::Output("  ".into())),
            })
            .is_err()
        );
    }

    #[test]
    fn a_stream_frame_says_what_it_carries() {
        assert!(stream_chunk_from_wire(&v1::StreamChunk::default()).is_err());
        assert!(
            stream_chunk_from_wire(&v1::StreamChunk {
                operation_request_id: "operation-1".into(),
                chunk: Some(v1::stream_chunk::Chunk::End(false)),
                dispatch_state: v1::DispatchState::NotDispatched as i32,
                outcome_certainty: v1::OutcomeCertainty::ConfirmedSuccess as i32,
            })
            .is_err()
        );

        // A stream that simply stops is a truncation, so the terminal frame is
        // where the dispatch state is reported and it has to be known.
        let end = stream_chunk_from_wire(&v1::StreamChunk {
            operation_request_id: "operation-1".into(),
            chunk: Some(v1::stream_chunk::Chunk::End(true)),
            dispatch_state: v1::DispatchState::DispatchAttempted as i32,
            outcome_certainty: v1::OutcomeCertainty::Unknown as i32,
        })
        .expect("a terminal frame");
        assert_eq!(end.chunk, PluginStreamChunkKind::End);
        assert_eq!(end.dispatch, DispatchState::DispatchAttempted);
        assert_eq!(end.certainty, OutcomeCertainty::Unknown);

        assert!(
            stream_chunk_from_wire(&v1::StreamChunk {
                operation_request_id: "operation-1".into(),
                chunk: Some(v1::stream_chunk::Chunk::End(true)),
                dispatch_state: v1::DispatchState::Unspecified as i32,
                outcome_certainty: v1::OutcomeCertainty::ConfirmedSuccess as i32,
            })
            .is_err()
        );
    }

    fn unavailable_with(code: PluginFailureCode) -> PluginFailure {
        PluginFailure {
            code,
            message: "the consumer went away".into(),
        }
    }
}
