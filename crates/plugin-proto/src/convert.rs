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
    DispatchState, LifecycleOutcome, MAX_FRAME_BYTES, OutcomeCertainty, PluginArtifactIdentity,
    PluginCapability, PluginCapabilityKind, PluginDescriptor, PluginExecutionContext,
    PluginExecutionOutcome, PluginExecutionShape, PluginFailure, PluginFailureCode, PluginHandle,
    PluginHostHealth, PluginInvokeResponse, PluginLoadRequest, PluginLoadResponse,
    PluginProtocolError, PluginRegistrationClass, PluginRegistrationDescriptor,
    PluginRegistrationOrdering, PluginSessionIdentity, PluginSuccess,
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
/// The approved digests travel with it. They are the runtime's statement of
/// what it approved, so the side performing the load confirms an identity
/// rather than deciding one.
pub fn load_request_to_wire(request: &PluginLoadRequest) -> v1::LoadRequest {
    v1::LoadRequest {
        session_id: String::new(),
        context: None,
        plugin_id: request.plugin_id.clone(),
        artifact: request.artifact.clone(),
        manifest_digest: request.identity.manifest_sha256.clone(),
        library_digest: request.identity.library_sha256.clone(),
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
        capabilities.push(PluginCapability {
            id: capability.id.clone(),
            kind: capability_kind_from_wire(capability.kind)?,
            declared_digest: capability.declared_digest.clone(),
        });
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
        registrations: wire
            .registrations
            .iter()
            .map(registration_from_wire)
            .collect::<Result<Vec<_>, _>>()?,
        capabilities,
    })
}

/// Validate one registration description.
///
/// A registration the runtime cannot order or classify is worse than a missing
/// one, because the proxy would be built and then behave unlike the plugin it
/// stands for. Every field that decides behaviour is therefore required rather
/// than defaulted.
fn registration_from_wire(
    wire: &v1::PluginRegistrationDescriptor,
) -> Result<PluginRegistrationDescriptor, PluginProtocolError> {
    if wire.registration_id.trim().is_empty() {
        return Err(malformed("a registration with no identity"));
    }
    if wire.component_kind.trim().is_empty() {
        return Err(malformed("a registration with no component kind"));
    }
    let class = v1::PluginRegistrationClass::try_from(wire.class)
        .map_err(|_| malformed(format!("an unknown registration class {}", wire.class)))?;
    let class = match class {
        v1::PluginRegistrationClass::Unspecified => {
            return Err(malformed("a registration with no class"));
        }
        v1::PluginRegistrationClass::RegistrationMiddleware => PluginRegistrationClass::Middleware,
        v1::PluginRegistrationClass::RegistrationGuardrail => PluginRegistrationClass::Guardrail,
        v1::PluginRegistrationClass::RegistrationSubscriber => PluginRegistrationClass::Subscriber,
        v1::PluginRegistrationClass::RegistrationTool => PluginRegistrationClass::Tool,
        v1::PluginRegistrationClass::RegistrationLlmIntercept => {
            PluginRegistrationClass::LlmIntercept
        }
        v1::PluginRegistrationClass::RegistrationPayloadCodec => {
            PluginRegistrationClass::PayloadCodec
        }
    };
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
    let ordering = wire
        .ordering
        .as_ref()
        .ok_or_else(|| malformed("a registration with no ordering"))?;

    Ok(PluginRegistrationDescriptor {
        registration_id: wire.registration_id.clone(),
        component_kind: wire.component_kind.clone(),
        class,
        ordering: PluginRegistrationOrdering {
            priority: ordering.priority,
            may_break_chain: ordering.may_break_chain,
        },
        shape,
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

        let back = load_request_from_wire(&load_request_to_wire(&request)).expect("round trip");

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
}
