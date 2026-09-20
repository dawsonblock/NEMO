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
    DispatchState, OutcomeCertainty, PluginCapability, PluginCapabilityKind, PluginDescriptor,
    PluginExecutionContext, PluginFailure, PluginFailureCode, PluginHandle, PluginLoadResponse,
    PluginProtocolError, PluginSuccess,
};

use crate::v1;

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
        capabilities,
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
    Ok(PluginLoadResponse {
        handle: PluginHandle {
            plugin_id: handle.plugin_id.clone(),
            generation: handle.generation,
        },
        descriptor: descriptor_from_wire(descriptor)?,
    })
}

/// Convert a domain success into its wire form.
pub fn success_to_wire(success: &PluginSuccess) -> Result<v1::InvokeOutcome, PluginProtocolError> {
    match success {
        PluginSuccess::Invoked(response) => Ok(v1::InvokeOutcome {
            dispatch_state: dispatch_to_wire(DispatchState::NotDispatched) as i32,
            outcome_certainty: outcome_to_wire(OutcomeCertainty::ConfirmedSuccess) as i32,
            result: Some(v1::invoke_outcome::Result::Output(response.output.clone())),
        }),
        other => Err(malformed(format!(
            "{} has no invocation outcome representation",
            success_name(other)
        ))),
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
}
