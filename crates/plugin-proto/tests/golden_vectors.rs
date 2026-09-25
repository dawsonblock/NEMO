// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Golden vectors for the plugin wire model.
//!
//! With protobuf the `.proto` file is the cross-language schema, so a second
//! language generates its own types from it rather than parsing a recorded
//! example. What vectors add is drift detection: the encoded bytes of a fixed
//! message are recorded, so renumbering a field or changing a type is caught
//! here instead of by a peer that starts decoding nonsense.
//!
//! Run with `UPDATE_PLUGIN_VECTORS=1` to regenerate the file. Regenerating is a
//! deliberate act: the point is that a wire change cannot happen without
//! someone seeing this file change with it.

use std::path::PathBuf;

use nemo_relay_plugin_proto::v1;
use prost::Message;

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("qualification/abi/plugin-v1/vectors.json")
}

/// Messages that appear in a service signature but have no vector yet.
///
/// The inventory check below fails when a message reaches a service signature
/// without being either vectored or listed here, so the gap is a decision
/// somebody made rather than something that happened. Closing this list is part
/// of the ABI-closure work.
const PENDING_VECTORS: &[&str] = &[
    "AttachOutcome",
    "AttachRequest",
    "CancelOperationRequest",
    "EmitMarkRequest",
    "EmitMarkResponse",
    "HealthRequest",
    "InspectRequest",
    "InvokeRequest",
    "ResolveCodecRequest",
    "ResolveCodecResponse",
    "ScopeStackRequest",
    "ScopeStackResponse",
    "SessionCloseRequest",
    "SessionCloseResponse",
    "StreamChunk",
    "UnloadRequest",
];

/// Every message named in an `rpc` signature of the checked-in schema.
fn messages_reachable_from_services() -> Vec<String> {
    let proto = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("proto/nemo/relay/plugin/v1/plugin_host.proto");
    let source = std::fs::read_to_string(&proto).expect("read proto");

    let mut names = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if !line.starts_with("rpc ") {
            continue;
        }
        // `rpc Name(Req) returns (Resp);`, with `stream` allowed on either side.
        for part in line.split(['(', ')']) {
            let candidate = part.trim().trim_start_matches("stream").trim();
            if candidate.starts_with(|c: char| c.is_ascii_uppercase()) && !candidate.contains(' ') {
                names.push(candidate.to_owned());
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Every message the vectors cover, in a fixed order.
fn messages() -> Vec<(&'static str, Vec<u8>)> {
    let context = |id: &str| v1::PluginExecutionContext {
        operation_request_id: id.to_owned(),
        protocol_version: 1,
        runtime_binding_digest: "runtime-binding-digest".into(),
        deadline_unix_ms: 1_700_000_000_000,
        remaining_budget_millis: 29_000,
        max_response_bytes: 1_048_576,
    };
    let descriptor = || v1::PluginDescriptor {
        plugin_id: "example".into(),
        plugin_version: Some(">=0.9,<1.0".into()),
        negotiated_abi_version: Some(4),
        manifest_digest: Some("manifest-digest".into()),
        registration_kinds: vec!["example_kind".into()],
        capabilities: Vec::new(),
        registrations: vec![v1::PluginRegistrationDescriptor {
            registration_id: "registration-1".into(),
            component_kind: "example_kind".into(),
            operation: v1::PluginRegistrationOperation::RegistrationOperationToolRequestIntercept
                as i32,
            ordering: Some(v1::PluginRegistrationOrdering {
                priority: Some(10),
                may_break_chain: Some(false),
            }),
            shape: v1::PluginExecutionShape::ShapeUnary as i32,
            config_keys: vec!["model".into()],
            declared_digest: None,
            gated_registration: Some("example_kind:gated".into()),
        }],
    };
    let handle = || v1::PluginHandle {
        plugin_id: "example".into(),
        generation: 41,
    };

    vec![
        (
            "HandshakeRequest",
            v1::HandshakeRequest {
                protocol_version: 1,
                runtime_binding_digest: "runtime-binding-digest".into(),
                client_nonce: "client-nonce".into(),
                session_credential: "session-credential".into(),
                maximum_frame_bytes: nemo_relay_plugin_proto::MAX_FRAME_BYTES,
                supported_features: vec!["streaming".into(), "cancel".into()],
                offered_read_capabilities: vec![v1::HostReadCapability::RuntimeDiagnostics as i32],
                supported_registration_operations: vec![
                    v1::PluginRegistrationOperation::RegistrationOperationToolRequestIntercept
                        as i32,
                ],
            }
            .encode_to_vec(),
        ),
        (
            "LoadRequest",
            v1::LoadRequest {
                session_id: "session-1".into(),
                context: Some(context("operation-1")),
                plugin_id: "example".into(),
                artifact: "relay-plugin.toml".into(),
                manifest_digest: "manifest-digest".into(),
                library_digest: "library-digest".into(),
            }
            .encode_to_vec(),
        ),
        (
            "LoadResponse",
            v1::LoadResponse {
                handle: Some(handle()),
                descriptor: Some(descriptor()),
            }
            .encode_to_vec(),
        ),
        (
            "PluginFailure",
            v1::PluginFailure {
                code: v1::FailureCode::OversizedFrame as i32,
                message: "frame exceeds the limit".into(),
                observed: Some(u64::from(nemo_relay_plugin_proto::MAX_FRAME_BYTES) + 1),
                limit: Some(nemo_relay_plugin_proto::MAX_FRAME_BYTES),
                expected_version: None,
                received_version: None,
            }
            .encode_to_vec(),
        ),
        (
            "InvokeOutcome",
            v1::InvokeOutcome {
                dispatch_state: v1::DispatchState::DispatchAttempted as i32,
                outcome_certainty: v1::OutcomeCertainty::Unknown as i32,
                result: Some(v1::invoke_outcome::Result::Failure(v1::PluginFailure {
                    code: v1::FailureCode::HostCrashed as i32,
                    message: "the plugin host exited during dispatch".into(),
                    observed: None,
                    limit: None,
                    expected_version: None,
                    received_version: None,
                })),
                // The answer names the invocation it answers: an outcome that
                // belongs to no operation is not one the kernel may attribute.
                operation_request_id: "operation-1".into(),
            }
            .encode_to_vec(),
        ),
        // The lifecycle outcomes. Each carries the same payloads the bare
        // response messages used to, inside a oneof whose other arm is the
        // structured failure, so a peer that answers coherently can say that
        // the operation failed without the caller mistaking it for a channel
        // error.
        (
            "HandshakeOutcome",
            v1::HandshakeOutcome {
                result: Some(v1::handshake_outcome::Result::Established(
                    v1::HandshakeResponse {
                        protocol_version: 1,
                        host_release_version: "0.9.1".into(),
                        host_native_abi_version: 5,
                        session_id: "session-1".into(),
                        host_instance_id: "host-1".into(),
                        host_nonce: "host-nonce".into(),
                        maximum_frame_bytes: nemo_relay_plugin_proto::MAX_FRAME_BYTES,
                        supported_features: vec!["streaming".into()],
                        accepted_read_capabilities: vec![
                            v1::HostReadCapability::RuntimeDiagnostics as i32,
                        ],
                    },
                )),
            }
            .encode_to_vec(),
        ),
        (
            "LoadOutcome",
            v1::LoadOutcome {
                result: Some(v1::load_outcome::Result::Loaded(v1::LoadResponse {
                    handle: Some(handle()),
                    descriptor: Some(descriptor()),
                })),
            }
            .encode_to_vec(),
        ),
        (
            "UnloadOutcome",
            v1::UnloadOutcome {
                result: Some(v1::unload_outcome::Result::Failure(v1::PluginFailure {
                    code: v1::FailureCode::StaleHandle as i32,
                    message: "the handle names a generation that is no longer loaded".into(),
                    observed: None,
                    limit: None,
                    expected_version: None,
                    received_version: None,
                })),
            }
            .encode_to_vec(),
        ),
        (
            "InspectOutcome",
            v1::InspectOutcome {
                result: Some(v1::inspect_outcome::Result::Inspected(
                    v1::InspectResponse {
                        descriptors: vec![descriptor()],
                    },
                )),
            }
            .encode_to_vec(),
        ),
        (
            "CancelOperationOutcome",
            v1::CancelOperationOutcome {
                result: Some(v1::cancel_operation_outcome::Result::Cancelled(
                    v1::CancelOperationResponse {},
                )),
            }
            .encode_to_vec(),
        ),
        (
            "HealthOutcome",
            v1::HealthOutcome {
                result: Some(v1::health_outcome::Result::Health(v1::HealthResponse {
                    protocol_version: 1,
                    accepting_work: true,
                    loaded: vec![handle()],
                })),
            }
            .encode_to_vec(),
        ),
        // The duplex session, once for each family it exists to carry: a
        // downstream stream the plugin paces one pull at a time, and a
        // completion settled after its callback returned. Three vectors share
        // the envelope's name because the envelope is one message; what differs
        // is which arm it carries.
        (
            "PluginSessionMessage",
            v1::PluginSessionMessage {
                session_id: "session-1".into(),
                message: Some(v1::plugin_session_message::Message::StreamOpen(
                    v1::DownstreamStreamOpenRequest {
                        host_call_id: "call-1".into(),
                        operation_request_id: "operation-1".into(),
                        request_json: r#"{"model":"example"}"#.into(),
                    },
                )),
            }
            .encode_to_vec(),
        ),
        (
            "PluginSessionMessage",
            v1::PluginSessionMessage {
                session_id: "session-1".into(),
                message: Some(v1::plugin_session_message::Message::StreamItem(
                    v1::DownstreamStreamItem {
                        host_call_id: "call-2".into(),
                        stream_id: "stream-1".into(),
                        chunk_json: r#"{"delta":"hi"}"#.into(),
                    },
                )),
            }
            .encode_to_vec(),
        ),
        (
            "PluginSessionMessage",
            v1::PluginSessionMessage {
                session_id: "session-1".into(),
                message: Some(v1::plugin_session_message::Message::CompletionSettle(
                    v1::CompletionSettle {
                        completion_id: "completion-1".into(),
                        operation_request_id: "operation-1".into(),
                        result: Some(v1::completion_settle::Result::Failure(v1::PluginFailure {
                            code: v1::FailureCode::Unavailable as i32,
                            message: "the downstream provider refused".into(),
                            observed: None,
                            limit: None,
                            expected_version: None,
                            received_version: None,
                        })),
                    },
                )),
            }
            .encode_to_vec(),
        ),
        (
            "PluginSessionMessage",
            v1::PluginSessionMessage {
                session_id: "session-1".into(),
                message: Some(v1::plugin_session_message::Message::OutputCredit(
                    v1::OutputCredit {
                        operation_request_id: "operation-1".into(),
                        items: 8,
                    },
                )),
            }
            .encode_to_vec(),
        ),
        (
            "ContinuationRequest",
            v1::ContinuationRequest {
                session_id: "session-1".into(),
                operation_request_id: "operation-1".into(),
                host_call_id: "call-1".into(),
                invocation_json: r#"{"input":true}"#.into(),
            }
            .encode_to_vec(),
        ),
        (
            "ContinuationOutcome",
            v1::ContinuationOutcome {
                result: Some(v1::continuation_outcome::Result::ValueJson(
                    r#"{"ok":true}"#.into(),
                )),
            }
            .encode_to_vec(),
        ),
        // The remaining host-used messages, so a field that is renumbered or
        // retyped shows up here rather than at a peer.
        (
            "EmitMarkRequest",
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
            .encode_to_vec(),
        ),
        (
            "ScopeStackRequest",
            v1::ScopeStackRequest {
                session_id: "session-1".into(),
                operation_request_id: "operation-1".into(),
                host_call_id: "call-1".into(),
                operation: v1::ScopeOperation::Push as i32,
                payload_json: Some(r#"{"name":"step"}"#.into()),
            }
            .encode_to_vec(),
        ),
        (
            "ResolveCodecRequest",
            v1::ResolveCodecRequest {
                session_id: "session-1".into(),
                operation_request_id: "operation-1".into(),
                host_call_id: "call-1".into(),
                operation: v1::CodecOperation::LlmRequestDecode as i32,
                payload_json: r#"{"model":"example"}"#.into(),
                codec_reference: "codec-1".into(),
            }
            .encode_to_vec(),
        ),
        (
            "ContinuationChunk",
            v1::ContinuationChunk {
                host_call_id: "call-1".into(),
                sequence: 1,
                chunk_json: r#"{"delta":"hi"}"#.into(),
            }
            .encode_to_vec(),
        ),
        (
            "ContinuationChunkDisposition",
            v1::ContinuationChunkDisposition {
                host_call_id: "call-1".into(),
                sequence: 1,
                disposition: Some(v1::continuation_chunk_disposition::Disposition::Decision(
                    v1::ChunkDisposition::Continue as i32,
                )),
            }
            .encode_to_vec(),
        ),
        (
            "UnloadRequest",
            v1::UnloadRequest {
                session_id: "session-1".into(),
                context: Some(context("operation-2")),
                handle: Some(handle()),
            }
            .encode_to_vec(),
        ),
        ("UnloadResponse", v1::UnloadResponse {}.encode_to_vec()),
        (
            "InspectRequest",
            v1::InspectRequest {
                session_id: "session-1".into(),
                context: Some(context("operation-3")),
                handle: None,
            }
            .encode_to_vec(),
        ),
        (
            "ActivateRequest",
            v1::ActivateRequest {
                session_id: "session-1".into(),
                // Vectored as a serving activation: discovery is an inspection
                // affordance, and the vector records the shape production sends.
                discovery: false,
                context: Some(context("operation-7")),
                components: vec![v1::ComponentConfiguration {
                    kind: "example".into(),
                    config_json: r#"{"model":"example"}"#.into(),
                }],
            }
            .encode_to_vec(),
        ),
        (
            "ActivateOutcome",
            v1::ActivateOutcome {
                result: Some(v1::activate_outcome::Result::Activated(
                    v1::ActivateResponse {
                        descriptors: vec![descriptor()],
                    },
                )),
            }
            .encode_to_vec(),
        ),
        (
            "InvokeRequest",
            v1::InvokeRequest {
                session_id: "session-1".into(),
                context: Some(context("operation-4")),
                handle: Some(handle()),
                registration_id: "example.run".into(),
                arguments: r#"{"input":true}"#.into(),
            }
            .encode_to_vec(),
        ),
        (
            "StreamChunk",
            v1::StreamChunk {
                operation_request_id: "operation-4".into(),
                chunk: Some(v1::stream_chunk::Chunk::Data(r#"{"delta":"hi"}"#.into())),
                dispatch_state: v1::DispatchState::NotDispatched as i32,
                outcome_certainty: v1::OutcomeCertainty::ConfirmedSuccess as i32,
            }
            .encode_to_vec(),
        ),
        (
            "CancelOperationRequest",
            v1::CancelOperationRequest {
                session_id: "session-1".into(),
                context: Some(context("operation-5")),
                operation_request_id: "operation-4".into(),
            }
            .encode_to_vec(),
        ),
        (
            "CancelOperationResponse",
            v1::CancelOperationResponse {}.encode_to_vec(),
        ),
        (
            "HealthRequest",
            v1::HealthRequest {
                session_id: "session-1".into(),
                context: Some(context("operation-6")),
            }
            .encode_to_vec(),
        ),
        (
            "SessionCloseRequest",
            v1::SessionCloseRequest {
                session_id: "session-1".into(),
            }
            .encode_to_vec(),
        ),
        (
            "SessionCloseResponse",
            v1::SessionCloseResponse {}.encode_to_vec(),
        ),
        (
            "SessionCloseOutcome",
            v1::SessionCloseOutcome {
                result: Some(v1::session_close_outcome::Result::Closed(
                    v1::SessionCloseResponse {},
                )),
            }
            .encode_to_vec(),
        ),
        ("EmitMarkResponse", v1::EmitMarkResponse {}.encode_to_vec()),
        (
            "ScopeStackResponse",
            v1::ScopeStackResponse {
                result: Some(v1::scope_stack_response::Result::Output(
                    r#"{"scope_id":"018f0b3c-5f5a-7c3e-9a2b-1c2d3e4f5a6b"}"#.into(),
                )),
            }
            .encode_to_vec(),
        ),
        (
            "ResolveCodecResponse",
            v1::ResolveCodecResponse {
                result: Some(v1::resolve_codec_response::Result::Failure(
                    v1::PluginFailure {
                        code: v1::FailureCode::Unavailable as i32,
                        message: "no codec is attached to this call".into(),
                        ..Default::default()
                    },
                )),
            }
            .encode_to_vec(),
        ),
    ]
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn every_message_in_a_service_signature_is_vectored_or_explicitly_pending() {
    let covered: Vec<String> = messages()
        .into_iter()
        .map(|(name, _)| name.to_owned())
        .collect();
    let pending: Vec<String> = PENDING_VECTORS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();

    let reachable = messages_reachable_from_services();
    assert!(
        reachable.len() >= 20,
        "the schema parse found {} service messages, so this check would pass by \
         finding nothing: {reachable:?}",
        reachable.len()
    );

    let mut unaccounted: Vec<String> = reachable
        .into_iter()
        .filter(|name| !covered.contains(name) && !pending.contains(name))
        .collect();
    unaccounted.sort();

    assert!(
        unaccounted.is_empty(),
        "these messages are reachable from a service and are neither vectored nor \
         listed as pending: {unaccounted:?}"
    );
}

#[test]
fn the_recorded_wire_bytes_represent_the_current_schema() {
    let path = vectors_path();
    let current: Vec<(String, String)> = messages()
        .into_iter()
        .map(|(name, bytes)| (name.to_owned(), encode_hex(&bytes)))
        .collect();

    if std::env::var("UPDATE_PLUGIN_VECTORS").is_ok() {
        let body: Vec<String> = current
            .iter()
            .map(|(name, hex)| {
                format!("    {{ \"message\": \"{name}\", \"protobuf_hex\": \"{hex}\" }}")
            })
            .collect();
        std::fs::write(
            &path,
            format!(
                "{{\n  \"revision\": 1,\n  \"note\": \"Encoded bytes of the plugin wire model. Regenerate with UPDATE_PLUGIN_VECTORS=1 and review the diff.\",\n  \"vectors\": [\n{}\n  ]\n}}\n",
                body.join(",\n")
            ),
        )
        .expect("write vectors");
        return;
    }

    let recorded = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let parsed: serde_json::Value = serde_json::from_str(&recorded).expect("parse vectors");
    let entries = parsed["vectors"].as_array().expect("vectors array");
    assert_eq!(
        entries.len(),
        current.len(),
        "the vector file covers a different number of messages than the schema does"
    );

    for (entry, (name, hex)) in entries.iter().zip(current.iter()) {
        assert_eq!(entry["message"].as_str(), Some(name.as_str()));
        let recorded_hex = entry["protobuf_hex"].as_str().expect("hex");
        assert_eq!(
            recorded_hex, hex,
            "{name} encodes differently than the recorded vector; a field was \
             renumbered or retyped, and every peer would misread it"
        );

        // The recorded bytes must decode as the message they claim to be and
        // re-encode to themselves, so a vector cannot describe something this
        // schema cannot round-trip.
        let bytes = decode_hex(recorded_hex);
        let reencoded = match entry["message"].as_str().expect("message name") {
            "HandshakeRequest" => v1::HandshakeRequest::decode(bytes.as_slice())
                .expect("decode HandshakeRequest")
                .encode_to_vec(),
            "LoadRequest" => v1::LoadRequest::decode(bytes.as_slice())
                .expect("decode LoadRequest")
                .encode_to_vec(),
            "LoadResponse" => v1::LoadResponse::decode(bytes.as_slice())
                .expect("decode LoadResponse")
                .encode_to_vec(),
            "PluginFailure" => v1::PluginFailure::decode(bytes.as_slice())
                .expect("decode PluginFailure")
                .encode_to_vec(),
            "InvokeOutcome" => v1::InvokeOutcome::decode(bytes.as_slice())
                .expect("decode InvokeOutcome")
                .encode_to_vec(),
            "HandshakeOutcome" => v1::HandshakeOutcome::decode(bytes.as_slice())
                .expect("decode HandshakeOutcome")
                .encode_to_vec(),
            "LoadOutcome" => v1::LoadOutcome::decode(bytes.as_slice())
                .expect("decode LoadOutcome")
                .encode_to_vec(),
            "UnloadOutcome" => v1::UnloadOutcome::decode(bytes.as_slice())
                .expect("decode UnloadOutcome")
                .encode_to_vec(),
            "InspectOutcome" => v1::InspectOutcome::decode(bytes.as_slice())
                .expect("decode InspectOutcome")
                .encode_to_vec(),
            "CancelOperationOutcome" => v1::CancelOperationOutcome::decode(bytes.as_slice())
                .expect("decode CancelOperationOutcome")
                .encode_to_vec(),
            "HealthOutcome" => v1::HealthOutcome::decode(bytes.as_slice())
                .expect("decode HealthOutcome")
                .encode_to_vec(),
            "PluginSessionMessage" => v1::PluginSessionMessage::decode(bytes.as_slice())
                .expect("decode PluginSessionMessage")
                .encode_to_vec(),
            "ContinuationRequest" => v1::ContinuationRequest::decode(bytes.as_slice())
                .expect("decode ContinuationRequest")
                .encode_to_vec(),
            "ContinuationOutcome" => v1::ContinuationOutcome::decode(bytes.as_slice())
                .expect("decode ContinuationOutcome")
                .encode_to_vec(),
            "EmitMarkRequest" => v1::EmitMarkRequest::decode(bytes.as_slice())
                .expect("decode EmitMarkRequest")
                .encode_to_vec(),
            "ScopeStackRequest" => v1::ScopeStackRequest::decode(bytes.as_slice())
                .expect("decode ScopeStackRequest")
                .encode_to_vec(),
            "ResolveCodecRequest" => v1::ResolveCodecRequest::decode(bytes.as_slice())
                .expect("decode ResolveCodecRequest")
                .encode_to_vec(),
            "ContinuationChunk" => v1::ContinuationChunk::decode(bytes.as_slice())
                .expect("decode ContinuationChunk")
                .encode_to_vec(),
            "ContinuationChunkDisposition" => {
                v1::ContinuationChunkDisposition::decode(bytes.as_slice())
                    .expect("decode ContinuationChunkDisposition")
                    .encode_to_vec()
            }
            "UnloadRequest" => v1::UnloadRequest::decode(bytes.as_slice())
                .expect("decode UnloadRequest")
                .encode_to_vec(),
            "UnloadResponse" => v1::UnloadResponse::decode(bytes.as_slice())
                .expect("decode UnloadResponse")
                .encode_to_vec(),
            "InspectRequest" => v1::InspectRequest::decode(bytes.as_slice())
                .expect("decode InspectRequest")
                .encode_to_vec(),
            "ActivateRequest" => v1::ActivateRequest::decode(bytes.as_slice())
                .expect("decode ActivateRequest")
                .encode_to_vec(),
            "ActivateOutcome" => v1::ActivateOutcome::decode(bytes.as_slice())
                .expect("decode ActivateOutcome")
                .encode_to_vec(),
            "InvokeRequest" => v1::InvokeRequest::decode(bytes.as_slice())
                .expect("decode InvokeRequest")
                .encode_to_vec(),
            "StreamChunk" => v1::StreamChunk::decode(bytes.as_slice())
                .expect("decode StreamChunk")
                .encode_to_vec(),
            "CancelOperationRequest" => v1::CancelOperationRequest::decode(bytes.as_slice())
                .expect("decode CancelOperationRequest")
                .encode_to_vec(),
            "CancelOperationResponse" => v1::CancelOperationResponse::decode(bytes.as_slice())
                .expect("decode CancelOperationResponse")
                .encode_to_vec(),
            "HealthRequest" => v1::HealthRequest::decode(bytes.as_slice())
                .expect("decode HealthRequest")
                .encode_to_vec(),
            "SessionCloseRequest" => v1::SessionCloseRequest::decode(bytes.as_slice())
                .expect("decode SessionCloseRequest")
                .encode_to_vec(),
            "SessionCloseResponse" => v1::SessionCloseResponse::decode(bytes.as_slice())
                .expect("decode SessionCloseResponse")
                .encode_to_vec(),
            "SessionCloseOutcome" => v1::SessionCloseOutcome::decode(bytes.as_slice())
                .expect("decode SessionCloseOutcome")
                .encode_to_vec(),
            "EmitMarkResponse" => v1::EmitMarkResponse::decode(bytes.as_slice())
                .expect("decode EmitMarkResponse")
                .encode_to_vec(),
            "ScopeStackResponse" => v1::ScopeStackResponse::decode(bytes.as_slice())
                .expect("decode ScopeStackResponse")
                .encode_to_vec(),
            "ResolveCodecResponse" => v1::ResolveCodecResponse::decode(bytes.as_slice())
                .expect("decode ResolveCodecResponse")
                .encode_to_vec(),
            other => panic!("no decoder for recorded vector {other}"),
        };
        assert_eq!(reencoded, bytes, "{name} does not round-trip");
    }
}
