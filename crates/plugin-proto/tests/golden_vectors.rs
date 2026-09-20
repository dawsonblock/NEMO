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

    vec![
        (
            "HandshakeRequest",
            v1::HandshakeRequest {
                protocol_version: 1,
                runtime_binding_digest: "runtime-binding-digest".into(),
                host_instance_id: "host-1".into(),
                session_nonce: "nonce-1".into(),
                maximum_frame_bytes: nemo_relay_plugin_proto::MAX_FRAME_BYTES,
                supported_features: vec!["streaming".into(), "cancel".into()],
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
            }
            .encode_to_vec(),
        ),
        (
            "LoadResponse",
            v1::LoadResponse {
                handle: Some(v1::PluginHandle {
                    plugin_id: "example".into(),
                    generation: 41,
                }),
                descriptor: Some(v1::PluginDescriptor {
                    plugin_id: "example".into(),
                    plugin_version: Some(">=0.9,<1.0".into()),
                    negotiated_abi_version: Some(4),
                    manifest_digest: Some("manifest-digest".into()),
                    registration_kinds: vec!["example_kind".into()],
                    capabilities: Vec::new(),
                }),
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
            other => panic!("no decoder for recorded vector {other}"),
        };
        assert_eq!(reencoded, bytes, "{name} does not round-trip");
    }
}
