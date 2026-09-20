// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The conversion-coverage manifest for the plugin-host boundary.
//!
//! Every message the host uses is listed with how it crosses, which converter
//! owns it, which vector records its bytes, and which tests refuse a malformed
//! version of it. The checks here fail when a message reaches a service
//! signature without an entry, when an entry names a converter or a test that
//! does not exist, when a vector is claimed but absent, and when a wire type
//! converts infallibly into a domain type.
//!
//! The point is not the table; it is that adding an RPC and forgetting to
//! harden its conversion path is a failing build rather than a finding in the
//! next audit.

use std::collections::BTreeSet;
use std::path::PathBuf;

struct Entry {
    /// The protobuf message.
    message: &'static str,
    /// Which ways it crosses.
    direction: &'static str,
    /// Whether trusted runtime logic consumes or builds the converted value.
    trusted: bool,
    /// Converter functions that own this message's crossing.
    converters: &'static [&'static str],
    /// Why it has no converter, when it has none.
    why_no_converter: &'static str,
    /// Golden vectors that record its bytes.
    golden: &'static [&'static str],
    /// Why it has no golden vector, when it has none.
    why_no_golden: &'static str,
    /// Tests that refuse a malformed version of it.
    negatives: &'static [&'static str],
    /// Why it has no negative test, when it has none.
    why_no_negatives: &'static str,
}

const fn entry(
    message: &'static str,
    direction: &'static str,
    converters: &'static [&'static str],
    golden: &'static [&'static str],
    negatives: &'static [&'static str],
) -> Entry {
    entry_with_reasons(
        message, direction, true, converters, "", golden, "", negatives, "",
    )
}

#[allow(clippy::too_many_arguments)]
const fn entry_with_reasons(
    message: &'static str,
    direction: &'static str,
    trusted: bool,
    converters: &'static [&'static str],
    why_no_converter: &'static str,
    golden: &'static [&'static str],
    why_no_golden: &'static str,
    negatives: &'static [&'static str],
    why_no_negatives: &'static str,
) -> Entry {
    Entry {
        message,
        direction,
        trusted,
        converters,
        why_no_converter,
        golden,
        why_no_golden,
        negatives,
        why_no_negatives,
    }
}

const MANIFEST: &[Entry] = &[
    entry(
        "HandshakeRequest",
        "wire->domain",
        &["handshake_request_from_wire"],
        &["HandshakeRequest"],
        &["a_handshake_carries_the_read_capabilities_it_asks_for_and_gets"],
    ),
    entry_with_reasons(
        "HandshakeResponse",
        "wire->domain",
        false,
        &["session_identity_from_wire"],
        "",
        &[],
        "the session it establishes is recorded by HandshakeOutcome, whose vector carries it",
        &["a_session_is_validated_rather_than_adopted"],
        "",
    ),
    entry(
        "HandshakeOutcome",
        "wire->domain",
        &["handshake_outcome_from_wire"],
        &["HandshakeOutcome"],
        &["an_outcome_with_neither_arm_is_malformed"],
    ),
    entry(
        "LoadRequest",
        "both",
        &["load_request_from_wire", "load_request_to_wire"],
        &["LoadRequest"],
        &["a_load_request_without_an_approved_identity_is_refused"],
    ),
    entry(
        "LoadResponse",
        "wire->domain",
        &["load_response_from_wire"],
        &["LoadResponse"],
        &[
            "a_load_response_whose_handle_and_descriptor_disagree_is_refused",
            "a_handle_at_generation_zero_is_refused",
            "a_load_response_without_a_descriptor_is_refused",
        ],
    ),
    entry(
        "LoadOutcome",
        "wire->domain",
        &["load_outcome_from_wire"],
        &["LoadOutcome"],
        &["a_success_arm_is_still_validated"],
    ),
    entry(
        "UnloadRequest",
        "wire->domain",
        &["unload_request_from_wire"],
        &["UnloadRequest"],
        &["a_handle_is_validated_when_a_request_names_one"],
    ),
    entry_with_reasons(
        "UnloadResponse",
        "wire->domain",
        false,
        &["unload_response_from_wire"],
        "",
        &["UnloadResponse"],
        "",
        &[],
        "an empty acknowledgement has no field to refuse",
    ),
    entry(
        "UnloadOutcome",
        "wire->domain",
        &["unload_outcome_from_wire"],
        &["UnloadOutcome"],
        &["an_outcome_with_neither_arm_is_malformed"],
    ),
    entry(
        "InspectRequest",
        "wire->domain",
        &["inspect_request_from_wire"],
        &["InspectRequest"],
        &["a_handle_is_validated_when_a_request_names_one"],
    ),
    entry(
        "InspectOutcome",
        "wire->domain",
        &["inspect_outcome_from_wire"],
        &["InspectOutcome"],
        &["an_outcome_with_neither_arm_is_malformed"],
    ),
    entry(
        "InvokeRequest",
        "wire->domain",
        &["invoke_request_from_wire"],
        &["InvokeRequest"],
        &["an_invocation_takes_its_budget_from_the_context"],
    ),
    entry(
        "InvokeOutcome",
        "both",
        &["execution_outcome_from_wire", "execution_outcome_to_wire"],
        &["InvokeOutcome"],
        &["an_outcome_keeps_the_dispatch_certainty_it_was_given"],
    ),
    entry(
        "StreamChunk",
        "wire->domain",
        &["stream_chunk_from_wire"],
        &["StreamChunk"],
        &["a_stream_frame_says_what_it_carries"],
    ),
    entry(
        "CancelOperationRequest",
        "wire->domain",
        &["cancel_operation_request_from_wire"],
        &["CancelOperationRequest"],
        &["a_cancellation_that_names_no_operation_is_refused"],
    ),
    entry_with_reasons(
        "CancelOperationResponse",
        "wire->domain",
        false,
        &["cancel_response_from_wire"],
        "",
        &["CancelOperationResponse"],
        "",
        &[],
        "an empty acknowledgement has no field to refuse",
    ),
    entry(
        "CancelOperationOutcome",
        "wire->domain",
        &["cancel_outcome_from_wire"],
        &["CancelOperationOutcome"],
        &["an_outcome_with_neither_arm_is_malformed"],
    ),
    entry(
        "HealthRequest",
        "wire->domain",
        &["operation_envelope_from_wire"],
        &["HealthRequest"],
        &["an_operation_envelope_is_validated_before_its_payload"],
    ),
    entry(
        "HealthOutcome",
        "wire->domain",
        &["health_outcome_from_wire"],
        &["HealthOutcome"],
        &[
            "an_outcome_with_neither_arm_is_malformed",
            "a_health_report_is_validated_like_the_load_it_describes",
        ],
    ),
    entry(
        "SessionCloseRequest",
        "wire->domain",
        &["operation_envelope_from_wire"],
        &["SessionCloseRequest"],
        &["an_operation_envelope_is_validated_before_its_payload"],
    ),
    entry_with_reasons(
        "SessionCloseResponse",
        "wire->domain",
        false,
        &[],
        "an empty acknowledgement has nothing to convert",
        &["SessionCloseResponse"],
        "",
        &[],
        "an empty acknowledgement has no field to refuse",
    ),
    entry(
        "EmitMarkRequest",
        "wire->domain",
        &["mark_request_from_wire"],
        &["EmitMarkRequest"],
        &["a_mark_that_cannot_mean_what_it_says_is_refused"],
    ),
    entry_with_reasons(
        "EmitMarkResponse",
        "wire->domain",
        false,
        &[],
        "an empty acknowledgement has nothing to convert",
        &["EmitMarkResponse"],
        "",
        &[],
        "an empty acknowledgement has no field to refuse",
    ),
    entry(
        "ScopeStackRequest",
        "wire->domain",
        &["scope_stack_request_from_wire"],
        &["ScopeStackRequest"],
        &["a_scope_or_codec_call_must_name_a_known_operation"],
    ),
    entry(
        "ScopeStackResponse",
        "wire->domain",
        &["scope_stack_response_from_wire"],
        &["ScopeStackResponse"],
        &["a_host_call_answer_is_an_answer_or_a_failure"],
    ),
    entry(
        "ResolveCodecRequest",
        "wire->domain",
        &["resolve_codec_request_from_wire"],
        &["ResolveCodecRequest"],
        &["a_scope_or_codec_call_must_name_a_known_operation"],
    ),
    entry(
        "ResolveCodecResponse",
        "wire->domain",
        &["resolve_codec_response_from_wire"],
        &["ResolveCodecResponse"],
        &["a_host_call_answer_is_an_answer_or_a_failure"],
    ),
    entry(
        "ContinuationRequest",
        "both",
        &[
            "continuation_request_from_wire",
            "continuation_request_to_wire",
        ],
        &["ContinuationRequest"],
        &["a_continuation_round_trips_and_refuses_to_carry_nothing"],
    ),
    entry(
        "ContinuationOutcome",
        "both",
        &[
            "continuation_outcome_from_wire",
            "continuation_outcome_to_wire",
        ],
        &["ContinuationOutcome"],
        &["a_continuation_round_trips_and_refuses_to_carry_nothing"],
    ),
    entry(
        "ContinuationChunk",
        "both",
        &["continuation_chunk_from_wire"],
        &["ContinuationChunk"],
        &["a_chunk_and_its_answer_carry_the_sequence_that_binds_them"],
    ),
    entry(
        "ContinuationChunkDisposition",
        "both",
        &["continuation_disposition_from_wire"],
        &["ContinuationChunkDisposition"],
        &["a_chunk_and_its_answer_carry_the_sequence_that_binds_them"],
    ),
    entry(
        "PluginSessionMessage",
        "both",
        &["session_message_from_wire", "session_message_to_wire"],
        &["PluginSessionMessage"],
        &["a_session_message_that_names_nothing_is_refused"],
    ),
    // The arms of the session envelope. They are converted by the envelope's
    // converters because that is what converts them, and listing them is what
    // makes a new arm visible here rather than only inside the match.
    entry_with_reasons(
        "DownstreamStreamOpenRequest",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["every_session_message_survives_the_wire"],
        "",
    ),
    entry_with_reasons(
        "DownstreamStreamOpened",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["every_session_message_survives_the_wire"],
        "",
    ),
    entry_with_reasons(
        "DownstreamStreamOpenFailed",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["every_session_message_survives_the_wire"],
        "",
    ),
    entry_with_reasons(
        "DownstreamStreamPullRequest",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["a_session_message_that_names_nothing_is_refused"],
        "",
    ),
    entry_with_reasons(
        "DownstreamStreamItem",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["a_session_message_that_names_nothing_is_refused"],
        "",
    ),
    entry_with_reasons(
        "DownstreamStreamEnd",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["a_session_message_that_names_nothing_is_refused"],
        "",
    ),
    entry_with_reasons(
        "DownstreamStreamFailed",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["every_session_message_survives_the_wire"],
        "",
    ),
    entry_with_reasons(
        "DownstreamStreamCancel",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["every_session_message_survives_the_wire"],
        "",
    ),
    entry_with_reasons(
        "DownstreamStreamRelease",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["every_session_message_survives_the_wire"],
        "",
    ),
    entry_with_reasons(
        "CompletionSettle",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["a_settlement_or_outcome_without_a_result_is_refused"],
        "",
    ),
    entry_with_reasons(
        "CompletionOutcome",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["a_settlement_or_outcome_without_a_result_is_refused"],
        "",
    ),
    entry_with_reasons(
        "CompletionCancelled",
        "both",
        true,
        &["session_message_from_wire", "session_message_to_wire"],
        "",
        &[],
        "carried inside the session envelope, whose vectors record it",
        &["every_session_message_survives_the_wire"],
        "",
    ),
];

fn manifest_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn proto_source() -> String {
    std::fs::read_to_string(manifest_path(
        "proto/nemo/relay/plugin/v1/plugin_host.proto",
    ))
    .expect("read the schema")
}

fn convert_source() -> String {
    std::fs::read_to_string(manifest_path("src/convert.rs")).expect("read the conversions")
}

/// Every message named in an `rpc` signature.
fn service_messages() -> BTreeSet<String> {
    let source = proto_source();
    let mut names = BTreeSet::new();
    for line in source.lines() {
        let line = line.trim();
        if !line.starts_with("rpc ") {
            continue;
        }
        for part in line.split(['(', ')']) {
            let candidate = part.trim().trim_start_matches("stream").trim();
            if candidate.starts_with(|c: char| c.is_ascii_uppercase()) && !candidate.contains(' ') {
                names.insert(candidate.to_owned());
            }
        }
    }
    names
}

/// Every message a oneof in `PluginSessionMessage` can carry.
fn session_messages() -> BTreeSet<String> {
    let source = proto_source();
    let mut names = BTreeSet::new();
    let mut inside = false;
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("message PluginSessionMessage") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if line.starts_with('}') {
            break;
        }
        if let Some((declaration, _)) = line.split_once('=') {
            let parts: Vec<&str> = declaration.split_whitespace().collect();
            if let Some(name) = parts.last() {
                let name = name.trim();
                if name.starts_with(|c: char| c.is_ascii_uppercase()) {
                    names.insert(name.to_owned());
                }
            }
        }
    }
    names
}

/// Every message the schema declares.
fn declared_messages() -> BTreeSet<String> {
    let source = proto_source();
    source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("message "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

fn recorded_vectors() -> BTreeSet<String> {
    let path = manifest_path("../../qualification/abi/plugin-v1/vectors.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("parse the vectors");
    parsed["vectors"]
        .as_array()
        .expect("a vectors array")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .map(str::to_owned)
        .collect()
}

#[test]
fn every_host_used_message_is_in_the_manifest() {
    let listed: BTreeSet<String> = MANIFEST
        .iter()
        .map(|entry| entry.message.to_owned())
        .collect();
    let mut expected = service_messages();
    expected.extend(session_messages());

    let missing: Vec<&String> = expected.difference(&listed).collect();
    assert!(
        missing.is_empty(),
        "these messages reach a service or the session without a conversion entry: {missing:?}"
    );

    // And the manifest cannot describe messages the schema does not have, which
    // is how a renamed or deleted message would otherwise leave a stale entry
    // behind.
    let declared = declared_messages();
    let unknown: Vec<&str> = listed
        .iter()
        .filter(|name| !declared.contains(*name))
        .map(String::as_str)
        .collect();
    assert!(
        unknown.is_empty(),
        "the manifest describes messages the schema does not declare: {unknown:?}"
    );
}

#[test]
fn every_manifest_entry_names_converters_and_tests_that_exist() {
    let source = convert_source();
    let mut problems = Vec::new();

    for entry in MANIFEST {
        if entry.converters.is_empty() && entry.why_no_converter.is_empty() {
            problems.push(format!(
                "{}: no converter and no reason given",
                entry.message
            ));
        }
        if !matches!(entry.direction, "wire->domain" | "domain->wire" | "both") {
            problems.push(format!(
                "{}: direction {} is not one this manifest defines",
                entry.message, entry.direction
            ));
        }
        for converter in entry.converters {
            let plain = format!("fn {converter}(");
            let public = format!("pub fn {converter}(");
            if !source.contains(&plain) {
                problems.push(format!(
                    "{}: converter {converter} does not exist",
                    entry.message
                ));
            } else if entry.trusted && !source.contains(&public) {
                problems.push(format!(
                    "{}: converter {converter} feeds trusted logic but is not public",
                    entry.message
                ));
            }
        }
        for test in entry.negatives {
            if !source.contains(&format!("fn {test}(")) {
                problems.push(format!(
                    "{}: negative test {test} does not exist",
                    entry.message
                ));
            }
        }
        if entry.negatives.is_empty() && entry.why_no_negatives.is_empty() {
            problems.push(format!(
                "{}: no negative test and no reason given",
                entry.message
            ));
        }
    }

    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn every_claimed_vector_is_recorded() {
    let recorded = recorded_vectors();
    let mut problems = Vec::new();

    for entry in MANIFEST {
        if entry.golden.is_empty() && entry.why_no_golden.is_empty() {
            // A message with no vector is a gap, and it has to be a stated one.
            problems.push(format!("{}: no vector and no reason given", entry.message));
        }
        for vector in entry.golden {
            if !recorded.contains(*vector) {
                problems.push(format!(
                    "{}: claims vector {vector}, which is not recorded",
                    entry.message
                ));
            }
        }
    }

    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn no_wire_type_converts_into_a_domain_type_infallibly() {
    // A wire type is not a domain type. Every crossing has to be fallible,
    // because protobuf's every-field-is-optional is not a domain property; an
    // `impl From<v1::…>` would compile into a shortcut that accepts states the
    // domain cannot mean.
    let source = convert_source();
    let offenders: Vec<&str> = source
        .lines()
        .filter(|line| line.contains("impl From<v1::"))
        .collect();
    assert!(
        offenders.is_empty(),
        "these conversions are infallible, so `.into()` would compile and skip validation: {offenders:?}"
    );
}
