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
