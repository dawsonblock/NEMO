// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Codec capabilities: what a plugin may use, for how long, and for what.
//!
//! An LLM sanitizer decides with the call's codec, and a codec is a live object the
//! runtime holds — it cannot cross a process boundary, and a plugin that could name any
//! codec it liked would be choosing how the runtime reads a payload rather than being
//! told. So a plugin is given a *reference* for the one invocation that has a codec
//! active, and the work is done on the side that holds the object, against a record this
//! side keeps.
//!
//! Three properties make the reference a capability rather than a name:
//!
//! - **Invocation binding.** A reference issued for operation A is not usable by
//!   operation B, even when both calls use the same codec. A codec is per call; a
//!   capability that outlived its call would be a way to use one call's authority while
//!   making another.
//! - **Direction binding.** A request codec and a response codec are different traits,
//!   so a reference for one direction is not a weaker reference for the other.
//! - **Identity binding.** The capability records which codec it was issued for, and the
//!   plugin's own request has to agree with it. A plugin cannot resolve a capability
//!   issued for the built-in chat codec and use it as if it were a runtime-registered
//!   one.
//!
//! Lifetime is a guard, not a convention. Issuing returns a [`CodecCapabilityGuard`]
//! beside the reference; when the invocation ends the guard drops and the record is
//! gone. A reference used afterwards is not "expired" in any interesting sense — it is
//! unknown, because nothing remembers it, and remembering every reference this process
//! ever forgot would be a leak in exchange for a better error message.
//!
//! This mirrors the worker subsystem, which solved the same problem in the same shape
//! (`WorkerCodecCapability` and its guard, `codec-<uuid>` references, invocation and
//! direction checks) for the worker transport. The invariants are deliberately the same
//! ones; only the side that holds the object differs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use nemo_relay::codec::traits::{LlmCodec, LlmResponseCodec};
use nemo_relay_plugin_protocol::{CodecDirection, CodecRef, LlmCodecIdentity};

/// Why a codec reference was refused.
///
/// The variants are the cases a caller has to be able to tell apart when it decides
/// what to record, and they are deliberately not one "denied": a capability for another
/// call, a capability for the other direction, and a capability for another codec are
/// three different mistakes with three different fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecRefusal {
    /// Nothing this runtime issued answers to that reference: either it was never
    /// issued, or the invocation it belonged to has ended and the record is gone.
    Unknown,
    /// The reference belongs to another invocation.
    WrongOperation,
    /// The reference was issued for the other payload direction.
    WrongDirection,
    /// The reference was issued for a different *kind* of codec than the one asked for.
    WrongCodecKind,
    /// The reference was issued for another codec of the same kind.
    WrongCodecIdentity,
}

impl CodecRefusal {
    /// A short, stable name for records and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "codec_capability_unknown",
            Self::WrongOperation => "codec_capability_wrong_operation",
            Self::WrongDirection => "codec_capability_wrong_direction",
            Self::WrongCodecKind => "codec_capability_wrong_kind",
            Self::WrongCodecIdentity => "codec_capability_wrong_identity",
        }
    }
}

/// What one issued reference authorizes: the codec itself, and what it was issued for.
///
/// The object is held rather than named because the reference is only worth holding if
/// the side that validates it can also *use* it: the work happens here, against the codec
/// this record owns, so a plugin never needs the object and a reference is never a way to
/// name a codec this side would otherwise refuse to load.
struct IssuedCodec {
    operation: String,
    direction: CodecDirection,
    identity: LlmCodecIdentity,
    codec: CodecHandle,
}

/// The codec an issued capability authorizes.
///
/// The two directions are different traits on this side, and carrying the object in the
/// direction's own type is what makes "a request capability used as a response
/// capability" impossible to express rather than something to check for at the point of
/// use.
#[derive(Clone)]
pub enum CodecHandle {
    /// A codec that reads and writes the request an LLM call makes.
    Request(Arc<dyn LlmCodec>),
    /// A codec that reads the response an LLM call returned.
    Response(Arc<dyn LlmResponseCodec>),
}

impl CodecHandle {
    /// Which direction this handle belongs to.
    pub fn direction(&self) -> CodecDirection {
        match self {
            Self::Request(_) => CodecDirection::Request,
            Self::Response(_) => CodecDirection::Response,
        }
    }
}

impl std::fmt::Debug for CodecHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The codec is not printed: it is a live object holding provider state, and what a
        // reader needs from a log line is which direction it authorizes.
        formatter
            .debug_tuple("CodecHandle")
            .field(&self.direction())
            .finish()
    }
}

/// The references this runtime has issued and not yet taken back.
///
/// One store per boundary, because the record is process-wide: a reference issued by one
/// session must not be usable by another, and one map with the operation identity in each
/// entry is what makes that checkable without a second lookup.
#[derive(Default)]
pub struct CodecCapabilities {
    issued: Mutex<HashMap<String, IssuedCodec>>,
}

impl std::fmt::Debug for CodecCapabilities {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The references are not printed: what a reader of a log line needs is how many
        // capabilities are outstanding, and printing the record would put a usable
        // reference into the log.
        formatter
            .debug_struct("CodecCapabilities")
            .field("outstanding", &self.outstanding())
            .finish()
    }
}

impl CodecCapabilities {
    /// An empty record.
    pub fn new() -> Self {
        Self::default()
    }

    fn issued(&self) -> MutexGuard<'_, HashMap<String, IssuedCodec>> {
        self.issued.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Issue a request-capability for one invocation.
    ///
    /// The guard is the lifetime: hold it for exactly as long as the invocation can use
    /// the codec, and drop it when the invocation ends. Nothing else revokes.
    pub fn issue_request(
        self: &Arc<Self>,
        operation: impl Into<String>,
        codec: Arc<dyn LlmCodec>,
    ) -> (CodecRef, CodecCapabilityGuard) {
        self.issue(
            operation,
            CodecDirection::Request,
            codec.codec_identity(),
            CodecHandle::Request(codec),
        )
    }

    /// Issue a response-capability for one invocation.
    pub fn issue_response(
        self: &Arc<Self>,
        operation: impl Into<String>,
        codec: Arc<dyn LlmResponseCodec>,
    ) -> (CodecRef, CodecCapabilityGuard) {
        self.issue(
            operation,
            CodecDirection::Response,
            codec.codec_identity(),
            CodecHandle::Response(codec),
        )
    }

    fn issue(
        self: &Arc<Self>,
        operation: impl Into<String>,
        direction: CodecDirection,
        identity: LlmCodecIdentity,
        codec: CodecHandle,
    ) -> (CodecRef, CodecCapabilityGuard) {
        debug_assert_eq!(codec.direction(), direction);
        let reference = CodecRef::issue();
        self.issued().insert(
            reference.as_str().to_string(),
            IssuedCodec {
                operation: operation.into(),
                direction,
                identity,
                codec,
            },
        );
        (
            reference.clone(),
            CodecCapabilityGuard {
                store: Arc::clone(self),
                reference: reference.as_str().to_string(),
            },
        )
    }

    /// Check a reference a plugin asked to use.
    ///
    /// The checks are ordered cheapest-first and each one is a refusal rather than a
    /// fallback: an unknown reference is not "no codec", another invocation's reference
    /// is not "this invocation's", and a reference for another codec is not a request to
    /// use the one that was issued.
    ///
    /// # Errors
    /// Returns the [`CodecRefusal`] naming which check failed.
    pub fn resolve(
        &self,
        reference: &CodecRef,
        operation: &str,
        direction: CodecDirection,
        expected: &LlmCodecIdentity,
    ) -> Result<CodecHandle, CodecRefusal> {
        let issued = self.issued();
        let Some(capability) = issued.get(reference.as_str()) else {
            return Err(CodecRefusal::Unknown);
        };
        if capability.operation != operation {
            return Err(CodecRefusal::WrongOperation);
        }
        if capability.direction != direction {
            return Err(CodecRefusal::WrongDirection);
        }
        if !same_kind(&capability.identity, expected) {
            return Err(CodecRefusal::WrongCodecKind);
        }
        if capability.identity != *expected {
            return Err(CodecRefusal::WrongCodecIdentity);
        }
        Ok(capability.codec.clone())
    }

    /// Forget one reference.
    fn revoke(&self, reference: &str) {
        self.issued().remove(reference);
    }

    /// How many references are outstanding. For tests and diagnostics.
    pub fn outstanding(&self) -> usize {
        self.issued().len()
    }
}

/// Whether two identities describe the same *kind* of codec.
///
/// The split matters because the runtime's codec traits expose an identity and no
/// version: "you asked for a runtime-registered codec and this is a built-in one" and
/// "you asked for a different built-in codec" are the two mistakes a plugin can make,
/// and they are worth telling apart.
fn same_kind(left: &LlmCodecIdentity, right: &LlmCodecIdentity) -> bool {
    matches!(
        (left, right),
        (LlmCodecIdentity::None, LlmCodecIdentity::None)
            | (LlmCodecIdentity::Opaque, LlmCodecIdentity::Opaque)
            | (LlmCodecIdentity::BuiltIn(_), LlmCodecIdentity::BuiltIn(_))
            | (LlmCodecIdentity::Runtime(_), LlmCodecIdentity::Runtime(_))
    )
}

/// The lifetime of one issued capability.
///
/// Not a handle to the codec: a handle would be something to keep, and what this
/// invocation is allowed to keep is nothing. Dropping it is what ends the capability,
/// which is why every path out of an invocation — an answer, a refusal, a cancellation,
/// a panic that unwinds — ends it without anybody remembering to.
pub struct CodecCapabilityGuard {
    store: Arc<CodecCapabilities>,
    reference: String,
}

impl CodecCapabilityGuard {
    /// The reference this guard keeps alive.
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

impl Drop for CodecCapabilityGuard {
    fn drop(&mut self) {
        self.store.revoke(&self.reference);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay::api::llm::LlmRequest;
    use nemo_relay::codec::request::AnnotatedLlmRequest;
    use nemo_relay::codec::response::AnnotatedLlmResponse;
    use nemo_relay::json::Json;
    use nemo_relay_plugin_protocol::BuiltinLlmCodec;

    /// A request codec that answers with a fixed identity, so a test can tell which codec
    /// a capability resolves to without a provider.
    struct TestCodec {
        identity: LlmCodecIdentity,
    }

    impl LlmCodec for TestCodec {
        fn codec_identity(&self) -> LlmCodecIdentity {
            self.identity.clone()
        }

        fn decode(&self, _request: &LlmRequest) -> nemo_relay::error::Result<AnnotatedLlmRequest> {
            Ok(AnnotatedLlmRequest::default())
        }

        fn encode(
            &self,
            _annotated: &AnnotatedLlmRequest,
            original: &LlmRequest,
        ) -> nemo_relay::error::Result<LlmRequest> {
            Ok(original.clone())
        }
    }

    /// The response direction's twin.
    struct TestResponseCodec {
        identity: LlmCodecIdentity,
    }

    impl LlmResponseCodec for TestResponseCodec {
        fn codec_identity(&self) -> LlmCodecIdentity {
            self.identity.clone()
        }

        fn decode_response(
            &self,
            _response: &Json,
        ) -> nemo_relay::error::Result<AnnotatedLlmResponse> {
            Ok(AnnotatedLlmResponse::default())
        }
    }

    fn request_codec(identity: LlmCodecIdentity) -> Arc<dyn LlmCodec> {
        Arc::new(TestCodec { identity })
    }

    fn response_codec(identity: LlmCodecIdentity) -> Arc<dyn LlmResponseCodec> {
        Arc::new(TestResponseCodec { identity })
    }

    fn store() -> Arc<CodecCapabilities> {
        Arc::new(CodecCapabilities::new())
    }

    /// The case everything else is measured against: a reference issued for this
    /// invocation, this direction and this codec is the only one that resolves.
    #[test]
    fn a_capability_resolves_for_the_invocation_it_was_issued_to() {
        let store = store();
        let identity = LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat);
        let (reference, guard) =
            store.issue_request("operation-1", request_codec(identity.clone()));

        let resolved = store
            .resolve(
                &reference,
                "operation-1",
                CodecDirection::Request,
                &identity,
            )
            .expect("the capability it was issued for");
        assert_eq!(
            resolved.direction(),
            CodecDirection::Request,
            "and what it resolves to is the codec of that direction"
        );
        // And it is still the same capability a moment later: resolving is not using up.
        assert!(
            store
                .resolve(
                    &reference,
                    "operation-1",
                    CodecDirection::Request,
                    &identity
                )
                .is_ok()
        );
        assert_eq!(store.outstanding(), 1);
        drop(guard);
        assert_eq!(store.outstanding(), 0);
    }

    /// An unknown reference is refused, and so is one whose invocation has ended.
    ///
    /// The second is the same refusal on purpose: a reference the runtime has forgotten
    /// is not a reference it can act on, and keeping a list of everything it ever issued
    /// so it could say "expired" instead of "unknown" would be a leak in exchange for a
    /// better sentence.
    #[test]
    fn an_unknown_or_finished_capability_is_refused() {
        let store = store();
        let identity = LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat);

        let never_issued = CodecRef::issue();
        assert_eq!(
            store
                .resolve(
                    &never_issued,
                    "operation-1",
                    CodecDirection::Request,
                    &identity
                )
                .expect_err("nothing issued that"),
            CodecRefusal::Unknown
        );

        let (finished, guard) = store.issue_request("operation-1", request_codec(identity.clone()));
        assert!(
            store
                .resolve(&finished, "operation-1", CodecDirection::Request, &identity)
                .is_ok()
        );
        drop(guard);
        assert_eq!(
            store
                .resolve(&finished, "operation-1", CodecDirection::Request, &identity)
                .expect_err("the invocation is over"),
            CodecRefusal::Unknown,
            "a capability does not outlive the invocation that held it"
        );
    }

    /// The regression the whole design is for: another call's capability is not this
    /// call's, whether the other call has finished or is still running.
    #[test]
    fn one_calls_capability_is_refused_by_another_call() {
        let store = store();
        let identity = LlmCodecIdentity::Runtime("runtime-chat".into());
        let (capability_a, guard_a) =
            store.issue_request("operation-a", request_codec(identity.clone()));

        // Operation A has not finished, and B still cannot borrow its capability.
        assert_eq!(
            store
                .resolve(
                    &capability_a,
                    "operation-b",
                    CodecDirection::Request,
                    &identity
                )
                .expect_err("another call's capability"),
            CodecRefusal::WrongOperation
        );

        // A finishes; B starts and tries A's reference.
        drop(guard_a);
        assert_eq!(
            store
                .resolve(
                    &capability_a,
                    "operation-b",
                    CodecDirection::Request,
                    &identity
                )
                .expect_err("the call that held it is over"),
            CodecRefusal::Unknown
        );

        // Even handed the reference deliberately, B refuses it: this is the check that
        // makes it a capability rather than a token both calls can spend.
        let (capability_b, _guard_b) =
            store.issue_request("operation-b", request_codec(identity.clone()));
        assert!(
            store
                .resolve(
                    &capability_b,
                    "operation-b",
                    CodecDirection::Request,
                    &identity
                )
                .is_ok()
        );
        assert_ne!(capability_a, capability_b);
    }

    /// Two live calls, interleaved: each resolves its own and neither resolves the
    /// other's.
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_invocations_cannot_use_each_others_capabilities() {
        let store = store();
        let identity = LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::AnthropicMessages);
        let (capability_a, _guard_a) =
            store.issue_request("operation-a", request_codec(identity.clone()));
        let (capability_b, _guard_b) =
            store.issue_request("operation-b", request_codec(identity.clone()));

        let first = {
            let store = Arc::clone(&store);
            let identity = identity.clone();
            let capability_a = capability_a.clone();
            let capability_b = capability_b.clone();
            tokio::spawn(async move {
                assert!(
                    store
                        .resolve(
                            &capability_a,
                            "operation-a",
                            CodecDirection::Request,
                            &identity
                        )
                        .is_ok()
                );
                assert_eq!(
                    store
                        .resolve(
                            &capability_b,
                            "operation-a",
                            CodecDirection::Request,
                            &identity
                        )
                        .expect_err("B's capability in A's call"),
                    CodecRefusal::WrongOperation
                );
            })
        };
        let second = {
            let store = Arc::clone(&store);
            let identity = identity.clone();
            let capability_a = capability_a.clone();
            let capability_b = capability_b.clone();
            tokio::spawn(async move {
                assert!(
                    store
                        .resolve(
                            &capability_b,
                            "operation-b",
                            CodecDirection::Request,
                            &identity
                        )
                        .is_ok()
                );
                assert_eq!(
                    store
                        .resolve(
                            &capability_a,
                            "operation-b",
                            CodecDirection::Request,
                            &identity
                        )
                        .expect_err("A's capability in B's call"),
                    CodecRefusal::WrongOperation
                );
            })
        };
        first.await.expect("the first invocation");
        second.await.expect("the second invocation");
        assert_eq!(store.outstanding(), 2, "both calls are still in flight");
    }

    /// A reference for one payload direction is not a reference for the other.
    #[test]
    fn a_capability_is_bound_to_its_direction() {
        let store = store();
        let identity = LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiResponses);
        let (reference, _guard) =
            store.issue_response("operation-1", response_codec(identity.clone()));

        assert_eq!(
            store
                .resolve(
                    &reference,
                    "operation-1",
                    CodecDirection::Request,
                    &identity
                )
                .expect_err("a response capability"),
            CodecRefusal::WrongDirection
        );
        assert!(
            store
                .resolve(
                    &reference,
                    "operation-1",
                    CodecDirection::Response,
                    &identity
                )
                .is_ok()
        );
    }

    /// And it is bound to the codec it was issued for: another kind is one refusal,
    /// another codec of the same kind is another.
    #[test]
    fn a_capability_is_bound_to_the_codec_it_was_issued_for() {
        let store = store();
        let (reference, _guard) = store.issue_request(
            "operation-1",
            request_codec(LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat)),
        );

        assert_eq!(
            store
                .resolve(
                    &reference,
                    "operation-1",
                    CodecDirection::Request,
                    &LlmCodecIdentity::Runtime("runtime-chat".into())
                )
                .expect_err("a reference for a built-in is not one for a runtime codec"),
            CodecRefusal::WrongCodecKind
        );
        assert_eq!(
            store
                .resolve(
                    &reference,
                    "operation-1",
                    CodecDirection::Request,
                    &LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::AnthropicMessages)
                )
                .expect_err("a different codec of the same kind"),
            CodecRefusal::WrongCodecIdentity
        );
        assert!(
            store
                .resolve(
                    &reference,
                    "operation-1",
                    CodecDirection::Request,
                    &LlmCodecIdentity::BuiltIn(BuiltinLlmCodec::OpenAiChat)
                )
                .is_ok()
        );
    }

    /// Each guard takes back its own reference and nothing else.
    #[test]
    fn a_guard_revokes_only_its_own_capability() {
        let store = store();
        let identity = LlmCodecIdentity::Opaque;
        let (first, guard_first) =
            store.issue_request("operation-1", request_codec(identity.clone()));
        let (second, _guard_second) =
            store.issue_request("operation-2", request_codec(identity.clone()));

        drop(guard_first);
        assert_eq!(
            store
                .resolve(&first, "operation-1", CodecDirection::Request, &identity)
                .expect_err("the guard took it back"),
            CodecRefusal::Unknown
        );
        assert!(
            store
                .resolve(&second, "operation-2", CodecDirection::Request, &identity)
                .is_ok(),
            "the other call's capability is untouched"
        );
    }
}
