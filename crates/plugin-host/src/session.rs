// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The kernel's view of one plugin session.
//!
//! The conversions refuse a message that cannot mean what it says. The
//! invariants that need *memory* are here: whether a completion was ever
//! expected, whether it has already been settled or cancelled, whether a stream
//! is open, terminal or released, whether a pull is outstanding, and whether the
//! chunk a disposition answers is the chunk that was actually sent. None of
//! those can be decided from one message, and a boundary that ignored them would
//! let a hostile or confused peer replay, reorder or invent.
//!
//! This is deliberately not a transport and not a driver: it takes the domain
//! messages the conversions produced and answers whether they fit the session,
//! so the supervisor that owns the socket and the callbacks can stay about the
//! socket and the callbacks.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use nemo_relay_plugin_protocol::{
    PluginCompletionCancelled, PluginCompletionOutcome, PluginCompletionSettlement,
    PluginContinuationChunk, PluginContinuationDisposition, PluginContinuationRequest,
    PluginFailure, PluginFailureCode, PluginProtocolError, PluginStreamControl, PluginStreamEnd,
    PluginStreamFailed, PluginStreamItem, PluginStreamOpenFailed, PluginStreamOpenRequest,
    PluginStreamOpened, PluginStreamPullRequest,
};

/// A protocol violation the session remembers enough to refuse.
fn rejected(message: impl Into<String>) -> PluginProtocolError {
    PluginProtocolError::new(PluginFailureCode::Rejected, message)
}

/// What the kernel knows about one stream it opened.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StreamState {
    /// The kernel is producing and the plugin may pull.
    Open,
    /// The plugin cancelled it; no further items are produced.
    Cancelled,
    /// The stream ended or failed.
    Terminal,
}

/// What the kernel knows about one stream.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stream {
    operation_request_id: String,
    state: StreamState,
    /// The pull the kernel owes an answer to, if any.
    outstanding_pull: Option<String>,
}

/// What the kernel knows about one completion it is waiting on.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CompletionState {
    /// The callback returned without a result; a settlement is expected.
    Pending,
    /// The awaiting runtime cancelled it; a settlement must be refused.
    Cancelled,
    /// It settled; a second settlement must be refused.
    Settled,
}

/// One completion, with the operation it belongs to.
///
/// The operation is kept so the session can forget everything an operation
/// owned when it finishes; without it, a long-lived session would accumulate a
/// settlement record for every callback it ever dispatched.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Completion {
    operation_request_id: String,
    state: CompletionState,
}

/// What the kernel knows about one continuation it is producing for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Continuation {
    operation_request_id: String,
    /// The next chunk's one-based sequence.
    next_sequence: u64,
    /// The chunk sent and not yet answered.
    awaiting_disposition: Option<u64>,
}

/// The kernel's view of one session.
///
/// Every method is one direction of one message: the `received_*` methods
/// validate what the plugin sent, and the `sent_*` methods record what the
/// kernel sent, because a message can only be judged against what came before
/// it.
#[derive(Debug, Default)]
pub struct PluginSessionState {
    session_id: String,
    streams: BTreeMap<String, Stream>,
    /// Stream opens the kernel owes an answer to, by call identity.
    pending_opens: BTreeMap<String, String>,
    completions: BTreeMap<String, Completion>,
    continuations: BTreeMap<String, Continuation>,
    /// Call identities that are outstanding right now. An identity is the
    /// correlation for exactly one call at a time; reusing one while it is still
    /// outstanding is how an answer gets applied to the wrong call.
    outstanding_calls: BTreeSet<String>,
}

impl PluginSessionState {
    /// Start tracking a session.
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            ..Self::default()
        }
    }

    /// The session this state belongs to.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Whether the session still holds anything.
    ///
    /// A session with nothing outstanding holds no state a supervisor has to
    /// carry across a restart.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
            && self.pending_opens.is_empty()
            && self.completions.is_empty()
            && self.continuations.is_empty()
    }

    /// Record that the kernel expects a completion.
    ///
    /// The kernel creates the identity, so a settlement can only ever name one
    /// it made: a peer that invents an identity is refused rather than believed.
    pub fn expect_completion(
        &mut self,
        completion_id: &str,
        operation_request_id: &str,
    ) -> Result<(), PluginProtocolError> {
        if completion_id.trim().is_empty() || operation_request_id.trim().is_empty() {
            return Err(rejected("a completion needs an identity and an operation"));
        }
        match self.completions.get(completion_id) {
            Some(_) => Err(rejected(format!(
                "completion {completion_id} was already expected"
            ))),
            None => {
                self.completions.insert(
                    completion_id.to_owned(),
                    Completion {
                        operation_request_id: operation_request_id.to_owned(),
                        state: CompletionState::Pending,
                    },
                );
                Ok(())
            }
        }
    }

    /// Record that the kernel cancelled a completion.
    pub fn cancel_completion(
        &mut self,
        cancelled: &PluginCompletionCancelled,
    ) -> Result<(), PluginProtocolError> {
        let completion = self
            .completions
            .get_mut(&cancelled.completion_id)
            .ok_or_else(|| {
                rejected(format!(
                    "completion {} was never expected",
                    cancelled.completion_id
                ))
            })?;
        match completion.state {
            CompletionState::Pending => {
                completion.state = CompletionState::Cancelled;
                Ok(())
            }
            CompletionState::Cancelled => Err(rejected(format!(
                "completion {} was already cancelled",
                cancelled.completion_id
            ))),
            CompletionState::Settled => Err(rejected(format!(
                "completion {} settled before it could be cancelled",
                cancelled.completion_id
            ))),
        }
    }

    /// Validate a settlement, returning the answer the kernel owes the plugin.
    ///
    /// Infallible on purpose: a settlement that cannot be accepted is not a
    /// message the kernel failed to read, it is a settlement the plugin has to be
    /// told about, or its callback waits forever.
    pub fn settle(&mut self, settlement: &PluginCompletionSettlement) -> PluginCompletionOutcome {
        let refusal = match self.completions.get(&settlement.completion_id) {
            Some(Completion {
                state: CompletionState::Pending,
                ..
            }) => None,
            Some(Completion {
                state: CompletionState::Cancelled,
                ..
            }) => Some(PluginFailure {
                code: PluginFailureCode::Cancelled,
                message: format!(
                    "completion {} was cancelled before it settled",
                    settlement.completion_id
                ),
            }),
            Some(Completion {
                state: CompletionState::Settled,
                ..
            }) => Some(PluginFailure {
                code: PluginFailureCode::Rejected,
                message: format!(
                    "completion {} was already settled",
                    settlement.completion_id
                ),
            }),
            None => Some(PluginFailure {
                code: PluginFailureCode::Rejected,
                message: format!("completion {} was never expected", settlement.completion_id),
            }),
        };
        if refusal.is_none() {
            self.completions
                .get_mut(&settlement.completion_id)
                .expect("the completion was just found")
                .state = CompletionState::Settled;
        }
        PluginCompletionOutcome {
            completion_id: settlement.completion_id.clone(),
            result: match refusal {
                Some(failure) => Err(failure),
                None => Ok(()),
            },
        }
    }

    /// Record that the kernel started producing a continuation for an operation.
    pub fn start_continuation(
        &mut self,
        request: &PluginContinuationRequest,
    ) -> Result<(), PluginProtocolError> {
        self.claim_call(&request.host_call_id)?;
        self.continuations.insert(
            request.host_call_id.clone(),
            Continuation {
                operation_request_id: request.operation_request_id.clone(),
                next_sequence: 1,
                awaiting_disposition: None,
            },
        );
        Ok(())
    }

    /// Record the next chunk of a continuation.
    ///
    /// The kernel does not produce chunk N+1 until the disposition for N
    /// arrives, so sending while one is outstanding is refused here as well as
    /// refused by the plugin: the kernel enforcing its own rule is what keeps
    /// the sequence honest rather than merely observed.
    pub fn send_chunk(
        &mut self,
        chunk: &PluginContinuationChunk,
    ) -> Result<(), PluginProtocolError> {
        let continuation = self
            .continuations
            .get_mut(&chunk.host_call_id)
            .ok_or_else(|| rejected(format!("continuation {} is not open", chunk.host_call_id)))?;
        if let Some(awaiting) = continuation.awaiting_disposition {
            return Err(rejected(format!(
                "continuation {} is still waiting for the answer to chunk {awaiting}",
                chunk.host_call_id
            )));
        }
        if chunk.sequence != continuation.next_sequence {
            return Err(rejected(format!(
                "continuation {} is at sequence {}, not {}",
                chunk.host_call_id, continuation.next_sequence, chunk.sequence
            )));
        }
        continuation.awaiting_disposition = Some(chunk.sequence);
        continuation.next_sequence += 1;
        Ok(())
    }

    /// Validate the plugin's answer about a chunk.
    pub fn receive_chunk_disposition(
        &mut self,
        disposition: &PluginContinuationDisposition,
    ) -> Result<(), PluginProtocolError> {
        let continuation = self
            .continuations
            .get_mut(&disposition.host_call_id)
            .ok_or_else(|| {
                rejected(format!(
                    "continuation {} is not open",
                    disposition.host_call_id
                ))
            })?;
        match continuation.awaiting_disposition {
            // A replay, a regression and an answer to a chunk nobody sent are
            // one case: the answer does not name the chunk that is outstanding.
            Some(awaiting) if awaiting != disposition.sequence => Err(rejected(format!(
                "continuation {} answered chunk {}, but chunk {awaiting} is outstanding",
                disposition.host_call_id, disposition.sequence
            ))),
            Some(_) => {
                continuation.awaiting_disposition = None;
                Ok(())
            }
            None => Err(rejected(format!(
                "continuation {} answered chunk {} with nothing outstanding",
                disposition.host_call_id, disposition.sequence
            ))),
        }
    }

    /// Validate that the plugin asked to open a stream.
    pub fn receive_open_request(
        &mut self,
        request: &PluginStreamOpenRequest,
    ) -> Result<(), PluginProtocolError> {
        self.claim_call(&request.host_call_id)?;
        self.pending_opens.insert(
            request.host_call_id.clone(),
            request.operation_request_id.clone(),
        );
        Ok(())
    }

    /// Record that the kernel opened a stream in answer to a request.
    pub fn send_opened(&mut self, opened: &PluginStreamOpened) -> Result<(), PluginProtocolError> {
        let operation_request_id =
            self.pending_opens
                .remove(&opened.host_call_id)
                .ok_or_else(|| {
                    rejected(format!(
                        "no stream was requested by call {}",
                        opened.host_call_id
                    ))
                })?;
        if self.streams.contains_key(&opened.stream_id) {
            return Err(rejected(format!(
                "stream {} already exists in this session",
                opened.stream_id
            )));
        }
        self.outstanding_calls.remove(&opened.host_call_id);
        self.streams.insert(
            opened.stream_id.clone(),
            Stream {
                operation_request_id,
                state: StreamState::Open,
                outstanding_pull: None,
            },
        );
        Ok(())
    }

    /// Record that the kernel refused to open a stream.
    pub fn send_open_failed(
        &mut self,
        failed: &PluginStreamOpenFailed,
    ) -> Result<(), PluginProtocolError> {
        if self.pending_opens.remove(&failed.host_call_id).is_none() {
            return Err(rejected(format!(
                "no stream was requested by call {}",
                failed.host_call_id
            )));
        }
        self.outstanding_calls.remove(&failed.host_call_id);
        Ok(())
    }

    /// Validate a pull.
    ///
    /// One pull at a time, because the ABI allows one outstanding pull per
    /// stream and a second would make the next item's answer ambiguous.
    pub fn receive_pull(
        &mut self,
        pull: &PluginStreamPullRequest,
    ) -> Result<(), PluginProtocolError> {
        self.claim_call(&pull.host_call_id)?;
        let stream = self.streams.get_mut(&pull.stream_id).ok_or_else(|| {
            rejected(format!(
                "stream {} is not open in this session",
                pull.stream_id
            ))
        })?;
        match stream.state {
            StreamState::Open => {}
            StreamState::Cancelled => {
                return Err(rejected(format!("stream {} was cancelled", pull.stream_id)));
            }
            StreamState::Terminal => {
                return Err(rejected(format!("stream {} already ended", pull.stream_id)));
            }
        }
        if let Some(outstanding) = &stream.outstanding_pull {
            return Err(rejected(format!(
                "stream {} still owes an answer to call {outstanding}",
                pull.stream_id
            )));
        }
        stream.outstanding_pull = Some(pull.host_call_id.clone());
        Ok(())
    }

    /// Record an item the kernel produced.
    pub fn send_item(&mut self, item: &PluginStreamItem) -> Result<(), PluginProtocolError> {
        self.answer_pull(&item.stream_id, &item.host_call_id, false)
    }

    /// Record that the kernel ended a stream.
    pub fn send_end(&mut self, end: &PluginStreamEnd) -> Result<(), PluginProtocolError> {
        self.answer_pull(&end.stream_id, &end.host_call_id, true)
    }

    /// Record that the kernel failed a stream.
    pub fn send_stream_failed(
        &mut self,
        failed: &PluginStreamFailed,
    ) -> Result<(), PluginProtocolError> {
        self.answer_pull(&failed.stream_id, &failed.host_call_id, true)
    }

    /// Validate that the plugin cancelled a stream.
    pub fn receive_cancel(
        &mut self,
        cancel: &PluginStreamControl,
    ) -> Result<(), PluginProtocolError> {
        let stream = self.streams.get_mut(&cancel.stream_id).ok_or_else(|| {
            rejected(format!(
                "stream {} is not open in this session",
                cancel.stream_id
            ))
        })?;
        match stream.state {
            StreamState::Open => {
                stream.state = StreamState::Cancelled;
                // The pull in flight is answered by the cancellation, not by an
                // item: the kernel produces nothing more for this stream.
                stream.outstanding_pull = None;
                Ok(())
            }
            StreamState::Cancelled => Err(rejected(format!(
                "stream {} was already cancelled",
                cancel.stream_id
            ))),
            StreamState::Terminal => Err(rejected(format!(
                "stream {} already ended",
                cancel.stream_id
            ))),
        }
    }

    /// Validate that the plugin released a stream.
    ///
    /// A released stream is forgotten here, and a later pull, item or
    /// cancellation naming it is refused as one naming no stream, because it is.
    pub fn receive_release(
        &mut self,
        release: &PluginStreamControl,
    ) -> Result<(), PluginProtocolError> {
        match self.streams.remove(&release.stream_id) {
            Some(stream) => {
                if let Some(outstanding) = stream.outstanding_pull {
                    self.outstanding_calls.remove(&outstanding);
                }
                Ok(())
            }
            None => Err(rejected(format!(
                "stream {} is not open in this session",
                release.stream_id
            ))),
        }
    }

    /// Forget everything belonging to an operation that has finished.
    ///
    /// A session outlives the operations that use it, so without this the state
    /// would grow for the life of the session.
    pub fn forget_operation(&mut self, operation_request_id: &str) {
        self.streams.retain(|_, stream| {
            if stream.operation_request_id == operation_request_id {
                if let Some(outstanding) = &stream.outstanding_pull {
                    self.outstanding_calls.remove(outstanding);
                }
                false
            } else {
                true
            }
        });
        self.continuations
            .retain(|_, continuation| continuation.operation_request_id != operation_request_id);
        self.completions
            .retain(|_, completion| completion.operation_request_id != operation_request_id);
    }

    /// Record that the kernel answered a pull.
    fn answer_pull(
        &mut self,
        stream_id: &str,
        host_call_id: &str,
        terminal: bool,
    ) -> Result<(), PluginProtocolError> {
        let stream = self
            .streams
            .get_mut(stream_id)
            .ok_or_else(|| rejected(format!("stream {stream_id} is not open in this session")))?;
        match &stream.outstanding_pull {
            Some(outstanding) if outstanding == host_call_id => {
                stream.outstanding_pull = None;
                if terminal {
                    stream.state = StreamState::Terminal;
                }
                self.outstanding_calls.remove(host_call_id);
                Ok(())
            }
            Some(outstanding) => Err(rejected(format!(
                "stream {stream_id} owes its answer to call {outstanding}, not {host_call_id}"
            ))),
            None => Err(rejected(format!(
                "stream {stream_id} has no pull outstanding for call {host_call_id}"
            ))),
        }
    }

    /// Claim a call identity for the duration of one call.
    fn claim_call(&mut self, host_call_id: &str) -> Result<(), PluginProtocolError> {
        if host_call_id.trim().is_empty() {
            return Err(rejected("a call needs an identity"));
        }
        if self.outstanding_calls.contains(host_call_id) {
            return Err(rejected(format!(
                "call {host_call_id} is already outstanding"
            )));
        }
        self.outstanding_calls.insert(host_call_id.to_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_failure() -> PluginFailure {
        PluginFailure {
            code: PluginFailureCode::Unavailable,
            message: "the provider refused".into(),
        }
    }

    fn session_with_stream() -> PluginSessionState {
        let mut session = PluginSessionState::new("session-1");
        session
            .receive_open_request(&PluginStreamOpenRequest {
                host_call_id: "open-1".into(),
                operation_request_id: "operation-1".into(),
                request_json: r#"{"model":"example"}"#.into(),
            })
            .expect("an open request");
        session
            .send_opened(&PluginStreamOpened {
                host_call_id: "open-1".into(),
                stream_id: "stream-1".into(),
            })
            .expect("an opened stream");
        session
    }

    fn pull(session: &mut PluginSessionState, call: &str) {
        session
            .receive_pull(&PluginStreamPullRequest {
                host_call_id: call.into(),
                stream_id: "stream-1".into(),
            })
            .expect("a pull");
    }

    #[test]
    fn a_pull_is_answered_once_and_only_by_the_call_that_made_it() {
        let mut session = session_with_stream();
        pull(&mut session, "pull-1");

        // An item answering a different call cannot be applied to the pull that
        // is outstanding.
        assert!(
            session
                .send_item(&PluginStreamItem {
                    host_call_id: "pull-2".into(),
                    stream_id: "stream-1".into(),
                    chunk_json: r#"{"delta":"hi"}"#.into(),
                })
                .is_err()
        );

        session
            .send_item(&PluginStreamItem {
                host_call_id: "pull-1".into(),
                stream_id: "stream-1".into(),
                chunk_json: r#"{"delta":"hi"}"#.into(),
            })
            .expect("the item the pull asked for");

        // And the same call cannot be answered twice.
        assert!(
            session
                .send_item(&PluginStreamItem {
                    host_call_id: "pull-1".into(),
                    stream_id: "stream-1".into(),
                    chunk_json: r#"{"delta":"again"}"#.into(),
                })
                .is_err()
        );
    }

    #[test]
    fn a_second_pull_while_one_is_outstanding_is_refused() {
        let mut session = session_with_stream();
        pull(&mut session, "pull-1");

        // Two outstanding pulls would make the next item's answer ambiguous.
        let error = session
            .receive_pull(&PluginStreamPullRequest {
                host_call_id: "pull-2".into(),
                stream_id: "stream-1".into(),
            })
            .expect_err("a second pull");
        assert_eq!(error.failure.code, PluginFailureCode::Rejected);

        // A pull for a stream that was never opened is refused as such.
        assert!(
            session
                .receive_pull(&PluginStreamPullRequest {
                    host_call_id: "pull-3".into(),
                    stream_id: "stream-2".into(),
                })
                .is_err()
        );
    }

    #[test]
    fn an_item_after_the_terminal_frame_is_refused() {
        let mut session = session_with_stream();
        pull(&mut session, "pull-1");
        session
            .send_end(&PluginStreamEnd {
                host_call_id: "pull-1".into(),
                stream_id: "stream-1".into(),
            })
            .expect("an end");

        assert!(
            session
                .send_item(&PluginStreamItem {
                    host_call_id: "pull-1".into(),
                    stream_id: "stream-1".into(),
                    chunk_json: r#"{"delta":"late"}"#.into(),
                })
                .is_err()
        );
        // And a pull after the terminal frame is refused rather than answered
        // with nothing.
        assert!(
            session
                .receive_pull(&PluginStreamPullRequest {
                    host_call_id: "pull-2".into(),
                    stream_id: "stream-1".into(),
                })
                .is_err()
        );
    }

    #[test]
    fn a_released_stream_is_gone() {
        let mut session = session_with_stream();
        session
            .receive_release(&PluginStreamControl {
                host_call_id: "release-1".into(),
                stream_id: "stream-1".into(),
            })
            .expect("a release");

        // Released twice is a message about a stream this session does not have.
        assert!(
            session
                .receive_release(&PluginStreamControl {
                    host_call_id: "release-2".into(),
                    stream_id: "stream-1".into(),
                })
                .is_err()
        );
        assert!(
            session
                .receive_pull(&PluginStreamPullRequest {
                    host_call_id: "pull-1".into(),
                    stream_id: "stream-1".into(),
                })
                .is_err()
        );
    }

    #[test]
    fn a_cancelled_stream_produces_nothing_more() {
        let mut session = session_with_stream();
        pull(&mut session, "pull-1");
        session
            .receive_cancel(&PluginStreamControl {
                host_call_id: "cancel-1".into(),
                stream_id: "stream-1".into(),
            })
            .expect("a cancellation");

        // The pull in flight is gone with the cancellation: an item answering it
        // would be an item for a stream the plugin stopped consuming.
        assert!(
            session
                .send_item(&PluginStreamItem {
                    host_call_id: "pull-1".into(),
                    stream_id: "stream-1".into(),
                    chunk_json: r#"{"delta":"hi"}"#.into(),
                })
                .is_err()
        );
        assert!(
            session
                .receive_cancel(&PluginStreamControl {
                    host_call_id: "cancel-2".into(),
                    stream_id: "stream-1".into(),
                })
                .is_err()
        );
    }

    #[test]
    fn a_completion_settles_once_and_after_cancellation_never() {
        let mut session = PluginSessionState::new("session-1");
        session
            .expect_completion("completion-1", "operation-1")
            .expect("an expected completion");
        session
            .expect_completion("completion-2", "operation-1")
            .expect("a second completion");

        // A completion nobody expected cannot be settled: the identity is the
        // kernel's to create, so a settlement naming one it never made is
        // refused rather than believed.
        let invented = session.settle(&PluginCompletionSettlement {
            completion_id: "completion-3".into(),
            operation_request_id: "operation-1".into(),
            result: Ok(r#"{"ok":true}"#.into()),
        });
        assert!(invented.result.is_err());

        let accepted = session.settle(&PluginCompletionSettlement {
            completion_id: "completion-1".into(),
            operation_request_id: "operation-1".into(),
            result: Ok(r#"{"ok":true}"#.into()),
        });
        assert_eq!(accepted.result, Ok(()));

        let twice = session.settle(&PluginCompletionSettlement {
            completion_id: "completion-1".into(),
            operation_request_id: "operation-1".into(),
            result: Ok(r#"{"second":true}"#.into()),
        });
        assert_eq!(
            twice.result.expect_err("a second settlement").code,
            PluginFailureCode::Rejected
        );

        session
            .cancel_completion(&PluginCompletionCancelled {
                completion_id: "completion-2".into(),
            })
            .expect("a cancellation");
        let after_cancel = session.settle(&PluginCompletionSettlement {
            completion_id: "completion-2".into(),
            operation_request_id: "operation-1".into(),
            result: Err(client_failure()),
        });
        assert_eq!(
            after_cancel
                .result
                .expect_err("a cancelled completion")
                .code,
            PluginFailureCode::Cancelled
        );
    }

    #[test]
    fn a_chunk_is_answered_before_the_next_is_produced() {
        let mut session = PluginSessionState::new("session-1");
        session
            .start_continuation(&PluginContinuationRequest {
                operation_request_id: "operation-1".into(),
                host_call_id: "continue-1".into(),
                invocation_json: r#"{"input":true}"#.into(),
            })
            .expect("a continuation");

        session
            .send_chunk(&PluginContinuationChunk {
                host_call_id: "continue-1".into(),
                sequence: 1,
                chunk_json: r#"{"delta":"a"}"#.into(),
            })
            .expect("the first chunk");

        // Chunk two before the answer to chunk one would leave the plugin's
        // decision applying to whichever chunk arrived last.
        assert!(
            session
                .send_chunk(&PluginContinuationChunk {
                    host_call_id: "continue-1".into(),
                    sequence: 2,
                    chunk_json: r#"{"delta":"b"}"#.into(),
                })
                .is_err()
        );

        // A disposition for a chunk nobody sent is refused, which covers a
        // replay and a regression in one rule.
        assert!(
            session
                .receive_chunk_disposition(&PluginContinuationDisposition {
                    host_call_id: "continue-1".into(),
                    sequence: 3,
                    disposition: Ok(nemo_relay_plugin_protocol::PluginChunkDecision::Continue),
                })
                .is_err()
        );

        session
            .receive_chunk_disposition(&PluginContinuationDisposition {
                host_call_id: "continue-1".into(),
                sequence: 1,
                disposition: Ok(nemo_relay_plugin_protocol::PluginChunkDecision::Stop),
            })
            .expect("the answer to chunk one");

        // The answer to chunk one does not authorise chunk three.
        assert!(
            session
                .send_chunk(&PluginContinuationChunk {
                    host_call_id: "continue-1".into(),
                    sequence: 3,
                    chunk_json: r#"{"delta":"c"}"#.into(),
                })
                .is_err()
        );
        session
            .send_chunk(&PluginContinuationChunk {
                host_call_id: "continue-1".into(),
                sequence: 2,
                chunk_json: r#"{"delta":"b"}"#.into(),
            })
            .expect("the second chunk");
    }

    #[test]
    fn a_call_identity_cannot_be_outstanding_twice() {
        let mut session = session_with_stream();
        pull(&mut session, "pull-1");

        // The same identity for a second call while the first is outstanding is
        // how an answer gets applied to the wrong call.
        assert!(
            session
                .receive_open_request(&PluginStreamOpenRequest {
                    host_call_id: "pull-1".into(),
                    operation_request_id: "operation-2".into(),
                    request_json: r#"{"model":"example"}"#.into(),
                })
                .is_err()
        );
    }

    #[test]
    fn an_operation_that_finished_leaves_nothing_behind() {
        let mut session = session_with_stream();
        pull(&mut session, "pull-1");
        session
            .start_continuation(&PluginContinuationRequest {
                operation_request_id: "operation-1".into(),
                host_call_id: "continue-1".into(),
                invocation_json: "{}".into(),
            })
            .expect("a continuation");
        session
            .expect_completion("completion-1", "operation-1")
            .expect("a completion");
        let leftover_completion = session.settle(&PluginCompletionSettlement {
            completion_id: "completion-1".into(),
            operation_request_id: "operation-1".into(),
            result: Ok("{}".into()),
        });
        assert_eq!(leftover_completion.result, Ok(()));

        session.forget_operation("operation-1");

        assert!(session.is_empty());
        // The identity it was holding is free again, which is what keeps a
        // long-lived session from refusing every later call identity it ever
        // saw.
        session
            .receive_open_request(&PluginStreamOpenRequest {
                host_call_id: "pull-1".into(),
                operation_request_id: "operation-2".into(),
                request_json: "{}".into(),
            })
            .expect("the identity is free");
    }
}
