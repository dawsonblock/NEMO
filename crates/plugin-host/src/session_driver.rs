// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The kernel's side of the duplex session.
//!
//! Most of what crosses this boundary is one request and one answer. A stream is
//! not: the plugin opens a downstream stream, pulls it one chunk at a time, and
//! may cancel or release it while a pull is outstanding — so its pace is the
//! plugin's, and the kernel's work behind it advances only when the plugin asks.
//! That is what the session channel carries, and this is what turns its messages
//! into the kernel's own actions.
//!
//! Two responsibilities, deliberately kept apart. `session.rs` decides what a
//! message may mean and when it may mean it — a pull for a stream that is not
//! open, a second pull while one is outstanding, a chunk answered twice. This
//! decides what the kernel *does*: call the provider chain the plugin is
//! wrapping, produce the next item, and stop producing when the plugin stops
//! asking. A driver that made its own decisions would be a second answer to the
//! same question, and the two would drift.
//!
//! What it does not do yet, and what the streaming increment still owes: a
//! cancellation that arrives while the kernel is producing is answered after the
//! pull it interrupted rather than instead of it, because the loop here reads and
//! answers one message at a time. Until that changes, an intercept that abandons
//! a slow downstream stream waits for the chunk it asked for. The class is not
//! served until the rest of the streaming path lands, so nothing depends on this
//! yet; the limitation is written down rather than implied.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::StreamExt;
use nemo_relay::api::llm::LlmRequest;
use nemo_relay::api::runtime::LlmJsonStream;
use nemo_relay_plugin_protocol::{
    PluginFailure, PluginFailureCode, PluginSessionMessage, PluginSessionPayload, PluginStreamEnd,
    PluginStreamFailed, PluginStreamItem, PluginStreamOpenFailed, PluginStreamOpenRequest,
    PluginStreamOpened, PluginStreamPullRequest,
};

use crate::continuations::{Continuations, ParkedChain};
use crate::session::PluginSessionState;

/// A stream this kernel is producing for the plugin to pull.
struct OpenStream {
    /// The operation the stream belongs to, so the kernel can say whose it is.
    operation_request_id: String,
    /// The stream the wrapped chain produced.
    stream: LlmJsonStream,
}

/// One session channel, driven.
pub struct SessionDriver {
    session_id: String,
    state: PluginSessionState,
    continuations: Arc<Continuations>,
    streams: HashMap<String, OpenStream>,
    /// Minted identities for the streams this kernel opens.
    opened: u64,
}

impl SessionDriver {
    /// Drive one session's channel.
    pub fn new(session_id: impl Into<String>, continuations: Arc<Continuations>) -> Self {
        let session_id = session_id.into();
        Self {
            state: PluginSessionState::new(session_id.clone()),
            session_id,
            continuations,
            streams: HashMap::new(),
            opened: 0,
        }
    }

    /// Handle one message, answering with what the kernel owes the plugin.
    ///
    /// `Err` is a protocol violation rather than a refusal the plugin can read:
    /// the state machine refused the message, which means the two sides no
    /// longer agree about this session, so the channel ends rather than
    /// continuing with one side's picture of it.
    pub async fn handle(
        &mut self,
        message: PluginSessionMessage,
    ) -> Result<Vec<PluginSessionMessage>, String> {
        let session_id = self.session_id.clone();
        let answering = move |payload: PluginSessionPayload| PluginSessionMessage {
            session_id: session_id.clone(),
            message: payload,
        };
        match message.message {
            PluginSessionPayload::StreamOpen(request) => {
                self.state
                    .receive_open_request(&request)
                    .map_err(|error| error.failure.message)?;
                match self.open(&request).await {
                    Ok(opened) => {
                        self.state
                            .send_opened(&opened)
                            .map_err(|error| error.failure.message)?;
                        Ok(vec![answering(PluginSessionPayload::StreamOpened(opened))])
                    }
                    Err(failure) => {
                        let failed = PluginStreamOpenFailed {
                            host_call_id: request.host_call_id.clone(),
                            failure,
                        };
                        self.state
                            .send_open_failed(&failed)
                            .map_err(|error| error.failure.message)?;
                        Ok(vec![answering(PluginSessionPayload::StreamOpenFailed(
                            failed,
                        ))])
                    }
                }
            }
            PluginSessionPayload::StreamPull(pull) => {
                self.state
                    .receive_pull(&pull)
                    .map_err(|error| error.failure.message)?;
                Ok(vec![answering(self.produce(&pull).await?)])
            }
            PluginSessionPayload::StreamCancel(control) => {
                self.state
                    .receive_cancel(&control)
                    .map_err(|error| error.failure.message)?;
                // The plugin stopped asking; the kernel stops producing. Nothing
                // is owed in reply: the cancellation answers the pull in flight.
                self.streams.remove(&control.stream_id);
                Ok(Vec::new())
            }
            PluginSessionPayload::StreamRelease(control) => {
                self.state
                    .receive_release(&control)
                    .map_err(|error| error.failure.message)?;
                self.streams.remove(&control.stream_id);
                Ok(Vec::new())
            }
            other => Err(format!(
                "a session message the kernel does not receive from a host: {other:?}"
            )),
        }
    }

    /// Open the downstream stream an operation asked for.
    async fn open(
        &mut self,
        request: &PluginStreamOpenRequest,
    ) -> Result<PluginStreamOpened, PluginFailure> {
        let refusal = |message: String| PluginFailure {
            code: PluginFailureCode::Rejected,
            message,
        };
        let parked = self
            .continuations
            .parked(&request.operation_request_id)
            .ok_or_else(|| {
                refusal(format!(
                    "no chain is parked for operation '{}', so there is no stream to open",
                    request.operation_request_id
                ))
            })?;
        let ParkedChain::LlmStream(next) = parked.chain else {
            return Err(refusal(format!(
                "operation '{}' holds a {} position, which has no downstream stream",
                request.operation_request_id,
                match parked.chain {
                    ParkedChain::Tool(_) => "tool",
                    ParkedChain::Llm(_) => "provider",
                    ParkedChain::LlmStream(_) => unreachable!("matched above"),
                }
            )));
        };
        let provider_request: LlmRequest =
            serde_json::from_str(&request.request_json).map_err(|error| {
                refusal(format!(
                    "an open request must carry a provider request: {error}"
                ))
            })?;
        let stream = next(provider_request)
            .await
            .map_err(|error| refusal(error.to_string()))?;
        self.opened += 1;
        let stream_id = format!("{}-{}", request.operation_request_id, self.opened);
        self.streams.insert(
            stream_id.clone(),
            OpenStream {
                operation_request_id: request.operation_request_id.clone(),
                stream,
            },
        );
        Ok(PluginStreamOpened {
            host_call_id: request.host_call_id.clone(),
            stream_id,
        })
    }

    /// Produce the next item of a pulled stream.
    async fn produce(
        &mut self,
        pull: &PluginStreamPullRequest,
    ) -> Result<PluginSessionPayload, String> {
        let Some(open) = self.streams.get_mut(&pull.stream_id) else {
            // The state machine refused this pull unless it knows the stream, so
            // reaching here means the kernel lost a producer it believes it has.
            return Err(format!(
                "stream '{}' is open to the plugin but has no producer here",
                pull.stream_id
            ));
        };
        // Kept so a refusal can say whose stream it is, and so the operation a
        // stream belongs to is recoverable when a session is torn down.
        let _operation = &open.operation_request_id;
        match open.stream.next().await {
            Some(Ok(chunk)) => {
                let item = PluginStreamItem {
                    host_call_id: pull.host_call_id.clone(),
                    stream_id: pull.stream_id.clone(),
                    chunk_json: chunk.to_string(),
                };
                self.state
                    .send_item(&item)
                    .map_err(|error| error.failure.message)?;
                Ok(PluginSessionPayload::StreamItem(item))
            }
            Some(Err(error)) => {
                let failed = PluginStreamFailed {
                    host_call_id: pull.host_call_id.clone(),
                    stream_id: pull.stream_id.clone(),
                    failure: PluginFailure {
                        code: PluginFailureCode::Rejected,
                        message: error.to_string(),
                    },
                };
                self.state
                    .send_stream_failed(&failed)
                    .map_err(|error| error.failure.message)?;
                self.streams.remove(&pull.stream_id);
                Ok(PluginSessionPayload::StreamFailed(failed))
            }
            None => {
                let end = PluginStreamEnd {
                    host_call_id: pull.host_call_id.clone(),
                    stream_id: pull.stream_id.clone(),
                };
                self.state
                    .send_end(&end)
                    .map_err(|error| error.failure.message)?;
                self.streams.remove(&pull.stream_id);
                Ok(PluginSessionPayload::StreamEnd(end))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay::api::llm::LlmRequest;
    use nemo_relay::api::runtime::LlmStreamExecutionNextFn;
    use nemo_relay_plugin_protocol::{
        PluginFailureCode, PluginStreamControl, PluginStreamOpenRequest, PluginStreamPullRequest,
    };

    fn request(content: serde_json::Value) -> LlmRequest {
        LlmRequest {
            headers: serde_json::Map::new(),
            content,
        }
    }

    /// A chain position whose stream produces `chunks`, then ends.
    fn producing(chunks: Vec<serde_json::Value>) -> LlmStreamExecutionNextFn {
        Arc::new(move |_request| {
            let chunks = chunks.clone();
            Box::pin(async move {
                Ok(LlmJsonStream::new(tokio_stream::iter(
                    chunks.into_iter().map(Ok).collect::<Vec<_>>(),
                )))
            })
        })
    }

    fn open(host_call_id: &str, operation: &str) -> PluginSessionMessage {
        PluginSessionMessage {
            session_id: "session-1".into(),
            message: PluginSessionPayload::StreamOpen(PluginStreamOpenRequest {
                host_call_id: host_call_id.into(),
                operation_request_id: operation.into(),
                request_json: serde_json::to_string(&request(serde_json::json!({"model": "x"})))
                    .expect("a request"),
            }),
        }
    }

    fn pull(host_call_id: &str, stream_id: &str) -> PluginSessionMessage {
        PluginSessionMessage {
            session_id: "session-1".into(),
            message: PluginSessionPayload::StreamPull(PluginStreamPullRequest {
                host_call_id: host_call_id.into(),
                stream_id: stream_id.into(),
            }),
        }
    }

    /// The kernel produces what the plugin pulls, one item per pull, and says
    /// when the stream is done.
    #[tokio::test]
    async fn a_pull_is_answered_with_the_next_item_and_then_with_the_end() {
        let continuations = Arc::new(Continuations::new());
        let _held = continuations.hold_llm_stream(
            "operation-1",
            "registration-1",
            producing(vec![
                serde_json::json!({"chunk": 1}),
                serde_json::json!({"chunk": 2}),
            ]),
        );
        let mut driver = SessionDriver::new("session-1", Arc::clone(&continuations));

        let opened = driver
            .handle(open("call-1", "operation-1"))
            .await
            .expect("an open");
        let PluginSessionPayload::StreamOpened(opened) = &opened[0].message else {
            panic!("the kernel opens a stream: {opened:?}");
        };
        let stream_id = opened.stream_id.clone();

        let first = driver
            .handle(pull("call-2", &stream_id))
            .await
            .expect("a pull");
        let PluginSessionPayload::StreamItem(item) = &first[0].message else {
            panic!("a pull is answered with an item: {first:?}");
        };
        assert_eq!(item.chunk_json, serde_json::json!({"chunk": 1}).to_string());

        let second = driver
            .handle(pull("call-3", &stream_id))
            .await
            .expect("a pull");
        assert!(matches!(
            second[0].message,
            PluginSessionPayload::StreamItem(_)
        ));

        // The producer had two chunks, so the third pull learns the stream is
        // over rather than waiting for one that is never coming.
        let ended = driver
            .handle(pull("call-4", &stream_id))
            .await
            .expect("a pull");
        assert!(matches!(
            ended[0].message,
            PluginSessionPayload::StreamEnd(_)
        ));
    }

    /// An operation with no parked stream is refused, and refused in a way the
    /// plugin can read: opening is asynchronous on its side, so the answer is a
    /// message rather than a transport failure.
    #[tokio::test]
    async fn an_open_for_an_operation_with_no_position_is_refused() {
        let continuations = Arc::new(Continuations::new());
        let mut driver = SessionDriver::new("session-1", Arc::clone(&continuations));
        let answer = driver
            .handle(open("call-1", "operation-nobody-holds"))
            .await
            .expect("an answer");
        let PluginSessionPayload::StreamOpenFailed(failed) = &answer[0].message else {
            panic!("a refusal the plugin can read: {answer:?}");
        };
        assert_eq!(failed.failure.code, PluginFailureCode::Rejected);
        assert!(
            failed.failure.message.contains("no chain is parked"),
            "{finished:?}",
            finished = failed.failure
        );
    }

    /// A position that is not a stream has no downstream stream to open, and says
    /// so rather than producing one from the wrong chain.
    #[tokio::test]
    async fn an_open_for_a_position_of_another_family_is_refused() {
        let continuations = Arc::new(Continuations::new());
        let _held = continuations.hold_tool(
            "operation-1",
            "registration-1",
            Arc::new(|args| {
                Box::pin(async move { Ok(nemo_relay::api::tool::ToolExecutionResult::new(args)) })
            }),
        );
        let mut driver = SessionDriver::new("session-1", Arc::clone(&continuations));
        let answer = driver
            .handle(open("call-1", "operation-1"))
            .await
            .expect("an answer");
        let PluginSessionPayload::StreamOpenFailed(failed) = &answer[0].message else {
            panic!("a refusal the plugin can read: {answer:?}");
        };
        assert!(
            failed
                .failure
                .message
                .contains("which has no downstream stream"),
            "{failure:?}",
            failure = failed.failure
        );
    }

    /// A cancel stops the kernel producing, and the stream is gone with it.
    #[tokio::test]
    async fn a_cancel_stops_production_and_the_stream_is_released_with_it() {
        let continuations = Arc::new(Continuations::new());
        let _held = continuations.hold_llm_stream(
            "operation-1",
            "registration-1",
            producing(vec![
                serde_json::json!({"chunk": 1}),
                serde_json::json!({"chunk": 2}),
            ]),
        );
        let mut driver = SessionDriver::new("session-1", Arc::clone(&continuations));
        let opened = driver
            .handle(open("call-1", "operation-1"))
            .await
            .expect("an open");
        let PluginSessionPayload::StreamOpened(opened) = &opened[0].message else {
            panic!("the kernel opens a stream: {opened:?}");
        };
        let stream_id = opened.stream_id.clone();

        let cancelled = driver
            .handle(PluginSessionMessage {
                session_id: "session-1".into(),
                message: PluginSessionPayload::StreamCancel(PluginStreamControl {
                    host_call_id: "call-cancel".into(),
                    stream_id: stream_id.clone(),
                }),
            })
            .await
            .expect("a cancel");
        assert!(
            cancelled.is_empty(),
            "a cancel is not answered: {cancelled:?}"
        );

        // Pulling a cancelled stream is refused by the state machine, which is
        // what the plugin learns: it stopped the stream, so it may not keep it.
        let refused = driver.handle(pull("call-2", &stream_id)).await;
        assert!(
            refused.is_err(),
            "a cancelled stream cannot be pulled: {refused:?}"
        );
    }

    /// A release drops the kernel's stream and forgets it.
    #[tokio::test]
    async fn a_release_drops_the_stream_the_kernel_was_producing() {
        let continuations = Arc::new(Continuations::new());
        let _held = continuations.hold_llm_stream(
            "operation-1",
            "registration-1",
            producing(vec![serde_json::json!({"chunk": 1})]),
        );
        let mut driver = SessionDriver::new("session-1", Arc::clone(&continuations));
        let opened = driver
            .handle(open("call-1", "operation-1"))
            .await
            .expect("an open");
        let PluginSessionPayload::StreamOpened(opened) = &opened[0].message else {
            panic!("the kernel opens a stream: {opened:?}");
        };
        let stream_id = opened.stream_id.clone();

        driver
            .handle(PluginSessionMessage {
                session_id: "session-1".into(),
                message: PluginSessionPayload::StreamRelease(PluginStreamControl {
                    host_call_id: "call-release".into(),
                    stream_id: stream_id.clone(),
                }),
            })
            .await
            .expect("a release");
        assert!(
            !driver.streams.contains_key(&stream_id),
            "the producer is gone with the release"
        );
        // And a second release is refused, because the stream it names is not
        // one this session holds any more.
        assert!(
            driver
                .handle(PluginSessionMessage {
                    session_id: "session-1".into(),
                    message: PluginSessionPayload::StreamRelease(PluginStreamControl {
                        host_call_id: "call-release-again".into(),
                        stream_id: stream_id.clone(),
                    }),
                })
                .await
                .is_err()
        );
    }

    /// A stream whose producer fails ends in a failure the plugin can read,
    /// rather than in silence, which it could not tell from a slow producer.
    #[tokio::test]
    async fn a_stream_that_fails_answers_with_the_failure() {
        let continuations = Arc::new(Continuations::new());
        let failing: LlmStreamExecutionNextFn = Arc::new(|_request| {
            Box::pin(async move {
                Ok(LlmJsonStream::new(tokio_stream::iter(vec![Err(
                    nemo_relay::error::FlowError::Internal("the provider fell over".to_string()),
                )])))
            })
        });
        let _held = continuations.hold_llm_stream("operation-1", "registration-1", failing);
        let mut driver = SessionDriver::new("session-1", Arc::clone(&continuations));
        let opened = driver
            .handle(open("call-1", "operation-1"))
            .await
            .expect("an open");
        let PluginSessionPayload::StreamOpened(opened) = &opened[0].message else {
            panic!("the kernel opens a stream: {opened:?}");
        };
        let stream_id = opened.stream_id.clone();

        let failed = driver
            .handle(pull("call-2", &stream_id))
            .await
            .expect("a pull");
        let PluginSessionPayload::StreamFailed(failed) = &failed[0].message else {
            panic!("a failing producer is a failure the plugin can read: {failed:?}");
        };
        assert!(
            failed.failure.message.contains("fell over"),
            "{failure:?}",
            failure = failed.failure
        );
    }

    /// A message the kernel does not receive from a host ends the channel rather
    /// than being answered as if it were addressed to it.
    #[tokio::test]
    async fn a_message_from_the_wrong_side_ends_the_channel() {
        let continuations = Arc::new(Continuations::new());
        let mut driver = SessionDriver::new("session-1", Arc::clone(&continuations));
        let refused = driver
            .handle(PluginSessionMessage {
                session_id: "session-1".into(),
                message: PluginSessionPayload::StreamOpened(PluginStreamOpened {
                    host_call_id: "call-1".into(),
                    stream_id: "stream-1".into(),
                }),
            })
            .await;
        assert!(
            refused.is_err(),
            "the kernel does not receive an opening from a host: {refused:?}"
        );
    }
}
