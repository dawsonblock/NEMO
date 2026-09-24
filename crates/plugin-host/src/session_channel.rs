// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The host's end of the session channel.
//!
//! A plugin that wraps a streaming call pulls the stream the kernel is producing,
//! one chunk at a time, and it does that from inside a callback that is running in
//! this process. This is what stands between the two: a caller asks the kernel for
//! the downstream stream of one operation and gets back something it can poll, and
//! every poll is a message the kernel answers.
//!
//! Pacing is the point. The kernel produces the next chunk when it is asked for
//! one, so a plugin that stops pulling stops the work behind it — which is what an
//! in-process stream does too, and what makes the boundary invisible to the
//! callback rather than merely equivalent on average.
//!
//! One task per stream does the pulling, and the pollable value is that task's
//! output. Two reasons: a `poll_next` cannot await, and — more importantly — the
//! consumer dropping the stream has to reach the kernel as a cancellation rather
//! than as a host that stopped asking without saying so.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Stream, StreamExt};
use nemo_relay::api::llm::LlmRequest;
use nemo_relay::api::runtime::LlmJsonStream;
use nemo_relay_plugin_protocol::{
    PluginSessionMessage, PluginSessionPayload, PluginStreamControl, PluginStreamOpenRequest,
    PluginStreamPullRequest,
};
use tokio_stream::wrappers::ReceiverStream;

use crate::runtime_service::{KernelCallbacks, SESSION_CREDENTIAL_HEADER};

/// A channel to the kernel this host serves.
///
/// One per host: the kernel serves one session per process, so a second channel
/// would be a second reader of the same session's answers.
pub struct SessionChannel {
    /// Where this host's messages go.
    outbound: tokio::sync::mpsc::Sender<nemo_relay_plugin_proto::v1::PluginSessionMessage>,
    /// Where the kernel's answers arrive, by the call that asked.
    answers: std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<String, tokio::sync::oneshot::Sender<PluginSessionPayload>>,
        >,
    >,
    /// The session these messages belong to.
    session_id: String,
    /// Minted per call, so an answer can be attributed to the call that asked.
    ///
    /// Shared rather than owned: every stream this channel opens pulls on its own
    /// task, and two of them minting from their own copy of the counter would
    /// produce the same call identity — which is how an answer ends up applied to
    /// the wrong call.
    calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl std::fmt::Debug for SessionChannel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionChannel")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl KernelCallbacks {
    /// Open the channel a host pulls its plugins' downstream streams over.
    ///
    /// # Errors
    /// Returns the transport's words when the kernel cannot be reached, and the
    /// kernel's when it refuses the channel — a credential that is not this
    /// session's, a session this kernel does not serve.
    pub async fn open_session(&self, session_id: &str) -> Result<SessionChannel, String> {
        let (outbound, messages) = tokio::sync::mpsc::channel(SESSION_OUTBOUND_CAPACITY);
        let answers: std::sync::Arc<
            std::sync::Mutex<
                std::collections::HashMap<
                    String,
                    tokio::sync::oneshot::Sender<PluginSessionPayload>,
                >,
            >,
        > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        let mut request = tonic::Request::new(ReceiverStream::new(messages));
        request
            .metadata_mut()
            .insert(SESSION_CREDENTIAL_HEADER, self.credential().clone());
        let mut answers_in = self
            .client()
            .clone()
            .session(request)
            .await
            .map_err(|status| status.to_string())?
            .into_inner();

        // The reader: one task for the host, because the kernel answers the calls
        // this host makes and every answer names the call it answers.
        let routing = std::sync::Arc::clone(&answers);
        // Weak, because this reader is not what keeps the channel — and with it
        // the kernel's session — alive: the host letting go of its end is the
        // signal that ends the session, and a reader holding a sender would be
        // holding that signal open.
        let cancelling = outbound.downgrade();
        let session = session_id.to_owned();
        tokio::spawn(async move {
            while let Some(answer) = answers_in.next().await {
                let Ok(answer) = answer else { return };
                let Ok(answer) =
                    nemo_relay_plugin_proto::convert::session_message_from_wire(&answer)
                else {
                    return;
                };
                // The stream an answer names, when the answer is one that
                // creates a stream: an answer nobody receives has to leave
                // nothing behind, and only this answer can name what it left.
                let (call, opened) = match &answer.message {
                    PluginSessionPayload::StreamOpened(opened) => {
                        (opened.host_call_id.clone(), Some(opened.stream_id.clone()))
                    }
                    PluginSessionPayload::StreamOpenFailed(failed) => {
                        (failed.host_call_id.clone(), None)
                    }
                    PluginSessionPayload::StreamItem(item) => (item.host_call_id.clone(), None),
                    PluginSessionPayload::StreamEnd(end) => (end.host_call_id.clone(), None),
                    PluginSessionPayload::StreamFailed(failed) => {
                        (failed.host_call_id.clone(), None)
                    }
                    // Answers to calls this side did not make are not this side's
                    // to route; a session that sent one is answered by ending the
                    // channel, which the loop does by returning.
                    _ => return,
                };
                let waiting = routing
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&call);
                let delivered = match waiting {
                    Some(waiting) => waiting.send(answer.message).is_ok(),
                    None => false,
                };
                if delivered {
                    continue;
                }
                // The call that asked for this stream is gone: the consumer
                // walked away while the open was in flight, so the kernel has
                // made a stream this host cannot hand to anyone. It is cancelled
                // here because this is the last place its identity exists — the
                // owner that would have cancelled it no longer does — and a
                // stream nothing names is one the kernel keeps producing for.
                //
                // Awaited rather than tried: a cancellation dropped because a
                // buffer was full is the leak this is here to prevent, and this
                // reader is a task of its own rather than a `poll_next`, so it is
                // the one place in the channel that can afford to wait.
                if let Some(stream_id) = opened
                    && let Some(cancelling) = cancelling.upgrade()
                {
                    let cancellation = PluginSessionMessage {
                        session_id: session.clone(),
                        message: PluginSessionPayload::StreamCancel(PluginStreamControl {
                            host_call_id: format!("cancel-{stream_id}"),
                            stream_id,
                        }),
                    };
                    let _ = cancelling
                        .send(nemo_relay_plugin_proto::convert::session_message_to_wire(
                            &cancellation,
                        ))
                        .await;
                }
            }
        });

        Ok(SessionChannel {
            outbound,
            answers,
            session_id: session_id.to_owned(),
            calls: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
        })
    }
}

/// How many messages a host may have in flight to its kernel.
///
/// One call at a time per stream is the ABI's rule, so this is room for several
/// streams rather than for one stream running ahead of its answers.
const SESSION_OUTBOUND_CAPACITY: usize = 16;

impl SessionChannel {
    /// Ask the kernel for the downstream stream of one operation.
    ///
    /// The value this returns pulls: each poll asks the kernel for the next chunk,
    /// and the stream ends when the kernel says it has produced everything —
    /// `None` — or fails with the failure the producer reported.
    ///
    /// # Errors
    /// Returns the kernel's refusal when there is no stream to open for that
    /// operation, which is a callback asking for a position nothing holds.
    pub async fn open_stream(
        &self,
        operation_request_id: &str,
        request: &LlmRequest,
    ) -> Result<PullStream, String> {
        let request_json =
            serde_json::to_string(request).map_err(|error| format!("unserializable: {error}"))?;
        let host_call_id = self.next_call();
        // Registered before the message is sent, not after: an answer that
        // arrives first has nowhere to go, and a call whose answer is dropped is
        // a call that waits forever. The same rule the pulling task follows.
        let answer = self.await_answer(&host_call_id)?;
        self.outbound
            .send(nemo_relay_plugin_proto::convert::session_message_to_wire(
                &PluginSessionMessage {
                    session_id: self.session_id.clone(),
                    message: PluginSessionPayload::StreamOpen(PluginStreamOpenRequest {
                        host_call_id,
                        operation_request_id: operation_request_id.to_owned(),
                        request_json,
                    }),
                },
            ))
            .await
            .map_err(|_| "the kernel is no longer reachable".to_string())?;

        let answered = answer
            .await
            .map_err(|_| "the session ended before the kernel answered".to_string())?;
        match answered {
            PluginSessionPayload::StreamOpened(opened) => Ok(self.pull(opened.stream_id)),
            PluginSessionPayload::StreamOpenFailed(failed) => Err(failed.failure.message),
            // Anything else answering an open is a session that answered a call
            // with something the call cannot mean.
            other => Err(format!("the kernel answered an open with {other:?}")),
        }
    }

    /// One identity per call this host makes.
    fn next_call(&self) -> String {
        format!(
            "{}-{}",
            self.session_id,
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        )
    }

    /// Register a place for the answer to one call, before it is sent.
    fn await_answer(
        &self,
        host_call_id: &str,
    ) -> Result<tokio::sync::oneshot::Receiver<PluginSessionPayload>, String> {
        let (sender, answer) = tokio::sync::oneshot::channel();
        let replaced = self
            .answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(host_call_id.to_owned(), sender);
        if replaced.is_some() {
            // Two calls under one identity would make an answer ambiguous, which
            // is the one thing this router exists to prevent.
            return Err(format!("call identity '{host_call_id}' was reused"));
        }
        Ok(answer)
    }

    /// A stream that pulls `stream_id` from the kernel.
    fn pull(&self, stream_id: String) -> PullStream {
        let (items, received) = tokio::sync::mpsc::channel(SESSION_STREAM_BUFFER);
        let outbound = self.outbound.clone();
        let answers = std::sync::Arc::clone(&self.answers);
        let session_id = self.session_id.clone();
        // The same counter every other stream on this channel mints from.
        let calls = std::sync::Arc::clone(&self.calls);
        let address = stream_id.clone();
        let pulling = tokio::spawn(async move {
            loop {
                let host_call_id = format!(
                    "{session_id}-{}",
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                );
                let (sender, answer) = tokio::sync::oneshot::channel();
                answers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(host_call_id.clone(), sender);
                let sent = outbound
                    .send(nemo_relay_plugin_proto::convert::session_message_to_wire(
                        &PluginSessionMessage {
                            session_id: session_id.clone(),
                            message: PluginSessionPayload::StreamPull(PluginStreamPullRequest {
                                host_call_id,
                                stream_id: address.clone(),
                            }),
                        },
                    ))
                    .await;
                if sent.is_err() {
                    return;
                }
                let answered = match answer.await {
                    Ok(answered) => answered,
                    Err(_) => return,
                };
                let item = match answered {
                    PluginSessionPayload::StreamItem(item) => {
                        match serde_json::from_str(&item.chunk_json) {
                            Ok(chunk) => Ok(chunk),
                            Err(error) => Err(nemo_relay::error::FlowError::Internal(format!(
                                "the kernel's chunk is not JSON: {error}"
                            ))),
                        }
                    }
                    PluginSessionPayload::StreamEnd(_) => return,
                    PluginSessionPayload::StreamFailed(failed) => {
                        let _ = items
                            .send(Err(nemo_relay::error::FlowError::Internal(
                                failed.failure.message.clone(),
                            )))
                            .await;
                        return;
                    }
                    _ => return,
                };
                // A consumer that stopped reading is a consumer that stopped
                // wanting the stream, and the kernel has to be told: nothing else
                // reaches it as a cancellation.
                if items.send(item).await.is_err() {
                    return;
                }
            }
        });

        PullStream {
            received: ReceiverStream::new(received),
            pulling: Some(pulling),
            cancellation: Some((self.outbound.clone(), stream_id, self.session_id.clone())),
        }
    }
}

/// How many chunks a host holds for a consumer that is slower than its kernel.
const SESSION_STREAM_BUFFER: usize = 4;

/// A stream pulled from the kernel by a callback in this process.
pub struct PullStream {
    received: ReceiverStream<Result<nemo_relay::json::Json, nemo_relay::error::FlowError>>,
    /// The task doing the pulling, held so the stream owns it.
    pulling: Option<tokio::task::JoinHandle<()>>,
    /// What to tell the kernel when this stream goes away.
    cancellation: Option<(
        tokio::sync::mpsc::Sender<nemo_relay_plugin_proto::v1::PluginSessionMessage>,
        String,
        String,
    )>,
}

impl std::fmt::Debug for PullStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PullStream").finish_non_exhaustive()
    }
}

impl PullStream {
    /// Wrap this as the managed stream the plugin's callback receives.
    pub fn into_managed(self) -> LlmJsonStream
    where
        Self: Send + 'static,
    {
        LlmJsonStream::new(self)
    }
}

impl Stream for PullStream {
    type Item = Result<nemo_relay::json::Json, nemo_relay::error::FlowError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        // The pulling task owns the sender, so the channel closing *is* the end of
        // the stream: the kernel said so, the task ended, or the session broke.
        // Reading the task's state as well as the channel is what keeps a stream
        // the kernel finished from looking like one that is merely quiet.
        Pin::new(&mut this.received).poll_next(context)
    }
}

impl Drop for PullStream {
    fn drop(&mut self) {
        if let Some(pulling) = self.pulling.take() {
            pulling.abort();
        }
        // The kernel produces nothing more once it is told the plugin stopped
        // asking, so a dropped stream is a cancellation rather than a stream the
        // kernel keeps feeding.
        if let Some((outbound, stream_id, session_id)) = self.cancellation.take() {
            let cancellation = PluginSessionMessage {
                session_id,
                message: PluginSessionPayload::StreamCancel(PluginStreamControl {
                    host_call_id: format!("cancel-{stream_id}"),
                    stream_id,
                }),
            };
            let _ = outbound.try_send(nemo_relay_plugin_proto::convert::session_message_to_wire(
                &cancellation,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::transport::Server;

    const SESSION_ID: &str = "session-channel";
    const CREDENTIAL: &str = "session-channel-credential";

    /// A kernel serving one session channel, with one stream parked for one
    /// operation, reachable over a real socket.
    async fn serve_kernel(chunks: Vec<Result<serde_json::Value, String>>) -> std::path::PathBuf {
        use nemo_relay_plugin_proto::v1::relay_runtime_server::RelayRuntimeServer;

        let continuations = std::sync::Arc::new(crate::continuations::Continuations::new());
        let stream: nemo_relay::api::runtime::LlmStreamExecutionNextFn =
            std::sync::Arc::new(move |_request| {
                let chunks = chunks.clone();
                Box::pin(async move {
                    Ok(nemo_relay::api::runtime::LlmJsonStream::new(
                        tokio_stream::iter(
                            chunks
                                .into_iter()
                                .map(|chunk| chunk.map_err(nemo_relay::error::FlowError::Internal)),
                        ),
                    ))
                })
            });
        // Parked for as long as the channel test runs: the guard is leaked on
        // purpose, because the kernel's session outlives this helper.
        std::mem::forget(continuations.hold_llm_stream("operation-1", "registration-1", stream));

        let service = crate::runtime_service::RelayRuntimeService::new(
            crate::runtime_service::RelayRuntimeConfig {
                session_id: SESSION_ID.into(),
                session_credential: CREDENTIAL.into(),
                protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
                runtime_binding_digest: "session-channel-binding".into(),
                operation_scopes: std::sync::Arc::new(
                    crate::operation_scopes::OperationScopes::new(),
                ),
                continuations,
            },
        );
        let directory = std::env::temp_dir().join(format!(
            "nemo-schan-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&directory).expect("a socket directory");
        let endpoint = directory.join("k");
        let listener = tokio::net::UnixListener::bind(&endpoint).expect("a kernel socket");
        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(RelayRuntimeServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
                .await;
        });
        endpoint
    }

    async fn callbacks(endpoint: &std::path::Path) -> KernelCallbacks {
        let client = crate::runtime_service::connect_to_kernel(
            endpoint,
            nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        )
        .await
        .expect("a client");
        KernelCallbacks::new(client, CREDENTIAL).expect("the credential")
    }

    /// A plugin's pull reaches the kernel and comes back as the next chunk.
    #[tokio::test]
    async fn a_pull_yields_the_next_chunk_and_then_the_end() {
        let endpoint = serve_kernel(vec![
            Ok(serde_json::json!({"chunk": 1})),
            Ok(serde_json::json!({"chunk": 2})),
        ])
        .await;
        let callbacks = callbacks(&endpoint).await;
        let channel = callbacks
            .open_session(SESSION_ID)
            .await
            .expect("an open channel");

        let request = LlmRequest {
            headers: serde_json::Map::new(),
            content: serde_json::json!({"model": "fixture"}),
        };
        let mut stream = channel
            .open_stream("operation-1", &request)
            .await
            .expect("a stream the kernel is producing");

        assert_eq!(
            stream.next().await.expect("a chunk").expect("a chunk"),
            serde_json::json!({"chunk": 1})
        );
        assert_eq!(
            stream.next().await.expect("a chunk").expect("a chunk"),
            serde_json::json!({"chunk": 2})
        );
        assert!(
            stream.next().await.is_none(),
            "the kernel said the stream was over"
        );
    }

    /// An operation with no stream to open is refused, and the refusal is the
    /// kernel's own words rather than a channel that went quiet.
    #[tokio::test]
    async fn an_operation_with_no_stream_is_refused() {
        let endpoint = serve_kernel(vec![Ok(serde_json::json!({"chunk": 1}))]).await;
        let callbacks = callbacks(&endpoint).await;
        let channel = callbacks
            .open_session(SESSION_ID)
            .await
            .expect("an open channel");
        let request = LlmRequest {
            headers: serde_json::Map::new(),
            content: serde_json::json!({}),
        };
        let refused = channel
            .open_stream("operation-nobody-holds", &request)
            .await
            .expect_err("a refusal");
        assert!(
            refused.contains("no chain is parked"),
            "the kernel's words reach the callback: {refused}"
        );
    }

    /// A producer that fails ends the stream with the failure, after whatever it
    /// produced before failing.
    #[tokio::test]
    async fn a_failing_producer_reaches_the_consumer_as_a_failure() {
        let endpoint = serve_kernel(vec![
            Ok(serde_json::json!({"chunk": 1})),
            Err("the provider fell over".to_string()),
        ])
        .await;
        let callbacks = callbacks(&endpoint).await;
        let channel = callbacks
            .open_session(SESSION_ID)
            .await
            .expect("an open channel");
        let request = LlmRequest {
            headers: serde_json::Map::new(),
            content: serde_json::json!({}),
        };
        let mut stream = channel
            .open_stream("operation-1", &request)
            .await
            .expect("a stream");

        assert_eq!(
            stream.next().await.expect("a chunk").expect("a chunk"),
            serde_json::json!({"chunk": 1})
        );
        let failure = stream
            .next()
            .await
            .expect("an answer")
            .expect_err("the producer's failure");
        assert!(
            failure.to_string().contains("fell over"),
            "the failure the producer reported is what the consumer sees: {failure}"
        );
        assert!(stream.next().await.is_none(), "and then the stream ends");
    }

    /// A consumer that stops reading stops the kernel producing.
    ///
    /// The proof is on the kernel's side: the stream it was serving is dropped,
    /// which the cancellation message is what asks for. A host that merely
    /// stopped pulling would leave the kernel's producer alive, and a kernel
    /// holding a producer for a consumer that walked away is the leak this
    /// exists to prevent.
    ///
    /// The same has to hold one step earlier, when the consumer walks away while
    /// the *open* is in flight: the kernel has been asked for a stream and has
    /// not answered yet, so the identity the cancellation needs does not exist on
    /// this side. `an_open_the_caller_left_cancels_the_kernel_s_producer` is that
    /// window.
    #[tokio::test]
    async fn a_dropped_stream_cancels_the_kernel_s_producer() {
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watching = std::sync::Arc::clone(&dropped);
        let endpoint = serve_kernel_with_marker(
            vec![
                Ok(serde_json::json!({"chunk": 1})),
                Ok(serde_json::json!({"chunk": 2})),
            ],
            watching,
            None,
        )
        .await;
        let callbacks = callbacks(&endpoint).await;
        let channel = callbacks
            .open_session(SESSION_ID)
            .await
            .expect("an open channel");
        let request = LlmRequest {
            headers: serde_json::Map::new(),
            content: serde_json::json!({}),
        };
        let mut stream = channel
            .open_stream("operation-1", &request)
            .await
            .expect("a stream");
        assert!(stream.next().await.is_some(), "the first chunk arrives");
        drop(stream);

        let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !dropped.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            stopped.is_ok(),
            "the kernel dropped the producer the consumer walked away from"
        );
    }

    /// An open nobody is waiting for is cancelled rather than left producing.
    ///
    /// The narrowest window in the cascade: the plugin has asked the kernel for
    /// the downstream stream of an operation and the kernel has not answered, so
    /// the stream it is about to create has no name on this side yet. Waiting is
    /// what makes that window reachable at all — the kernel is held inside the
    /// open until the caller has already gone — and the proof is again on the
    /// kernel's side, because a stream nobody names is one nothing else will
    /// ever cancel.
    #[tokio::test]
    async fn an_open_the_caller_left_cancels_the_kernel_s_producer() {
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate = std::sync::Arc::new(OpenGate::new());
        let endpoint = serve_kernel_with_marker(
            vec![Ok(serde_json::json!({"chunk": 1}))],
            std::sync::Arc::clone(&dropped),
            Some(std::sync::Arc::clone(&gate)),
        )
        .await;
        let callbacks = callbacks(&endpoint).await;
        let channel = callbacks
            .open_session(SESSION_ID)
            .await
            .expect("an open channel");
        let request = LlmRequest {
            headers: serde_json::Map::new(),
            content: serde_json::json!({}),
        };

        // The caller walks away while the kernel is inside the open: the future
        // that would have received the stream is dropped, so the answer it would
        // have carried has no owner on this side.
        {
            let opening = channel.open_stream("operation-1", &request);
            let mut opening = std::pin::pin!(opening);
            tokio::select! {
                () = gate.entered.notified() => {}
                answered = &mut opening => panic!(
                    "the kernel answered before it opened the stream: {answered:?}"
                ),
            }
        }
        // The kernel finishes the open it was already in, and the stream it
        // creates must not outlive the caller that asked for it.
        gate.release.notify_one();

        let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !dropped.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            stopped.is_ok(),
            "the stream the kernel opened for a caller that left was cancelled"
        );
    }

    /// A pause the kernel takes inside the open it was asked for.
    ///
    /// The window between asking for a stream and the kernel answering it is too
    /// narrow to hit by timing, and a test that tried would be a test about the
    /// scheduler. The kernel parks where the test can see it and continues when
    /// the test says so.
    struct OpenGate {
        /// Fires as the kernel enters the open.
        entered: tokio::sync::Notify,
        /// Released by the test to let the kernel create the producer.
        release: tokio::sync::Notify,
    }

    impl OpenGate {
        fn new() -> Self {
            Self {
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
            }
        }
    }

    /// Two streams on one channel pull independently, and their answers do not
    /// cross.
    ///
    /// Each pull is answered by the call that asked, so the identities have to be
    /// unique across the channel rather than per stream: two streams minting from
    /// their own copy of a counter would ask with the same identity and one
    /// answer would land in the other's hands. Both streams here are opened for
    /// the same operation — the ABI allows it — so nothing but the identity tells
    /// their answers apart.
    #[tokio::test]
    async fn two_streams_on_one_channel_do_not_swap_answers() {
        let endpoint = serve_kernel(vec![
            Ok(serde_json::json!({"chunk": 1})),
            Ok(serde_json::json!({"chunk": 2})),
        ])
        .await;
        let callbacks = callbacks(&endpoint).await;
        let channel = callbacks
            .open_session(SESSION_ID)
            .await
            .expect("an open channel");
        let request = LlmRequest {
            headers: serde_json::Map::new(),
            content: serde_json::json!({"model": "fixture"}),
        };
        let mut first = channel
            .open_stream("operation-1", &request)
            .await
            .expect("a first stream");
        let mut second = channel
            .open_stream("operation-1", &request)
            .await
            .expect("a second stream");

        // Interleaved, so an answer routed by anything but its own call identity
        // would show up as one stream receiving the other's chunk.
        assert_eq!(
            first.next().await.expect("a chunk").expect("a chunk"),
            serde_json::json!({"chunk": 1})
        );
        assert_eq!(
            second.next().await.expect("a chunk").expect("a chunk"),
            serde_json::json!({"chunk": 1})
        );
        assert_eq!(
            first.next().await.expect("a chunk").expect("a chunk"),
            serde_json::json!({"chunk": 2})
        );
        assert_eq!(
            second.next().await.expect("a chunk").expect("a chunk"),
            serde_json::json!({"chunk": 2})
        );
        assert!(first.next().await.is_none());
        assert!(second.next().await.is_none());
    }

    /// The same kernel, with a producer that records when it is dropped.
    ///
    /// `gate` holds the kernel inside the open when a test needs to see the
    /// window between asking for a stream and the kernel answering it.
    async fn serve_kernel_with_marker(
        chunks: Vec<Result<serde_json::Value, String>>,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
        gate: Option<std::sync::Arc<OpenGate>>,
    ) -> std::path::PathBuf {
        use nemo_relay_plugin_proto::v1::relay_runtime_server::RelayRuntimeServer;

        let continuations = std::sync::Arc::new(crate::continuations::Continuations::new());
        let stream: nemo_relay::api::runtime::LlmStreamExecutionNextFn =
            std::sync::Arc::new(move |_request| {
                let chunks = chunks.clone();
                let dropped = std::sync::Arc::clone(&dropped);
                let gate = gate.clone();
                Box::pin(async move {
                    let items: Vec<Result<serde_json::Value, nemo_relay::error::FlowError>> =
                        chunks
                            .into_iter()
                            .map(|chunk| {
                                chunk.map_err(|message| {
                                    nemo_relay::error::FlowError::Internal(message)
                                })
                            })
                            .collect();
                    struct Watched {
                        items: std::vec::IntoIter<
                            Result<serde_json::Value, nemo_relay::error::FlowError>,
                        >,
                        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
                    }
                    impl Stream for Watched {
                        type Item = Result<serde_json::Value, nemo_relay::error::FlowError>;
                        fn poll_next(
                            mut self: Pin<&mut Self>,
                            _context: &mut Context<'_>,
                        ) -> Poll<Option<Self::Item>> {
                            Poll::Ready(self.items.next())
                        }
                    }
                    impl Drop for Watched {
                        fn drop(&mut self) {
                            self.dropped
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                    if let Some(gate) = &gate {
                        gate.entered.notify_one();
                        gate.release.notified().await;
                    }
                    Ok(nemo_relay::api::runtime::LlmJsonStream::new(Watched {
                        items: items.into_iter(),
                        dropped,
                    }))
                })
            });
        std::mem::forget(continuations.hold_llm_stream("operation-1", "registration-1", stream));

        let service = crate::runtime_service::RelayRuntimeService::new(
            crate::runtime_service::RelayRuntimeConfig {
                session_id: SESSION_ID.into(),
                session_credential: CREDENTIAL.into(),
                protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
                runtime_binding_digest: "session-channel-binding".into(),
                operation_scopes: std::sync::Arc::new(
                    crate::operation_scopes::OperationScopes::new(),
                ),
                continuations,
            },
        );
        let directory = std::env::temp_dir().join(format!(
            "nemo-schan-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&directory).expect("a socket directory");
        let endpoint = directory.join("k");
        let listener = tokio::net::UnixListener::bind(&endpoint).expect("a kernel socket");
        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(RelayRuntimeServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
                .await;
        });
        endpoint
    }
}
