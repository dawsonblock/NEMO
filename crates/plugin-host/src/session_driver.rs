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
//! What this must never do is wait on a producer. A dispatcher that awaited
//! `poll_next` would let one plugin's unresponsive provider decide whether any
//! other stream — or the cancellation of its own — is served, and a peer can hold
//! an unresponsive provider for as long as it likes. So the dispatcher routes and
//! never produces: every stream is owned by an actor of its own, the actor owns
//! the producer, and what the actor produces reaches the plugin through the
//! session's writer rather than through the dispatcher.
//!
//! The invariants this rests on, in the order they are load-bearing:
//!
//! 1. **The dispatcher never awaits a producer.** `SessionDriver::handle` has no
//!    `await` in it at all. It validates a message against the session's own
//!    record and routes it; everything that can block happens inside an actor.
//! 2. **One actor per stream, and the actor is the only owner of its producer.**
//!    The stream's lifecycle, the pull being produced for, and the identity of
//!    the next pull are the actor's fields, so no other task can observe a
//!    half-transitioned stream or produce for it.
//! 3. **One outstanding pull per stream.** The session's record refuses a second
//!    pull while one is outstanding, before the message can be routed, so an
//!    actor never has two polls in flight and a result is never ambiguous.
//! 4. **Every pull has an identity, and a result is accepted only for the pull it
//!    was produced for.** The session records a result only for the call the
//!    stream is still waiting for. A result that arrives for a pull a
//!    cancellation already settled is *stale* — it belongs to a call nobody is
//!    waiting for — so it is discarded rather than answered or refused.
//! 5. **Cancellation settles the stream, not the producer's cooperation.** A
//!    cancellation drops the outstanding poll future and then the producer. A
//!    producer that is parked forever is cancelled by being dropped, not by
//!    being asked to notice.
//! 6. **Actors are bounded.** One actor owns at most one outstanding poll, so the
//!    ceiling on actors is the ceiling on concurrent producing work; opens in
//!    flight are bounded on their own, because an open runs a chain rather than a
//!    poll.
//! 7. **A producer's panic fails its stream, not the session.** Panics from
//!    plugin code are contained: the stream settles with what happened, its
//!    producer is dropped, and the session keeps serving its other streams.
//! 8. **Order is the transport's, and it is enough.** One actor, one producer and
//!    at most one outstanding pull per stream means the frames of a stream cannot
//!    be interleaved or reordered by this side: they reach the plugin in the order
//!    the session recorded them. Explicit frame sequence numbers would be needed
//!    only if a stream ever had more than one producer, or if a transport could
//!    deliver one stream's frames out of order — neither of which is true here.
//! 9. **Demand is credit, and credit is granted by demand rather than ahead of it.**
//!    A pull grants one frame's worth and never more, so a stream nobody has asked
//!    about is not polled at all: a stream costs the session its consumer's
//!    appetite, not its producer's willingness to run ahead. One pull at a time is
//!    the strongest demand the protocol can express, which is why the grant is one.
//! 10. **Every frame is measured, and the ceilings are the session's.** What a
//!    stream sends is what it costs: the frame that opens it, its data, the failure
//!    that ends it and the terminal frame are each measured against the session's
//!    frame, byte and frame-count ceilings before they cross, and a frame that
//!    would cross one is not sent — the stream is over instead, and so is the work
//!    behind it.
//! 11. **A stream may not outlive the call it belongs to.** The deadline is the
//!    operation's, taken from the budget the chain position was parked under, and
//!    it is enforced whether or not anyone is asking: an idle stream is over when
//!    its call's time is up and its producer goes with it, an open still blocked at
//!    the deadline never becomes a stream, and a pull whose producer is still
//!    working at the deadline is answered with the deadline rather than with a
//!    frame. What ended the stream is held for the next pull when nothing was
//!    outstanding — a stream's frames are answers to demand, and the ending is one
//!    of them.
//!
//! What the streaming increment still owes is the mark-attribution matrix and the
//! last of the death phases, not more of this session: the mark window now follows
//! execution across the plugin's own task boundary — the SDK's side of the ABI,
//! with the session carrying the resulting marks like any other frame — and
//! everything else the class owed is here and asserted: the deadline, the ceilings,
//! the terminal rule, and the shutdown that drops every producer, with the mixture
//! run rather than argued in
//! `streams_that_end_every_way_at_once_leave_nothing_behind`. The class is not
//! served until the matrix lands, so nothing depends on the actor's shape yet.

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use futures_util::{FutureExt, StreamExt};
use nemo_relay::api::llm::LlmRequest;
use nemo_relay::api::runtime::LlmJsonStream;
use nemo_relay_plugin_protocol::{
    PluginFailure, PluginFailureCode, PluginSessionMessage, PluginSessionPayload, PluginStreamEnd,
    PluginStreamFailed, PluginStreamItem, PluginStreamOpenFailed, PluginStreamOpenRequest,
    PluginStreamOpened, PluginStreamPullRequest,
};

use crate::continuations::{Continuations, ParkedChain};
use crate::session::PluginSessionState;

/// How much of one session's work may be in flight at once.
///
/// Every field is a ceiling rather than a queue: a session that is at one refuses
/// the work rather than holding it, because holding it is what turns a plugin's
/// appetite into this kernel's memory.
#[derive(Debug, Clone, Copy)]
pub struct SessionLimits {
    /// How many streams one session may be serving at once.
    ///
    /// An actor owns one producer and at most one outstanding poll, so this is
    /// also the bound on how much producing work one plugin can have in flight.
    pub max_stream_actors: usize,
    /// How many opens one session may have in flight at once.
    ///
    /// An open runs the chain a plugin is wrapping, which is work this session
    /// cannot bound by waiting for it: it bounds it by refusing more of it.
    pub max_pending_opens: usize,
    /// The largest encoded frame this session will send for one stream.
    ///
    /// A frame above it is not sent: the stream settles with a failure instead,
    /// which is the outcome that bounds the work rather than the message. The
    /// default is the boundary's own frame limit, so a stream can never be the
    /// thing that carries a frame the boundary would refuse.
    pub max_frame_bytes: u32,
    /// How many encoded bytes one stream's frames may add up to.
    ///
    /// Every frame counts, terminal ones included: a stream costs the session what
    /// it sends, and the frame that ends it is one of the frames it sends.
    pub max_stream_bytes: u64,
    /// How many frames one stream may send, the terminal one included.
    pub max_stream_frames: u64,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_stream_actors: 64,
            max_pending_opens: 16,
            max_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
            max_stream_bytes: 16 * 1024 * 1024,
            max_stream_frames: 16 * 1024,
        }
    }
}

/// How many pulls one stream's actor may have queued.
///
/// The protocol allows one outstanding pull, so a queue deeper than one is slack
/// rather than a plan: a second pull is refused before it can be routed, and a
/// stream that neither produces nor stops is not a stream that may accumulate
/// demand for work it has not done.
const STREAM_PULL_CAPACITY: usize = 4;

/// The pull an actor is producing for, and the identity it was produced under.
struct ActivePull {
    /// The identity this pull was minted with.
    ///
    /// Monotonic per stream, so a result can be checked against the pull it
    /// claims to answer rather than against whichever pull happens to be active.
    pull_id: u64,
    /// The call the plugin made, which is what an answer has to name.
    host_call_id: String,
}

/// Where a stream is in its life.
///
/// Cancellation is not a state here, deliberately: a cancelled stream has no
/// actor at all, which is the same statement made more strongly — there is no
/// task left to hold the stream and so no transition back to `Open` to prevent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    /// The chain is being called and has not answered yet.
    Opening,
    /// The producer is open and waiting to be pulled.
    Open,
    /// A pull is being produced for.
    PullPending,
    /// The stream is over: it ended or failed, or it never opened.
    Terminal,
}

/// What the poll of one pull produced.
enum Produced {
    /// The stream was settled instead of producing: the actor stops.
    Settled,
    /// The call's deadline passed while the producer was still working.
    Expired,
    /// The producer answered, with an item, a failure, or the end.
    Next(Option<Result<nemo_relay::json::Json, nemo_relay::error::FlowError>>),
}

/// One result of a pull, in the shapes the wire takes.
enum PullResult {
    Data(nemo_relay::json::Json),
    End,
    Failed(PluginFailure),
}

/// The dispatcher's handle on one stream's actor.
struct StreamActorHandle {
    /// Where this stream's pulls go.
    ///
    /// Dropping the handle is how the dispatcher stops a stream: the actor reads
    /// its pulls closing as the stream going away, which is where a cancellation
    /// and a release both arrive, and which cannot be lost behind a full queue the
    /// way a message can.
    pulls: tokio::sync::mpsc::Sender<PluginStreamPullRequest>,
}

/// One session channel, driven.
pub struct SessionDriver {
    session_id: String,
    /// The session's own record of what its peer sent and what it sent back.
    ///
    /// Shared rather than owned because an actor records what it sends at the
    /// moment it sends it: the state machine is the session's memory, and the
    /// actor producing a stream is as much the session as the dispatcher is.
    state: Arc<Mutex<PluginSessionState>>,
    continuations: Arc<Continuations>,
    /// Where the messages this session owes the plugin are written.
    ///
    /// Unbounded on purpose, and bounded by the protocol instead: one outstanding
    /// pull per stream and a bounded number of streams means this holds at most
    /// one answer per stream, while the transport's own buffer still paces what
    /// reaches the plugin.
    writes: tokio::sync::mpsc::UnboundedSender<nemo_relay_plugin_proto::v1::PluginSessionMessage>,
    /// The actors this session has, by stream identity.
    actors: HashMap<String, StreamActorHandle>,
    /// How many actors are running right now.
    ///
    /// The map says what the session has routed to; this says what is still
    /// alive, which is the number that has to return to zero for a session that
    /// has drained — including actors whose entry has not been reaped yet.
    actors_alive: Arc<AtomicUsize>,
    limits: SessionLimits,
    /// Minted identities for the streams this kernel opens.
    opened: u64,
}

impl SessionDriver {
    /// Drive one session's channel.
    pub fn new(
        session_id: impl Into<String>,
        continuations: Arc<Continuations>,
        writes: tokio::sync::mpsc::UnboundedSender<
            nemo_relay_plugin_proto::v1::PluginSessionMessage,
        >,
    ) -> Self {
        Self::with_limits(session_id, continuations, writes, SessionLimits::default())
    }

    /// The same session, with its own ceilings on what it will hold.
    pub fn with_limits(
        session_id: impl Into<String>,
        continuations: Arc<Continuations>,
        writes: tokio::sync::mpsc::UnboundedSender<
            nemo_relay_plugin_proto::v1::PluginSessionMessage,
        >,
        limits: SessionLimits,
    ) -> Self {
        let session_id = session_id.into();
        Self {
            state: Arc::new(Mutex::new(PluginSessionState::new(session_id.clone()))),
            session_id,
            continuations,
            writes,
            actors: HashMap::new(),
            actors_alive: Arc::new(AtomicUsize::new(0)),
            limits,
            opened: 0,
        }
    }

    /// Handle one message, routing it to the actor that owns what it names.
    ///
    /// Nothing here awaits, which is the point: a message that starts work hands
    /// that work to an actor, and a message that settles a stream takes its actor
    /// away. A producer parked in `poll_next` therefore cannot delay this call,
    /// whichever stream it belongs to.
    ///
    /// `Err` is a protocol violation rather than a refusal the plugin can read:
    /// the state machine refused the message, which means the two sides no longer
    /// agree about this session, so the channel ends rather than continuing with
    /// one side's picture of it.
    pub fn handle(&mut self, message: PluginSessionMessage) -> Result<(), String> {
        self.reap();
        match message.message {
            PluginSessionPayload::StreamOpen(request) => self.open(request),
            PluginSessionPayload::StreamPull(pull) => self.pull(pull),
            PluginSessionPayload::StreamCancel(control) => {
                self.state()
                    .receive_cancel(&control)
                    .map_err(|error| error.failure.message)?;
                self.stop(&control.stream_id);
                Ok(())
            }
            PluginSessionPayload::StreamRelease(control) => {
                self.state()
                    .receive_release(&control)
                    .map_err(|error| error.failure.message)?;
                self.stop(&control.stream_id);
                Ok(())
            }
            other => Err(format!(
                "a session message the kernel does not receive from a host: {other:?}"
            )),
        }
    }

    /// How many actors this session is running right now.
    ///
    /// Zero is a session that has drained: every stream it served has ended, been
    /// cancelled, or been released, and the task that was producing for it is
    /// gone with it.
    pub fn actors_alive(&self) -> usize {
        self.actors_alive.load(Ordering::SeqCst)
    }

    /// How many streams this session is serving, with the finished ones reaped.
    pub fn served_streams(&mut self) -> usize {
        self.reap();
        self.actors.len()
    }

    /// The session's own record, for the one operation that reads it.
    fn state(&self) -> std::sync::MutexGuard<'_, PluginSessionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Send one message to the plugin.
    ///
    /// A message the session decided to send is one the plugin is waiting for, so
    /// the only failure to answer is that there is no session left to send it to.
    fn answer(&self, payload: PluginSessionPayload) {
        // The dispatcher's own messages are not frames of a stream — they are the
        // answers to opens — so they are converted here and measured nowhere: a
        // stream's ceilings bound what a stream sends.
        let _ = self
            .writes
            .send(nemo_relay_plugin_proto::convert::session_message_to_wire(
                &PluginSessionMessage {
                    session_id: self.session_id.clone(),
                    message: payload,
                },
            ));
    }

    /// Forget the actors that have finished.
    ///
    /// An actor's pulls close when its task ends, so this is the exact moment
    /// its stream is over. Keeping a finished actor's entry would let a
    /// long-lived session's registry grow with every stream it ever served, and
    /// would hold a place inside the ceiling the session bounds its actors by.
    fn reap(&mut self) {
        self.actors.retain(|_, actor| !actor.pulls.is_closed());
    }

    /// Stop producing for a stream and drop the producer behind it.
    ///
    /// The session's record has already settled the stream; what is left is the
    /// work. Dropping the handle closes the actor's pulls, which its select reads
    /// as the stream going away — so the actor drops the poll it was in and then
    /// the producer, and a cancellation reaches the work behind the stream rather
    /// than a token inside it.
    fn stop(&mut self, stream_id: &str) {
        self.actors.remove(stream_id);
    }

    /// Take on the stream an operation asked for.
    ///
    /// The actor opens it, because calling the chain a plugin is wrapping can
    /// take as long as the provider behind it and this dispatcher has other
    /// messages to serve. What the dispatcher decides is whether the session may
    /// take the work on at all, which is why the ceilings are checked here.
    fn open(&mut self, request: PluginStreamOpenRequest) -> Result<(), String> {
        // A session at its ceiling refuses the work rather than holding it, and
        // the ceilings are read before the session's record takes the open on: an
        // open this session will not run is not one it owes a stream.
        let refusal = if self.actors.len() >= self.limits.max_stream_actors {
            Some(format!(
                "this session is already serving {} streams",
                self.limits.max_stream_actors
            ))
        } else if self.state().pending_opens() >= self.limits.max_pending_opens {
            Some(format!(
                "this session already has {} opens in flight",
                self.limits.max_pending_opens
            ))
        } else {
            None
        };
        if let Some(message) = refusal {
            // The refusal is still an answer to the call, so the record claims the
            // call and settles it in the same breath: an identity is claimed even
            // when the work is refused, or a peer could reuse it for other work
            // while the plugin still believes the first call is unanswered.
            let mut state = self.state();
            state
                .receive_open_request(&request)
                .map_err(|error| error.failure.message)?;
            let failed = PluginStreamOpenFailed {
                host_call_id: request.host_call_id.clone(),
                failure: PluginFailure {
                    code: PluginFailureCode::Rejected,
                    message,
                },
            };
            state
                .send_open_failed(&failed)
                .map_err(|error| error.failure.message)?;
            drop(state);
            self.answer(PluginSessionPayload::StreamOpenFailed(failed));
            return Ok(());
        }

        self.state()
            .receive_open_request(&request)
            .map_err(|error| error.failure.message)?;
        self.opened += 1;
        let stream_id = format!("{}-{}", request.operation_request_id, self.opened);

        let (pulls, scheduled) = tokio::sync::mpsc::channel(STREAM_PULL_CAPACITY);
        let actor = StreamActor {
            session_id: self.session_id.clone(),
            stream_id: stream_id.clone(),
            request,
            continuations: Arc::clone(&self.continuations),
            state: Arc::clone(&self.state),
            writes: self.writes.clone(),
            pulls: scheduled,
            producer: None,
            lifecycle: Lifecycle::Opening,
            active_pull: None,
            next_pull_id: 1,
            deadline: None,
            outcome: None,
            credit: 0,
            spent_bytes: 0,
            spent_frames: 0,
            limits: self.limits,
            alive: Arc::clone(&self.actors_alive),
        };
        self.actors.insert(stream_id, StreamActorHandle { pulls });
        self.actors_alive.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let mut actor = actor;
            // A panic is contained here rather than allowed to take the task down
            // silently: the stream settles with what happened, its producer is
            // dropped, and the session keeps serving its other streams.
            let outcome = FutureExt::catch_unwind(AssertUnwindSafe(actor.serve())).await;
            if let Err(payload) = outcome {
                actor.failed(panic_message(payload.as_ref()));
            }
        });
        Ok(())
    }

    /// Route a pull to the stream's actor.
    fn pull(&mut self, pull: PluginStreamPullRequest) -> Result<(), String> {
        self.state()
            .receive_pull(&pull)
            .map_err(|error| error.failure.message)?;
        let actor = self.actors.get(&pull.stream_id).ok_or_else(|| {
            format!(
                "stream '{}' is open in this session but has no producer here",
                pull.stream_id
            )
        })?;
        // One pull at a time is the session's rule and its record has just
        // checked it, so this queue holds the pull being routed and nothing else:
        // the actor consumes it before the next pull can be accepted. A queue
        // that is full or closed would mean the actor and the record disagree,
        // which is a session this kernel cannot serve.
        actor.pulls.try_send(pull).map_err(|error| match error {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                "this session routed a pull to a stream that had not produced the last one"
                    .to_string()
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                "this session routed a pull to a stream whose producer has already gone".to_string()
            }
        })
    }
}

/// What a panic said, for a failure the plugin can read.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "the stream's producer panicked".to_string())
}

/// A future that completes when a deadline passes, if there is one.
///
/// Taken as a value rather than read from the actor so that the wait can be raced
/// against the producer the actor is holding: both are what the select needs, and
/// neither borrows the other.
async fn expires(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        // No deadline is not a deadline that never passes: it is nothing to wait
        // for, so this never completes.
        None => std::future::pending().await,
    }
}

/// The failure that says a stream ran out of the call's time.
fn deadline_failure(message: &str) -> PluginFailure {
    PluginFailure {
        code: PluginFailureCode::DeadlineExceeded,
        message: message.to_string(),
    }
}

/// When a budget's deadline lands, in this task's own clock.
///
/// A budget carries an absolute deadline in Unix milliseconds because it travels;
/// a task waits on its own clock, so the two are reconciled once, here, where the
/// stream takes the call's deadline for its own.
fn deadline_of(budget: &nemo_relay::api::runtime::ExecutionBudget) -> Option<tokio::time::Instant> {
    let deadline = budget.deadline_unix_ms?;
    let remaining = deadline.saturating_sub(nemo_relay::api::runtime::budget_now_unix_ms());
    Some(tokio::time::Instant::now() + std::time::Duration::from_millis(remaining))
}

/// One stream, owned by the task that produces it.
///
/// Everything a stream needs to be produced lives here and nowhere else: the
/// producer, where the stream is in its life, the pull being produced for, and
/// the identity the next pull will have. Nothing outside this task can produce
/// for the stream, which is why "one outstanding pull" is a property of the
/// session's shape rather than a rule two tasks have to keep agreeing on.
struct StreamActor {
    session_id: String,
    stream_id: String,
    /// The open this actor is answering, kept for the failure a stream that
    /// never opened owes its caller.
    request: PluginStreamOpenRequest,
    continuations: Arc<Continuations>,
    state: Arc<Mutex<PluginSessionState>>,
    /// Where this stream's frames go, already in the form they cross in: a frame
    /// is measured before it is sent, so it is converted where it is measured.
    writes: tokio::sync::mpsc::UnboundedSender<nemo_relay_plugin_proto::v1::PluginSessionMessage>,
    /// The pulls the plugin has made, in the order the session accepted them.
    ///
    /// One at a time, because the session's record refuses a second pull while
    /// one is outstanding — so this is the demand for this stream and not a queue
    /// of it.
    pulls: tokio::sync::mpsc::Receiver<PluginStreamPullRequest>,
    /// The stream the wrapped chain answered with, once it has.
    producer: Option<LlmJsonStream>,
    lifecycle: Lifecycle,
    /// The pull being produced for, while one is outstanding.
    active_pull: Option<ActivePull>,
    /// The identity the next pull this actor produces for will have.
    next_pull_id: u64,
    /// When this stream must be over, if the operation it belongs to has a
    /// deadline.
    ///
    /// Taken from the budget the chain position was parked under, which is the
    /// call's: a stream is part of the call whose chain it wraps, so it may not
    /// outlive the call's deadline. A deadline already past is one the stream is
    /// over before it produces anything.
    deadline: Option<tokio::time::Instant>,
    /// What ended this stream, when it ended with something the plugin has not been
    /// told yet.
    ///
    /// A deadline can pass while nothing is outstanding, and there is no frame to
    /// attach the ending to: the next pull is what the plugin learns on, so the
    /// failure is held rather than sent unsolicited. Nothing is produced behind it
    /// — the producer is already gone.
    outcome: Option<PluginFailure>,
    /// How many frames the consumer has asked for and not been answered.
    ///
    /// This is the whole of this stream's demand accounting. A pull grants one
    /// frame's worth and never more — the session's record refuses a second pull
    /// while one is outstanding, so `initial_credit = 1` is the strongest demand
    /// the protocol can express, and it is a grant rather than a head start: a
    /// stream the plugin has not asked about has no credit and is not polled.
    credit: u64,
    /// What this stream's frames have cost, in encoded bytes and in frames.
    spent_bytes: u64,
    spent_frames: u64,
    /// The ceilings this session holds the stream to.
    limits: SessionLimits,
    /// The session's count of actors that are running.
    alive: Arc<AtomicUsize>,
}

impl Drop for StreamActor {
    fn drop(&mut self) {
        // Dropping the actor is what drops the producer, and the count is what
        // makes that observable: a session that has drained is one where the work
        // behind every stream is gone, not one where a message about stopping was
        // sent.
        self.alive.fetch_sub(1, Ordering::SeqCst);
    }
}

impl StreamActor {
    /// The session's own record, for the one operation that reads it.
    fn state(&self) -> std::sync::MutexGuard<'_, PluginSessionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The frame one message becomes, if this session's ceilings will carry it.
    ///
    /// Everything a stream sends is measured here — the frame that opens it, its
    /// data, the failure that ends it and the terminal frame alike — because a
    /// stream costs the session what it sends and the frame that ends it is one of
    /// the frames it sends. Nothing is charged here: a frame is charged when it is
    /// sent, and a frame the session turns out not to owe is one it never sent.
    fn measured(
        &self,
        payload: &PluginSessionPayload,
    ) -> Result<(nemo_relay_plugin_proto::v1::PluginSessionMessage, u64), PluginFailure> {
        let frame =
            nemo_relay_plugin_proto::convert::session_message_to_wire(&PluginSessionMessage {
                session_id: self.session_id.clone(),
                message: payload.clone(),
            });
        let encoded = nemo_relay_plugin_proto::convert::session_message_encoded_len(&frame) as u64;
        if encoded > u64::from(self.limits.max_frame_bytes) {
            return Err(PluginFailure {
                code: PluginFailureCode::OversizedFrame {
                    observed: encoded,
                    limit: self.limits.max_frame_bytes,
                },
                message: format!(
                    "this stream produced a frame of {encoded} bytes, above the {} bytes this \
                     session will send",
                    self.limits.max_frame_bytes
                ),
            });
        }
        if self.spent_bytes + encoded > self.limits.max_stream_bytes {
            return Err(PluginFailure {
                code: PluginFailureCode::Rejected,
                message: format!(
                    "this stream has reached its {}-byte budget: the next frame would make it {}",
                    self.limits.max_stream_bytes,
                    self.spent_bytes + encoded
                ),
            });
        }
        if self.spent_frames + 1 > self.limits.max_stream_frames {
            return Err(PluginFailure {
                code: PluginFailureCode::Rejected,
                message: format!(
                    "this stream has reached its budget of {} frames",
                    self.limits.max_stream_frames
                ),
            });
        }
        Ok((frame, encoded))
    }

    /// Charge a measured frame to the stream and send it.
    fn dispatch(&mut self, frame: nemo_relay_plugin_proto::v1::PluginSessionMessage, cost: u64) {
        self.spent_bytes += cost;
        self.spent_frames += 1;
        let _ = self.writes.send(frame);
    }

    /// Record what this session is sending, or report that its two halves
    /// disagree.
    ///
    /// A record that refuses a message the actor decided to send is not a peer
    /// misbehaving: it is this session's own bookkeeping disagreeing with itself.
    /// The panic is caught where the actor runs, so the stream settles with a
    /// failure and the session keeps serving its others — which is the outcome to
    /// prefer over a stream that failed silently and a peer that waits forever.
    fn record(
        &self,
        recorded: Result<(), nemo_relay_plugin_protocol::PluginProtocolError>,
        what: &str,
    ) {
        if let Err(error) = recorded {
            panic!(
                "this session refused the {what} it was sending: {}",
                error.failure.message
            );
        }
    }

    /// Open the stream this actor was created for, then serve its pulls.
    async fn serve(&mut self) {
        match self.open_upstream().await {
            Ok(producer) => {
                // The record comes first: the plugin may pull the moment it sees
                // the opening, and a pull the session has not recorded an open
                // for is one it has to refuse.
                let opened = PluginStreamOpened {
                    host_call_id: self.request.host_call_id.clone(),
                    stream_id: self.stream_id.clone(),
                };
                let opening =
                    match self.measured(&PluginSessionPayload::StreamOpened(opened.clone())) {
                        Ok(measured) => measured,
                        // The frame that opens the stream does not fit this
                        // session's ceilings, so the stream can never be announced
                        // and never be used: it is settled unopened, which is the
                        // outcome that leaves nothing owing and nothing producing.
                        Err(crossed) => {
                            self.fail_open(PluginFailure {
                                code: crossed.code,
                                message: format!("the stream was not opened: {}", crossed.message),
                            });
                            return;
                        }
                    };
                self.record(self.state().send_opened(&opened), "opening");
                self.producer = Some(producer);
                self.lifecycle = Lifecycle::Open;
                self.dispatch(opening.0, opening.1);
            }
            Err(failure) => {
                self.fail_open(failure);
                return;
            }
        }

        loop {
            // Credit is what says there is demand. A producer nobody has asked
            // about is one the actor does not poll, so a stream's cost is bounded
            // by its consumer's appetite rather than by its producer's — and a
            // stream whose consumer has stopped asking waits here rather than
            // running ahead of it.
            if let Some(outcome) = self.outcome.clone() {
                // The stream is over and the plugin has not been told. The pull it
                // makes now is what it is told on: the failure is the answer to
                // that demand rather than a message nobody asked for.
                let Some(pull) = self.pulls.recv().await else {
                    return;
                };
                self.grant(pull);
                let granted = self.active_pull.take().expect("a granted pull");
                self.fail(granted, outcome);
                return;
            }
            if self.credit == 0 {
                let deadline = self.deadline;
                let pull = tokio::select! {
                    biased;
                    // The call's deadline does not wait for demand: a stream whose
                    // operation has run out of time is over whether or not its
                    // consumer is still asking, and the producer goes with it.
                    () = expires(deadline) => {
                        self.expire();
                        continue;
                    }
                    pull = self.pulls.recv() => pull,
                };
                let Some(pull) = pull else {
                    // The session let this stream go without saying so — the handle
                    // closing is the same instruction as a cancellation, and the one
                    // that cannot be lost behind a queue.
                    return;
                };
                self.grant(pull);
            }
            if !self.produce().await {
                return;
            }
        }
    }

    /// Take one pull's worth of demand.
    ///
    /// One pull is one frame's worth, and the session's record refuses a second
    /// pull while one is outstanding: the grant is one, so N is one.
    fn grant(&mut self, pull: PluginStreamPullRequest) {
        self.active_pull = Some(ActivePull {
            pull_id: self.next_pull_id,
            host_call_id: pull.host_call_id,
        });
        self.next_pull_id += 1;
        self.credit = 1;
    }

    /// Settle a stream whose deadline passed while nothing was outstanding.
    ///
    /// The producer is dropped — the call's time is up, so the work behind the
    /// stream is over — and what ended the stream is held for the next pull, which
    /// is the message the plugin will read it in. Nothing is sent unsolicited: a
    /// stream's frames are answers to demand, and the ending is one of them.
    fn expire(&mut self) {
        self.producer = None;
        self.lifecycle = Lifecycle::Terminal;
        self.outcome = Some(deadline_failure(
            "the operation's deadline passed before the stream produced what was asked for",
        ));
    }

    /// Call the chain the plugin is wrapping and take the stream it answers with.
    ///
    /// Raced against the session ending, because the chain is not this actor's
    /// to wait for once there is no session left to answer.
    async fn open_upstream(&mut self) -> Result<LlmJsonStream, PluginFailure> {
        let refusal = |message: String| PluginFailure {
            code: PluginFailureCode::Rejected,
            message,
        };
        let parked = self
            .continuations
            .parked(&self.request.operation_request_id)
            .ok_or_else(|| {
                refusal(format!(
                    "no chain is parked for operation '{}', so there is no stream to open",
                    self.request.operation_request_id
                ))
            })?;
        // The call's deadline, taken before the chain is called: an open that
        // blocks past it never becomes a stream.
        self.deadline = parked.budget.as_ref().and_then(deadline_of);
        let ParkedChain::LlmStream(next) = parked.chain else {
            return Err(refusal(format!(
                "operation '{}' holds a {} position, which has no downstream stream",
                self.request.operation_request_id,
                match parked.chain {
                    ParkedChain::Tool(_) => "tool",
                    ParkedChain::Llm(_) => "provider",
                    ParkedChain::LlmStream(_) => unreachable!("matched above"),
                }
            )));
        };
        let provider_request: LlmRequest = serde_json::from_str(&self.request.request_json)
            .map_err(|error| {
                refusal(format!(
                    "an open request must carry a provider request: {error}"
                ))
            })?;

        let deadline = self.deadline;
        let opened = tokio::select! {
            biased;
            _ = self.pulls.recv() => Err(refusal(
                "the session ended before the stream opened".to_string(),
            )),
            // The chain is downstream work, and it is the call's deadline that
            // bounds it: an open still blocked when the call's time is up never
            // becomes a stream.
            () = expires(deadline) => Err(deadline_failure(
                "the operation's deadline passed while the chain that opens this \
                 stream was still blocked",
            )),
            opened = next(provider_request) => {
                opened.map_err(|error| refusal(error.to_string()))
            }
        };
        opened
    }

    /// Report that the stream never opened.
    fn fail_open(&mut self, failure: PluginFailure) {
        let failed = PluginStreamOpenFailed {
            host_call_id: self.request.host_call_id.clone(),
            failure,
        };
        let payload = PluginSessionPayload::StreamOpenFailed(failed.clone());
        // Measured like every other frame: the failure is a frame this session
        // sends, and one that does not fit its ceiling is one that cannot cross.
        let measured = self.measured(&payload);
        // A stream that failed silently would be worse than a session whose
        // record disagrees with what it sent, so the message is what is owed and
        // the record is made whether or not the frame can cross.
        self.record(self.state().send_open_failed(&failed), "open failure");
        if let Ok((frame, cost)) = measured {
            self.dispatch(frame, cost);
        }
        self.lifecycle = Lifecycle::Terminal;
    }

    /// Produce the next frame of the pull the actor is holding, or settle without
    /// one.
    ///
    /// The poll runs against the two things that take a stream away from it — the
    /// plugin stopping and the session ending — because a cancellation must not
    /// wait for a producer that never yields. `biased` is what makes that a rule
    /// rather than a race: a cancellation that arrived while the producer was
    /// also ready is the one that decides, so which of the two the runtime
    /// happened to notice first cannot change whether the stream is cancelled.
    ///
    /// Answers whether the actor has more to serve.
    async fn produce(&mut self) -> bool {
        let deadline = self.deadline;
        let Some(producer) = self.producer.as_mut() else {
            return false;
        };
        let Some(pull_id) = self.active_pull.as_ref().map(|pull| pull.pull_id) else {
            return false;
        };
        self.lifecycle = Lifecycle::PullPending;

        let produced = {
            let pulls = &mut self.pulls;
            tokio::select! {
                biased;
                scheduled = pulls.recv() => match scheduled {
                    // Dropping this future is what cancels the poll: the producer
                    // is not asked to notice, it is stopped.
                    None => Produced::Settled,
                    Some(_) => panic!(
                        "this session refuses a second pull before it routes one, so an actor \
                         producing for a pull cannot be handed another"
                    ),
                },
                // The deadline bounds the work, so a producer that is still
                // blocking when the call's time is up is a producer whose frame
                // will never be the answer to this pull.
                () = expires(deadline) => Produced::Expired,
                item = producer.next() => Produced::Next(item),
            }
        };

        match produced {
            Produced::Settled => false,
            Produced::Expired => {
                let Some(active) = self.active_pull.take() else {
                    return false;
                };
                self.fail(
                    active,
                    deadline_failure(
                        "the operation's deadline passed while the downstream stream was \
                         producing the frame this pull asked for",
                    ),
                );
                false
            }
            Produced::Next(Some(Ok(chunk))) => self.deliver(pull_id, PullResult::Data(chunk)),
            Produced::Next(Some(Err(error))) => self.deliver(
                pull_id,
                PullResult::Failed(PluginFailure {
                    code: PluginFailureCode::Rejected,
                    message: error.to_string(),
                }),
            ),
            Produced::Next(None) => self.deliver(pull_id, PullResult::End),
        }
    }

    /// Record a result against the pull it was produced for, and send it on.
    ///
    /// The identity is checked rather than assumed: a result belongs to the pull
    /// it was produced for, and a stale result delivered against a fresh pull
    /// would be an answer nobody asked for. Whether the stream is still waiting
    /// for that pull, and the record of the answer, are one critical section —
    /// a cancellation that settled the pull in between would otherwise let the
    /// session record an answer to a call it has already closed.
    ///
    /// Answers whether the actor has more to serve.
    fn deliver(&mut self, pull_id: u64, result: PullResult) -> bool {
        let Some(active) = self.active_pull.take() else {
            return false;
        };
        if active.pull_id != pull_id {
            return false;
        }
        let terminal = !matches!(result, PullResult::Data(_));
        let payload = match result {
            PullResult::Data(chunk) => PluginSessionPayload::StreamItem(PluginStreamItem {
                host_call_id: active.host_call_id.clone(),
                stream_id: self.stream_id.clone(),
                chunk_json: chunk.to_string(),
            }),
            PullResult::End => PluginSessionPayload::StreamEnd(PluginStreamEnd {
                host_call_id: active.host_call_id.clone(),
                stream_id: self.stream_id.clone(),
            }),
            PullResult::Failed(failure) => PluginSessionPayload::StreamFailed(PluginStreamFailed {
                host_call_id: active.host_call_id.clone(),
                stream_id: self.stream_id.clone(),
                failure,
            }),
        };
        // A frame this session's ceilings refuse ends the stream rather than
        // crossing it: the ceiling is what the work is bounded by, so the work is
        // what stops.
        let measured = match self.measured(&payload) {
            Ok(measured) => measured,
            Err(refusal) => {
                self.fail(active, refusal);
                return false;
            }
        };
        // The record and the send are one step, and the frame is charged only
        // once the session has recorded the answer it is: a stream the session
        // settled while its producer was finishing is owed nothing, and its last
        // frame is stale rather than sent.
        if !self
            .state()
            .settle_pull(&self.stream_id, &active.host_call_id, terminal)
        {
            // The stream was cancelled or released while its producer was
            // finishing. The result is stale: it belongs to a call nobody is
            // waiting for, and discarding it is what lets a cancellation settle a
            // stream without the session reading its last frame as a violation.
            return false;
        }
        self.lifecycle = if terminal {
            Lifecycle::Terminal
        } else {
            Lifecycle::Open
        };
        // A data frame spends the credit it was produced under; the terminal frame
        // is what the pull was for, so it needs none.
        if !terminal {
            self.credit = self.credit.saturating_sub(1);
        }
        self.dispatch(measured.0, measured.1);
        !terminal
    }

    /// Settle a stream that crossed a ceiling of this session.
    ///
    /// The stream is over and its producer is dropped: a ceiling is what bounds the
    /// work, so the work is what stops. The failure is a frame like any other —
    /// measured, charged, and sent only if it fits — and the session's record is
    /// settled even when that frame does not fit, because a session that owes an
    /// answer it can never deliver is worse than one whose ceiling could not carry
    /// the settlement.
    fn fail(&mut self, pull: ActivePull, failure: PluginFailure) {
        let failed = PluginStreamFailed {
            host_call_id: pull.host_call_id.clone(),
            stream_id: self.stream_id.clone(),
            failure,
        };
        let payload = PluginSessionPayload::StreamFailed(failed.clone());
        match self.measured(&payload) {
            Ok((frame, cost)) => {
                if self
                    .state()
                    .settle_pull(&self.stream_id, &pull.host_call_id, true)
                {
                    self.dispatch(frame, cost);
                }
            }
            Err(_) => {
                self.state()
                    .settle_pull(&self.stream_id, &pull.host_call_id, true);
            }
        }
        self.lifecycle = Lifecycle::Terminal;
    }

    /// Settle a stream whose actor panicked.
    ///
    /// Plugin code runs behind the ABI, so a panic in it must not take the session
    /// with it: the stream settles with what happened and every other stream keeps
    /// being served. What is settled depends on where the stream was — an open
    /// that never answered, a pull that was being produced for, or nothing that
    /// anyone is waiting on.
    fn failed(&mut self, message: String) {
        let failure = PluginFailure {
            code: PluginFailureCode::Rejected,
            message: format!(
                "the producer for operation '{}' panicked: {message}",
                self.request.operation_request_id
            ),
        };
        match self.lifecycle {
            Lifecycle::Opening => {
                let failed = PluginStreamOpenFailed {
                    host_call_id: self.request.host_call_id.clone(),
                    failure,
                };
                let payload = PluginSessionPayload::StreamOpenFailed(failed.clone());
                let measured = self.measured(&payload);
                // Best effort: a panic is already the case where the session's
                // record and the actor may disagree, and the plugin is owed the
                // failure either way.
                let _ = self.state().send_open_failed(&failed);
                if let Ok((frame, cost)) = measured {
                    self.dispatch(frame, cost);
                }
            }
            Lifecycle::PullPending => {
                let Some(pull) = self.active_pull.take() else {
                    return;
                };
                let failed = PluginStreamFailed {
                    host_call_id: pull.host_call_id.clone(),
                    stream_id: self.stream_id.clone(),
                    failure,
                };
                let payload = PluginSessionPayload::StreamFailed(failed.clone());
                let measured = self.measured(&payload);
                if self
                    .state()
                    .settle_pull(&self.stream_id, &pull.host_call_id, true)
                    && let Ok((frame, cost)) = measured
                {
                    self.dispatch(frame, cost);
                }
            }
            // Nothing is outstanding, so nothing is owed: the stream is dropped
            // and the session is none the wiser.
            Lifecycle::Open | Lifecycle::Terminal => {}
        }
        self.lifecycle = Lifecycle::Terminal;
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

    /// One session under test, with the answers it owes readable as messages.
    struct Session {
        driver: SessionDriver,
        continuations: Arc<Continuations>,
        written:
            tokio::sync::mpsc::UnboundedReceiver<nemo_relay_plugin_proto::v1::PluginSessionMessage>,
        /// Set by a producer that says when it is dropped.
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Session {
        fn new() -> Self {
            Self::with_limits(SessionLimits::default())
        }

        fn with_limits(limits: SessionLimits) -> Self {
            let continuations = Arc::new(Continuations::new());
            let (writes, written) = tokio::sync::mpsc::unbounded_channel();
            Self {
                driver: SessionDriver::with_limits(
                    "session-1",
                    Arc::clone(&continuations),
                    writes,
                    limits,
                ),
                continuations,
                written,
                dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }

        /// Park a chain position that answers with `producer`.
        fn park(&self, operation: &str, producer: LlmStreamExecutionNextFn) {
            // Held for the session's life: the guard borrows the registry, and
            // the session takes the shared handle.
            std::mem::forget(self.continuations.hold_llm_stream(
                operation,
                "registration-1",
                producer,
            ));
        }

        /// Park a position of the tool family, which has no downstream stream.
        fn park_tool(&self, operation: &str, next: nemo_relay::api::runtime::ToolExecutionNextFn) {
            std::mem::forget(
                self.continuations
                    .hold_tool(operation, "registration-1", next),
            );
        }

        /// A producer that produces `chunks` and then ends, saying when it is
        /// dropped.
        fn park_producing(&self, operation: &str, chunks: Vec<serde_json::Value>) {
            let dropped = Arc::clone(&self.dropped);
            self.park(operation, watched(chunks, dropped));
        }

        /// A producer whose first poll never resolves.
        fn park_pending(&self, operation: &str) {
            let dropped = Arc::clone(&self.dropped);
            self.park(operation, never(dropped));
        }

        /// A producer whose first poll never resolves, with a sentinel of its own.
        fn park_pending_watched(&self, operation: &str) -> Arc<std::sync::atomic::AtomicBool> {
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            self.park(operation, never(Arc::clone(&dropped)));
            dropped
        }

        /// A producer that never yields, under a budget whose deadline is short
        /// enough to fire while the stream is being pulled.
        async fn park_gated_watched(&self, operation: &str) -> Arc<std::sync::atomic::AtomicBool> {
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let producer = never(Arc::clone(&dropped));
            let continuations = Arc::clone(&self.continuations);
            let operation = operation.to_owned();
            let millis = 50_u64;
            let now = nemo_relay::api::runtime::budget_now_unix_ms();
            nemo_relay::api::runtime::with_execution_budget(
                nemo_relay::api::runtime::ExecutionBudget::new(now + millis, millis),
                async move {
                    std::mem::forget(continuations.hold_llm_stream(
                        &operation,
                        "registration-1",
                        producer,
                    ));
                },
            )
            .await;
            dropped
        }

        /// A producer that produces `chunks` and then ends, with a sentinel of its
        /// own.
        fn park_watched(
            &self,
            operation: &str,
            chunks: Vec<serde_json::Value>,
        ) -> Arc<std::sync::atomic::AtomicBool> {
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            self.park(operation, watched(chunks, Arc::clone(&dropped)));
            dropped
        }

        /// Park a chain position under a budget whose deadline is `after` from now.
        ///
        /// The budget is the call's, and it is the call's deadline the stream
        /// inherits: a stream is part of the call whose chain it wraps, so it may
        /// not outlive it.
        async fn park_until(
            &self,
            operation: &str,
            producer: LlmStreamExecutionNextFn,
            after: std::time::Duration,
        ) {
            let millis = u64::try_from(after.as_millis()).expect("a deadline in milliseconds");
            let now = nemo_relay::api::runtime::budget_now_unix_ms();
            let continuations = Arc::clone(&self.continuations);
            let operation = operation.to_owned();
            nemo_relay::api::runtime::with_execution_budget(
                nemo_relay::api::runtime::ExecutionBudget::new(now + millis, millis),
                async move {
                    std::mem::forget(continuations.hold_llm_stream(
                        &operation,
                        "registration-1",
                        producer,
                    ));
                },
            )
            .await;
        }

        /// Wait until a producer's own sentinel says it was dropped.
        async fn await_sentinel(&self, sentinel: &std::sync::atomic::AtomicBool, stream: &str) {
            let dropped = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !sentinel.load(std::sync::atomic::Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
            })
            .await;
            assert!(dropped.is_ok(), "{stream} dropped its producer");
        }

        /// Wait until a producer says it was dropped.
        async fn await_dropped(&self) {
            let dropped = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !self.dropped.load(std::sync::atomic::Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
            })
            .await;
            assert!(dropped.is_ok(), "the producer behind the stream is dropped");
        }

        /// A producer that says how many times it was polled, and when it was
        /// dropped.
        fn park_counting(
            &self,
            operation: &str,
            chunks: Vec<serde_json::Value>,
        ) -> Arc<std::sync::atomic::AtomicUsize> {
            let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            self.park(
                operation,
                counted(chunks, Arc::clone(&polls), Arc::clone(&self.dropped)),
            );
            polls
        }

        fn handle(&mut self, payload: PluginSessionPayload) -> Result<(), String> {
            self.driver.handle(PluginSessionMessage {
                session_id: "session-1".into(),
                message: payload,
            })
        }

        fn open(&mut self, call: &str, operation: &str) -> Result<(), String> {
            self.handle(PluginSessionPayload::StreamOpen(PluginStreamOpenRequest {
                host_call_id: call.into(),
                operation_request_id: operation.into(),
                request_json: serde_json::to_string(&request(serde_json::json!({"model": "x"})))
                    .expect("a request"),
            }))
        }

        fn pull(&mut self, call: &str, stream_id: &str) -> Result<(), String> {
            self.handle(PluginSessionPayload::StreamPull(PluginStreamPullRequest {
                host_call_id: call.into(),
                stream_id: stream_id.into(),
            }))
        }

        fn control(
            &mut self,
            payload: impl FnOnce(PluginStreamControl) -> PluginSessionPayload,
            call: &str,
            stream_id: &str,
        ) -> Result<(), String> {
            self.handle(payload(PluginStreamControl {
                host_call_id: call.into(),
                stream_id: stream_id.into(),
            }))
        }

        fn cancel(&mut self, call: &str, stream_id: &str) -> Result<(), String> {
            self.control(PluginSessionPayload::StreamCancel, call, stream_id)
        }

        fn release(&mut self, call: &str, stream_id: &str) -> Result<(), String> {
            self.control(PluginSessionPayload::StreamRelease, call, stream_id)
        }

        /// The next message the session owes the plugin.
        async fn answer(&mut self) -> PluginSessionPayload {
            let answer =
                tokio::time::timeout(std::time::Duration::from_secs(5), self.written.recv())
                    .await
                    .expect("an answer within the time a session is allowed to take")
                    .expect("a message");
            let answer = nemo_relay_plugin_proto::convert::session_message_from_wire(&answer)
                .expect("a converted answer");
            assert_eq!(answer.session_id, "session-1");
            answer.message
        }

        /// Open a stream and take its identity.
        async fn opened(&mut self, call: &str, operation: &str) -> String {
            self.open(call, operation).expect("an open request");
            match self.answer().await {
                PluginSessionPayload::StreamOpened(opened) => {
                    assert_eq!(opened.host_call_id, call);
                    opened.stream_id
                }
                other => panic!("the kernel opens the stream: {other:?}"),
            }
        }

        /// Wait for the session's actors to be gone.
        async fn actors_gone(&self) {
            let gone = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while self.driver.actors_alive() != 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await;
            assert!(gone.is_ok(), "every actor the session started is gone");
        }

        /// The same, and the producer behind the stream is gone with it.
        async fn drained(&self) {
            self.actors_gone().await;
            assert!(
                self.dropped.load(std::sync::atomic::Ordering::SeqCst),
                "the producer behind the stream was dropped"
            );
        }

        /// Whether the stream's actor has stopped.
        fn stream_stopped(&self, stream_id: &str) -> bool {
            match self.driver.actors.get(stream_id) {
                Some(actor) => actor.pulls.is_closed(),
                None => true,
            }
        }

        /// Drive a stream with pulls until its actor stops, answering what crossed.
        ///
        /// Each pull is one frame's worth of demand, so a test that wants to see a
        /// stream's frames asks for them. A stream that stops producing — because it
        /// ended, or because a ceiling refused a frame it could not send — leaves an
        /// actor that is gone rather than one that is waiting, which is how this
        /// knows to stop asking.
        async fn drive(&mut self, stream_id: &str, up_to: usize) -> Vec<PluginSessionPayload> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut crossed = Vec::new();
            for index in 0..up_to {
                if self.stream_stopped(stream_id) {
                    break;
                }
                if self
                    .pull(&format!("pull-{}", index + 1), stream_id)
                    .is_err()
                {
                    break;
                }
                let answered = loop {
                    if let Ok(answer) = self.written.try_recv() {
                        break Some(answer);
                    }
                    if self.stream_stopped(stream_id) {
                        break None;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the stream answers a pull or stops without one"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                };
                let Some(answered) = answered else { break };
                let answered =
                    nemo_relay_plugin_proto::convert::session_message_from_wire(&answered)
                        .expect("a converted answer");
                let terminal = matches!(
                    answered.message,
                    PluginSessionPayload::StreamEnd(_) | PluginSessionPayload::StreamFailed(_)
                );
                crossed.push(answered.message);
                if terminal {
                    break;
                }
            }
            crossed
        }
    }

    fn request(content: serde_json::Value) -> LlmRequest {
        LlmRequest {
            headers: serde_json::Map::new(),
            content,
        }
    }

    /// A chain position whose stream produces `chunks` and then ends, with the
    /// producer's lifetime observable.
    fn watched(
        chunks: Vec<serde_json::Value>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    ) -> LlmStreamExecutionNextFn {
        /// A producer that says when it is gone.
        struct Watched {
            items: std::vec::IntoIter<serde_json::Value>,
            dropped: Arc<std::sync::atomic::AtomicBool>,
        }
        impl tokio_stream::Stream for Watched {
            type Item = Result<nemo_relay::json::Json, nemo_relay::error::FlowError>;
            fn poll_next(
                mut self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                std::task::Poll::Ready(self.items.next().map(Ok))
            }
        }
        impl Drop for Watched {
            fn drop(&mut self) {
                self.dropped
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        Arc::new(move |_request| {
            let chunks = chunks.clone();
            let dropped = Arc::clone(&dropped);
            Box::pin(async move {
                Ok(LlmJsonStream::new(Watched {
                    items: chunks.into_iter(),
                    dropped,
                }))
            })
        })
    }

    /// A producer whose first poll never resolves, and that says when it is
    /// dropped.
    fn never(dropped: Arc<std::sync::atomic::AtomicBool>) -> LlmStreamExecutionNextFn {
        /// A producer that never produces, and says when it is gone.
        struct Never(Arc<std::sync::atomic::AtomicBool>);
        impl tokio_stream::Stream for Never {
            type Item = Result<nemo_relay::json::Json, nemo_relay::error::FlowError>;
            fn poll_next(
                self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                std::task::Poll::Pending
            }
        }
        impl Drop for Never {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        Arc::new(move |_request| {
            let dropped = Arc::clone(&dropped);
            Box::pin(async move { Ok(LlmJsonStream::new(Never(dropped))) })
        })
    }

    /// A chain position whose stream produces `chunks` and then never resolves,
    /// saying when it is dropped.
    ///
    /// The producer that runs out of work without running out of stream: a deadline
    /// between frames is what this is here to be caught by.
    fn then_pending(
        chunks: Vec<serde_json::Value>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    ) -> LlmStreamExecutionNextFn {
        /// A producer that produces what it has and then nothing.
        struct ThenPending {
            items: std::vec::IntoIter<serde_json::Value>,
            dropped: Arc<std::sync::atomic::AtomicBool>,
        }
        impl tokio_stream::Stream for ThenPending {
            type Item = Result<nemo_relay::json::Json, nemo_relay::error::FlowError>;
            fn poll_next(
                mut self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                match self.items.next() {
                    Some(chunk) => std::task::Poll::Ready(Some(Ok(chunk))),
                    None => std::task::Poll::Pending,
                }
            }
        }
        impl Drop for ThenPending {
            fn drop(&mut self) {
                self.dropped
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        Arc::new(move |_request| {
            let chunks = chunks.clone();
            let dropped = Arc::clone(&dropped);
            Box::pin(async move {
                Ok(LlmJsonStream::new(ThenPending {
                    items: chunks.into_iter(),
                    dropped,
                }))
            })
        })
    }

    /// A chain position that never answers with a stream.
    fn hanging_chain() -> LlmStreamExecutionNextFn {
        Arc::new(|_request| {
            Box::pin(std::future::pending::<
                nemo_relay::error::Result<LlmJsonStream>,
            >())
        })
    }

    /// A chain position whose stream produces `chunks` and then ends, counting the
    /// polls it is asked for and saying when it is dropped.
    fn counted(
        chunks: Vec<serde_json::Value>,
        polls: Arc<std::sync::atomic::AtomicUsize>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    ) -> LlmStreamExecutionNextFn {
        /// A producer that counts what it is asked for.
        struct Counted {
            items: std::vec::IntoIter<serde_json::Value>,
            polls: Arc<std::sync::atomic::AtomicUsize>,
            dropped: Arc<std::sync::atomic::AtomicBool>,
        }
        impl tokio_stream::Stream for Counted {
            type Item = Result<nemo_relay::json::Json, nemo_relay::error::FlowError>;
            fn poll_next(
                mut self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::task::Poll::Ready(self.items.next().map(Ok))
            }
        }
        impl Drop for Counted {
            fn drop(&mut self) {
                self.dropped
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        Arc::new(move |_request| {
            let chunks = chunks.clone();
            let polls = Arc::clone(&polls);
            let dropped = Arc::clone(&dropped);
            Box::pin(async move {
                Ok(LlmJsonStream::new(Counted {
                    items: chunks.into_iter(),
                    polls,
                    dropped,
                }))
            })
        })
    }

    /// What this session will send for one frame, measured the way the session
    /// measures it.
    fn measured(payload: PluginSessionPayload) -> u64 {
        let wire =
            nemo_relay_plugin_proto::convert::session_message_to_wire(&PluginSessionMessage {
                session_id: "session-1".into(),
                message: payload,
            });
        nemo_relay_plugin_proto::convert::session_message_encoded_len(&wire) as u64
    }

    /// The frames a stream of one operation sends, in the order it sends them.
    ///
    /// The identities are the ones the session mints for the first stream of
    /// `operation-1` and the pulls this suite makes — `call-1` for the open and
    /// `pull-1`, `pull-2`, ... for the pulls — because a ceiling is a ceiling on
    /// bytes, and bytes depend on the names.
    fn stream_frames(chunks: &[serde_json::Value]) -> Vec<u64> {
        let stream = "operation-1-1";
        let mut frames = vec![measured(PluginSessionPayload::StreamOpened(
            PluginStreamOpened {
                host_call_id: "call-1".into(),
                stream_id: stream.into(),
            },
        ))];
        for (index, chunk) in chunks.iter().enumerate() {
            frames.push(measured(PluginSessionPayload::StreamItem(
                PluginStreamItem {
                    host_call_id: format!("pull-{}", index + 1),
                    stream_id: stream.into(),
                    chunk_json: chunk.to_string(),
                },
            )));
        }
        frames.push(measured(PluginSessionPayload::StreamEnd(PluginStreamEnd {
            host_call_id: format!("pull-{}", chunks.len() + 1),
            stream_id: stream.into(),
        })));
        frames
    }

    /// A producer whose first poll panics.
    fn panicking() -> LlmStreamExecutionNextFn {
        /// A producer that panics where plugin code runs.
        struct Panicking;
        impl tokio_stream::Stream for Panicking {
            type Item = Result<nemo_relay::json::Json, nemo_relay::error::FlowError>;
            fn poll_next(
                self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                panic!("the provider fell over");
            }
        }
        Arc::new(move |_request| Box::pin(async move { Ok(LlmJsonStream::new(Panicking)) }))
    }

    /// The kernel produces what the plugin pulls, one item per pull, and says
    /// when the stream is done.
    #[tokio::test]
    async fn a_pull_is_answered_with_the_next_item_and_then_with_the_end() {
        let mut session = Session::new();
        session.park_producing(
            "operation-1",
            vec![
                serde_json::json!({"chunk": 1}),
                serde_json::json!({"chunk": 2}),
            ],
        );
        let stream_id = session.opened("call-1", "operation-1").await;

        session.pull("call-2", &stream_id).expect("a pull");
        let PluginSessionPayload::StreamItem(item) = session.answer().await else {
            panic!("a pull is answered with an item");
        };
        assert_eq!(item.chunk_json, serde_json::json!({"chunk": 1}).to_string());

        session.pull("call-3", &stream_id).expect("a pull");
        assert!(matches!(
            session.answer().await,
            PluginSessionPayload::StreamItem(_)
        ));

        // The producer had two chunks, so the third pull learns the stream is
        // over rather than waiting for one that is never coming.
        session.pull("call-4", &stream_id).expect("a pull");
        assert!(matches!(
            session.answer().await,
            PluginSessionPayload::StreamEnd(_)
        ));
        session.drained().await;
        assert_eq!(session.driver.served_streams(), 0);
    }

    /// A producer that never resolves does not stop the session serving anything
    /// else, and its cancellation does not wait for it.
    ///
    /// This is the property the actor exists for. The dispatcher has no `await`
    /// in it, so the only way a parked producer could hold the session up is
    /// through the actor — and the actor reads a cancellation by dropping the
    /// poll it is in rather than by waiting for the producer to notice.
    #[tokio::test]
    async fn a_parked_producer_holds_up_neither_the_session_nor_its_cancellation() {
        let mut session = Session::new();
        session.park_pending("operation-1");
        session.park_pending("operation-2");
        session.park_producing("operation-3", vec![serde_json::json!({"chunk": 1})]);
        let parked = session.opened("call-1", "operation-1").await;
        let other = session.opened("call-2", "operation-2").await;
        let serving = session.opened("call-3", "operation-3").await;

        // A pull for the parked stream is routed, and its actor parks in the
        // producer: nothing answers, because nothing has been produced.
        session.pull("call-4", &parked).expect("a pull");

        // The session answers another stream's pull in the meantime, which is
        // the property that a blocked producer must not cost.
        session.pull("call-5", &serving).expect("a pull");
        let PluginSessionPayload::StreamItem(item) = session.answer().await else {
            panic!("the stream that can produce is served while another is parked");
        };
        assert_eq!(item.chunk_json, serde_json::json!({"chunk": 1}).to_string());

        // Cancelling the parked stream settles it: the actor drops the poll it
        // was in and then the producer, without the producer ever yielding.
        session.cancel("cancel-1", &parked).expect("a cancellation");
        session.cancel("cancel-2", &other).expect("a cancellation");
        // The stream that was producing is released rather than cancelled, and
        // that it can be is what says the session is still serving messages.
        session.release("release-1", &serving).expect("a release");
        session.drained().await;
        assert_eq!(session.driver.served_streams(), 0);
    }

    /// An operation with no parked stream is refused, and refused in a way the
    /// plugin can read: opening is asynchronous on its side, so the answer is a
    /// message rather than a transport failure.
    #[tokio::test]
    async fn an_open_for_an_operation_with_no_position_is_refused() {
        let mut session = Session::new();
        session
            .open("call-1", "operation-nobody-holds")
            .expect("an open request");
        let PluginSessionPayload::StreamOpenFailed(failed) = session.answer().await else {
            panic!("a refusal the plugin can read");
        };
        assert_eq!(failed.failure.code, PluginFailureCode::Rejected);
        assert!(
            failed.failure.message.contains("no chain is parked"),
            "{failure:?}",
            failure = failed.failure
        );
        session.actors_gone().await;
    }

    /// A position that is not a stream has no downstream stream to open, and says
    /// so rather than producing one from the wrong chain.
    #[tokio::test]
    async fn an_open_for_a_position_of_another_family_is_refused() {
        let mut session = Session::new();
        session.park_tool(
            "operation-1",
            Arc::new(|args| {
                Box::pin(async move { Ok(nemo_relay::api::tool::ToolExecutionResult::new(args)) })
            }),
        );
        // The tool position is not a stream position, so the open is refused
        // rather than answered with a stream built from the wrong chain.
        session
            .open("call-1", "operation-1")
            .expect("an open request");
        let PluginSessionPayload::StreamOpenFailed(failed) = session.answer().await else {
            panic!("a refusal the plugin can read");
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
        let mut session = Session::new();
        session.park_producing(
            "operation-1",
            vec![
                serde_json::json!({"chunk": 1}),
                serde_json::json!({"chunk": 2}),
            ],
        );
        let stream_id = session.opened("call-1", "operation-1").await;

        session.cancel("cancel-1", &stream_id).expect("a cancel");
        session.drained().await;

        // Pulling a cancelled stream is refused by the state machine, which is
        // what the plugin learns: it stopped the stream, so it may not keep it.
        let refused = session.pull("call-2", &stream_id);
        assert!(
            refused.is_err(),
            "a cancelled stream cannot be pulled: {refused:?}"
        );
    }

    /// A cancellation between frames settles the stream and stops its producer.
    ///
    /// Nothing about the stream being mid-flight changes the answer: the frame
    /// that crossed is the last one, the producer is dropped with whatever it was
    /// holding, and the stream may not be pulled again.
    #[tokio::test]
    async fn a_cancellation_between_frames_stops_the_stream() {
        let mut session = Session::new();
        session.park_producing(
            "operation-1",
            vec![
                serde_json::json!({"chunk": 1}),
                serde_json::json!({"chunk": 2}),
            ],
        );
        let stream_id = session.opened("call-1", "operation-1").await;
        session.pull("call-2", &stream_id).expect("a pull");
        assert!(matches!(
            session.answer().await,
            PluginSessionPayload::StreamItem(_)
        ));

        // The first frame crossed and the second never will: the cancellation
        // arrives between them, with the producer holding one more.
        session
            .cancel("cancel-1", &stream_id)
            .expect("a cancellation");
        session.drained().await;
        assert_eq!(session.driver.served_streams(), 0);
        assert!(
            session.pull("call-3", &stream_id).is_err(),
            "a cancelled stream cannot be pulled"
        );
    }

    /// A cancellation for a stream that already ended is a no-op, and the session
    /// keeps serving after it.
    ///
    /// The end of a stream and its consumer being dropped are a race a peer cannot
    /// win: both look the same from the far side of the boundary, and the drop
    /// arrives as the cancellation that the end made unnecessary. Refusing it
    /// would end a session over a race this boundary creates.
    #[tokio::test]
    async fn a_cancellation_for_a_stream_that_ended_leaves_the_session_serving() {
        let mut session = Session::new();
        session.park_producing("operation-1", vec![serde_json::json!({"chunk": 1})]);
        let stream_id = session.opened("call-1", "operation-1").await;
        session.pull("call-2", &stream_id).expect("a pull");
        assert!(matches!(
            session.answer().await,
            PluginSessionPayload::StreamItem(_)
        ));
        session.pull("call-3", &stream_id).expect("a pull");
        assert!(matches!(
            session.answer().await,
            PluginSessionPayload::StreamEnd(_)
        ));

        session
            .cancel("cancel-1", &stream_id)
            .expect("a cancellation for a stream that ended");
        session
            .release("release-1", &stream_id)
            .expect("a release after the stream ended");
        session.drained().await;

        // And the session is still serving: a stream that ended is not a session
        // that is broken.
        session.park_producing("operation-2", vec![serde_json::json!({"chunk": 2})]);
        let next = session.opened("call-4", "operation-2").await;
        session.pull("call-5", &next).expect("a pull");
        assert!(matches!(
            session.answer().await,
            PluginSessionPayload::StreamItem(_)
        ));
    }

    /// A cancellation naming a stream this session never opened is the one
    /// cancellation the session cannot treat as stale: it has no record to check
    /// it against, so refusing it ends the channel rather than continuing with a
    /// peer that names streams it was never given.
    #[tokio::test]
    async fn a_cancellation_for_a_stream_the_session_never_had_ends_the_channel() {
        let mut session = Session::new();
        let refused = session.cancel("cancel-1", "operation-1-1");
        assert!(
            refused.is_err(),
            "a cancellation for a stream that was never opened: {refused:?}"
        );
    }

    /// A release drops the kernel's stream and forgets it.
    #[tokio::test]
    async fn a_release_drops_the_stream_the_kernel_was_producing() {
        let mut session = Session::new();
        session.park_producing("operation-1", vec![serde_json::json!({"chunk": 1})]);
        let stream_id = session.opened("call-1", "operation-1").await;

        session.release("call-2", &stream_id).expect("a release");
        session.drained().await;

        // And a second release is refused, because the stream it names is not
        // one this session holds any more.
        assert!(
            session
                .release("call-3", &stream_id)
                .expect_err("a second release")
                .contains("not open in this session")
        );
    }

    /// A stream whose producer fails ends in a failure the plugin can read,
    /// rather than in silence, which it could not tell from a slow producer.
    #[tokio::test]
    async fn a_stream_that_fails_answers_with_the_failure() {
        let mut session = Session::new();
        session.park(
            "operation-1",
            Arc::new(|_request| {
                Box::pin(async move {
                    Ok(LlmJsonStream::new(tokio_stream::iter(vec![Err(
                        nemo_relay::error::FlowError::Internal("the provider fell over".into()),
                    )])))
                })
            }),
        );
        let stream_id = session.opened("call-1", "operation-1").await;

        session.pull("call-2", &stream_id).expect("a pull");
        let PluginSessionPayload::StreamFailed(failed) = session.answer().await else {
            panic!("a failing producer is a failure the plugin can read");
        };
        assert!(
            failed.failure.message.contains("fell over"),
            "{failure:?}",
            failure = failed.failure
        );
        assert_eq!(session.driver.served_streams(), 0);
    }

    /// A producer that panics fails its stream and leaves the session serving.
    ///
    /// The panic happens where plugin code runs, so it must not be able to take
    /// the kernel's session with it: the stream settles with what happened, its
    /// producer is dropped, and a stream beside it is unaffected.
    #[tokio::test]
    async fn a_panicking_producer_fails_its_stream_and_not_the_session() {
        let mut session = Session::new();
        session.park("operation-1", panicking());
        session.park_producing("operation-2", vec![serde_json::json!({"chunk": 1})]);
        let panicking = session.opened("call-1", "operation-1").await;
        let serving = session.opened("call-2", "operation-2").await;

        session.pull("call-3", &panicking).expect("a pull");
        let PluginSessionPayload::StreamFailed(failed) = session.answer().await else {
            panic!("a panicking producer is a failure the plugin can read");
        };
        assert!(
            failed.failure.message.contains("fell over"),
            "the failure says what the producer did: {failure:?}",
            failure = failed.failure
        );

        // The stream beside it is untouched, and the session is still serving:
        // a panic in one plugin's producer is that stream's failure.
        session.pull("call-4", &serving).expect("a pull");
        assert!(matches!(
            session.answer().await,
            PluginSessionPayload::StreamItem(_)
        ));
        assert_eq!(session.driver.served_streams(), 1);
    }

    /// A second pull while one is outstanding is refused before it is routed.
    ///
    /// The refusal is what keeps demand unambiguous: with two pulls in flight
    /// there is no answer that belongs to one of them rather than the other.
    #[tokio::test]
    async fn a_second_pull_while_one_is_outstanding_ends_the_channel() {
        let mut session = Session::new();
        // The producer never yields, so the pull it is producing for stays
        // outstanding for as long as the test needs it to.
        session.park_pending("operation-1");
        let stream_id = session.opened("call-1", "operation-1").await;
        session.pull("call-2", &stream_id).expect("a pull");

        let refused = session.pull("call-3", &stream_id);
        assert!(
            refused.is_err(),
            "the session refuses a second pull rather than queuing it: {refused:?}"
        );
    }

    /// Cancelling one stream leaves its neighbours alone.
    ///
    /// Two streams of one operation are the case where nothing but the stream
    /// identity tells their answers apart, so a cancellation that reached the
    /// wrong actor would show up as the other stream losing its chunk.
    #[tokio::test]
    async fn a_cancel_of_one_stream_does_not_touch_another() {
        let mut session = Session::new();
        session.park_producing(
            "operation-1",
            vec![
                serde_json::json!({"chunk": 1}),
                serde_json::json!({"chunk": 2}),
            ],
        );
        let first = session.opened("call-1", "operation-1").await;
        let second = session.opened("call-2", "operation-1").await;
        assert_ne!(
            first, second,
            "two streams of one operation are two streams"
        );

        session.cancel("cancel-1", &first).expect("a cancel");

        session.pull("call-3", &second).expect("a pull");
        let PluginSessionPayload::StreamItem(item) = session.answer().await else {
            panic!("the stream beside the cancelled one still produces");
        };
        assert_eq!(item.stream_id, second);
        assert_eq!(item.chunk_json, serde_json::json!({"chunk": 1}).to_string());
    }

    /// Streams that end every way at once, over and over, leave nothing behind.
    ///
    /// Every other test here pins one state, deliberately. This is for the races they
    /// cannot see — an actor cancelled while its neighbours are producing, a release
    /// landing between another stream's frames, a deadline firing while a pull is
    /// outstanding, a session ending under all of it — run enough times that a
    /// missing cleanup shows up as a count that does not return to where it started.
    ///
    /// The baseline is taken *per round* rather than once around the loop, because
    /// leakage that accumulates one object at a time is exactly what a single
    /// end-of-loop check would miss. Nothing here requires a particular order between
    /// the streams: what is asserted is what each stream owes and the counts every
    /// round has to give back.
    #[tokio::test]
    async fn streams_that_end_every_way_at_once_leave_nothing_behind() {
        for round in 0..25 {
            let mut session = Session::new();
            let finishing = session.park_watched(
                "operation-1",
                vec![
                    serde_json::json!({"chunk": 1}),
                    serde_json::json!({"chunk": 2}),
                ],
            );
            let cancelled = session.park_pending_watched("operation-2");
            let released =
                session.park_watched("operation-3", vec![serde_json::json!({"chunk": 3})]);
            let expiring = session.park_gated_watched("operation-4").await;

            let baseline = (session.driver.actors_alive(), 0);

            let completed = session.opened("call-1", "operation-1").await;
            let never = session.opened("call-2", "operation-2").await;
            let let_go = session.opened("call-3", "operation-3").await;
            let timed_out = session.opened("call-4", "operation-4").await;
            assert_eq!(
                session.driver.actors_alive(),
                baseline.0 + 4,
                "round {round} opened four streams, each with an actor of its own"
            );

            // Four ways of ending, interleaved: one finishes, one is cancelled with a
            // pull outstanding, one is let go unpulled, and one runs out of its
            // call's time while a pull is outstanding.
            session.pull("call-5", &completed).expect("a pull");
            assert!(matches!(
                session.answer().await,
                PluginSessionPayload::StreamItem(_)
            ));
            session.pull("call-6", &never).expect("a pull");
            session.cancel("cancel-1", &never).expect("a cancellation");
            session.release("release-1", &let_go).expect("a release");
            session.pull("call-7", &timed_out).expect("a pull");

            session.pull("call-8", &completed).expect("a pull");
            assert!(matches!(
                session.answer().await,
                PluginSessionPayload::StreamItem(_)
            ));
            session.pull("call-9", &completed).expect("a pull");
            assert!(matches!(
                session.answer().await,
                PluginSessionPayload::StreamEnd(_)
            ));

            // Everything settles, and every round gives the counts back.
            session.actors_gone().await;
            for (stream, sentinel) in [
                ("the stream that finished", &finishing),
                ("the stream that was cancelled", &cancelled),
                ("the stream that was released", &released),
                ("the stream that ran out of time", &expiring),
            ] {
                session.await_sentinel(sentinel, stream).await;
            }
            assert_eq!(
                session.driver.actors_alive(),
                baseline.0,
                "round {round} left an actor behind"
            );
            assert_eq!(
                session.driver.served_streams(),
                baseline.1,
                "round {round} left a stream in the registry"
            );
        }
    }

    /// A session that ends takes every producer with it.
    ///
    /// One stream is parked in a pull and another is waiting to be asked for
    /// anything at all. The session ending — whichever way it ends — is what stops
    /// both, and the producers are the evidence rather than the absence of an
    /// error: a session that ended is not one that left work behind, whatever the
    /// work was doing when it did.
    #[tokio::test]
    async fn a_session_that_ends_drops_every_producer() {
        let mut session = Session::new();
        let producing = session.park_pending_watched("operation-1");
        let waiting = session.park_watched("operation-2", vec![serde_json::json!({"chunk": 2})]);
        let squeezed = session.opened("call-1", "operation-1").await;
        session.opened("call-2", "operation-2").await;
        // One stream is producing for a pull that will never be answered, and the
        // other has not been asked for anything.
        session.pull("call-3", &squeezed).expect("a pull");

        drop(session);

        for (stream, sentinel) in [
            ("the producing stream", producing),
            ("the waiting stream", waiting),
        ] {
            let dropped = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !sentinel.load(std::sync::atomic::Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
            })
            .await;
            assert!(
                dropped.is_ok(),
                "{stream} dropped its producer when the session ended"
            );
        }
    }

    /// A deadline before the first frame: the stream is over when the call's time
    /// is up, whether or not its consumer has asked for anything.
    ///
    /// A deadline that only arrived at the next pull would be the consumer's
    /// deadline rather than the call's, and the work behind the stream would be
    /// held open by a consumer that had stopped asking.
    #[tokio::test]
    async fn a_deadline_before_the_first_frame_ends_the_stream() {
        let mut session = Session::new();
        session
            .park_until(
                "operation-1",
                then_pending(Vec::new(), Arc::clone(&session.dropped)),
                std::time::Duration::from_millis(100),
            )
            .await;
        let stream_id = session.opened("call-1", "operation-1").await;

        // Nobody pulls, and the stream ends anyway: the producer goes with the
        // call's time. Waiting for that drop is what makes this the state the test
        // names rather than one the scheduler picked.
        session.await_dropped().await;

        // The pull that comes afterwards is answered with what ended the stream,
        // so a consumer that asks late learns why rather than waiting for a frame
        // that will never come.
        let crossed = session.drive(&stream_id, 2).await;
        let Some(PluginSessionPayload::StreamFailed(failed)) = crossed.first() else {
            panic!("the deadline is the answer to the pull that follows it: {crossed:?}");
        };
        assert_eq!(failed.failure.code, PluginFailureCode::DeadlineExceeded);
        session.actors_gone().await;
    }

    /// A deadline while a pull is pending: the pull is answered with the deadline
    /// rather than waiting for a producer that may never produce.
    #[tokio::test]
    async fn a_deadline_while_a_pull_is_pending_answers_the_pull() {
        let mut session = Session::new();
        session
            .park_until(
                "operation-1",
                never(Arc::clone(&session.dropped)),
                std::time::Duration::from_millis(100),
            )
            .await;
        let stream_id = session.opened("call-1", "operation-1").await;

        // The pull is made and the producer never answers it; the deadline is what
        // the pull is answered with.
        let crossed = session.drive(&stream_id, 2).await;
        let Some(PluginSessionPayload::StreamFailed(failed)) = crossed.first() else {
            panic!("a pull the deadline interrupts is answered with it: {crossed:?}");
        };
        assert_eq!(failed.failure.code, PluginFailureCode::DeadlineExceeded);
        session.drained().await;
    }

    /// A deadline between frames: a stream that produced a frame and then blocked
    /// is over when the call's time is up.
    #[tokio::test]
    async fn a_deadline_between_frames_ends_the_stream() {
        let mut session = Session::new();
        session
            .park_until(
                "operation-1",
                then_pending(
                    vec![serde_json::json!({"chunk": 1})],
                    Arc::clone(&session.dropped),
                ),
                std::time::Duration::from_millis(100),
            )
            .await;
        let stream_id = session.opened("call-1", "operation-1").await;

        let crossed = session.drive(&stream_id, 3).await;
        assert!(
            matches!(crossed.first(), Some(PluginSessionPayload::StreamItem(_))),
            "the frame that crossed before the deadline is the frame the plugin got: \
             {crossed:?}"
        );
        let Some(PluginSessionPayload::StreamFailed(failed)) = crossed.get(1) else {
            panic!("the stream ends with the deadline rather than with silence: {crossed:?}");
        };
        assert_eq!(failed.failure.code, PluginFailureCode::DeadlineExceeded);
        session.drained().await;
    }

    /// A deadline while the open is blocked: the stream never opens, and the plugin
    /// is told why rather than waiting for a chain that may never answer.
    #[tokio::test]
    async fn a_deadline_while_the_open_is_blocked_refuses_the_open() {
        let mut session = Session::new();
        session
            .park_until(
                "operation-1",
                hanging_chain(),
                std::time::Duration::from_millis(100),
            )
            .await;
        session
            .open("call-1", "operation-1")
            .expect("an open request");

        let PluginSessionPayload::StreamOpenFailed(failed) = session.answer().await else {
            panic!("an open the deadline ended is refused rather than opened");
        };
        assert_eq!(failed.failure.code, PluginFailureCode::DeadlineExceeded);
        session.actors_gone().await;
    }

    /// A stream nobody pulls is never polled.
    ///
    /// Credit is the whole of a stream's demand accounting, and it is granted by
    /// demand rather than ahead of it: no pull, no credit, no poll. That is what
    /// keeps a stream's cost bounded by its consumer's appetite rather than by its
    /// producer's willingness to run ahead, and it holds whatever the transport
    /// later does with buffers.
    #[tokio::test]
    async fn a_stream_nobody_pulls_is_never_polled() {
        let mut session = Session::new();
        let quiet = session.park_counting(
            "operation-1",
            vec![
                serde_json::json!({"chunk": 1}),
                serde_json::json!({"chunk": 2}),
            ],
        );
        session.park_producing("operation-2", vec![serde_json::json!({"chunk": 1})]);
        let never_asked = session.opened("call-1", "operation-1").await;
        let serving = session.opened("call-2", "operation-2").await;

        // The session is doing work — another stream is opened, served and
        // released — and the stream nobody asked about is left alone throughout.
        session.pull("call-3", &serving).expect("a pull");
        assert!(matches!(
            session.answer().await,
            PluginSessionPayload::StreamItem(_)
        ));
        session.release("call-4", &serving).expect("a release");
        assert_eq!(
            quiet.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a producer nobody has asked about is not polled"
        );

        // One pull is one frame's worth of demand: the first poll is the first
        // pull's, not the first of several.
        session.pull("call-5", &never_asked).expect("a pull");
        assert!(matches!(
            session.answer().await,
            PluginSessionPayload::StreamItem(_)
        ));
        assert_eq!(
            quiet.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one pull is one poll"
        );
    }

    /// The frame ceiling: a frame at the limit crosses, one byte over does not, and
    /// the stream that produced it is over either way.
    #[tokio::test]
    async fn a_frame_one_byte_over_the_ceiling_ends_the_stream() {
        // A chunk whose frame is much larger than the frame that reports the
        // failure: what crosses the ceiling is the data, not the message about it.
        let chunk = serde_json::json!({"chunk": "x".repeat(4096)});
        let exact = measured(PluginSessionPayload::StreamItem(PluginStreamItem {
            host_call_id: "pull-1".into(),
            stream_id: "operation-1-1".into(),
            chunk_json: chunk.to_string(),
        }));

        for (limit, crosses) in [(exact - 1, false), (exact, true), (exact + 1, true)] {
            let mut session = Session::with_limits(SessionLimits {
                max_frame_bytes: u32::try_from(limit).expect("a frame ceiling"),
                ..SessionLimits::default()
            });
            session.park_producing("operation-1", vec![chunk.clone()]);
            let stream_id = session.opened("call-1", "operation-1").await;
            let crossed = session.drive(&stream_id, 4).await;
            session.drained().await;

            if crosses {
                assert!(
                    matches!(
                        crossed.as_slice(),
                        [
                            PluginSessionPayload::StreamItem(_),
                            PluginSessionPayload::StreamEnd(_)
                        ]
                    ),
                    "a frame at or under {limit} bytes crosses: {crossed:?}"
                );
            } else {
                // The frame that was refused is not sent, and the failure that
                // replaces it is: a plugin learns which ceiling it met.
                let Some(PluginSessionPayload::StreamFailed(failed)) = crossed.last() else {
                    panic!("a stream whose frame was refused ends with a failure: {crossed:?}");
                };
                assert!(
                    matches!(
                        failed.failure.code,
                        PluginFailureCode::OversizedFrame { .. }
                    ),
                    "the failure says which ceiling was crossed: {failure:?}",
                    failure = failed.failure
                );
                assert!(
                    !crossed
                        .iter()
                        .any(|frame| matches!(frame, PluginSessionPayload::StreamItem(_))),
                    "the frame over the ceiling was not sent: {crossed:?}"
                );
            }
        }
    }

    /// The cumulative byte ceiling counts every frame a stream sends, the terminal
    /// one included.
    #[tokio::test]
    async fn the_stream_byte_ceiling_counts_every_frame() {
        let chunks = vec![
            serde_json::json!({"chunk": 1}),
            serde_json::json!({"chunk": 2}),
        ];
        let total: u64 = stream_frames(&chunks).iter().sum();

        for (limit, ends) in [(total - 1, false), (total, true), (total + 1, true)] {
            let mut session = Session::with_limits(SessionLimits {
                max_stream_bytes: limit,
                ..SessionLimits::default()
            });
            session.park_producing("operation-1", chunks.clone());
            let stream_id = session.opened("call-1", "operation-1").await;
            let crossed = session.drive(&stream_id, 4).await;
            session.drained().await;

            let terminal = crossed
                .iter()
                .any(|frame| matches!(frame, PluginSessionPayload::StreamEnd(_)));
            assert_eq!(
                terminal, ends,
                "a stream of {total} bytes ends within a {limit}-byte budget: {crossed:?}"
            );
        }
    }

    /// The frame-count ceiling counts every frame a stream sends, the terminal one
    /// included.
    #[tokio::test]
    async fn the_stream_frame_ceiling_counts_every_frame() {
        let chunks = vec![
            serde_json::json!({"chunk": 1}),
            serde_json::json!({"chunk": 2}),
        ];
        let total = stream_frames(&chunks).len() as u64;

        for (limit, ends) in [(total - 1, false), (total, true), (total + 1, true)] {
            let mut session = Session::with_limits(SessionLimits {
                max_stream_frames: limit,
                ..SessionLimits::default()
            });
            session.park_producing("operation-1", chunks.clone());
            let stream_id = session.opened("call-1", "operation-1").await;
            let crossed = session.drive(&stream_id, 4).await;
            session.drained().await;

            let terminal = crossed
                .iter()
                .any(|frame| matches!(frame, PluginSessionPayload::StreamEnd(_)));
            assert_eq!(
                terminal, ends,
                "a stream of {total} frames ends within a budget of {limit}: {crossed:?}"
            );
        }
    }

    /// A session refuses to take on more streams than its ceiling, and says so in
    /// the shape an open is answered in.
    #[tokio::test]
    async fn a_session_refuses_more_streams_than_it_may_serve() {
        let mut session = Session::with_limits(SessionLimits {
            max_stream_actors: 2,
            max_pending_opens: 2,
            ..SessionLimits::default()
        });
        session.park_pending("operation-1");
        session.park_pending("operation-2");
        session.park_pending("operation-3");
        session.opened("call-1", "operation-1").await;
        session.opened("call-2", "operation-2").await;

        session
            .open("call-3", "operation-3")
            .expect("an open request");
        let PluginSessionPayload::StreamOpenFailed(failed) = session.answer().await else {
            panic!("a stream past the ceiling is refused");
        };
        assert!(
            failed.failure.message.contains("already serving 2 streams"),
            "{failure:?}",
            failure = failed.failure
        );
    }

    /// A session bounds the opens it has not answered yet, separately from the
    /// streams it is serving.
    #[tokio::test]
    async fn a_session_refuses_more_opens_in_flight_than_it_may_hold() {
        let release = Arc::new(tokio::sync::Notify::new());
        let parked: LlmStreamExecutionNextFn = {
            let release = Arc::clone(&release);
            Arc::new(move |_request| {
                let release = Arc::clone(&release);
                Box::pin(async move {
                    release.notified().await;
                    Ok(LlmJsonStream::new(tokio_stream::iter(Vec::new())))
                })
            })
        };
        let mut session = Session::with_limits(SessionLimits {
            max_stream_actors: 8,
            max_pending_opens: 1,
            ..SessionLimits::default()
        });
        session.park("operation-1", Arc::clone(&parked));
        session.park("operation-2", Arc::clone(&parked));

        // The first open is in flight — the chain has not answered — and the
        // second is refused rather than held behind it.
        session.open("call-1", "operation-1").expect("an open");
        session.open("call-2", "operation-2").expect("an open");
        let PluginSessionPayload::StreamOpenFailed(failed) = session.answer().await else {
            panic!("an open past the ceiling is refused");
        };
        assert!(
            failed.failure.message.contains("1 opens in flight"),
            "{failure:?}",
            failure = failed.failure
        );

        // The open that was in flight is not lost by the refusal beside it: when
        // the chain answers, the stream it opened is announced.
        release.notify_one();
        let PluginSessionPayload::StreamOpened(opened) = session.answer().await else {
            panic!("the open that was in flight still answers");
        };
        assert_eq!(opened.host_call_id, "call-1");
    }

    /// A message the kernel does not receive from a host ends the channel rather
    /// than being answered as if it were addressed to it.
    #[tokio::test]
    async fn a_message_from_the_wrong_side_ends_the_channel() {
        let mut session = Session::new();
        let refused = session.handle(PluginSessionPayload::StreamOpened(PluginStreamOpened {
            host_call_id: "call-1".into(),
            stream_id: "stream-1".into(),
        }));
        assert!(
            refused.is_err(),
            "the kernel does not receive an opening from a host: {refused:?}"
        );
    }
}
