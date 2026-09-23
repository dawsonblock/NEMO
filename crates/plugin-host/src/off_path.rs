// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A runtime for the work a plugin does *beside* a call.
//!
//! Observers and sanitizers are invoked from the runtime's dispatcher, off the
//! task that made the call. The thread that would answer them is often the thread
//! that is waiting for them — on a single-threaded caller runtime it always is —
//! and an answer that can only arrive on a thread the caller is holding is a
//! deadlock that ends at the budget. That was the sanitizer hang: 5 s took 16 s,
//! 60 s took 181 s, and the events arrived with their observability fields
//! cleared, because a guardrail that never answered is a guardrail that failed.
//!
//! So the work gets a runtime of its own, owned by the composition rather than by
//! whichever runtime happened to call in. Three properties follow, and each is
//! why this is a resource rather than a helper:
//!
//! - **The caller's topology stops mattering.** A single-threaded caller is
//!   served exactly as a multi-threaded one, because neither thread is asked to
//!   answer work it is waiting for.
//! - **Affinity is deterministic.** The runtime that drives the transport is the
//!   runtime that awaits it, rather than whichever executor context the
//!   dispatcher happened to be running on.
//! - **Concurrency is bounded and stated.** An event-heavy workload cannot turn
//!   the off-path path into an unbounded queue; the bound is configuration, and
//!   saturation fails closed per family instead of blocking the call that is
//!   being observed.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use nemo_relay_plugin_protocol::{
    PluginExecutionContext, PluginExecutionOutcome, PluginFailureCode, PluginInvocationError,
    PluginInvokeRequest, PluginProtocolError,
};
use tokio::sync::{Mutex, Semaphore, oneshot};

/// How much a runtime asks of plugins *beside* the calls it makes.
///
/// Two settings rather than one because they answer different questions: how long
/// one off-path operation may take, and how many may be in flight at once. Both
/// are stated, because a runtime that decides either for its deployment is a
/// runtime whose limit nobody chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservabilityPolicy {
    /// Longest one off-path operation may take.
    pub budget_millis: u64,
    /// How many off-path operations may be in flight at once.
    pub max_in_flight: usize,
}

impl ObservabilityPolicy {
    /// Refuse a policy that states nothing.
    ///
    /// Zero would mean "no time" and "no capacity", which nobody means, and both
    /// are the same mistake as a default: a value the deployment did not choose.
    pub fn validate(&self) -> Result<(), PluginProtocolError> {
        if self.budget_millis == 0 {
            return Err(refused(
                "an observability budget of zero milliseconds would refuse every off-path operation",
            ));
        }
        if self.max_in_flight == 0 {
            return Err(refused(
                "an in-flight limit of zero would refuse every off-path operation",
            ));
        }
        Ok(())
    }
}

fn refused(message: &str) -> PluginProtocolError {
    PluginProtocolError::new(PluginFailureCode::Rejected, message.to_string())
}

/// The mark this runtime emits when an observer's delivery failed.
pub const OBSERVER_FAILURE_MARK: &str = "nemo.plugin.observer.failed";

/// The mark this runtime emits when a sanitize guardrail failed.
///
/// The chain clears the observability fields when a sanitizer fails, which is the
/// fail-closed direction — and also why a failure used to be invisible: the event
/// arrived without a payload and only a log line said why. A class whose whole
/// purpose is deciding what other people may see should say when it could not
/// decide.
pub const SANITIZE_FAILURE_MARK: &str = "nemo.plugin.sanitize.failed";

/// Record one off-path failure in this runtime's own stream.
///
/// One function rather than one per family: the mark names the family, and the
/// shape — a registration and a reason — is the same fact either way. A failure
/// that cannot be recorded is dropped rather than propagated, because the caller
/// is already reporting it and an observer of the record must not change what the
/// caller sees.
pub(crate) fn record_failure(mark: &str, registration: &str, reason: &str) {
    let _ = nemo_relay::api::scope::event(
        nemo_relay::api::scope::EmitMarkEventParams::builder()
            .name(mark)
            .data_opt(Some(serde_json::json!({
                "registration": registration,
                "reason": reason,
            })))
            .build(),
    );
}

/// The runtime off-path plugin work runs on.
///
/// Owned by the composition that started the host, so every off-path family
/// shares one runtime, one bound and one lifetime: a plugin's observers and
/// sanitizers cannot outlive the runtime that asked for them, and a later family
/// adopts the same mechanism instead of rediscovering the same deadlock.
pub struct OffPathPluginExecutor {
    /// The handle work is submitted through.
    handle: tokio::runtime::Handle,
    /// The runtime itself, held so it can be ended without blocking.
    ///
    /// Ending a runtime by dropping it panics inside an async context, and the
    /// composition that owns this is usually torn down from one. Ending it in the
    /// background is what off-path work wants anyway: nothing on the call's path
    /// is waiting for it, and a teardown that blocked on a plugin would put the
    /// plugin back in the way of the runtime it was supposed to be beside.
    runtime: Option<tokio::runtime::Runtime>,
    in_flight: Arc<Semaphore>,
    running: Arc<AtomicUsize>,
    /// The session this runtime attaches its own transport to, when it has one.
    descriptor: Option<crate::attached::ConnectionDescriptor>,
    /// The attached transport, created on this runtime the first time it is
    /// needed: creating it elsewhere and moving it here would keep its tasks
    /// where it was made, which is the bug this exists to remove.
    attached: Mutex<Option<Arc<crate::attached::AttachedClient>>>,
}

impl Drop for OffPathPluginExecutor {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl std::fmt::Debug for OffPathPluginExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OffPathPluginExecutor")
            .field("running", &self.running.load(Ordering::SeqCst))
            .field("available_permits", &self.in_flight.available_permits())
            .finish()
    }
}

impl OffPathPluginExecutor {
    /// Start a runtime for off-path work, with `max_in_flight` as its bound.
    pub fn start(policy: &ObservabilityPolicy) -> Result<Self, PluginProtocolError> {
        policy.validate()?;
        // More than one worker so an off-path operation can await the transport
        // while another completes: a single worker would reintroduce the very
        // shape this runtime exists to remove.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("nemo-plugin-off-path")
            .enable_all()
            .build()
            .map_err(|error| refused(&format!("the off-path runtime did not start: {error}")))?;
        let handle = runtime.handle().clone();
        Ok(Self {
            handle,
            runtime: Some(runtime),
            in_flight: Arc::new(Semaphore::new(policy.max_in_flight)),
            running: Arc::new(AtomicUsize::new(0)),
            descriptor: None,
            attached: Mutex::new(None),
        })
    }

    /// Submit one off-path operation, or refuse it because the bound is reached.
    ///
    /// `None` is saturation rather than failure: the caller decides what a
    /// refused operation means for its family — an observer drops the event and
    /// records it, a sanitizer fails closed — and neither blocks the call it was
    /// observing, which is the one thing an off-path operation may never do.
    pub fn submit<T>(
        &self,
        work: impl std::future::Future<Output = T> + Send + 'static,
    ) -> Option<oneshot::Receiver<T>>
    where
        T: Send + 'static,
    {
        let permit = Arc::clone(&self.in_flight).try_acquire_owned().ok()?;
        let running = Arc::clone(&self.running);
        let (answered, received) = oneshot::channel();
        self.handle.spawn(async move {
            running.fetch_add(1, Ordering::SeqCst);
            let outcome = work.await;
            running.fetch_sub(1, Ordering::SeqCst);
            drop(permit);
            let _ = answered.send(outcome);
        });
        Some(received)
    }

    /// Run a long-lived task here without holding a permit.
    ///
    /// For the loop that drains one observer's queue: the loop is not an
    /// operation, and the operations it performs take permits as they go. Holding
    /// one for the loop would spend the bound on idleness.
    pub fn spawn_long_lived(
        &self,
        work: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> tokio::task::AbortHandle {
        self.handle.spawn(work).abort_handle()
    }

    /// Wait for an operation to answer, or say that this executor stopped first.
    pub async fn answer<T>(
        received: oneshot::Receiver<T>,
    ) -> Result<T, nemo_relay::error::FlowError> {
        received.await.map_err(|_| {
            nemo_relay::error::FlowError::Internal(
                "the runtime this runtime asked for off-path work stopped before the plugin \
                 answered"
                    .to_string(),
            )
        })
    }

    /// Attach to the session this runtime's off-path work belongs to.
    pub fn attach_to(mut self, descriptor: crate::attached::ConnectionDescriptor) -> Self {
        self.descriptor = Some(descriptor);
        self
    }

    /// The attached transport, connecting and attaching it on this runtime if this
    /// is the first off-path call.
    async fn attached(&self) -> Result<Arc<crate::attached::AttachedClient>, String> {
        let mut cached = self.attached.lock().await;
        if let Some(client) = cached.as_ref() {
            return Ok(Arc::clone(client));
        }
        let Some(descriptor) = self.descriptor.clone() else {
            return Err(
                "this runtime has no session transport beside the call's, so it cannot ask a \
                 plugin to do work off the call's path"
                    .to_string(),
            );
        };
        // Submitted here rather than connected here, so both the connection and the
        // client are created *on this runtime*.
        let Some(received) =
            self.submit(async move { crate::attached::AttachedClient::connect(descriptor).await })
        else {
            return Err(
                "this runtime is at its in-flight limit, so it cannot open its transport"
                    .to_string(),
            );
        };
        let client = match received.await {
            Ok(Ok(client)) => Arc::new(client),
            Ok(Err(error)) => return Err(error.failure.message),
            Err(_) => return Err("this runtime stopped before its transport attached".to_string()),
        };
        *cached = Some(Arc::clone(&client));
        Ok(client)
    }

    /// Invoke one registration over this runtime's attached transport.
    ///
    /// The uncertainty a caller needs survives: an error after the transport was
    /// entered is reported as entered, not as a definite non-dispatch.
    pub async fn invoke(
        &self,
        request: PluginInvokeRequest,
        context: PluginExecutionContext,
    ) -> Result<PluginExecutionOutcome, PluginInvocationError> {
        let client = self
            .attached()
            .await
            .map_err(|message| PluginInvocationError {
                failure: nemo_relay_plugin_protocol::PluginFailure {
                    code: PluginFailureCode::Unavailable,
                    message,
                },
                phase: nemo_relay_plugin_protocol::PluginInvocationPhase::RefusedBeforeBackend,
            })?;
        client.invoke(request, context).await
    }

    /// How many operations are running now.
    pub fn running(&self) -> usize {
        self.running.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn policy(budget_millis: u64, max_in_flight: usize) -> ObservabilityPolicy {
        ObservabilityPolicy {
            budget_millis,
            max_in_flight,
        }
    }

    #[test]
    fn a_policy_that_states_nothing_is_refused() {
        for impossible in [policy(0, 4), policy(5_000, 0)] {
            assert!(
                impossible.validate().is_err(),
                "a policy of zeros is not a policy: {impossible:?}"
            );
        }
        assert!(policy(5_000, 4).validate().is_ok());
    }

    #[test]
    fn off_path_work_runs_here_whatever_thread_submitted_it() {
        let executor = OffPathPluginExecutor::start(&policy(5_000, 4)).expect("an executor");
        // Submitted from a plain thread, which is not a tokio worker at all: the
        // affinity this runtime provides is that the answer does not depend on
        // where the question came from.
        let caller = std::thread::spawn(move || {
            let answered = executor.submit(async { 7 }).expect("a permit");
            let answer = answered.blocking_recv().expect("an answer");
            (answer, executor)
        });
        let (answer, executor) = caller.join().expect("the submitting thread");
        assert_eq!(answer, 7);
        assert_eq!(executor.running(), 0, "the permit came back");
    }

    #[test]
    fn a_bounded_executor_refuses_work_it_cannot_hold() {
        let executor = OffPathPluginExecutor::start(&policy(5_000, 1)).expect("an executor");
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        // Suspended, not blocked: a worker thread held by the test would measure
        // the test rather than the bound.
        let held = executor
            .submit(async move {
                let _ = released.await;
            })
            .expect("the first operation holds the only permit");

        // Waiting for it to be running makes the saturation a fact rather than a
        // race against the runtime's scheduler.
        for _ in 0..400 {
            if executor.running() == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            executor.submit(async {}).is_none(),
            "saturation is a refusal rather than an unbounded queue"
        );

        release.send(()).expect("release the first operation");
        for _ in 0..400 {
            if executor.submit(async {}).is_some() {
                drop(held);
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the permit never came back");
    }

    #[tokio::test]
    async fn an_executor_that_stopped_fails_pending_work_cleanly() {
        let executor = OffPathPluginExecutor::start(&policy(5_000, 2)).expect("an executor");
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let pending = executor
            .submit(async move {
                let _ = released.await;
                1
            })
            .expect("a permit");
        // The work is still blocked, and the runtime that was going to answer it
        // is gone: the caller learns that instead of waiting out a budget.
        drop(executor);
        assert!(
            OffPathPluginExecutor::answer(pending).await.is_err(),
            "a stopped executor answers nothing, and says so"
        );
        drop(release);
    }
}
