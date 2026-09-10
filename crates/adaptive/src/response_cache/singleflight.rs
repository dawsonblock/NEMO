// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-local collapse of concurrent identical cache misses.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use nemo_relay::api::runtime::{LlmJsonStream, LlmStreamInner};
use nemo_relay::error::{FlowError, Result as FlowResult};
use serde_json::Value as Json;
use tokio::sync::oneshot;
use tokio::time::{Instant, timeout};
use tokio_stream::Stream;

use crate::config::SingleFlightLimits;

type SharedCall<T> = Shared<BoxFuture<'static, FlowResult<T>>>;

struct ActiveCall<T> {
    id: usize,
    call: SharedCall<T>,
    waiters: usize,
}

/// Snapshot of bounded single-flight state for focused tests.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SingleFlightStats {
    /// Number of distinct cache keys with provider work in flight.
    pub active_keys: usize,
    /// Number of followers currently waiting on an existing key.
    pub waiters: usize,
    /// Number of calls that joined an existing key.
    pub hits: usize,
    /// Number of provider calls admitted as a new key.
    pub new_calls: usize,
    /// Number of active-key or waiter admission rejections.
    pub rejections: usize,
    /// Number of provider calls holding all concurrency permits.
    pub provider_active_requests: usize,
    /// Number of provider operations waiting for coordinated admission.
    pub provider_pending_requests: usize,
}

#[derive(Default)]
struct Counters {
    active_keys: AtomicUsize,
    waiters: AtomicUsize,
    hits: AtomicUsize,
    new_calls: AtomicUsize,
    rejections: AtomicUsize,
}

impl Counters {
    fn try_reserve_waiter(&self, limit: usize) -> bool {
        let mut current = self.waiters.load(Ordering::Relaxed);
        loop {
            if current >= limit {
                return false;
            }
            match self.waiters.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }
}

fn remove_completed_call<T>(
    calls: &Mutex<HashMap<String, ActiveCall<T>>>,
    counters: &Counters,
    key: &str,
    call_id: usize,
) {
    let mut calls = calls.lock().unwrap_or_else(|error| error.into_inner());
    if calls.get(key).is_some_and(|active| active.id == call_id) {
        calls.remove(key);
        counters.active_keys.fetch_sub(1, Ordering::Relaxed);
    }
}

struct PendingAdmission {
    ticket: usize,
    provider: String,
    model: Option<String>,
    grant: oneshot::Sender<ProviderPermits>,
}

#[derive(Default)]
struct AdmissionState {
    queue: VecDeque<PendingAdmission>,
    pending_global: usize,
    pending_provider: HashMap<String, usize>,
    active_global: usize,
    active_provider: HashMap<String, usize>,
    active_model: HashMap<(String, String), usize>,
}

struct PendingAdmissionReservation {
    controller: Arc<ProviderConcurrency>,
    ticket: Option<usize>,
}

impl PendingAdmissionReservation {
    fn disarm(&mut self) {
        self.ticket = None;
    }

    fn cancel(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            self.controller.cancel_pending(ticket);
        }
    }
}

impl Drop for PendingAdmissionReservation {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Coordinated provider/model admission for live operations.
///
/// Admission is all-or-nothing: a request is queued before it receives any
/// active capacity, then removed from the queue only when the global,
/// provider, and model limits can all be satisfied. This avoids chained
/// semaphore permit hoarding and bounds both active and pending work.
pub(crate) struct ProviderConcurrency {
    limits: SingleFlightLimits,
    state: Mutex<AdmissionState>,
    next_ticket: AtomicUsize,
    active_requests: AtomicUsize,
    pending_requests: AtomicUsize,
}

impl ProviderConcurrency {
    /// Create a coordinated limiter with provider-admission limits.
    pub(crate) fn new(limits: SingleFlightLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(AdmissionState::default()),
            next_ticket: AtomicUsize::new(0),
            active_requests: AtomicUsize::new(0),
            pending_requests: AtomicUsize::new(0),
        }
    }

    pub(crate) async fn acquire(
        self: &Arc<Self>,
        provider: &str,
        model: Option<&str>,
    ) -> FlowResult<ProviderPermits> {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(
                self.limits.provider_admission_timeout_ms,
            ))
            .unwrap_or_else(Instant::now);

        // Admit immediately before consuming a pending slot. This preserves
        // available capacity for unrelated providers even when another queue
        // is saturated.
        if let Some(permits) = self.try_admit_immediately(provider, model) {
            return Ok(permits);
        }

        let (mut reservation, receiver) = self.enqueue(provider, model)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            reservation.cancel();
            return Err(FlowError::Timeout {
                resource: "provider_admission",
            });
        }

        match timeout(remaining, receiver).await {
            Ok(Ok(permits)) => {
                reservation.disarm();
                Ok(permits)
            }
            Ok(Err(_)) => {
                reservation.cancel();
                Err(FlowError::Internal(
                    "provider admission scheduler stopped".into(),
                ))
            }
            Err(_) => {
                reservation.cancel();
                Err(FlowError::Timeout {
                    resource: "provider_admission",
                })
            }
        }
    }

    /// Run a live provider operation while holding the global, provider, and
    /// model concurrency permits for the complete operation lifetime.
    pub(crate) async fn execute<F, T>(
        self: &Arc<Self>,
        provider: &str,
        model: Option<&str>,
        future: F,
    ) -> FlowResult<T>
    where
        F: std::future::Future<Output = FlowResult<T>>,
    {
        let _permits = self.acquire(provider, model).await?;
        future.await
    }

    /// Attach provider permits to a stream so they remain held until EOF,
    /// successful or failed close, or drop. Consumer terminalization alone
    /// does not release the producer's capacity. Long-lived streaming calls
    /// therefore count against the same budgets as buffered calls.
    pub(crate) fn guard_stream(
        self: &Arc<Self>,
        stream: LlmJsonStream,
        permits: ProviderPermits,
    ) -> LlmJsonStream {
        let _ = self;
        LlmJsonStream::from_closeable(GuardedProviderStream {
            stream,
            permits: Some(permits),
        })
    }

    #[cfg(test)]
    fn active_requests(&self) -> usize {
        self.active_requests.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn pending_requests(&self) -> usize {
        self.pending_requests.load(Ordering::Relaxed)
    }

    fn enqueue(
        self: &Arc<Self>,
        provider: &str,
        model: Option<&str>,
    ) -> FlowResult<(
        PendingAdmissionReservation,
        oneshot::Receiver<ProviderPermits>,
    )> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.pending_global >= self.limits.max_pending_provider_requests {
            return Err(FlowError::ResourceExhausted {
                resource: "provider_admission.pending",
                limit: self.limits.max_pending_provider_requests,
            });
        }
        let provider_pending = state.pending_provider.get(provider).copied().unwrap_or(0);
        if provider_pending >= self.limits.max_pending_provider_per_provider {
            return Err(FlowError::ResourceExhausted {
                resource: "provider_admission.pending_provider",
                limit: self.limits.max_pending_provider_per_provider,
            });
        }

        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        let (grant, receiver) = oneshot::channel();
        state.queue.push_back(PendingAdmission {
            ticket,
            provider: provider.to_string(),
            model: model.map(str::to_string),
            grant,
        });
        state.pending_global += 1;
        *state
            .pending_provider
            .entry(provider.to_string())
            .or_default() += 1;
        self.pending_requests.fetch_add(1, Ordering::Relaxed);
        let reservation = PendingAdmissionReservation {
            controller: Arc::clone(self),
            ticket: Some(ticket),
        };
        drop(state);
        self.schedule_pending();
        Ok((reservation, receiver))
    }

    fn try_admit_immediately(
        self: &Arc<Self>,
        provider: &str,
        model: Option<&str>,
    ) -> Option<ProviderPermits> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        // Do not let a new request consume capacity that an older eligible
        // waiter is already entitled to. The caller will enqueue behind that
        // waiter, and schedule_pending() will grant both atomically whenever
        // capacity permits. Ineligible waiters for saturated providers are
        // intentionally skipped so unrelated providers still make progress.
        if state
            .queue
            .iter()
            .any(|pending| self.can_admit(&state, pending))
        {
            return None;
        }
        if !self.can_admit_parts(&state, provider, model) {
            return None;
        }
        state.active_global += 1;
        *state
            .active_provider
            .entry(provider.to_string())
            .or_default() += 1;
        if let Some(model) = model {
            *state
                .active_model
                .entry((provider.to_string(), model.to_string()))
                .or_default() += 1;
        }
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        Some(ProviderPermits {
            controller: Arc::clone(self),
            provider: provider.to_string(),
            model: model.map(str::to_string),
        })
    }

    fn can_admit(&self, state: &AdmissionState, pending: &PendingAdmission) -> bool {
        self.can_admit_parts(state, &pending.provider, pending.model.as_deref())
    }

    fn can_admit_parts(&self, state: &AdmissionState, provider: &str, model: Option<&str>) -> bool {
        if state.active_global >= self.limits.max_global_provider_concurrency {
            return false;
        }
        if state.active_provider.get(provider).copied().unwrap_or(0)
            >= self.limits.max_provider_concurrency
        {
            return false;
        }
        model.is_none_or(|model| {
            state
                .active_model
                .get(&(provider.to_string(), model.to_string()))
                .copied()
                .unwrap_or(0)
                < self.limits.max_model_concurrency
        })
    }

    fn cancel_pending(self: &Arc<Self>, ticket: usize) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let Some(index) = state
            .queue
            .iter()
            .position(|pending| pending.ticket == ticket)
        else {
            return;
        };
        let pending = state.queue.remove(index).expect("pending admission index");
        state.pending_global = state.pending_global.saturating_sub(1);
        decrement_count(&mut state.pending_provider, &pending.provider);
        self.pending_requests.fetch_sub(1, Ordering::Relaxed);
        let grants = self.schedule_pending_locked(&mut state);
        drop(state);
        self.send_grants(grants);
    }

    fn release(self: &Arc<Self>, provider: &str, model: Option<&str>) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.active_global = state.active_global.saturating_sub(1);
        decrement_count(&mut state.active_provider, &provider.to_string());
        if let Some(model) = model {
            decrement_count(
                &mut state.active_model,
                &(provider.to_string(), model.to_string()),
            );
        }
        self.active_requests.fetch_sub(1, Ordering::Relaxed);
        let grants = self.schedule_pending_locked(&mut state);
        drop(state);
        self.send_grants(grants);
    }

    /// Grant the oldest eligible pending requests without waking every waiter.
    ///
    /// The queue is scanned from the front so an eligible request cannot be
    /// leapfrogged by a newer request. Requests for a saturated provider/model
    /// may be skipped so unrelated providers continue making progress.
    fn schedule_pending(self: &Arc<Self>) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let grants = self.schedule_pending_locked(&mut state);
        drop(state);
        self.send_grants(grants);
    }

    fn schedule_pending_locked(
        self: &Arc<Self>,
        state: &mut AdmissionState,
    ) -> Vec<(oneshot::Sender<ProviderPermits>, ProviderPermits)> {
        let mut grants = Vec::new();
        while let Some(index) = state
            .queue
            .iter()
            .position(|pending| self.can_admit(state, pending))
        {
            let pending = state.queue.remove(index).expect("pending admission index");
            state.pending_global = state.pending_global.saturating_sub(1);
            decrement_count(&mut state.pending_provider, &pending.provider);
            state.active_global += 1;
            *state
                .active_provider
                .entry(pending.provider.clone())
                .or_default() += 1;
            if let Some(model) = &pending.model {
                *state
                    .active_model
                    .entry((pending.provider.clone(), model.clone()))
                    .or_default() += 1;
            }
            self.pending_requests.fetch_sub(1, Ordering::Relaxed);
            self.active_requests.fetch_add(1, Ordering::Relaxed);
            let permits = ProviderPermits {
                controller: Arc::clone(self),
                provider: pending.provider,
                model: pending.model,
            };
            grants.push((pending.grant, permits));
        }
        grants
    }

    fn send_grants(&self, grants: Vec<(oneshot::Sender<ProviderPermits>, ProviderPermits)>) {
        for (grant, permits) in grants {
            if grant.send(permits).is_err() {
                // A cancelled receiver drops the permit, returning capacity to
                // the scheduler through ProviderPermits::drop.
            }
        }
    }
}

pub(crate) struct ProviderPermits {
    controller: Arc<ProviderConcurrency>,
    provider: String,
    model: Option<String>,
}

struct GuardedProviderStream {
    stream: LlmJsonStream,
    permits: Option<ProviderPermits>,
}

impl Stream for GuardedProviderStream {
    type Item = FlowResult<Json>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_next(cx);
        if matches!(result, Poll::Ready(None)) {
            this.permits.take();
        }
        result
    }
}

impl LlmStreamInner for GuardedProviderStream {
    fn terminalize(self: Pin<&mut Self>) {
        let this = self.get_mut();
        Pin::new(&mut this.stream).terminalize();
    }

    fn close(self: Pin<&mut Self>) -> Pin<Box<dyn Future<Output = FlowResult<()>> + Send + '_>> {
        Box::pin(async move {
            let this = self.get_mut();
            let result = this.stream.close().await;
            this.permits.take();
            result
        })
    }
}

impl Drop for ProviderPermits {
    fn drop(&mut self) {
        self.controller
            .release(&self.provider, self.model.as_deref());
    }
}

fn decrement_count<K>(counts: &mut HashMap<K, usize>, key: &K)
where
    K: Eq + std::hash::Hash,
{
    if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(key);
        }
    }
}

/// A keyed set of live provider calls shared by concurrent cache misses.
pub(crate) struct SingleFlight<T> {
    calls: Arc<Mutex<HashMap<String, ActiveCall<T>>>>,
    limits: SingleFlightLimits,
    concurrency: Arc<ProviderConcurrency>,
    counters: Arc<Counters>,
}

impl<T> Default for SingleFlight<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new(SingleFlightLimits::default())
    }
}

impl<T> SingleFlight<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Create a single-flight set with independent provider concurrency limits.
    pub(crate) fn new(limits: SingleFlightLimits) -> Self {
        let concurrency = Arc::new(ProviderConcurrency::new(limits.clone()));
        Self::with_concurrency(limits, concurrency)
    }

    /// Create a single-flight set sharing a provider concurrency limiter.
    pub(crate) fn with_concurrency(
        limits: SingleFlightLimits,
        concurrency: Arc<ProviderConcurrency>,
    ) -> Self {
        Self {
            calls: Arc::new(Mutex::new(HashMap::new())),
            limits,
            concurrency,
            counters: Arc::new(Counters::default()),
        }
    }

    /// Run `future` once for `key`, returning whether this caller installed it.
    ///
    /// A detached driver keeps the provider call alive if the first caller is
    /// cancelled. The entry is removed after completion so failures and
    /// timeouts can be retried by a later request.
    #[cfg(test)]
    pub(crate) async fn run<F>(&self, key: String, future: F) -> (FlowResult<T>, bool)
    where
        F: Future<Output = FlowResult<T>> + Send + 'static,
    {
        self.run_with_context(key, "unknown", None, future).await
    }

    /// Like [`Self::run`], but bounds live work by provider and optional model.
    pub(crate) async fn run_with_context<F>(
        &self,
        key: String,
        provider: &str,
        model: Option<&str>,
        future: F,
    ) -> (FlowResult<T>, bool)
    where
        F: Future<Output = FlowResult<T>> + Send + 'static,
    {
        let (call, leader, waiter, leader_call_id) = {
            let mut calls = self.calls.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(active) = calls.get_mut(&key) {
                if active.waiters >= self.limits.max_waiters_per_key {
                    self.counters.rejections.fetch_add(1, Ordering::Relaxed);
                    return (
                        Err(FlowError::ResourceExhausted {
                            resource: "singleflight.waiters_per_key",
                            limit: self.limits.max_waiters_per_key,
                        }),
                        false,
                    );
                }
                if !self
                    .counters
                    .try_reserve_waiter(self.limits.max_global_waiters)
                {
                    self.counters.rejections.fetch_add(1, Ordering::Relaxed);
                    return (
                        Err(FlowError::ResourceExhausted {
                            resource: "singleflight.global_waiters",
                            limit: self.limits.max_global_waiters,
                        }),
                        false,
                    );
                }
                active.waiters += 1;
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                (
                    active.call.clone(),
                    false,
                    Some(WaiterReservation {
                        calls: Arc::clone(&self.calls),
                        key: key.clone(),
                        call_id: active.id,
                        counters: Arc::clone(&self.counters),
                    }),
                    None,
                )
            } else {
                if calls.len() >= self.limits.max_active_keys {
                    self.counters.rejections.fetch_add(1, Ordering::Relaxed);
                    return (
                        Err(FlowError::ResourceExhausted {
                            resource: "singleflight.active_keys",
                            limit: self.limits.max_active_keys,
                        }),
                        false,
                    );
                }
                let concurrency = Arc::clone(&self.concurrency);
                let provider = provider.to_string();
                let model = model.map(str::to_string);
                let call = async move {
                    let _permits = concurrency.acquire(&provider, model.as_deref()).await?;
                    future.await
                }
                .boxed()
                .shared();
                let call_id = self.counters.new_calls.fetch_add(1, Ordering::Relaxed);
                calls.insert(
                    key.clone(),
                    ActiveCall {
                        id: call_id,
                        call: call.clone(),
                        waiters: 0,
                    },
                );
                self.counters.active_keys.fetch_add(1, Ordering::Relaxed);
                (call, true, None, Some(call_id))
            }
        };

        if leader {
            let driver = call.clone();
            let calls = Arc::clone(&self.calls);
            let counters = Arc::clone(&self.counters);
            let call_id = leader_call_id.expect("single-flight leader must have a call id");
            let driver_key = key.clone();
            tokio::spawn(async move {
                let _ = driver.await;
                remove_completed_call(&calls, &counters, &driver_key, call_id);
            });
        }

        let result = call.await;
        if leader {
            // Remove a completed entry before returning to the caller. Without
            // this synchronous cleanup, an immediate retry can join the
            // already-completed shared future and replay a provider error (or
            // an uncached response) as if it were a cache hit. The detached
            // driver remains as the cancellation-safe fallback and uses the
            // call id to avoid removing a newer call for the same key.
            remove_completed_call(
                &self.calls,
                &self.counters,
                &key,
                leader_call_id.expect("single-flight leader must have a call id"),
            );
        }
        drop(waiter);
        (result, leader)
    }

    /// Run work through the limiter shared by this single-flight set without
    /// requiring a cache key. This covers uncached and fail-open executions.
    pub(crate) async fn execute<F, U>(
        &self,
        provider: &str,
        model: Option<&str>,
        future: F,
    ) -> FlowResult<U>
    where
        F: Future<Output = FlowResult<U>>,
    {
        self.concurrency.execute(provider, model, future).await
    }

    /// Return bounded-resource counters for focused pressure tests.
    #[cfg(test)]
    pub(crate) fn stats(&self) -> SingleFlightStats {
        SingleFlightStats {
            active_keys: self.counters.active_keys.load(Ordering::Relaxed),
            waiters: self.counters.waiters.load(Ordering::Relaxed),
            hits: self.counters.hits.load(Ordering::Relaxed),
            new_calls: self.counters.new_calls.load(Ordering::Relaxed),
            rejections: self.counters.rejections.load(Ordering::Relaxed),
            provider_active_requests: self.concurrency.active_requests(),
            provider_pending_requests: self.concurrency.pending_requests(),
        }
    }
}

struct WaiterReservation<T> {
    calls: Arc<Mutex<HashMap<String, ActiveCall<T>>>>,
    key: String,
    // A completed entry may leave the map before every follower has dropped its
    // reservation. Never decrement a later call that reused the same key.
    call_id: usize,
    counters: Arc<Counters>,
}

impl<T> Drop for WaiterReservation<T> {
    fn drop(&mut self) {
        if let Some(active) = self
            .calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(&self.key)
            && active.id == self.call_id
        {
            active.waiters = active.waiters.saturating_sub(1);
        }
        self.counters.waiters.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
#[path = "../../tests/unit/response_cache/singleflight_tests.rs"]
mod tests;
