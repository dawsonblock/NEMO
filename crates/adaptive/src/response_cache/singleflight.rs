// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-local collapse of concurrent identical cache misses.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use nemo_relay::error::{FlowError, Result as FlowResult};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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
}

#[derive(Default)]
struct Counters {
    active_keys: AtomicUsize,
    waiters: AtomicUsize,
    hits: AtomicUsize,
    new_calls: AtomicUsize,
    rejections: AtomicUsize,
}

/// Shared provider/model concurrency limits for cache-miss provider calls.
pub(crate) struct ProviderConcurrency {
    limits: SingleFlightLimits,
    global: Arc<Semaphore>,
    providers: Mutex<HashMap<String, Weak<Semaphore>>>,
    models: Mutex<HashMap<String, Weak<Semaphore>>>,
    active_requests: AtomicUsize,
}

impl ProviderConcurrency {
    /// Create a limiter with the response-cache single-flight limits.
    pub(crate) fn new(limits: SingleFlightLimits) -> Self {
        Self {
            global: Arc::new(Semaphore::new(limits.max_global_provider_concurrency)),
            limits,
            providers: Mutex::new(HashMap::new()),
            models: Mutex::new(HashMap::new()),
            active_requests: AtomicUsize::new(0),
        }
    }

    async fn acquire(
        self: &Arc<Self>,
        provider: &str,
        model: Option<&str>,
    ) -> FlowResult<ProviderPermits> {
        let global = acquire_permit(
            Arc::clone(&self.global),
            "singleflight.global_provider_concurrency",
            self.limits.max_global_provider_concurrency,
        )
        .await?;
        let provider_permit = acquire_permit(
            scoped_semaphore(
                &self.providers,
                provider,
                self.limits.max_provider_concurrency,
            ),
            "singleflight.provider_concurrency",
            self.limits.max_provider_concurrency,
        )
        .await?;
        let model_permit = match model {
            Some(model) => Some(
                acquire_permit(
                    scoped_semaphore(
                        &self.models,
                        &format!("{provider}\u{1f}{model}"),
                        self.limits.max_model_concurrency,
                    ),
                    "singleflight.model_concurrency",
                    self.limits.max_model_concurrency,
                )
                .await?,
            ),
            None => None,
        };
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        Ok(ProviderPermits {
            _global: global,
            _provider: provider_permit,
            _model: model_permit,
            limiter: Arc::clone(self),
        })
    }

    #[cfg(test)]
    fn active_requests(&self) -> usize {
        self.active_requests.load(Ordering::Relaxed)
    }
}

struct ProviderPermits {
    _global: OwnedSemaphorePermit,
    _provider: OwnedSemaphorePermit,
    _model: Option<OwnedSemaphorePermit>,
    limiter: Arc<ProviderConcurrency>,
}

impl Drop for ProviderPermits {
    fn drop(&mut self) {
        self.limiter.active_requests.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn acquire_permit(
    semaphore: Arc<Semaphore>,
    resource: &'static str,
    limit: usize,
) -> FlowResult<OwnedSemaphorePermit> {
    semaphore
        .acquire_owned()
        .await
        .map_err(|_| FlowError::ResourceExhausted { resource, limit })
}

fn scoped_semaphore(
    entries: &Mutex<HashMap<String, Weak<Semaphore>>>,
    key: &str,
    limit: usize,
) -> Arc<Semaphore> {
    let mut entries = entries.lock().unwrap_or_else(|error| error.into_inner());
    entries.retain(|_, semaphore| semaphore.strong_count() > 0);
    if let Some(semaphore) = entries.get(key).and_then(Weak::upgrade) {
        return semaphore;
    }
    let semaphore = Arc::new(Semaphore::new(limit));
    entries.insert(key.to_string(), Arc::downgrade(&semaphore));
    semaphore
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
        let (call, leader, waiter) = {
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
                active.waiters += 1;
                self.counters.waiters.fetch_add(1, Ordering::Relaxed);
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
                (call, true, None)
            }
        };

        if leader {
            let driver = call.clone();
            let calls = Arc::clone(&self.calls);
            let counters = Arc::clone(&self.counters);
            tokio::spawn(async move {
                let _ = driver.await;
                if calls
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remove(&key)
                    .is_some()
                {
                    counters.active_keys.fetch_sub(1, Ordering::Relaxed);
                }
            });
        }

        let result = call.await;
        drop(waiter);
        (result, leader)
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
