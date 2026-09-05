// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-local collapse of concurrent identical cache misses.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use nemo_relay::error::Result as FlowResult;

type SharedCall<T> = Shared<BoxFuture<'static, FlowResult<T>>>;

/// A keyed set of live provider calls shared by concurrent cache misses.
pub(crate) struct SingleFlight<T> {
    calls: Arc<Mutex<HashMap<String, SharedCall<T>>>>,
}

impl<T> Default for SingleFlight<T> {
    fn default() -> Self {
        Self {
            calls: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<T> SingleFlight<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Run `future` once for `key`, returning whether this caller installed it.
    ///
    /// A detached driver keeps the provider call alive if the first caller is
    /// cancelled. The entry is removed after completion so failures and
    /// timeouts can be retried by a later request.
    pub(crate) async fn run<F>(&self, key: String, future: F) -> (FlowResult<T>, bool)
    where
        F: Future<Output = FlowResult<T>> + Send + 'static,
    {
        let (call, leader) = {
            let mut calls = self.calls.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(call) = calls.get(&key) {
                (call.clone(), false)
            } else {
                let call = future.boxed().shared();
                calls.insert(key.clone(), call.clone());
                (call, true)
            }
        };

        if leader {
            let driver = call.clone();
            let calls = Arc::clone(&self.calls);
            tokio::spawn(async move {
                let _ = driver.await;
                calls
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remove(&key);
            });
        }

        (call.await, leader)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/response_cache/singleflight_tests.rs"]
mod tests;
