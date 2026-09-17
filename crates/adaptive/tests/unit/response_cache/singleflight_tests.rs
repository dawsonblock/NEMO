// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use nemo_relay::api::runtime::LlmJsonStream;
use nemo_relay::error::FlowError;
use serde_json::json;
use tokio::sync::{Notify, mpsc};
use tokio_stream::StreamExt;

use super::*;

#[tokio::test]
async fn concurrent_identical_calls_execute_provider_once() {
    let flight = Arc::new(SingleFlight::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());

    let first = {
        let flight = Arc::clone(&flight);
        let calls = Arc::clone(&calls);
        let release = Arc::clone(&release);
        tokio::spawn(async move {
            flight
                .run("same-key".into(), async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    release.notified().await;
                    Ok(json!({"answer": 42}))
                })
                .await
        })
    };

    while calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    let second = {
        let flight = Arc::clone(&flight);
        let calls = Arc::clone(&calls);
        tokio::spawn(async move {
            flight
                .run("same-key".into(), async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({"wrong": true}))
                })
                .await
        })
    };

    tokio::task::yield_now().await;
    release.notify_one();
    let (first_result, first_leader) = first.await.unwrap();
    let (second_result, second_leader) = second.await.unwrap();

    assert_eq!(first_result.unwrap(), json!({"answer": 42}));
    assert_eq!(second_result.unwrap(), json!({"answer": 42}));
    assert!(first_leader);
    assert!(!second_leader);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn leader_cancellation_does_not_cancel_shared_provider_call() {
    let flight = Arc::new(SingleFlight::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());

    let leader = {
        let flight = Arc::clone(&flight);
        let calls = Arc::clone(&calls);
        let release = Arc::clone(&release);
        tokio::spawn(async move {
            flight
                .run("cancel-key".into(), async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    release.notified().await;
                    Ok(json!("complete"))
                })
                .await
        })
    };

    while calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    let follower = {
        let flight = Arc::clone(&flight);
        tokio::spawn(async move {
            flight
                .run("cancel-key".into(), async { Ok(json!("wrong")) })
                .await
        })
    };

    tokio::task::yield_now().await;
    leader.abort();
    release.notify_one();
    let (result, is_leader) = follower.await.unwrap();

    assert_eq!(result.unwrap(), json!("complete"));
    assert!(!is_leader);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn active_key_admission_rejects_distinct_work_at_the_configured_limit() {
    let flight = Arc::new(SingleFlight::new(SingleFlightLimits {
        max_active_keys: 1,
        ..SingleFlightLimits::default()
    }));
    let calls = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());

    let leader = {
        let flight = Arc::clone(&flight);
        let calls = Arc::clone(&calls);
        let release = Arc::clone(&release);
        tokio::spawn(async move {
            flight
                .run("first-key".into(), async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    release.notified().await;
                    Ok(json!("first"))
                })
                .await
        })
    };

    while calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    let (result, is_leader) = flight
        .run("second-key".into(), async { Ok(json!("must not run")) })
        .await;
    assert!(!is_leader);
    assert!(matches!(
        result,
        Err(FlowError::ResourceExhausted {
            resource: "singleflight.active_keys",
            limit: 1,
        })
    ));
    assert_eq!(flight.stats().rejections, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    release.notify_one();
    assert_eq!(leader.await.unwrap().0.unwrap(), json!("first"));
}

#[tokio::test]
async fn follower_admission_is_bounded_and_cancellation_releases_its_reservation() {
    let flight = Arc::new(SingleFlight::new(SingleFlightLimits {
        max_waiters_per_key: 1,
        ..SingleFlightLimits::default()
    }));
    let calls = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());

    let leader = {
        let flight = Arc::clone(&flight);
        let calls = Arc::clone(&calls);
        let release = Arc::clone(&release);
        tokio::spawn(async move {
            flight
                .run("hot-key".into(), async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    release.notified().await;
                    Ok(json!("complete"))
                })
                .await
        })
    };
    while calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    let follower = {
        let flight = Arc::clone(&flight);
        tokio::spawn(async move {
            flight
                .run("hot-key".into(), async { Ok(json!("must not run")) })
                .await
        })
    };
    while flight.stats().waiters != 1 {
        tokio::task::yield_now().await;
    }

    let (result, is_leader) = flight
        .run("hot-key".into(), async { Ok(json!("must not run")) })
        .await;
    assert!(!is_leader);
    assert!(matches!(
        result,
        Err(FlowError::ResourceExhausted {
            resource: "singleflight.waiters_per_key",
            limit: 1,
        })
    ));
    assert_eq!(flight.stats().rejections, 1);

    follower.abort();
    let _ = follower.await;
    while flight.stats().waiters != 0 {
        tokio::task::yield_now().await;
    }

    release.notify_one();
    assert_eq!(leader.await.unwrap().0.unwrap(), json!("complete"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn global_follower_admission_is_bounded_across_keys() {
    let flight = Arc::new(SingleFlight::new(SingleFlightLimits {
        max_global_waiters: 1,
        ..SingleFlightLimits::default()
    }));
    let release = Arc::new(Notify::new());

    let leader = {
        let flight = Arc::clone(&flight);
        let release = Arc::clone(&release);
        tokio::spawn(async move {
            flight
                .run("global-waiter-key".into(), async move {
                    release.notified().await;
                    Ok(json!("complete"))
                })
                .await
        })
    };
    tokio::task::yield_now().await;

    let follower = {
        let flight = Arc::clone(&flight);
        tokio::spawn(async move {
            flight
                .run("global-waiter-key".into(), async { Ok(json!("wrong")) })
                .await
        })
    };
    while flight.stats().waiters < 1 {
        tokio::task::yield_now().await;
    }

    let (result, is_leader) = flight
        .run("global-waiter-key".into(), async { Ok(json!("wrong")) })
        .await;
    assert!(!is_leader);
    assert!(matches!(
        result,
        Err(FlowError::ResourceExhausted {
            resource: "singleflight.global_waiters",
            limit: 1,
        })
    ));

    release.notify_one();
    assert_eq!(leader.await.unwrap().0.unwrap(), json!("complete"));
    assert_eq!(follower.await.unwrap().0.unwrap(), json!("complete"));
    assert_eq!(flight.stats().waiters, 0);
}

#[tokio::test]
async fn streaming_provider_permit_lives_until_stream_eof() {
    let limits = SingleFlightLimits {
        max_global_provider_concurrency: 1,
        ..SingleFlightLimits::default()
    };
    let concurrency = Arc::new(ProviderConcurrency::new(limits));
    let permits = concurrency
        .acquire("provider", Some("model"))
        .await
        .unwrap();
    let mut stream = concurrency.guard_stream(
        LlmJsonStream::new(tokio_stream::iter(vec![Ok(json!({"chunk": 1}))])),
        permits,
    );

    assert_eq!(concurrency.active_requests(), 1);
    assert_eq!(stream.next().await.unwrap().unwrap(), json!({"chunk": 1}));
    assert_eq!(concurrency.active_requests(), 1);
    assert!(stream.next().await.is_none());
    assert_eq!(concurrency.active_requests(), 0);
}

#[tokio::test]
async fn streaming_provider_permit_lives_through_terminalization_until_close() {
    let concurrency = Arc::new(ProviderConcurrency::new(SingleFlightLimits {
        max_global_provider_concurrency: 1,
        ..SingleFlightLimits::default()
    }));
    let permits = concurrency
        .acquire("provider", Some("model"))
        .await
        .unwrap();
    let mut stream = concurrency.guard_stream(
        LlmJsonStream::new(tokio_stream::iter(vec![Ok(json!({"chunk": 1}))])),
        permits,
    );

    stream.terminalize();
    assert_eq!(concurrency.active_requests(), 1);
    stream.close().await.unwrap();
    assert_eq!(concurrency.active_requests(), 0);
}

#[tokio::test]
async fn provider_pending_admission_is_bounded() {
    let concurrency = Arc::new(ProviderConcurrency::new(SingleFlightLimits {
        max_global_provider_concurrency: 1,
        max_provider_concurrency: 1,
        max_model_concurrency: 1,
        max_pending_provider_requests: 2,
        provider_admission_timeout_ms: 1000,
        ..SingleFlightLimits::default()
    }));
    let first = concurrency
        .acquire("provider", Some("model"))
        .await
        .unwrap();

    let pending_a = {
        let concurrency = Arc::clone(&concurrency);
        tokio::spawn(async move { concurrency.acquire("provider", Some("model")).await })
    };
    let pending_b = {
        let concurrency = Arc::clone(&concurrency);
        tokio::spawn(async move { concurrency.acquire("provider", Some("model")).await })
    };
    while concurrency.pending_requests() != 2 {
        tokio::task::yield_now().await;
    }

    let rejected = concurrency.acquire("provider", Some("model")).await;
    assert!(matches!(
        rejected,
        Err(FlowError::ResourceExhausted {
            resource: "provider_admission.pending",
            limit: 2,
        })
    ));

    pending_a.abort();
    pending_b.abort();
    let _ = pending_a.await;
    let _ = pending_b.await;
    assert_eq!(concurrency.pending_requests(), 0);
    drop(first);
    assert_eq!(concurrency.active_requests(), 0);
}

#[tokio::test]
async fn provider_admission_timeout_releases_pending_state() {
    let concurrency = Arc::new(ProviderConcurrency::new(SingleFlightLimits {
        max_global_provider_concurrency: 1,
        max_provider_concurrency: 1,
        max_model_concurrency: 1,
        max_pending_provider_requests: 1,
        provider_admission_timeout_ms: 5,
        ..SingleFlightLimits::default()
    }));
    let first = concurrency
        .acquire("provider", Some("model"))
        .await
        .unwrap();
    let timed_out = concurrency.acquire("provider", Some("model")).await;
    assert!(matches!(
        timed_out,
        Err(FlowError::Timeout {
            resource: "provider_admission",
        })
    ));
    assert_eq!(concurrency.pending_requests(), 0);
    drop(first);
}

#[tokio::test]
async fn provider_admission_skips_blocked_provider_without_starving_other_provider() {
    let concurrency = Arc::new(ProviderConcurrency::new(SingleFlightLimits {
        max_global_provider_concurrency: 2,
        max_provider_concurrency: 1,
        max_model_concurrency: 1,
        provider_admission_timeout_ms: 1000,
        ..SingleFlightLimits::default()
    }));
    let first_a = concurrency
        .acquire("provider-a", Some("model"))
        .await
        .unwrap();

    let pending_a = {
        let concurrency = Arc::clone(&concurrency);
        tokio::spawn(async move { concurrency.acquire("provider-a", Some("model")).await })
    };
    while concurrency.pending_requests() != 1 {
        tokio::task::yield_now().await;
    }

    let second_b = concurrency
        .acquire("provider-b", Some("model"))
        .await
        .unwrap();
    assert_eq!(concurrency.active_requests(), 2);
    drop(second_b);
    drop(first_a);
    let admitted_a = pending_a.await.unwrap().unwrap();
    drop(admitted_a);
    assert_eq!(concurrency.active_requests(), 0);
}

#[tokio::test]
async fn immediate_admission_bypasses_a_full_unrelated_pending_queue() {
    let concurrency = Arc::new(ProviderConcurrency::new(SingleFlightLimits {
        max_global_provider_concurrency: 2,
        max_provider_concurrency: 1,
        max_model_concurrency: 1,
        max_pending_provider_requests: 1,
        max_pending_provider_per_provider: 1,
        provider_admission_timeout_ms: 1000,
        ..SingleFlightLimits::default()
    }));
    let first_a = concurrency
        .acquire("provider-a", Some("model"))
        .await
        .unwrap();
    let pending_a = {
        let concurrency = Arc::clone(&concurrency);
        tokio::spawn(async move { concurrency.acquire("provider-a", Some("model")).await })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while concurrency.pending_requests() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("provider-a pending request was not enqueued");

    // The pending queue is full for provider A, but global capacity remains
    // available. Provider B must be admitted immediately rather than rejected
    // because another provider is saturated.
    let second_b = concurrency
        .acquire("provider-b", Some("model"))
        .await
        .unwrap();
    assert_eq!(concurrency.active_requests(), 2);
    drop(second_b);
    drop(first_a);
    let admitted_a = pending_a.await.unwrap().unwrap();
    drop(admitted_a);
    assert_eq!(concurrency.active_requests(), 0);
    assert_eq!(concurrency.pending_requests(), 0);
}

#[tokio::test]
async fn release_grants_existing_eligible_waiter_before_new_arrival() {
    for _ in 0..64 {
        let concurrency = Arc::new(ProviderConcurrency::new(SingleFlightLimits {
            max_global_provider_concurrency: 1,
            max_provider_concurrency: 1,
            max_model_concurrency: 1,
            max_pending_provider_requests: 4,
            max_pending_provider_per_provider: 4,
            provider_admission_timeout_ms: 1000,
            ..SingleFlightLimits::default()
        }));
        let first = concurrency
            .acquire("provider", Some("model"))
            .await
            .unwrap();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let waiting = {
            let concurrency = Arc::clone(&concurrency);
            let sender = sender.clone();
            tokio::spawn(async move {
                let permit = concurrency
                    .acquire("provider", Some("model"))
                    .await
                    .unwrap();
                sender.send('a').unwrap();
                drop(permit);
            })
        };
        while concurrency.pending_requests() != 1 {
            tokio::task::yield_now().await;
        }

        drop(first);
        let arriving = {
            let concurrency = Arc::clone(&concurrency);
            tokio::spawn(async move {
                let permit = concurrency
                    .acquire("provider", Some("model"))
                    .await
                    .unwrap();
                sender.send('b').unwrap();
                drop(permit);
            })
        };

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), receiver.recv())
                .await
                .unwrap(),
            Some('a')
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), receiver.recv())
                .await
                .unwrap(),
            Some('b')
        );
        waiting.await.unwrap();
        arriving.await.unwrap();
        assert_eq!(concurrency.active_requests(), 0);
        assert_eq!(concurrency.pending_requests(), 0);
    }
}

#[tokio::test]
async fn provider_model_limit_serializes_distinct_cache_misses() {
    let flight = Arc::new(SingleFlight::new(SingleFlightLimits {
        max_active_keys: 2,
        max_global_provider_concurrency: 2,
        max_provider_concurrency: 2,
        max_model_concurrency: 1,
        ..SingleFlightLimits::default()
    }));
    let first_started = Arc::new(AtomicUsize::new(0));
    let second_started = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());

    let first = {
        let flight = Arc::clone(&flight);
        let first_started = Arc::clone(&first_started);
        let release = Arc::clone(&release);
        tokio::spawn(async move {
            flight
                .run_with_context("first-key".into(), "provider", Some("model"), async move {
                    first_started.fetch_add(1, Ordering::SeqCst);
                    release.notified().await;
                    Ok(json!("first"))
                })
                .await
        })
    };
    while first_started.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    let second = {
        let flight = Arc::clone(&flight);
        let second_started = Arc::clone(&second_started);
        tokio::spawn(async move {
            flight
                .run_with_context("second-key".into(), "provider", Some("model"), async move {
                    second_started.fetch_add(1, Ordering::SeqCst);
                    Ok(json!("second"))
                })
                .await
        })
    };
    while flight.stats().active_keys != 2 {
        tokio::task::yield_now().await;
    }
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(second_started.load(Ordering::SeqCst), 0);
    assert_eq!(flight.stats().provider_active_requests, 1);

    release.notify_one();
    assert_eq!(first.await.unwrap().0.unwrap(), json!("first"));
    assert_eq!(second.await.unwrap().0.unwrap(), json!("second"));
    assert_eq!(flight.stats().provider_active_requests, 0);
}
