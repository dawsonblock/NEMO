// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use nemo_relay::error::FlowError;
use serde_json::json;
use tokio::sync::Notify;

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
