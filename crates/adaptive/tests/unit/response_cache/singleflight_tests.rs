// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    release.notify_waiters();
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
    release.notify_waiters();
    let (result, is_leader) = follower.await.unwrap();

    assert_eq!(result.unwrap(), json!("complete"));
    assert!(!is_leader);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
