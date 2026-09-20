// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The process boundary, exercised end to end.
//!
//! These are the first tests in which a plugin lifecycle operation crosses a
//! process boundary: a real child is spawned, it handshakes over a socket it
//! was told about and a credential it was given out of band, and the kernel's
//! operations are answered by that process rather than by a library call.

use std::path::PathBuf;
use std::time::Duration;

use nemo_relay::plugin::execution::PluginExecutionBackend;
use nemo_relay_plugin_host::conformance;
use nemo_relay_plugin_host::supervisor::{PluginHostSupervisorConfig, ProcessPluginBackend};
use nemo_relay_plugin_protocol::{PROTOCOL_VERSION, PluginExecutionContext, PluginFailureCode};

/// The host binary this crate builds, handed to the test by cargo.
fn host_executable() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nemo-plugin-host"))
}

fn host_config() -> PluginHostSupervisorConfig {
    PluginHostSupervisorConfig {
        executable: host_executable(),
        runtime_binding_digest: "test-runtime-binding".into(),
        offered_read_capabilities: Vec::new(),
        startup_timeout: Duration::from_secs(20),
    }
}

fn context() -> PluginExecutionContext {
    PluginExecutionContext {
        operation_request_id: "operation-1".into(),
        protocol_version: PROTOCOL_VERSION,
        runtime_binding_digest: "test-runtime-binding".into(),
        deadline_unix_ms: u64::MAX,
        remaining_budget_millis: 30_000,
        max_response_bytes: 1024,
    }
}

#[tokio::test]
async fn the_process_backend_satisfies_the_same_conformance_suite() {
    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");

    // The same suite the in-process backend runs, with no forked expectations:
    // if the two implementations disagree, they disagree here.
    let findings = conformance::check(&backend).await;

    assert!(findings.is_empty(), "{findings:#?}");
    assert!(
        backend.process_id().is_some(),
        "the backend should hold a running host"
    );
}

#[tokio::test]
async fn a_host_that_has_exited_is_a_crash_and_not_an_answer() {
    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");

    backend.kill().await.expect("the host should be killable");

    let error = backend
        .health(context())
        .await
        .expect_err("a host that exited cannot answer");

    // A process that ended and a message that did not arrive call for different
    // responses, so the two are never collapsed into one.
    assert_eq!(
        error.failure.code,
        PluginFailureCode::HostCrashed,
        "{error:?}"
    );
}

#[tokio::test]
async fn killing_the_host_does_not_kill_the_kernel() {
    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");
    backend.kill().await.expect("the host should be killable");

    // The failing operation is the boundary's, and the kernel it belongs to is
    // still running: that is the whole point of the separation.
    for _ in 0..2 {
        let error = backend
            .inspect(
                nemo_relay_plugin_protocol::PluginInspectRequest { handle: None },
                context(),
            )
            .await
            .expect_err("a host that exited cannot be inspected");
        assert_eq!(error.failure.code, PluginFailureCode::HostCrashed);
    }
}

#[tokio::test]
async fn a_crashed_host_is_replaced_by_one_that_holds_nothing() {
    let mut backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");
    let crashed_session = backend.session().session_id.clone();
    backend.kill().await.expect("the host should be killable");
    assert!(
        backend.exit_status().await.is_some(),
        "the host should be observed as exited"
    );

    backend.restart().await.expect("a fresh host should start");

    // A new session, and nothing loaded: the previous host's session and the
    // generations behind its handles belonged to it, so a handle from before the
    // crash addresses nothing here.
    assert_ne!(backend.session().session_id, crashed_session);
    let descriptors = backend
        .inspect(
            nemo_relay_plugin_protocol::PluginInspectRequest { handle: None },
            context(),
        )
        .await
        .expect("a fresh host answers");
    assert!(descriptors.is_empty());
}

#[tokio::test]
async fn an_operation_that_may_not_start_is_refused_before_it_crosses() {
    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");

    let expired = PluginExecutionContext {
        operation_request_id: "operation-expired".into(),
        protocol_version: PROTOCOL_VERSION,
        runtime_binding_digest: "test-runtime-binding".into(),
        // A deadline already in the past: the host must not be asked to do work
        // the kernel has no time to wait for.
        deadline_unix_ms: 1,
        remaining_budget_millis: 30_000,
        max_response_bytes: 1024,
    };
    let error = backend
        .health(expired)
        .await
        .expect_err("an operation that is already out of time");

    assert_eq!(error.failure.code, PluginFailureCode::DeadlineExceeded);
}
