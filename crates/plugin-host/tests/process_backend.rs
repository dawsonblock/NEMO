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
        // The host is started with the runtime binding its operations must
        // claim: the suite's contexts are bound to this runtime, and the host now
        // refuses a context bound to another one.
        runtime_binding_digest: "conformance-binding".into(),
        offered_read_capabilities: Vec::new(),
        maximum_frame_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        startup_timeout: Duration::from_secs(20),
    }
}

fn context() -> PluginExecutionContext {
    PluginExecutionContext {
        operation_request_id: "operation-1".into(),
        protocol_version: PROTOCOL_VERSION,
        runtime_binding_digest: "conformance-binding".into(),
        deadline_unix_ms: u64::MAX,
        remaining_budget_millis: 30_000,
        max_response_bytes: 1024,
    }
}

/// Wall-clock milliseconds, for an absolute deadline.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_millis() as u64
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
async fn a_real_native_plugin_loads_in_the_child_and_only_there() {
    use nemo_relay::plugin::dynamic::plugin_artifact_identity;
    use nemo_relay_plugin_protocol::{PluginArtifactIdentity, PluginLoadRequest};

    let library = std::env::var_os("NEMO_RELAY_TEST_NATIVE_PLUGIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/test-plugin-fixtures/debug/libnemo_relay_plugin_fixture.dylib")
        });
    assert!(
        library.exists(),
        "the native fixture is missing; run `just build-test-plugin-fixtures`: {}",
        library.display()
    );

    // A manifest in its own directory, written here so this test says exactly
    // what it loads rather than borrowing another suite's helper.
    let manifest_dir = std::env::temp_dir().join(format!(
        "nemo-ph-manifest-{}",
        nemo_relay_plugin_protocol::Uuid::now_v7().simple()
    ));
    std::fs::create_dir_all(&manifest_dir).expect("a manifest directory");
    let manifest = manifest_dir.join("relay-plugin.toml");
    std::fs::write(
        &manifest,
        format!(
            "manifest_version = 1\n\n[plugin]\nid = \"fixture_native\"\nkind = \"rust_dynamic\"\n\n[compat]\nrelay = \"={}\"\nnative_api = \"1\"\n\n[defaults]\nenabled = false\n\n[capabilities]\nitems = [\"plugin_native\"]\n\n[load]\nlibrary = \"{}\"\nsymbol = \"nemo_relay_fixture_native_plugin\"\n",
            env!("CARGO_PKG_VERSION"),
            library.display()
        ),
    )
    .expect("write the manifest");

    let artifact = manifest.to_string_lossy().into_owned();
    let (manifest_sha256, library_sha256) =
        plugin_artifact_identity(&artifact).expect("the identity of an existing artifact");
    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");

    // The identity the kernel approves is the identity the child verifies: an
    // artifact that is not the approved one is refused rather than loaded.
    let wrong = backend
        .load(
            PluginLoadRequest {
                plugin_id: "fixture_native".into(),
                artifact: artifact.clone(),
                identity: PluginArtifactIdentity {
                    manifest_sha256: "0".repeat(64),
                    library_sha256: library_sha256.clone(),
                },
            },
            context(),
        )
        .await
        .expect_err("an artifact that is not the approved one");
    assert_eq!(wrong.failure.code, PluginFailureCode::Rejected, "{wrong:?}");

    let loaded = backend
        .load(
            PluginLoadRequest {
                plugin_id: "fixture_native".into(),
                artifact,
                identity: PluginArtifactIdentity {
                    manifest_sha256: manifest_sha256.clone(),
                    library_sha256,
                },
            },
            context(),
        )
        .await
        .expect("the approved artifact");

    // The approved digest, the verified digest and the reported one are the same
    // value, so the evidence chain has no gap in it.
    assert_eq!(
        loaded.descriptor.manifest_digest.as_deref(),
        Some(manifest_sha256.as_str())
    );
    assert_eq!(loaded.handle.plugin_id, "fixture_native");

    // The child holds it, and says so on inspection.
    let described = backend
        .inspect(
            nemo_relay_plugin_protocol::PluginInspectRequest {
                handle: Some(loaded.handle.clone()),
            },
            context(),
        )
        .await
        .expect("an inspection");
    assert_eq!(described.len(), 1);
    assert_eq!(described[0].plugin_id, "fixture_native");

    // And unloading it leaves nothing behind.
    backend
        .unload(
            nemo_relay_plugin_protocol::PluginUnloadRequest {
                handle: loaded.handle,
            },
            context(),
        )
        .await
        .expect("an unload");
    let after = backend
        .inspect(
            nemo_relay_plugin_protocol::PluginInspectRequest { handle: None },
            context(),
        )
        .await
        .expect("an inspection");
    assert!(after.is_empty(), "{after:#?}");

    let _ = std::fs::remove_dir_all(&manifest_dir);
}

#[tokio::test]
async fn a_real_tool_call_reaches_a_registration_inside_the_child() {
    use nemo_relay_plugin_protocol::{PluginActivateRequest, PluginComponentConfiguration};

    // A plugin that registers exactly one class, which is what a kernel that can
    // proxy one class needs: the other fixture registers sixteen, and activating
    // it against a one-class session is refused — correctly, but uselessly for
    // this test.
    let library = std::env::var_os("NEMO_RELAY_TEST_NATIVE_INTERCEPT_PLUGIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
                "../../target/test-plugin-fixtures/debug/libnemo_relay_native_intercept_fixture.dylib",
            )
        });
    assert!(
        library.exists(),
        "the single-registration fixture is missing; run `just build-test-plugin-fixtures`"
    );

    let manifest_dir = std::env::temp_dir().join(format!(
        "nemo-ph-intercept-{}",
        nemo_relay_plugin_protocol::Uuid::now_v7().simple()
    ));
    std::fs::create_dir_all(&manifest_dir).expect("a manifest directory");
    let manifest = manifest_dir.join("relay-plugin.toml");
    std::fs::write(
        &manifest,
        format!(
            "manifest_version = 1\n\n[plugin]\nid = \"fixture_intercept\"\nkind = \"rust_dynamic\"\n\n[compat]\nrelay = \"={}\"\nnative_api = \"1\"\n\n[defaults]\nenabled = false\n\n[capabilities]\nitems = [\"plugin_native\"]\n\n[load]\nlibrary = \"{}\"\nsymbol = \"nemo_relay_native_intercept_fixture\"\n",
            env!("CARGO_PKG_VERSION"),
            library.display()
        ),
    )
    .expect("write the manifest");

    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");
    let artifact = manifest.to_string_lossy().into_owned();
    let (manifest_sha256, library_sha256) =
        nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact)
            .expect("the fixture's identity");

    // The child loads it and runs its register callback; what comes back is the
    // registration, which is what the kernel installs a proxy from.
    let loaded = backend
        .load(
            nemo_relay_plugin_protocol::PluginLoadRequest {
                plugin_id: "fixture_intercept".into(),
                artifact,
                identity: nemo_relay_plugin_protocol::PluginArtifactIdentity {
                    manifest_sha256,
                    library_sha256,
                },
            },
            context(),
        )
        .await
        .expect("the fixture should load");
    let descriptors = backend
        .activate(
            PluginActivateRequest {
                components: vec![PluginComponentConfiguration {
                    kind: "fixture_intercept".into(),
                    config_json: "{}".into(),
                }],
            },
            context(),
        )
        .await
        .expect("the one class this backend can serve");
    let descriptor = descriptors
        .iter()
        .find(|descriptor| descriptor.plugin_id == "fixture_intercept")
        .expect("the activated plugin");

    // The kernel installs the proxy, then makes a real call through its own
    // chain: the chain runs in this process, the registration runs in the child.
    let binding = backend.runtime_binding_digest().to_owned();
    let manager = std::sync::Arc::new(nemo_relay::plugin::execution::PluginManager::new(
        std::sync::Arc::new(backend),
    ));
    let context = nemo_relay_plugin_host::proxy::ProxyContext::new(manager, binding, 5_000);
    let proxies =
        nemo_relay_plugin_host::proxy::install(context, descriptor, loaded.handle.clone())
            .expect("the kernel can proxy a tool request intercept");

    // The chain runs under the trusted budget the runtime would publish for the
    // action: without it the proxy refuses, because a registration reached
    // outside a managed action has no deadline to inherit.
    let rewritten = nemo_relay::api::runtime::with_execution_budget(
        nemo_relay::api::runtime::ExecutionBudget::new(
            nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
            30_000,
        ),
        async {
            nemo_relay::api::tool::tool_request_intercepts(
                "example_tool",
                serde_json::json!({"input": true}),
            )
            .await
        },
    )
    .await
    .expect("the chain should reach the child");
    assert_eq!(
        rewritten["native_intercept"], true,
        "the rewrite came from the plugin process: {rewritten}"
    );

    // And dropping the proxies takes the registration out of the kernel's chain.
    drop(proxies);
    let after = nemo_relay::api::tool::tool_request_intercepts(
        "example_tool",
        serde_json::json!({"input": true}),
    )
    .await
    .expect("the chain");
    assert_eq!(
        after["native_intercept"],
        serde_json::Value::Null,
        "{after}"
    );

    let _ = std::fs::remove_dir_all(&manifest_dir);
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
async fn a_host_that_stops_answering_is_killed_at_the_deadline() {
    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");
    let process_id = backend.process_id().expect("a running host");

    // Stopping the process is what a plugin that hangs looks like from the
    // kernel's side: the socket is still open and nothing will ever answer on
    // it.
    let stopped = std::process::Command::new("kill")
        .args(["-STOP", &process_id.to_string()])
        .status()
        .expect("the stop signal");
    assert!(stopped.success(), "the host should be stoppable");

    let deadline = now_unix_ms() + 500;
    let budgeted = PluginExecutionContext {
        operation_request_id: "operation-budgeted".into(),
        protocol_version: PROTOCOL_VERSION,
        runtime_binding_digest: "conformance-binding".into(),
        deadline_unix_ms: deadline,
        remaining_budget_millis: 500,
        max_response_bytes: 1024,
    };
    let error = backend
        .health(budgeted)
        .await
        .expect_err("a stopped host cannot answer");

    // A deadline that passed is a deadline, not a crash: the kernel is the one
    // that ended the process, and reporting that as `HostCrashed` would blame
    // the plugin for the kernel's own decision.
    assert_eq!(
        error.failure.code,
        PluginFailureCode::DeadlineExceeded,
        "{error:?}"
    );

    // And it is gone: the kernel killed it rather than waiting for a plugin to
    // honour a cancellation token it never agreed to.
    assert!(
        backend.exit_status().await.is_some(),
        "the host should have been killed, not merely abandoned"
    );
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
        runtime_binding_digest: "conformance-binding".into(),
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
