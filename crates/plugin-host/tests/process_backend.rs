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

mod support;

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
        limits: nemo_relay_plugin_host::limits::PluginHostLimits::default(),
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

    let fixture = support::PreparedFixture::write(
        "fixture_native",
        "nemo-ph-manifest",
        support::native_fixture(),
        "nemo_relay_fixture_native_plugin",
    );
    let artifact = fixture.artifact();
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
}

// Single-threaded, deliberately: an off-path callback's answer arrives over the
// composition's own transport, created on the off-path runtime, so the caller's
// topology must not decide whether a plugin can answer. This test hung on exactly
// this runtime before that transport existed.
#[tokio::test]
async fn a_real_tool_call_reaches_a_registration_inside_the_child() {
    use nemo_relay_plugin_protocol::{PluginActivateRequest, PluginComponentConfiguration};

    // A plugin that registers exactly one class, which is what a kernel that can
    // proxy one class needs: the other fixture registers sixteen, and activating
    // it against a one-class session is refused — correctly, but uselessly for
    // this test.
    let fixture = support::PreparedFixture::write(
        "fixture_intercept",
        "nemo-ph-intercept",
        support::intercept_fixture(),
        "nemo_relay_native_intercept_fixture",
    );

    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");
    let artifact = fixture.artifact();
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
                // A serving composition, as production is.
                discovery: false,
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
    // The off-path runtime this composition would own, because the fixture
    // registers the sanitize classes too.
    let off_path = std::sync::Arc::new(
        nemo_relay_plugin_host::off_path::OffPathPluginExecutor::start(
            &nemo_relay_plugin_host::off_path::ObservabilityPolicy {
                budget_millis: 5_000,
                max_in_flight: 8,
            },
        )
        .expect("an off-path runtime"),
    );
    let context = nemo_relay_plugin_host::proxy::ProxyContext::new(manager, binding, 5_000)
        .with_observability_budget(5_000)
        .with_off_path_executor(off_path)
        // The fixture registers an execution intercept, whose continuation is the
        // kernel's own chain: a composition that cannot hold one refuses to
        // install it, which is what this registry is for.
        .with_continuations(std::sync::Arc::new(
            nemo_relay_plugin_host::continuations::Continuations::new(),
        ));
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
}

// The classes whose answer is an event, through a real child. Single-threaded for
// the same reason as the composition test above: the answer arrives over the
// composition's own transport, so the caller's thread count must not decide whether
// a sanitizer can answer.
#[tokio::test]
async fn a_real_event_sanitizer_in_the_child_changes_only_what_is_published() {
    use nemo_relay_plugin_host::ProcessLoadedPlugins;
    use nemo_relay_plugin_protocol::PluginComponentConfiguration;

    // Three mark sanitizers, two scope-start sanitizers and one scope-end sanitizer
    // are what this fixture registers, and the log is how "which of them ran" becomes
    // a fact this process can read rather than an inference from the answer.
    let log = std::env::temp_dir().join(format!(
        "nemo-event-sanitizers-{}.log",
        nemo_relay_plugin_protocol::Uuid::now_v7().simple()
    ));
    let _ = std::fs::remove_file(&log);
    let fixture = support::PreparedFixture::write(
        "fixture_intercept",
        "nemo-ph-event-sanitizers",
        support::intercept_fixture(),
        "nemo_relay_native_intercept_fixture",
    );
    let loaded = ProcessLoadedPlugins::load(
        host_config(),
        5_000,
        nemo_relay_plugin_host::off_path::ObservabilityPolicy {
            budget_millis: 5_000,
            max_in_flight: 8,
        },
        [("fixture_intercept".to_string(), fixture.artifact())],
        [PluginComponentConfiguration {
            kind: "fixture_intercept".into(),
            config_json: serde_json::json!({ "sanitizer_log": log.to_string_lossy() }).to_string(),
        }],
    )
    .await
    .expect("a plugin served from another process");

    // What this runtime published, as the runtime's own subscribers saw it.
    let published: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let published = std::sync::Arc::clone(&published);
        nemo_relay::api::subscriber::register_subscriber(
            "process-backend-event-sanitizers",
            std::sync::Arc::new(move |event: &nemo_relay::api::event::Event| {
                published.lock().unwrap().push(serde_json::json!({
                    "name": event.name(),
                    "kind": event.kind(),
                    "phase": event.scope_category().map(|phase| format!("{phase:?}")),
                    "metadata": event.metadata().cloned(),
                    "data": event.data().cloned(),
                }));
            }),
        )
        .expect("a subscriber");
    }

    // A mark this runtime emits itself, and a managed call: the mark goes through the
    // mark chain, the call's scope start and end through the two scope chains.
    nemo_relay::api::runtime::with_execution_budget(
        nemo_relay::api::runtime::ExecutionBudget::new(
            nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
            30_000,
        ),
        async {
            nemo_relay::api::scope::event(
                nemo_relay::api::scope::EmitMarkEventParams::builder()
                    .name("sanitizer-qualification-mark")
                    .build(),
            )
            .expect("an emitted mark");
            nemo_relay::api::tool::tool_call_execute(
                nemo_relay::api::tool::ToolCallExecuteParams::builder()
                    .name("sanitizer_qualification_tool")
                    .args(serde_json::json!({ "input": true }))
                    .func(std::sync::Arc::new(|args| {
                        Box::pin(async move { Ok(args.into()) })
                    }))
                    .build(),
            )
            .await
        },
    )
    .await
    .expect("a managed call whose events the sanitizers in the child are shown");
    nemo_relay::api::subscriber::flush_subscribers().expect("a flush");

    let published = published.lock().unwrap().clone();
    let markers = |event: &serde_json::Value| -> Vec<String> {
        event["metadata"]
            .as_object()
            .map(|metadata| {
                metadata
                    .iter()
                    .filter(|(_, value)| value.as_bool() == Some(true))
                    .map(|(key, _)| key.clone())
                    .filter(|key| key.starts_with("fixture_"))
                    .collect()
            })
            .unwrap_or_default()
    };

    // The mark: its own name survives — the sanitizer changes what observers see and
    // not what the event is — and all three mark registrations contributed, because
    // the chain in this process runs one proxy per registration.
    let mark = published
        .iter()
        .find(|event| event["name"] == serde_json::json!("sanitizer-qualification-mark"))
        .unwrap_or_else(|| panic!("the mark this runtime emitted was published: {published:#?}"));
    assert_eq!(
        markers(mark),
        vec!["fixture_mark_a", "fixture_mark_b", "fixture_mark_c"],
        "every mark sanitizer in the child contributed, in the chain's order"
    );

    // The two scope directions, each from its own family.
    let scope_start = published
        .iter()
        .find(|event| {
            event["kind"] == serde_json::json!("scope")
                && event["phase"] == serde_json::json!("Start")
                && markers(event)
                    .iter()
                    .any(|key| key.starts_with("fixture_scope"))
        })
        .unwrap_or_else(|| panic!("a sanitized scope start was published: {published:#?}"));
    assert_eq!(
        markers(scope_start),
        vec!["fixture_scope_start_other", "fixture_scope_start_sanitize"],
        "both scope-start registrations ran, and no other family did"
    );
    let scope_end = published
        .iter()
        .find(|event| {
            event["kind"] == serde_json::json!("scope")
                && event["phase"] == serde_json::json!("End")
                && markers(event)
                    .iter()
                    .any(|key| key.starts_with("fixture_scope"))
        })
        .unwrap_or_else(|| panic!("a sanitized scope end was published: {published:#?}"));
    assert_eq!(
        markers(scope_end),
        vec!["fixture_scope_end_sanitize"],
        "the end direction runs its own registration only"
    );

    // And the child ran exactly the registration each proxy stands for, once per
    // event: a host that ran the family per call would show each mark registration
    // as many times as the family has members, and a kernel that collapsed the three
    // proxies into one call would show one line per event. The log is read per class
    // against the number of events this runtime published, because a managed call
    // emits more than one of each.
    let ran: Vec<String> = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect();
    // The runtime's own records are published without the sanitize chain — the rule
    // that keeps a sanitizer that cannot answer from looping on the record of its own
    // failure — so they are not marks the chain serves and not counted here.
    let published_marks = published
        .iter()
        .filter(|event| {
            event["kind"] == serde_json::json!("mark")
                && !event["name"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("nemo.plugin.")
        })
        .count();
    let published_starts = published
        .iter()
        .filter(|event| {
            event["kind"] == serde_json::json!("scope")
                && event["phase"] == serde_json::json!("Start")
        })
        .count();
    let published_ends = published
        .iter()
        .filter(|event| {
            event["kind"] == serde_json::json!("scope")
                && event["phase"] == serde_json::json!("End")
        })
        .count();
    assert_eq!(
        ran.iter()
            .filter(|name| name.starts_with("fixture_mark"))
            .count(),
        published_marks * 3,
        "{published_marks} mark events, three mark registrations each: {ran:?}"
    );
    assert_eq!(
        ran.iter()
            .filter(|name| name == &"fixture_scope_start_sanitize")
            .count(),
        published_starts,
        "one scope-start sanitizer per start event: {ran:?}"
    );
    assert_eq!(
        ran.iter()
            .filter(|name| name == &"fixture_scope_start_other")
            .count(),
        published_starts,
        "and its neighbour, once per start event: {ran:?}"
    );
    assert_eq!(
        ran.iter()
            .filter(|name| name == &"fixture_scope_end_sanitize")
            .count(),
        published_ends,
        "one scope-end sanitizer per end event: {ran:?}"
    );
    // Every run of a chain is the family, once each, in priority order: three names
    // per mark event and two per start event, with no name twice in one run.
    for run in ran
        .chunks(3)
        .filter(|run| run.iter().all(|name| name.starts_with("fixture_mark")))
    {
        assert_eq!(
            run,
            ["fixture_mark_a", "fixture_mark_b", "fixture_mark_c"],
            "a mark event's chain is each registration once, in priority order: {ran:?}"
        );
    }

    nemo_relay::api::subscriber::deregister_subscriber("process-backend-event-sanitizers")
        .expect("a deregistration");
    let _ = std::fs::remove_file(&log);
    drop(loaded);
}

// The confidentiality property through a real child: a sanitizer that could not
// answer must not become a path by which what it was shown reaches anything
// publishable. The proxy's own test asserts this with a scripted peer; this asserts
// it with the peer being a process.
#[tokio::test]
async fn a_failing_sanitizer_in_the_child_cannot_publish_what_it_was_shown() {
    use nemo_relay_plugin_host::{ProcessLoadedPlugins, confidentiality};
    use nemo_relay_plugin_protocol::PluginComponentConfiguration;

    let fixture = support::PreparedFixture::write(
        "fixture_intercept",
        "nemo-ph-event-sanitizer-failure",
        support::intercept_fixture(),
        "nemo_relay_native_intercept_fixture",
    );
    let loaded = ProcessLoadedPlugins::load(
        host_config(),
        5_000,
        nemo_relay_plugin_host::off_path::ObservabilityPolicy {
            budget_millis: 5_000,
            max_in_flight: 8,
        },
        [("fixture_intercept".to_string(), fixture.artifact())],
        [PluginComponentConfiguration {
            kind: "fixture_intercept".into(),
            config_json: serde_json::json!({ "event_sanitizer_failures": true }).to_string(),
        }],
    )
    .await
    .expect("a plugin served from another process");

    // Everything this runtime published, and everything it recorded about a
    // sanitizer that could not decide.
    let published: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let failures: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let published = std::sync::Arc::clone(&published);
        let failures = std::sync::Arc::clone(&failures);
        nemo_relay::api::subscriber::register_subscriber(
            "process-backend-sanitize-failures",
            std::sync::Arc::new(move |event: &nemo_relay::api::event::Event| {
                if event.name() == nemo_relay_plugin_host::off_path::SANITIZE_FAILURE_MARK {
                    failures.lock().unwrap().push(serde_json::json!({
                        "data": event.data().cloned(),
                    }));
                }
                published.lock().unwrap().push(serde_json::json!({
                    "name": event.name(),
                    "observable": event.to_json_value().to_string(),
                }));
            }),
        )
        .expect("a subscriber");
    }

    // A mark whose mutable observability fields each carry a value that must not
    // survive a sanitizer that could not decide. The name is the runtime's own: it is
    // identity rather than payload, so a sanitizer is shown it and cannot rewrite it.
    let name = "sanitizer-qualification-secret";
    let (fields, sentinel) = confidentiality::sentinel_fields();
    nemo_relay::api::runtime::with_execution_budget(
        nemo_relay::api::runtime::ExecutionBudget::new(
            nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
            30_000,
        ),
        async {
            nemo_relay::api::scope::event(
                nemo_relay::api::scope::EmitMarkEventParams::builder()
                    .name(name)
                    .data_opt(fields.data.clone())
                    .metadata_opt(fields.metadata.clone())
                    .category_profile_opt(fields.category_profile.clone())
                    .build(),
            )
            .expect("an emitted mark");
        },
    )
    .await;
    nemo_relay::api::subscriber::flush_subscribers().expect("a flush");

    // The published copy: the fields were cleared rather than published, so nothing
    // the sanitizer was shown is in it.
    let published = published.lock().unwrap().clone();
    let published_copy = published
        .iter()
        .find(|event| event["name"] == serde_json::json!(name))
        .unwrap_or_else(|| panic!("the mark was published: {published:#?}"));
    sentinel.assert_absent(
        "the event this runtime published after a sanitizer failed",
        published_copy["observable"]
            .as_str()
            .expect("a serialized event"),
    );

    // And the failure is a fact in this runtime's stream rather than a log line in
    // the other process: the kernel knows which registration could not answer.
    let failures = failures.lock().unwrap().clone();
    assert!(
        failures.iter().any(|failure| {
            failure["data"]["registration"]
                .as_str()
                .is_some_and(|registration| registration.ends_with("fixture_mark_refuses"))
        }),
        "the refused sanitization was recorded against its registration: {failures:#?}"
    );

    nemo_relay::api::subscriber::deregister_subscriber("process-backend-sanitize-failures")
        .expect("a deregistration");
    drop(loaded);
}

#[tokio::test]
async fn the_process_backend_satisfies_the_shared_lifecycle_suite() {
    // The same walk the in-process backend runs, with no forked expectations:
    // a load, a duplicate load, an unload, a reload and a stale handle, answered
    // by a child process.
    let fixture = support::PreparedFixture::write(
        "fixture_native",
        "nemo-ph-lifecycle",
        support::native_fixture(),
        "nemo_relay_fixture_native_plugin",
    );
    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");

    let findings = conformance::check_lifecycle(&backend, &fixture.lifecycle()).await;

    assert!(findings.is_empty(), "{findings:#?}");
}

#[tokio::test]
async fn a_second_transport_attaches_to_the_session_and_serves_only_invocations() {
    use nemo_relay_plugin_host::attached::AttachedClient;
    use nemo_relay_plugin_protocol::{PluginHandle, PluginInvokeRequest};

    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");
    let descriptor = backend.connection_descriptor();
    let attached = AttachedClient::connect(descriptor.clone())
        .await
        .expect("a second transport should attach to the established session");
    assert_eq!(
        attached.descriptor().session_id,
        descriptor.session_id,
        "the attach joins the session the kernel established"
    );

    // A second transport is another way to reach the same session: a registration
    // the session does not hold is refused *by the host*, which is what shows the
    // request was served rather than dropped.
    let outcome = attached
        .invoke(
            PluginInvokeRequest {
                handle: PluginHandle {
                    plugin_id: "absent".into(),
                    generation: 1,
                },
                registration_id: "absent".into(),
                arguments: "{}".into(),
                budget_millis: 5_000,
            },
            context(),
        )
        .await;
    assert!(
        outcome
            .map(|outcome| outcome.result.is_err())
            .unwrap_or(true),
        "the session answered, and its answer was that nothing holds that registration"
    );

    // Naming the *right* session is not enough on its own. A peer that has the
    // credential — because it started its own host, or because it read one's
    // environment — and has learned which session this is still cannot join it
    // without the capability the kernel minted for it.
    let another_capability = nemo_relay_plugin_host::attached::ConnectionDescriptor {
        capability: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".into(),
        ..descriptor.clone()
    };
    assert!(
        AttachedClient::connect(another_capability).await.is_err(),
        "a transport presenting another capability cannot join the session"
    );

    // And the attach is what authorises a transport: a descriptor naming a session
    // the host never established is refused rather than served.
    let stranger = nemo_relay_plugin_host::attached::ConnectionDescriptor {
        session_id: "another-session".into(),
        ..descriptor
    };
    assert!(
        AttachedClient::connect(stranger).await.is_err(),
        "a session this host did not establish cannot be joined"
    );
}

#[tokio::test]
async fn the_kernel_serves_its_socket_and_refuses_a_caller_without_the_credential() {
    use nemo_relay_plugin_host::runtime_service::{SESSION_CREDENTIAL_HEADER, connect_to_kernel};
    use tonic::metadata::MetadataValue;

    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");
    let mut client = connect_to_kernel(
        backend.kernel_endpoint(),
        nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
    )
    .await
    .expect("the kernel serves the socket its child was told about");

    let mark = |session_id: String| nemo_relay_plugin_proto::v1::EmitMarkRequest {
        session_id,
        operation_request_id: "operation-1".into(),
        host_call_id: "call-1".into(),
        name: "native.mark".into(),
        ..Default::default()
    };

    // The path is not a secret — the child is told it, and a caller that knows
    // it still has to be this session's host. Naming the right session
    // deliberately: the credential is what makes the caller, not the identity it
    // claims.
    let anonymous = client
        .emit_mark(mark(backend.session().session_id.clone()))
        .await
        .expect_err("a caller with no credential");
    assert_eq!(anonymous.code(), tonic::Code::PermissionDenied);

    let mut wrong = tonic::Request::new(mark(backend.session().session_id.clone()));
    wrong.metadata_mut().insert(
        SESSION_CREDENTIAL_HEADER,
        MetadataValue::try_from("not-the-credential").expect("a header value"),
    );
    let refused = client
        .emit_mark(wrong)
        .await
        .expect_err("a caller with another session's credential");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
}

// Single-threaded for the same reason: the composition test carries the sanitize
// invariant, and that invariant must not depend on the caller's thread count.
#[tokio::test]
async fn the_composition_installs_a_plugin_from_another_process_into_this_chain() {
    use nemo_relay_plugin_host::ProcessLoadedPlugins;
    use nemo_relay_plugin_protocol::PluginComponentConfiguration;

    // The composition a runtime selects when it wants native plugins out of its
    // own process: it starts the host, loads the approved artifact there,
    // activates the component there, and installs a proxy here — with no loader
    // call in this process at all.
    let fixture = support::PreparedFixture::write(
        "fixture_intercept",
        "nemo-ph-composed",
        support::intercept_fixture(),
        "nemo_relay_native_intercept_fixture",
    );
    let observed_path = std::env::temp_dir()
        .join(format!(
            "nemo-observer-{}.log",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ))
        .to_string_lossy()
        .into_owned();
    let loaded = ProcessLoadedPlugins::load(
        host_config(),
        5_000,
        // How long off-path work may take and how much of it may be in flight,
        // stated rather than defaulted.
        nemo_relay_plugin_host::off_path::ObservabilityPolicy {
            budget_millis: 5_000,
            max_in_flight: 8,
        },
        [("fixture_intercept".to_string(), fixture.artifact())],
        [PluginComponentConfiguration {
            kind: "fixture_intercept".into(),
            config_json: serde_json::json!({ "observer_log": observed_path }).to_string(),
        }],
    )
    .await
    .expect("a plugin served from another process");
    assert_eq!(loaded.handles().len(), 1, "one plugin was loaded");
    let mut registrations = loaded.registrations();
    registrations.sort_unstable();
    assert_eq!(
        registrations,
        vec![
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_conditional",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_execution",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_llm_conditional",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_llm_execution",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_llm_rewrite",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_metadata",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_observer",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_rewrite",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_sanitize_never",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_sanitize_request",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_sanitize_response",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_mark_a",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_mark_b",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_mark_c",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_scope_end_sanitize",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_scope_start_other",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_scope_start_sanitize"
        ],
        "every registration the plugin made is proxied here, in the classes this kernel serves"
    );

    // Off-path failures are recorded in this runtime's own stream, so this
    // subscriber is what turns "the payload was withheld" into a fact the test
    // can read.
    let failures: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let failures = std::sync::Arc::clone(&failures);
        nemo_relay::api::subscriber::register_subscriber(
            "process-backend-off-path-failures",
            std::sync::Arc::new(move |event: &nemo_relay::api::event::Event| {
                if event.name() == nemo_relay_plugin_host::observer::OBSERVER_FAILURE_MARK
                    || event.name() == nemo_relay_plugin_host::off_path::SANITIZE_FAILURE_MARK
                {
                    failures.lock().unwrap().push(serde_json::json!({
                        "mark": event.name(),
                        "data": event.data().cloned(),
                    }));
                }
            }),
        )
        .expect("a subscriber");
    }

    // An observer in the other process sees this runtime's events: its own
    // runtime's subscribers are not this runtime's, so the witness is a file the
    // child writes and this process reads.
    nemo_relay::api::runtime::with_execution_budget(
        nemo_relay::api::runtime::ExecutionBudget::new(
            nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
            30_000,
        ),
        async {
            nemo_relay::api::tool::tool_call_execute(
                nemo_relay::api::tool::ToolCallExecuteParams::builder()
                    .name("example_tool")
                    .args(serde_json::json!({"input": true}))
                    .func(std::sync::Arc::new(|args| {
                        Box::pin(async move { Ok(args.into()) })
                    }))
                    .build(),
            )
            .await
        },
    )
    .await
    .expect("a managed tool call the observer was watching");

    // Delivery is asynchronous, so this waits for the witness rather than
    // assuming an order between two independent paths.
    let mut seen = String::new();
    for _ in 0..200 {
        seen = std::fs::read_to_string(&observed_path).unwrap_or_default();
        if seen.lines().any(|line| line == "example_tool") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        seen.lines().any(|line| line == "example_tool"),
        "the observer in the other process should have seen the call it was watching: {seen:?}"
    );
    let _ = std::fs::remove_file(&observed_path);

    // The second class reaches the child the same way, under the same trusted
    // budget the first does: the proxy refuses an invocation with nothing to
    // inherit, so this is one rule reaching two chains rather than a second
    // timeout source.
    let called = nemo_relay::api::runtime::with_execution_budget(
        nemo_relay::api::runtime::ExecutionBudget::new(
            nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
            30_000,
        ),
        async {
            nemo_relay::api::llm::llm_call_execute(
                nemo_relay::api::llm::LlmCallExecuteParams::builder()
                    .name("example-model")
                    .request(nemo_relay::api::llm::LlmRequest {
                        headers: serde_json::Map::new(),
                        content: serde_json::json!({"model": "example"}),
                    })
                    .func(std::sync::Arc::new(|request| {
                        Box::pin(async move {
                            Ok(nemo_relay::json::Json::Object(
                                request.content.as_object().cloned().unwrap_or_default(),
                            ))
                        })
                    }))
                    .build(),
            )
            .await
        },
    )
    .await
    .expect("the LLM chain should reach the child");
    assert_eq!(called["native_llm_intercept"], true, "{called}");

    // And the chain reaches it: the rewrite happens in the child, and this call
    // reads as an ordinary tool request intercept.
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
    assert_eq!(rewritten["native_intercept"], true, "{rewritten}");

    // A managed tool call is what emits the scope events an observer is shown:
    // the intercept chain above runs before any event exists, so the observer has
    // to be given a call rather than a rewrite.
    nemo_relay::api::runtime::with_execution_budget(
        nemo_relay::api::runtime::ExecutionBudget::new(
            nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
            30_000,
        ),
        async {
            nemo_relay::api::tool::tool_call_execute(
                nemo_relay::api::tool::ToolCallExecuteParams::builder()
                    .name("example_tool")
                    .args(serde_json::json!({"input": true}))
                    .func(std::sync::Arc::new(|args| {
                        Box::pin(async move { Ok(args.into()) })
                    }))
                    .build(),
            )
            .await
        },
    )
    .await
    .expect("a managed tool call the observer was watching");

    // A sanitize guardrail in another process changes what observers see and not
    // what the tool did. This is the boundary regression for the hang it used to
    // be: the guardrail's own runner returns in process, and here the same
    // guardrail is reached over the boundary — so a failure here is the boundary
    // and nothing else.
    let published: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recording = std::sync::Arc::clone(&published);
    nemo_relay::api::subscriber::register_subscriber(
        "process-backend-sanitized-payloads",
        std::sync::Arc::new(move |event: &nemo_relay::api::event::Event| {
            if event.name() == "sanitized_tool" {
                recording.lock().unwrap().push(serde_json::json!({
                    "has_data": event.data().is_some(),
                    "data": event.data().cloned(),
                }));
            }
        }),
    )
    .expect("a subscriber");
    let result = nemo_relay::api::runtime::with_execution_budget(
        nemo_relay::api::runtime::ExecutionBudget::new(
            nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
            30_000,
        ),
        async {
            nemo_relay::api::tool::tool_call_execute(
                nemo_relay::api::tool::ToolCallExecuteParams::builder()
                    .name("sanitized_tool")
                    .args(serde_json::json!({"input": true}))
                    .func(std::sync::Arc::new(|_args| {
                        Box::pin(async { Ok(serde_json::json!({"secret": "value"}).into()) })
                    }))
                    .build(),
            )
            .await
        },
    )
    .await
    .expect("a managed tool call whose payload is sanitized elsewhere");
    // Two registrations of the fixture touch this call, and they are different
    // kinds of thing: the execution intercept wraps the call and is *meant* to
    // change what it returns (its marker is in the result), while the sanitizers
    // only change the copy observers are shown. The assertion keeps the second
    // invariant — no sanitizer marker appears in the real result — and states the
    // first rather than pretending the fixture does nothing.
    assert_eq!(
        result.result,
        serde_json::json!({"secret": "value", "native_intercept_execution": true}),
        "an execution intercept changes the result; a sanitizer does not"
    );
    assert!(
        result.result.get("native_tool_response_sanitize").is_none(),
        "a sanitizer must not change what the tool returned: {}",
        result.result
    );
    nemo_relay::api::subscriber::flush_subscribers().expect("a flush");
    let published = published.lock().unwrap().clone();
    assert!(
        published.iter().any(|event| {
            event["has_data"] == serde_json::json!(true)
                && event["data"]
                    .get("native_tool_response_sanitize")
                    .and_then(|marker| marker.as_bool())
                    .unwrap_or(false)
                && event["data"].to_string().contains("secret")
        }),
        "the published copy should carry the sanitizer's work: {published:#?}"
    );
    nemo_relay::api::subscriber::deregister_subscriber("process-backend-sanitized-payloads")
        .expect("a deregistration");

    // A guardrail that refused to sanitize is recorded, not merely logged: the
    // chain clears the observability fields, so the record is the only thing that
    // says the payload was withheld rather than never produced.
    nemo_relay::api::subscriber::flush_subscribers().expect("a flush");
    let recorded = failures.lock().unwrap().clone();
    assert!(
        recorded.iter().any(|failure| {
            failure["mark"] == serde_json::json!(nemo_relay_plugin_host::off_path::SANITIZE_FAILURE_MARK)
                && failure["data"]["registration"]
                    .as_str()
                    .is_some_and(|registration| registration.ends_with("fixture_intercept_sanitize_never"))
                // What the record can say: the guardrail omitted the payload
                // rather than publishing it unsanitized. The guardrail's own
                // words stay in the child, because the chain replaces an omitted
                // payload with an omission rather than an error to carry.
                && failure["data"]["reason"]
                    .as_str()
                    .is_some_and(|reason| reason.contains("omitted the payload"))
        }),
        "a sanitizer that could not answer should be recorded: {recorded:#?}"
    );
    nemo_relay::api::subscriber::deregister_subscriber("process-backend-off-path-failures")
        .expect("a deregistration");

    // A decision crosses too, and it takes effect: the guardrail in the other
    // process refuses this tool, and the call is refused here with its reason.
    let refusal = nemo_relay::api::runtime::with_execution_budget(
        nemo_relay::api::runtime::ExecutionBudget::new(
            nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
            30_000,
        ),
        async {
            nemo_relay::api::tool::tool_call_execute(
                nemo_relay::api::tool::ToolCallExecuteParams::builder()
                    .name("rejected_tool")
                    .args(serde_json::json!({"input": true}))
                    .func(std::sync::Arc::new(|args| {
                        Box::pin(async move { Ok(args.into()) })
                    }))
                    .build(),
            )
            .await
        },
    )
    .await
    .expect_err("a tool the guardrail refused");
    assert!(
        matches!(
            refusal,
            nemo_relay::error::FlowError::GuardrailRejected(ref reason)
                if reason.contains("refuses this tool")
        ),
        "the decision reaches the caller: {refusal:?}"
    );

    // The LLM half of the decision, over the request rather than the arguments.
    let refusal = nemo_relay::api::runtime::with_execution_budget(
        nemo_relay::api::runtime::ExecutionBudget::new(
            nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
            30_000,
        ),
        async {
            nemo_relay::api::llm::llm_call_execute(
                nemo_relay::api::llm::LlmCallExecuteParams::builder()
                    .name("rejected-model")
                    .request(nemo_relay::api::llm::LlmRequest {
                        headers: serde_json::Map::new(),
                        content: serde_json::json!({"model": "rejected-model"}),
                    })
                    .func(std::sync::Arc::new(|request| {
                        Box::pin(async move {
                            Ok(nemo_relay::json::Json::Object(
                                request.content.as_object().cloned().unwrap_or_default(),
                            ))
                        })
                    }))
                    .build(),
            )
            .await
        },
    )
    .await
    .expect_err("a model the guardrail refused");
    assert!(
        matches!(
            refusal,
            nemo_relay::error::FlowError::GuardrailRejected(ref reason)
                if reason.contains("refuses this model")
        ),
        "the decision reaches the caller on the LLM chain too: {refusal:?}"
    );

    // An injector adds, and only adds: the tool's own result is what it was, and
    // the copy this runtime publishes carries the key the child contributed.
    let injected: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recording = std::sync::Arc::clone(&injected);
    nemo_relay::api::subscriber::register_subscriber(
        "process-backend-injected-metadata",
        std::sync::Arc::new(move |event: &nemo_relay::api::event::Event| {
            if event.name() == "injected_tool"
                && let Some(metadata) = event.metadata()
            {
                recording.lock().unwrap().push(metadata.clone());
            }
        }),
    )
    .expect("a subscriber");
    let result = nemo_relay::api::runtime::with_execution_budget(
        nemo_relay::api::runtime::ExecutionBudget::new(
            nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
            30_000,
        ),
        async {
            nemo_relay::api::tool::tool_call_execute(
                nemo_relay::api::tool::ToolCallExecuteParams::builder()
                    .name("injected_tool")
                    .args(serde_json::json!({"input": true}))
                    .func(std::sync::Arc::new(|_args| {
                        Box::pin(async { Ok(serde_json::json!({"kept": true}).into()) })
                    }))
                    .build(),
            )
            .await
        },
    )
    .await
    .expect("a managed tool call whose events are annotated elsewhere");
    // The injector's invariant is about the event, not the result: a metadata
    // injector adds attributes to what observers see. The execution intercept in
    // the same fixture wraps the call, so its marker is expected here.
    assert_eq!(
        result.result,
        serde_json::json!({"kept": true, "native_intercept_execution": true}),
        "an injector must not change what the tool returned"
    );
    assert!(
        result.result.get("native_injected").is_none(),
        "and injected metadata belongs to the event, not the result: {}",
        result.result
    );
    nemo_relay::api::subscriber::flush_subscribers().expect("a flush");
    let injected = injected.lock().unwrap().clone();
    assert!(
        injected.iter().any(|metadata| {
            metadata
                .get("native_injected")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
        }),
        "the copy this runtime published should carry the child's addition: {injected:#?}"
    );
    nemo_relay::api::subscriber::deregister_subscriber("process-backend-injected-metadata")
        .expect("a deregistration");

    // The composition was still holding the child, so end it deliberately and
    // watch the whole plugin leave together.
    let process_id = loaded.backend().process_id();
    assert!(process_id.is_some(), "the plugin lived in another process");

    // Dropping the composition takes every registration out of this process's
    // chains and ends the host: a complete plugin — every registration this fixture
    // makes, none of them left behind — may not outlive the runtime that installed
    // it.
    let handles = loaded.handles().to_vec();
    let registrations: Vec<String> = loaded
        .registrations()
        .into_iter()
        .map(str::to_owned)
        .collect();
    // A weak reference, not a clone: a clone would outlive the composition and
    // keep the child alive, which is the thing this part is checking.
    let backend = std::sync::Arc::downgrade(loaded.backend());
    drop(loaded);

    assert_eq!(
        registrations.len(),
        17,
        "this is the complete-plugin regression: every registration the fixture makes was served"
    );
    assert!(
        !handles.is_empty(),
        "the plugin was loaded by the session that was dropped"
    );
    let after = nemo_relay::api::tool::tool_request_intercepts(
        "example_tool",
        serde_json::json!({"input": true}),
    )
    .await
    .expect("the chain");
    assert_eq!(
        after["native_intercept"],
        serde_json::Value::Null,
        "the tool rewrite left with the composition: {after}"
    );
    assert!(
        nemo_relay::api::tool::tool_request_intercepts("example_tool", serde_json::json!({}))
            .await
            .is_ok(),
        "and the chain itself is still this runtime's, not the plugin's"
    );
    // The composition held the only handle to the child, so releasing it is what
    // ends the host — the kill is `Drop`'s, and the child cannot be left holding a
    // socket nobody will read.
    //
    // Released rather than released *immediately*: a task mid-flight on the
    // composition's own runtime can hold the last reference for the moment it
    // takes to notice it has been dropped. What the assertion is about is that
    // nothing holds it for good, so it waits for the release and fails when the
    // reference outlives the composition rather than when it outlives the
    // statement.
    let released = tokio::time::timeout(Duration::from_secs(5), async {
        while backend.upgrade().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        released.is_ok(),
        "the composition was the last holder of the host it started"
    );
    assert!(
        process_id.is_some(),
        "and it was a real process, not a handle this process kept"
    );
}

#[tokio::test]
async fn a_composition_refuses_a_cap_that_would_refuse_every_invocation() {
    use nemo_relay_plugin_host::ProcessLoadedPlugins;

    let fixture = support::PreparedFixture::write(
        "fixture_intercept",
        "nemo-ph-zerocap",
        support::intercept_fixture(),
        "nemo_relay_native_intercept_fixture",
    );
    let error = match ProcessLoadedPlugins::load(
        host_config(),
        0,
        nemo_relay_plugin_host::off_path::ObservabilityPolicy {
            budget_millis: 5_000,
            max_in_flight: 8,
        },
        [("fixture_intercept".to_string(), fixture.artifact())],
        Vec::new(),
    )
    .await
    {
        Err(error) => error,
        Ok(_) => panic!("a cap of zero would refuse every invocation"),
    };
    assert_eq!(error.failure.code, PluginFailureCode::Rejected, "{error:?}");
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
    let crashed_capability = backend.connection_descriptor().capability;
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
    // Holding the capability of a session that has ended is not a way into the
    // one that replaced it: the capability is minted per session, so the value
    // that authorised calls to the old host authorises nothing on the new one.
    assert_ne!(
        backend.connection_descriptor().capability,
        crashed_capability,
        "a replaced host does not keep the capability of the one it replaced"
    );
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

/// The same context, with the response budget this test is about.
fn context_with_budget(max_response_bytes: u32) -> PluginExecutionContext {
    PluginExecutionContext {
        max_response_bytes,
        ..context()
    }
}

/// The limits a deployment sets are the limits the child runs under.
///
/// Read from the kernel's own record of the child's limits rather than from
/// anything the child says about itself: what is being asserted is a property of
/// the process, not a report from it. Linux publishes that record, and the
/// platforms that do not are covered by the unit test that starts a child
/// through the same call the supervisor uses.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_host_runs_under_the_limits_it_was_started_with() {
    let address_space = 4 * 1024 * 1024 * 1024u64;
    let open_files = 256u64;
    let mut config = host_config();
    config.limits = nemo_relay_plugin_host::limits::PluginHostLimits {
        maximum_address_space_bytes: Some(address_space),
        maximum_processes: None,
        maximum_open_files: Some(open_files),
        no_new_privileges: true,
    };
    let backend = ProcessPluginBackend::launch(config)
        .await
        .expect("a host started under the limits its deployment asked for");
    let process_id = backend.process_id().expect("a running host");
    let record = std::fs::read_to_string(format!("/proc/{process_id}/limits"))
        .expect("the kernel's record of the child's limits");

    let limit_of = |name: &str| -> Option<(u64, u64)> {
        let line = record
            .lines()
            .find(|line| line.trim_start().starts_with(name))?;
        let mut fields = line
            .split_whitespace()
            .skip(name.split_whitespace().count());
        // Soft and hard are the two columns after the name; the unit follows.
        Some((fields.next()?.parse().ok()?, fields.next()?.parse().ok()?))
    };

    assert_eq!(
        limit_of("Max address space"),
        Some((address_space, address_space)),
        "the child holds the address-space ceiling it was started with, as both \
         its soft and its hard limit"
    );
    assert_eq!(
        limit_of("Max open files"),
        Some((open_files, open_files)),
        "and the descriptor limit, for the same reason: a hard limit left high \
         is a soft limit the child can raise back"
    );
}

/// Load the single-registration fixture in a child and activate it there.
///
/// The classes it registers are exactly the classes this backend can proxy, so a
/// serving activation is the one that answers.
async fn activated_intercept_fixture(
    backend: &ProcessPluginBackend,
) -> nemo_relay_plugin_protocol::PluginLoadResponse {
    use nemo_relay_plugin_protocol::{PluginActivateRequest, PluginComponentConfiguration};

    let fixture = support::PreparedFixture::write(
        "fixture_intercept",
        "nemo-ph-budget",
        support::intercept_fixture(),
        "nemo_relay_native_intercept_fixture",
    );
    let artifact = fixture.artifact();
    let (manifest_sha256, library_sha256) =
        nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact)
            .expect("the fixture's identity");
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
        .expect("the fixture should load in the child");
    backend
        .activate(
            PluginActivateRequest {
                discovery: false,
                components: vec![PluginComponentConfiguration {
                    kind: "fixture_intercept".into(),
                    config_json: "{}".into(),
                }],
            },
            context(),
        )
        .await
        .expect("a serving activation of the classes this backend can proxy");
    loaded
}

/// The registration the loaded fixture made, as the kernel would name it.
async fn tool_request_intercept_registration(
    backend: &ProcessPluginBackend,
    handle: &nemo_relay_plugin_protocol::PluginHandle,
) -> String {
    let descriptors = backend
        .inspect(
            nemo_relay_plugin_protocol::PluginInspectRequest {
                handle: Some(handle.clone()),
            },
            context(),
        )
        .await
        .expect("the loaded plugin's registrations");
    descriptors
        .iter()
        .flat_map(|descriptor| descriptor.registrations.iter())
        .find(|registration| {
            registration.operation
                == nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolRequestIntercept
        })
        .expect("the fixture registers a tool request intercept")
        .registration_id
        .clone()
}

#[tokio::test]
async fn a_session_keeps_the_frame_limit_the_kernel_configured() {
    // The limit a session carries has to be the one both sides can carry. This
    // kernel is configured well below the protocol's ceiling and the host's
    // default; a session that reported the host's own limit instead would open
    // every transport it hands out — the attached one included — at a size this
    // kernel does not decode.
    let configured = 1024 * 1024;
    let mut config = host_config();
    config.maximum_frame_bytes = configured;
    let backend = ProcessPluginBackend::launch(config)
        .await
        .expect("a plugin host should start and handshake");

    assert_eq!(
        backend.session().maximum_frame_bytes,
        configured,
        "the session keeps the limit this kernel offered, not the host's ceiling"
    );
    assert_eq!(
        backend.connection_descriptor().maximum_frame_bytes,
        configured,
        "and every transport built from the session is told the same one"
    );
}

#[tokio::test]
async fn an_answer_that_outgrows_its_operation_is_refused_by_the_kernel() {
    // The host measures the answer it is about to send, and the kernel measures
    // what arrived. The second measurement is the point of this test: the child
    // runs a native plugin, so an answer from it is not evidence the kernel
    // accepts without checking it against the operation that asked.
    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");
    let loaded = activated_intercept_fixture(&backend).await;
    let registration = tool_request_intercept_registration(&backend, &loaded.handle).await;
    // One invocation, and therefore one answer size: the budget is measured
    // against the answer this operation produces, so the operation's own name has
    // to be the same in the measurement as in the calls it is compared with.
    let operation = "operation-budget";
    let invocation = nemo_relay_plugin_protocol::PluginInvokeRequest {
        handle: loaded.handle.clone(),
        registration_id: registration.clone(),
        arguments: serde_json::json!({"tool": "fixture_tool", "args": {"input": true}}).to_string(),
        budget_millis: 5_000,
    };
    let context_for =
        |operation_request_id: &str, max_response_bytes: u32| PluginExecutionContext {
            operation_request_id: operation_request_id.into(),
            ..context_with_budget(max_response_bytes)
        };

    let answered = backend
        .invoke(invocation.clone(), context_for(operation, 64 * 1024))
        .await
        .expect("an answer within its budget");
    assert!(
        answered.result.is_ok(),
        "the registration answers: {answered:?}"
    );

    // What the answer costs on the wire, measured the way the budget is.
    let wire = nemo_relay_plugin_proto::convert::execution_outcome_to_wire(&answered, operation)
        .expect("the answer's wire form");
    let size = nemo_relay_plugin_proto::convert::invoke_outcome_encoded_len(&wire) as u32;

    // At the budget the answer is served; one byte under it is not.
    backend
        .invoke(invocation.clone(), context_for(operation, size))
        .await
        .expect("an answer exactly at its operation's budget");

    let refusal = backend
        .invoke(invocation, context_for(operation, size - 1))
        .await
        .expect_err("an answer one byte above its operation's budget");
    assert!(
        matches!(
            refusal.failure.code,
            PluginFailureCode::OversizedFrame { .. }
        ),
        "the refusal says what was wrong with the answer: {refusal:?}"
    );
}

/// The composition refuses a plugin it cannot serve whole.
///
/// This is the cost of the cutover stated as a test. The fixture behind it
/// registers every class the ABI exposes, and eight of them do not cross yet, so
/// a consumer that selects the process backend refuses the plugin at activation
/// rather than serving the eight it could. A runtime that silently dropped the
/// other eight would be reporting a load that did not happen, and the plugin
/// would believe its callbacks were installed.
///
/// When the boundary serves all sixteen this test changes from a refusal to a
/// load, which is the diff that says the bindings can follow the CLI.
#[tokio::test]
async fn a_plugin_the_boundary_cannot_serve_whole_is_refused() {
    use nemo_relay_plugin_host::ProcessLoadedPlugins;

    let fixture = support::PreparedFixture::write(
        "fixture_native",
        "nemo-ph-unsupported",
        support::native_fixture(),
        "nemo_relay_fixture_native_plugin",
    );
    let refusal = ProcessLoadedPlugins::load(
        host_config(),
        5_000,
        nemo_relay_plugin_host::off_path::ObservabilityPolicy {
            budget_millis: 5_000,
            max_in_flight: 8,
        },
        [("fixture_native".to_owned(), fixture.artifact())],
        [nemo_relay_plugin_protocol::PluginComponentConfiguration {
            kind: "fixture_native".into(),
            config_json: "{}".into(),
        }],
    )
    .await
    .err()
    .expect("a plugin registering classes the boundary cannot serve is refused");

    let message = refusal.failure.message.clone();
    assert!(
        message.contains("registers") && message.contains("can serve"),
        "the refusal says what the plugin registered and what this session can \
         serve: {message}"
    );
    // The classes it names are the ones the boundary does not carry, which is the
    // list this refusal exists to make visible — and the list the bindings'
    // cutover waits on.
    assert!(
        message.contains("tool_execution_intercept") && message.contains("mark_sanitize_guardrail"),
        "the refusal names the classes that do not cross: {message}"
    );
}

/// A wrapped call runs the rest of the chain, in the kernel, from a callback in
/// the child.
///
/// The architectural proof point of the duplex work, stated as one call: the
/// plugin's execution intercept decides when the downstream call runs, the
/// downstream call is the kernel's own chain, and both halves are visible from
/// the caller. The markers are the evidence — the request marker came back
/// inside the arguments the *kernel's* tool function received, which could only
/// happen if the child's continuation reached this process, and the result
/// marker came back on the result the child returned.
#[tokio::test]
async fn a_tool_execution_intercept_wraps_a_call_across_the_boundary() {
    use nemo_relay_plugin_host::ProcessLoadedPlugins;

    let fixture = support::PreparedFixture::write(
        "fixture_intercept",
        "nemo-ph-execution",
        support::intercept_fixture(),
        "nemo_relay_native_intercept_fixture",
    );
    let composition = ProcessLoadedPlugins::load(
        host_config(),
        5_000,
        nemo_relay_plugin_host::off_path::ObservabilityPolicy {
            budget_millis: 5_000,
            max_in_flight: 8,
        },
        [("fixture_intercept".to_owned(), fixture.artifact())],
        [nemo_relay_plugin_protocol::PluginComponentConfiguration {
            kind: "fixture_intercept".into(),
            config_json: "{}".into(),
        }],
    )
    .await
    .expect("a plugin whose registrations this boundary can serve");

    // The downstream call, made by the kernel, inside the plugin's continuation.
    // The mark the intercept asked the *call's* owner to emit travels back with
    // the outcome and is emitted here, in this process, where the call lives.
    let marks: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recording = std::sync::Arc::clone(&marks);
    nemo_relay::api::subscriber::register_subscriber(
        "process-backend-wrapped-call-marks",
        std::sync::Arc::new(move |event: &nemo_relay::api::event::Event| {
            if event.name() == "fixture.intercept.tool_execution.mark" {
                recording.lock().unwrap().push(event.name().to_string());
            }
        }),
    )
    .expect("a subscriber");
    let result = nemo_relay::api::runtime::with_execution_budget(
        nemo_relay::api::runtime::ExecutionBudget::new(
            nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
            30_000,
        ),
        async {
            nemo_relay::api::tool::tool_call_execute(
                nemo_relay::api::tool::ToolCallExecuteParams::builder()
                    .name("wrapped_tool")
                    .args(serde_json::json!({"input": true}))
                    .func(std::sync::Arc::new(|args| {
                        Box::pin(async move {
                            // What the kernel's own chain received, which is what
                            // the child's continuation asked it to run.
                            Ok(serde_json::json!({ "downstream_args": args }).into())
                        })
                    }))
                    .build(),
            )
            .await
        },
    )
    .await
    .expect("a managed tool call wrapped by a remote intercept");

    let result = result.result;
    assert_eq!(
        result["downstream_args"]["native_intercept_execution_request"], true,
        "the child's continuation reached this kernel's chain with the arguments it \
         decided on: {result}"
    );
    assert_eq!(
        result["native_intercept_execution"], true,
        "and the child returned the downstream result after marking it: {result}"
    );
    nemo_relay::api::subscriber::flush_subscribers().expect("a flush");
    assert_eq!(
        marks.lock().unwrap().len(),
        1,
        "the mark the intercept asked for was emitted by the call's owner"
    );
    nemo_relay::api::subscriber::deregister_subscriber("process-backend-wrapped-call-marks")
        .expect("a deregistration");

    drop(composition);
}

/// The shapes a wrapped call can take, each run through the boundary.
///
/// The ABI gives an intercept three powers over the call it wraps: it can decide
/// the result without running the call, run it once, or run it more than once —
/// and it can fail after running it. Each one is a different statement about
/// what crosses: "nothing downstream was entered", "the continuation reached the
/// kernel exactly once", "it reached the kernel twice, and both answers came
/// back", and "the call ran, and the plugin failed anyway".
#[tokio::test]
async fn a_wrapped_call_can_be_replaced_run_twice_or_failed_after() {
    use nemo_relay_plugin_host::ProcessLoadedPlugins;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let fixture = support::PreparedFixture::write(
        "fixture_intercept",
        "nemo-ph-execution-shapes",
        support::intercept_fixture(),
        "nemo_relay_native_intercept_fixture",
    );
    let composition = ProcessLoadedPlugins::load(
        host_config(),
        5_000,
        nemo_relay_plugin_host::off_path::ObservabilityPolicy {
            budget_millis: 5_000,
            max_in_flight: 8,
        },
        [("fixture_intercept".to_owned(), fixture.artifact())],
        [nemo_relay_plugin_protocol::PluginComponentConfiguration {
            kind: "fixture_intercept".into(),
            config_json: "{}".into(),
        }],
    )
    .await
    .expect("a plugin whose registrations this boundary can serve");

    /// Run one managed tool call whose downstream function counts its own calls.
    async fn run(
        args: serde_json::Value,
        calls: Arc<AtomicUsize>,
    ) -> nemo_relay::error::Result<serde_json::Value> {
        nemo_relay::api::runtime::with_execution_budget(
            nemo_relay::api::runtime::ExecutionBudget::new(
                nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
                30_000,
            ),
            async {
                nemo_relay::api::tool::tool_call_execute(
                    nemo_relay::api::tool::ToolCallExecuteParams::builder()
                        .name("wrapped_tool")
                        .args(args)
                        .func(Arc::new(move |args| {
                            let calls = Arc::clone(&calls);
                            Box::pin(async move {
                                calls.fetch_add(1, Ordering::SeqCst);
                                Ok(serde_json::json!({ "downstream_args": args }).into())
                            })
                        }))
                        .build(),
                )
                .await
            },
        )
        .await
        .map(|result| result.result)
    }

    // The plugin decides the result and never enters the call.
    let calls = Arc::new(AtomicUsize::new(0));
    let replaced = run(
        serde_json::json!({"input": true, "skip_next": true}),
        Arc::clone(&calls),
    )
    .await
    .expect("a call the plugin answered itself");
    assert_eq!(
        replaced["replaced_by_plugin"], true,
        "the plugin's own result is what the caller sees: {replaced}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "nothing downstream is entered when the plugin does not continue"
    );

    // The call runs once, in the kernel, and its answer comes back to the plugin.
    let calls = Arc::new(AtomicUsize::new(0));
    let once = run(serde_json::json!({"input": true}), Arc::clone(&calls))
        .await
        .expect("a wrapped call");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the call ran once");
    assert_eq!(
        once["downstream_args"]["native_intercept_execution_request"],
        true
    );
    assert_eq!(once["native_intercept_execution"], true);

    // The ABI lets an intercept call its continuation more than once, and both
    // calls have to reach the kernel and answer separately.
    let calls = Arc::new(AtomicUsize::new(0));
    let concurrent = run(
        serde_json::json!({"input": true, "use_concurrent_next": true}),
        Arc::clone(&calls),
    )
    .await
    .expect("a call the plugin ran twice");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "both of the intercept's continuations reached the kernel"
    );
    assert_eq!(concurrent["native_intercept_execution"], true);

    // And it can fail after running the call, which is the shape where the call
    // happened and the plugin's answer is an error anyway.
    let calls = Arc::new(AtomicUsize::new(0));
    let failed = run(
        serde_json::json!({"input": true, "fail_after_next": true}),
        Arc::clone(&calls),
    )
    .await
    .expect_err("an intercept that failed after its continuation");
    assert!(
        failed.to_string().contains("fails after its continuation"),
        "the plugin's own failure is what the caller sees: {failed}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the call it wrapped still ran"
    );

    drop(composition);
}

/// A wrapped provider call runs the rest of the chain, in the kernel, from a
/// callback in the child.
///
/// The tool intercept's twin, and deliberately made of the same parts: the same
/// suspended-chain machinery, the same unary resume, the same budget and panic
/// rules. What the test establishes is that the *shapes* differ and the mechanism
/// does not — the provider request the child decided on reached this kernel's
/// chain, and the response the chain produced came back to the child and returned
/// by it.
#[tokio::test]
async fn an_llm_execution_intercept_wraps_a_call_across_the_boundary() {
    use nemo_relay_plugin_host::ProcessLoadedPlugins;

    let fixture = support::PreparedFixture::write(
        "fixture_intercept",
        "nemo-ph-llm-execution",
        support::intercept_fixture(),
        "nemo_relay_native_intercept_fixture",
    );
    let composition = ProcessLoadedPlugins::load(
        host_config(),
        5_000,
        nemo_relay_plugin_host::off_path::ObservabilityPolicy {
            budget_millis: 5_000,
            max_in_flight: 8,
        },
        [("fixture_intercept".to_owned(), fixture.artifact())],
        [nemo_relay_plugin_protocol::PluginComponentConfiguration {
            kind: "fixture_intercept".into(),
            config_json: "{}".into(),
        }],
    )
    .await
    .expect("a plugin whose registrations this boundary can serve");

    /// Run one managed provider call whose downstream function echoes its request.
    async fn call(content: serde_json::Value) -> nemo_relay::error::Result<serde_json::Value> {
        nemo_relay::api::runtime::with_execution_budget(
            nemo_relay::api::runtime::ExecutionBudget::new(
                nemo_relay::api::runtime::budget_now_unix_ms() + 30_000,
                30_000,
            ),
            async {
                nemo_relay::api::llm::llm_call_execute(
                    nemo_relay::api::llm::LlmCallExecuteParams::builder()
                        .name("wrapped_provider")
                        .request(nemo_relay::api::llm::LlmRequest {
                            headers: serde_json::Map::new(),
                            content,
                        })
                        .func(std::sync::Arc::new(|request| {
                            Box::pin(async move {
                                // What this kernel's chain received, which is what
                                // the child's continuation asked it to run.
                                Ok(serde_json::json!({ "downstream_request": request.content }))
                            })
                        }))
                        .build(),
                )
                .await
            },
        )
        .await
    }

    let response = call(serde_json::json!({"model": "fixture-model"}))
        .await
        .expect("a managed provider call wrapped by a remote intercept");
    assert_eq!(
        response["downstream_request"]["native_intercept_llm_execution_request"], true,
        "the child's continuation reached this kernel's chain with the request it \
         decided on: {response}"
    );
    assert_eq!(
        response["native_intercept_llm_execution"], true,
        "and the child returned the downstream response after marking it: {response}"
    );

    // VARIANT: second call disabled
    #[allow(unreachable_code)]
    if false {
        let replaced = call(serde_json::json!({"model": "fixture-model", "skip_next": true}))
            .await
            .expect("a provider call the plugin answered itself");
        assert_eq!(
            replaced["replaced_by_plugin"], true,
            "the plugin's own response is what the caller sees: {replaced}"
        );
        assert!(
            replaced.get("downstream_request").is_none(),
            "nothing downstream was entered: {replaced}"
        );
    }

    drop(composition);
}

/// A host exits when the kernel that owns it goes away.
///
/// The supervisor kills the child when it drops, but that is not the only way a
/// kernel can end — it can exit, crash, or be killed, and in any of those the
/// host would otherwise be a process nobody owns, holding a socket nobody reads.
/// The host watches the pipe the supervisor opened for it, so the kernel's
/// absence reaches it even when no teardown ran.
///
/// The host is started here the way the supervisor starts it, and then abandoned
/// the way a kernel that exits abandons it: the write end of that pipe closes.
#[tokio::test]
async fn a_host_exits_when_its_kernel_goes_away() {
    use std::process::Stdio;

    let directory = std::env::temp_dir().join(format!(
        "nemo-ph-watchdog-{}",
        nemo_relay_plugin_protocol::Uuid::now_v7().simple()
    ));
    std::fs::create_dir_all(&directory).expect("a socket directory");
    let socket = directory.join("s");
    let mut command = std::process::Command::new(host_executable());
    command
        // The names the host binary reads, which are the supervisor's contract
        // with it rather than anything this test invents.
        .env("NEMO_RELAY_PLUGIN_HOST_SOCKET", &socket)
        .env("NEMO_RELAY_PLUGIN_HOST_CREDENTIAL", "watchdog-credential")
        .env("NEMO_RELAY_PLUGIN_HOST_BINDING", "watchdog-binding")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().expect("a host process");

    // Wait until it is serving, so what the test observes is the watchdog rather
    // than a host that never started.
    let started = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !socket.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        started.is_ok(),
        "the host bound its socket: {}",
        socket.display()
    );

    // The kernel goes away.
    drop(child.stdin.take());

    let exited = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if child
                .try_wait()
                .expect("a host that can be waited for")
                .is_some()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    let _ = child.kill();
    assert!(
        exited.is_ok(),
        "the host exited on its own once its kernel was gone"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The sixteen-surface fixture can be inspected over the boundary, in full.
///
/// Inspection exists so an operator can ask what a *serving* session would
/// refuse, which is the question a plugin author has when a load is refused
/// whole. That answer has to survive the conversion: a description that repeated
/// an attachment point would be refused on the way back, and the operator would
/// learn nothing about the plugin that needed the answer most.
///
/// This is also the case that caught a real defect. The fixture's register
/// callbacks run twice in this flow — once for the serving activation that is
/// refused, once for the inspection that follows — and the loader used to record
/// a *log* of every registration an instance ever made rather than the
/// registrations it currently has, so the second run described each of them
/// twice. The conversion refused the duplicate, which is what made the
/// description unreadable exactly when it was needed.
#[tokio::test]
async fn the_full_fixture_is_inspectable_over_the_boundary() {
    use nemo_relay_plugin_protocol::PluginRegistrationOperation as Operation;

    let fixture = support::PreparedFixture::write(
        "fixture_native",
        "nemo-ph-inspection",
        support::native_fixture(),
        "nemo_relay_fixture_native_plugin",
    );
    let artifact = fixture.artifact();
    let (manifest_sha256, library_sha256) =
        nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact)
            .expect("the fixture's identity");
    let backend = ProcessPluginBackend::launch(host_config())
        .await
        .expect("a plugin host should start and handshake");
    backend
        .load(
            nemo_relay_plugin_protocol::PluginLoadRequest {
                plugin_id: "fixture_native".into(),
                artifact,
                identity: nemo_relay_plugin_protocol::PluginArtifactIdentity {
                    manifest_sha256,
                    library_sha256,
                },
            },
            context(),
        )
        .await
        .expect("the fixture should load in the child");

    let components = [nemo_relay_plugin_protocol::PluginComponentConfiguration {
        kind: "fixture_native".into(),
        config_json: "{}".into(),
    }];
    // Serving first, and refused: the point of the inspection that follows.
    let serving = backend
        .activate(
            nemo_relay_plugin_protocol::PluginActivateRequest {
                discovery: false,
                components: components.to_vec(),
            },
            context(),
        )
        .await;
    assert!(
        serving.is_err(),
        "a serving activation of a plugin with unserved classes is refused whole"
    );

    let descriptors = backend
        .activate(
            nemo_relay_plugin_protocol::PluginActivateRequest {
                discovery: true,
                components: components.to_vec(),
            },
            context(),
        )
        .await
        .expect("a discovery activation reports rather than refuses");

    let operations: Vec<Operation> = descriptors
        .iter()
        .flat_map(|descriptor| descriptor.registrations.iter())
        .map(|registration| registration.operation)
        .collect();
    // Every class the ABI exposes, in one report, each once — which is what the
    // conversion above already enforced by accepting it.
    for expected in [
        Operation::Subscriber,
        Operation::EventMetadataInjector,
        Operation::MarkSanitizeGuardrail,
        Operation::ScopeSanitizeStartGuardrail,
        Operation::ScopeSanitizeEndGuardrail,
        Operation::ToolSanitizeRequestGuardrail,
        Operation::ToolSanitizeResponseGuardrail,
        Operation::ToolConditionalExecutionGuardrail,
        Operation::ToolRequestIntercept,
        Operation::ToolExecutionIntercept,
        Operation::LlmSanitizeRequestGuardrail,
        Operation::LlmSanitizeResponseGuardrail,
        Operation::LlmConditionalExecutionGuardrail,
        Operation::LlmRequestIntercept,
        Operation::LlmExecutionIntercept,
        Operation::LlmStreamExecutionIntercept,
    ] {
        assert!(
            operations.contains(&expected),
            "the report names {} among {} registrations: {operations:?}",
            expected.as_str(),
            operations.len()
        );
    }
    assert_eq!(
        operations.len(),
        17,
        "the fixture registers seventeen attachment points across the sixteen classes: \
         {operations:?}"
    );

    drop(backend);
}
