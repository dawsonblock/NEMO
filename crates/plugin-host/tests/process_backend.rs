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
        .with_off_path_executor(off_path);
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
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_llm_conditional",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_llm_rewrite",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_metadata",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_observer",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_rewrite",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_sanitize_never",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_sanitize_request",
            "nemo-relay-plugin.v1.fixture_intercept:1:fixture_intercept_sanitize_response"
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
    assert_eq!(
        result.result,
        serde_json::json!({"secret": "value"}),
        "the sanitizer must not change what the tool returned"
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
    assert_eq!(
        result.result,
        serde_json::json!({"kept": true}),
        "an injector must not change what the tool returned"
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
    // chains and ends the host: a complete plugin — all nine registrations this
    // fixture makes, none of them left behind — may not outlive the runtime that
    // installed it.
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
        9,
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
    assert!(
        backend.upgrade().is_none(),
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
