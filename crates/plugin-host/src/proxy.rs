// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The kernel-side proxies for a plugin's registrations.
//!
//! A host process holds a plugin's registrations; the kernel holds none of them,
//! because the callbacks live where the library is loaded. What the kernel
//! installs instead is one proxy per registration, at the priority the plugin
//! declared, under the identity the host reported — so a chain in the kernel
//! orders the plugin's registrations exactly where the plugin asked for them and
//! reaches each one through the seam.
//!
//! Only the classes the backend can serve are installed. A registration this
//! kernel cannot proxy is a registration that would silently not run, which is
//! what the activation's fail-closed check exists to prevent; reaching here with
//! one is refused rather than skipped.

use std::sync::Arc;

use nemo_relay::api::runtime::ToolInterceptFn;
use nemo_relay::plugin::execution::PluginExecutionBackend;
use nemo_relay_plugin_protocol::{
    DispatchState, OutcomeCertainty, PluginDescriptor, PluginExecutionContext, PluginFailureCode,
    PluginHandle, PluginInvokeRequest, PluginProtocolError, PluginRegistrationDescriptor,
    PluginRegistrationOperation, PluginSuccess, deadline_expired,
};

/// How long a proxied registration may take.
///
/// The interceptor callbacks the runtime invokes carry no context, so a proxy
/// has no budget of its own to inherit. It uses this one, and the follow-up is
/// to thread the caller's trusted action budget through the chain rather than
/// leaving a proxy to choose; until then the value is here, in one place, rather
/// than repeated per proxy.
const PROXY_BUDGET_MILLIS: u64 = 30_000;

/// Proxies installed for one loaded plugin.
///
/// Dropping this removes them: a registration whose plugin is no longer loaded
/// must not remain in the kernel's chains, or a later call would reach a proxy
/// that can only fail.
pub struct RegistrationProxies {
    tool_request_intercepts: Vec<String>,
}

impl std::fmt::Debug for RegistrationProxies {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistrationProxies")
            .field("tool_request_intercepts", &self.tool_request_intercepts)
            .finish()
    }
}

impl RegistrationProxies {
    /// The registrations currently proxied.
    pub fn registration_ids(&self) -> Vec<&str> {
        self.tool_request_intercepts
            .iter()
            .map(String::as_str)
            .collect()
    }
}

impl Drop for RegistrationProxies {
    fn drop(&mut self) {
        for registration in &self.tool_request_intercepts {
            let _ = nemo_relay::api::registry::deregister_tool_request_intercept(registration);
        }
    }
}

/// Install a proxy for every registration in `descriptors`.
pub fn install(
    backend: Arc<dyn PluginExecutionBackend>,
    descriptor: &PluginDescriptor,
    handle: PluginHandle,
) -> Result<RegistrationProxies, PluginProtocolError> {
    let mut installed = RegistrationProxies {
        tool_request_intercepts: Vec::new(),
    };

    for registration in &descriptor.registrations {
        match registration.operation {
            PluginRegistrationOperation::ToolRequestIntercept => {
                install_tool_request_intercept(&backend, registration, &handle)?;
                installed
                    .tool_request_intercepts
                    .push(registration.registration_id.clone());
            }
            other => {
                // Refused rather than skipped. A registration the kernel cannot
                // proxy would be one the plugin believes it made and the
                // runtime never calls, and silence is the worst of the three
                // possible answers.
                return Err(PluginProtocolError::new(
                    PluginFailureCode::Rejected,
                    format!(
                        "plugin {} registered {} and this kernel cannot proxy it",
                        descriptor.plugin_id,
                        other.as_str()
                    ),
                ));
            }
        }
    }
    Ok(installed)
}

/// Install the proxy for one tool request intercept.
fn install_tool_request_intercept(
    backend: &Arc<dyn PluginExecutionBackend>,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    let registration_id = registration.registration_id.clone();
    let handle = handle.clone();
    let priority = registration.ordering.priority.unwrap_or_default();
    let break_chain = registration.ordering.may_break_chain.unwrap_or(false);
    let backend = Arc::clone(backend);

    let callable: ToolInterceptFn = Arc::new(move |tool: String, args: serde_json::Value| {
        let backend = Arc::clone(&backend);
        let handle = handle.clone();
        let registration_id = registration_id.clone();
        Box::pin(async move {
            // The payload shape is the class's, not the wire's: the host reads
            // the tool name and the arguments out of one object.
            let payload = serde_json::json!({ "tool": tool, "args": args });
            let request = PluginInvokeRequest {
                handle,
                registration_id,
                arguments: payload.to_string(),
                budget_millis: PROXY_BUDGET_MILLIS,
            };
            let context = proxy_context();
            let outcome = backend.invoke(request, context).await.map_err(|error| {
                nemo_relay::error::FlowError::Internal(format!(
                    "the plugin host could not be reached: {}",
                    error.failure.message
                ))
            })?;
            match outcome.result {
                Ok(PluginSuccess::Invoked(response)) => serde_json::from_str(&response.output)
                    .map_err(|error| {
                        nemo_relay::error::FlowError::Internal(format!(
                            "a proxied registration answered with something that is not JSON: \
                             {error}"
                        ))
                    }),
                Ok(other) => Err(nemo_relay::error::FlowError::Internal(format!(
                    "a proxied registration answered with {}",
                    other_name(&other)
                ))),
                // The certainty travels with the failure in the outcome, and a
                // proxy does not get to relabel it: a plugin that may have
                // dispatched before its answer was lost produced no definite
                // result, and the caller sees that rather than a plain failure.
                Err(failure) => Err(nemo_relay::error::FlowError::Internal(format!(
                    "a proxied registration failed ({:?}, {:?}): {}",
                    outcome.dispatch, outcome.certainty, failure.message
                ))),
            }
        })
    });

    nemo_relay::api::registry::register_tool_request_intercept(
        &registration.registration_id,
        priority,
        break_chain,
        callable,
    )
    .map_err(|error| {
        PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "the proxy for '{}' could not be installed: {error}",
                registration.registration_id
            ),
        )
    })
}

/// What a proxy tells the seam about the operation it is making.
fn proxy_context() -> PluginExecutionContext {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0);
    PluginExecutionContext {
        operation_request_id: nemo_relay_plugin_protocol::Uuid::now_v7().to_string(),
        protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
        // Filled by the composition that owns the runtime identity; a proxy that
        // invented one would be claiming a binding it does not know.
        runtime_binding_digest: String::new(),
        deadline_unix_ms: now.saturating_add(PROXY_BUDGET_MILLIS),
        remaining_budget_millis: PROXY_BUDGET_MILLIS,
        max_response_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
    }
}

/// The name of a success a proxy cannot turn into arguments.
fn other_name(success: &PluginSuccess) -> &'static str {
    match success {
        PluginSuccess::Handshake(_) => "a handshake",
        PluginSuccess::Loaded(_) => "a load",
        PluginSuccess::Unloaded => "an unload",
        PluginSuccess::Invoked(_) => "an invocation",
        PluginSuccess::Inspected(_) => "an inspection",
        PluginSuccess::Health(_) => "a health report",
    }
}

/// Whether an outcome says the operation never started.
pub fn never_dispatched(outcome: &nemo_relay_plugin_protocol::PluginExecutionOutcome) -> bool {
    outcome.dispatch == DispatchState::NotDispatched
        && matches!(
            outcome.certainty,
            OutcomeCertainty::ConfirmedFailure | OutcomeCertainty::ConfirmedSuccess
        )
}

/// Whether the outcome's deadline has passed by the time it was reported.
pub fn expired(context: &PluginExecutionContext, now_unix_ms: u64) -> bool {
    deadline_expired(context.deadline_unix_ms, now_unix_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay::plugin::execution::PluginExecutionFuture;
    use nemo_relay_plugin_protocol::{
        PluginDescriptor, PluginExecutionOutcome, PluginInvokeResponse,
    };
    use std::sync::Mutex;

    /// A backend that records what it was asked to run.
    #[derive(Default)]
    struct RecordingProxyBackend {
        invocations: Mutex<Vec<(String, String)>>,
    }

    impl PluginExecutionBackend for RecordingProxyBackend {
        fn load<'a>(
            &'a self,
            _request: nemo_relay_plugin_protocol::PluginLoadRequest,
            _context: PluginExecutionContext,
        ) -> PluginExecutionFuture<'a, nemo_relay_plugin_protocol::PluginLoadResponse> {
            Box::pin(async move {
                Err(PluginProtocolError::new(
                    PluginFailureCode::Rejected,
                    "this backend loads nothing",
                ))
            })
        }

        fn unload<'a>(
            &'a self,
            _request: nemo_relay_plugin_protocol::PluginUnloadRequest,
            _context: PluginExecutionContext,
        ) -> PluginExecutionFuture<'a, ()> {
            Box::pin(async move { Ok(()) })
        }

        fn inspect<'a>(
            &'a self,
            _request: nemo_relay_plugin_protocol::PluginInspectRequest,
            _context: PluginExecutionContext,
        ) -> PluginExecutionFuture<'a, Vec<PluginDescriptor>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn invoke<'a>(
            &'a self,
            request: PluginInvokeRequest,
            _context: PluginExecutionContext,
        ) -> PluginExecutionFuture<'a, PluginExecutionOutcome> {
            Box::pin(async move {
                self.invocations
                    .lock()
                    .expect("the record")
                    .push((request.registration_id.clone(), request.arguments.clone()));
                Ok(PluginExecutionOutcome {
                    dispatch: DispatchState::NotDispatched,
                    certainty: OutcomeCertainty::ConfirmedSuccess,
                    result: Ok(PluginSuccess::Invoked(PluginInvokeResponse {
                        output: serde_json::json!({"rewritten": true}).to_string(),
                    })),
                })
            })
        }

        fn health<'a>(
            &'a self,
            _context: PluginExecutionContext,
        ) -> PluginExecutionFuture<'a, nemo_relay_plugin_protocol::PluginHostHealth> {
            Box::pin(async move {
                Ok(nemo_relay_plugin_protocol::PluginHostHealth {
                    protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
                    accepting_work: true,
                    loaded: Vec::new(),
                })
            })
        }
    }

    fn descriptor(operation: PluginRegistrationOperation) -> PluginDescriptor {
        PluginDescriptor {
            plugin_id: "example".into(),
            plugin_version: None,
            negotiated_abi_version: None,
            manifest_digest: None,
            registration_kinds: Vec::new(),
            registrations: vec![PluginRegistrationDescriptor {
                registration_id: "nemo-relay-plugin.v1.example:1:rewrite".into(),
                component_kind: "example".into(),
                operation,
                ordering: nemo_relay_plugin_protocol::PluginRegistrationOrdering {
                    priority: Some(10),
                    may_break_chain: Some(false),
                },
                shape: nemo_relay_plugin_protocol::registration_shape(operation),
                gated_registration: None,
                config_keys: Vec::new(),
                declared_digest: None,
            }],
            capabilities: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_proxy_reaches_the_backend_and_the_answer_returns_through_the_chain() {
        // Core's registries are process-global, so this is the only test in this
        // module that touches them.
        let backend = Arc::new(RecordingProxyBackend::default());
        let installed = install(
            backend.clone(),
            &descriptor(PluginRegistrationOperation::ToolRequestIntercept),
            PluginHandle {
                plugin_id: "example".into(),
                generation: 1,
            },
        )
        .expect("the one class this kernel proxies");
        assert_eq!(
            installed.registration_ids(),
            vec!["nemo-relay-plugin.v1.example:1:rewrite"]
        );

        // The kernel's own chain reaches the plugin's registration through the
        // proxy, and what the backend answered is what the chain returns.
        let rewritten = nemo_relay::api::tool::tool_request_intercepts(
            "example_tool",
            serde_json::json!({"input": true}),
        )
        .await
        .expect("the chain");
        assert_eq!(rewritten["rewritten"], true, "{rewritten}");

        let invocations = backend.invocations.lock().expect("the record").clone();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].0, "nemo-relay-plugin.v1.example:1:rewrite");
        // The payload is the class's: the tool name and the arguments to
        // rewrite, in one object the host can read.
        let payload: serde_json::Value =
            serde_json::from_str(&invocations[0].1).expect("a JSON payload");
        assert_eq!(payload["tool"], "example_tool");
        assert_eq!(payload["args"]["input"], true);

        // Dropping the proxies takes them out of the chain: a registration whose
        // plugin is no longer loaded must not be left behind to fail later.
        drop(installed);
        let after = nemo_relay::api::tool::tool_request_intercepts(
            "example_tool",
            serde_json::json!({"input": true}),
        )
        .await
        .expect("the chain");
        assert_eq!(after["rewritten"], serde_json::Value::Null, "{after}");
    }

    #[test]
    fn a_registration_the_kernel_cannot_proxy_is_refused_rather_than_skipped() {
        let backend = Arc::new(RecordingProxyBackend::default());
        let error = install(
            backend,
            &descriptor(PluginRegistrationOperation::LlmStreamExecutionIntercept),
            PluginHandle {
                plugin_id: "example".into(),
                generation: 1,
            },
        )
        .expect_err("a class this kernel cannot proxy");

        // A registration the kernel cannot proxy is one the plugin believes it
        // made and the runtime would never call, so activation refuses instead of
        // installing what it can and forgetting the rest.
        assert_eq!(error.failure.code, PluginFailureCode::Rejected);
        assert!(
            error
                .failure
                .message
                .contains("llm_stream_execution_intercept"),
            "{error:?}"
        );
    }
}
