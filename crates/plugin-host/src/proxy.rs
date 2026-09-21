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
use nemo_relay::plugin::execution::PluginManager;
use nemo_relay_plugin_protocol::{
    DispatchState, OutcomeCertainty, PluginDescriptor, PluginExecutionContext, PluginFailureCode,
    PluginHandle, PluginInvokeRequest, PluginProtocolError, PluginRegistrationDescriptor,
    PluginRegistrationOperation, PluginSuccess, deadline_expired,
};

/// What a proxy needs to invoke a registration safely.
///
/// The manager rather than the backend, because the manager is where the
/// central controls live: protocol and binding validation, request-identity
/// uniqueness, the trusted deadline. A proxy that called the backend directly
/// would be a second, weaker path into the same process boundary.
#[derive(Clone)]
pub struct ProxyContext {
    manager: Arc<PluginManager>,
    /// The budget the caller's trusted deadline leaves, in milliseconds.
    ///
    /// Supplied rather than invented: a proxy that chose its own budget would
    /// be a place where a plugin can outlive the work it was asked to do. Zero
    /// is refused at installation, because a registration that may not run is
    /// not a registration to install.
    budget_millis: u64,
    runtime_binding_digest: String,
}

impl ProxyContext {
    /// Build the context a proxy runs under.
    pub fn new(
        manager: Arc<PluginManager>,
        budget_millis: u64,
        runtime_binding_digest: impl Into<String>,
    ) -> Result<Self, PluginProtocolError> {
        if budget_millis == 0 {
            return Err(PluginProtocolError::new(
                PluginFailureCode::DeadlineExceeded,
                "no budget remains for a proxied registration to run in",
            ));
        }
        Ok(Self {
            manager,
            budget_millis,
            runtime_binding_digest: runtime_binding_digest.into(),
        })
    }
}

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
    context: ProxyContext,
    descriptor: &PluginDescriptor,
    handle: PluginHandle,
) -> Result<RegistrationProxies, PluginProtocolError> {
    let mut installed = RegistrationProxies {
        tool_request_intercepts: Vec::new(),
    };

    for registration in &descriptor.registrations {
        match registration.operation {
            PluginRegistrationOperation::ToolRequestIntercept => {
                install_tool_request_intercept(&context, registration, &handle)?;
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
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    let registration_id = registration.registration_id.clone();
    let handle = handle.clone();
    let priority = registration.ordering.priority.unwrap_or_default();
    let break_chain = registration.ordering.may_break_chain.unwrap_or(false);
    let context = context.clone();

    let callable: ToolInterceptFn = Arc::new(move |tool: String, args: serde_json::Value| {
        let context = context.clone();
        let handle = handle.clone();
        let registration_id = registration_id.clone();
        Box::pin(async move {
            // The payload shape is the class's, not the wire's: the host reads
            // the tool name and the arguments out of one object.
            let payload = serde_json::json!({ "tool": tool, "args": args });
            let request = PluginInvokeRequest {
                handle,
                registration_id: registration_id.clone(),
                arguments: payload.to_string(),
                budget_millis: context.budget_millis,
            };
            let execution = context.execution_context();
            let outcome = context
                .manager
                .invoke(request, execution)
                .await
                .map_err(|error| nemo_relay::error::FlowError::PluginInvocation {
                    registration: registration_id.clone(),
                    failure: error.failure,
                    // The call never reached the plugin: the manager refuses
                    // before dispatch, so nothing was attempted.
                    dispatch: DispatchState::NotDispatched,
                    certainty: OutcomeCertainty::ConfirmedFailure,
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
                // The certainty travels with the failure rather than being
                // rendered into a message: a caller deciding whether an effect
                // may have happened has to read that structurally, and "the
                // plugin may have dispatched" is a different fact from "the
                // plugin failed".
                Err(failure) => Err(nemo_relay::error::FlowError::PluginInvocation {
                    registration: registration_id,
                    failure,
                    dispatch: outcome.dispatch,
                    certainty: outcome.certainty,
                }),
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

impl ProxyContext {
    /// What a proxy tells the manager about the operation it is making.
    ///
    /// The binding is the session's, not the proxy's invention: the host checks
    /// it against the session it established, and a proxy that sent none is
    /// refused — which is how that requirement was found. The deadline is the
    /// caller's budget, so no layer below the caller can enlarge it.
    fn execution_context(&self) -> PluginExecutionContext {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0);
        PluginExecutionContext {
            operation_request_id: nemo_relay_plugin_protocol::Uuid::now_v7().to_string(),
            protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
            runtime_binding_digest: self.runtime_binding_digest.clone(),
            deadline_unix_ms: now.saturating_add(self.budget_millis),
            remaining_budget_millis: self.budget_millis,
            max_response_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        }
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
    use nemo_relay::plugin::execution::{
        PluginExecutionBackend, PluginExecutionFuture, PluginManager,
    };
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
        let context = ProxyContext::new(
            Arc::new(PluginManager::new(
                backend.clone() as Arc<dyn PluginExecutionBackend>
            )),
            5_000,
            "test-binding",
        )
        .expect("a budget to run in");
        let installed = install(
            context,
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
        let context = ProxyContext::new(
            Arc::new(PluginManager::new(
                backend as Arc<dyn PluginExecutionBackend>,
            )),
            5_000,
            "test-binding",
        )
        .expect("a budget to run in");
        let error = install(
            context,
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
