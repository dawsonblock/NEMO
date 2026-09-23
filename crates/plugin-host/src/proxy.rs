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

use crate::operation_scopes::OperationScopes;
use nemo_relay::api::llm::LlmRequest;
use nemo_relay::api::runtime::{LlmRequestInterceptFn, ToolInterceptFn, ToolSanitizeFn};
use nemo_relay::codec::request::AnnotatedLlmRequest;
use nemo_relay::plugin::execution::PluginManager;
use nemo_relay_plugin_protocol::{
    PluginDescriptor, PluginExecutionContext, PluginFailureCode, PluginHandle, PluginInvokeRequest,
    PluginProtocolError, PluginRegistrationDescriptor, PluginRegistrationOperation, PluginSuccess,
};

/// What a proxy needs in order to invoke a registration safely.
///
/// The manager rather than the backend, because the manager is where the central
/// controls live: protocol and binding validation, request-identity uniqueness,
/// the trusted deadline. A proxy that called the backend directly would be a
/// second, weaker path into the same process boundary.
///
/// There is deliberately no budget here. A budget belongs to an invocation, not
/// to a registration: a proxy installed once and used two hours later has no
/// idea what the action can still afford, so it reads the trusted budget the
/// runtime publishes while a managed call runs, and refuses when there is none.
#[derive(Clone)]
pub struct ProxyContext {
    manager: Arc<PluginManager>,
    runtime_binding_digest: String,
    /// The most a remote registration may be given, whatever it inherited.
    ///
    /// A cap, not a budget: it can only shorten what the runtime published.
    local_cap_millis: u64,
    /// Where an in-flight operation's scope is registered, when this kernel has a
    /// host that forwards a plugin's marks back to it.
    ///
    /// Optional because a kernel that forwards nothing has no use for it, and a
    /// proxy without one simply leaves the registry alone.
    operation_scopes: Option<Arc<OperationScopes>>,
    /// How long an observer's delivery may take, when the runtime states one.
    ///
    /// Separate from the registration cap because an observer is not part of the
    /// action whose event it sees: nothing about that action depends on the
    /// delivery, so it neither inherits the action's budget nor is allowed to
    /// extend it. Absent means this runtime wants no remote observers, which is
    /// refused rather than defaulted.
    observability_budget_millis: Option<u64>,
    /// The runtime off-path work runs on, when this composition started one.
    ///
    /// Required by the families whose work happens beside a call: their answer
    /// cannot come from a thread the caller is holding, which is what this
    /// runtime exists to make true.
    off_path: Option<Arc<crate::off_path::OffPathPluginExecutor>>,
}

impl ProxyContext {
    /// The context for work this runtime asks of a plugin beside a call.
    ///
    /// Built from the stated observability budget rather than from the task-local
    /// one: the dispatcher does not run in the calling task, so a proxy that read
    /// the call's budget here would read nothing and refuse every sanitizer.
    fn passive_execution_context(
        &self,
        operation_request_id: String,
    ) -> Result<PluginExecutionContext, nemo_relay::error::FlowError> {
        let Some(budget_millis) = self
            .observability_budget_millis
            .filter(|millis| *millis > 0)
        else {
            return Err(nemo_relay::error::FlowError::InvalidArgument(
                "this runtime states no budget for work beside a call, so it cannot ask a \
                 plugin to do any"
                    .to_string(),
            ));
        };
        let now = nemo_relay::api::runtime::budget_now_unix_ms();
        Ok(PluginExecutionContext {
            operation_request_id,
            protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
            runtime_binding_digest: self.runtime_binding_digest.clone(),
            deadline_unix_ms: now.saturating_add(budget_millis),
            remaining_budget_millis: budget_millis,
            max_response_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        })
    }

    /// Build the context a proxy runs under.
    pub fn new(
        manager: Arc<PluginManager>,
        runtime_binding_digest: impl Into<String>,
        local_cap_millis: u64,
    ) -> Self {
        Self {
            manager,
            runtime_binding_digest: runtime_binding_digest.into(),
            local_cap_millis,
            operation_scopes: None,
            observability_budget_millis: None,
            off_path: None,
        }
    }

    /// Give the composition's off-path runtime to the families that need it.
    pub fn with_off_path_executor(
        mut self,
        executor: Arc<crate::off_path::OffPathPluginExecutor>,
    ) -> Self {
        self.off_path = Some(executor);
        self
    }

    /// State how long an observer's delivery may take.
    pub fn with_observability_budget(mut self, millis: u64) -> Self {
        self.observability_budget_millis = Some(millis);
        self
    }

    /// Register in-flight operations in `scopes`.
    ///
    /// What this buys is attribution: a mark a plugin raises while its
    /// registration runs arrives on the kernel's server task, and the operation's
    /// scope is what says which call the mark belongs to.
    pub fn with_operation_scopes(mut self, scopes: Arc<OperationScopes>) -> Self {
        self.operation_scopes = Some(scopes);
        self
    }
}

/// Proxies installed for one loaded plugin.
///
/// Dropping this removes them: a registration whose plugin is no longer loaded
/// must not remain in the kernel's chains, or a later call would reach a proxy
/// that can only fail.
pub struct RegistrationProxies {
    tool_request_intercepts: Vec<String>,
    llm_request_intercepts: Vec<String>,
    subscribers: Vec<String>,
    metadata_injectors: Vec<String>,
    tool_sanitize_request: Vec<String>,
    tool_conditional: Vec<String>,
    llm_conditional: Vec<String>,
    tool_sanitize_response: Vec<String>,
    /// One delivery task per observer registration, ended with this value.
    deliveries: Vec<std::sync::Arc<crate::observer::ObserverDelivery>>,
}

impl std::fmt::Debug for RegistrationProxies {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistrationProxies")
            .field("tool_request_intercepts", &self.tool_request_intercepts)
            .field("llm_request_intercepts", &self.llm_request_intercepts)
            .field("subscribers", &self.subscribers)
            .field("metadata_injectors", &self.metadata_injectors)
            .field("tool_sanitize_request", &self.tool_sanitize_request)
            .field("tool_conditional", &self.tool_conditional)
            .field("llm_conditional", &self.llm_conditional)
            .field("tool_sanitize_response", &self.tool_sanitize_response)
            .finish()
    }
}

impl RegistrationProxies {
    /// The registrations currently proxied.
    pub fn registration_ids(&self) -> Vec<&str> {
        self.tool_request_intercepts
            .iter()
            .chain(self.llm_request_intercepts.iter())
            .chain(self.subscribers.iter())
            .chain(self.metadata_injectors.iter())
            .chain(self.tool_sanitize_request.iter())
            .chain(self.tool_conditional.iter())
            .chain(self.llm_conditional.iter())
            .chain(self.tool_sanitize_response.iter())
            .map(String::as_str)
            .collect()
    }
}

impl Drop for RegistrationProxies {
    fn drop(&mut self) {
        for registration in &self.tool_request_intercepts {
            let _ = nemo_relay::api::registry::deregister_tool_request_intercept(registration);
        }
        for registration in &self.llm_request_intercepts {
            let _ = nemo_relay::api::registry::deregister_llm_request_intercept(registration);
        }
        for registration in &self.metadata_injectors {
            let _ = nemo_relay::api::registry::deregister_event_metadata_injector(registration);
        }
        for registration in &self.subscribers {
            let _ = nemo_relay::api::subscriber::deregister_subscriber(registration);
        }
        for registration in &self.llm_conditional {
            let _ = nemo_relay::api::registry::deregister_llm_conditional_execution_guardrail(
                registration,
            );
        }
        for registration in &self.tool_conditional {
            let _ = nemo_relay::api::registry::deregister_tool_conditional_execution_guardrail(
                registration,
            );
        }
        for registration in &self.tool_sanitize_request {
            let _ =
                nemo_relay::api::registry::deregister_tool_sanitize_request_guardrail(registration);
        }
        for registration in &self.tool_sanitize_response {
            let _ = nemo_relay::api::registry::deregister_tool_sanitize_response_guardrail(
                registration,
            );
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
        llm_request_intercepts: Vec::new(),
        subscribers: Vec::new(),
        metadata_injectors: Vec::new(),
        tool_sanitize_request: Vec::new(),
        tool_conditional: Vec::new(),
        llm_conditional: Vec::new(),
        tool_sanitize_response: Vec::new(),
        deliveries: Vec::new(),
    };

    for registration in &descriptor.registrations {
        match registration.operation {
            PluginRegistrationOperation::LlmConditionalExecutionGuardrail => {
                install_llm_conditional(&context, registration, &handle)?;
                installed
                    .llm_conditional
                    .push(registration.registration_id.clone());
            }
            PluginRegistrationOperation::ToolConditionalExecutionGuardrail => {
                install_tool_conditional(&context, registration, &handle)?;
                installed
                    .tool_conditional
                    .push(registration.registration_id.clone());
            }
            PluginRegistrationOperation::ToolSanitizeRequestGuardrail => {
                install_tool_sanitize(&context, registration, &handle, false)?;
                installed
                    .tool_sanitize_request
                    .push(registration.registration_id.clone());
            }
            PluginRegistrationOperation::ToolSanitizeResponseGuardrail => {
                install_tool_sanitize(&context, registration, &handle, true)?;
                installed
                    .tool_sanitize_response
                    .push(registration.registration_id.clone());
            }
            PluginRegistrationOperation::EventMetadataInjector => {
                install_metadata_injector(&context, registration, &handle)?;
                installed
                    .metadata_injectors
                    .push(registration.registration_id.clone());
            }
            PluginRegistrationOperation::Subscriber => {
                installed
                    .deliveries
                    .push(install_subscriber(&context, registration, &handle)?);
                installed
                    .subscribers
                    .push(registration.registration_id.clone());
            }
            PluginRegistrationOperation::ToolRequestIntercept => {
                install_tool_request_intercept(&context, registration, &handle)?;
                installed
                    .tool_request_intercepts
                    .push(registration.registration_id.clone());
            }
            PluginRegistrationOperation::LlmRequestIntercept => {
                install_llm_request_intercept(&context, registration, &handle)?;
                installed
                    .llm_request_intercepts
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
            let execution = context.execution_context()?;
            let request = PluginInvokeRequest {
                handle,
                registration_id: registration_id.clone(),
                arguments: payload.to_string(),
                budget_millis: execution.remaining_budget_millis,
            };
            // The operation is registered for as long as it is in flight, so a
            // mark the host forwards while this registration runs reaches the
            // scope of the call that raised it rather than the server task's.
            let _in_flight = context.operation_scopes.as_ref().map(|scopes| {
                scopes.enter(
                    &execution.operation_request_id,
                    nemo_relay::api::runtime::current_scope_stack(),
                )
            });
            let outcome = context
                .manager
                .invoke(request, execution)
                .await
                .map_err(|error| nemo_relay::error::FlowError::PluginInvocation {
                    registration: registration_id.clone(),
                    // The phase decides what may be asserted: a refusal before
                    // the backend means nothing ran, and an error after it means
                    // the callback's execution is unaccounted for — which is a
                    // different statement, and the one the caller has to see
                    // rather than a definite negative.
                    dispatch: error.dispatch(),
                    certainty: error.certainty(),
                    failure: error.failure,
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
    /// The budget is the one the runtime published for the action being
    /// executed, narrowed by this proxy's cap. A proxy that finds none refuses:
    /// a registration reached outside a managed action has no deadline to
    /// inherit, and choosing one would be the invention this path exists to
    /// avoid. The binding is the session's, not the proxy's invention, because
    /// the host checks it against the session it established.
    fn execution_context(&self) -> Result<PluginExecutionContext, nemo_relay::error::FlowError> {
        let now = nemo_relay::api::runtime::budget_now_unix_ms();
        let inherited = nemo_relay::api::runtime::current_execution_budget().ok_or_else(|| {
            nemo_relay::error::FlowError::InvalidArgument(
                "a remote plugin registration was reached outside a managed action, so it has \
                 no trusted budget to run under"
                    .to_string(),
            )
        })?;
        let narrowed = inherited.narrowed_to(self.local_cap_millis, now);
        Ok(PluginExecutionContext {
            operation_request_id: nemo_relay_plugin_protocol::Uuid::now_v7().to_string(),
            protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
            runtime_binding_digest: self.runtime_binding_digest.clone(),
            deadline_unix_ms: narrowed.deadline_unix_ms.unwrap_or(now),
            remaining_budget_millis: narrowed.remaining_budget_millis,
            max_response_bytes: nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
        })
    }
}

/// Install the proxy for one LLM request intercept.
///
/// The same shape as the tool class, one level up: the kernel sends the
/// invocation its own chain holds — the request *and* the annotation a codec
/// produced, because a callback may rewrite either — and the child runs exactly
/// the registration the kernel named. The outcome crosses whole, so the marks a
/// callback schedules and the evidence it records arrive with it.
fn install_llm_request_intercept(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    let registration_id = registration.registration_id.clone();
    let handle = handle.clone();
    let priority = registration.ordering.priority.unwrap_or_default();
    let break_chain = registration.ordering.may_break_chain.unwrap_or(false);
    let context = context.clone();

    let callable: LlmRequestInterceptFn = Arc::new(
        move |name: String, request: LlmRequest, annotated: Option<AnnotatedLlmRequest>| {
            let context = context.clone();
            let handle = handle.clone();
            let registration_id = registration_id.clone();
            Box::pin(async move {
                let invocation = nemo_relay::api::llm::LlmRequestInterceptInvocation {
                    name,
                    request,
                    annotated_request: annotated,
                };
                let payload = serde_json::to_string(&invocation).map_err(|error| {
                    nemo_relay::error::FlowError::Internal(format!(
                        "an LLM request intercept invocation could not be serialized: {error}"
                    ))
                })?;
                let execution = context.execution_context()?;
                let request = PluginInvokeRequest {
                    handle,
                    registration_id: registration_id.clone(),
                    arguments: payload,
                    budget_millis: execution.remaining_budget_millis,
                };
                let _in_flight = context.operation_scopes.as_ref().map(|scopes| {
                    scopes.enter(
                        &execution.operation_request_id,
                        nemo_relay::api::runtime::current_scope_stack(),
                    )
                });
                let outcome =
                    context
                        .manager
                        .invoke(request, execution)
                        .await
                        .map_err(|error| nemo_relay::error::FlowError::PluginInvocation {
                            registration: registration_id.clone(),
                            dispatch: error.dispatch(),
                            certainty: error.certainty(),
                            failure: error.failure,
                        })?;
                match outcome.result {
                    Ok(PluginSuccess::Invoked(response)) => serde_json::from_str(&response.output)
                        .map_err(|error| {
                            nemo_relay::error::FlowError::Internal(format!(
                                "a proxied registration answered with something that is not an \
                                 outcome: {error}"
                            ))
                        }),
                    Ok(other) => Err(nemo_relay::error::FlowError::Internal(format!(
                        "a proxied registration answered with {}",
                        other_name(&other)
                    ))),
                    Err(failure) => Err(nemo_relay::error::FlowError::PluginInvocation {
                        registration: registration_id,
                        dispatch: outcome.dispatch,
                        certainty: outcome.certainty,
                        failure,
                    }),
                }
            })
        },
    );

    nemo_relay::api::registry::register_llm_request_intercept(
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

/// Install the proxy for one tool conditional-execution guardrail.
///
/// A decision rather than a rewrite: the child answers with a reason to refuse or
/// with nothing to allow, and the kernel's own chain reports that as a rejection.
/// The guardrail's scope events are emitted by that chain — around this proxy —
/// with the kernel's subscribers, so what a remote guardrail looks like in the
/// event stream is what an in-process one looks like.
fn install_tool_conditional(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    let registration_id = registration.registration_id.clone();
    let handle = handle.clone();
    let priority = registration.ordering.priority.unwrap_or_default();
    let context = context.clone();

    let callable: nemo_relay::api::runtime::ToolConditionalFn =
        Arc::new(move |tool: String, args: serde_json::Value| {
            let context = context.clone();
            let handle = handle.clone();
            let registration_id = registration_id.clone();
            Box::pin(async move {
                let payload = serde_json::json!({ "tool": tool, "args": args }).to_string();
                let execution = context.execution_context()?;
                let request = PluginInvokeRequest {
                    handle,
                    registration_id: registration_id.clone(),
                    arguments: payload,
                    budget_millis: execution.remaining_budget_millis,
                };
                let _in_flight = context.operation_scopes.as_ref().map(|scopes| {
                    scopes.enter(
                        &execution.operation_request_id,
                        nemo_relay::api::runtime::current_scope_stack(),
                    )
                });
                let outcome =
                    context
                        .manager
                        .invoke(request, execution)
                        .await
                        .map_err(|error| nemo_relay::error::FlowError::PluginInvocation {
                            registration: registration_id.clone(),
                            dispatch: error.dispatch(),
                            certainty: error.certainty(),
                            failure: error.failure,
                        })?;
                match outcome.result {
                    Ok(PluginSuccess::Invoked(response)) => serde_json::from_str(&response.output)
                        .map_err(|error| {
                            nemo_relay::error::FlowError::Internal(format!(
                                "a proxied guardrail answered with something that is not a \
                                 decision: {error}"
                            ))
                        }),
                    Ok(other) => Err(nemo_relay::error::FlowError::Internal(format!(
                        "a proxied guardrail answered with {}",
                        other_name(&other)
                    ))),
                    Err(failure) => Err(nemo_relay::error::FlowError::PluginInvocation {
                        registration: registration_id,
                        dispatch: outcome.dispatch,
                        certainty: outcome.certainty,
                        failure,
                    }),
                }
            })
        });

    nemo_relay::api::registry::register_tool_conditional_execution_guardrail(
        &registration.registration_id,
        priority,
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

/// Install the proxy for one LLM conditional-execution guardrail.
///
/// The tool decision's twin, over the request instead of the arguments: the child
/// answers with a reason to refuse or nothing to allow, and the kernel's chain
/// reports the refusal and emits the guardrail's scope events around this proxy.
fn install_llm_conditional(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    let registration_id = registration.registration_id.clone();
    let handle = handle.clone();
    let priority = registration.ordering.priority.unwrap_or_default();
    let context = context.clone();

    let callable: nemo_relay::api::runtime::LlmConditionalFn =
        Arc::new(move |request: LlmRequest| {
            let context = context.clone();
            let handle = handle.clone();
            let registration_id = registration_id.clone();
            Box::pin(async move {
                let payload = serde_json::to_string(&request).map_err(|error| {
                    nemo_relay::error::FlowError::Internal(format!(
                        "an LLM conditional request could not be serialized: {error}"
                    ))
                })?;
                let execution = context.execution_context()?;
                let invocation = PluginInvokeRequest {
                    handle,
                    registration_id: registration_id.clone(),
                    arguments: payload,
                    budget_millis: execution.remaining_budget_millis,
                };
                let _in_flight = context.operation_scopes.as_ref().map(|scopes| {
                    scopes.enter(
                        &execution.operation_request_id,
                        nemo_relay::api::runtime::current_scope_stack(),
                    )
                });
                let outcome = context
                    .manager
                    .invoke(invocation, execution)
                    .await
                    .map_err(|error| nemo_relay::error::FlowError::PluginInvocation {
                        registration: registration_id.clone(),
                        dispatch: error.dispatch(),
                        certainty: error.certainty(),
                        failure: error.failure,
                    })?;
                match outcome.result {
                    Ok(PluginSuccess::Invoked(response)) => serde_json::from_str(&response.output)
                        .map_err(|error| {
                            nemo_relay::error::FlowError::Internal(format!(
                                "a proxied guardrail answered with something that is not a \
                                 decision: {error}"
                            ))
                        }),
                    Ok(other) => Err(nemo_relay::error::FlowError::Internal(format!(
                        "a proxied guardrail answered with {}",
                        other_name(&other)
                    ))),
                    Err(failure) => Err(nemo_relay::error::FlowError::PluginInvocation {
                        registration: registration_id,
                        dispatch: outcome.dispatch,
                        certainty: outcome.certainty,
                        failure,
                    }),
                }
            })
        });

    nemo_relay::api::registry::register_llm_conditional_execution_guardrail(
        &registration.registration_id,
        priority,
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

/// Install the proxy for one tool sanitize guardrail.
///
/// A sanitize guardrail changes what observers see and never what the tool does,
/// which is what makes this proxy safe to have at all: it is handed the copy of
/// the payload an event would carry, and its answer is used for that event. A
/// refusal — including the host reporting that the guardrail omitted the payload
/// — is returned as an error, because that is how the kernel's chain learns to
/// publish nothing rather than publish unsanitized.
fn install_tool_sanitize(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
    response_direction: bool,
) -> Result<(), PluginProtocolError> {
    let registration_id = registration.registration_id.clone();
    let handle = handle.clone();
    let priority = registration.ordering.priority.unwrap_or_default();
    let context = context.clone();
    // The answer comes from the composition's off-path runtime rather than from
    // whichever runtime is running this callback: the caller's thread is often
    // the one waiting for it, and on a single-threaded caller runtime it always
    // is.
    let off_path = context.off_path.clone().ok_or_else(|| {
        PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "'{}' is a sanitize guardrail and this runtime started no runtime for work \
                 beside a call, so its answer could never arrive",
                registration.registration_id
            ),
        )
    })?;
    let callable: ToolSanitizeFn = Arc::new(move |tool: String, value: serde_json::Value| {
        let context = context.clone();
        let handle = handle.clone();
        let registration_id = registration_id.clone();
        let off_path = Arc::clone(&off_path);
        Box::pin(async move {
            let recording = registration_id.clone();
            let submitted = Arc::clone(&off_path).submit(async move {
                let payload = serde_json::json!({ "tool": tool, "value": value }).to_string();
                let execution = context.passive_execution_context(
                    nemo_relay_plugin_protocol::Uuid::now_v7().to_string(),
                )?;
                let request = PluginInvokeRequest {
                    handle,
                    registration_id: registration_id.clone(),
                    arguments: payload,
                    budget_millis: execution.remaining_budget_millis,
                };
                let _in_flight = context.operation_scopes.as_ref().map(|scopes| {
                    scopes.enter(
                        &execution.operation_request_id,
                        nemo_relay::api::runtime::current_scope_stack(),
                    )
                });
                // The off-path transport, never the primary one: this callback
                // runs beside the call, and the connection it uses is the one
                // whose tasks live on the runtime that awaits it.
                let outcome = off_path.invoke(request, execution).await.map_err(|error| {
                    nemo_relay::error::FlowError::PluginInvocation {
                        registration: registration_id.clone(),
                        dispatch: error.dispatch(),
                        certainty: error.certainty(),
                        failure: error.failure,
                    }
                })?;
                match outcome.result {
                    Ok(PluginSuccess::Invoked(response)) => serde_json::from_str(&response.output)
                        .map_err(|error| {
                            nemo_relay::error::FlowError::Internal(format!(
                                "a proxied guardrail answered with something that is not JSON: \
                                 {error}"
                            ))
                        }),
                    Ok(other) => Err(nemo_relay::error::FlowError::Internal(format!(
                        "a proxied guardrail answered with {}",
                        other_name(&other)
                    ))),
                    Err(failure) => Err(nemo_relay::error::FlowError::PluginInvocation {
                        registration: registration_id,
                        dispatch: outcome.dispatch,
                        certainty: outcome.certainty,
                        failure,
                    }),
                }
            });
            let Some(answer) = submitted else {
                // Saturation fails closed for this family: a payload that could
                // not be sanitized is not published unsanitized, and the call it
                // belongs to is never made to wait for the sanitizer.
                let error = nemo_relay::error::FlowError::ResourceExhausted {
                    resource: "plugin_observability_in_flight",
                    limit: 0,
                };
                crate::off_path::record_failure(
                    crate::off_path::SANITIZE_FAILURE_MARK,
                    &recording,
                    &error.to_string(),
                );
                return Err(error);
            };
            match crate::off_path::OffPathPluginExecutor::answer(answer)
                .await
                .and_then(|inner| inner)
            {
                Ok(value) => Ok(value),
                Err(error) => {
                    // The chain will clear the observability fields, which is the
                    // fail-closed answer; the record is what keeps a sanitizer
                    // that could not decide from being invisible.
                    crate::off_path::record_failure(
                        crate::off_path::SANITIZE_FAILURE_MARK,
                        &recording,
                        &error.to_string(),
                    );
                    Err(error)
                }
            }
        })
    });

    let installed = if response_direction {
        nemo_relay::api::registry::register_tool_sanitize_response_guardrail(
            &registration.registration_id,
            priority,
            callable,
        )
    } else {
        nemo_relay::api::registry::register_tool_sanitize_request_guardrail(
            &registration.registration_id,
            priority,
            callable,
        )
    };
    installed.map_err(|error| {
        PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "the proxy for '{}' could not be installed: {error}",
                registration.registration_id
            ),
        )
    })
}

/// Install the proxy for one event metadata injector.
///
/// An injector adds: it answers with the keys it wants added, and the kernel
/// inserts them into the copy of the event its dispatcher is about to publish.
/// Nothing it returns reaches the call that produced the event, which is the same
/// guarantee the sanitizers carry and the reason this class is safe to run
/// elsewhere.
///
/// Failure follows the family's own rule rather than a new one: an injector that
/// cannot answer preserves the event and continues without injection, so this
/// records the failure — an additive hook must not become a way to stop a runtime
/// from publishing — and lets the chain proceed with nothing added.
fn install_metadata_injector(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    let registration_id = registration.registration_id.clone();
    let handle = handle.clone();
    let priority = registration.ordering.priority.unwrap_or_default();
    let context = context.clone();
    let off_path = context.off_path.clone().ok_or_else(|| {
        PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "'{}' is a metadata injector and this runtime started no runtime for work beside \
                 a call, so its answer could never arrive",
                registration.registration_id
            ),
        )
    })?;

    let callable: nemo_relay::api::runtime::EventMetadataInjectorFn = Arc::new(
        move |event: std::sync::Arc<nemo_relay::api::event::Event>| {
            let context = context.clone();
            let handle = handle.clone();
            let registration_id = registration_id.clone();
            let off_path = Arc::clone(&off_path);
            Box::pin(async move {
                let observed = nemo_relay_plugin_protocol::PluginObservedEvent {
                    event: (*event).clone(),
                };
                let recording = registration_id.clone();
                let payload = serde_json::to_string(&observed).map_err(|error| {
                    nemo_relay::error::FlowError::Internal(format!(
                        "an observed event could not be serialized: {error}"
                    ))
                })?;
                let delivery = Arc::clone(&off_path);
                let submitted = off_path.submit(async move {
                    let execution = context.passive_execution_context(
                        nemo_relay_plugin_protocol::Uuid::now_v7().to_string(),
                    )?;
                    let request = PluginInvokeRequest {
                        handle,
                        registration_id: registration_id.clone(),
                        arguments: payload,
                        budget_millis: execution.remaining_budget_millis,
                    };
                    let _in_flight = context.operation_scopes.as_ref().map(|scopes| {
                        scopes.enter(
                            &execution.operation_request_id,
                            nemo_relay::api::runtime::current_scope_stack(),
                        )
                    });
                    let outcome = delivery.invoke(request, execution).await.map_err(|error| {
                        nemo_relay::error::FlowError::PluginInvocation {
                            registration: registration_id.clone(),
                            dispatch: error.dispatch(),
                            certainty: error.certainty(),
                            failure: error.failure,
                        }
                    })?;
                    match outcome.result {
                        Ok(PluginSuccess::Invoked(response)) => {
                            let additions: serde_json::Value =
                                serde_json::from_str(&response.output).map_err(|error| {
                                    nemo_relay::error::FlowError::Internal(format!(
                                        "a proxied injector answered with something that is not \
                                         metadata: {error}"
                                    ))
                                })?;
                            // The boundary the family needs: metadata is an
                            // object, and anything else is refused rather than
                            // coerced into one.
                            let Some(object) = additions.as_object() else {
                                return Err(nemo_relay::error::FlowError::InvalidArgument(
                                    "an injector's answer must be a JSON object of metadata".into(),
                                ));
                            };
                            Ok(object
                                .iter()
                                .map(|(key, value)| (key.clone(), value.clone()))
                                .collect::<std::collections::BTreeMap<_, _>>())
                        }
                        Ok(other) => Err(nemo_relay::error::FlowError::Internal(format!(
                            "a proxied injector answered with {}",
                            other_name(&other)
                        ))),
                        Err(failure) => Err(nemo_relay::error::FlowError::PluginInvocation {
                            registration: registration_id,
                            dispatch: outcome.dispatch,
                            certainty: outcome.certainty,
                            failure,
                        }),
                    }
                });
                let Some(answer) = submitted else {
                    // Saturation is the family's rule too: nothing is added, and
                    // the event is published as it was.
                    crate::off_path::record_failure(
                        crate::off_path::METADATA_FAILURE_MARK,
                        &recording,
                        "the off-path runtime is at its in-flight limit",
                    );
                    return Ok(std::collections::BTreeMap::new());
                };
                match crate::off_path::OffPathPluginExecutor::answer(answer)
                    .await
                    .and_then(|inner| inner)
                {
                    Ok(additions) => Ok(additions),
                    Err(error) => {
                        crate::off_path::record_failure(
                            crate::off_path::METADATA_FAILURE_MARK,
                            &recording,
                            &error.to_string(),
                        );
                        Err(error)
                    }
                }
            })
        },
    );

    nemo_relay::api::registry::register_event_metadata_injector(
        &registration.registration_id,
        priority,
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

/// Install the proxy for one event subscriber.
///
/// The kernel keeps its own subscriber list — one proxy per registration — and
/// the host runs exactly the registration this proxy stands for, which is the
/// same separation the intercept classes use. What differs is what happens when
/// it fails: see [`crate::observer`], where the rule is that an observer's
/// failure is recorded and stops there.
fn install_subscriber(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<std::sync::Arc<crate::observer::ObserverDelivery>, PluginProtocolError> {
    let Some(budget_millis) = context
        .observability_budget_millis
        .filter(|millis| *millis > 0)
    else {
        // No stated limit means no remote observers, rather than a limit this
        // layer chose for the runtime.
        return Err(PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "'{}' is a subscriber and this runtime states no observability budget, so it cannot \
                 be delivered to",
                registration.registration_id
            ),
        ));
    };
    let registration_id = registration.registration_id.clone();
    let off_path = context.off_path.clone().ok_or_else(|| {
        PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "'{}' is a subscriber and this runtime started no runtime for work beside a \
                 call, so its events would have nowhere to be answered from",
                registration.registration_id
            ),
        )
    })?;
    let delivery = std::sync::Arc::new(crate::observer::ObserverDelivery::start(
        Arc::clone(&off_path),
        Arc::clone(&context.manager),
        context.runtime_binding_digest.clone(),
        handle.clone(),
        registration_id.clone(),
        budget_millis,
        context.operation_scopes.clone(),
    )?);

    let offering = std::sync::Arc::clone(&delivery);
    let callable: nemo_relay::api::runtime::EventSubscriberFn =
        Arc::new(move |event: &nemo_relay::api::event::Event| {
            // An observer is not told about its own delivery failures. The
            // failure is reported as an event, and delivering that event to the
            // observer that caused it would ask it to fail again — an observer
            // that fails on every event would otherwise never stop being told.
            if event.name() == crate::observer::OBSERVER_FAILURE_MARK
                && event
                    .data()
                    .and_then(|data| data.get("registration"))
                    .and_then(|registration| registration.as_str())
                    == Some(registration_id.as_str())
            {
                return;
            }
            offering.offer(
                nemo_relay_plugin_protocol::PluginObservedEvent {
                    event: event.clone(),
                },
                &registration_id,
            );
        });
    nemo_relay::api::subscriber::register_subscriber(&registration.registration_id, callable)
        .map_err(|error| {
            PluginProtocolError::new(
                PluginFailureCode::Rejected,
                format!(
                    "the proxy for '{}' could not be installed: {error}",
                    registration.registration_id
                ),
            )
        })?;
    Ok(delivery)
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

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay::plugin::execution::{
        PluginExecutionBackend, PluginExecutionFuture, PluginManager,
    };
    use nemo_relay_plugin_protocol::{
        DispatchState, OutcomeCertainty, PluginDescriptor, PluginExecutionOutcome,
        PluginInvokeResponse,
    };
    use std::sync::Mutex;

    /// Core's registration chains are process-global, so the tests that install
    /// into them take turns: two suites sharing one registry would each observe
    /// the other's proxies.
    static PROXY_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Run a chain as the runtime would: under the trusted budget for the action.
    async fn run_under_budget<F>(future: F) -> F::Output
    where
        F: std::future::Future,
    {
        let now = nemo_relay::api::runtime::budget_now_unix_ms();
        nemo_relay::api::runtime::with_execution_budget(
            nemo_relay::api::runtime::ExecutionBudget::new(now + 30_000, 30_000),
            future,
        )
        .await
    }

    /// A sanitize proxy needs the runtime that can answer it.
    ///
    /// The callback runs on the dispatcher, off the call's task, so its answer
    /// arrives over the composition's attached transport. A composition that
    /// started no off-path runtime has nowhere for that answer to come from, and
    /// the refusal is the honest outcome: the alternative is a wait that ends at
    /// the budget. The caller's own thread count stopped mattering when the
    /// transport moved to the off-path runtime, which is why this test no longer
    /// has a second reason.
    #[tokio::test]
    async fn a_sanitize_proxy_needs_an_off_path_runtime() {
        let _guard = PROXY_TEST_LOCK.lock().await;
        let backend = Arc::new(RecordingProxyBackend::default());
        let context = ProxyContext::new(
            Arc::new(PluginManager::new(
                backend as Arc<dyn PluginExecutionBackend>,
            )),
            "test-binding",
            5_000,
        )
        .with_observability_budget(5_000);

        let error = install(
            context,
            &descriptor(PluginRegistrationOperation::ToolSanitizeResponseGuardrail),
            PluginHandle {
                plugin_id: "example".into(),
                generation: 1,
            },
        )
        .expect_err("a sanitize proxy with no off-path runtime");
        assert_eq!(error.failure.code, PluginFailureCode::Rejected, "{error:?}");
        assert!(
            error.failure.message.contains("runtime for work"),
            "the reason a sanitizer cannot be served here: {error:?}"
        );
    }

    /// An observer's delivery is not part of the action whose event it sees, so
    /// it does not inherit that action's budget. A runtime that states none
    /// cannot have remote observers: the alternative is a number this layer
    /// chose for the runtime.
    #[tokio::test]
    async fn a_subscriber_cannot_be_proxied_without_a_stated_observer_budget() {
        let _guard = PROXY_TEST_LOCK.lock().await;
        let backend = Arc::new(RecordingProxyBackend::default());
        let context = ProxyContext::new(
            Arc::new(PluginManager::new(
                backend as Arc<dyn PluginExecutionBackend>,
            )),
            "test-binding",
            5_000,
        );

        let error = install(
            context,
            &descriptor(PluginRegistrationOperation::Subscriber),
            PluginHandle {
                plugin_id: "example".into(),
                generation: 1,
            },
        )
        .expect_err("a subscriber with no observability budget");
        assert_eq!(error.failure.code, PluginFailureCode::Rejected, "{error:?}");
        assert!(
            error.failure.message.contains("observability budget"),
            "{error:?}"
        );
    }

    /// Outside a managed action there is no budget to inherit, and a proxy that
    /// invented one would let a registration outlive the work that asked for it.
    #[tokio::test]
    async fn a_proxy_reached_outside_a_managed_action_refuses_rather_than_inventing_a_deadline() {
        let _guard = PROXY_TEST_LOCK.lock().await;
        let backend = Arc::new(RecordingProxyBackend::default());
        let context = ProxyContext::new(
            Arc::new(PluginManager::new(
                backend.clone() as Arc<dyn PluginExecutionBackend>
            )),
            "test-binding",
            5_000,
        );
        let installed = install(
            context,
            &descriptor(PluginRegistrationOperation::ToolRequestIntercept),
            PluginHandle {
                plugin_id: "example".into(),
                generation: 1,
            },
        )
        .expect("the one class this kernel proxies");

        let error = nemo_relay::api::tool::tool_request_intercepts(
            "example_tool",
            serde_json::json!({"input": true}),
        )
        .await
        .expect_err("no trusted budget is in scope");

        assert!(
            error.to_string().contains("trusted budget"),
            "the refusal says why: {error}"
        );
        assert!(
            backend.invocations.lock().expect("the record").is_empty(),
            "nothing may reach the plugin without a budget to run under"
        );
        drop(installed);
    }

    /// A backend that records what it was asked to run.
    #[derive(Default)]
    struct RecordingProxyBackend {
        invocations: Mutex<Vec<(String, String)>>,
        /// When set, the backend fails *after* being entered, which is the case
        /// the phase distinction exists for.
        fails_after_being_entered: bool,
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
                if self.fails_after_being_entered {
                    return Err(PluginProtocolError::new(
                        PluginFailureCode::Unavailable,
                        "the plugin host did not answer",
                    ));
                }
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
        let _guard = PROXY_TEST_LOCK.lock().await;
        // Core's registries are process-global, so this is the only test in this
        // module that touches them.
        let backend = Arc::new(RecordingProxyBackend::default());
        let context = ProxyContext::new(
            Arc::new(PluginManager::new(
                backend.clone() as Arc<dyn PluginExecutionBackend>
            )),
            "test-binding",
            5_000,
        );
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
        let rewritten = run_under_budget(nemo_relay::api::tool::tool_request_intercepts(
            "example_tool",
            serde_json::json!({"input": true}),
        ))
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
        let after = run_under_budget(nemo_relay::api::tool::tool_request_intercepts(
            "example_tool",
            serde_json::json!({"input": true}),
        ))
        .await
        .expect("the chain");
        assert_eq!(after["rewritten"], serde_json::Value::Null, "{after}");
    }

    /// The P0 the audit found: an error from a backend that was entered is not
    /// proof that nothing ran, and a proxy that said so would state a fact it
    /// cannot account for.
    #[tokio::test]
    async fn a_failure_after_the_backend_was_entered_is_uncertain_and_not_a_definite_negative() {
        let _guard = PROXY_TEST_LOCK.lock().await;
        let backend = Arc::new(RecordingProxyBackend {
            invocations: Mutex::new(Vec::new()),
            fails_after_being_entered: true,
        });
        let context = ProxyContext::new(
            Arc::new(PluginManager::new(
                backend.clone() as Arc<dyn PluginExecutionBackend>
            )),
            "test-binding",
            5_000,
        );
        let installed = install(
            context,
            &descriptor(PluginRegistrationOperation::ToolRequestIntercept),
            PluginHandle {
                plugin_id: "example".into(),
                generation: 1,
            },
        )
        .expect("the one class this kernel proxies");

        let error = run_under_budget(nemo_relay::api::tool::tool_request_intercepts(
            "example_tool",
            serde_json::json!({"input": true}),
        ))
        .await
        .expect_err("the backend failed after it was entered");

        // The plugin's own reason survives, and so does the honest answer about
        // what happened: an attempt was made and the outcome is unknown.
        match error {
            nemo_relay::error::FlowError::PluginInvocation {
                dispatch,
                certainty,
                failure,
                ..
            } => {
                assert_eq!(dispatch, DispatchState::DispatchAttempted);
                assert_eq!(certainty, OutcomeCertainty::Unknown);
                assert_eq!(failure.code, PluginFailureCode::Unavailable);
            }
            other => panic!("expected a structured invocation failure, got {other:?}"),
        }
        assert_eq!(
            backend.invocations.lock().expect("the record").len(),
            1,
            "the backend was reached before it failed"
        );
        drop(installed);
    }

    /// And the other half: a refusal the manager made *before* the backend is
    /// proof that nothing ran, so it stays a definite negative.
    #[tokio::test]
    async fn a_manager_refusal_is_distinguishable_from_an_entered_backend() {
        let _guard = PROXY_TEST_LOCK.lock().await;
        let backend = Arc::new(RecordingProxyBackend::default());
        let manager = PluginManager::new(backend.clone() as Arc<dyn PluginExecutionBackend>);
        let expired = PluginExecutionContext {
            operation_request_id: "operation-expired".into(),
            protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
            runtime_binding_digest: "test-binding".into(),
            // Already past: the manager refuses before reaching a backend.
            deadline_unix_ms: 1,
            remaining_budget_millis: 5_000,
            max_response_bytes: 1024,
        };
        let error = manager
            .invoke(
                PluginInvokeRequest {
                    handle: PluginHandle {
                        plugin_id: "example".into(),
                        generation: 1,
                    },
                    registration_id: "nemo-relay-plugin.v1.example:1:rewrite".into(),
                    arguments: serde_json::json!({"tool": "t", "args": {}}).to_string(),
                    budget_millis: 5_000,
                },
                expired,
            )
            .await
            .expect_err("an operation that is already out of time");

        assert_eq!(
            error.phase,
            nemo_relay_plugin_protocol::PluginInvocationPhase::RefusedBeforeBackend
        );
        assert_eq!(error.dispatch(), DispatchState::NotDispatched);
        assert_eq!(error.certainty(), OutcomeCertainty::ConfirmedFailure);
        assert!(
            backend.invocations.lock().expect("the record").is_empty(),
            "a refusal before the backend means the backend was never reached"
        );
    }

    #[test]
    fn a_registration_the_kernel_cannot_proxy_is_refused_rather_than_skipped() {
        let backend = Arc::new(RecordingProxyBackend::default());
        let context = ProxyContext::new(
            Arc::new(PluginManager::new(
                backend as Arc<dyn PluginExecutionBackend>,
            )),
            "test-binding",
            5_000,
        );
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
