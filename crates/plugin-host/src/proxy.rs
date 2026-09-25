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
    PluginDescriptor, PluginEventSanitizeCall, PluginEventSanitizeClass, PluginExecutionContext,
    PluginFailureCode, PluginHandle, PluginInvokeRequest, PluginProtocolError,
    PluginRegistrationDescriptor, PluginRegistrationOperation, PluginSuccess,
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
    /// The backend a streaming invocation goes to, when this composition has one.
    ///
    /// Not the manager: that answers one request with one outcome, and a stream
    /// is a different shape of call rather than a longer one.
    streaming: Option<Arc<crate::supervisor::ProcessPluginBackend>>,
    /// The codec capabilities this session issues, for the classes whose plugin is given a
    /// codec it cannot hold.
    ///
    /// Required by the LLM sanitizers: the kernel resolves the call's codec, the plugin is
    /// sent a reference, and the kernel's own callback service is what checks it — so the
    /// record has to be the same one both halves see.
    codec_capabilities: Option<Arc<crate::codec_capability::CodecCapabilities>>,
    /// Where the rest of a chain is held while a plugin decides when to run it.
    ///
    /// Required by the families that wrap a call rather than answer one: an
    /// execution intercept's `next` is the kernel's own remainder of the chain,
    /// and a plugin in another process can only reach it by asking this kernel to
    /// resume it.
    continuations: Option<Arc<crate::continuations::Continuations>>,
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
            streaming: None,
            continuations: None,
            observability_budget_millis: None,
            off_path: None,
            codec_capabilities: None,
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

    /// Give the composition's codec capability record to the classes that need it.
    pub fn with_codec_capabilities(
        mut self,
        capabilities: Arc<crate::codec_capability::CodecCapabilities>,
    ) -> Self {
        self.codec_capabilities = Some(capabilities);
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

    /// Reach the backend that can start a streaming invocation.
    pub fn with_streaming_backend(
        mut self,
        backend: Arc<crate::supervisor::ProcessPluginBackend>,
    ) -> Self {
        self.streaming = Some(backend);
        self
    }

    /// Hold suspended chain positions in `continuations`.
    ///
    /// Not optional in spirit: a proxy for a class that wraps a call cannot serve
    /// it without one, and installing one that could not reach a continuation
    /// would be installing a callback whose `next` goes nowhere.
    pub fn with_continuations(
        mut self,
        continuations: Arc<crate::continuations::Continuations>,
    ) -> Self {
        self.continuations = Some(continuations);
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
    mark_sanitize: Vec<String>,
    scope_sanitize_start: Vec<String>,
    scope_sanitize_end: Vec<String>,
    llm_sanitize_request: Vec<String>,
    tool_sanitize_request: Vec<String>,
    tool_execution_intercepts: Vec<String>,
    llm_execution_intercepts: Vec<String>,
    llm_stream_execution_intercepts: Vec<String>,
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
            .field("mark_sanitize", &self.mark_sanitize)
            .field("scope_sanitize_start", &self.scope_sanitize_start)
            .field("scope_sanitize_end", &self.scope_sanitize_end)
            .field("llm_sanitize_request", &self.llm_sanitize_request)
            .field("tool_sanitize_request", &self.tool_sanitize_request)
            .field("tool_execution_intercepts", &self.tool_execution_intercepts)
            .field("llm_execution_intercepts", &self.llm_execution_intercepts)
            .field(
                "llm_stream_execution_intercepts",
                &self.llm_stream_execution_intercepts,
            )
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
            .chain(self.mark_sanitize.iter())
            .chain(self.scope_sanitize_start.iter())
            .chain(self.scope_sanitize_end.iter())
            .chain(self.llm_sanitize_request.iter())
            .chain(self.tool_sanitize_request.iter())
            .chain(self.tool_execution_intercepts.iter())
            .chain(self.llm_execution_intercepts.iter())
            .chain(self.llm_stream_execution_intercepts.iter())
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
        for registration in &self.mark_sanitize {
            let _ = nemo_relay::api::registry::deregister_mark_sanitize_guardrail(registration);
        }
        for registration in &self.scope_sanitize_start {
            let _ =
                nemo_relay::api::registry::deregister_scope_sanitize_start_guardrail(registration);
        }
        for registration in &self.scope_sanitize_end {
            let _ =
                nemo_relay::api::registry::deregister_scope_sanitize_end_guardrail(registration);
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
        for registration in &self.llm_sanitize_request {
            let _ =
                nemo_relay::api::registry::deregister_llm_sanitize_request_guardrail(registration);
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
        for registration in &self.tool_execution_intercepts {
            let _ = nemo_relay::api::registry::deregister_tool_execution_intercept(registration);
        }
        for registration in &self.llm_execution_intercepts {
            let _ = nemo_relay::api::registry::deregister_llm_execution_intercept(registration);
        }
        for registration in &self.llm_stream_execution_intercepts {
            let _ =
                nemo_relay::api::registry::deregister_llm_stream_execution_intercept(registration);
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
        mark_sanitize: Vec::new(),
        scope_sanitize_start: Vec::new(),
        scope_sanitize_end: Vec::new(),
        llm_sanitize_request: Vec::new(),
        tool_sanitize_request: Vec::new(),
        tool_execution_intercepts: Vec::new(),
        llm_execution_intercepts: Vec::new(),
        llm_stream_execution_intercepts: Vec::new(),
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
            // The class whose sanitizer is given the call's codec, which is why it is
            // the last to cross: the codec cannot, so the plugin is given an identity to
            // decide with and a reference the kernel checks.
            PluginRegistrationOperation::LlmSanitizeRequestGuardrail => {
                install_llm_sanitize_request(&context, registration, &handle)?;
                installed
                    .llm_sanitize_request
                    .push(registration.registration_id.clone());
            }
            // The three event sanitize families. One installer parameterised by
            // class, and three named wrappers over it: the class decides the
            // projection, the registry and — from the registration's own record — the
            // exact-registration door on the far side, and none of those is something
            // a caller passes in.
            PluginRegistrationOperation::MarkSanitizeGuardrail => {
                install_mark_sanitize(&context, registration, &handle)?;
                installed
                    .mark_sanitize
                    .push(registration.registration_id.clone());
            }
            PluginRegistrationOperation::ScopeSanitizeStartGuardrail => {
                install_scope_sanitize_start(&context, registration, &handle)?;
                installed
                    .scope_sanitize_start
                    .push(registration.registration_id.clone());
            }
            PluginRegistrationOperation::ScopeSanitizeEndGuardrail => {
                install_scope_sanitize_end(&context, registration, &handle)?;
                installed
                    .scope_sanitize_end
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
            PluginRegistrationOperation::ToolExecutionIntercept => {
                install_tool_execution_intercept(&context, registration, &handle)?;
                installed
                    .tool_execution_intercepts
                    .push(registration.registration_id.clone());
            }
            PluginRegistrationOperation::LlmExecutionIntercept => {
                install_llm_execution_intercept(&context, registration, &handle)?;
                installed
                    .llm_execution_intercepts
                    .push(registration.registration_id.clone());
            }
            PluginRegistrationOperation::LlmStreamExecutionIntercept => {
                install_llm_stream_execution_intercept(&context, registration, &handle)?;
                installed
                    .llm_stream_execution_intercepts
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

/// Install the proxy for one tool execution intercept.
///
/// The first family that *wraps* a call rather than answering one. The plugin
/// decides when the rest of the chain runs, and the rest of the chain is this
/// kernel's, so the kernel parks its own position for the operation and resumes
/// it when the host asks. What the plugin returns — the result it decided on,
/// plus the marks it asked for — comes back as one outcome, and the engine's own
/// chain wrapper appends whatever the continuation produced, so the marks and
/// their order are the ones an in-process intercept would have produced.
///
/// The continuation is held for exactly as long as this intercept runs. A
/// continuation that arrives after it returns finds nothing to resume, and one
/// still in flight when it returns is cancelled by the continuation's own lease
/// — the same rule the engine applies to an in-process `next`.
fn install_tool_execution_intercept(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    let registration_id = registration.registration_id.clone();
    let handle = handle.clone();
    let priority = registration.ordering.priority.unwrap_or_default();
    let context = context.clone();
    // A composition that cannot hold a continuation cannot serve this class: the
    // plugin's `next` would have nowhere to go, and installing the proxy anyway
    // would install a callback whose continuation silently did nothing.
    let continuations = context.continuations.clone().ok_or_else(|| {
        PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "the proxy for '{}' needs the composition to hold continuations: an execution \
                 intercept's continuation is the kernel's own chain",
                registration.registration_id
            ),
        )
    })?;

    let callable: nemo_relay::api::runtime::ToolExecutionFn =
        Arc::new(move |name: &str, args: serde_json::Value, next| {
            let context = context.clone();
            let handle = handle.clone();
            let registration_id = registration_id.clone();
            let continuations = Arc::clone(&continuations);
            let name = name.to_owned();
            Box::pin(async move {
                let payload = serde_json::json!({ "tool": name, "args": args }).to_string();
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
                let _held = continuations.hold_tool(
                    &execution.operation_request_id,
                    &registration_id,
                    next,
                );
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
                                "a proxied execution intercept answered with something that is \
                                 not an outcome: {error}"
                            ))
                        }),
                    Ok(other) => Err(nemo_relay::error::FlowError::Internal(format!(
                        "a proxied execution intercept answered with {}",
                        other_name(&other)
                    ))),
                    Err(failure) => Err(nemo_relay::error::FlowError::PluginInvocation {
                        registration: registration_id.clone(),
                        dispatch: outcome.dispatch,
                        certainty: outcome.certainty,
                        failure,
                    }),
                }
            })
        });

    nemo_relay::api::registry::register_tool_execution_intercept(
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

/// Install the proxy for one streaming LLM execution intercept.
///
/// The third execution family, and the only one whose answer is a stream in both
/// directions: the plugin pulls the downstream stream through the session channel
/// while the kernel reads the stream the plugin returned. The kernel's part is to
/// park the chain position the host will pull from, start the invocation, and hand
/// the frames it produces to the caller as a managed stream.
///
/// The parked position is released when the stream ends or is dropped, in that
/// order of importance: a stream the caller stopped reading has to stop the
/// plugin, which needs the position to be gone rather than merely unused.
fn install_llm_stream_execution_intercept(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    let registration_id = registration.registration_id.clone();
    let handle = handle.clone();
    let priority = registration.ordering.priority.unwrap_or_default();
    let context = context.clone();
    let continuations = context.continuations.clone().ok_or_else(|| {
        PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "the proxy for '{}' needs the composition to hold continuations: a streaming \
                 intercept's downstream stream is the kernel's own chain",
                registration.registration_id
            ),
        )
    })?;

    let callable: nemo_relay::api::runtime::LlmStreamExecutionFn =
        Arc::new(move |name: &str, request: LlmRequest, next| {
            let context = context.clone();
            let handle = handle.clone();
            let registration_id = registration_id.clone();
            let continuations = Arc::clone(&continuations);
            let name = name.to_owned();
            Box::pin(async move {
                let payload = serde_json::json!({ "name": name, "request": request });
                let execution = context.execution_context()?;
                let invocation = PluginInvokeRequest {
                    handle,
                    registration_id: registration_id.clone(),
                    arguments: payload.to_string(),
                    budget_millis: execution.remaining_budget_millis,
                };
                let _in_flight = context.operation_scopes.as_ref().map(|scopes| {
                    scopes.enter(
                        &execution.operation_request_id,
                        nemo_relay::api::runtime::current_scope_stack(),
                    )
                });
                // Held for the life of the stream rather than the life of the
                // call: the plugin pulls from this position while its own stream
                // is being read, and a position released when the call returned
                // would refuse the pull that comes later.
                let held = continuations.hold_llm_stream(
                    &execution.operation_request_id,
                    &registration_id,
                    next,
                );
                // The streaming call goes to the backend rather than through the
                // manager: the manager's job is one request and one answer, and
                // this answer is a stream.
                let streaming = context.streaming.clone().ok_or_else(|| {
                    nemo_relay::error::FlowError::Internal(
                        "this composition reaches no streaming backend".to_string(),
                    )
                })?;
                let frames = streaming
                    .invoke_stream(invocation, execution.clone())
                    .await
                    .map_err(|error| nemo_relay::error::FlowError::PluginInvocation {
                        registration: registration_id.clone(),
                        // The call was handed to the host before anything could
                        // fail here, and the plugin's callback is what runs
                        // there: whether it produced anything is not something
                        // this side can deny, so the failure says so.
                        dispatch: nemo_relay_plugin_protocol::DispatchState::DispatchAttempted,
                        certainty: nemo_relay_plugin_protocol::OutcomeCertainty::Unknown,
                        failure: error.failure,
                    })?;
                Ok(nemo_relay::api::runtime::LlmJsonStream::new(
                    FramesAsChunks {
                        operation_request_id: frames.operation_request_id().to_owned(),
                        frames: Box::pin(frames),
                        terminal: false,
                        _held: held,
                    },
                ))
            })
        });

    nemo_relay::api::registry::register_llm_stream_execution_intercept(
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

/// The kernel's view of a streaming invocation's frames, as a plugin stream.
///
/// The frames are read one at a time, because reading is what asks the host for
/// the next one. The parked chain position is held here so it outlives the call
/// that started the stream and is released when the stream is finished with.
struct FramesAsChunks {
    /// The invocation these frames answer.
    operation_request_id: String,
    /// The frames, one at a time: reading is what asks the host for the next one.
    frames: std::pin::Pin<
        Box<
            dyn tokio_stream::Stream<
                    Item = Result<
                        nemo_relay_plugin_protocol::PluginStreamChunk,
                        PluginProtocolError,
                    >,
                > + Send,
        >,
    >,
    /// Whether the frames said the stream was over.
    ///
    /// The terminal frame is the only thing that says a streaming call was
    /// complete, so this is what tells an end from a stream that stopped.
    terminal: bool,
    _held: crate::continuations::ContinuationGuard,
}

impl tokio_stream::Stream for FramesAsChunks {
    type Item = Result<nemo_relay::json::Json, nemo_relay::error::FlowError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use nemo_relay_plugin_protocol::PluginStreamChunkKind;
        use std::task::Poll;

        let this = self.as_mut().get_mut();
        let operation = this.operation_request_id.clone();
        match std::pin::Pin::new(&mut this.frames).poll_next(context) {
            Poll::Ready(Some(Ok(frame))) => match frame.chunk {
                PluginStreamChunkKind::Data(data) => match serde_json::from_str(&data) {
                    Ok(chunk) => Poll::Ready(Some(Ok(chunk))),
                    Err(error) => Poll::Ready(Some(Err(nemo_relay::error::FlowError::Internal(
                        format!("a streamed chunk is not JSON: {error}"),
                    )))),
                },
                // The plugin said the stream was over; the caller's stream ends
                // here rather than waiting for a frame that is not coming.
                PluginStreamChunkKind::End => {
                    this.terminal = true;
                    Poll::Ready(None)
                }
                PluginStreamChunkKind::Failed(failure) => {
                    Poll::Ready(Some(Err(nemo_relay::error::FlowError::PluginInvocation {
                        registration: operation,
                        dispatch: frame.dispatch,
                        certainty: frame.certainty,
                        failure,
                    })))
                }
            },
            Poll::Ready(Some(Err(error))) => {
                // The frames themselves failed: nothing more can arrive, so this
                // failure is what the caller gets and the stream is over with it.
                this.terminal = true;
                Poll::Ready(Some(Err(nemo_relay::error::FlowError::PluginInvocation {
                    registration: operation,
                    // The frames that arrived were produced by the plugin, so
                    // whether the call happened is not this failure's to deny.
                    dispatch: nemo_relay_plugin_protocol::DispatchState::DispatchAttempted,
                    certainty: nemo_relay_plugin_protocol::OutcomeCertainty::Unknown,
                    failure: nemo_relay_plugin_protocol::PluginFailure {
                        code: error.failure.code,
                        message: error.failure.message,
                    },
                })))
            }
            // The frames stopped. A streaming call is complete when the frame that
            // says so arrives and not otherwise: a host that answered and stopped,
            // or a session that broke, has said neither, and handing the caller a
            // truncated stream as a finished one is the failure this refuses.
            Poll::Ready(None) => {
                if this.terminal {
                    Poll::Ready(None)
                } else {
                    this.terminal = true;
                    Poll::Ready(Some(Err(nemo_relay::error::FlowError::PluginInvocation {
                        registration: operation.clone(),
                        dispatch: nemo_relay_plugin_protocol::DispatchState::DispatchAttempted,
                        certainty: nemo_relay_plugin_protocol::OutcomeCertainty::Unknown,
                        failure: nemo_relay_plugin_protocol::PluginFailure {
                            code: nemo_relay_plugin_protocol::PluginFailureCode::MalformedResponse,
                            message: format!(
                                "the stream of operation '{operation}' stopped without the frame \
                                 that says it was over"
                            ),
                        },
                    })))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Install the proxy for one non-streaming LLM execution intercept.
///
/// The tool execution intercept's twin, one layer up: the plugin decides when the
/// provider call runs, the call happens here, and the continuation between them
/// is the same suspended-chain machinery. What differs is only the shape that
/// travels — a provider request down, a provider response back — which is what
/// the parked entry's family records.
fn install_llm_execution_intercept(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    let registration_id = registration.registration_id.clone();
    let handle = handle.clone();
    let priority = registration.ordering.priority.unwrap_or_default();
    let context = context.clone();
    let continuations = context.continuations.clone().ok_or_else(|| {
        PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "the proxy for '{}' needs the composition to hold continuations: an execution \
                 intercept's continuation is the kernel's own chain",
                registration.registration_id
            ),
        )
    })?;

    let callable: nemo_relay::api::runtime::LlmExecutionFn =
        Arc::new(move |name: &str, request: LlmRequest, next| {
            let context = context.clone();
            let handle = handle.clone();
            let registration_id = registration_id.clone();
            let continuations = Arc::clone(&continuations);
            let name = name.to_owned();
            Box::pin(async move {
                let payload = serde_json::json!({ "name": name, "request": request });
                let execution = context.execution_context()?;
                let invocation = PluginInvokeRequest {
                    handle,
                    registration_id: registration_id.clone(),
                    arguments: payload.to_string(),
                    budget_millis: execution.remaining_budget_millis,
                };
                let _in_flight = context.operation_scopes.as_ref().map(|scopes| {
                    scopes.enter(
                        &execution.operation_request_id,
                        nemo_relay::api::runtime::current_scope_stack(),
                    )
                });
                let _held =
                    continuations.hold_llm(&execution.operation_request_id, &registration_id, next);
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
                                "a proxied LLM execution intercept answered with something that \
                                 is not a response: {error}"
                            ))
                        }),
                    Ok(other) => Err(nemo_relay::error::FlowError::Internal(format!(
                        "a proxied LLM execution intercept answered with {}",
                        other_name(&other)
                    ))),
                    Err(failure) => Err(nemo_relay::error::FlowError::PluginInvocation {
                        registration: registration_id.clone(),
                        dispatch: outcome.dispatch,
                        certainty: outcome.certainty,
                        failure,
                    }),
                }
            })
        });

    nemo_relay::api::registry::register_llm_execution_intercept(
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

/// Install the proxy for one LLM request sanitize registration.
///
/// This is the class the codec capability protocol exists for. A request sanitizer is given
/// the call's codec beside the payload, and a codec is a live object this process holds —
/// so what the plugin is sent is the codec's *identity*, which it decides with, and a
/// *reference*, which it may spend on exactly this invocation. The work happens here,
/// against the codec the call is using, and the plugin never holds the object.
///
/// The reference is issued for the invocation and dropped when it ends, whether that is an
/// answer, a refusal, a failure, saturation or a cancellation: the guard lives in the future
/// this callback returns, so every way out of the call takes the capability with it.
///
/// Failure follows the family's rule: a payload nobody could sanitize is omitted. The chain
/// omits it when this returns an error, and the record says why, because a sanitizer that
/// never worked and one that omitted everything look the same from the event alone.
fn install_llm_sanitize_request(
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
                "'{}' is an LLM request sanitizer and this runtime started no runtime for work \
                 beside a call, so its answer could never arrive",
                registration.registration_id
            ),
        )
    })?;
    let codecs = context.codec_capabilities.clone().ok_or_else(|| {
        PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "'{}' is an LLM request sanitizer and this runtime has no codec capability \
                 record, so a sanitizer could not use the codec the call is running under",
                registration.registration_id
            ),
        )
    })?;

    let callable: nemo_relay::api::runtime::LlmSanitizeRequestFn = Arc::new(
        move |request: nemo_relay::api::llm::LlmRequest,
              sanitize: nemo_relay::api::runtime::LlmSanitizeRequestContext| {
            let context = context.clone();
            let handle = handle.clone();
            let registration_id = registration_id.clone();
            let off_path = Arc::clone(&off_path);
            let codecs = Arc::clone(&codecs);
            Box::pin(async move {
                let recording = registration_id.clone();
                // The identity the plugin is told, and the reference it may use. Both are
                // the kernel's: a plugin has no say in which codec its call is running under.
                let operation_request_id = nemo_relay_plugin_protocol::Uuid::now_v7().to_string();
                let identity = sanitize.codec().clone();
                let issued = sanitize
                    .resolve_codec()
                    .map(|codec| codecs.issue_request(&operation_request_id, codec));
                let (reference, _capability) = match issued {
                    Some((reference, guard)) => (Some(reference), Some(guard)),
                    None => (None, None),
                };
                let (kind, id) = crate::codec_context::identity_to_wire(&identity);
                let mut call_context = serde_json::json!({ "codec_kind": kind });
                if let Some(id) = id {
                    call_context["codec_id"] = serde_json::Value::String(id);
                }
                if let Some(reference) = reference.as_ref() {
                    call_context["codec_reference"] =
                        serde_json::Value::String(reference.as_str().to_string());
                }
                let payload = serde_json::json!({
                    "request": request,
                    "context": call_context,
                })
                .to_string();
                let submitted = Arc::clone(&off_path).submit(async move {
                    let execution = context.passive_execution_context(operation_request_id)?;
                    let invoke = PluginInvokeRequest {
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
                    let outcome = off_path.invoke(invoke, execution).await.map_err(|error| {
                        nemo_relay::error::FlowError::PluginInvocation {
                            registration: registration_id.clone(),
                            dispatch: error.dispatch(),
                            certainty: error.certainty(),
                            failure: error.failure,
                        }
                    })?;
                    match outcome.result {
                        Ok(PluginSuccess::Invoked(response)) => {
                            serde_json::from_str::<nemo_relay::api::llm::LlmRequest>(
                                &response.output,
                            )
                            .map(Some)
                            .map_err(|error| {
                                nemo_relay::error::FlowError::Internal(format!(
                                    "a proxied LLM request sanitizer answered with something that \
                                     is not a request: {error}"
                                ))
                            })
                        }
                        Ok(other) => Err(nemo_relay::error::FlowError::Internal(format!(
                            "a proxied LLM request sanitizer answered with {}",
                            other_name(&other)
                        ))),
                        // A refusal is the family's omission: the payload is not published,
                        // and the plugin's own words are what the record carries.
                        Err(failure) => Err(nemo_relay::error::FlowError::PluginInvocation {
                            registration: registration_id,
                            dispatch: outcome.dispatch,
                            certainty: outcome.certainty,
                            failure,
                        }),
                    }
                });
                let Some(answer) = submitted else {
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
                    Ok(request) => Ok(request),
                    Err(error) => {
                        crate::off_path::record_failure(
                            crate::off_path::SANITIZE_FAILURE_MARK,
                            &recording,
                            &error.to_string(),
                        );
                        Err(error)
                    }
                }
            })
        },
    );

    nemo_relay::api::registry::register_llm_sanitize_request_guardrail(
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

/// Install the proxy for one event sanitize registration.
///
/// Three families share one shape and one serialization, and that is exactly why
/// the class is not a parameter of anything a caller can influence: the class this
/// proxy was installed for decides the projection it builds, the registry it goes
/// into, and — on the far side, from the registration's own record — the
/// exact-registration door the host runs. A mark sanitizer that could be reached
/// through the scope-start chain would be a capability the caller chose rather than
/// one the kernel granted.
///
/// What crosses is the projection rather than the runtime's event: the name a
/// sanitizer decides on, the phase when it is a scope event, and the mutable fields
/// it may change. What comes back is those fields and nothing else, so the class,
/// the registration identity, the operation identity and the envelope stay the
/// kernel's — a remote sanitizer cannot rename, re-parent or re-time the event it
/// sanitized, because it was never shown one.
///
/// Failure follows the family's rule: a payload that could not be sanitized is not
/// published unsanitized. Here that means the callback fails and the chain clears
/// the observability fields, and the failure is recorded, because a sanitizer that
/// never worked and one that cleared everything look identical from the event alone.
fn install_event_sanitize(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
    class: PluginEventSanitizeClass,
) -> Result<(), PluginProtocolError> {
    let registration_id = registration.registration_id.clone();
    let handle = handle.clone();
    let priority = registration.ordering.priority.unwrap_or_default();
    let context = context.clone();
    // Beside the call, like the tool pair: these run from the dispatcher, off the
    // task that made the call, so their answer has to arrive on a runtime the caller
    // is not holding.
    let off_path = context.off_path.clone().ok_or_else(|| {
        PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "'{}' is an event sanitizer and this runtime started no runtime for work beside a \
                 call, so its answer could never arrive",
                registration.registration_id
            ),
        )
    })?;

    let callable: nemo_relay::api::runtime::EventSanitizeFn = Arc::new(
        move |event: std::sync::Arc<nemo_relay::api::event::Event>,
              fields: nemo_relay::api::event::EventSanitizeFields| {
            let context = context.clone();
            let handle = handle.clone();
            let registration_id = registration_id.clone();
            let off_path = Arc::clone(&off_path);
            Box::pin(async move {
                let recording = registration_id.clone();
                // Built here, from the class this proxy stands for and the event the
                // chain handed it: an event of another kind is refused rather than
                // forwarded, because a projection is not a place to discover that the
                // chain and the class disagree.
                let call = PluginEventSanitizeCall::from_event(class, &event, fields).map_err(
                    |error| {
                        let error = nemo_relay::error::FlowError::Internal(error.failure.message);
                        crate::off_path::record_failure(
                            crate::off_path::SANITIZE_FAILURE_MARK,
                            &recording,
                            &error.to_string(),
                        );
                        error
                    },
                )?;
                let payload = serde_json::to_string(&call).map_err(|error| {
                    nemo_relay::error::FlowError::Internal(format!(
                        "a sanitizer projection could not be serialized: {error}"
                    ))
                })?;
                let submitted = Arc::clone(&off_path).submit(async move {
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
                        Ok(PluginSuccess::Invoked(response)) => {
                            serde_json::from_str::<nemo_relay::api::event::EventSanitizeFields>(
                                &response.output,
                            )
                            .map_err(|error| {
                                nemo_relay::error::FlowError::Internal(format!(
                                    "a proxied sanitizer answered with something that is not \
                                     fields: {error}"
                                ))
                            })
                        }
                        Ok(other) => Err(nemo_relay::error::FlowError::Internal(format!(
                            "a proxied sanitizer answered with {}",
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
                    // not be sanitized is not published unsanitized.
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
                    Ok(fields) => Ok(fields),
                    Err(error) => {
                        // The chain clears the observability fields, which is the
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
        },
    );

    let installed = match class {
        PluginEventSanitizeClass::Mark => {
            nemo_relay::api::registry::register_mark_sanitize_guardrail(
                &registration.registration_id,
                priority,
                callable,
            )
        }
        PluginEventSanitizeClass::ScopeStart => {
            nemo_relay::api::registry::register_scope_sanitize_start_guardrail(
                &registration.registration_id,
                priority,
                callable,
            )
        }
        PluginEventSanitizeClass::ScopeEnd => {
            nemo_relay::api::registry::register_scope_sanitize_end_guardrail(
                &registration.registration_id,
                priority,
                callable,
            )
        }
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

/// The mark direction of [`install_event_sanitize`].
fn install_mark_sanitize(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    install_event_sanitize(
        context,
        registration,
        handle,
        PluginEventSanitizeClass::Mark,
    )
}

/// The scope-start direction of [`install_event_sanitize`].
fn install_scope_sanitize_start(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    install_event_sanitize(
        context,
        registration,
        handle,
        PluginEventSanitizeClass::ScopeStart,
    )
}

/// The scope-end direction of [`install_event_sanitize`].
fn install_scope_sanitize_end(
    context: &ProxyContext,
    registration: &PluginRegistrationDescriptor,
    handle: &PluginHandle,
) -> Result<(), PluginProtocolError> {
    install_event_sanitize(
        context,
        registration,
        handle,
        PluginEventSanitizeClass::ScopeEnd,
    )
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

    /// The frames a streaming invocation answers with, as the kernel reads them.
    ///
    /// The rule this pins is the one a terminal frame exists for: a stream is
    /// complete when the frame that says so arrives, and a host that stops after
    /// answering — or a session that broke — has said neither. Each case also
    /// checks the other half of the same rule: the chain position the kernel holds
    /// for the stream is given back when the stream ends, whichever way it ends.
    #[tokio::test]
    async fn a_stream_of_frames_that_stops_without_a_terminal_frame_is_a_failure() {
        use nemo_relay_plugin_protocol::{DispatchState, OutcomeCertainty, PluginStreamChunkKind};
        use tokio_stream::StreamExt;

        /// A chain position, and the registry holding it.
        fn hold_a_position() -> (
            crate::continuations::ContinuationGuard,
            Arc<crate::continuations::Continuations>,
        ) {
            let continuations = Arc::new(crate::continuations::Continuations::new());
            let held = continuations.hold_llm_stream(
                "operation-1",
                "registration-1",
                Arc::new(|_request| {
                    Box::pin(async move {
                        Ok(nemo_relay::api::runtime::LlmJsonStream::new(
                            tokio_stream::iter(Vec::<
                                Result<nemo_relay::json::Json, nemo_relay::error::FlowError>,
                            >::new()),
                        ))
                    })
                }),
            );
            (held, continuations)
        }

        let chunk = |kind: PluginStreamChunkKind| nemo_relay_plugin_protocol::PluginStreamChunk {
            operation_request_id: "operation-1".into(),
            chunk: kind,
            dispatch: DispatchState::DispatchAttempted,
            certainty: OutcomeCertainty::Unknown,
        };
        let data = |value: serde_json::Value| chunk(PluginStreamChunkKind::Data(value.to_string()));

        // A stream that answers and stops is not a stream that finished.
        let (held, position) = hold_a_position();
        let mut stopped = FramesAsChunks {
            operation_request_id: "operation-1".into(),
            frames: Box::pin(tokio_stream::iter(vec![Ok(data(
                serde_json::json!({"chunk": 1}),
            ))])),
            terminal: false,
            _held: held,
        };
        assert_eq!(
            stopped.next().await.expect("a chunk").expect("a chunk"),
            serde_json::json!({"chunk": 1})
        );
        let refused = stopped
            .next()
            .await
            .expect("the end of the frames is an answer")
            .expect_err("a stream that stopped without saying so is a failure");
        assert!(
            refused
                .to_string()
                .contains("without the frame that says it was over"),
            "the failure says what was missing: {refused}"
        );
        assert!(
            stopped.next().await.is_none(),
            "and then the stream is over, having said why"
        );
        drop(stopped);
        assert_eq!(
            position.in_flight(),
            0,
            "the position the stream held is given back when it stops"
        );

        // A stream that says it is over is one that finished.
        let (held, position) = hold_a_position();
        let mut finished = FramesAsChunks {
            operation_request_id: "operation-1".into(),
            frames: Box::pin(tokio_stream::iter(vec![
                Ok(data(serde_json::json!({"chunk": 1}))),
                Ok(chunk(PluginStreamChunkKind::End)),
            ])),
            terminal: false,
            _held: held,
        };
        assert!(finished.next().await.expect("a chunk").is_ok());
        assert!(
            finished.next().await.is_none(),
            "the terminal frame is what ends the caller's stream"
        );
        drop(finished);
        assert_eq!(position.in_flight(), 0, "and so is a stream that finished");

        // A stream that failed says why, once, and its end is the end.
        let (held, position) = hold_a_position();
        let mut failed = FramesAsChunks {
            operation_request_id: "operation-1".into(),
            frames: Box::pin(tokio_stream::iter(vec![Ok(chunk(
                PluginStreamChunkKind::Failed(nemo_relay_plugin_protocol::PluginFailure {
                    code: nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
                    message: "the provider fell over".into(),
                }),
            ))])),
            terminal: false,
            _held: held,
        };
        let failure = failed
            .next()
            .await
            .expect("an answer")
            .expect_err("a failed stream is a failure");
        assert!(failure.to_string().contains("fell over"), "{failure}");
        drop(failed);
        assert_eq!(position.in_flight(), 0, "and so is a stream that failed");

        // A session that broke mid-stream — the frames themselves failing — is a
        // failure rather than an end, and it is the last thing the caller hears.
        let (held, position) = hold_a_position();
        let mut broken = FramesAsChunks {
            operation_request_id: "operation-1".into(),
            frames: Box::pin(tokio_stream::iter(vec![
                Ok(data(serde_json::json!({"chunk": 1}))),
                Err(PluginProtocolError::new(
                    nemo_relay_plugin_protocol::PluginFailureCode::Unavailable,
                    "the host is gone",
                )),
            ])),
            terminal: false,
            _held: held,
        };
        assert!(broken.next().await.expect("a chunk").is_ok());
        let broken_failure = broken
            .next()
            .await
            .expect("an answer")
            .expect_err("a broken session is a failure");
        assert!(
            broken_failure.to_string().contains("the host is gone"),
            "{broken_failure}"
        );
        assert!(
            broken.next().await.is_none(),
            "and the stream is over with the failure rather than waiting for more"
        );
        drop(broken);
        assert_eq!(
            position.in_flight(),
            0,
            "and a broken stream gives it back too"
        );
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
        // A class with no proxy at all. Every class but this one has been given a proxy,
        // including the LLM request sanitizer whose codec capability protocol landed last —
        // so this names the last one whose shape the boundary does not carry yet, and it
        // will need a new example when that lands too.
        let error = install(
            context,
            &descriptor(PluginRegistrationOperation::LlmSanitizeResponseGuardrail),
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
                .contains("llm_sanitize_response_guardrail"),
            "{error:?}"
        );
    }
}
