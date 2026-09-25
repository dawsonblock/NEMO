// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The one activation path: what the CLI and every binding do to run plugins.
//!
//! There is a single lifecycle here on purpose. Four compositions that each
//! claimed a host, registered builtins, partitioned their plugins, activated
//! static components and rolled back after a failure would be four subtly
//! different activation semantics wearing one interface, and the differences
//! would show up as failures only one of them could reproduce. So the sequence
//! lives in one place, and the callers differ only in what they hand it: the
//! plugins to run, how a host is started, and what they want to check once the
//! process-hosted plugins are up.
//!
//! The invariant is the one a caller can rely on without knowing any of that:
//! `activate` returning `Ok` means every required component is live and owned by
//! the returned value, and `activate` returning `Err` means no partial
//! activation survives.
//!
//! What this owns today is the static configuration, the process-hosted native
//! plugins, the process-wide ownership and the rollback. Worker plugins are not
//! here yet: their lane needs a feature this crate does not carry, so a caller
//! that runs them — the CLI — keeps that half for now, and the next lane to move
//! is that one rather than a new one.

use std::sync::{Arc, Mutex};

use nemo_relay::plugin::dynamic::{
    DynamicPluginActivationSpec, DynamicPluginKind, NativePluginLoadSpec,
};
use nemo_relay::plugin::{
    ConfigDiagnostic, ConfigReport, PluginComponentSpec, PluginConfig, PluginError,
    PluginHostLease, acquire_plugin_host_lease, clear_plugin_configuration_for_host,
    ensure_builtin_plugins_registered, initialize_plugins_exact_for_host,
};
use nemo_relay_plugin_protocol::PluginProtocolError;

use crate::ProcessLoadedPlugins;
use crate::supervisor::PluginHostSupervisorConfig;

/// What an activation needs beyond the plugins themselves.
pub struct IsolationPolicy {
    /// How a host process for this activation is started.
    ///
    /// The caller builds this because it is the caller that knows where the host
    /// beside it is: a CLI looks beside its own executable, a Node addon resolves
    /// the one inside its platform package, and a deployment may name one
    /// outright. What the composition decides is when a host is started and what
    /// happens if it cannot be.
    pub supervisor: PluginHostSupervisorConfig,
    /// Longest one registration may take.
    ///
    /// A registration that has not answered in this long is one this runtime
    /// cannot wait for: the proxy gives up and the host is told, rather than
    /// letting a plugin's slowness become the runtime's.
    pub registration_cap_millis: u64,
    /// The budget and in-flight bound for work done beside a call.
    pub observability: crate::off_path::ObservabilityPolicy,
    /// A check the caller wants run once the process-hosted plugins are running.
    ///
    /// Run at that point rather than after `activate` returns, because it is the
    /// moment between "the artifact was approved" and "the activation committed"
    /// — a caller that wants to know the artifact it approved is still the
    /// artifact that is running has nowhere else to ask. A check that fails
    /// rolls the whole activation back like any other failure.
    pub after_native_startup: Option<Box<dyn FnOnce() -> Result<(), String> + Send>>,
}

impl IsolationPolicy {
    /// A policy that starts hosts the way this process's neighbours do.
    pub fn beside_this_executable(
        runtime_binding_digest: impl Into<String>,
        registration_cap_millis: u64,
        observability: crate::off_path::ObservabilityPolicy,
    ) -> Self {
        Self {
            supervisor: PluginHostSupervisorConfig::beside_this_executable(runtime_binding_digest),
            registration_cap_millis,
            observability,
            after_native_startup: None,
        }
    }
}

/// A failure that stopped an activation, or that an activation could not undo.
#[derive(Debug)]
pub enum PluginActivationError {
    /// A plugin error, carrying what it was about in its message.
    Plugin(PluginError),
    /// The process boundary refused something.
    Boundary(PluginProtocolError),
    /// Activation failed and its rollback could not be shown to be complete.
    ///
    /// The process-wide ownership was retained rather than released: a second
    /// activation in a process whose registrations may be half-removed would be
    /// registering into a state nobody can describe.
    Retained(String),
}

impl PluginActivationError {
    /// The plugin error this failure carries, when it is one.
    pub fn as_plugin_error(&self) -> Option<&PluginError> {
        match self {
            Self::Plugin(error) => Some(error),
            Self::Boundary(_) | Self::Retained(_) => None,
        }
    }
}

impl std::fmt::Display for PluginActivationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plugin(error) => write!(formatter, "{error}"),
            Self::Boundary(error) => write!(formatter, "{}", error.failure.message),
            Self::Retained(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for PluginActivationError {}

impl From<PluginError> for PluginActivationError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

impl From<PluginProtocolError> for PluginActivationError {
    fn from(error: PluginProtocolError) -> Self {
        Self::Boundary(error)
    }
}

/// One process's activated plugin configuration, and everything it owns.
///
/// Holding this holds the process-wide ownership and the host process the native
/// plugins run in. Clearing it — or dropping it — tears both down in the order
/// that keeps callbacks from outliving the code they came from.
#[must_use = "dropping the activation clears and unloads its plugins"]
pub struct ActivatedPluginRuntime {
    /// The process-wide right this activation claimed.
    ///
    /// Taken by `clear`, so a torn-down activation cannot release ownership
    /// twice, and retained (never taken) when rollback could not be shown
    /// complete.
    claim: Option<PluginHostLease>,
    /// The native plugins, held in a host process rather than in this one.
    native: Option<ProcessLoadedPlugins>,
    /// What activation reported about the configuration it activated.
    report: ConfigReport,
    /// Whether teardown has begun.
    active: bool,
}

impl ActivatedPluginRuntime {
    /// Activate everything the configuration and the dynamic plugins ask for.
    ///
    /// The order is the one this runtime has always had and the one its
    /// qualification pins: the configuration's own components register first,
    /// then the process-hosted native plugins start, then the workers. A native
    /// plugin that cannot be approved therefore fails *after* the static
    /// components have registered — and the activation is rolled back, so a
    /// caller sees the failure and a process with no half-registered plugin.
    pub async fn activate<I>(
        config: PluginConfig,
        dynamic_plugins: I,
        policy: IsolationPolicy,
    ) -> Result<Self, PluginActivationError>
    where
        I: IntoIterator<Item = DynamicPluginActivationSpec>,
    {
        let dynamic_plugins = dynamic_plugins.into_iter().collect::<Vec<_>>();
        validate_dynamic_plugin_specs(&dynamic_plugins)?;

        if let Some(plugin) = dynamic_plugins
            .iter()
            .find(|plugin| plugin.kind == DynamicPluginKind::Worker)
        {
            return Err(PluginActivationError::Plugin(PluginError::InvalidConfig(
                format!(
                    "worker dynamic plugin '{}' is not part of this composition yet: the worker \
                     lane is still the caller's",
                    plugin.plugin_id
                ),
            )));
        }

        let claim = acquire_plugin_host_lease()?;
        let owner_id = claim.owner_id();
        // Builtin registration is cached process-wide, and it has to complete
        // before a dynamic plugin can claim a reserved builtin kind and cache a
        // failed registration attempt under it for the rest of the process.
        if let Err(error) = ensure_builtin_plugins_registered() {
            drop(claim);
            return Err(PluginActivationError::Plugin(error));
        }

        let IsolationPolicy {
            supervisor,
            registration_cap_millis,
            observability,
            after_native_startup,
        } = policy;

        // What each lane gets is decided here rather than discovered later: a
        // native plugin's components run where its library is, and everything
        // else — the configuration's own components and the worker-backed
        // dynamic ones — runs here.
        let components = match native_components(&dynamic_plugins) {
            Ok(components) => components,
            Err(error) => {
                drop(claim);
                return Err(error);
            }
        };
        let native_specs = dynamic_plugins
            .iter()
            .filter(|plugin| plugin.kind == DynamicPluginKind::RustDynamic)
            .map(|plugin| (plugin.plugin_id.clone(), plugin.manifest_ref.clone()))
            .collect::<Vec<_>>();
        let mut config = config;
        config.components.extend(
            dynamic_plugins
                .iter()
                .filter(|plugin| plugin.kind != DynamicPluginKind::RustDynamic)
                .map(|plugin| PluginComponentSpec {
                    kind: plugin.plugin_id.clone(),
                    enabled: true,
                    config: plugin.config.clone(),
                }),
        );

        let rollback_failures = Arc::new(Mutex::new(Vec::new()));
        let mut stage = ActivationStage {
            claim,
            owner_id,
            native: None,
            rollback_failures: Arc::clone(&rollback_failures),
        };

        let attempt = Self::activate_stages(
            &mut stage,
            config,
            native_specs,
            components,
            supervisor,
            registration_cap_millis,
            observability,
            after_native_startup,
        )
        .await;
        match attempt {
            Ok(report) => Ok(Self {
                claim: Some(stage.claim),
                native: stage.native,
                report,
                active: true,
            }),
            Err(error) => Err(stage.rollback(error)),
        }
    }

    #[allow(clippy::too_many_arguments)] // One call site, and each argument is a decision.
    async fn activate_stages(
        stage: &mut ActivationStage,
        config: PluginConfig,
        native_specs: Vec<(String, String)>,
        components: Vec<nemo_relay_plugin_protocol::PluginComponentConfiguration>,
        supervisor: PluginHostSupervisorConfig,
        registration_cap_millis: u64,
        observability: crate::off_path::ObservabilityPolicy,
        after_native_startup: Option<Box<dyn FnOnce() -> Result<(), String> + Send>>,
    ) -> Result<ConfigReport, PluginActivationError> {
        let diagnostics: Vec<ConfigDiagnostic> = Vec::new();
        let report = initialize_plugins_exact_for_host(
            config,
            stage.owner_id,
            Arc::clone(&stage.rollback_failures),
            diagnostics,
        )
        .await
        .map_err(PluginActivationError::Plugin)?;

        if !native_specs.is_empty() {
            for (plugin_id, artifact) in &native_specs {
                // Approval happens before a process starts, so an artifact that
                // cannot be approved is a refusal rather than a host to clean up.
                NativePluginLoadSpec::approved(plugin_id, artifact).map_err(|error| {
                    PluginActivationError::Plugin(context("native plugin load failed", error))
                })?;
            }
            stage.native = Some(
                ProcessLoadedPlugins::load(
                    supervisor,
                    registration_cap_millis,
                    observability,
                    native_specs,
                    components,
                )
                .await
                .map_err(|error| {
                    PluginActivationError::Plugin(PluginError::RegistrationFailed(format!(
                        "native plugin load failed: {}",
                        error.failure.message
                    )))
                })?,
            );
        }
        if let Some(check) = after_native_startup
            && let Err(message) = check()
        {
            return Err(PluginActivationError::Plugin(
                PluginError::RegistrationFailed(format!("native plugin load failed: {message}")),
            ));
        }

        Ok(report)
    }

    /// What activation reported about the configuration it activated.
    pub fn report(&self) -> &ConfigReport {
        &self.report
    }

    /// The process-hosted plugins, when this activation has any.
    pub fn native(&self) -> Option<&ProcessLoadedPlugins> {
        self.native.as_ref()
    }

    /// The process id of the host running the native plugins, when there is one.
    ///
    /// Exposed because "the plugin ran in another process" is a thing a
    /// qualification has to assert rather than infer, and the process is the
    /// only place that fact lives.
    pub fn native_process_id(&self) -> Option<u32> {
        self.native
            .as_ref()
            .and_then(|native| native.backend().process_id())
    }

    /// Whether teardown has begun.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Remove every callback, then unload the code those callbacks came from.
    pub fn clear(mut self) -> Result<(), PluginActivationError> {
        self.clear_inner()
    }

    fn clear_inner(&mut self) -> Result<(), PluginActivationError> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        let Some(claim) = self.claim.as_ref() else {
            return Ok(());
        };
        let outcome = clear_plugin_configuration_for_host(claim.owner_id());
        let mut errors = outcome
            .result
            .err()
            .map(|error| vec![error.to_string()])
            .unwrap_or_default();
        if !outcome.callbacks_cleared {
            // Core could not prove it removed everything a plugin registered, so
            // this process must not hand its ownership to another activation. The
            // host process is still dropped: every callback the kernel holds is a
            // proxy in *this* process, and the code that answers them is the
            // host's — killing it cannot leave a dangling call here, and leaving
            // it running would be a process nobody owns.
            self.native.take();
            let retained = self.claim.take();
            std::mem::forget(retained);
            errors.push(
                "the plugin configuration could not be shown to be removed; this process's \
                 plugin ownership was retained rather than released"
                    .to_string(),
            );
            return Err(PluginActivationError::Retained(format!(
                "plugin teardown failed: {}",
                errors.join("; ")
            )));
        }

        // Callbacks are gone, so the code behind them can go too, and the
        // ownership is released last: a process that released it while its
        // teardown was still outstanding would let the next activation start
        // over a configuration that has not finished ending.
        self.native.take();
        self.claim.take();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(PluginActivationError::Retained(format!(
                "plugin teardown failed: {}",
                errors.join("; ")
            )))
        }
    }
}

impl Drop for ActivatedPluginRuntime {
    fn drop(&mut self) {
        // A drop that cannot clear has nothing left to say: core logs what its
        // own teardown could not do, and a second report from here would be the
        // same failure twice. What matters is that it does not panic, and that
        // the ownership is retained rather than released (see `clear_inner`).
        let _ = self.clear_inner();
    }
}

/// The pieces of an activation that exist while it is being built.
///
/// Separate from [`ActivatedPluginRuntime`] because a failure has to be able to
/// run the rollback over what exists *so far*, and a partially built value of
/// the finished type would be a value a caller could hold.
struct ActivationStage {
    claim: PluginHostLease,
    owner_id: u64,
    native: Option<ProcessLoadedPlugins>,
    rollback_failures: Arc<Mutex<Vec<String>>>,
}

impl ActivationStage {
    /// Undo what this activation did, in the order it did it.
    fn rollback(self, error: PluginActivationError) -> PluginActivationError {
        let outcome = clear_plugin_configuration_for_host(self.owner_id);
        let mut errors = outcome
            .result
            .err()
            .map(|error| vec![error.to_string()])
            .unwrap_or_default();
        // The host goes regardless of what clearing proved: its code is in
        // another process, so ending it cannot leave a call in this process
        // pointing at freed memory.
        drop(self.native);

        let incomplete = self
            .rollback_failures
            .lock()
            .map(|failures| failures.clone())
            .unwrap_or_else(|lock_error| {
                vec![format!("rollback failure lock poisoned: {lock_error}")]
            });
        if outcome.callbacks_cleared && incomplete.is_empty() {
            drop(self.claim);
            return error;
        }
        errors.extend(incomplete);
        std::mem::forget(self.claim);
        PluginActivationError::Retained(format!(
            "{}; activation rollback was incomplete: {}; this process's plugin ownership was \
             retained because callbacks may remain registered",
            error,
            if errors.is_empty() {
                "plugin teardown was incomplete".to_string()
            } else {
                errors.join("; ")
            }
        ))
    }
}

/// The component configurations that belong to the process that runs them.
fn native_components(
    dynamic_plugins: &[DynamicPluginActivationSpec],
) -> Result<Vec<nemo_relay_plugin_protocol::PluginComponentConfiguration>, PluginActivationError> {
    dynamic_plugins
        .iter()
        .filter(|plugin| plugin.kind == DynamicPluginKind::RustDynamic)
        .map(|plugin| {
            Ok(nemo_relay_plugin_protocol::PluginComponentConfiguration {
                kind: plugin.plugin_id.clone(),
                config_json: serde_json::to_string(&plugin.config).map_err(|error| {
                    PluginActivationError::Plugin(context(
                        "native plugin load failed",
                        PluginError::Internal(format!(
                            "native plugin '{}' has a configuration that cannot be serialized: \
                             {error}",
                            plugin.plugin_id
                        )),
                    ))
                })?,
            })
        })
        .collect()
}

fn validate_dynamic_plugin_specs(
    dynamic_plugins: &[DynamicPluginActivationSpec],
) -> Result<(), PluginActivationError> {
    if dynamic_plugins.is_empty() {
        return Err(PluginActivationError::Plugin(PluginError::InvalidConfig(
            concat!(
                "dynamic plugin activation requires at least one dynamic plugin; ",
                "use plugin initialization for a static-only configuration"
            )
            .into(),
        )));
    }
    let mut plugin_ids = std::collections::HashSet::with_capacity(dynamic_plugins.len());
    for plugin in dynamic_plugins {
        if !plugin_ids.insert(plugin.plugin_id.as_str()) {
            return Err(PluginActivationError::Plugin(PluginError::InvalidConfig(
                format!("duplicate dynamic plugin id '{}'", plugin.plugin_id),
            )));
        }
    }
    Ok(())
}

/// Add the context a failure is about, keeping the kind it carries.
///
/// The kind is kept because callers act on it: a binding maps a not-found
/// plugin and a conflicting one to different statuses, and an error whose kind
/// was flattened into a string would make them the same failure.
fn context(prefix: &str, error: PluginError) -> PluginError {
    match error {
        PluginError::InvalidConfig(message) => {
            PluginError::InvalidConfig(format!("{prefix}: {message}"))
        }
        PluginError::Conflict(message) => PluginError::Conflict(format!("{prefix}: {message}")),
        PluginError::NotFound(message) => PluginError::NotFound(format!("{prefix}: {message}")),
        PluginError::Serialization(error) => {
            PluginError::Internal(format!("{prefix}: serialization error: {error}"))
        }
        PluginError::Internal(message) => PluginError::Internal(format!("{prefix}: {message}")),
        PluginError::RegistrationFailed(message) => {
            PluginError::RegistrationFailed(format!("{prefix}: {message}"))
        }
        PluginError::ResourceExhausted { resource, limit } => {
            PluginError::ResourceExhausted { resource, limit }
        }
    }
}
