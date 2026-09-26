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
//! What this owns is every lane: the static configuration, the process-hosted
//! native plugins, the worker plugins when this build carries that lane, the
//! process-wide ownership, and the rollback. A caller adds the parts only it can
//! know — where a host is, and what it wants checked once the native plugins are
//! up — and nothing else.

use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::BoxFuture;
use nemo_relay::plugin::dynamic::{
    DynamicPluginActivationSpec, DynamicPluginKind, NativePluginLoadSpec,
};
#[cfg(feature = "worker-grpc")]
use nemo_relay::plugin::dynamic::{
    WorkerPluginActivation, WorkerPluginLoadSpec, load_worker_plugins,
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
    /// Longest one registration may take when nothing says otherwise.
    ///
    /// A registration that has not answered in this long is one this runtime
    /// cannot wait for: the proxy gives up and the host is told, rather than
    /// letting a plugin's slowness become the runtime's.
    pub const REGISTRATION_CAP_MILLIS: u64 = 5_000;

    /// How many off-path plugin operations may be in flight at once.
    ///
    /// Stated rather than left to whatever the machine can hold, because the
    /// point of the bound is that a plugin cannot choose it.
    pub const OFF_PATH_IN_FLIGHT: usize = 64;

    /// The policy a runtime gets when it has no reason to choose otherwise.
    ///
    /// The cap and the bound are the project's own numbers, stated once here so
    /// that four consumers cannot state four — the same drift this module exists
    /// to remove. The caller says which implementation it is, because that is
    /// the part only the caller knows.
    pub fn for_runtime(implementation: &str) -> Self {
        let cap = Self::REGISTRATION_CAP_MILLIS;
        Self {
            supervisor: PluginHostSupervisorConfig::beside_this_executable(
                crate::supervisor::plugin_runtime_binding(implementation),
            ),
            registration_cap_millis: cap,
            observability: crate::off_path::ObservabilityPolicy {
                budget_millis: cap,
                max_in_flight: Self::OFF_PATH_IN_FLIGHT,
            },
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
    /// The worker plugins, held for the same reason in the other direction: a
    /// worker's code is its own process, and its adapter is this one's.
    #[cfg(feature = "worker-grpc")]
    worker: Option<WorkerPluginActivation>,
    /// What activation reported about the configuration it activated.
    report: ConfigReport,
    /// Whether teardown has begun.
    active: bool,
}

impl ActivatedPluginRuntime {
    /// Activate after layering `config` over the discovered plugin files.
    ///
    /// This is the entry a binding uses: it was handed a configuration by
    /// whoever embedded it, and the deployment's own `plugins.toml` files are
    /// underneath it. Resolving here rather than in each binding is what keeps
    /// "which configuration is active" one answer instead of four.
    pub async fn activate_with_discovered_config<I>(
        config: PluginConfig,
        dynamic_plugins: I,
        policy: IsolationPolicy,
    ) -> Result<Self, PluginActivationError>
    where
        I: IntoIterator<Item = DynamicPluginActivationSpec>,
    {
        let dynamic_plugins = dynamic_plugins.into_iter().collect::<Vec<_>>();
        // Asked before discovery, which is the order the bindings have always
        // had: a call with nothing to activate is refused before a malformed
        // discovered file can turn it into a different failure, and before any
        // ownership is claimed.
        validate_dynamic_plugin_specs(&dynamic_plugins)?;
        let resolved = nemo_relay::plugin::resolve_plugin_config(config)
            .map_err(PluginActivationError::Plugin)?;
        Self::activate_resolved(resolved, dynamic_plugins, policy).await
    }

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
        Self::activate_resolved(
            nemo_relay::plugin::ResolvedPluginConfig {
                config,
                diagnostics: Vec::new(),
            },
            dynamic_plugins,
            policy,
        )
        .await
    }

    /// Activate a configuration that has already been resolved.
    async fn activate_resolved<I>(
        resolved: nemo_relay::plugin::ResolvedPluginConfig,
        dynamic_plugins: I,
        policy: IsolationPolicy,
    ) -> Result<Self, PluginActivationError>
    where
        I: IntoIterator<Item = DynamicPluginActivationSpec>,
    {
        let dynamic_plugins = dynamic_plugins.into_iter().collect::<Vec<_>>();
        // The transaction runs on an executor of its own rather than on the
        // caller's task. An activation claims process-wide ownership, registers
        // components and starts processes; a caller that stops waiting halfway
        // through must not be able to leave that half-applied, and cancellation
        // is a caller's decision rather than the runtime's. The task runs to
        // completion — commit or rollback — and a caller that went away simply
        // never receives the handle, whose drop then tears the result down.
        run_owned(
            async move { Self::activate_transaction(resolved, dynamic_plugins, policy).await },
        )
        .await
    }

    async fn activate_transaction(
        resolved: nemo_relay::plugin::ResolvedPluginConfig,
        dynamic_plugins: Vec<DynamicPluginActivationSpec>,
        policy: IsolationPolicy,
    ) -> Result<Self, PluginActivationError> {
        let nemo_relay::plugin::ResolvedPluginConfig {
            config,
            diagnostics,
        } = resolved;
        validate_dynamic_plugin_specs(&dynamic_plugins)?;

        #[cfg(not(feature = "worker-grpc"))]
        if let Some(plugin) = dynamic_plugins
            .iter()
            .find(|plugin| plugin.kind == DynamicPluginKind::Worker)
        {
            return Err(PluginActivationError::Plugin(PluginError::InvalidConfig(
                format!(
                    "worker dynamic plugin '{}' requires a build with the 'worker-grpc' feature",
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
        // The components the configuration did not name: every dynamic plugin
        // whose code this process runs. They are activated with the
        // configuration, and only after the lane that registers them has been
        // loaded — a worker's component cannot be activated before the worker
        // that answers for it exists.
        let dynamic_components = dynamic_plugins
            .iter()
            .filter(|plugin| plugin.kind != DynamicPluginKind::RustDynamic)
            .map(|plugin| PluginComponentSpec {
                kind: plugin.plugin_id.clone(),
                enabled: true,
                config: plugin.config.clone(),
            })
            .collect::<Vec<_>>();

        let rollback_failures = Arc::new(Mutex::new(Vec::new()));
        #[cfg(feature = "worker-grpc")]
        let worker_specs = dynamic_plugins
            .iter()
            .filter(|plugin| plugin.kind == DynamicPluginKind::Worker)
            .map(|plugin| WorkerPluginLoadSpec {
                plugin_id: plugin.plugin_id.clone(),
                manifest_ref: plugin.manifest_ref.clone(),
                environment_ref: plugin.environment_ref.clone(),
                config: plugin.config.clone(),
            })
            .collect::<Vec<_>>();
        let mut stage = ActivationStage {
            claim,
            owner_id,
            native: None,
            #[cfg(feature = "worker-grpc")]
            worker: None,
            rollback_failures: Arc::clone(&rollback_failures),
        };

        let attempt = Self::activate_stages(
            &mut stage,
            config,
            native_specs,
            components,
            dynamic_components,
            diagnostics,
            #[cfg(feature = "worker-grpc")]
            worker_specs,
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
                #[cfg(feature = "worker-grpc")]
                worker: stage.worker,
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
        dynamic_components: Vec<PluginComponentSpec>,
        diagnostics: Vec<ConfigDiagnostic>,
        #[cfg(feature = "worker-grpc")] worker_specs: Vec<WorkerPluginLoadSpec>,
        supervisor: PluginHostSupervisorConfig,
        registration_cap_millis: u64,
        observability: crate::off_path::ObservabilityPolicy,
        after_native_startup: Option<Box<dyn FnOnce() -> Result<(), String> + Send>>,
    ) -> Result<ConfigReport, PluginActivationError> {
        // The configuration's own components register first, and they are cleared
        // again before the final activation. That is not bookkeeping: a native
        // artifact that cannot be approved must fail *after* they registered —
        // the order this runtime has always had, and the one its qualification
        // pins — while a worker's component can only be activated once the worker
        // that registers its kind has been loaded. So the first activation is
        // what the deployment configured, and the last is that plus every dynamic
        // component this process runs.
        // Only when a lane's component has to be activated is the configuration
        // activated a second time: a worker's kind does not exist until the
        // worker is loaded, so its component cannot be in the first activation.
        // The cost is that the deployment's own register callbacks run again in
        // that case — the sequence this runtime has always had for a dynamic
        // activation, kept rather than changed here. An additive activation that
        // adds components without re-registering the configured ones is the way
        // to remove that cost, and it is a change to the kernel's activation API
        // rather than to this composition.
        let needs_second_activation = !dynamic_components.is_empty();
        // Discovery's diagnostics belong to whichever activation ends up active:
        // reporting them twice, or reporting them for an activation that was
        // replaced, would describe a configuration that is not the running one.
        let (first_diagnostics, second_diagnostics) = if needs_second_activation {
            (Vec::new(), diagnostics)
        } else {
            (diagnostics, Vec::new())
        };
        let report = initialize_plugins_exact_for_host(
            config.clone(),
            stage.owner_id,
            Arc::clone(&stage.rollback_failures),
            first_diagnostics,
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
                    PluginActivationError::Plugin(context(
                        "native plugin load failed",
                        plugin_error_from_boundary(error),
                    ))
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

        #[cfg(feature = "worker-grpc")]
        if !worker_specs.is_empty() {
            stage.worker = Some(load_worker_plugins(worker_specs).map_err(|error| {
                PluginActivationError::Plugin(context("worker plugin load failed", error))
            })?);
        }

        if !needs_second_activation {
            return Ok(report);
        }
        let mut full_config = config;
        full_config.components.extend(dynamic_components);
        initialize_plugins_exact_for_host(
            full_config,
            stage.owner_id,
            Arc::clone(&stage.rollback_failures),
            second_diagnostics,
        )
        .await
        .map_err(PluginActivationError::Plugin)
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
            #[cfg(feature = "worker-grpc")]
            self.worker.take();
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
        #[cfg(feature = "worker-grpc")]
        self.worker.take();
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
    #[cfg(feature = "worker-grpc")]
    worker: Option<WorkerPluginActivation>,
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
        // The host and the workers go regardless of what clearing proved: their
        // code is in their own processes, so ending them cannot leave a call in
        // this process pointing at freed memory.
        drop(self.native);
        #[cfg(feature = "worker-grpc")]
        drop(self.worker);

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

/// How many activation transactions may be waiting to run.
///
/// One runs at a time — the process-wide ownership allows nothing else — so this
/// is a queue of callers rather than of work, and a caller that has to wait
/// behind four others is a caller that should be told so instead of growing a
/// queue nobody chose.
const ACTIVATION_QUEUE_CAPACITY: usize = 4;

/// The executor activation transactions run on.
static ACTIVATION_EXECUTOR: OnceLock<
    Result<tokio::sync::mpsc::Sender<BoxFuture<'static, ()>>, String>,
> = OnceLock::new();

/// Run one activation transaction on an executor the caller cannot cancel.
async fn run_owned<F>(operation: F) -> Result<ActivatedPluginRuntime, PluginActivationError>
where
    F: std::future::Future<Output = Result<ActivatedPluginRuntime, PluginActivationError>>
        + Send
        + 'static,
{
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let job: BoxFuture<'static, ()> = Box::pin(async move {
        let _ = result_tx.send(operation.await);
    });
    activation_executor()?
        .try_send(job)
        .map_err(|error| match error {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                PluginActivationError::Plugin(PluginError::ResourceExhausted {
                    resource: "plugin.activation_queue",
                    limit: ACTIVATION_QUEUE_CAPACITY,
                })
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => PluginActivationError::Plugin(
                PluginError::Internal("the plugin activation executor stopped".to_string()),
            ),
        })?;
    match result_rx.await {
        Ok(result) => result,
        Err(_) => Err(PluginActivationError::Plugin(PluginError::Internal(
            "the plugin activation task stopped before returning a result".to_string(),
        ))),
    }
}

/// The executor, started on first use and kept for the life of the process.
///
/// A runtime of its own rather than whichever one the caller happens to be on: a
/// caller's runtime can be dropped, and a transaction that must finish cannot
/// live on a runtime that may not. Current-thread because transactions are one
/// at a time — the ownership sees to that — and because a second lane would only
/// let two of them race for the same claim.
fn activation_executor()
-> Result<&'static tokio::sync::mpsc::Sender<BoxFuture<'static, ()>>, PluginActivationError> {
    let executor = ACTIVATION_EXECUTOR.get_or_init(|| {
        let (sender, mut receiver) =
            tokio::sync::mpsc::channel::<BoxFuture<'static, ()>>(ACTIVATION_QUEUE_CAPACITY);
        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("nemo-relay-plugin-activation".to_string())
            .spawn(move || {
                // One worker rather than a current-thread runtime: the lanes a
                // transaction starts may spawn onto the runtime that is driving
                // them, and a runtime that cannot accept a spawn from another
                // thread turns that into a refusal the caller never asked for.
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name("nemo-plugin-activation-worker")
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = startup_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                let _ = startup_tx.send(Ok(()));
                runtime.block_on(async move {
                    while let Some(job) = receiver.recv().await {
                        job.await;
                    }
                });
            })
            .map_err(|error| format!("failed to start the plugin activation executor: {error}"))?;
        startup_rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|error| format!("the plugin activation executor did not start: {error}"))?
            .map(|()| sender)
    });
    match executor {
        Ok(sender) => Ok(sender),
        Err(error) => Err(PluginActivationError::Plugin(PluginError::Internal(
            error.clone(),
        ))),
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

/// The plugin error a boundary refusal corresponds to.
///
/// A refusal that arrives from the host is as specific as the one the kernel
/// would have produced in process, and the kind is the part a caller acts on: a
/// binding that cannot tell "the plugin was rejected" from "the host crashed"
/// reports both as the same failure, and a caller loses the half it could have
/// fixed. Anything with no closer equivalent stays a registration failure, which
/// is what "this activation did not happen" means.
fn plugin_error_from_boundary(
    error: nemo_relay_plugin_protocol::PluginProtocolError,
) -> PluginError {
    use nemo_relay_plugin_protocol::PluginFailureCode;

    let message = error.failure.message;
    match error.failure.code {
        PluginFailureCode::Rejected | PluginFailureCode::MalformedResponse => {
            PluginError::InvalidConfig(message)
        }
        PluginFailureCode::UnknownPlugin | PluginFailureCode::Unavailable => {
            PluginError::NotFound(message)
        }
        PluginFailureCode::AlreadyLoading
        | PluginFailureCode::AlreadyLoaded
        | PluginFailureCode::StaleHandle
        | PluginFailureCode::GenerationExhausted => PluginError::Conflict(message),
        _ => PluginError::RegistrationFailed(message),
    }
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
