// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Plugin execution backends.
//!
//! This crate holds implementations of the kernel-owned
//! [`PluginExecutionBackend`] interface. It is deliberately *not* part of the
//! kernel: the kernel decides what may be asked of a plugin and under what
//! budget, while whoever composes the runtime decides how the plugin is reached
//! and injects that choice.
//!
//! Today there is one implementation, and it is a compatibility bridge rather
//! than a destination. [`InProcessPluginBackend`] calls the existing in-process
//! loader, which means the native plugin ABI still runs inside the kernel
//! address space and the milestone's `kernel-process unsafe tokens` metric does
//! not move. It exists so the seam can be built and conformance-tested before
//! anything is moved across a process boundary, and it is the implementation
//! that the process backend will replace.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::supervisor::{PluginHostSupervisorConfig, ProcessPluginBackend};
use nemo_relay::plugin::dynamic::{
    NativePluginActivation, NativePluginLoadSpec, load_native_plugins,
};
use nemo_relay::plugin::execution::{PluginExecutionBackend, PluginExecutionFuture, PluginManager};
use nemo_relay_plugin_protocol::{
    PROTOCOL_VERSION, PluginArtifactIdentity, PluginDescriptor, PluginExecutionContext,
    PluginFailure, PluginFailureCode, PluginHandle, PluginHostHealth, PluginInspectRequest,
    PluginLifecycle, PluginLoadRequest, PluginLoadResponse, PluginProtocolError,
    PluginRegistrationDescriptor, PluginRegistrationOrdering, PluginUnloadRequest,
    registration_shape,
};

/// What this host process was built from.
///
/// The release is this crate's, which is the crate the host binary is built
/// from, and the ABI revision is the one its loader carries. Both describe
/// *this* executable rather than the runtime that started it, which is what
/// makes reporting them worth anything: the runtime compares them against its
/// own expectation, so a host from another build fails the handshake instead of
/// serving a session nobody can account for.
pub fn host_build() -> nemo_relay_plugin_protocol::PluginHostBuild {
    nemo_relay_plugin_protocol::PluginHostBuild {
        release_version: env!("CARGO_PKG_VERSION").to_string(),
        native_abi_version: nemo_relay_plugin::NEMO_RELAY_NATIVE_ABI_VERSION,
    }
}

/// What the backend holds for one plugin identifier.
///
/// The `Loading` arm is a reservation, not a status report. Loading happens
/// without the lock held, so without a reservation a second request could pass
/// the "is it loaded?" check while the first is still working, and two requests
/// would map onto one result — the first caller's success reported to the
/// second, or two libraries loaded under one identifier.
enum Entry {
    /// A load is in progress; the identifier is claimed.
    Loading,
    /// The plugin is loaded.
    ///
    /// Boxed because a loaded plugin carries far more than the reservation
    /// marker, and the map holds many of them.
    Loaded(Box<LoadedPlugin>),
}

/// A plugin loaded through the in-process loader.
struct LoadedPlugin {
    handle: PluginHandle,
    /// What was true when the plugin was loaded, apart from its registrations.
    descriptor: PluginDescriptor,
    /// The live activation: read for its registrations, and held for its
    /// `Drop`.
    ///
    /// Dropping the activation deregisters the plugin kinds and unloads the
    /// library, so it has to live exactly as long as this entry does.
    activation: NativePluginActivation,
}

impl LoadedPlugin {
    /// Describe the loaded plugin, reading its registrations from the loader.
    ///
    /// Native registration is config-driven: the loader registers a plugin
    /// kind at load time, and the callbacks that install components arrive when
    /// the runtime initializes the plugin's configuration. A list frozen at
    /// load time would therefore report nothing for a plugin that has since
    /// registered everywhere, which is the opposite of a truthful description.
    fn describe(&self) -> PluginDescriptor {
        let mut descriptor = self.descriptor.clone();
        descriptor.registrations = registration_descriptors(&self.activation.loaded_plugins());
        descriptor
    }
}

/// Describe every registration the loader recorded, as the protocol wants it.
///
/// Nothing here is invented: the attachment point, the ordering the plugin
/// declared and the gate target are what the ABI callbacks carried, and the
/// shape is derived from the attachment point rather than reported separately
/// and allowed to disagree with it.
fn registration_descriptors(
    plugins: &[nemo_relay::plugin::dynamic::NativeLoadedPlugin],
) -> Vec<PluginRegistrationDescriptor> {
    let mut descriptors = Vec::new();
    for plugin in plugins {
        for registration in &plugin.registrations {
            descriptors.push(PluginRegistrationDescriptor {
                registration_id: registration.qualified_name.clone(),
                component_kind: plugin.plugin_kind.clone(),
                operation: registration.operation,
                ordering: PluginRegistrationOrdering {
                    priority: registration.priority,
                    may_break_chain: registration.may_break_chain,
                },
                shape: registration_shape(registration.operation),
                gated_registration: registration.gated_registration.clone(),
                // The native ABI declares no per-registration configuration
                // keys, so there is nothing to report rather than something
                // known to be empty.
                config_keys: Vec::new(),
                declared_digest: None,
            });
        }
    }
    descriptors
}

/// Executes plugins through the in-process native loader.
///
/// This is the compatibility implementation. It reaches the same loader the
/// kernel uses today, so behaviour is unchanged; what changes is that the kernel
/// no longer has to know which implementation it is talking to.
pub struct InProcessPluginBackend {
    loaded: Mutex<HashMap<String, Entry>>,
    generations: AtomicU64,
}

impl Default for InProcessPluginBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl InProcessPluginBackend {
    /// Create an empty backend.
    pub fn new() -> Self {
        Self {
            loaded: Mutex::new(HashMap::new()),
            generations: AtomicU64::new(1),
        }
    }

    fn loaded(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.loaded.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn descriptors(&self) -> Vec<PluginDescriptor> {
        let mut descriptors: Vec<PluginDescriptor> = self
            .loaded()
            .values()
            .filter_map(|entry| match entry {
                Entry::Loaded(loaded) => Some(loaded.describe()),
                Entry::Loading => None,
            })
            .collect();
        descriptors.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
        descriptors
    }

    fn handles(&self) -> Vec<PluginHandle> {
        let mut handles: Vec<PluginHandle> = self
            .loaded()
            .values()
            .filter_map(|entry| match entry {
                Entry::Loaded(loaded) => Some(loaded.handle.clone()),
                Entry::Loading => None,
            })
            .collect();
        handles.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
        handles
    }
}

fn refused(message: impl Into<String>) -> PluginProtocolError {
    PluginProtocolError {
        failure: PluginFailure {
            code: PluginFailureCode::Rejected,
            message: message.into(),
        },
    }
}

/// What this backend knows about one identifier, from the entry it holds.
///
/// The rules about what each state admits live in the contract, not here: a
/// backend that decided for itself which requests its own states allow would be
/// a second place for the lifecycle to be wrong, and the two sides of the
/// boundary have to refuse the same request with the same code.
fn lifecycle_of(entry: Option<&Entry>) -> PluginLifecycle {
    match entry {
        None => PluginLifecycle::Absent,
        Some(Entry::Loading) => PluginLifecycle::Loading,
        Some(Entry::Loaded(loaded)) => PluginLifecycle::Loaded {
            generation: loaded.handle.generation,
        },
    }
}

/// The refusal a state gives, with the detail only this side can supply.
///
/// The code comes from the contract's lifecycle and the text is built here, so
/// the two can describe the same fact in one place rather than at each call
/// site.
fn lifecycle_refusal(
    state: PluginLifecycle,
    plugin_id: &str,
    requested_generation: Option<u64>,
    code: PluginFailureCode,
) -> PluginProtocolError {
    let message = match &code {
        PluginFailureCode::UnknownPlugin => format!("plugin {plugin_id} is not loaded"),
        PluginFailureCode::AlreadyLoading => format!("plugin {plugin_id} is being loaded"),
        PluginFailureCode::AlreadyLoaded => format!("plugin {plugin_id} is already loaded"),
        PluginFailureCode::StaleHandle => format!(
            "plugin {plugin_id} is loaded at generation {}, not {}",
            state.generation().unwrap_or_default(),
            requested_generation.unwrap_or_default()
        ),
        other => format!("plugin {plugin_id} was refused as {other:?}"),
    };
    PluginProtocolError::new(code, message)
}

impl InProcessPluginBackend {
    /// Run one registration a loaded plugin made.
    ///
    /// The in-process backend exists for plugins that register into *this*
    /// process: their callbacks are already in the runtime's own registries, so
    /// there is no proxy to reach and nothing for this to forward to. It refuses
    /// rather than pretending, because an invocation that quietly did nothing
    /// would look like a registration that ran.
    pub async fn invoke_registration(
        &self,
        request: nemo_relay_plugin_protocol::PluginInvokeRequest,
        _context: PluginExecutionContext,
    ) -> Result<
        nemo_relay_plugin_protocol::PluginExecutionOutcome,
        nemo_relay_plugin_protocol::PluginProtocolError,
    > {
        Err(PluginProtocolError::new(
            PluginFailureCode::Rejected,
            format!(
                "plugin {} is hosted in this process; registration {} has no proxy to invoke",
                request.handle.plugin_id, request.registration_id
            ),
        ))
    }
}

impl PluginExecutionBackend for InProcessPluginBackend {
    fn load<'a>(
        &'a self,
        request: PluginLoadRequest,
        _context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, PluginLoadResponse> {
        Box::pin(async move {
            // Claim the identifier before doing any work. Releasing the lock
            // while the loader runs would otherwise let a concurrent request
            // see "not loaded" and start a second load of the same plugin.
            {
                let mut loaded = self.loaded();
                let state = lifecycle_of(loaded.get(&request.plugin_id));
                if let Err(code) = state.admit_load() {
                    return Err(lifecycle_refusal(state, &request.plugin_id, None, code));
                }
                loaded.insert(request.plugin_id.clone(), Entry::Loading);
            }

            // The approval travels with the load rather than being checked
            // separately: the loader confirms it against the bytes of an open
            // handle immediately before it opens the library, so the digest and
            // the file it describes are the same instance.
            let approved = request.identity.clone();
            let activation =
                match load_native_plugins([NativePluginLoadSpec::with_approved_identity(
                    request.plugin_id.clone(),
                    request.artifact.clone(),
                    approved.clone(),
                )]) {
                    Ok(activation) => activation,
                    Err(error) => {
                        // Release the reservation so a later attempt is possible.
                        self.loaded().remove(&request.plugin_id);
                        return Err(refused(error.to_string()));
                    }
                };

            // Checked rather than wrapping: a generation that silently reused a
            // number would let a stale handle address a newer instance, which
            // is the one thing the generation exists to prevent.
            let generation = self
                .generations
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| {
                    PluginProtocolError::new(
                        PluginFailureCode::GenerationExhausted,
                        "the plugin generation counter cannot advance",
                    )
                })?;

            // Only what the loader actually knows is reported. The earlier
            // version synthesised a Tool capability for every registered kind
            // and claimed the host's maximum ABI as the plugin's negotiated one,
            // which turned an unknown into a security-relevant assertion.
            let mut registration_kinds = Vec::new();
            let mut plugin_version = None;
            for plugin in activation.loaded_plugins() {
                registration_kinds.push(plugin.plugin_kind);
                plugin_version = plugin_version.or(plugin.declared_compat);
            }
            let descriptor = PluginDescriptor {
                plugin_id: request.plugin_id.clone(),
                plugin_version,
                negotiated_abi_version: None,
                // The digest this load verified, so the approved identity, the
                // verified identity and the reported one are the same value.
                manifest_digest: Some(approved.manifest_sha256.clone()),
                registration_kinds,
                // Whatever the loader has recorded so far. Empty at load time
                // is the truth rather than a gap: native registration is
                // config-driven, so a plugin's callbacks run when the runtime
                // initializes its components, and `describe` reads them again
                // then. Inventing descriptors here would be the same mistake as
                // the synthesised capabilities this replaced.
                registrations: registration_descriptors(&activation.loaded_plugins()),
                capabilities: Vec::new(),
            };
            let handle = PluginHandle {
                plugin_id: request.plugin_id.clone(),
                generation,
            };
            let mut loaded = self.loaded();
            loaded.insert(
                request.plugin_id.clone(),
                Entry::Loaded(Box::new(LoadedPlugin {
                    handle: handle.clone(),
                    descriptor: descriptor.clone(),
                    activation,
                })),
            );
            Ok(PluginLoadResponse { handle, descriptor })
        })
    }

    fn unload<'a>(
        &'a self,
        request: PluginUnloadRequest,
        _context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, ()> {
        Box::pin(async move {
            let mut loaded = self.loaded();
            let state = lifecycle_of(loaded.get(&request.handle.plugin_id));
            // A handle from before a reload must not be able to unload the
            // instance that replaced it, and the caller needs to know that is
            // what happened rather than that nothing was there.
            if let Err(code) = state.admit_generation(request.handle.generation) {
                return Err(lifecycle_refusal(
                    state,
                    &request.handle.plugin_id,
                    Some(request.handle.generation),
                    code,
                ));
            }
            // Dropping the entry drops the activation, which deregisters the
            // plugin kinds and unloads the library.
            loaded.remove(&request.handle.plugin_id);
            Ok(())
        })
    }

    fn inspect<'a>(
        &'a self,
        request: PluginInspectRequest,
        _context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, Vec<PluginDescriptor>> {
        Box::pin(async move {
            match request.handle {
                None => Ok(self.descriptors()),
                Some(handle) => {
                    let loaded = self.loaded();
                    let state = lifecycle_of(loaded.get(&handle.plugin_id));
                    match state.admit_generation(handle.generation) {
                        Err(code) => Err(lifecycle_refusal(
                            state,
                            &handle.plugin_id,
                            Some(handle.generation),
                            code,
                        )),
                        Ok(()) => Ok(vec![
                            loaded
                                .get(&handle.plugin_id)
                                .and_then(|entry| match entry {
                                    Entry::Loaded(loaded) => Some(loaded.describe()),
                                    Entry::Loading => None,
                                })
                                .expect("an admitted handle names a loaded instance"),
                        ]),
                    }
                }
            }
        })
    }

    fn invoke<'a>(
        &'a self,
        request: nemo_relay_plugin_protocol::PluginInvokeRequest,
        context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, nemo_relay_plugin_protocol::PluginExecutionOutcome> {
        Box::pin(async move { self.invoke_registration(request, context).await })
    }

    fn health<'a>(
        &'a self,
        _context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, PluginHostHealth> {
        Box::pin(async move {
            Ok(PluginHostHealth {
                protocol_version: PROTOCOL_VERSION,
                accepting_work: true,
                loaded: self.handles(),
            })
        })
    }
}

/// A second transport attached to a session the kernel established.
pub mod attached;
/// The capability a session's transports have to present.
pub mod capability;
pub mod codec_capability;
pub mod codec_context;
pub mod confidentiality;
pub mod conformance;
/// The continuations a kernel holds for the plugins that asked for them.
pub mod continuations;
/// The bounds a host process is started under.
pub mod limits;
/// Delivering this runtime's events to observers in another process.
pub mod observer;
/// The runtime that work beside a call runs on.
pub mod off_path;
/// Which scope stack each in-flight operation belongs to.
pub mod operation_scopes;
/// The kernel-side proxies for a plugin's registrations.
pub mod proxy;
/// The kernel's side of the boundary: the calls a running plugin makes back.
pub mod runtime_service;
/// The host's side of the boundary: the service the host process serves.
pub mod service;
/// The kernel's view of one plugin session: the invariants that need memory.
pub mod session;
/// The host's end of the duplex session channel.
pub mod session_channel;
/// The kernel's side of the duplex session channel.
pub mod session_driver;
/// The kernel's side of the process boundary: spawning, handshaking, and the
/// backend that reaches a host process.
pub mod supervisor;

/// Native plugins loaded through a backend, kept loaded for as long as this is held.
///
/// The direct loader returned an RAII guard whose `Drop` deregistered the plugin
/// kinds, and callers arranged teardown around that: sessions close, subscribers
/// flush, and only then does the guard drop, so a runtime callback cannot outlive
/// the code behind it. This preserves that shape while the loader itself moves
/// behind the backend — dropping this drops the backend, which drops the
/// activations it holds and deregisters their kinds at the same point.
pub struct LoadedPlugins {
    backend: Arc<InProcessPluginBackend>,
    handles: Vec<PluginHandle>,
}

/// Plugins loaded in a host process, with their registrations proxied here.
///
/// This is the composition a runtime selects when it wants native plugins out of
/// its own process. It does the four things that decision implies, in the order
/// the boundary requires: start a host and handshake with it; load each approved
/// artifact through the backend rather than through a loader here; activate the
/// components each plugin was loaded for, so its register callbacks run where its
/// library is; and install one proxy per registration the host reported, at the
/// priority the plugin declared.
///
/// It fails closed on a plugin whose registrations this kernel cannot serve: a
/// load that reported success while a callback disappeared would be worse than a
/// refused load, because the plugin would believe it had registered something the
/// runtime never calls.
///
/// Dropping this removes the proxies and kills the host, so a plugin's callbacks
/// cannot outlive the runtime that installed them.
pub struct ProcessLoadedPlugins {
    backend: Arc<ProcessPluginBackend>,
    /// Held so it outlives the proxies that submit to it.
    ///
    /// Read for one reason: the composition reports it, and a caller tearing the
    /// composition down should be able to see that off-path work is a resource
    /// this owns rather than a task nobody can stop.
    off_path: Arc<crate::off_path::OffPathPluginExecutor>,
    proxies: Vec<crate::proxy::RegistrationProxies>,
    handles: Vec<PluginHandle>,
}

impl ProcessLoadedPlugins {
    /// Load, activate and proxy every plugin in `specs`.
    ///
    /// `components` is what each loaded plugin should activate: in this runtime's
    /// plugin model a library load does not run a plugin's register callbacks, so
    /// the components the deployment asked for are what make them happen — in the
    /// host, where the library is.
    pub async fn load<I, J>(
        config: PluginHostSupervisorConfig,
        registration_cap_millis: u64,
        observability: crate::off_path::ObservabilityPolicy,
        specs: I,
        components: J,
    ) -> Result<Self, PluginProtocolError>
    where
        I: IntoIterator<Item = (String, String)>,
        J: IntoIterator<Item = nemo_relay_plugin_protocol::PluginComponentConfiguration>,
    {
        // A registration is never given more than the action it serves can
        // afford, and this is the second limit on top of that. Zero would mean
        // "no time at all", which nobody means, so it is refused rather than
        // treated as a default.
        observability.validate()?;
        if registration_cap_millis == 0 {
            return Err(refused(
                "a registration cap of zero milliseconds would refuse every invocation",
            ));
        }
        // What is about to be loaded is approved before anything is started: a
        // load that cannot happen — an artifact that is missing, or that is not
        // the approved one — is refused without a process to clean up, and the
        // refusal is the same one the loader would have given.
        let mut approved = Vec::new();
        for (plugin_id, artifact) in specs {
            let (manifest_sha256, library_sha256) =
                nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact).map_err(
                    |error| {
                        refused(format!(
                            "plugin '{plugin_id}' could not be approved: {error}"
                        ))
                    },
                )?;
            approved.push((
                plugin_id,
                artifact,
                PluginArtifactIdentity {
                    manifest_sha256,
                    library_sha256,
                },
            ));
        }
        let backend = Arc::new(ProcessPluginBackend::launch(config).await?);
        // The off-path runtime belongs to this composition and outlives every
        // proxy installed from it. It attaches a transport of its own, created on
        // that runtime: work done beside a call must be answerable by a thread the
        // caller is not holding, and by a connection whose tasks live where the
        // work runs.
        let off_path = Arc::new(
            crate::off_path::OffPathPluginExecutor::start(&observability)?
                .attach_to(backend.connection_descriptor()),
        );
        let binding = backend.runtime_binding_digest().to_owned();
        let manager = Arc::new(PluginManager::new(
            Arc::clone(&backend) as Arc<dyn PluginExecutionBackend>
        ));

        let mut handles = Vec::new();
        // The host confirms the identity it was given rather than deciding for
        // itself what a reference points at; the approval above is what it is
        // confirming.
        for (plugin_id, artifact, identity) in approved {
            let loaded = manager
                .load(
                    PluginLoadRequest {
                        plugin_id,
                        artifact,
                        identity,
                    },
                    lifecycle_context(&binding, "load"),
                )
                .await
                .map_err(|error| PluginProtocolError {
                    failure: PluginFailure {
                        code: error.failure.code,
                        message: error.failure.message,
                    },
                })?;
            handles.push(loaded.handle);
        }

        let components: Vec<_> = components.into_iter().collect();
        let descriptors = if components.is_empty() {
            Vec::new()
        } else {
            backend
                .activate(
                    nemo_relay_plugin_protocol::PluginActivateRequest {
                        components,
                        // A composition serves: it wants the classes it can proxy,
                        // and a plugin registering anything else is refused whole
                        // rather than half-served.
                        discovery: false,
                    },
                    lifecycle_context(&binding, "activate"),
                )
                .await?
        };

        // One proxy per registration, installable only for the classes this
        // backend can serve. The manager is the only path to the backend, and
        // the operation scopes are what attach a mark the plugin raises to the
        // call that raised it.
        let context = crate::proxy::ProxyContext::new(manager, binding, registration_cap_millis)
            .with_streaming_backend(Arc::clone(&backend))
            .with_operation_scopes(backend.operation_scopes())
            .with_continuations(backend.continuations())
            .with_observability_budget(observability.budget_millis)
            .with_off_path_executor(Arc::clone(&off_path))
            // The codec capabilities this session issues: the LLM sanitizers are given a
            // codec they cannot hold, so the record has to be the one the kernel's own
            // callback service checks.
            .with_codec_capabilities(backend.codec_capabilities());
        let mut proxies = Vec::new();
        for descriptor in &descriptors {
            let handle = handles
                .iter()
                .find(|handle| handle.plugin_id == descriptor.plugin_id)
                .cloned()
                .ok_or_else(|| {
                    refused(format!(
                        "the host activated {} without having loaded it",
                        descriptor.plugin_id
                    ))
                })?;
            proxies.push(crate::proxy::install(context.clone(), descriptor, handle)?);
        }

        Ok(Self {
            backend,
            proxies,
            handles,
            off_path,
        })
    }

    /// The identity of every loaded plugin.
    pub fn handles(&self) -> &[PluginHandle] {
        &self.handles
    }

    /// Whether nothing was loaded.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// The registrations currently proxied here.
    pub fn registrations(&self) -> Vec<&str> {
        self.proxies
            .iter()
            .flat_map(crate::proxy::RegistrationProxies::registration_ids)
            .collect()
    }

    /// The backend holding the loaded plugins.
    pub fn backend(&self) -> &Arc<ProcessPluginBackend> {
        &self.backend
    }

    /// The runtime work beside a call runs on.
    pub fn off_path(&self) -> &Arc<crate::off_path::OffPathPluginExecutor> {
        &self.off_path
    }
}

impl LoadedPlugins {
    /// Load every `(plugin id, artifact)` pair, or fail without leaving any loaded.
    pub async fn load<I>(specs: I) -> Result<Self, PluginProtocolError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let backend = Arc::new(InProcessPluginBackend::new());
        let manager = PluginManager::new(backend.clone());
        let mut handles = Vec::new();
        for (plugin_id, artifact) in specs {
            // The identity is approved here, before anything is loaded, so
            // whatever performs the load confirms what it was told to load
            // rather than deciding for itself what the reference points at.
            let (manifest_sha256, library_sha256) =
                nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact)
                    .map_err(|error| refused(error.to_string()))?;
            let loaded = manager
                .load(
                    PluginLoadRequest {
                        plugin_id,
                        artifact,
                        identity: PluginArtifactIdentity {
                            manifest_sha256,
                            library_sha256,
                        },
                    },
                    context_with_live_deadline(),
                )
                .await?;
            handles.push(loaded.handle);
        }
        Ok(Self { backend, handles })
    }

    /// Return whether nothing was loaded.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Return the identity of every loaded plugin.
    pub fn handles(&self) -> &[PluginHandle] {
        &self.handles
    }

    /// Return the backend holding the loaded plugins.
    pub fn backend(&self) -> &Arc<InProcessPluginBackend> {
        &self.backend
    }
}

/// A bounded context for one lifecycle operation of a session.
///
/// Bounded rather than open-ended, and bound to the session's own runtime digest:
/// the host refuses an operation that claims a runtime it was not started for, so
/// a placeholder digest here would make every load fail rather than making it
/// lenient.
fn lifecycle_context(runtime_binding_digest: &str, operation: &str) -> PluginExecutionContext {
    PluginExecutionContext {
        operation_request_id: format!(
            "{operation}-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ),
        protocol_version: PROTOCOL_VERSION,
        runtime_binding_digest: runtime_binding_digest.to_owned(),
        deadline_unix_ms: nemo_relay::api::runtime::budget_now_unix_ms().saturating_add(30_000),
        remaining_budget_millis: 30_000,
        max_response_bytes: 1024,
    }
}

fn context_with_live_deadline() -> PluginExecutionContext {
    PluginExecutionContext {
        operation_request_id: "in-process-load".into(),
        protocol_version: PROTOCOL_VERSION,
        runtime_binding_digest: "in-process".into(),
        deadline_unix_ms: u64::MAX,
        remaining_budget_millis: 29_000,
        max_response_bytes: 1024,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_in_process_backend_satisfies_the_backend_conformance_suite() {
        let findings = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build a current-thread runtime")
            .block_on(conformance::check(&InProcessPluginBackend::new()));

        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn a_failed_load_releases_its_reservation() {
        // The identifier is claimed before the loader runs, so a failure has to
        // give the claim back. A reservation that outlived its load would wedge
        // the plugin permanently: every later attempt would report
        // `AlreadyLoading` for something that is not loading and never will be.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build a current-thread runtime");
        let backend = InProcessPluginBackend::new();
        let context = PluginExecutionContext {
            operation_request_id: "load".into(),
            protocol_version: PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            deadline_unix_ms: u64::MAX,
            remaining_budget_millis: 29_000,
            max_response_bytes: 1024,
        };

        for attempt in 0..2 {
            let failure = runtime
                .block_on(backend.load(
                    PluginLoadRequest {
                        plugin_id: "absent-plugin".into(),
                        artifact: "/nonexistent/relay-plugin.toml".into(),
                        identity: PluginArtifactIdentity {
                            manifest_sha256: "unused-for-this-attempt".into(),
                            library_sha256: "unused-for-this-attempt".into(),
                        },
                    },
                    context.clone(),
                ))
                .expect_err("a manifest that does not exist cannot load");
            assert_eq!(
                failure.failure.code,
                PluginFailureCode::Rejected,
                "attempt {attempt} must fail on the manifest, not on a stale reservation"
            );
        }

        assert!(backend.handles().is_empty());
    }

    #[test]
    fn a_recorded_registration_becomes_a_descriptor_that_says_where_it_attaches() {
        use nemo_relay::api::registry::RuntimeRegistrationKind;
        use nemo_relay::plugin::dynamic::{NativeLoadedPlugin, NativePluginRegistration};
        use nemo_relay_plugin_protocol::{PluginExecutionShape, PluginRegistrationOperation};

        let plugins = vec![NativeLoadedPlugin {
            plugin_kind: "fixture_native".into(),
            declared_compat: Some("=0.9.1".into()),
            registrations: vec![
                NativePluginRegistration {
                    operation: RuntimeRegistrationKind::ToolRequestIntercept,
                    local_name: "rewrite_args".into(),
                    qualified_name: "nemo-relay-plugin.v1.fixture_native:1:rewrite_args".into(),
                    priority: Some(5),
                    may_break_chain: Some(true),
                    gated_registration: None,
                },
                NativePluginRegistration {
                    operation: RuntimeRegistrationKind::Subscriber,
                    local_name: "events".into(),
                    qualified_name: "nemo-relay-plugin.v1.fixture_native:1:events".into(),
                    // A subscriber carries no priority and no chain answer, and
                    // the descriptor has to say so rather than say zero.
                    priority: None,
                    may_break_chain: None,
                    gated_registration: Some("other-plugin:1:events".into()),
                },
            ],
        }];

        let descriptors = registration_descriptors(&plugins);

        assert_eq!(descriptors.len(), 2);
        assert_eq!(
            descriptors[0].operation,
            PluginRegistrationOperation::ToolRequestIntercept
        );
        assert_eq!(descriptors[0].component_kind, "fixture_native");
        assert_eq!(
            descriptors[0].registration_id,
            "nemo-relay-plugin.v1.fixture_native:1:rewrite_args"
        );
        assert_eq!(descriptors[0].shape, PluginExecutionShape::Unary);
        assert_eq!(descriptors[0].ordering.priority, Some(5));
        assert_eq!(descriptors[0].ordering.may_break_chain, Some(true));
        assert_eq!(descriptors[0].gated_registration, None);

        assert_eq!(
            descriptors[1].operation,
            PluginRegistrationOperation::Subscriber
        );
        assert_eq!(descriptors[1].ordering.priority, None);
        assert_eq!(descriptors[1].ordering.may_break_chain, None);
        assert_eq!(
            descriptors[1].gated_registration.as_deref(),
            Some("other-plugin:1:events")
        );
    }
}
