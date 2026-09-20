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

use nemo_relay::plugin::dynamic::{
    NativePluginActivation, NativePluginLoadSpec, load_native_plugins,
};
use nemo_relay::plugin::execution::{PluginExecutionBackend, PluginExecutionFuture, PluginManager};
use nemo_relay_plugin_protocol::{
    PROTOCOL_VERSION, PluginArtifactIdentity, PluginDescriptor, PluginExecutionContext,
    PluginFailure, PluginFailureCode, PluginHandle, PluginHostHealth, PluginInspectRequest,
    PluginLoadRequest, PluginLoadResponse, PluginProtocolError, PluginRegistrationDescriptor,
    PluginRegistrationOrdering, PluginUnloadRequest, registration_shape,
};

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
                match loaded.get(&request.plugin_id) {
                    Some(Entry::Loading) => {
                        return Err(PluginProtocolError::new(
                            PluginFailureCode::AlreadyLoading,
                            format!("plugin {} is being loaded", request.plugin_id),
                        ));
                    }
                    Some(Entry::Loaded(_)) => {
                        return Err(PluginProtocolError::new(
                            PluginFailureCode::AlreadyLoaded,
                            format!("plugin {} is already loaded", request.plugin_id),
                        ));
                    }
                    None => {
                        loaded.insert(request.plugin_id.clone(), Entry::Loading);
                    }
                }
            }

            let activation = match load_native_plugins([NativePluginLoadSpec {
                plugin_id: request.plugin_id.clone(),
                manifest_ref: request.artifact,
            }]) {
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
                manifest_digest: None,
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
            match loaded.get(&request.handle.plugin_id) {
                Some(Entry::Loading) => {
                    return Err(PluginProtocolError::new(
                        PluginFailureCode::AlreadyLoading,
                        format!("plugin {} is being loaded", request.handle.plugin_id),
                    ));
                }
                Some(Entry::Loaded(entry)) => {
                    if entry.handle.generation != request.handle.generation {
                        // The plugin exists, but this handle is from before a
                        // reload. It must not be able to unload the instance
                        // that replaced it, and the caller needs to know that is
                        // what happened rather than that nothing was there.
                        return Err(PluginProtocolError::new(
                            PluginFailureCode::StaleHandle,
                            format!(
                                "plugin {} is loaded at generation {}, not {}",
                                request.handle.plugin_id,
                                entry.handle.generation,
                                request.handle.generation
                            ),
                        ));
                    }
                }
                None => {
                    return Err(PluginProtocolError::new(
                        PluginFailureCode::UnknownPlugin,
                        format!("plugin {} is not loaded", request.handle.plugin_id),
                    ));
                }
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
                Some(handle) => match self.loaded().get(&handle.plugin_id) {
                    Some(Entry::Loaded(entry)) if entry.handle.generation == handle.generation => {
                        Ok(vec![entry.describe()])
                    }
                    Some(Entry::Loaded(entry)) => Err(PluginProtocolError::new(
                        PluginFailureCode::StaleHandle,
                        format!(
                            "plugin {} is loaded at generation {}, not {}",
                            handle.plugin_id, entry.handle.generation, handle.generation
                        ),
                    )),
                    Some(Entry::Loading) => Err(PluginProtocolError::new(
                        PluginFailureCode::AlreadyLoading,
                        format!("plugin {} is being loaded", handle.plugin_id),
                    )),
                    None => Err(PluginProtocolError::new(
                        PluginFailureCode::UnknownPlugin,
                        format!("plugin {} is not loaded", handle.plugin_id),
                    )),
                },
            }
        })
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

pub mod conformance;

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
