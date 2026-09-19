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
use std::sync::{Mutex, PoisonError};

use nemo_relay::plugin::dynamic::{
    NativePluginActivation, NativePluginLoadSpec, load_native_plugins,
};
use nemo_relay::plugin::execution::{PluginExecutionBackend, PluginExecutionFuture};
use nemo_relay_plugin::NEMO_RELAY_NATIVE_ABI_VERSION;
use nemo_relay_plugin_protocol::{
    PROTOCOL_VERSION, PluginDescriptor, PluginExecutionContext, PluginFailure, PluginFailureCode,
    PluginHandle, PluginHostHealth, PluginInspectRequest, PluginLoadRequest, PluginProtocolError,
    PluginUnloadRequest,
};

/// A plugin loaded through the in-process loader.
///
/// The activation is held rather than dropped because it is the lifetime guard
/// for the loaded library: dropping it deregisters the plugin kinds and unloads
/// the code, so it has to live exactly as long as the handle does.
struct LoadedPlugin {
    handle: PluginHandle,
    descriptor: PluginDescriptor,
    /// Held for its `Drop` and never read.
    ///
    /// Dropping the activation deregisters the plugin kinds and unloads the
    /// library, so it has to live exactly as long as this entry does. The
    /// underscore says the field is kept for that effect rather than because
    /// anything looks at it.
    _activation: NativePluginActivation,
}

/// Executes plugins through the in-process native loader.
///
/// This is the compatibility implementation. It reaches the same loader the
/// kernel uses today, so behaviour is unchanged; what changes is that the kernel
/// no longer has to know which implementation it is talking to.
pub struct InProcessPluginBackend {
    loaded: Mutex<HashMap<String, LoadedPlugin>>,
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

    fn loaded(&self) -> std::sync::MutexGuard<'_, HashMap<String, LoadedPlugin>> {
        self.loaded.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn descriptors(&self) -> Vec<PluginDescriptor> {
        let mut descriptors: Vec<PluginDescriptor> = self
            .loaded()
            .values()
            .map(|loaded| loaded.descriptor.clone())
            .collect();
        descriptors.sort_by(|left, right| left.name.cmp(&right.name));
        descriptors
    }

    fn handles(&self) -> Vec<PluginHandle> {
        let mut handles: Vec<PluginHandle> = self
            .loaded()
            .values()
            .map(|loaded| loaded.handle.clone())
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
    ) -> PluginExecutionFuture<'a, PluginDescriptor> {
        Box::pin(async move {
            if self.loaded().contains_key(&request.plugin_id) {
                return Err(refused(format!(
                    "plugin {} is already loaded",
                    request.plugin_id
                )));
            }
            let activation = load_native_plugins([NativePluginLoadSpec {
                plugin_id: request.plugin_id.clone(),
                manifest_ref: request.artifact,
            }])
            .map_err(|error| refused(error.to_string()))?;

            let generation = self.generations.fetch_add(1, Ordering::SeqCst);
            let descriptor = PluginDescriptor {
                name: request.plugin_id.clone(),
                abi_version: u16::try_from(NEMO_RELAY_NATIVE_ABI_VERSION).unwrap_or(u16::MAX),
                capabilities: activation
                    .plugin_kinds()
                    .into_iter()
                    .map(|plugin_kind| nemo_relay_plugin_protocol::PluginCapability {
                        id: plugin_kind,
                        kind: nemo_relay_plugin_protocol::PluginCapabilityKind::Tool,
                        declared_digest: String::new(),
                    })
                    .collect(),
            };
            self.loaded().insert(
                request.plugin_id.clone(),
                LoadedPlugin {
                    handle: PluginHandle {
                        plugin_id: request.plugin_id,
                        generation,
                    },
                    descriptor: descriptor.clone(),
                    _activation: activation,
                },
            );
            Ok(descriptor)
        })
    }

    fn unload<'a>(
        &'a self,
        request: PluginUnloadRequest,
        _context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, ()> {
        Box::pin(async move {
            let mut loaded = self.loaded();
            let matches = loaded
                .get(&request.handle.plugin_id)
                .is_some_and(|entry| entry.handle.generation == request.handle.generation);
            if !matches {
                // A handle whose generation does not match addresses nothing:
                // either the plugin was never loaded or it was unloaded and
                // reloaded since, and neither may unload the current instance.
                return Err(PluginProtocolError {
                    failure: PluginFailure {
                        code: PluginFailureCode::UnknownPlugin,
                        message: format!(
                            "no loaded plugin {} at generation {}",
                            request.handle.plugin_id, request.handle.generation
                        ),
                    },
                });
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
                Some(handle) => self
                    .loaded()
                    .get(&handle.plugin_id)
                    .filter(|entry| entry.handle.generation == handle.generation)
                    .map(|entry| vec![entry.descriptor.clone()])
                    .ok_or_else(|| PluginProtocolError {
                        failure: PluginFailure {
                            code: PluginFailureCode::UnknownPlugin,
                            message: format!(
                                "no loaded plugin {} at generation {}",
                                handle.plugin_id, handle.generation
                            ),
                        },
                    }),
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
}
