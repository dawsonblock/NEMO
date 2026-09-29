// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The kernel's side of the native plugin boundary: supervision and composition.
//!
//! This crate starts a host process, hands it approved artifacts, serves the
//! registrations it reports through proxies in this process, and owns the session
//! between them. What it does *not* do is load a library: the child's own end of
//! the protocol lives in `nemo-relay-native-loader`, which this crate does not
//! depend on, and the architecture test is what keeps that true.
//!
//! The modules it does carry are the ones both ends share — capabilities, codec
//! handles, continuations, operation scopes, the runtime service — plus the
//! supervisor's own.

pub mod activation;
pub mod attached;
pub mod capability;
pub mod codec_capability;
pub mod codec_context;
pub mod continuations;
pub mod host_location;
pub mod isolation_policy;
pub mod limits;
pub mod observer;
pub mod off_path;
pub mod operation_context;
pub mod operation_scopes;
pub mod proxy;
pub mod runtime_service;
pub mod session;
pub mod session_channel;
pub mod session_driver;
pub mod supervisor;

use std::sync::Arc;

use nemo_relay::plugin::execution::{PluginExecutionBackend, PluginManager};
use nemo_relay_plugin_protocol::{
    PluginArtifactIdentity, PluginFailure, PluginHandle, PluginLoadRequest, PluginProtocolError,
};

use crate::operation_context::{lifecycle_context, refused};
use crate::supervisor::{PluginHostSupervisorConfig, ProcessPluginBackend};

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
