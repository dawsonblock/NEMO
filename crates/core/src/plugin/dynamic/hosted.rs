// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What a hosted plugin is allowed to ask this runtime to do.
//!
//! A native plugin's code runs in a host process, but the runtime it participates
//! in is this one: it owns the plugin registry, the invocation a callback belongs
//! to, the marks that invocation emits, and the decision about whether an
//! artifact is the one that was approved. [`NativeHostRuntime`] is that
//! participation, named as operations rather than as the state those operations
//! happen to touch.
//!
//! The distinction is the point. The loader needs to *install* a registration,
//! not to call `register_plugin_tracked`; it needs to know *which window a mark
//! belongs to*, not to read a task-local; it needs *the digest of these bytes*,
//! not the hashing helper the kernel happens to share. Naming the operations here
//! keeps the decision about locks, leases, continuation contexts, event
//! identities and staging policy on this side, where it can change without the
//! loader learning that it changed.
//!
//! The four responsibilities the operations divide into are deliberately not four
//! traits. Registration ownership, invocation context, artifact verification and
//! compatibility validation answer different questions, but a hosted plugin
//! runtime answers all of them, and splitting the handle would only make callers
//! hold more of it. What matters is that every operation is semantic and that the
//! set is closed: an operation may not be added here to publish an internal, and
//! `crates/core/tests/integration/native_seam_tests.rs` records which kernel items
//! the loader used to reach, what each one maps to, and fails if the loader names
//! one of them — or any other module-level kernel item that is not `pub` — again.

use std::fs::File;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::api::runtime::MiddlewareContinuationContext;
use crate::api::scope::EmitMarkEventParams;
use crate::error::Result as FlowResult;
use crate::plugin::execution::{ForwardedMark, MarkForwarder};
use crate::plugin::{
    Plugin, PluginRegistrationContext, Result, RuntimeDiagnosticsSnapshotEntry,
    active_runtime_diagnostics_snapshot, deregister_plugin_registration_checked,
    register_plugin_tracked,
};

use super::{
    deregister_tracked_registrations_checked, validate_annotated_request_consumer_compatibility,
    validate_dynamic_plugin_relay_compatibility,
};

/// The identity a registration was given when it was installed.
///
/// A registration is addressed by this rather than by its kind alone, so a
/// teardown that finds a *different* registration under the same name can say so
/// instead of removing somebody else's plugin.
pub type RegistrationId = u64;

/// What happened when one registration was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationRemoval {
    /// The registration was there and is gone.
    Removed,
    /// Nothing was registered under that name.
    Missing,
    /// A different registration holds that name now, and was left alone.
    Replaced,
}

/// How a set of registrations came apart during teardown.
///
/// The errors are the reason a teardown is not simply a loop over removals:
/// whatever failed has to reach the caller, and whether the artifact may be
/// unloaded is a separate question from whether every removal succeeded — a
/// registration that was replaced rather than removed is an error, but the one
/// that owns the name now is not this teardown's to unload.
#[derive(Debug, Default)]
pub struct RegistrationTeardown {
    errors: Vec<String>,
    safe_to_unload: bool,
}

impl RegistrationTeardown {
    /// A teardown that removed everything and may unload.
    ///
    /// The kernel starts one before every teardown it runs, and a host that
    /// composes more than one lane starts one to fold them into.
    #[must_use]
    pub fn success() -> Self {
        Self {
            errors: Vec::new(),
            safe_to_unload: true,
        }
    }

    /// Record one failure, and whether the artifact may still be unloaded.
    pub(crate) fn record_error(&mut self, error: impl Into<String>, safe_to_unload: bool) {
        self.errors.push(error.into());
        self.safe_to_unload &= safe_to_unload;
    }

    /// Fold another teardown's result into this one.
    pub fn merge(&mut self, other: Self) {
        self.errors.extend(other.errors);
        self.safe_to_unload &= other.safe_to_unload;
    }

    /// Every failure this teardown recorded, in the order it met them.
    #[must_use]
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// Whether the artifact that contributed these registrations may be unloaded.
    #[must_use]
    pub fn safe_to_unload(&self) -> bool {
        self.safe_to_unload
    }
}

/// A hosted plugin runtime's participation, as the code hosting one uses it.
///
/// The handle carries nothing: it names the operations, and an implementation
/// that needs state for them keeps that state where the state already is. A
/// handle rather than free functions because that is the shape the boundary
/// needs — a host process asks *this* runtime, and when more than one
/// implementation exists the handle is the single place the choice lives.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeHostRuntime;

impl NativeHostRuntime {
    /// The runtime of the process this code is running in.
    pub const fn new() -> Self {
        Self
    }

    // --- registration ownership ---------------------------------------------

    /// Install a plugin implementation under the name it reports.
    ///
    /// The returned identity is what a later removal is checked against, so a
    /// plugin cannot be unloaded out from under a successor that took its name.
    pub fn install_plugin(&self, plugin: Arc<dyn Plugin>) -> Result<RegistrationId> {
        register_plugin_tracked(plugin)
    }

    /// Whether this runtime qualifies a registration's component names in its namespace.
    ///
    /// A registration context decides how the names it registers are written; the
    /// hosted side asks rather than assuming, because a runtime that qualifies and
    /// one that does not must agree on the same name.
    #[must_use]
    pub fn qualifies_component_names(&self, context: &PluginRegistrationContext) -> bool {
        context.uses_plugin_component_namespace()
    }

    /// Encode one component-name field the way a qualified name is written.
    #[must_use]
    pub fn qualify_component_field(&self, field: &str) -> String {
        crate::plugin::encode_plugin_component_field(field)
    }

    /// Remove one registration, if it is still the registration it names.
    pub fn remove_plugin(
        &self,
        plugin_kind: &str,
        registration_id: RegistrationId,
    ) -> Result<RegistrationRemoval> {
        deregister_plugin_registration_checked(plugin_kind, registration_id).map(|outcome| {
            match outcome {
                crate::plugin::PluginDeregistrationOutcome::Removed => RegistrationRemoval::Removed,
                crate::plugin::PluginDeregistrationOutcome::Missing => RegistrationRemoval::Missing,
                crate::plugin::PluginDeregistrationOutcome::Replaced => {
                    RegistrationRemoval::Replaced
                }
            }
        })
    }

    /// Remove every registration a tracked set names, newest first.
    ///
    /// The set is consumed rather than read, because a teardown that ran twice
    /// would otherwise report the second removal as a failure instead of
    /// treating the first as the one that happened.
    pub fn tear_down(
        &self,
        tracked: &mut Vec<(String, RegistrationId)>,
        lane: &str,
    ) -> RegistrationTeardown {
        deregister_tracked_registrations_checked(tracked, lane)
    }

    /// Run a mutation that owns this runtime's plugin registry.
    ///
    /// Registration is cancellation-resistant: the work runs on the process-wide
    /// plugin lifecycle executor rather than on whichever thread asked, so a
    /// caller that stops waiting cannot leave a half-registered plugin behind.
    pub async fn run_owned_mutation<T, F, Fut>(&self, label: &'static str, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        crate::plugin::run_owned_plugin_mutation(label, work).await
    }

    // --- invocation context --------------------------------------------------

    /// The mark window the calling invocation is running under, when there is one.
    ///
    /// A callback that returns a stream keeps this: the work outlives the call,
    /// and a mark raised while polling belongs to the operation whose callback
    /// raised it rather than to whatever thread is polling.
    #[must_use]
    pub fn capture_mark_window(&self) -> Option<Arc<dyn MarkForwarder>> {
        crate::plugin::execution::current_mark_forwarder()
    }

    /// Turn mark parameters into the shape a host forwards.
    pub fn forward_mark(
        &self,
        params: &EmitMarkEventParams<'_>,
    ) -> crate::error::Result<ForwardedMark> {
        crate::api::scope::forwarded_mark(params)
    }

    /// Isolate a continuation context against the invocation that is calling it.
    ///
    /// A continuation is a fresh branch of the operation: concurrent retries and
    /// fan-outs must not share one scope stack, so the branch gets its own
    /// snapshot of what is visible from here rather than the context the callback
    /// began with.
    pub fn isolate_invocation(
        &self,
        context: &MiddlewareContinuationContext,
    ) -> FlowResult<MiddlewareContinuationContext> {
        context.isolated_for_current_invocation()
    }

    /// The runtime's own failure records, as a plugin is allowed to see them.
    #[must_use]
    pub fn runtime_diagnostics(&self) -> Vec<RuntimeDiagnosticsSnapshotEntry> {
        active_runtime_diagnostics_snapshot()
    }

    // --- artifact verification -----------------------------------------------

    /// The digest that names a byte string.
    #[must_use]
    pub fn hash_bytes(&self, bytes: &[u8]) -> String {
        super::artifact::sha256_hex(bytes)
    }

    /// The digest that names the bytes an open handle yields.
    ///
    /// A handle rather than a path, so the digest describes the instance that
    /// will be loaded rather than a name that could be repointed between the two.
    pub fn hash_open_file(&self, file: &mut File) -> Result<String> {
        super::artifact::sha256_of_reader(file)
    }

    /// The digest that names the file at a path.
    pub fn hash_path(&self, path: &Path) -> Result<String> {
        super::artifact::sha256_of_path(path)
    }

    /// Refuse a file whose bytes do not hash to `expected`.
    pub fn verify_path(&self, path: &Path, expected: &str) -> Result<()> {
        super::artifact::verify_sha256(path, expected)
    }

    /// Resolve a manifest-relative library reference.
    #[must_use]
    pub fn resolve_manifest_relative(&self, manifest: &Path, reference: &str) -> PathBuf {
        super::artifact::resolve_manifest_relative_path(manifest, reference)
    }

    // --- compatibility validation --------------------------------------------

    /// Refuse a plugin whose declared Relay compatibility excludes this release.
    pub fn validate_relay_compatibility(&self, relay: Option<&str>, lane: &str) -> Result<()> {
        validate_dynamic_plugin_relay_compatibility(relay, lane)
    }

    /// Refuse a request-intercepting plugin that claims a range Relay 0.5 serves.
    ///
    /// An annotated request is a shape the 0.5 line does not produce, so a plugin
    /// that says it can consume one cannot be claiming to work there.
    pub fn validate_request_consumer_compatibility(&self, relay: &str, lane: &str) -> Result<()> {
        validate_annotated_request_consumer_compatibility(relay, lane)
    }
}
