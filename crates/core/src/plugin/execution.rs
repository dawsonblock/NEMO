// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The kernel-owned seam for plugin execution.
//!
//! The kernel decides *what* may be asked of a plugin and under what budget.
//! It does not decide *how* the plugin is reached: that belongs to whoever
//! composes the runtime, which supplies an implementation of
//! [`PluginExecutionBackend`]. The distinction is what makes it possible to
//! move native plugin loading out of the kernel process later without the
//! kernel noticing, because every operation already arrives as a request with a
//! correlation identifier, a deadline, and a response budget.
//!
//! Two properties here are deliberate and load-bearing.
//!
//! The interface is asynchronous. A process backend necessarily involves IPC and
//! deadlines, and a synchronous interface shaped around the current in-process
//! loader would have to be redesigned the moment that boundary appears.
//!
//! Nothing here names a transport. No sockets, pipes, child processes, encodings,
//! or file descriptors appear in this module, because those are implementation
//! choices of whichever backend is composed.
//!
//! There is no global backend. A process-wide singleton would hide the
//! composition decision, make tests order-dependent, and detach the backend from
//! the runtime identity it is supposed to serve.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use nemo_relay_plugin_protocol::{
    DispatchState, OutcomeCertainty, PluginDescriptor, PluginExecutionContext,
    PluginExecutionOutcome, PluginFailureCode, PluginHostHealth, PluginInspectRequest,
    PluginInvokeRequest, PluginLoadRequest, PluginLoadResponse, PluginProtocolError, PluginSuccess,
    PluginUnloadRequest, check_execution_context,
};

/// A plugin operation in progress.
///
/// Boxed and pinned because the backend is held behind a trait object: the
/// implementation is chosen at composition time, so the kernel cannot know its
/// future type.
pub type PluginExecutionFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, PluginProtocolError>> + Send + 'a>>;

/// Operations the kernel may ask of a plugin host.
///
/// The operations are lifecycle operations, deliberately. What a loaded plugin
/// *does* — intercepting an LLM call, observing an event, sanitizing a payload —
/// is dispatched through the runtime's own component machinery once the plugin
/// has registered, so the seam does not need to describe it. A process host that
/// must serve those calls needs a further operation, which arrives with the host
/// rather than being guessed at here.
pub trait PluginExecutionBackend: Send + Sync {
    /// Load one plugin and return what it declares about itself.
    fn load<'a>(
        &'a self,
        request: PluginLoadRequest,
        context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, PluginLoadResponse>;

    /// Unload a plugin, releasing whatever the implementation holds for it.
    fn unload<'a>(
        &'a self,
        request: PluginUnloadRequest,
        context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, ()>;

    /// Describe a loaded plugin, or every loaded plugin when no handle is given.
    fn inspect<'a>(
        &'a self,
        request: PluginInspectRequest,
        context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, Vec<PluginDescriptor>>;

    /// Report whether the backend is currently accepting work.
    fn health<'a>(
        &'a self,
        context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, PluginHostHealth>;

    /// Run one registration a loaded plugin made.
    ///
    /// This is what a kernel calls when its own chain reaches a proxy: the
    /// backend is responsible for reaching the registration and for reporting
    /// what is known about the outcome, including whether the plugin may have
    /// reached an external system before the answer was lost.
    ///
    /// A backend whose plugins register into the caller's own process does not
    /// proxy anything, and says so rather than pretending to invoke.
    fn invoke<'a>(
        &'a self,
        request: PluginInvokeRequest,
        context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, PluginExecutionOutcome>;
}

/// Owner of plugin execution, holding whichever backend was composed.
///
/// The manager exists so the deadline rule has one home. Every operation checks
/// the context's deadline before the backend is reached, which is what makes
/// "an operation that is already out of time is never started" true for every
/// backend rather than being a rule each implementation has to remember.
pub struct PluginManager {
    backend: Arc<dyn PluginExecutionBackend>,
    /// Request identities currently in flight.
    ///
    /// Only concurrent identities are tracked, so this stays bounded by the
    /// number of outstanding operations. Two live operations sharing one
    /// identity would make their responses ambiguous, and a caller could not
    /// tell which result answered which request.
    in_flight: Mutex<HashSet<String>>,
}

impl PluginManager {
    /// Compose a manager around a backend.
    pub fn new(backend: Arc<dyn PluginExecutionBackend>) -> Self {
        Self {
            backend,
            in_flight: Mutex::new(HashSet::new()),
        }
    }

    /// Return the backend this manager dispatches to.
    pub fn backend(&self) -> &Arc<dyn PluginExecutionBackend> {
        &self.backend
    }

    fn in_flight(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Check every invariant that holds for all backends, then claim the
    /// request identity.
    ///
    /// A backend is not asked to remember these. If it were, each new backend
    /// would have to re-derive the same rules, and the ones it forgot would be
    /// the ones nobody tested.
    fn begin(&self, context: &PluginExecutionContext) -> Result<InFlight<'_>, PluginProtocolError> {
        // The same validator the host runs, so the two sides cannot drift into
        // enforcing different contracts: whatever the kernel refuses here, the
        // host refuses there.
        check_execution_context(context, "", now_unix_ms())?;
        let mut in_flight = self.in_flight();
        if !in_flight.insert(context.operation_request_id.clone()) {
            return Err(PluginProtocolError::new(
                PluginFailureCode::Rejected,
                "an operation with this request identity is already in flight",
            ));
        }
        drop(in_flight);
        Ok(InFlight {
            manager: self,
            request_id: context.operation_request_id.clone(),
        })
    }

    /// Load one plugin.
    pub async fn load(
        &self,
        request: PluginLoadRequest,
        context: PluginExecutionContext,
    ) -> Result<PluginLoadResponse, PluginProtocolError> {
        let _in_flight = self.begin(&context)?;
        self.backend.load(request, context).await
    }

    /// Unload a plugin.
    pub async fn unload(
        &self,
        request: PluginUnloadRequest,
        context: PluginExecutionContext,
    ) -> Result<(), PluginProtocolError> {
        let _in_flight = self.begin(&context)?;
        self.backend.unload(request, context).await
    }

    /// Describe loaded plugins.
    pub async fn inspect(
        &self,
        request: PluginInspectRequest,
        context: PluginExecutionContext,
    ) -> Result<Vec<PluginDescriptor>, PluginProtocolError> {
        let _in_flight = self.begin(&context)?;
        self.backend.inspect(request, context).await
    }

    /// Run one registration a loaded plugin made.
    ///
    /// The same central controls every lifecycle operation receives: the
    /// operation is validated against the session's contract, its identity is
    /// reserved so two live operations cannot share one, and the backend is
    /// reached only through here. That is what makes a kernel-side proxy a
    /// caller of the manager rather than a second path into the boundary.
    pub async fn invoke(
        &self,
        request: PluginInvokeRequest,
        context: PluginExecutionContext,
    ) -> Result<PluginExecutionOutcome, PluginProtocolError> {
        let _in_flight = self.begin(&context)?;
        self.backend.invoke(request, context).await
    }

    /// Report backend health.
    pub async fn health(
        &self,
        context: PluginExecutionContext,
    ) -> Result<PluginHostHealth, PluginProtocolError> {
        let _in_flight = self.begin(&context)?;
        self.backend.health(context).await
    }
}

/// An in-flight request identity, released when the operation ends.
///
/// A guard rather than an explicit removal so an early return, an error, or a
/// panic cannot leave the identity claimed and make every later operation with
/// the same identifier look like a duplicate.
struct InFlight<'a> {
    manager: &'a PluginManager,
    request_id: String,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.manager.in_flight().remove(&self.request_id);
    }
}

/// Failure for an operation the composed backend does not implement.
pub fn unsupported(operation: &str) -> PluginProtocolError {
    PluginProtocolError::new(
        PluginFailureCode::Unavailable,
        format!("the composed plugin backend does not implement {operation}"),
    )
}

/// Bind a plugin result to what the caller knows about dispatch.
///
/// A plugin failure is not by itself a definite outcome. A caller that turns one
/// into an effect state has to say whether the plugin may have reached an
/// external system, and this is the shape that carries the answer rather than
/// leaving it to be assumed.
pub fn outcome_from(
    result: Result<PluginSuccess, PluginProtocolError>,
    dispatch: DispatchState,
    certainty: OutcomeCertainty,
) -> PluginExecutionOutcome {
    PluginExecutionOutcome {
        dispatch,
        certainty,
        result: result.map_err(|error| error.failure),
    }
}

/// Wall-clock milliseconds, for comparing against an absolute deadline.
///
/// A clock before the epoch reports zero rather than failing: every deadline
/// then looks passed, which is the fail-closed reading.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay_plugin_protocol::{
        PluginCapability, PluginExecutionContext, PluginFailureCode, PluginHandle,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A backend that records whether it was reached.
    struct RecordingBackend {
        calls: AtomicUsize,
    }

    impl RecordingBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
            })
        }
    }

    impl PluginExecutionBackend for RecordingBackend {
        fn invoke<'a>(
            &'a self,
            _request: PluginInvokeRequest,
            _context: PluginExecutionContext,
        ) -> PluginExecutionFuture<'a, PluginExecutionOutcome> {
            Box::pin(async move {
                Err(PluginProtocolError::new(
                    PluginFailureCode::Rejected,
                    "the recording backend serves no invocations",
                ))
            })
        }

        fn load<'a>(
            &'a self,
            request: PluginLoadRequest,
            _context: PluginExecutionContext,
        ) -> PluginExecutionFuture<'a, PluginLoadResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(PluginLoadResponse {
                    handle: PluginHandle {
                        plugin_id: request.plugin_id.clone(),
                        generation: 1,
                    },
                    descriptor: PluginDescriptor {
                        plugin_id: request.plugin_id,
                        plugin_version: None,
                        negotiated_abi_version: Some(1),
                        manifest_digest: None,
                        registration_kinds: Vec::new(),
                        registrations: Vec::new(),
                        capabilities: Vec::<PluginCapability>::new(),
                    },
                })
            })
        }

        fn unload<'a>(
            &'a self,
            _request: PluginUnloadRequest,
            _context: PluginExecutionContext,
        ) -> PluginExecutionFuture<'a, ()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(()) })
        }

        fn inspect<'a>(
            &'a self,
            _request: PluginInspectRequest,
            _context: PluginExecutionContext,
        ) -> PluginExecutionFuture<'a, Vec<PluginDescriptor>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn health<'a>(
            &'a self,
            _context: PluginExecutionContext,
        ) -> PluginExecutionFuture<'a, PluginHostHealth> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(PluginHostHealth {
                    protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
                    accepting_work: true,
                    loaded: Vec::<PluginHandle>::new(),
                })
            })
        }
    }

    fn test_identity() -> nemo_relay_plugin_protocol::PluginArtifactIdentity {
        nemo_relay_plugin_protocol::PluginArtifactIdentity {
            manifest_sha256: "manifest".into(),
            library_sha256: "library".into(),
        }
    }

    fn context(deadline_unix_ms: u64) -> PluginExecutionContext {
        PluginExecutionContext {
            operation_request_id: "operation-1".into(),
            remaining_budget_millis: 29_000,
            protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            deadline_unix_ms,
            max_response_bytes: 1024,
        }
    }

    #[tokio::test]
    async fn the_manager_rejects_contexts_every_backend_would_have_to_check() {
        // These rules live here so a new backend cannot forget them. Each case
        // asserts the specific failure rather than that something failed.
        let backend = RecordingBackend::new();
        let manager = PluginManager::new(backend.clone());
        let load = |_context: PluginExecutionContext| PluginLoadRequest {
            plugin_id: "example".into(),
            artifact: "relay-plugin.toml".into(),
            identity: test_identity(),
        };

        let mut wrong_version = context(live_deadline());
        wrong_version.protocol_version = nemo_relay_plugin_protocol::PROTOCOL_VERSION + 1;
        let failure = manager
            .load(load(wrong_version.clone()), wrong_version)
            .await
            .expect_err("a version the kernel does not speak must be refused");
        assert!(matches!(
            failure.failure.code,
            PluginFailureCode::VersionMismatch { .. }
        ));

        let mut no_binding = context(live_deadline());
        no_binding.runtime_binding_digest = "  ".into();
        let failure = manager
            .load(load(no_binding.clone()), no_binding)
            .await
            .expect_err("a blank runtime binding is not a binding");
        assert_eq!(failure.failure.code, PluginFailureCode::Rejected);

        let mut oversized = context(live_deadline());
        oversized.max_response_bytes = nemo_relay_plugin_protocol::MAX_FRAME_BYTES + 1;
        let failure = manager
            .load(load(oversized.clone()), oversized)
            .await
            .expect_err("a response budget above the frame limit is not honour-able");
        assert!(matches!(
            failure.failure.code,
            PluginFailureCode::OversizedFrame { .. }
        ));

        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            0,
            "none of these may reach the backend"
        );
    }

    #[tokio::test]
    async fn a_released_request_identity_can_be_reused() {
        // Unique among *concurrent* operations, not forever: a caller that
        // retries with the same identity after a completed operation is not
        // making an ambiguous request.
        let backend = RecordingBackend::new();
        let manager = PluginManager::new(backend.clone());
        let load = PluginLoadRequest {
            plugin_id: "example".into(),
            artifact: "relay-plugin.toml".into(),
            identity: test_identity(),
        };

        for _ in 0..2 {
            manager
                .load(load.clone(), context(live_deadline()))
                .await
                .expect("a live context loads");
        }

        assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
    }

    fn expired_deadline() -> u64 {
        1
    }

    fn live_deadline() -> u64 {
        u64::MAX
    }

    #[tokio::test]
    async fn the_manager_reaches_the_backend_it_was_given() {
        let backend = RecordingBackend::new();
        let manager = PluginManager::new(backend.clone());

        manager
            .load(
                PluginLoadRequest {
                    plugin_id: "example".into(),
                    artifact: "relay-plugin.toml".into(),
                    identity: test_identity(),
                },
                context(live_deadline()),
            )
            .await
            .expect("load");

        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_expired_deadline_is_refused_before_the_backend_is_reached() {
        // The acceptance gate: nothing is dispatched to a plugin that is already
        // out of time, so a backend cannot report work it should never have
        // started.
        let backend = RecordingBackend::new();
        let manager = PluginManager::new(backend.clone());

        let failure = manager
            .load(
                PluginLoadRequest {
                    plugin_id: "example".into(),
                    artifact: "relay-plugin.toml".into(),
                    identity: test_identity(),
                },
                context(expired_deadline()),
            )
            .await
            .expect_err("an expired deadline must be refused");

        assert_eq!(failure.failure.code, PluginFailureCode::DeadlineExceeded);
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            0,
            "the backend must not be reached at all"
        );
    }

    #[tokio::test]
    async fn health_is_refused_on_the_same_terms_as_load() {
        let backend = RecordingBackend::new();
        let manager = PluginManager::new(backend.clone());

        assert!(manager.health(context(expired_deadline())).await.is_err());
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_manager_does_not_own_a_process_wide_backend() {
        // Two managers built from different backends must stay independent; a
        // singleton would make this test impossible to write, which is the point.
        let first: Arc<dyn PluginExecutionBackend> = RecordingBackend::new();
        let second: Arc<dyn PluginExecutionBackend> = RecordingBackend::new();
        let a = PluginManager::new(first.clone());
        let b = PluginManager::new(second);

        assert!(!Arc::ptr_eq(a.backend(), b.backend()));
        assert!(Arc::ptr_eq(a.backend(), &first));
    }
}
