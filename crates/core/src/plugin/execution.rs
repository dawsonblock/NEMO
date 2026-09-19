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

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use nemo_relay_plugin_protocol::{
    DispatchState, OutcomeCertainty, PluginDescriptor, PluginExecutionContext,
    PluginExecutionOutcome, PluginFailureCode, PluginHostHealth, PluginInspectRequest,
    PluginLoadRequest, PluginLoadResponse, PluginProtocolError, PluginResponse,
    PluginUnloadRequest, check_deadline,
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
}

/// Owner of plugin execution, holding whichever backend was composed.
///
/// The manager exists so the deadline rule has one home. Every operation checks
/// the context's deadline before the backend is reached, which is what makes
/// "an operation that is already out of time is never started" true for every
/// backend rather than being a rule each implementation has to remember.
pub struct PluginManager {
    backend: Arc<dyn PluginExecutionBackend>,
}

impl PluginManager {
    /// Compose a manager around a backend.
    pub fn new(backend: Arc<dyn PluginExecutionBackend>) -> Self {
        Self { backend }
    }

    /// Return the backend this manager dispatches to.
    pub fn backend(&self) -> &Arc<dyn PluginExecutionBackend> {
        &self.backend
    }

    /// Load one plugin.
    pub async fn load(
        &self,
        request: PluginLoadRequest,
        context: PluginExecutionContext,
    ) -> Result<PluginLoadResponse, PluginProtocolError> {
        check_deadline(context.deadline_unix_ms)?;
        self.backend.load(request, context).await
    }

    /// Unload a plugin.
    pub async fn unload(
        &self,
        request: PluginUnloadRequest,
        context: PluginExecutionContext,
    ) -> Result<(), PluginProtocolError> {
        check_deadline(context.deadline_unix_ms)?;
        self.backend.unload(request, context).await
    }

    /// Describe loaded plugins.
    pub async fn inspect(
        &self,
        request: PluginInspectRequest,
        context: PluginExecutionContext,
    ) -> Result<Vec<PluginDescriptor>, PluginProtocolError> {
        check_deadline(context.deadline_unix_ms)?;
        self.backend.inspect(request, context).await
    }

    /// Report backend health.
    pub async fn health(
        &self,
        context: PluginExecutionContext,
    ) -> Result<PluginHostHealth, PluginProtocolError> {
        check_deadline(context.deadline_unix_ms)?;
        self.backend.health(context).await
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
    result: Result<PluginResponse, PluginProtocolError>,
    dispatch: DispatchState,
    certainty: OutcomeCertainty,
) -> PluginExecutionOutcome {
    PluginExecutionOutcome {
        dispatch,
        certainty,
        result: result.map_err(|error| error.failure),
    }
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
                        name: request.plugin_id,
                        abi_version: 1,
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

    fn context(deadline_unix_ms: u64) -> PluginExecutionContext {
        PluginExecutionContext {
            request_id: "operation-1".into(),
            protocol_version: nemo_relay_plugin_protocol::PROTOCOL_VERSION,
            runtime_binding_digest: "binding".into(),
            deadline_unix_ms,
            max_response_bytes: 1024,
        }
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
