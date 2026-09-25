// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The kernel's side of the process boundary: spawn, handshake, and the backend.
//!
//! Everything the boundary is supposed to guarantee is enforced here rather than
//! asked of the child: the socket lives in a directory only this process can
//! read, the child starts with a filtered environment and one credential, the
//! handshake has to bind the runtime identity before any operation is sent, and
//! a deadline that passes kills the process rather than waiting for a plugin to
//! honour a cancellation token.
//!
//! Nothing here trusts the child's own account of itself. A host that exits is
//! reported as `HostCrashed` rather than as an unavailable service, because the
//! two call for different responses: one is a process that ended, and the other
//! is a message that did not arrive.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use nemo_relay::plugin::execution::{PluginExecutionBackend, PluginExecutionFuture};
use nemo_relay_plugin_proto::convert::{
    context_to_wire, health_outcome_from_wire, inspect_outcome_from_wire, inspect_request_to_wire,
    load_outcome_from_wire, load_request_to_wire, unload_outcome_from_wire, unload_request_to_wire,
};
use nemo_relay_plugin_proto::v1;
use nemo_relay_plugin_proto::v1::plugin_host_client::PluginHostClient;
use nemo_relay_plugin_proto::v1::relay_runtime_server::RelayRuntimeServer;
use nemo_relay_plugin_protocol::{
    MAX_FRAME_BYTES, PROTOCOL_VERSION, PluginDescriptor, PluginExecutionContext, PluginFailure,
    PluginFailureCode, PluginHostHealth, PluginHostReadCapability, PluginInspectRequest,
    PluginLoadRequest, PluginLoadResponse, PluginProtocolError, PluginSessionIdentity,
    PluginUnloadRequest, Uuid, deadline_expired,
};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tonic::transport::Server;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

use crate::operation_scopes::OperationScopes;
use crate::runtime_service::{RelayRuntimeConfig, RelayRuntimeService};

/// How to start a plugin host.
#[derive(Debug, Clone)]
pub struct PluginHostSupervisorConfig {
    /// The `nemo-plugin-host` executable.
    pub executable: PathBuf,
    /// Digest of the runtime identity the host is bound to.
    pub runtime_binding_digest: String,
    /// Kernel-held state the host may read, if any.
    pub offered_read_capabilities: Vec<PluginHostReadCapability>,
    /// Largest frame either side will accept.
    ///
    /// Carried so the transport decoder is configured from the same value the
    /// handshake negotiates, rather than from a transport default that could
    /// disagree with the protocol.
    pub maximum_frame_bytes: u32,
    /// What the host process is allowed to take from the machine.
    ///
    /// Applied to the child rather than to this process, and applied before it
    /// runs any plugin code, so nothing a plugin does can raise it.
    pub limits: crate::limits::PluginHostLimits,
    /// How long to wait for the host to start and handshake.
    pub startup_timeout: Duration,
}

impl PluginHostSupervisorConfig {
    /// Start from the executable that ships beside this process.
    ///
    /// Three places are tried, in order, because "beside this process" is not
    /// one place in every build: a test harness runs from `deps/` while the
    /// binary it exercises is one directory above, and a deployment that
    /// installs the host somewhere else can say where. The first one that exists
    /// is used; when none does, the path beside this process is returned so the
    /// failure names the location the deployment was expected to fill.
    pub fn beside_this_executable(runtime_binding_digest: impl Into<String>) -> Self {
        let executable = resolve_executable();
        Self {
            executable,
            runtime_binding_digest: runtime_binding_digest.into(),
            offered_read_capabilities: Vec::new(),
            maximum_frame_bytes: MAX_FRAME_BYTES,
            limits: crate::limits::PluginHostLimits::default(),
            startup_timeout: Duration::from_secs(10),
        }
    }
}

/// Environment variable naming the host executable, for deployments that do not
/// install it beside the process that starts it.
pub const EXECUTABLE_ENV: &str = "NEMO_RELAY_PLUGIN_HOST";

/// Where the host executable is, given where this process is.
fn resolve_executable() -> PathBuf {
    if let Some(configured) = std::env::var_os(EXECUTABLE_ENV) {
        let configured = PathBuf::from(configured);
        if configured.exists() {
            return configured;
        }
    }
    let beside = directory_holding_this_process();
    for candidate in beside_this_process(&beside) {
        if candidate.exists() {
            return candidate;
        }
    }
    beside.join(executable_name())
}

/// The directory holding the executable that started this process.
///
/// It is the interpreter's own directory for a binding loaded into Python or
/// Node rather than a plugin host's, which is what makes an installation beside
/// the interpreter an installation beside the thing that starts the host.
fn directory_holding_this_process() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_default()
}

/// The places a host is looked for once nothing has named one.
fn beside_this_process(beside: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![beside.join(executable_name())];
    if let Some(above) = beside.parent() {
        candidates.push(above.join(executable_name()));
    }
    candidates
}

/// Where a host would have been found, in the order it was looked for.
///
/// Read by the failure below rather than by the resolution above, so a
/// deployment that received a runtime without the host is told which locations
/// it was expected to fill instead of only which file was missing.
fn host_search_locations() -> Vec<PathBuf> {
    let mut locations = Vec::new();
    if let Some(configured) = std::env::var_os(EXECUTABLE_ENV) {
        locations.push(PathBuf::from(configured));
    }
    locations.extend(beside_this_process(&directory_holding_this_process()));
    locations
}

fn executable_name() -> &'static str {
    if cfg!(windows) {
        "nemo-plugin-host.exe"
    } else {
        "nemo-plugin-host"
    }
}

/// A running plugin host process.
pub struct PluginHostSupervisor {
    /// The child, behind a lock because killing it and asking whether it exited
    /// happen from `&self`: a backend operation holds no exclusive borrow.
    child: Mutex<Child>,
    /// The child's process id, captured while it was running.
    process_id: Option<u32>,
    /// The write end of the pipe the host watches for its kernel's absence.
    ///
    /// Dropped with the session, which is what tells the host that this kernel
    /// is gone even when `Drop` never runs — a process that exits, or is killed,
    /// closes it as surely as a clean teardown does.
    child_pipe: Option<tokio::process::ChildStdin>,
    /// Removed when the supervisor drops, so nothing outlives the session.
    socket_dir: PathBuf,
    /// The socket this kernel serves for the child's own calls.
    kernel_endpoint: PathBuf,
    /// The task serving it, aborted with the session.
    ///
    /// The handle keeps the task's own result rather than discarding it: a
    /// server that stopped serving says so where the session ends, instead of
    /// looking like a kernel whose socket merely went quiet.
    runtime_server: tokio::task::JoinHandle<Result<(), String>>,
    /// The executor the kernel's own callback service runs on.
    ///
    /// Its own runtime rather than whichever runtime started this host, and that is a
    /// structural property rather than a preference: a plugin's callback can call *back* into
    /// the kernel — a codec resolution is the case that found it — so the call the kernel is
    /// waiting on and the call that answers it must not need the same execution lane. On a
    /// runtime with one lane the kernel would hold it while waiting for an answer that needs
    /// it, and a deadlock is not something an embedding application should be able to choose
    /// by picking a current-thread runtime. Two workers, because serving a callback while
    /// answering another is the ordinary case for a busy session.
    callback_runtime: Option<tokio::runtime::Runtime>,
    /// The scope stack each in-flight operation belongs to.
    ///
    /// Held here because both sides of the kernel need the same map: the proxy
    /// registers an operation while it runs, and the service looks the operation
    /// up when the host forwards a mark a plugin raised during it.
    operation_scopes: Arc<OperationScopes>,
    /// The continuations this session is holding for the plugins it runs.
    ///
    /// Owned by the supervisor because both halves need it: the proxy parks a
    /// position while an intercept runs, and the kernel's own service resumes it
    /// when the host asks.
    continuations: Arc<crate::continuations::Continuations>,
    /// The codec capabilities this session has issued and not yet taken back.
    ///
    /// Owned here for the same reason as the continuations: the proxy issues a reference
    /// while a sanitize invocation runs and holds the guard for exactly that call, and the
    /// kernel's own service is what checks a reference and executes the codec work.
    codecs: Arc<crate::codec_capability::CodecCapabilities>,
    session: PluginSessionIdentity,
    /// Kept for a second transport: the host checks the credential at attach as
    /// it does at handshake, so a descriptor has to carry it.
    session_credential: String,
    /// Kept for the same reason, and because the session's identity does not
    /// carry it: the binding is a property of the runtime, not of the handshake.
    runtime_binding_digest: String,
    /// What this session's operations have to present.
    ///
    /// Minted here, before the handshake, because it is the kernel's to choose:
    /// a host that minted its own capability would be handing out the thing that
    /// authorises calls to it.
    capability: crate::capability::SessionCapability,
    client: PluginHostClient<Channel>,
}

impl PluginHostSupervisor {
    /// Spawn a host, handshake with it, and hold the session.
    pub async fn spawn(config: PluginHostSupervisorConfig) -> Result<Self, PluginProtocolError> {
        let socket_dir = create_runtime_dir()?;
        let socket = socket_dir.join("s");
        let credential = Uuid::now_v7().to_string();
        // The capability every operation on this session has to present, minted
        // before the host is told anything so that the session is established
        // with it rather than asking for one afterwards.
        let capability = crate::capability::SessionCapability::mint().map_err(|error| {
            unavailable(format!("failed to mint a session capability: {error}"))
        })?;
        // The kernel's own socket, in the same private directory. The child is
        // told about it and given a credential of its own: a call back into the
        // kernel is a different relationship than a call into the host, and each
        // side checks the credential the other was given rather than the path,
        // which anybody who can read the environment already knows.
        let kernel_endpoint = socket_dir.join("k");
        let kernel_credential = Uuid::now_v7().to_string();
        let operation_scopes = Arc::new(OperationScopes::new());
        let continuations = Arc::new(crate::continuations::Continuations::new());
        // The codec capabilities this session will issue. One record for the session, held
        // here rather than by the proxy, because the kernel's own callback service is what
        // checks a reference and the object it authorizes has to be reachable from both.
        let codecs = Arc::new(crate::codec_capability::CodecCapabilities::new());
        // Bound before the child starts, so the path it is told about exists by
        // the time it could want it. Accepting begins once the session is
        // established, because the service is bound to that session.
        // Bound as an ordinary socket rather than a tokio one, because the executor that will
        // *accept* on it is not the one that is running this function: a tokio listener belongs
        // to the reactor that created it, so adopting it on another runtime would leave a socket
        // that accepts at the operating-system level and never answers. The callback executor
        // adopts this one from inside its own reactor below.
        let kernel_listener =
            std::os::unix::net::UnixListener::bind(&kernel_endpoint).map_err(|error| {
                unavailable(format!(
                    "failed to bind the kernel's socket at '{}': {error}",
                    kernel_endpoint.display()
                ))
            })?;
        let mut command = Command::new(&config.executable);
        // The bounds the child runs under, applied between `fork` and `exec`.
        // This is the only point at which they can be applied and the only point
        // at which they cannot be undone by what they are bounding: whatever the
        // plugin does afterwards, these are the limits it does it under.
        #[cfg(unix)]
        {
            let limits = config.limits;
            // Safety: the closure runs in the forked child before `exec`, and
            // calls `setrlimit` (and, on Linux, `prctl`) and nothing else: it
            // allocates nothing, takes no locks, and returns only an error the
            // spawn reports.
            unsafe {
                command.pre_exec(move || crate::limits::apply(&limits));
            }
        }
        // A filtered environment: the child gets what it needs to be this host
        // and nothing about the kernel's own environment that it has no business
        // reading.
        command
            .env_clear()
            .env(
                "PATH",
                std::env::var("PATH").unwrap_or_else(|_| String::new()),
            )
            .env("NEMO_RELAY_PLUGIN_HOST_SOCKET", &socket)
            .env("NEMO_RELAY_PLUGIN_HOST_CREDENTIAL", &credential)
            .env("NEMO_RELAY_KERNEL_SOCKET", &kernel_endpoint)
            .env("NEMO_RELAY_KERNEL_CREDENTIAL", &kernel_credential)
            .env(
                "NEMO_RELAY_PLUGIN_HOST_BINDING",
                &config.runtime_binding_digest,
            )
            .env(
                "NEMO_RELAY_PLUGIN_HOST_PROTOCOL",
                PROTOCOL_VERSION.to_string(),
            )
            // A pipe rather than null: the host watches it and exits when the
            // kernel that owns it goes away, which is the one thing that still
            // holds when a supervisor never gets to run its own teardown. The
            // write end is kept in this struct, so a session that ends closes it.
            .stdin(Stdio::piped())
            // Logs stay logs: the child's output goes to this process's streams
            // and is never a channel the protocol travels on.
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let child = command.spawn().map_err(|error| {
            // A host that is not there is a deployment that received a runtime
            // without the executable that makes isolation possible, so the
            // failure names what was looked for rather than only that the spawn
            // failed: a caller cannot repair a path it was never told.
            if !config.executable.exists() {
                let looked = host_search_locations()
                    .into_iter()
                    .map(|location| format!("'{}'", location.display()))
                    .collect::<Vec<_>>()
                    .join(", ");
                return unavailable(format!(
                    "the plugin host executable '{}' does not exist, and a runtime that starts a \
                     host needs the host installed beside it; it was looked for at {looked}, and \
                     {EXECUTABLE_ENV} names one somewhere else",
                    config.executable.display(),
                ));
            }
            unavailable(format!(
                "failed to start plugin host '{}': {error}; the limits the child was to run \
                 under are applied here, so a limit this platform refuses is a host that does \
                 not start rather than one that runs unbounded",
                config.executable.display(),
            ))
        })?;
        let process_id = child.id();
        let mut child = child;
        // Held, not used: the host reads it, and what it observes is the moment
        // this handle goes away with the session.
        let child_pipe = child.stdin.take();

        // One budget covers the whole startup: the socket appearing *and* the
        // handshake completing. A host that binds, accepts and then never
        // answers would otherwise hold `spawn` open forever, which would make the
        // stated guarantee half true.
        let startup = tokio::time::timeout(config.startup_timeout, async {
            let channel = loop {
                match connect(&socket).await {
                    Ok(channel) => break channel,
                    Err(error) => {
                        // The startup budget bounds this loop, so a host that
                        // never binds is killed when it expires rather than
                        // retried forever.
                        if let Some(status) = child.try_wait().ok().flatten() {
                            return Err(unavailable(format!(
                                "plugin host did not accept a connection at '{}': {error}; \
                                 the host exited with {status}",
                                socket.display()
                            )));
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            };
            let client = PluginHostClient::new(channel)
                .max_decoding_message_size(config.maximum_frame_bytes as usize)
                .max_encoding_message_size(config.maximum_frame_bytes as usize);
            let mut client = client;
            let session = handshake(
                &mut client,
                &credential,
                &config.runtime_binding_digest,
                &config.offered_read_capabilities,
                &ProcessPluginBackend::supported_registration_operations(),
                config.maximum_frame_bytes,
                &capability,
            )
            .await?;
            Ok::<_, PluginProtocolError>((client, session))
        })
        .await;

        let (client, session) = match startup {
            Ok(Ok(started)) => started,
            Ok(Err(error)) => {
                let _ = child.kill().await;
                return Err(error);
            }
            Err(_) => {
                // A host that will not finish starting is not a host.
                let _ = child.kill().await;
                let _ = std::fs::remove_dir_all(&socket_dir);
                return Err(unavailable(
                    "the plugin host did not start and handshake within its startup budget",
                ));
            }
        };
        // Every transport this session opens uses this one number, so it has to
        // be the number both sides can carry rather than whichever one named it
        // last. The host reports what it will accept and the kernel cannot be
        // told a size larger than the one it configured itself for, so the
        // session keeps the smaller of the two — including for the second,
        // attached transport, which is handed this value and no other.
        let negotiated_frame_limit = session
            .maximum_frame_bytes
            .min(config.maximum_frame_bytes)
            .min(MAX_FRAME_BYTES);
        let session = PluginSessionIdentity {
            maximum_frame_bytes: negotiated_frame_limit,
            ..session
        };

        // The kernel's side of the boundary, serving the session that was just established — on
        // an executor of its own, because a plugin's callback can call back into the kernel and
        // the two directions must not need the same lane.
        let callback_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("nemo-plugin-callbacks")
            .enable_all()
            .build()
            .map_err(|error| {
                PluginProtocolError::new(
                    nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
                    format!(
                        "the executor the kernel's callback service needs did not start: {error}"
                    ),
                )
            })?;
        // Spawned rather than awaited: nothing calls it until a plugin's host does, and
        // holding `start` open for that would make starting a host depend on a call nobody
        // has made.
        let serving_session_id = session.session_id.clone();
        let serving_binding_digest = config.runtime_binding_digest.clone();
        let serving_operation_scopes = Arc::clone(&operation_scopes);
        let serving_continuations = Arc::clone(&continuations);
        let serving_codecs = Arc::clone(&codecs);
        let runtime_server = callback_runtime.spawn(async move {
            if let Err(error) = kernel_listener.set_nonblocking(true) {
                return Err(format!(
                    "the kernel's socket could not be made non-blocking: {error}"
                ));
            }
            // Adopted here, inside the executor that will accept on it: this is the line that
            // binds the socket's reactor to the runtime that serves the session.
            let listener =
                tokio::net::UnixListener::from_std(kernel_listener).map_err(|error| {
                    format!("the kernel's socket could not be adopted by its executor: {error}")
                })?;
            Server::builder()
                .add_service(RelayRuntimeServer::new(RelayRuntimeService::new(
                    RelayRuntimeConfig {
                        session_id: serving_session_id,
                        session_credential: kernel_credential,
                        protocol_version: PROTOCOL_VERSION,
                        runtime_binding_digest: serving_binding_digest,
                        operation_scopes: serving_operation_scopes,
                        continuations: serving_continuations,
                        codecs: serving_codecs,
                    },
                )))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
                .await
                .map_err(|error| error.to_string())
        });

        Ok(Self {
            child: Mutex::new(child),
            process_id,
            child_pipe,
            socket_dir,
            kernel_endpoint,
            runtime_server,
            callback_runtime: Some(callback_runtime),
            operation_scopes,
            continuations,
            codecs,
            session,
            session_credential: credential,
            capability,
            runtime_binding_digest: config.runtime_binding_digest.clone(),
            client,
        })
    }

    /// The session this host established.
    pub fn session(&self) -> &PluginSessionIdentity {
        &self.session
    }

    /// The socket this kernel serves for the child's own calls.
    ///
    /// The path is not a secret — the child is told it, and knowing it is not
    /// enough to be served — so exposing it lets a caller point a host's client
    /// at the right socket without also exposing the credential that authorises
    /// it.
    pub fn kernel_endpoint(&self) -> &Path {
        &self.kernel_endpoint
    }

    /// Everything a second transport needs to attach to this session.
    pub fn connection_descriptor(&self) -> crate::attached::ConnectionDescriptor {
        crate::attached::ConnectionDescriptor {
            endpoint: self.socket_dir.join("s"),
            session_credential: self.session_credential.clone(),
            runtime_binding_digest: self.runtime_binding_digest.clone(),
            session_id: self.session.session_id.clone(),
            maximum_frame_bytes: self.session.maximum_frame_bytes,
            capability: self.capability.as_str().to_owned(),
        }
    }

    /// The registry that says which scope an in-flight operation belongs to.
    ///
    /// Whoever installs a proxy registers into it, so a mark the host forwards
    /// during an operation is attached to the call that raised it.
    pub fn operation_scopes(&self) -> Arc<OperationScopes> {
        Arc::clone(&self.operation_scopes)
    }

    /// The continuations this session holds for the plugins it runs.
    pub fn continuations(&self) -> Arc<crate::continuations::Continuations> {
        Arc::clone(&self.continuations)
    }

    /// The codec capabilities this session issues into.
    pub fn codec_capabilities(&self) -> Arc<crate::codec_capability::CodecCapabilities> {
        Arc::clone(&self.codecs)
    }

    /// The host's process id, as it was while the process was running.
    pub fn process_id(&self) -> Option<u32> {
        self.process_id
    }

    /// End the host process.
    pub async fn kill(&self) -> Result<(), PluginProtocolError> {
        self.child
            .lock()
            .await
            .kill()
            .await
            .map_err(|error| unavailable(format!("failed to kill the plugin host: {error}")))
    }

    /// Whether the host has already exited, and how.
    async fn exit_status(&self) -> Option<std::process::ExitStatus> {
        self.child.lock().await.try_wait().ok().flatten()
    }

    /// Send one lifecycle request, holding it to the operation's budget.
    async fn request<W, F>(&self, budget: Duration, send: F) -> Result<W, PluginProtocolError>
    where
        F: std::future::Future<Output = Result<W, tonic::Status>>,
    {
        match tokio::time::timeout(budget, send).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(status)) => {
                // A transport failure is either a host that ended or a channel
                // that broke; the difference decides whether the kernel may
                // consider the operation undone, so it is never guessed at.
                Err(match self.exit_status().await {
                    Some(status) => crashed(format!("the plugin host exited: {status}")),
                    None => {
                        // The channel broke while the host is still running, so
                        // nobody can say whether it acted on the request. Keeping
                        // it alive would leave a process whose state the kernel
                        // cannot account for; killing it makes the session's
                        // state certain again, which is what a restart from
                        // nothing depends on.
                        let _ = self.child.lock().await.kill().await;
                        unavailable(format!(
                            "the plugin host did not answer '{status}', so its state is unknown \
                             and it was killed"
                        ))
                    }
                })
            }
            Err(_) => {
                // The deadline is the kernel's, and a plugin is not trusted to
                // honour it: the process is killed rather than asked to stop.
                let _ = self.child.lock().await.kill().await;
                Err(PluginProtocolError::new(
                    PluginFailureCode::DeadlineExceeded,
                    "the plugin host exceeded the operation's budget".to_string(),
                ))
            }
        }
    }
}

impl Drop for PluginHostSupervisor {
    fn drop(&mut self) {
        // The server is this session's, and it goes when the session does.
        self.runtime_server.abort();
        // And the executor it ran on. Ended in the background for the same reason the off-path
        // runtime is: a composition is usually torn down from inside an async context, and
        // dropping a runtime there panics.
        if let Some(runtime) = self.callback_runtime.take() {
            runtime.shutdown_background();
        }
        // The pipe closes here too, so a host whose kill somehow did not land
        // still learns that this kernel is gone.
        drop(self.child_pipe.take());
        // And so does the host process. `kill_on_drop` is not enough on its own:
        // it signals the child from a task on this process's runtime, and the
        // last composition of a process is dropped exactly when that runtime is
        // shutting down — so the task may never run, and the host outlives the
        // session that started it. Signalling here is synchronous, and a signal
        // cannot be lost to a scheduler that is going away.
        let _ = self.child.get_mut().start_kill();
        // The directory holds the socket and nothing else, and it is removed
        // with the session it belonged to.
        let _ = std::fs::remove_dir_all(&self.socket_dir);
    }
}

/// A backend that reaches the plugin host process.
pub struct ProcessPluginBackend {
    supervisor: PluginHostSupervisor,
    /// How to start a replacement, so a crashed host can be replaced without the
    /// caller having to know it ever existed.
    config: PluginHostSupervisorConfig,
}

impl ProcessPluginBackend {
    /// Registration classes this backend can install a proxy for.
    ///
    /// Derived from what the backend implements rather than supplied by a
    /// caller: a caller that could declare support the backend does not have
    /// would break the guarantee that a load which cannot be served does not
    /// happen. Each entry is next to the proxy that makes it true — a class
    /// belongs here when the kernel can install a proxy for it and the host can
    /// run it — and the list is the whole of what the boundary carries today.
    pub fn supported_registration_operations()
    -> Vec<nemo_relay_plugin_protocol::PluginRegistrationOperation> {
        // The classes this kernel can install a proxy for and this host can run.
        // A class appearing here without a proxy would let a load report success
        // for a callback the runtime never calls, so the list grows one entry at
        // a time, next to the proxy that makes the entry true.
        vec![
            nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolRequestIntercept,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmRequestIntercept,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::Subscriber,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::EventMetadataInjector,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolConditionalExecutionGuardrail,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmConditionalExecutionGuardrail,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolSanitizeRequestGuardrail,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolSanitizeResponseGuardrail,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::ToolExecutionIntercept,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmExecutionIntercept,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmStreamExecutionIntercept,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::MarkSanitizeGuardrail,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::ScopeSanitizeStartGuardrail,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::ScopeSanitizeEndGuardrail,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmSanitizeRequestGuardrail,
            nemo_relay_plugin_protocol::PluginRegistrationOperation::LlmSanitizeResponseGuardrail,
        ]
    }

    /// Ask the host to activate components and report what they registered.
    ///
    /// The kernel sends the configuration, the plugin's register callbacks run in
    /// the host, and the descriptors that come back are what the kernel installs
    /// proxies from. A plugin that registered something this session cannot
    /// serve is refused by the host, so nothing is activated that the kernel
    /// would then have to ignore.
    pub async fn activate(
        &self,
        request: nemo_relay_plugin_protocol::PluginActivateRequest,
        context: PluginExecutionContext,
    ) -> Result<Vec<PluginDescriptor>, PluginProtocolError> {
        let budget = Self::budget(&context, now_unix_ms()?)?;
        let session_id = self.supervisor.session.session_id.clone();
        let wire = nemo_relay_plugin_proto::convert::activate_request_to_wire(
            &request,
            &session_id,
            &context,
        );
        let mut client = self.supervisor.client.clone();
        let request = capable(wire, &self.supervisor.capability);
        let outcome = self
            .supervisor
            .request(budget, async move { client.activate(request).await })
            .await?
            .into_inner();
        nemo_relay_plugin_proto::convert::activate_outcome_from_wire(&outcome)?
            .into_result()
            .map_err(error_to_protocol)
    }

    /// Start a streaming invocation and read its frames.
    ///
    /// The one call whose answer is a stream rather than a value: the host runs
    /// the registration and produces the frames the plugin's returned stream
    /// yields, and this side reads them one at a time. Reading is what asks the
    /// host for the next one, so a kernel that stops reading stops the plugin —
    /// which is the same pacing the downstream direction has, in the other
    /// direction.
    ///
    /// The deadline is not applied to the stream as a whole here: a stream's
    /// budget is about when it *starts* and about the bytes it carries, and the
    /// operation's deadline is enforced on the call the way it is for any other
    /// — by the supervisor's kill when the host overruns.
    pub async fn invoke_stream(
        &self,
        request: nemo_relay_plugin_protocol::PluginInvokeRequest,
        context: PluginExecutionContext,
    ) -> Result<PluginStreamFrames, PluginProtocolError> {
        let budget = Self::budget(&context, now_unix_ms()?)?;
        let session_id = self.supervisor.session.session_id.clone();
        let wire = nemo_relay_plugin_proto::convert::invoke_request_to_wire(
            &request,
            &session_id,
            &context,
        );
        let mut client = self.supervisor.client.clone();
        let start = capable(wire, &self.supervisor.capability);
        // The call itself is bounded by the operation's budget; the frames that
        // follow are bounded by the reader, which is the backpressure the host
        // is entitled to see.
        let started = self
            .supervisor
            .request(budget, async move { client.invoke_stream(start).await })
            .await?;
        Ok(PluginStreamFrames {
            frames: started.into_inner(),
            operation_request_id: context.operation_request_id.clone(),
            terminal: false,
        })
    }

    /// Take ownership of a running host.
    pub fn new(supervisor: PluginHostSupervisor, config: PluginHostSupervisorConfig) -> Self {
        Self { supervisor, config }
    }

    /// Spawn a host and serve it.
    pub async fn launch(config: PluginHostSupervisorConfig) -> Result<Self, PluginProtocolError> {
        let supervisor = PluginHostSupervisor::spawn(config.clone()).await?;
        Ok(Self::new(supervisor, config))
    }

    /// The session this backend belongs to.
    pub fn session(&self) -> &PluginSessionIdentity {
        self.supervisor.session()
    }

    /// The runtime binding this backend's host was started with.
    ///
    /// The kernel knows it — it sent it — and the host checks every operation
    /// against it, so anything the kernel asks on the session's behalf has to
    /// carry it.
    pub fn runtime_binding_digest(&self) -> &str {
        &self.config.runtime_binding_digest
    }

    /// The host's process id, while it is running.
    pub fn process_id(&self) -> Option<u32> {
        self.supervisor.process_id()
    }

    /// The socket this backend's kernel serves for the child's own calls.
    pub fn kernel_endpoint(&self) -> &Path {
        self.supervisor.kernel_endpoint()
    }

    /// The registry that says which scope an in-flight operation belongs to.
    pub fn operation_scopes(&self) -> Arc<OperationScopes> {
        self.supervisor.operation_scopes()
    }

    /// The continuations this session holds for the plugins it runs.
    pub fn continuations(&self) -> Arc<crate::continuations::Continuations> {
        self.supervisor.continuations()
    }

    /// The codec capabilities this session issues into.
    pub fn codec_capabilities(&self) -> Arc<crate::codec_capability::CodecCapabilities> {
        self.supervisor.codec_capabilities()
    }

    /// Everything a second transport needs to attach to this session.
    pub fn connection_descriptor(&self) -> crate::attached::ConnectionDescriptor {
        self.supervisor.connection_descriptor()
    }

    /// End the host process.
    pub async fn kill(&self) -> Result<(), PluginProtocolError> {
        self.supervisor.kill().await
    }

    /// Whether the host has exited, and how.
    pub async fn exit_status(&self) -> Option<std::process::ExitStatus> {
        self.supervisor.exit_status().await
    }

    /// Replace a host that has exited with a fresh one.
    ///
    /// Deliberately *not* a reload. Everything the previous host held — its
    /// session, its loaded plugins, and the generations behind their handles —
    /// belonged to that session, and a new host starts with none of it: a handle
    /// from before the crash addresses nothing, and the kernel has to ask for a
    /// load again. Restarting with the old set in place would imply a continuity
    /// the crash took away, and the loaded set is the kernel's record rather than
    /// the backend's.
    pub async fn restart(&mut self) -> Result<(), PluginProtocolError> {
        let supervisor = PluginHostSupervisor::spawn(self.config.clone()).await?;
        // The old supervisor drops here, which kills it if it is somehow still
        // running and removes its socket directory either way.
        self.supervisor = supervisor;
        Ok(())
    }

    /// How long the operation may take, or a refusal if it may not start.
    fn budget(
        context: &PluginExecutionContext,
        now_unix_ms: u64,
    ) -> Result<Duration, PluginProtocolError> {
        if deadline_expired(context.deadline_unix_ms, now_unix_ms) {
            return Err(PluginProtocolError::new(
                PluginFailureCode::DeadlineExceeded,
                "the operation's deadline has already passed".to_string(),
            ));
        }
        let remaining = context
            .deadline_unix_ms
            .saturating_sub(now_unix_ms)
            .min(context.remaining_budget_millis);
        Ok(Duration::from_millis(remaining))
    }
}

impl PluginExecutionBackend for ProcessPluginBackend {
    fn load<'a>(
        &'a self,
        request: PluginLoadRequest,
        context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, PluginLoadResponse> {
        Box::pin(async move {
            let budget = Self::budget(&context, now_unix_ms()?)?;
            let session_id = self.supervisor.session.session_id.clone();
            let wire = load_request_to_wire(&request, &session_id, &context);
            let mut client = self.supervisor.client.clone();
            let request = capable(wire, &self.supervisor.capability);
            let outcome = self
                .supervisor
                .request(budget, async move { client.load(request).await })
                .await?
                .into_inner();
            let outcome = load_outcome_from_wire(&outcome)?
                .into_result()
                .map_err(error_to_protocol)?;
            Ok(outcome)
        })
    }

    fn unload<'a>(
        &'a self,
        request: PluginUnloadRequest,
        context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, ()> {
        Box::pin(async move {
            let budget = Self::budget(&context, now_unix_ms()?)?;
            let session_id = self.supervisor.session.session_id.clone();
            let wire = unload_request_to_wire(&request, &session_id, &context);
            let mut client = self.supervisor.client.clone();
            let request = capable(wire, &self.supervisor.capability);
            let outcome = self
                .supervisor
                .request(budget, async move { client.unload(request).await })
                .await?
                .into_inner();
            unload_outcome_from_wire(&outcome)?
                .into_result()
                .map_err(error_to_protocol)
        })
    }

    fn inspect<'a>(
        &'a self,
        request: PluginInspectRequest,
        context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, Vec<PluginDescriptor>> {
        Box::pin(async move {
            let budget = Self::budget(&context, now_unix_ms()?)?;
            let session_id = self.supervisor.session.session_id.clone();
            let wire = inspect_request_to_wire(&request, &session_id, &context);
            let mut client = self.supervisor.client.clone();
            let request = capable(wire, &self.supervisor.capability);
            let outcome = self
                .supervisor
                .request(budget, async move { client.inspect(request).await })
                .await?
                .into_inner();
            inspect_outcome_from_wire(&outcome)?
                .into_result()
                .map_err(error_to_protocol)
        })
    }

    fn invoke<'a>(
        &'a self,
        request: nemo_relay_plugin_protocol::PluginInvokeRequest,
        context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, nemo_relay_plugin_protocol::PluginExecutionOutcome> {
        Box::pin(async move {
            let budget = Self::budget(&context, now_unix_ms()?)?;
            let session_id = self.supervisor.session.session_id.clone();
            let wire = nemo_relay_plugin_proto::convert::invoke_request_to_wire(
                &request,
                &session_id,
                &context,
            );
            let mut client = self.supervisor.client.clone();
            let request = capable(wire, &self.supervisor.capability);
            let outcome = self
                .supervisor
                .request(budget, async move { client.invoke(request).await })
                .await?
                .into_inner();
            // The same budget the host measured against, measured again here.
            // This side does not take the host's word for it any more than it
            // takes its word for anything else: the host runs a native plugin,
            // and an answer that outgrew its operation is refused on arrival
            // rather than handed to a caller that asked for a smaller one.
            nemo_relay_plugin_proto::convert::check_invoke_outcome_budget(
                &outcome,
                context.max_response_bytes,
            )?;
            // The outcome travels whole, because the distinction it carries is
            // the reason it exists: a plugin that may have dispatched before the
            // channel died produced no definite result, and collapsing that into
            // a failure would turn "nobody knows" into "it did not happen".
            //
            // It also has to be the outcome for *this* invocation: the answer
            // names the operation the host accepted, and an answer that names a
            // different one is refused here rather than attributed to this call.
            nemo_relay_plugin_proto::convert::invocation_answer_from_wire(
                &outcome,
                &context.operation_request_id,
            )
        })
    }

    fn health<'a>(
        &'a self,
        context: PluginExecutionContext,
    ) -> PluginExecutionFuture<'a, PluginHostHealth> {
        Box::pin(async move {
            let budget = Self::budget(&context, now_unix_ms()?)?;
            let session_id = self.supervisor.session.session_id.clone();
            let wire = v1::HealthRequest {
                session_id,
                context: Some(context_to_wire(&context)),
            };
            let mut client = self.supervisor.client.clone();
            let request = capable(wire, &self.supervisor.capability);
            let outcome = self
                .supervisor
                .request(budget, async move { client.health(request).await })
                .await?
                .into_inner();
            health_outcome_from_wire(&outcome)?
                .into_result()
                .map_err(error_to_protocol)
        })
    }
}

/// The frames one streaming invocation produces.
///
/// Read one at a time, because reading is what asks the host for the next one:
/// a stream this side stops reading is one the plugin stops producing, which is
/// the pacing the host's own pull has in the other direction.
pub struct PluginStreamFrames {
    frames: tonic::Streaming<v1::StreamChunk>,
    /// The invocation these frames belong to.
    operation_request_id: String,
    /// Whether a terminal frame has been read, so a stream ends once.
    terminal: bool,
}

impl std::fmt::Debug for PluginStreamFrames {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PluginStreamFrames")
            .field("operation_request_id", &self.operation_request_id)
            .field("terminal", &self.terminal)
            .finish()
    }
}

impl PluginStreamFrames {
    /// The invocation these frames answer.
    pub fn operation_request_id(&self) -> &str {
        &self.operation_request_id
    }
}

impl tokio_stream::Stream for PluginStreamFrames {
    type Item = Result<nemo_relay_plugin_protocol::PluginStreamChunk, PluginProtocolError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;

        let this = self.as_mut().get_mut();
        if this.terminal {
            return Poll::Ready(None);
        }
        match std::pin::Pin::new(&mut this.frames).poll_next(context) {
            Poll::Ready(Some(Ok(frame))) => {
                let converted = nemo_relay_plugin_proto::convert::stream_chunk_from_wire(&frame);
                match converted {
                    Ok(chunk) => {
                        // A frame naming another operation is refused rather than
                        // attributed to this stream: the answer has to be the
                        // answer to the invocation that asked.
                        if chunk.operation_request_id != this.operation_request_id {
                            this.terminal = true;
                            return Poll::Ready(Some(Err(PluginProtocolError::new(
                                PluginFailureCode::MalformedResponse,
                                format!(
                                    "a streaming answer names '{}' but arrived for '{}'",
                                    chunk.operation_request_id, this.operation_request_id
                                ),
                            ))));
                        }
                        if !matches!(
                            chunk.chunk,
                            nemo_relay_plugin_protocol::PluginStreamChunkKind::Data(_)
                        ) {
                            this.terminal = true;
                        }
                        Poll::Ready(Some(Ok(chunk)))
                    }
                    Err(error) => {
                        this.terminal = true;
                        Poll::Ready(Some(Err(error)))
                    }
                }
            }
            Poll::Ready(Some(Err(status))) => {
                // The channel broke mid-stream. Whether the plugin had produced
                // anything is known — the frames already read — but whether its
                // work finished is not, and the failure says so rather than
                // claiming either.
                this.terminal = true;
                Poll::Ready(Some(Err(PluginProtocolError::new(
                    PluginFailureCode::Unavailable,
                    format!("the plugin host's stream ended: {status}"),
                ))))
            }
            // A stream that simply stopped is a truncation, not an end: the
            // protocol ends a stream with a terminal frame, so this is a failure
            // rather than something a caller may read as completion.
            Poll::Ready(None) => {
                this.terminal = true;
                Poll::Ready(Some(Err(PluginProtocolError::new(
                    PluginFailureCode::MalformedResponse,
                    "the plugin host's stream ended without a terminal frame".to_string(),
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The plugin's structured failure as a protocol error.
fn error_to_protocol(failure: PluginFailure) -> PluginProtocolError {
    PluginProtocolError::new(failure.code, failure.message)
}

fn unavailable(message: impl Into<String>) -> PluginProtocolError {
    PluginProtocolError::new(PluginFailureCode::Unavailable, message)
}

fn crashed(message: impl Into<String>) -> PluginProtocolError {
    PluginProtocolError::new(PluginFailureCode::HostCrashed, message)
}

/// Wall-clock milliseconds, for comparing against an absolute deadline.
fn now_unix_ms() -> Result<u64, PluginProtocolError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| unavailable(format!("the system clock is before the epoch: {error}")))?;
    Ok(now.as_millis() as u64)
}

/// A directory only this process can read, for one host's socket.
///
/// The name is short on purpose: a Unix socket path has a small, fixed limit,
/// and the platform's temporary directory can already be most of it, so a long
/// name here would refuse to bind on a machine whose temp directory is deep.
fn create_runtime_dir() -> Result<PathBuf, PluginProtocolError> {
    // The random tail, not the timestamp: two hosts started in the same
    // millisecond would otherwise share a directory, and the second would find
    // the first's socket already there.
    let unique = Uuid::now_v7().simple().to_string();
    let dir = std::env::temp_dir().join(format!("nemo-ph-{}", &unique[20..]));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .recursive(true)
        .create(&dir)
        .map_err(|error| unavailable(format!("failed to create '{}': {error}", dir.display())))?;
    Ok(dir)
}

/// Dial a host's socket.
async fn connect(socket: &Path) -> Result<Channel, String> {
    let path: Arc<PathBuf> = Arc::new(socket.to_path_buf());
    let endpoint = Endpoint::try_from("http://[::]:50051").map_err(|error| error.to_string())?;
    endpoint
        .connect_with_connector(service_fn(move |_| {
            let path = Arc::clone(&path);
            async move {
                UnixStream::connect(&*path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .map_err(|error| error.to_string())
}

/// A request carrying the capability this session's operations have to present.
///
/// Every call after the handshake presents it, and the host refuses a call that
/// does not. The session's identity says which session a request means; this
/// says the request may use it — and an identity is what an attach announces,
/// so without this the two would be the same thing.
fn capable<T>(message: T, capability: &crate::capability::SessionCapability) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request.metadata_mut().insert(
        crate::capability::SESSION_CAPABILITY_HEADER,
        tonic::metadata::MetadataValue::try_from(capability.as_str())
            .expect("a minted capability is ASCII hex, and so is a valid header value"),
    );
    request
}

/// Establish the session this host will answer on.
async fn handshake(
    client: &mut PluginHostClient<Channel>,
    credential: &str,
    runtime_binding_digest: &str,
    offered_read_capabilities: &[PluginHostReadCapability],
    supported_registration_operations: &[nemo_relay_plugin_protocol::PluginRegistrationOperation],
    maximum_frame_bytes: u32,
    capability: &crate::capability::SessionCapability,
) -> Result<PluginSessionIdentity, PluginProtocolError> {
    let request = v1::HandshakeRequest {
        protocol_version: u32::from(PROTOCOL_VERSION),
        runtime_binding_digest: runtime_binding_digest.to_string(),
        client_nonce: Uuid::now_v7().to_string(),
        session_credential: credential.to_string(),
        // What this kernel is configured to carry, not the protocol's ceiling:
        // advertising the ceiling while decoding at a smaller limit would open a
        // session whose stated size nothing on this side honours.
        maximum_frame_bytes,
        supported_features: Vec::new(),
        offered_read_capabilities: offered_read_capabilities
            .iter()
            .map(|capability| {
                nemo_relay_plugin_proto::convert::read_capability_to_wire(*capability)
            })
            .collect(),
        supported_registration_operations: supported_registration_operations
            .iter()
            .map(|operation| {
                nemo_relay_plugin_proto::convert::registration_operation_to_wire(*operation)
            })
            .collect(),
    };
    let outcome = client
        .handshake(capable(request, capability))
        .await
        .map_err(|status| unavailable(format!("the plugin host did not answer: {status}")))?
        .into_inner();
    let identity = nemo_relay_plugin_proto::convert::handshake_outcome_from_wire(&outcome)?
        .into_result()
        .map_err(error_to_protocol)?;
    if identity.protocol_version != PROTOCOL_VERSION {
        return Err(PluginProtocolError::new(
            PluginFailureCode::VersionMismatch {
                expected: PROTOCOL_VERSION,
                received: identity.protocol_version,
            },
            format!(
                "the plugin host speaks version {}, this kernel speaks {}",
                identity.protocol_version, PROTOCOL_VERSION
            ),
        ));
    }
    if identity.maximum_frame_bytes > MAX_FRAME_BYTES {
        return Err(PluginProtocolError::new(
            PluginFailureCode::OversizedFrame {
                observed: u64::from(identity.maximum_frame_bytes),
                limit: MAX_FRAME_BYTES,
            },
            format!(
                "the plugin host will accept {} byte frames, above the {} this kernel speaks",
                identity.maximum_frame_bytes, MAX_FRAME_BYTES
            ),
        ));
    }
    if !identity.accepted_within(offered_read_capabilities) {
        // A host cannot read what it was not offered, so an acceptance that
        // names something else is refused rather than believed.
        return Err(PluginProtocolError::new(
            PluginFailureCode::Rejected,
            "the plugin host accepted a read capability it was not offered".to_string(),
        ));
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_missing_host_is_reported_with_the_places_it_was_looked_for() {
        // A deployment that received a runtime without the host cannot repair a
        // path it was never told, so the failure names the file, the locations
        // the resolver tries in order, and the variable that names one somewhere
        // else — rather than reporting only that a spawn failed.
        let config = PluginHostSupervisorConfig {
            executable: PathBuf::from("/nonexistent/nemo-plugin-host"),
            runtime_binding_digest: "binding".to_string(),
            offered_read_capabilities: Vec::new(),
            maximum_frame_bytes: MAX_FRAME_BYTES,
            limits: crate::limits::PluginHostLimits::default(),
            startup_timeout: Duration::from_secs(1),
        };
        let message = match PluginHostSupervisor::spawn(config).await {
            Ok(_) => panic!("a host that is not there does not start"),
            Err(error) => error.to_string(),
        };
        assert!(
            message.contains("/nonexistent/nemo-plugin-host"),
            "{message}"
        );
        assert!(message.contains(EXECUTABLE_ENV), "{message}");
        assert!(message.contains(executable_name()), "{message}");
    }
}
