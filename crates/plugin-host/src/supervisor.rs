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
use nemo_relay_plugin_protocol::{
    MAX_FRAME_BYTES, PROTOCOL_VERSION, PluginDescriptor, PluginExecutionContext, PluginFailure,
    PluginFailureCode, PluginHostHealth, PluginHostReadCapability, PluginInspectRequest,
    PluginLoadRequest, PluginLoadResponse, PluginProtocolError, PluginSessionIdentity,
    PluginUnloadRequest, Uuid, deadline_expired,
};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

/// How to start a plugin host.
#[derive(Debug, Clone)]
pub struct PluginHostSupervisorConfig {
    /// The `nemo-plugin-host` executable.
    pub executable: PathBuf,
    /// Digest of the runtime identity the host is bound to.
    pub runtime_binding_digest: String,
    /// Kernel-held state the host may read, if any.
    pub offered_read_capabilities: Vec<PluginHostReadCapability>,
    /// How long to wait for the host to start and handshake.
    pub startup_timeout: Duration,
}

impl PluginHostSupervisorConfig {
    /// Start from the executable that ships beside this process.
    pub fn beside_this_executable(runtime_binding_digest: impl Into<String>) -> Self {
        let executable = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .map(|dir| dir.join(executable_name()))
            .unwrap_or_else(|| PathBuf::from(executable_name()));
        Self {
            executable,
            runtime_binding_digest: runtime_binding_digest.into(),
            offered_read_capabilities: Vec::new(),
            startup_timeout: Duration::from_secs(10),
        }
    }
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
    /// Removed when the supervisor drops, so nothing outlives the session.
    socket_dir: PathBuf,
    session: PluginSessionIdentity,
    client: PluginHostClient<Channel>,
}

impl PluginHostSupervisor {
    /// Spawn a host, handshake with it, and hold the session.
    pub async fn spawn(config: PluginHostSupervisorConfig) -> Result<Self, PluginProtocolError> {
        let socket_dir = create_runtime_dir()?;
        let socket = socket_dir.join("s");
        let credential = Uuid::now_v7().to_string();
        let mut command = Command::new(&config.executable);
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
            .env(
                "NEMO_RELAY_PLUGIN_HOST_BINDING",
                &config.runtime_binding_digest,
            )
            .env(
                "NEMO_RELAY_PLUGIN_HOST_PROTOCOL",
                PROTOCOL_VERSION.to_string(),
            )
            .stdin(Stdio::null())
            // Logs stay logs: the child's output goes to this process's streams
            // and is never a channel the protocol travels on.
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let child = command.spawn().map_err(|error| {
            unavailable(format!(
                "failed to start plugin host '{}': {error}",
                config.executable.display()
            ))
        })?;
        let process_id = child.id();
        let mut child = child;

        let deadline = tokio::time::Instant::now() + config.startup_timeout;
        let channel = loop {
            match connect(&socket).await {
                Ok(channel) => break channel,
                Err(error) if tokio::time::Instant::now() < deadline => {
                    let _ = error;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => {
                    let status = child.try_wait().ok().flatten();
                    return Err(unavailable(format!(
                        "plugin host did not accept a connection at '{}': {error}{}",
                        socket.display(),
                        match status {
                            Some(status) => format!("; the host exited with {status}"),
                            None => "; the host is still running".to_string(),
                        }
                    )));
                }
            }
        };

        let mut client = PluginHostClient::new(channel);
        let session = handshake(
            &mut client,
            &credential,
            &config.runtime_binding_digest,
            &config.offered_read_capabilities,
        )
        .await?;

        Ok(Self {
            child: Mutex::new(child),
            process_id,
            socket_dir,
            session,
            client,
        })
    }

    /// The session this host established.
    pub fn session(&self) -> &PluginSessionIdentity {
        &self.session
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
                    None => unavailable(format!("the plugin host did not answer: {status}")),
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

    /// The host's process id, while it is running.
    pub fn process_id(&self) -> Option<u32> {
        self.supervisor.process_id()
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
            let outcome = self
                .supervisor
                .request(budget, async move { client.load(wire).await })
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
            let outcome = self
                .supervisor
                .request(budget, async move { client.unload(wire).await })
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
            let outcome = self
                .supervisor
                .request(budget, async move { client.inspect(wire).await })
                .await?
                .into_inner();
            inspect_outcome_from_wire(&outcome)?
                .into_result()
                .map_err(error_to_protocol)
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
            let outcome = self
                .supervisor
                .request(budget, async move { client.health(wire).await })
                .await?
                .into_inner();
            health_outcome_from_wire(&outcome)?
                .into_result()
                .map_err(error_to_protocol)
        })
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

/// Establish the session this host will answer on.
async fn handshake(
    client: &mut PluginHostClient<Channel>,
    credential: &str,
    runtime_binding_digest: &str,
    offered_read_capabilities: &[PluginHostReadCapability],
) -> Result<PluginSessionIdentity, PluginProtocolError> {
    let request = v1::HandshakeRequest {
        protocol_version: u32::from(PROTOCOL_VERSION),
        runtime_binding_digest: runtime_binding_digest.to_string(),
        client_nonce: Uuid::now_v7().to_string(),
        session_credential: credential.to_string(),
        maximum_frame_bytes: MAX_FRAME_BYTES,
        supported_features: Vec::new(),
        offered_read_capabilities: offered_read_capabilities
            .iter()
            .map(|capability| {
                nemo_relay_plugin_proto::convert::read_capability_to_wire(*capability)
            })
            .collect(),
    };
    let outcome = client
        .handshake(request)
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
