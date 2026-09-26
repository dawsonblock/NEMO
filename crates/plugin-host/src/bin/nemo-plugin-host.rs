// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The plugin host process.
//!
//! It loads native plugins and serves the kernel's lifecycle operations on a
//! Unix socket that only the kernel is told about, with a credential passed out
//! of band so knowing the path is not enough to be treated as the kernel. What
//! it must *not* do is decide anything the kernel is supposed to decide: every
//! request is converted before it is used, and every answer is a structured
//! outcome.
//!
//! Configuration arrives through the environment rather than arguments so the
//! supervisor can pass it without a shell and without a parser, and the process
//! exits non-zero rather than serving a session it cannot establish.

use std::path::PathBuf;
use std::process::ExitCode;

use nemo_relay_plugin_host::InProcessPluginBackend;
use nemo_relay_plugin_host::service::{ForwardedStep, PluginHostConfig, PluginHostService};
use nemo_relay_plugin_proto::v1::plugin_host_server::PluginHostServer;
use nemo_relay_plugin_protocol::PROTOCOL_VERSION;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

/// Socket the supervisor told us to serve on.
const SOCKET: &str = "NEMO_RELAY_PLUGIN_HOST_SOCKET";
/// Credential the supervisor passed out of band.
const CREDENTIAL: &str = "NEMO_RELAY_PLUGIN_HOST_CREDENTIAL";
/// Runtime binding this host belongs to.
const BINDING: &str = "NEMO_RELAY_PLUGIN_HOST_BINDING";
/// Protocol version the supervisor speaks.
const PROTOCOL: &str = "NEMO_RELAY_PLUGIN_HOST_PROTOCOL";
/// Socket the kernel serves for this host's own calls.
const KERNEL_SOCKET: &str = "NEMO_RELAY_KERNEL_SOCKET";
/// Credential the kernel gave this host for those calls.
const KERNEL_CREDENTIAL: &str = "NEMO_RELAY_KERNEL_CREDENTIAL";
/// Largest frame this host will accept, when it should be smaller than the
/// protocol's ceiling.
///
/// Set by whoever starts the host, because the size a process is willing to
/// receive is its own decision: the handshake then negotiates the smaller of
/// this and what the kernel offers, and both sides carry one number afterwards.
const FRAME_BYTES: &str = "NEMO_RELAY_PLUGIN_HOST_FRAME_BYTES";
/// How many forwarded marks this host may hold before it stops accepting more.
///
/// The marks come from a plugin and the drain comes from a socket, so the queue
/// is the buffer between two speeds neither of which this process controls. A
/// bound is what keeps a plugin that emits faster than the kernel reads from
/// growing this process without limit; the value is large enough that an
/// ordinary burst is absorbed and small enough to be a bound.
const MARK_QUEUE_CAPACITY: &str = "NEMO_RELAY_PLUGIN_HOST_MARK_QUEUE";
/// Pending marks a host holds when nothing said otherwise.
const DEFAULT_MARK_QUEUE_CAPACITY: usize = 1024;

fn main() -> ExitCode {
    let socket = match std::env::var_os(SOCKET) {
        Some(socket) => PathBuf::from(socket),
        None => {
            eprintln!("{SOCKET} is not set: this process serves one supervisor's socket");
            return ExitCode::from(2);
        }
    };
    let credential = std::env::var(CREDENTIAL).unwrap_or_default();
    if credential.is_empty() {
        eprintln!(
            "{CREDENTIAL} is not set: a host without a credential cannot tell the kernel apart"
        );
        return ExitCode::from(2);
    }
    let maximum_frame_bytes = match std::env::var(FRAME_BYTES) {
        Ok(value) => match value.parse::<u32>() {
            Ok(limit) if limit > 0 && limit <= nemo_relay_plugin_protocol::MAX_FRAME_BYTES => limit,
            Ok(limit) => {
                eprintln!(
                    "{FRAME_BYTES} is {limit}: a host accepts between 1 and {} bytes",
                    nemo_relay_plugin_protocol::MAX_FRAME_BYTES
                );
                return ExitCode::from(2);
            }
            Err(_) => {
                eprintln!("{FRAME_BYTES} is not a number: {value}");
                return ExitCode::from(2);
            }
        },
        Err(_) => nemo_relay_plugin_protocol::MAX_FRAME_BYTES,
    };
    let config = PluginHostConfig {
        protocol_version: match std::env::var(PROTOCOL) {
            Ok(version) => match version.parse() {
                Ok(version) => version,
                Err(_) => {
                    eprintln!("{PROTOCOL} is not a protocol version: {version}");
                    return ExitCode::from(2);
                }
            },
            Err(_) => PROTOCOL_VERSION,
        },
        runtime_binding_digest: std::env::var(BINDING).unwrap_or_default(),
        session_credential: credential,
        maximum_frame_bytes,
    };
    // A capacity of zero is refused rather than treated as a default: it would
    // mean "accept no mark at all", which is not a bound anybody meant.
    let mark_queue_capacity = match std::env::var(MARK_QUEUE_CAPACITY) {
        Ok(value) => match value.parse::<usize>() {
            Ok(capacity) if capacity > 0 => capacity,
            Ok(_) => {
                eprintln!(
                    "{MARK_QUEUE_CAPACITY} is zero: a host that queues nothing serves nothing"
                );
                return ExitCode::from(2);
            }
            Err(_) => {
                eprintln!("{MARK_QUEUE_CAPACITY} is not a number: {value}");
                return ExitCode::from(2);
            }
        },
        Err(_) => DEFAULT_MARK_QUEUE_CAPACITY,
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to start the host runtime: {error}");
            return ExitCode::from(1);
        }
    };
    // A host belongs to the kernel that started it, and nothing else keeps it
    // alive: a kernel that exits — cleanly, by crashing, or by being killed —
    // closes the write end of this pipe, and a host that stayed after that would
    // be a process nobody owns, holding a socket nobody reads. The supervisor
    // also kills the child when it drops; this is what covers the case where it
    // never gets to.
    std::thread::spawn(|| {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut byte = [0u8; 1];
        let _ = stdin.read(&mut byte);
        std::process::exit(0);
    });
    runtime.block_on(async move {
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("failed to bind {}: {error}", socket.display());
                return ExitCode::from(1);
            }
        };
        // The backend this process serves is the in-process loader: it is the
        // same code the kernel ran before this boundary existed, which is what
        // makes the two comparable while the loader is still in the kernel's
        // dependency graph.
        let backend = std::sync::Arc::new(InProcessPluginBackend::new());
        // The kernel's own socket: a plugin's marks belong to the kernel's event
        // stream, so this process forwards them rather than emitting them into a
        // runtime whose subscribers nobody reads. A host started without one
        // emits them locally, which is all a host outside a kernel can do.
        let forwarding = match (
            std::env::var_os(KERNEL_SOCKET).map(PathBuf::from),
            std::env::var(KERNEL_CREDENTIAL),
        ) {
            (Some(endpoint), Ok(kernel_credential)) if !kernel_credential.is_empty() => {
                match nemo_relay_plugin_host::runtime_service::connect_to_kernel(
                    &endpoint,
                    config.maximum_frame_bytes,
                )
                .await
                {
                    Ok(mut client) => {
                        // The same connection serves both callbacks: the marks a
                        // plugin raises and the continuation of a call it wraps.
                        // The continuation gets its own client handle so a long
                        // wrapped call cannot hold up the mark queue behind it.
                        let callbacks = nemo_relay_plugin_host::runtime_service::KernelCallbacks::new(
                            client.clone(),
                            &kernel_credential,
                        )
                        // Remembering the endpoint is what lets a caller on another runtime
                        // — the codec bridge, whose thread blocks on the answer — open its
                        // own connection there instead of waiting on this runtime's tasks.
                        .map(|callbacks| callbacks.with_reconnect(endpoint.clone(), config.maximum_frame_bytes))
                        .map_err(|error| {
                            eprintln!("{KERNEL_CREDENTIAL} is unusable: {error}");
                            ExitCode::from(2)
                        });
                        let callbacks = match callbacks {
                            Ok(callbacks) => callbacks,
                            Err(code) => return code,
                        };
                        let (sender, mut steps) =
                            tokio::sync::mpsc::channel::<ForwardedStep>(mark_queue_capacity);
                        tokio::spawn(async move {
                            let mut failure: Option<String> = None;
                            while let Some(step) = steps.recv().await {
                                match step {
                                    ForwardedStep::Mark { session_id, mark } => {
                                        if failure.is_some() {
                                            // Already unusable: keep draining so a
                                            // flush reports the first fault rather
                                            // than waiting for a mark that will not
                                            // be sent.
                                            continue;
                                        }
                                        let wire =
                                            nemo_relay_plugin_proto::convert::mark_request_to_wire(
                                                &mark,
                                                &session_id,
                                            );
                                        let mut request = tonic::Request::new(wire);
                                        match kernel_credential.parse() {
                                            Ok(value) => {
                                                request.metadata_mut().insert(
                                                    nemo_relay_plugin_host::runtime_service::SESSION_CREDENTIAL_HEADER,
                                                    value,
                                                );
                                            }
                                            Err(error) => {
                                                failure =
                                                    Some(format!("unusable credential: {error}"));
                                                continue;
                                            }
                                        }
                                        if let Err(status) = client.emit_mark(request).await {
                                            failure = Some(status.to_string());
                                        }
                                    }
                                    ForwardedStep::Flush { done } => {
                                        let _ = done.send(failure.take().map_or(Ok(()), Err));
                                    }
                                }
                            }
                        });
                        Some((sender, callbacks))
                    }
                    Err(error) => {
                        eprintln!(
                            "failed to reach the kernel at '{}': {error}",
                            endpoint.display()
                        );
                        None
                    }
                }
            }
            _ => None,
        };
        // The transport decoder is configured from the same limit the handshake
        // negotiates. A transport default that disagreed with the protocol would
        // make the negotiated frame size declarative rather than enforced.
        let frame_limit = config.maximum_frame_bytes as usize;
        let service = PluginHostService::new(backend, config);
        let service = match forwarding {
            Some((sender, callbacks)) => service
                .with_mark_forwarding(sender)
                .with_kernel_callbacks(callbacks),
            None => service,
        };
        let served = Server::builder()
            .add_service(
                PluginHostServer::new(service)
                    .max_decoding_message_size(frame_limit)
                    .max_encoding_message_size(frame_limit),
            )
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await;
        match served {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("the plugin host stopped serving: {error}");
                ExitCode::from(1)
            }
        }
    })
}
