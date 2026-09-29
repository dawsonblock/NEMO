// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Startup behavior checks for the native plugin host executable.
#![cfg(unix)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A requested callback connection failure must prevent partial host service.
#[test]
fn a_requested_kernel_callback_connection_failure_stops_host_startup() {
    let temporary = tempfile::tempdir().expect("temporary host socket directory");
    let host_socket = temporary.path().join("host.sock");
    let missing_kernel_socket = temporary.path().join("missing-kernel.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_nemo-plugin-host"))
        .env("NEMO_RELAY_PLUGIN_HOST_SOCKET", &host_socket)
        .env("NEMO_RELAY_PLUGIN_HOST_CREDENTIAL", "host-credential")
        .env("NEMO_RELAY_KERNEL_SOCKET", &missing_kernel_socket)
        .env("NEMO_RELAY_KERNEL_CREDENTIAL", "kernel-credential")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch the plugin host");
    let _stdin = child.stdin.take().expect("hold the supervisor pipe open");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().expect("poll plugin host").is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "host startup did not fail promptly"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("collect host output");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to reach the kernel"),
        "startup must name the failed callback connection: {stderr}"
    );
}
