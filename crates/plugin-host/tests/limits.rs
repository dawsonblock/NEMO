// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Evidence that the bounds a deployment states reach the process that runs a
//! plugin.
//!
//! Stated as a test rather than asserted in prose because the way it can go
//! wrong is quiet: `pre_exec` runs in the forked child, where a failure that is
//! not propagated leaves a host running with no bound at all. The child is
//! asked what it holds, through the same call the supervisor uses.

use std::os::unix::process::CommandExt;

use nemo_relay_plugin_host::limits::PluginHostLimits;

/// The limits reach the process they are applied to.
#[test]
fn the_limits_reach_the_process_they_are_applied_to() {
    let limits = PluginHostLimits {
        maximum_address_space_bytes: None,
        maximum_processes: None,
        maximum_open_files: Some(128),
        no_new_privileges: false,
    };
    let mut command = std::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("ulimit -n")
        .stdin(std::process::Stdio::null());
    // Safety: the closure runs in the forked child before `exec` and calls only
    // `setrlimit`, which is async-signal-safe, allocates nothing and takes no
    // locks.
    unsafe {
        command.pre_exec(move || nemo_relay_plugin_host::limits::apply(&limits));
    }
    let output = command.output().expect("a child started under the limits");
    assert!(output.status.success(), "the child ran: {output:?}");
    let reported = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        reported.trim(),
        "128",
        "the child holds the limit it was started with, not the one this process \
         has: {reported:?}"
    );
}
