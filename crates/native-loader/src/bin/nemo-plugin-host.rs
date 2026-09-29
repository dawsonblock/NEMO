// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Platform entry point for the native plugin host executable.

use std::process::ExitCode;

#[cfg(unix)]
#[path = "unix/nemo-plugin-host.rs"]
mod unix_host;

#[cfg(unix)]
fn main() -> ExitCode {
    unix_host::run()
}

#[cfg(windows)]
fn main() -> ExitCode {
    eprintln!("native plugin process isolation is unsupported on windows");
    ExitCode::from(2)
}
