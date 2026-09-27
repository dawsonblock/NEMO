// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loading native NeMo Relay plugins: the loader and the host process's own end.
//!
//! This crate is the child's package. It opens a `cdylib` an operator approved,
//! checks the bytes against the approval, negotiates the ABI revision with the
//! plugin's entry symbol, installs the plugin's registrations through the
//! hosted-runtime seam, composes those registrations with a runtime configuration
//! as one activation transaction, and — in [`service`] — serves all of that to the
//! kernel over the boundary protocol. The binary it builds, `nemo-plugin-host`, is
//! the process the supervisor starts.
//!
//! It lives outside the kernel on purpose. Everything it needs from the kernel it
//! asks for through `nemo_relay::plugin::dynamic::NativeHostRuntime`, which is where
//! the decisions about registration ownership, invocation context, artifact
//! verification and compatibility live; the kernel, in turn, does not depend on this
//! crate, so a kernel process cannot link `dlopen` at all. The ABI it speaks is
//! `nemo-relay-native-abi`.
//!
//! The supervisor's own side of the protocol is `nemo-relay-plugin-host`: it holds
//! the modules both ends share — capabilities, codec handles, continuations,
//! operation scopes, the runtime service — and this crate depends on it for them.
//! The reverse edge is the one the architecture test forbids, because it is the one
//! that would put a loader in the kernel's process.
//!
//! Questions about what this crate may name inside the kernel are answered by the
//! seam's own tests in the kernel crate: the reach into the runtime is the
//! operations on that handle and nothing else.

mod backend;
/// Test support for the confidentiality property across the boundary.
///
/// Nothing in a production build calls into this: it is the sentinel and the
/// helpers the boundary tests use — in this crate and in the supervisor's — to
/// prove a plugin cannot smuggle a value through. It is a public module for that
/// reason and not because it is part of the crate's interface.
pub mod confidentiality;
/// The conformance suite both ends of the protocol are held to.
///
/// It is public for the same reason `confidentiality` is: the supervisor's tests
/// run it against the process backend, this crate's tests run it against the
/// in-process one, and both are tests of the same contract.
pub mod conformance;
mod host;
mod native;
/// The service the host process serves the kernel's lifecycle operations on.
pub mod service;

pub use backend::{InProcessPluginBackend, LoadedPlugins, host_build};
pub use host::PluginHostActivation;
pub use native::*;
pub use service::{ForwardedStep, PluginHostConfig, PluginHostService};

/// The path to the child binary this crate builds.
///
/// `CARGO_BIN_EXE_<name>` is defined only for the package that owns the binary, and
/// the supervisor's tests live in another package, so the path is derived from the
/// running test's own directory instead — the same target directory, one level up
/// from `deps/`. It exists so that a test which needs to start a host process finds
/// the host this workspace built rather than guessing at a path.
#[must_use]
pub fn child_binary() -> std::path::PathBuf {
    let mut directory = std::env::current_exe().expect("the running test binary has a path");
    directory.pop();
    if directory.ends_with("deps") {
        directory.pop();
    }
    directory.join(format!("nemo-plugin-host{}", std::env::consts::EXE_SUFFIX))
}
