// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loading native NeMo Relay plugins, and activating them in the host that does.
//!
//! This crate is the loader: it opens a `cdylib` an operator approved, checks the
//! bytes against the approval, negotiates the ABI revision with the plugin's entry
//! symbol, installs the plugin's registrations through the hosted-runtime seam, and
//! — in [`host`] — composes those registrations with a runtime configuration as one
//! activation transaction.
//!
//! It lives outside the kernel on purpose. Everything it needs from the kernel it
//! asks for through `nemo_relay::plugin::dynamic::NativeHostRuntime`, which is where
//! the decisions about registration ownership, invocation context, artifact
//! verification and compatibility live; the kernel, in turn, does not depend on this
//! crate, so a kernel process cannot link `dlopen` at all. The ABI it speaks is
//! `nemo-relay-native-abi`.
//!
//! `ALLOWED_INTERNALS`-style questions about what this crate may name are answered
//! by the seam's own tests in the kernel crate: the loader's reach into the runtime
//! is the operations on that handle and nothing else.

mod host;
mod native;

pub use host::{DynamicPluginActivationSpec, PluginHostActivation};
pub use native::*;
