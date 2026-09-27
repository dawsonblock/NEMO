// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The native plugin ABI's own crate.
//!
//! What is here so far is its vocabulary: the revisions a host can carry, named so
//! that a check reads as "this table predates that feature" rather than as a
//! comparison of numbers nobody can date, and the status codes both sides report.
//! The versioned tables and the structs that cross the boundary follow — this
//! crate exists first so that they have somewhere to go, and so that the re-export
//! path every plugin author already compiles against is proven to survive the
//! move.
//!
//! The separation is the point rather than the size: an ABI that lives in the
//! same crate as its host-side implementation cannot be frozen independently of
//! it, and a frozen table is what a built plugin depends on.

/// Native plugin ABI version supported by this crate.
///
/// Version 4 adds completion-scoped codecs, pull-based LLM streams, extended
/// mark emission, runtime diagnostics, and activation-owned runtime-registration
/// discovery and dynamic conditional middleware guardrail control. Version 5 adds
/// the mark window: an invocation-scoped attribution context the host captures and
/// a plugin carries across its own asynchronous work, so a mark raised outside the
/// synchronous call that created a callback still belongs to the operation whose
/// callback raised it. Hosts retain frozen version-4, version-3 and version-2
/// tables for already-built plugins that target those layouts.
pub const NEMO_RELAY_NATIVE_ABI_VERSION: u32 = 5;
/// ABI version that introduced completion-based asynchronous middleware.
pub const NEMO_RELAY_NATIVE_ABI_VERSION_ASYNC_MIDDLEWARE: u32 = 3;
/// ABI version that introduced the v4 host extension: completion-scoped codecs,
/// pull-based LLM streams, extended mark emission, runtime diagnostics, and
/// activation-owned dynamic gate control.
pub const NEMO_RELAY_NATIVE_ABI_VERSION_COMPLETION_CODECS: u32 = 4;

/// Legacy native plugin ABI accepted by Relay hosts for compatibility.
pub const NEMO_RELAY_NATIVE_ABI_VERSION_LEGACY: u32 = 2;

/// Status codes returned by stable native ABI functions.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NemoRelayStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// A resource with the given name already exists.
    AlreadyExists = 1,
    /// The requested resource was not found.
    NotFound = 2,
    /// The scope stack is empty.
    ScopeStackEmpty = 3,
    /// A guardrail rejected the operation.
    GuardrailRejected = 4,
    /// An internal runtime error occurred.
    Internal = 5,
    /// A required pointer argument was null.
    NullPointer = 6,
    /// A JSON string argument could not be parsed.
    InvalidJson = 7,
    /// A string argument contained invalid UTF-8.
    InvalidUtf8 = 8,
    /// A function argument had an invalid value.
    InvalidArg = 9,
    /// A stream reached end-of-stream and has no chunk to return.
    StreamEnd = 10,
    /// A bounded stream queue is full; retry this operation after it advances.
    Backpressured = 11,
}
