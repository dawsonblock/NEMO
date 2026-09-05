// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Storage backends for adaptive runtime state and learned artifacts.

/// Erased backend alias used by runtime configuration and dependency injection.
pub mod erased;
/// In-memory backend useful for tests and local-only runtime state.
pub mod memory;
/// Async storage traits implemented by adaptive persistence backends.
pub mod traits;

#[cfg(test)]
#[path = "../../tests/unit/storage_tests.rs"]
mod tests;
