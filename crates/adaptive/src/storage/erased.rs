// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Type-erased storage backend aliases.

/// Type-erased adaptive storage backend.
///
/// This alias is used by runtime configuration code when the concrete backend
/// type does not matter and only the [`crate::storage::traits::StorageBackendDyn`]
/// contract is required.
pub type AnyBackend = Box<dyn crate::storage::traits::StorageBackendDyn + Send + Sync>;
