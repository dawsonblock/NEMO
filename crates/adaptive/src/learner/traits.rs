// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared learner traits for adaptive background processing.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use crate::error::Result;
use crate::storage::traits::StorageBackendDyn;
use crate::types::cache::HotCache;
use crate::types::records::RunRecord;

/// Background learner that updates adaptive state from observed runs.
pub trait Learner: Send + Sync + 'static {
    /// Process one observed run and update backend state plus the hot cache.
    ///
    /// # Parameters
    /// - `run`: Telemetry record to learn from.
    /// - `backend`: Storage backend used to persist learner state.
    /// - `hot_cache`: Shared in-memory cache to refresh with the latest results.
    ///
    /// # Returns
    /// A future that resolves when the learner has finished processing the run.
    fn process_run<'a>(
        &'a self,
        run: &'a RunRecord,
        backend: &'a dyn StorageBackendDyn,
        hot_cache: &'a Arc<RwLock<HotCache>>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}
