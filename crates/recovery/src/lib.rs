// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Recovery controller scaffolding for durable effect reconciliation.

#[cfg(feature = "unstable-hardening")]
/// Experimental recovery-controller contracts.
pub mod unstable {
    use nemo_relay_ledger::unstable::{ActionLease, ExecutionState};
    use std::collections::HashSet;

    /// Durable action selected by recovery discovery.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RecoveryCandidate {
        /// Stable durable action identifier.
        pub action_id: String,
        /// Current lifecycle state observed at discovery time.
        pub state: ExecutionState,
        /// Last known reconciliation attempts.
        pub reconciliation_attempts: u64,
        /// Earliest time this candidate should be retried.
        pub next_reconciliation_at_unix_ms: Option<u64>,
    }

    /// Result of reconciling one durable action.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RecoveryDisposition {
        /// Recovery reached a conclusive terminal state.
        Conclusive,
        /// Recovery remained uncertain and should be retried later.
        Inconclusive,
        /// Recovery escalated for operator review.
        Escalated,
    }

    /// Recovery queue execution limits.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RecoveryControllerConfig {
        /// Maximum candidates processed in one scan cycle.
        pub batch_size: usize,
    }

    impl Default for RecoveryControllerConfig {
        fn default() -> Self {
            Self { batch_size: 128 }
        }
    }

    /// Recovery candidate discovery boundary.
    pub trait RecoveryScanner {
        /// Adapter-specific failure type.
        type Error;

        /// Discover reconcilable actions in bounded batches.
        fn scan_candidates(
            &self,
            now_unix_ms: u64,
            limit: usize,
        ) -> Result<Vec<RecoveryCandidate>, Self::Error>;
    }

    /// Recovery scheduler persistence boundary.
    pub trait RecoveryScheduler {
        /// Adapter-specific failure type.
        type Error;

        /// Persist a deterministic update after one recovery attempt.
        fn record_attempt(
            &self,
            action_id: &str,
            now_unix_ms: u64,
            disposition: RecoveryDisposition,
            error: Option<&str>,
        ) -> Result<(), Self::Error>;
    }

    /// Kernel boundary for one fenced recovery attempt.
    pub trait RecoveryKernel {
        /// Adapter-specific failure type.
        type Error;

        /// Recover one action under a reconciliation lease.
        fn recover_action(
            &self,
            action_id: &str,
            lease: &ActionLease,
        ) -> Result<RecoveryDisposition, Self::Error>;
    }

    /// Production recovery coordinator for bounded reconciliation loops.
    pub struct RecoveryController<S, C, K> {
        scanner: S,
        scheduler: C,
        kernel: K,
        config: RecoveryControllerConfig,
    }

    impl<S, C, K> RecoveryController<S, C, K> {
        /// Construct a new bounded recovery coordinator.
        pub fn new(scanner: S, scheduler: C, kernel: K, config: RecoveryControllerConfig) -> Self {
            Self {
                scanner,
                scheduler,
                kernel,
                config,
            }
        }
    }

    impl<S, C, K, SE, CE, KE> RecoveryController<S, C, K>
    where
        S: RecoveryScanner<Error = SE>,
        C: RecoveryScheduler<Error = CE>,
        K: RecoveryKernel<Error = KE>,
        SE: std::error::Error + Send + Sync + 'static,
        CE: std::error::Error + Send + Sync + 'static,
        KE: std::error::Error + Send + Sync + 'static,
    {
        /// Run one bounded scan/process cycle.
        pub fn run_once(&self, now_unix_ms: u64, owner_id: &str) -> Result<usize, RecoveryError> {
            let mut processed = 0usize;
            let candidates = self
                .scanner
                .scan_candidates(now_unix_ms, self.config.batch_size)
                .map_err(|error| RecoveryError::Scan(Box::new(error)))?;
            let mut seen = HashSet::new();

            for candidate in candidates {
                if !seen.insert(candidate.action_id.clone()) {
                    continue;
                }
                let lease = ActionLease {
                    owner_id: owner_id.to_owned(),
                    generation: candidate.reconciliation_attempts,
                    expires_at_unix_ms: now_unix_ms.saturating_add(30_000),
                };
                let disposition = self
                    .kernel
                    .recover_action(&candidate.action_id, &lease)
                    .map_err(|error| RecoveryError::Recover(Box::new(error)))?;
                self.scheduler
                    .record_attempt(&candidate.action_id, now_unix_ms, disposition, None)
                    .map_err(|error| RecoveryError::Schedule(Box::new(error)))?;
                processed = processed.saturating_add(1);
            }

            Ok(processed)
        }
    }

    /// Unified recovery-controller failure.
    #[derive(Debug)]
    pub enum RecoveryError {
        /// Candidate discovery failed.
        Scan(Box<dyn std::error::Error + Send + Sync + 'static>),
        /// Kernel reconciliation failed.
        Recover(Box<dyn std::error::Error + Send + Sync + 'static>),
        /// Attempt scheduling persistence failed.
        Schedule(Box<dyn std::error::Error + Send + Sync + 'static>),
    }

    impl std::fmt::Display for RecoveryError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Scan(error) => write!(formatter, "recovery scan failed: {error}"),
                Self::Recover(error) => write!(formatter, "recovery kernel failed: {error}"),
                Self::Schedule(error) => write!(formatter, "recovery scheduling failed: {error}"),
            }
        }
    }

    impl std::error::Error for RecoveryError {}
}
