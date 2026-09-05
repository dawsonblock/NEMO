// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory adaptive storage backend.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::RwLock;

use crate::error::{AdaptiveError, Result};
use crate::storage::traits::{StorageBackend, StorageBackendDyn};
use crate::trie::accumulator::AccumulatorState;
use crate::trie::serialization::TrieEnvelope;
use crate::types::plan::ExecutionPlan;
use crate::types::records::RunRecord;

/// In-memory backend storing adaptive state in process-local hash maps.
///
/// This backend is primarily useful for tests, examples, or deployments where
/// adaptive state does not need to survive process restarts.
pub struct InMemoryBackend {
    runs: RwLock<HashMap<String, Vec<RunRecord>>>,
    plans: RwLock<HashMap<String, ExecutionPlan>>,
    tries: RwLock<HashMap<String, TrieEnvelope>>,
    accumulators: RwLock<HashMap<String, AccumulatorState>>,
    observations: RwLock<HashMap<String, Vec<crate::acg::prompt_ir::PromptIR>>>,
    stability: RwLock<HashMap<String, crate::acg::stability::StabilityAnalysisResult>>,
}

impl InMemoryBackend {
    /// Create an empty in-memory backend.
    ///
    /// # Returns
    /// A new [`InMemoryBackend`] with empty storage maps.
    pub fn new() -> Self {
        Self {
            runs: RwLock::new(HashMap::new()),
            plans: RwLock::new(HashMap::new()),
            tries: RwLock::new(HashMap::new()),
            accumulators: RwLock::new(HashMap::new()),
            observations: RwLock::new(HashMap::new()),
            stability: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryBackend {
    fn store_run(&self, record: &RunRecord) -> impl Future<Output = Result<()>> + Send {
        let result = {
            let mut guard = self
                .runs
                .write()
                .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")));
            match guard {
                Ok(ref mut runs) => {
                    runs.entry(record.agent_id.clone())
                        .or_default()
                        .push(record.clone());
                    Ok(())
                }
                Err(error) => Err(error),
            }
        };
        async move { result }
    }

    fn load_plan(
        &self,
        agent_id: &str,
    ) -> impl Future<Output = Result<Option<ExecutionPlan>>> + Send {
        let result = {
            let guard = self
                .plans
                .read()
                .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")));
            match guard {
                Ok(ref plans) => Ok(plans.get(agent_id).cloned()),
                Err(error) => Err(error),
            }
        };
        async move { result }
    }

    fn list_runs(&self, agent_id: &str) -> impl Future<Output = Result<Vec<RunRecord>>> + Send {
        let result = {
            let guard = self
                .runs
                .read()
                .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")));
            match guard {
                Ok(ref runs) => Ok(runs.get(agent_id).cloned().unwrap_or_default()),
                Err(error) => Err(error),
            }
        };
        async move { result }
    }
}

impl StorageBackendDyn for InMemoryBackend {
    fn store_run_dyn<'a>(
        &'a self,
        record: &'a RunRecord,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.store_run(record))
    }

    fn load_plan_dyn<'a>(
        &'a self,
        agent_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ExecutionPlan>>> + Send + 'a>> {
        Box::pin(self.load_plan(agent_id))
    }

    fn list_runs_dyn<'a>(
        &'a self,
        agent_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<RunRecord>>> + Send + 'a>> {
        Box::pin(self.list_runs(agent_id))
    }

    fn store_trie<'a>(
        &'a self,
        agent_id: &'a str,
        envelope: &'a TrieEnvelope,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let result = {
            let mut guard = self
                .tries
                .write()
                .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")));
            match guard {
                Ok(ref mut tries) => {
                    tries.insert(agent_id.to_string(), envelope.clone());
                    Ok(())
                }
                Err(error) => Err(error),
            }
        };
        Box::pin(async move { result })
    }

    fn load_trie<'a>(
        &'a self,
        agent_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<TrieEnvelope>>> + Send + 'a>> {
        let result = {
            let guard = self
                .tries
                .read()
                .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")));
            match guard {
                Ok(ref tries) => Ok(tries.get(agent_id).cloned()),
                Err(error) => Err(error),
            }
        };
        Box::pin(async move { result })
    }

    fn store_accumulators<'a>(
        &'a self,
        agent_id: &'a str,
        state: &'a AccumulatorState,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let result = {
            let mut guard = self
                .accumulators
                .write()
                .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")));
            match guard {
                Ok(ref mut accumulators) => {
                    accumulators.insert(agent_id.to_string(), state.clone());
                    Ok(())
                }
                Err(error) => Err(error),
            }
        };
        Box::pin(async move { result })
    }

    fn load_accumulators<'a>(
        &'a self,
        agent_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<AccumulatorState>>> + Send + 'a>> {
        let result = {
            let guard = self
                .accumulators
                .read()
                .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")));
            match guard {
                Ok(ref accumulators) => Ok(accumulators.get(agent_id).cloned()),
                Err(error) => Err(error),
            }
        };
        Box::pin(async move { result })
    }

    fn store_plan(&self, plan: &ExecutionPlan) -> Result<()> {
        let mut guard = self
            .plans
            .write()
            .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")))?;
        guard.insert(plan.agent_id.clone(), plan.clone());
        Ok(())
    }

    fn store_observations<'a>(
        &'a self,
        agent_id: &'a str,
        observations: &'a [crate::acg::prompt_ir::PromptIR],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let result = {
            let mut guard = self
                .observations
                .write()
                .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")));
            match guard {
                Ok(ref mut observations_map) => {
                    observations_map.insert(agent_id.to_string(), observations.to_vec());
                    Ok(())
                }
                Err(error) => Err(error),
            }
        };
        Box::pin(async move { result })
    }

    fn load_observations<'a>(
        &'a self,
        agent_id: &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<Vec<crate::acg::prompt_ir::PromptIR>>>> + Send + 'a>,
    > {
        let result = {
            let guard = self
                .observations
                .read()
                .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")));
            match guard {
                Ok(ref observations_map) => Ok(observations_map.get(agent_id).cloned()),
                Err(error) => Err(error),
            }
        };
        Box::pin(async move { result })
    }

    fn store_stability<'a>(
        &'a self,
        agent_id: &'a str,
        result: &'a crate::acg::stability::StabilityAnalysisResult,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let store_result = {
            let mut guard = self
                .stability
                .write()
                .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")));
            match guard {
                Ok(ref mut stability_map) => {
                    stability_map.insert(agent_id.to_string(), result.clone());
                    Ok(())
                }
                Err(error) => Err(error),
            }
        };
        Box::pin(async move { store_result })
    }

    fn load_stability<'a>(
        &'a self,
        agent_id: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<crate::acg::stability::StabilityAnalysisResult>>>
                + Send
                + 'a,
        >,
    > {
        let result = {
            let guard = self
                .stability
                .read()
                .map_err(|error| AdaptiveError::Internal(format!("lock poisoned: {error}")));
            match guard {
                Ok(ref stability_map) => Ok(stability_map.get(agent_id).cloned()),
                Err(error) => Err(error),
            }
        };
        Box::pin(async move { result })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/storage_memory_internal_tests.rs"]
mod tests;
