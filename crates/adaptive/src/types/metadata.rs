// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Metadata and hint payload types used by adaptive planning.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JSON value alias used by adaptive metadata payloads.
pub type Json = serde_json::Value;

/// Metadata template attached to an adaptive execution plan.
///
/// This payload is copied into run-level metadata snapshots and carries
/// parallelism hints plus any backend- or integration-specific extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataEnvelope {
    /// Run identifier the metadata template was last derived from.
    pub run_id: Uuid,
    /// Agent identifier the template applies to.
    pub agent_id: String,
    /// Tool parallelism hints discovered for the agent.
    pub parallel_hints: Vec<ParallelHint>,
    /// Arbitrary caller-defined metadata extensions.
    pub extensions: Json,
}

/// Hint describing one tool's membership in a parallel-execution cohort.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelHint {
    /// Tool name that participates in the hinted group.
    pub tool_name: String,
    /// Stable group identifier shared by all tools in the cohort.
    pub group_id: String,
    /// Whether the hint was explicitly authored rather than inferred.
    pub explicit: bool,
}

/// Runtime hint bundle exposed to downstream integrations.
///
/// These values summarize the current learned default behavior for an agent and
/// are suitable for transport in provider-specific headers or metadata fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHints {
    /// Output-size limit hint in tokens.
    pub osl: u32,
    /// Inter-arrival-time hint in milliseconds.
    pub iat: u32,
    /// Scheduling priority hint derived from latency sensitivity.
    pub priority: i32,
    /// Learned latency sensitivity score for the current prefix.
    pub latency_sensitivity: f64,
    /// Identifier of the prefix or trie node the hints came from.
    pub prefix_id: String,
    /// Estimated total number of requests in the workflow.
    pub total_requests: u32,
}
