// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Adaptive execution-plan data models.

use serde::{Deserialize, Serialize};

use crate::types::metadata::MetadataEnvelope;

/// Group of tools that have been observed to run in parallel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelGroup {
    /// Stable identifier for the parallel group.
    pub group_id: String,
    /// Tool names that belong to the group.
    pub tool_names: Vec<String>,
}

/// Learned execution plan for an agent.
///
/// The plan captures discovered tool fan-outs and the metadata template used to
/// expose those discoveries to later runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    /// Agent identifier the plan applies to.
    pub agent_id: String,
    /// Parallel groups learned for the agent.
    pub parallel_groups: Vec<ParallelGroup>,
    /// Metadata template emitted alongside the plan.
    pub metadata_template: MetadataEnvelope,
}
