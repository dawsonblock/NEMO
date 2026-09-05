// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serializable adaptive runtime data models.

/// Hot-cache structures used by the adaptive runtime on the intercept path.
pub mod cache;
/// Metadata and hint payloads attached to adaptive execution plans.
pub mod metadata;
/// Execution-plan types describing discovered tool parallelism.
pub mod plan;
/// Run and call record types collected by the telemetry pipeline.
pub mod records;

#[cfg(test)]
#[path = "../../tests/unit/types_tests.rs"]
mod tests;
