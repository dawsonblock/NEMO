// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Adaptive learners that derive runtime hints from observed executions.

/// Learner that builds latency sensitivity hints from run history.
pub mod latency;
/// Common learner trait implemented by adaptive background processors.
pub mod traits;

#[cfg(test)]
#[path = "../../tests/unit/learner_tests.rs"]
mod tests;
