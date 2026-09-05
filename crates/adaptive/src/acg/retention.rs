// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Retention intent generation from observed session timing distributions.

use serde::{Deserialize, Serialize};

use crate::acg::profile::DistributionSummary;
use crate::acg::types::{RetentionIntent, RetentionTier, SharingScope};

/// Thresholds used to map observed timing into a retention tier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetentionThresholds {
    /// Maximum median session duration for the ephemeral tier, in seconds.
    pub ephemeral_max_secs: f64,
    /// Maximum median session duration for the short-lived tier, in seconds.
    pub short_lived_max_secs: f64,
    /// Maximum median session duration for the session-duration tier, in seconds.
    pub session_duration_max_secs: f64,
    /// Maximum median session duration for the long-lived tier, in seconds.
    pub long_lived_max_secs: f64,
}

impl Default for RetentionThresholds {
    fn default() -> Self {
        Self {
            ephemeral_max_secs: 5.0,
            short_lived_max_secs: 60.0,
            session_duration_max_secs: 600.0,
            long_lived_max_secs: 3600.0,
        }
    }
}

/// Generate a retention intent from observed session timing distributions.
///
/// The median session duration determines the recommended retention tier. The
/// median inter-call gap is copied into the returned intent for downstream
/// policy decisions.
///
/// # Parameters
/// - `session_duration`: Observed session-duration distribution.
/// - `inter_call_gap`: Observed inter-call-gap distribution.
/// - `thresholds`: Tier thresholds used to classify the session duration.
///
/// # Returns
/// A [`RetentionIntent`] summarizing the recommended retention policy.
pub fn generate_retention_intent(
    session_duration: &DistributionSummary,
    inter_call_gap: &DistributionSummary,
    thresholds: &RetentionThresholds,
) -> RetentionIntent {
    let tier = if session_duration.p50 <= thresholds.ephemeral_max_secs {
        RetentionTier::Ephemeral
    } else if session_duration.p50 <= thresholds.short_lived_max_secs {
        RetentionTier::ShortLived
    } else if session_duration.p50 <= thresholds.session_duration_max_secs {
        RetentionTier::SessionDuration
    } else if session_duration.p50 <= thresholds.long_lived_max_secs {
        RetentionTier::LongLived
    } else {
        RetentionTier::Permanent
    };

    RetentionIntent {
        recommended_tier: tier,
        expected_session_duration_secs: Some(session_duration.p50),
        inter_call_gap_p50_ms: Some(inter_call_gap.p50 * 1000.0),
        scope_label: SharingScope::Session,
    }
}

/// Generate a retention intent with the default thresholds.
///
/// # Parameters
/// - `session_duration`: Observed session-duration distribution.
/// - `inter_call_gap`: Observed inter-call-gap distribution.
///
/// # Returns
/// A [`RetentionIntent`] produced with [`RetentionThresholds::default`].
pub fn generate_retention_intent_default(
    session_duration: &DistributionSummary,
    inter_call_gap: &DistributionSummary,
) -> RetentionIntent {
    generate_retention_intent(
        session_duration,
        inter_call_gap,
        &RetentionThresholds::default(),
    )
}
