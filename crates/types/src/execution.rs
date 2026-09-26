// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Dispatch-certainty vocabulary shared across the execution boundary.
//!
//! These two enums decide whether an effect may be retried, so more than one
//! layer needs them: the kernel classifies a backend error with them, and the
//! plugin contract has to report them so a plugin failure cannot be mistaken for
//! a definite outcome. They live here rather than beside the classifier because
//! a contract crate cannot depend on an adapter, and duplicating a
//! security-relevant classification is how the two copies drift apart.
//!
//! [`crate::execution::DispatchState`] and [`crate::execution::OutcomeCertainty`]
//! answer different questions and must not be collapsed: the first says whether
//! the external system may have been contacted, the second says whether the
//! runtime can prove what happened. An effect that was definitely dispatched and
//! definitely failed is a different case from one that was never dispatched, and
//! both are different from one nobody can account for.

use serde::{Deserialize, Serialize};

/// Dispatch certainty at the external-effect boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DispatchState {
    /// The provider was not contacted.
    NotDispatched,
    /// Dispatch was attempted but acceptance is not proven.
    DispatchAttempted,
    /// The provider accepted the dispatch, but completion may remain unknown.
    DispatchConfirmed,
}

/// Certainty about the external effect outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutcomeCertainty {
    /// The effect definitely did not commit.
    ConfirmedFailure,
    /// The effect definitely committed.
    ConfirmedSuccess,
    /// The runtime cannot prove success or failure.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_certainty_survives_a_round_trip() {
        for state in [
            DispatchState::NotDispatched,
            DispatchState::DispatchAttempted,
            DispatchState::DispatchConfirmed,
        ] {
            let encoded = serde_json::to_string(&state).expect("encode dispatch state");
            let decoded: DispatchState =
                serde_json::from_str(&encoded).expect("decode dispatch state");
            assert_eq!(decoded, state);
        }
    }

    #[test]
    fn dispatch_state_and_outcome_certainty_are_not_interchangeable() {
        // Pinned so that a later "simplification" that merges the two has to
        // delete a test that says why they are separate.
        assert_eq!(
            serde_json::to_string(&DispatchState::NotDispatched).expect("encode"),
            r#""NOT_DISPATCHED""#
        );
        assert_eq!(
            serde_json::to_string(&OutcomeCertainty::ConfirmedFailure).expect("encode"),
            r#""CONFIRMED_FAILURE""#
        );
    }
}
