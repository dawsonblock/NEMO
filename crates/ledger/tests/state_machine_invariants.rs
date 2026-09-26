// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exhaustive checks over the consequential-effect state machine.
//!
//! The lifecycle predicates are where several kernel invariants are enforced:
//! only defined transitions are legal (K-001), a proven pre-dispatch failure is
//! the only route to `FAILED` once dispatch has begun (K-015), and a possibly
//! dispatched action becomes `UNKNOWN` rather than `FAILED` (K-016). Those are
//! exactly the properties the 0.10 refactor has to preserve while it moves code
//! between crates, so this file checks every ordered pair of states against
//! every predicate instead of the handful of pairs an example test covers.
//!
//! The state space is nine states, so "every pair" is 81 cases per predicate.
//! That is cheap enough to run on every commit, and exhaustive enough that a
//! loosened transition cannot slip through unnoticed.
//!
//! The predicates live behind the `unstable-hardening` feature, so this file is
//! compiled only when that feature is on. Workspace builds enable it through
//! `nemo-effect-runtime`, which is why `just test-rust` exercises these checks.
//! Running the crate alone reports zero tests unless the feature is named:
//! `cargo test -p nemo-relay-ledger --features unstable-hardening`.

#![cfg(feature = "unstable-hardening")]

use nemo_relay_ledger::unstable::{
    ExecutionState, is_leaseable_state, is_valid_authorization_transition,
    is_valid_generic_transition, is_valid_leased_transition, is_valid_lifecycle_transition,
    is_valid_pre_dispatch_failure_finalization,
};

/// Every lifecycle state, taken from the enum's own enumeration.
///
/// The list lives with the enum so the state space has one definition. The
/// exhaustive `name` match below still fails to compile if a variant is added,
/// which is what forces `ExecutionState::ALL` to be extended too.
const ALL: [ExecutionState; 9] = ExecutionState::ALL;

/// States that end the lifecycle.
const TERMINAL: [ExecutionState; 3] = [
    ExecutionState::Committed,
    ExecutionState::Failed,
    ExecutionState::Cancelled,
];

fn name(state: ExecutionState) -> &'static str {
    match state {
        ExecutionState::Proposed => "PROPOSED",
        ExecutionState::Authorized => "AUTHORIZED",
        ExecutionState::Prepared => "PREPARED",
        ExecutionState::Dispatching => "DISPATCHING",
        ExecutionState::Committed => "COMMITTED",
        ExecutionState::Failed => "FAILED",
        ExecutionState::Unknown => "UNKNOWN",
        ExecutionState::Reconciling => "RECONCILING",
        ExecutionState::Cancelled => "CANCELLED",
    }
}

#[test]
fn every_variant_is_covered_exactly_once() {
    let mut names: Vec<&str> = ALL.iter().map(|state| name(*state)).collect();
    names.sort_unstable();
    names.dedup();

    assert_eq!(
        names.len(),
        ALL.len(),
        "ALL must list every variant exactly once"
    );
}

#[test]
fn terminal_states_have_no_outgoing_transition() {
    for state in TERMINAL {
        for next in ALL {
            assert!(
                !is_valid_lifecycle_transition(Some(state), next),
                "{} must not reach {}",
                name(state),
                name(next)
            );
            assert!(
                !is_valid_generic_transition(state, next),
                "an unfenced update must not leave {}",
                name(state)
            );
            assert!(
                !is_valid_leased_transition(state, next),
                "a fenced lease must not leave {}",
                name(state)
            );
        }
    }
}

#[test]
fn the_terminal_set_is_exactly_the_states_with_no_successor() {
    let computed: Vec<&str> = ALL
        .iter()
        .filter(|state| {
            !ALL.iter()
                .any(|next| is_valid_lifecycle_transition(Some(**state), *next))
        })
        .map(|state| name(*state))
        .collect();

    assert_eq!(computed, ["COMMITTED", "FAILED", "CANCELLED"]);
}

#[test]
fn a_lifecycle_begins_only_with_proposed() {
    for next in ALL {
        assert_eq!(
            is_valid_lifecycle_transition(None, next),
            next == ExecutionState::Proposed,
            "an action must start at PROPOSED, not {}",
            name(next)
        );
    }
}

#[test]
fn narrower_predicates_never_invent_a_transition() {
    for current in ALL {
        for next in ALL {
            let in_graph = is_valid_lifecycle_transition(Some(current), next);
            let context = format!("{} -> {}", name(current), name(next));

            assert!(
                !is_valid_authorization_transition(current, next) || in_graph,
                "authorization allowed {context} outside the lifecycle graph"
            );
            assert!(
                !is_valid_generic_transition(current, next) || in_graph,
                "an unfenced update allowed {context} outside the lifecycle graph"
            );
            assert!(
                !is_valid_leased_transition(current, next) || in_graph,
                "a fenced lease allowed {context} outside the lifecycle graph"
            );
        }
    }
}

#[test]
fn only_evidence_backed_paths_can_reach_failed_after_dispatch() {
    for current in ALL {
        // A fenced lease may not terminalize failure: the fenced path handles
        // non-terminal movement, and failure needs evidence.
        assert!(
            !is_valid_leased_transition(current, ExecutionState::Failed),
            "a fenced lease must not move {} to FAILED",
            name(current)
        );
        // An unfenced update may not terminalize at all.
        assert!(
            !is_valid_generic_transition(current, ExecutionState::Failed),
            "an unfenced update must not move {} to FAILED",
            name(current)
        );
    }

    // Predecessors of FAILED in the graph are the dispatch and reconciliation
    // states; nothing before dispatch can reach it.
    let predecessors: Vec<&str> = ALL
        .iter()
        .filter(|state| is_valid_lifecycle_transition(Some(**state), ExecutionState::Failed))
        .map(|state| name(*state))
        .collect();

    assert_eq!(predecessors, ["DISPATCHING", "UNKNOWN", "RECONCILING"]);
}

#[test]
fn pre_dispatch_failure_finalization_is_exactly_the_dispatching_state() {
    for current in ALL {
        assert_eq!(
            is_valid_pre_dispatch_failure_finalization(current),
            current == ExecutionState::Dispatching,
            "pre-dispatch failure finalization must be limited to DISPATCHING, checked {}",
            name(current)
        );
    }

    // The sanctioned route to FAILED must also be legal in the graph itself.
    assert!(is_valid_lifecycle_transition(
        Some(ExecutionState::Dispatching),
        ExecutionState::Failed
    ));
}

#[test]
fn a_possibly_dispatched_action_has_a_non_failure_destination() {
    assert!(
        is_valid_lifecycle_transition(Some(ExecutionState::Dispatching), ExecutionState::Unknown),
        "DISPATCHING must be able to become UNKNOWN"
    );
    assert!(
        is_valid_leased_transition(ExecutionState::Dispatching, ExecutionState::Unknown),
        "a fenced lease must be able to record UNKNOWN"
    );
    assert!(
        !TERMINAL.contains(&ExecutionState::Unknown),
        "UNKNOWN is a claim about missing evidence, not a terminal outcome"
    );
}

#[test]
fn only_fenced_non_terminal_states_carry_a_lease() {
    for state in ALL {
        if is_leaseable_state(state) {
            assert!(
                !TERMINAL.contains(&state),
                "{} must not be leaseable",
                name(state)
            );
            assert!(
                !is_valid_leased_transition(state, ExecutionState::Failed),
                "a leased {} must not be able to finalize FAILED",
                name(state)
            );
        }
    }

    assert!(is_leaseable_state(ExecutionState::Dispatching));
    assert!(is_leaseable_state(ExecutionState::Unknown));
    assert!(!is_leaseable_state(ExecutionState::Proposed));
}
