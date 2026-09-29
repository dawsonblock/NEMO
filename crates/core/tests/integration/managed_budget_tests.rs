// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The trusted budget a managed call publishes, and where that budget comes from.
//!
//! `with_execution_budget` and the proxy's read of it already existed, but
//! nothing on a real managed path published one, so a registration reached
//! through an ordinary tool call had no budget to inherit. The boundary now
//! resolves one from three sources — the deadline its parent published, the
//! durable action lease's expiry, and `now` plus the configured cap for that
//! kind of call — takes the smallest, and publishes it for the whole call.
//!
//! Two properties are the point of the file: no layer may enlarge what it
//! inherited, and nothing here invents a bound. A call with none of the three
//! sources publishes nothing rather than choosing a number, which is the
//! difference between a policy and the thirty-second constant this replaced.

#![allow(clippy::await_holding_lock)]

use std::sync::{Arc, Mutex};

mod test_support;
use test_support::ready;

use nemo_relay::api::registry::{
    deregister_tool_request_intercept, register_tool_request_intercept,
};
use nemo_relay::api::runtime::{
    ExecutionBudget, ManagedBudget, ManagedCall, ManagedExecutionConfiguration,
    NemoRelayContextState, budget_now_unix_ms, configure_managed_execution, create_scope_stack,
    current_execution_budget, global_context, resolve_managed_budget, set_thread_scope_stack,
    with_effect_lease_expiry,
};
use nemo_relay::api::tool::{ToolCallExecuteParams, tool_call_execute};
use nemo_relay::error::FlowError;
use serde_json::json;

/// The instant every resolution below is measured against, so a resolution is a
/// pure function of its inputs.
const NOW: u64 = 1_700_000_000_000;

/// The registration chains and the process-wide caps are shared by every test in
/// this binary, so the tests that touch either take turns.
static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn configuration(tool_ms: Option<u64>, llm_ms: Option<u64>) -> ManagedExecutionConfiguration {
    ManagedExecutionConfiguration {
        tool_call_max_duration_ms: tool_ms,
        llm_call_max_duration_ms: llm_ms,
    }
}

fn bounded(budget: ManagedBudget) -> ExecutionBudget {
    match budget {
        ManagedBudget::Bounded(budget) => budget,
        ManagedBudget::Unbounded => panic!("expected a bounded budget"),
    }
}

fn reset_global() {
    let context = global_context();
    let mut state = context.write().unwrap();
    *state = NemoRelayContextState::new();
}

fn setup_isolated_thread() {
    let stack = create_scope_stack();
    set_thread_scope_stack(stack);
}

/// Install an intercept that records the budget the chain was reached under.
fn record_budget(name: &str, seen: &Arc<Mutex<Vec<Option<ExecutionBudget>>>>) {
    let seen = seen.clone();
    register_tool_request_intercept(
        name,
        0,
        false,
        Arc::new(move |_tool, args| {
            seen.lock().unwrap().push(current_execution_budget());
            ready(args)
        }),
    )
    .unwrap();
}

fn tool_params(name: &str) -> ToolCallExecuteParams {
    ToolCallExecuteParams::builder()
        .name(name)
        .args(json!({"input": true}))
        .func(Arc::new(|args| Box::pin(async move { Ok(args.into()) })))
        .build()
}

#[test]
fn the_configured_cap_bounds_a_call_that_inherits_nothing() {
    let budget = bounded(
        resolve_managed_budget(
            &configuration(Some(5_000), None),
            ManagedCall::Tool,
            None,
            None,
            NOW,
        )
        .expect("a configured cap"),
    );
    assert_eq!(budget.deadline_unix_ms, Some(NOW + 5_000));
    assert_eq!(budget.remaining_budget_millis, 5_000);
}

#[test]
fn an_inherited_deadline_bounds_a_call_that_also_has_a_cap() {
    // The parent has 500 ms left and the cap allows 5 s. The parent wins,
    // because a cap may never enlarge what was inherited.
    let budget = bounded(
        resolve_managed_budget(
            &configuration(Some(5_000), None),
            ManagedCall::Tool,
            Some(ExecutionBudget::new(NOW + 500, 500)),
            None,
            NOW,
        )
        .expect("the parent's deadline"),
    );
    assert_eq!(budget.deadline_unix_ms, Some(NOW + 500));
    assert_eq!(budget.remaining_budget_millis, 500);
}

#[test]
fn a_lease_expiry_bounds_a_call_that_has_no_parent() {
    let budget = bounded(
        resolve_managed_budget(
            &configuration(Some(5_000), None),
            ManagedCall::Tool,
            None,
            Some(NOW + 700),
            NOW,
        )
        .expect("the lease expiry"),
    );
    assert_eq!(budget.deadline_unix_ms, Some(NOW + 700));
    assert_eq!(budget.remaining_budget_millis, 700);
}

#[test]
fn the_lease_bounds_a_call_whose_parent_allows_more() {
    let budget = bounded(
        resolve_managed_budget(
            &configuration(Some(5_000), None),
            ManagedCall::Tool,
            Some(ExecutionBudget::new(NOW + 900, 900)),
            Some(NOW + 600),
            NOW,
        )
        .expect("the lease expiry"),
    );
    assert_eq!(budget.deadline_unix_ms, Some(NOW + 600));
    assert_eq!(budget.remaining_budget_millis, 600);
}

#[test]
fn a_call_with_no_source_at_all_is_unbounded_rather_than_invented() {
    // No parent, no lease, no configured cap: nothing has decided how long this
    // may take. Reporting that is the point — choosing a number here is exactly
    // what this API exists to prevent.
    let resolved = resolve_managed_budget(
        &ManagedExecutionConfiguration::default(),
        ManagedCall::Tool,
        None,
        None,
        NOW,
    )
    .expect("resolution");
    assert_eq!(resolved, ManagedBudget::Unbounded);
}

#[test]
fn a_bound_that_has_already_passed_refuses_instead_of_starting_the_work() {
    let expired_parent = resolve_managed_budget(
        &configuration(Some(5_000), None),
        ManagedCall::Tool,
        Some(ExecutionBudget::new(NOW - 1, 0)),
        None,
        NOW,
    )
    .expect_err("an inherited deadline that has passed");
    assert!(
        matches!(expired_parent, FlowError::Timeout { .. }),
        "{expired_parent}"
    );

    let expired_lease = resolve_managed_budget(
        &configuration(Some(5_000), None),
        ManagedCall::Tool,
        None,
        Some(NOW - 1),
        NOW,
    )
    .expect_err("a lease that has lapsed");
    assert!(
        matches!(expired_lease, FlowError::Timeout { .. }),
        "{expired_lease}"
    );
}

#[test]
fn a_nested_call_cannot_start_from_a_fresh_full_cap() {
    // The outer call gets 800 ms from its cap and 250 ms of it is spent. The
    // inner call has a cap of its own that would allow thirty seconds; it must
    // still live inside what the outer one has left.
    let outer = bounded(
        resolve_managed_budget(
            &configuration(Some(800), Some(30_000)),
            ManagedCall::Tool,
            None,
            None,
            NOW,
        )
        .expect("the outer budget"),
    );
    let spent = 250;
    let inner = bounded(
        resolve_managed_budget(
            &configuration(Some(800), Some(30_000)),
            ManagedCall::Llm,
            Some(outer),
            None,
            NOW + spent,
        )
        .expect("the inner budget"),
    );

    assert_eq!(inner.deadline_unix_ms, outer.deadline_unix_ms);
    assert_eq!(inner.remaining_budget_millis, 800 - spent);
}

#[test]
fn the_two_kinds_of_call_have_their_own_caps() {
    let tool = bounded(
        resolve_managed_budget(
            &configuration(Some(1_000), Some(9_000)),
            ManagedCall::Tool,
            None,
            None,
            NOW,
        )
        .expect("a tool cap"),
    );
    let llm = bounded(
        resolve_managed_budget(
            &configuration(Some(1_000), Some(9_000)),
            ManagedCall::Llm,
            None,
            None,
            NOW,
        )
        .expect("an llm cap"),
    );
    assert_eq!(tool.remaining_budget_millis, 1_000);
    assert_eq!(llm.remaining_budget_millis, 9_000);
}

#[tokio::test]
async fn a_managed_tool_call_publishes_the_configured_cap_to_its_chain() {
    let _guard = TEST_MUTEX.lock().unwrap();
    reset_global();
    setup_isolated_thread();
    let previous = configure_managed_execution(configuration(Some(60_000), None));
    let seen = Arc::new(Mutex::new(Vec::new()));
    record_budget("budget-recording-intercept", &seen);

    let before = budget_now_unix_ms();
    tool_call_execute(tool_params("budgeted-tool"))
        .await
        .expect("a tool call under a configured cap");

    let recorded = seen.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1, "the chain runs once per call");
    let budget = recorded[0].expect("the boundary publishes a budget");
    let deadline = budget
        .deadline_unix_ms
        .expect("a published budget has a deadline");
    assert!(
        deadline > before && deadline <= before + 60_000,
        "the deadline is the configured cap, measured from the call: {budget:?}"
    );
    assert!(
        current_execution_budget().is_none(),
        "the budget is scoped to the call rather than left behind"
    );

    deregister_tool_request_intercept("budget-recording-intercept").unwrap();
    configure_managed_execution(previous);
}

#[tokio::test]
async fn a_managed_call_with_no_stated_cap_publishes_no_budget() {
    let _guard = TEST_MUTEX.lock().unwrap();
    reset_global();
    setup_isolated_thread();
    let previous = configure_managed_execution(ManagedExecutionConfiguration::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    record_budget("uncapped-recording-intercept", &seen);

    tool_call_execute(tool_params("uncapped-tool"))
        .await
        .expect("a tool call still runs");

    let recorded = seen.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0], None,
        "nothing stated a bound, so nothing is published for a registration to inherit"
    );

    deregister_tool_request_intercept("uncapped-recording-intercept").unwrap();
    configure_managed_execution(previous);
}

#[tokio::test]
async fn a_published_lease_expiry_bounds_the_managed_call() {
    let _guard = TEST_MUTEX.lock().unwrap();
    reset_global();
    setup_isolated_thread();
    // No configured cap at all: the lease is the only bound, so what the chain
    // sees is the lease rather than the runtime's own policy.
    let previous = configure_managed_execution(ManagedExecutionConfiguration::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    record_budget("leased-recording-intercept", &seen);

    let expiry = budget_now_unix_ms() + 900;
    with_effect_lease_expiry(expiry, async {
        tool_call_execute(tool_params("leased-tool"))
            .await
            .expect("a tool call under a lease");
    })
    .await;

    let recorded = seen.lock().unwrap().clone();
    let budget = recorded[0].expect("the lease bounds the call on its own");
    assert_eq!(
        budget.deadline_unix_ms,
        Some(expiry),
        "the lease contributes its expiry, never a duration"
    );

    deregister_tool_request_intercept("leased-recording-intercept").unwrap();
    configure_managed_execution(previous);
}

#[tokio::test]
async fn a_lapsed_lease_refuses_the_call_before_anything_reaches_the_chain() {
    let _guard = TEST_MUTEX.lock().unwrap();
    reset_global();
    setup_isolated_thread();
    let previous = configure_managed_execution(ManagedExecutionConfiguration::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    record_budget("lapsed-recording-intercept", &seen);

    let expired = budget_now_unix_ms().saturating_sub(1);
    let error = with_effect_lease_expiry(expired, async {
        tool_call_execute(tool_params("lapsed-tool")).await
    })
    .await
    .expect_err("a lease that has already lapsed");
    assert!(matches!(error, FlowError::Timeout { .. }), "{error}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "a refused call reaches no intercept at all"
    );

    deregister_tool_request_intercept("lapsed-recording-intercept").unwrap();
    configure_managed_execution(previous);
}

#[tokio::test]
async fn a_nested_managed_call_inherits_its_parent_deadline_over_its_own_cap() {
    let _guard = TEST_MUTEX.lock().unwrap();
    reset_global();
    setup_isolated_thread();
    // Both kinds of call get the same generous cap, so anything the inner call
    // inherits has to come from its parent rather than from configuration.
    let previous = configure_managed_execution(configuration(Some(800), Some(800)));
    let seen = Arc::new(Mutex::new(Vec::new()));

    let recorded = seen.clone();
    register_tool_request_intercept(
        "nested-budget-intercept",
        0,
        false,
        Arc::new(move |_tool, args| {
            let recorded = recorded.clone();
            Box::pin(async move {
                let depth = {
                    let mut guard = recorded.lock().unwrap();
                    guard.push(current_execution_budget());
                    guard.len()
                };
                if depth == 1 {
                    tool_call_execute(tool_params("inner-tool"))
                        .await
                        .expect("a nested tool call");
                }
                Ok(args)
            })
        }),
    )
    .unwrap();

    tool_call_execute(tool_params("outer-tool"))
        .await
        .expect("the outer tool call");

    let recorded = seen.lock().unwrap().clone();
    assert_eq!(recorded.len(), 2, "outer then inner");
    let outer = recorded[0].expect("the outer call is bounded");
    let inner = recorded[1].expect("the inner call is bounded");
    assert_eq!(
        inner.deadline_unix_ms, outer.deadline_unix_ms,
        "the inner call lives inside the outer deadline rather than starting a fresh cap"
    );
    assert!(
        inner.remaining_budget_millis <= outer.remaining_budget_millis,
        "an inner call may never be given more than its parent had"
    );

    deregister_tool_request_intercept("nested-budget-intercept").unwrap();
    configure_managed_execution(previous);
}
