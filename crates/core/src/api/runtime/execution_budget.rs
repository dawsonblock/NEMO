// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The trusted budget a managed call is running under.
//!
//! A layer that reaches outside the process — a remote plugin registration, for
//! instance — has to tell the far side how long it may take. The only honest
//! source for that is the action the runtime is executing, so the runtime
//! publishes it here while a managed call runs, and anything lower in the stack
//! reads it rather than choosing for itself.
//!
//! The rule every reader must follow is the same one the EffectStore uses:
//!
//! ```text
//! effective remaining = min(remaining now, inherited remaining)
//! effective deadline  = min(inherited deadline, now + local cap)
//! ```
//!
//! A shorter budget is always allowed. A longer one never is, because it would
//! let work outlive the action that asked for it — and a caller that has already
//! given up should not be waiting on something a plugin invented.
//!
//! It is a task-local rather than a parameter because the interceptor callbacks
//! a plugin registers take the tool name and the arguments, and widening every
//! callback signature to carry timing would change the ABI's shape for a value
//! the runtime already knows. A task-local also cannot be enlarged by a plugin:
//! it is read-only to anything below the frame the runtime set it in.

use std::time::{SystemTime, UNIX_EPOCH};

tokio::task_local! {
    static EXECUTION_BUDGET: ExecutionBudget;
}

/// The trusted budget one managed call is running under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionBudget {
    /// Absolute deadline in milliseconds since the Unix epoch, when the runtime
    /// has one.
    pub deadline_unix_ms: Option<u64>,
    /// What is left of the budget, as the runtime computed it.
    pub remaining_budget_millis: u64,
}

impl ExecutionBudget {
    /// A budget with a deadline and a remainder.
    pub fn new(deadline_unix_ms: u64, remaining_budget_millis: u64) -> Self {
        Self {
            deadline_unix_ms: Some(deadline_unix_ms),
            remaining_budget_millis,
        }
    }

    /// A budget whose deadline has already passed.
    pub fn expired() -> Self {
        Self {
            deadline_unix_ms: Some(0),
            remaining_budget_millis: 0,
        }
    }

    /// What a layer may spend, given what it inherited and its own cap.
    ///
    /// The cap can only shorten: an inherited deadline in the past, or a smaller
    /// remainder, wins. This is the only arithmetic a layer is allowed to do
    /// with a budget.
    pub fn narrowed_to(&self, local_cap_millis: u64, now_unix_ms: u64) -> Self {
        let remaining = self
            .remaining_budget_millis
            .saturating_sub(now_unix_ms.saturating_sub(self.issued_at_unix_ms(now_unix_ms)))
            .min(local_cap_millis);
        Self {
            deadline_unix_ms: self
                .deadline_unix_ms
                .map(|deadline| deadline.min(now_unix_ms.saturating_add(local_cap_millis))),
            remaining_budget_millis: remaining,
        }
    }

    /// When this budget was issued, as far as a reader can tell.
    ///
    /// A budget carries a deadline and a remainder; the moment it was issued is
    /// the deadline minus the remainder, which is enough to charge a layer for
    /// the time it has taken since.
    fn issued_at_unix_ms(&self, _now_unix_ms: u64) -> u64 {
        match self.deadline_unix_ms {
            Some(deadline) => deadline.saturating_sub(self.remaining_budget_millis),
            None => 0,
        }
    }
}

/// Run a future with the trusted budget in scope.
pub async fn with_execution_budget<F>(budget: ExecutionBudget, future: F) -> F::Output
where
    F: std::future::Future,
{
    EXECUTION_BUDGET.scope(budget, future).await
}

/// The trusted budget in scope, if the runtime set one.
///
/// `None` means the call is not running under a managed action's budget, and a
/// layer that needs one to be safe has to refuse rather than choose: inventing a
/// deadline here is exactly how work outlives the action that asked for it.
pub fn current_execution_budget() -> Option<ExecutionBudget> {
    EXECUTION_BUDGET.try_with(|budget| *budget).ok()
}

/// Milliseconds since the Unix epoch, as the runtime measures them.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}
