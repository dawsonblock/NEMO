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
//!
//! A managed boundary does not invent the budget it publishes. It takes the
//! smallest of three sources — the deadline its parent published, the durable
//! action lease's expiry, and `now` plus the configured cap for that kind of
//! call — and refuses to run when a source that exists has already passed. A
//! call with none of the three publishes nothing: nothing has decided how long
//! it may take, and a number chosen here would be the invention this module
//! exists to prevent.

use std::sync::RwLock;
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

/// What a deployment states about how long a managed call may take.
///
/// There is deliberately no default. A managed call with no inherited budget, no
/// effect lease and no configured cap has nothing bounding it, and the honest
/// answer is to publish nothing rather than to pick a number: a fallback
/// constant is how the previous build ended up with a thirty-second budget
/// nobody had chosen, and moving that number into runtime configuration without
/// making it explicit would repeat the mistake in a place that looks more
/// official.
///
/// What "publish nothing" costs is stated where it is paid: a registration
/// reached across the plugin boundary refuses without a trusted budget, so a
/// deployment that wants remote plugins states these caps. Work that stays in
/// process is unaffected either way, which is why an absent cap is not a startup
/// failure.
///
/// The caps are separate because the calls are different: a tool call and a
/// model call do not share a latency profile, and one number that fits both is
/// either too loose for one or too tight for the other.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ManagedExecutionConfiguration {
    /// Longest a managed tool call may run.
    pub tool_call_max_duration_ms: Option<u64>,
    /// Longest a managed LLM call may run.
    pub llm_call_max_duration_ms: Option<u64>,
}

impl ManagedExecutionConfiguration {
    /// Development and test settings, where a stated cap is convenient.
    ///
    /// Named so that using it in production is a visible choice rather than a
    /// default: the point of the type is that an absent cap bounds nothing.
    pub fn development(cap_ms: u64) -> Self {
        Self {
            tool_call_max_duration_ms: Some(cap_ms),
            llm_call_max_duration_ms: Some(cap_ms),
        }
    }
}

/// The configuration of a process that has stated no caps.
const NO_CONFIGURED_CAPS: ManagedExecutionConfiguration = ManagedExecutionConfiguration {
    tool_call_max_duration_ms: None,
    llm_call_max_duration_ms: None,
};

static MANAGED_EXECUTION_CONFIGURATION: RwLock<ManagedExecutionConfiguration> =
    RwLock::new(NO_CONFIGURED_CAPS);

/// State the caps this process runs managed calls under, returning what was in
/// place.
///
/// Returning the previous value is deliberate: the only honest way to try one
/// policy inside a process that already has another — a test, say — is to put
/// the old one back, and the API hands it over rather than making the caller
/// reconstruct it.
pub fn configure_managed_execution(
    configuration: ManagedExecutionConfiguration,
) -> ManagedExecutionConfiguration {
    let mut current = MANAGED_EXECUTION_CONFIGURATION
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::mem::replace(&mut current, configuration)
}

/// The caps this process runs managed calls under.
pub fn managed_execution_configuration() -> ManagedExecutionConfiguration {
    *MANAGED_EXECUTION_CONFIGURATION
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

tokio::task_local! {
    static EFFECT_LEASE_EXPIRY_UNIX_MS: u64;
}

/// Run a future under a durable action lease's *expiry*.
///
/// The expiry rather than a duration, because the two are not interchangeable:
/// "the lease lasts thirty seconds" turned into `now + 30` at a later layer is a
/// lease silently extended, and a callback that started under one expiry keeps
/// it even if another task renews the lease behind it. A renewal bounds the
/// *next* operation, not the one already running.
///
/// This is where the effect-execution layer publishes the lease it holds, and it
/// publishes into a task-local below the frame that owns the lease, so nothing a
/// plugin does can widen it.
pub async fn with_effect_lease_expiry<F>(expiry_unix_ms: u64, future: F) -> F::Output
where
    F: std::future::Future,
{
    EFFECT_LEASE_EXPIRY_UNIX_MS
        .scope(expiry_unix_ms, future)
        .await
}

/// The durable lease expiry in scope, if the effect-execution layer published one.
pub fn current_effect_lease_expiry_unix_ms() -> Option<u64> {
    EFFECT_LEASE_EXPIRY_UNIX_MS.try_with(|expiry| *expiry).ok()
}

/// Which managed boundary is asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedCall {
    /// A managed tool call.
    Tool,
    /// A managed LLM call.
    Llm,
}

/// What bounds one managed call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedBudget {
    /// The call is bounded, and this is the budget it runs under.
    Bounded(ExecutionBudget),
    /// Nothing bounds the call: no inherited budget, no lease, no configured cap.
    ///
    /// Not an error, because work that stays in process is not made safer by a
    /// number nobody chose — and not a licence either: a registration reached
    /// across the plugin boundary refuses without a trusted budget, which is
    /// where an invented deadline would have done its damage.
    Unbounded,
}

/// Resolve the budget one managed call runs under.
///
/// Three sources, and the smallest wins:
///
/// ```text
/// inherited parent deadline
/// authoritative effect-lease expiry
/// now + the configured cap for this kind of call
/// ```
///
/// A lease contributes its *expiry*, never a duration: turning "30 seconds" into
/// `now + 30` at a later layer is how a lease gets silently extended, and a
/// callback that started under one expiry keeps that expiry even if another task
/// renews the lease behind it. Nothing downstream may extend the result.
///
/// A bound that has already passed refuses the call rather than starting work on
/// a budget the runtime has already spent; a call with no bound at all is
/// reported as [`ManagedBudget::Unbounded`].
pub fn resolve_managed_budget(
    configuration: &ManagedExecutionConfiguration,
    call: ManagedCall,
    inherited: Option<ExecutionBudget>,
    lease_expiry_unix_ms: Option<u64>,
    now_unix_ms: u64,
) -> Result<ManagedBudget, crate::error::FlowError> {
    use crate::error::FlowError;

    let cap_ms = match call {
        ManagedCall::Tool => configuration.tool_call_max_duration_ms,
        ManagedCall::Llm => configuration.llm_call_max_duration_ms,
    };
    let cap_deadline = cap_ms.map(|millis| now_unix_ms.saturating_add(millis));
    let candidates = [
        inherited.and_then(|budget| budget.deadline_unix_ms),
        lease_expiry_unix_ms,
        cap_deadline,
    ];
    let Some(deadline) = candidates.into_iter().flatten().min() else {
        return Ok(ManagedBudget::Unbounded);
    };
    if deadline <= now_unix_ms {
        // Either an inherited deadline that has passed or a lease that lapsed:
        // both mean the work may not start, and starting it would hand a plugin
        // time the runtime has already spent.
        return Err(FlowError::Timeout {
            resource: "managed_execution_budget",
        });
    }
    let remaining = deadline.saturating_sub(now_unix_ms);
    let inherited_remaining = inherited
        .map(|budget| budget.remaining_budget_millis)
        .unwrap_or(u64::MAX);
    Ok(ManagedBudget::Bounded(ExecutionBudget {
        deadline_unix_ms: Some(deadline),
        remaining_budget_millis: remaining.min(inherited_remaining),
    }))
}

/// Resolve the budget for a managed call from this process's configuration and
/// whatever the caller's frame published.
///
/// This is what a managed boundary calls. The sources are the runtime's rather
/// than the caller's, so a caller cannot choose its own deadline by asking, and
/// the inherited value comes from the task-local rather than a parameter, so a
/// nested call lives inside what its parent has left instead of starting from a
/// fresh cap.
pub fn resolve_managed_call_budget(
    call: ManagedCall,
) -> Result<ManagedBudget, crate::error::FlowError> {
    resolve_managed_budget(
        &managed_execution_configuration(),
        call,
        current_execution_budget(),
        current_effect_lease_expiry_unix_ms(),
        now_unix_ms(),
    )
}
