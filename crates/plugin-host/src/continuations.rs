// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The continuations a kernel holds for the plugin that asked for them.
//!
//! An execution intercept wraps the call it intercepts: the plugin decides
//! *when* the rest of the chain runs, and the rest of the chain is the kernel's.
//! A plugin in another process cannot reach it by calling anything local, so the
//! kernel holds the continuation while the plugin's callback runs, keyed by the
//! operation the callback belongs to, and runs it when the host asks.
//!
//! Held, not lent: the entry is removed when the intercept that owns it settles,
//! so a continuation that arrives afterwards is refused rather than run against
//! a chain position whose call has already returned. The continuation itself
//! carries the engine's own lease as well — a call still in flight when the
//! intercept settles is cancelled — so the rules a plugin sees are the ones an
//! in-process intercept sees, enforced on both sides of the boundary.
//!
//! Which family a position belongs to travels in the entry rather than on the
//! wire: one operation is one chain position, and the request that resumes it
//! carries only the input the plugin settled on. The wire is therefore the same
//! unary shape for every family that has one, and a request shaped for the wrong
//! family is refused by the entry it addresses rather than by a discriminator it
//! could get wrong.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use nemo_relay::api::runtime::{
    LlmExecutionNextFn, LlmStreamExecutionNextFn, MiddlewareContinuationContext,
    ToolExecutionNextFn,
};

/// One continuation the kernel is holding.
///
/// Cloned out to run rather than taken: the ABI lets an intercept call its
/// continuation more than once — retries and fan-out are what the isolated
/// context per call exists for — so the entry stays until the intercept settles.
#[derive(Clone)]
pub struct ParkedContinuation {
    /// The registration the operation is running, for a refusal that says which.
    pub registration_id: String,
    /// The Relay task context captured where the chain was, so the continuation
    /// runs in the scope and budget the call it belongs to had.
    pub context: MiddlewareContinuationContext,
    /// The managed budget the call it belongs to was running under, if any.
    ///
    /// Captured because the resumed chain runs on the kernel's server task,
    /// which has no budget of its own: without this, a registration the chain
    /// reaches downstream would refuse for having none — and a plugin could
    /// extend the call's deadline by holding its continuation. Resuming narrows
    /// it to what is left, so a continuation can only spend the call's remaining
    /// time.
    pub budget: Option<nemo_relay::api::runtime::ExecutionBudget>,
    /// The rest of the chain, and which family it belongs to.
    pub chain: ParkedChain,
}

/// The chain a position resumes, one variant per family that wraps a call.
///
/// The families differ in what they take and what they answer — a tool call's
/// arguments and result, a provider call's request and response — so the entry
/// holds the typed continuation rather than an erased one. What resumes it is
/// the same unary request either way.
#[derive(Clone)]
pub enum ParkedChain {
    /// The remainder of a tool call.
    Tool(ToolExecutionNextFn),
    /// The remainder of a non-streaming provider call.
    Llm(LlmExecutionNextFn),
    /// The remainder of a streaming provider call.
    ///
    /// Held for as long as the stream it produces is being pulled rather than
    /// until one call returns: a plugin paces a stream itself, so the position
    /// has to outlive the request that opened it.
    LlmStream(LlmStreamExecutionNextFn),
}

impl std::fmt::Debug for ParkedContinuation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParkedContinuation")
            .field("registration_id", &self.registration_id)
            .finish_non_exhaustive()
    }
}

/// The continuations in flight in one session.
#[derive(Default)]
pub struct Continuations {
    entries: Mutex<HashMap<String, ParkedContinuation>>,
}

impl std::fmt::Debug for Continuations {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Continuations")
            .field("in_flight", &self.in_flight())
            .finish()
    }
}

impl Continuations {
    /// A registry holding nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `next` for `operation_request_id` until the guard drops.
    ///
    /// A guard rather than a pair of calls for the reason the operation scopes
    /// use one: an intercept can end in more ways than it can start, and an entry
    /// that outlived its interrupt would let a later request run a chain
    /// position the kernel has already left.
    pub fn hold(
        &self,
        operation_request_id: &str,
        registration_id: &str,
        chain: ParkedChain,
    ) -> ContinuationGuard<'_> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                operation_request_id.to_owned(),
                ParkedContinuation {
                    registration_id: registration_id.to_owned(),
                    context: MiddlewareContinuationContext::capture(),
                    budget: nemo_relay::api::runtime::current_execution_budget(),
                    chain,
                },
            );
        ContinuationGuard {
            continuations: self,
            operation_request_id: operation_request_id.to_owned(),
        }
    }

    /// Hold the remainder of a tool call.
    pub fn hold_tool(
        &self,
        operation_request_id: &str,
        registration_id: &str,
        next: ToolExecutionNextFn,
    ) -> ContinuationGuard<'_> {
        self.hold(
            operation_request_id,
            registration_id,
            ParkedChain::Tool(next),
        )
    }

    /// Hold the remainder of a non-streaming provider call.
    pub fn hold_llm(
        &self,
        operation_request_id: &str,
        registration_id: &str,
        next: LlmExecutionNextFn,
    ) -> ContinuationGuard<'_> {
        self.hold(
            operation_request_id,
            registration_id,
            ParkedChain::Llm(next),
        )
    }

    /// Hold the remainder of a streaming provider call.
    ///
    /// The same parked position as the other families, with a continuation that
    /// answers with a stream instead of a value: what resumes it is a pull, and
    /// what finishes it is the plugin releasing the stream.
    pub fn hold_llm_stream(
        &self,
        operation_request_id: &str,
        registration_id: &str,
        next: LlmStreamExecutionNextFn,
    ) -> ContinuationGuard<'_> {
        self.hold(
            operation_request_id,
            registration_id,
            ParkedChain::LlmStream(next),
        )
    }

    /// The continuation held for the named operation, while it is held.
    pub fn parked(&self, operation_request_id: &str) -> Option<ParkedContinuation> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(operation_request_id)
            .cloned()
    }

    /// How many continuations are held.
    pub fn in_flight(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Removes one parked continuation when the intercept that owns it settles.
pub struct ContinuationGuard<'a> {
    continuations: &'a Continuations,
    operation_request_id: String,
}

impl Drop for ContinuationGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.continuations.entries.lock() {
            entries.remove(&self.operation_request_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay::api::runtime::ToolExecutionNextFn;
    use std::sync::Arc;

    fn next() -> ToolExecutionNextFn {
        Arc::new(|args| {
            Box::pin(async move { Ok(nemo_relay::api::tool::ToolExecutionResult::new(args)) })
        })
    }

    /// A continuation is held while its intercept runs and gone when it settles.
    #[tokio::test]
    async fn a_continuation_is_held_until_its_intercept_settles() {
        let continuations = Continuations::new();
        assert_eq!(continuations.in_flight(), 0);

        let guard = continuations.hold_tool("operation-1", "registration-1", next());
        assert_eq!(continuations.in_flight(), 1);
        let parked = continuations
            .parked("operation-1")
            .expect("the continuation the kernel is holding");
        assert_eq!(parked.registration_id, "registration-1");

        drop(guard);
        assert_eq!(continuations.in_flight(), 0);
        assert!(
            continuations.parked("operation-1").is_none(),
            "a continuation whose intercept settled is no longer held"
        );
    }

    /// The held continuation is callable more than once, which is what the ABI
    /// promises an intercept: retries and fan-out are allowed while it runs.
    #[tokio::test]
    async fn a_held_continuation_can_be_run_more_than_once() {
        let continuations = Continuations::new();
        let _guard = continuations.hold_tool("operation-1", "registration-1", next());
        let parked = continuations
            .parked("operation-1")
            .expect("a held continuation");
        for _ in 0..2 {
            let parked = parked.clone();
            let context = parked.context.clone();
            let args = serde_json::json!({"input": true});
            let crate::continuations::ParkedChain::Tool(next) = parked.chain else {
                panic!("this position holds a tool chain");
            };
            let result = context.invoke(move || next(args)).await;
            assert!(result.is_ok(), "the continuation ran: {result:?}");
        }
        assert_eq!(
            continuations.in_flight(),
            1,
            "running it does not consume it: only settling the intercept does"
        );
    }

    /// The family a position belongs to is held with it, so a request that
    /// resumes the wrong kind of chain is answered by the entry rather than by a
    /// discriminator the peer could get wrong.
    #[tokio::test]
    async fn a_position_remembers_which_family_it_belongs_to() {
        let continuations = Continuations::new();
        let _tool = continuations.hold_tool("operation-tool", "registration-1", next());
        let llm: nemo_relay::api::runtime::LlmExecutionNextFn = Arc::new(|request| {
            Box::pin(
                async move { Ok(serde_json::to_value(&request).expect("a request serializes")) },
            )
        });
        let _llm = continuations.hold_llm("operation-llm", "registration-2", llm);

        assert!(matches!(
            continuations
                .parked("operation-tool")
                .map(|held| held.chain),
            Some(ParkedChain::Tool(_))
        ));
        assert!(matches!(
            continuations.parked("operation-llm").map(|held| held.chain),
            Some(ParkedChain::Llm(_))
        ));

        let stream: nemo_relay::api::runtime::LlmStreamExecutionNextFn = Arc::new(|_request| {
            Box::pin(async move {
                Err(nemo_relay::error::FlowError::Internal(
                    "this test does not produce a stream".to_string(),
                ))
            })
        });
        let _streaming =
            continuations.hold_llm_stream("operation-stream", "registration-3", stream);
        assert!(matches!(
            continuations
                .parked("operation-stream")
                .map(|held| held.chain),
            Some(ParkedChain::LlmStream(_))
        ));
    }

    /// Two operations hold their own continuations, so a plugin cannot be handed
    /// a position in a chain it does not belong to.
    #[tokio::test]
    async fn continuations_are_kept_per_operation() {
        let continuations = Continuations::new();
        let _first = continuations.hold_tool("operation-1", "registration-1", next());
        let _second = continuations.hold_tool("operation-2", "registration-2", next());
        assert_eq!(continuations.in_flight(), 2);
        assert_eq!(
            continuations
                .parked("operation-2")
                .map(|held| held.registration_id),
            Some("registration-2".to_string())
        );
        assert!(continuations.parked("operation-3").is_none());
    }
}
