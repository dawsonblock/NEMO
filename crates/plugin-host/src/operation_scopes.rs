// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Which scope stack each in-flight operation belongs to.
//!
//! A mark a plugin raises arrives on the kernel's server task, not in the task
//! that made the call, so the service cannot read "the current scope" and get the
//! right answer. It has to be told which operation the mark belongs to, and this
//! is where that mapping lives: the kernel's proxy registers an operation while it
//! is in flight and removes it when it ends, so a mark naming an operation nothing
//! is running is refused rather than attached to whichever scope happened to be
//! current on the server task.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use nemo_relay::api::runtime::ScopeStackHandle;

/// The scope stack each in-flight operation belongs to.
#[derive(Default)]
pub struct OperationScopes {
    entries: Mutex<HashMap<String, ScopeStackHandle>>,
}

impl std::fmt::Debug for OperationScopes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The count rather than the entries: which operations are in flight is
        // useful in a log, and the stacks they belong to are not.
        formatter
            .debug_struct("OperationScopes")
            .field("in_flight", &self.in_flight())
            .finish()
    }
}

impl OperationScopes {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach `stack` to `operation_request_id` until the guard drops.
    ///
    /// A guard rather than a pair of calls because the operation can end in more
    /// ways than it can start: an early return, an error or a panic would
    /// otherwise leave an entry behind that a later mark could be attached to.
    pub fn enter(&self, operation_request_id: &str, stack: ScopeStackHandle) -> OperationScope<'_> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(operation_request_id.to_owned(), stack);
        OperationScope {
            scopes: self,
            operation_request_id: operation_request_id.to_owned(),
        }
    }

    /// The stack the named operation belongs to, while it is in flight.
    pub fn stack_for(&self, operation_request_id: &str) -> Option<ScopeStackHandle> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(operation_request_id)
            .cloned()
    }

    /// How many operations are in flight.
    pub fn in_flight(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// One operation's registration, removed when it drops.
pub struct OperationScope<'a> {
    scopes: &'a OperationScopes,
    operation_request_id: String,
}

impl Drop for OperationScope<'_> {
    fn drop(&mut self) {
        self.scopes
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.operation_request_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay::api::runtime::create_scope_stack;

    #[test]
    fn an_operation_is_registered_only_while_its_guard_lives() {
        let scopes = OperationScopes::new();
        let stack = create_scope_stack();
        assert!(scopes.stack_for("operation-1").is_none());

        {
            let _guard = scopes.enter("operation-1", stack.clone());
            assert_eq!(scopes.in_flight(), 1);
            assert!(scopes.stack_for("operation-1").is_some());
            // And not for an operation that was never started.
            assert!(scopes.stack_for("operation-2").is_none());
        }

        // The guard is the only thing that holds the registration, so a finished
        // operation leaves nothing for a late mark to attach to.
        assert_eq!(scopes.in_flight(), 0);
        assert!(scopes.stack_for("operation-1").is_none());
    }
}
