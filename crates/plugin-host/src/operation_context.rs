// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The context and the refusal both ends of the protocol use.
//!
//! These live here because the two ends share them: the supervisor builds the same
//! bounded context for a lifecycle operation that the child's own backend does, and
//! both refuse with a code the boundary owns rather than one each invents.

use nemo_relay_plugin_protocol::{PROTOCOL_VERSION, PluginExecutionContext, PluginProtocolError};

/// Refuse an operation with a message rather than a failure code nobody set.
///
/// A lifecycle refusal carries a code and a message, and every caller here has the
/// message but not the code: what the operation was refused *for* is protocol
/// vocabulary that the boundary decides, and a caller inventing a code would be a
/// second place that meaning lives.
#[must_use]
pub fn refused(message: impl Into<String>) -> PluginProtocolError {
    PluginProtocolError::new(
        nemo_relay_plugin_protocol::PluginFailureCode::Rejected,
        message.into(),
    )
}

/// A bounded context for one lifecycle operation of a session.
///
/// Bounded rather than open-ended, and bound to the session's own runtime digest:
/// the host refuses an operation that claims a runtime it was not started for, so
/// a placeholder digest here would make every load fail rather than making it
/// lenient.
#[must_use]
pub fn lifecycle_context(runtime_binding_digest: &str, operation: &str) -> PluginExecutionContext {
    PluginExecutionContext {
        operation_request_id: format!(
            "{operation}-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ),
        protocol_version: PROTOCOL_VERSION,
        runtime_binding_digest: runtime_binding_digest.to_owned(),
        deadline_unix_ms: nemo_relay::api::runtime::budget_now_unix_ms().saturating_add(30_000),
        remaining_budget_millis: 30_000,
        max_response_bytes: 1024,
    }
}
