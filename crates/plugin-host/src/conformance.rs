// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Behaviour every plugin execution backend must share.
//!
//! The point of a seam is that implementations are interchangeable, and the
//! only way to know that is to run the same checks against each of them. The
//! in-process compatibility backend runs this suite first; the process backend
//! runs the identical suite when it exists, which is what will show that it
//! implements the contract rather than merely having methods with the same
//! names.
//!
//! The suite reports findings rather than asserting so a caller can decide what
//! to do with them, and so one backend's failure does not hide the others.
//!
//! What is deliberately *not* here: deadline enforcement. The kernel's
//! [`nemo_relay::plugin::execution::PluginManager`] refuses an expired deadline
//! before any backend is reached, so a backend cannot be asked to prove
//! something it is not responsible for. What a backend does when a deadline
//! passes mid-operation is part of the process backend's contract and is tested
//! where that implementation lives.

use nemo_relay::plugin::execution::PluginExecutionBackend;
use nemo_relay_plugin_protocol::{
    PROTOCOL_VERSION, PluginExecutionContext, PluginFailureCode, PluginHandle,
    PluginInspectRequest, PluginProtocolError, PluginUnloadRequest,
};

fn context(request_id: &str) -> PluginExecutionContext {
    PluginExecutionContext {
        request_id: request_id.to_owned(),
        protocol_version: PROTOCOL_VERSION,
        runtime_binding_digest: "conformance-binding".into(),
        deadline_unix_ms: u64::MAX,
        max_response_bytes: 1024,
    }
}

fn code_of(error: &PluginProtocolError) -> &PluginFailureCode {
    &error.failure.code
}

/// Run every shared backend check and return what failed.
pub async fn check<B: PluginExecutionBackend + ?Sized>(backend: &B) -> Vec<String> {
    let mut findings = Vec::new();
    let unknown = PluginHandle {
        plugin_id: "conformance-absent".into(),
        generation: 1,
    };

    match backend
        .inspect(
            PluginInspectRequest { handle: None },
            context("inspect-all"),
        )
        .await
    {
        Ok(descriptors) if descriptors.is_empty() => {}
        Ok(descriptors) => findings.push(format!(
            "a backend with nothing loaded described {} plugin(s)",
            descriptors.len()
        )),
        Err(error) => findings.push(format!("inspecting nothing failed: {error}")),
    }

    match backend
        .inspect(
            PluginInspectRequest {
                handle: Some(unknown.clone()),
            },
            context("inspect-unknown"),
        )
        .await
    {
        Err(error) if matches!(code_of(&error), PluginFailureCode::UnknownPlugin) => {}
        Err(error) => findings.push(format!(
            "inspecting an unknown handle failed as {:?}, which a caller cannot act on",
            code_of(&error)
        )),
        Ok(descriptors) => findings.push(format!(
            "inspecting an unknown handle returned {} descriptor(s)",
            descriptors.len()
        )),
    }

    match backend
        .unload(
            PluginUnloadRequest {
                handle: unknown.clone(),
            },
            context("unload-unknown"),
        )
        .await
    {
        Err(error) if matches!(code_of(&error), PluginFailureCode::UnknownPlugin) => {}
        Err(error) => findings.push(format!(
            "unloading an unknown handle failed as {:?}, which a caller cannot act on",
            code_of(&error)
        )),
        Ok(()) => findings.push("unloading an unknown handle reported success".into()),
    }

    match backend.health(context("health")).await {
        Ok(health) => {
            if health.protocol_version != PROTOCOL_VERSION {
                findings.push(format!(
                    "health reported protocol version {}, not {PROTOCOL_VERSION}",
                    health.protocol_version
                ));
            }
            if health.loaded.iter().any(|handle| handle == &unknown) {
                findings.push("health reported a plugin that was never loaded".into());
            }
        }
        Err(error) => findings.push(format!("health failed: {error}")),
    }

    findings
}
