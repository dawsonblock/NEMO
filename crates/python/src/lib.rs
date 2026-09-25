// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! PyO3 native extension module for NeMo Relay.
//!
//! This crate compiles to a `_native` Python C extension that is imported by the
//! `nemo_relay` Python package. It exposes all core runtime types and API functions
//! to Python via PyO3.
//!
//! ## Modules
//!
//! - `py_types` — Python-facing type wrappers (`ScopeHandle`, `ToolHandle`, `Event`,
//!   `AtifExporter`, etc.). `Event` exposes typed lifecycle fields (`input`, `output`,
//!   `model_name`, `tool_call_id`). `AtifExporter` collects events and
//!   exports ATIF v1.7 trajectories.
//! - `py_api` — Python-facing API functions (`push_scope`, etc.). Tool calls
//!   accept `tool_call_id` and LLM calls accept `model_name` for ATIF correlation.
//! - `py_callable` — Bridges between Python callables and Rust callback types
//! - `py_context` — Notes on scope propagation between sync/async contexts
//! - `py_adaptive` — Python-facing adaptive helpers (`set_latency_sensitivity`)
//! - `py_plugin` — Python-facing generic plugin config/registration helpers
//! - `convert` — JSON ↔ Python conversion utilities
use nemo_relay::shared_runtime::initialize_shared_runtime_binding;
use nemo_relay_adaptive::plugin_component::register_adaptive_component;
use nemo_relay_pii_redaction::component::register_pii_redaction_component;
use pyo3::prelude::*;
use pyo3::types::PyModule;

mod convert;
#[doc(hidden)]
pub mod py_adaptive;
#[doc(hidden)]
pub mod py_api;
mod py_callable;
mod py_context;
#[doc(hidden)]
pub mod py_plugin;
mod py_storage;
#[doc(hidden)]
pub mod py_types;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;

/// The `_native` PyO3 module entry point. Registers all types and functions.
///
/// The stack a managed call's future needs, stated rather than inherited from
/// the runtime's default: see the initialization below for why the default is
/// not enough.
const PYTHON_FUTURE_STACK_BYTES: usize = 8 * 1024 * 1024;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // The runtime that drives every Python-facing future, sized before anything
    // can be spawned on it.
    //
    // A managed call that reaches a plugin runs through a chain of wrappers this
    // binding does not control — the caller's coroutine, the executor's future,
    // the registry chain, a plugin proxy, and the host's client — and one of
    // those frames is large. Tokio's default worker stack is 2 MiB, which the
    // chain fits through in the shallow cases and overflows in the deep ones: a
    // worker plugin invoked from Python walked off the end of its stack and took
    // the interpreter with it (SIGILL on the stack probe, found under a debugger
    // rather than guessed at). The size below is the same order the process's
    // main thread gets, which is the budget a coroutine of this depth needs.
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime
        .enable_all()
        .thread_stack_size(PYTHON_FUTURE_STACK_BYTES);
    pyo3_async_runtimes::tokio::init(runtime);
    initialize_shared_runtime_binding("python").map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to initialize NeMo Relay runtime ownership: {e}"
        ))
    })?;
    nemo_relay::logging::initialize_default_logging().map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to initialize NeMo Relay operational logging: {e}"
        ))
    })?;
    register_adaptive_component().map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to register adaptive plugin component: {e}"
        ))
    })?;
    register_pii_redaction_component().map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to register PII redaction plugin component: {e}"
        ))
    })?;
    py_types::register(m)?;
    py_api::register(m)?;
    py_plugin::register(m)?;
    py_adaptive::register(m)?;
    Ok(())
}

#[cfg(test)]
#[path = "../tests/coverage/coverage_tests.rs"]
mod coverage_tests;

#[cfg(test)]
#[path = "../tests/coverage/nemo_guardrails_coverage_tests.rs"]
mod nemo_guardrails_coverage_tests;
