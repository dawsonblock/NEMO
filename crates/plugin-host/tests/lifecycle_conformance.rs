// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The lifecycle, run against the backend that runs in the caller's process.
//!
//! `process_backend.rs` runs the same checks against a child. The two files
//! together are the claim that lifecycles do not depend on which backend was
//! composed: load, reload and unload have to refuse the same requests with the
//! same codes on both sides of the boundary, and a suite that only ran against
//! one of them would be checking an implementation rather than a contract.
//!
//! Both suites are the same code — `conformance::check` and
//! `conformance::check_lifecycle` — so a case added for one backend is
//! immediately a case for the other.

mod support;

use nemo_relay_plugin_host::InProcessPluginBackend;
use nemo_relay_plugin_host::conformance;

#[tokio::test]
async fn the_in_process_backend_satisfies_the_shared_lifecycle_suite() {
    let backend = InProcessPluginBackend::new();
    let prepared = support::PreparedFixture::write(
        "fixture_native",
        "nemo-lifecycle-in-process",
        support::native_fixture(),
        "nemo_relay_fixture_native_plugin",
    );

    let findings = conformance::check(&backend).await;
    assert!(findings.is_empty(), "{findings:#?}");

    let findings = conformance::check_lifecycle(&backend, &prepared.lifecycle()).await;
    assert!(findings.is_empty(), "{findings:#?}");
}
