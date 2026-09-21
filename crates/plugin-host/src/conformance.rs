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
    PROTOCOL_VERSION, PluginArtifactIdentity, PluginExecutionContext, PluginFailureCode,
    PluginHandle, PluginInspectRequest, PluginLoadRequest, PluginProtocolError,
    PluginUnloadRequest,
};

fn context(request_id: &str) -> PluginExecutionContext {
    PluginExecutionContext {
        operation_request_id: request_id.to_owned(),
        protocol_version: PROTOCOL_VERSION,
        runtime_binding_digest: "conformance-binding".into(),
        deadline_unix_ms: u64::MAX,
        remaining_budget_millis: 29_000,
        max_response_bytes: 1024,
    }
}

fn code_of(error: &PluginProtocolError) -> &PluginFailureCode {
    &error.failure.code
}

/// Check that a request was refused with the code the contract names.
///
/// Each refusal is a fact a caller acts on — retry, wait, or stop asking — so a
/// backend that answers with the right outcome under the wrong code is a
/// backend its caller cannot use.
fn refused_with<T>(
    result: Result<T, PluginProtocolError>,
    expected: PluginFailureCode,
    what: &str,
    findings: &mut Vec<String>,
) {
    match result {
        Ok(_) => findings.push(format!(
            "{what} was served rather than refused as {expected:?}"
        )),
        Err(error) if error.failure.code == expected => {}
        Err(error) => findings.push(format!(
            "{what} was refused as {:?} rather than {expected:?}",
            error.failure.code
        )),
    }
}

/// A plugin artifact a lifecycle check can load.
///
/// The suite does not build or discover plugins: a fixture is prepared by the
/// test that owns the artifact, and both backends are handed the same one, so
/// what the checks establish is behaviour rather than what each test happened to
/// find on its machine.
pub struct LifecycleFixture {
    /// The identifier the manifest declares, and the one the load is made under.
    pub plugin_id: String,
    /// Path to the manifest that describes the plugin.
    pub artifact: String,
}

/// Run the shared lifecycle checks and return what failed.
///
/// The checks walk one plugin through load, reload and unload, because the
/// states are only meaningful in relation to each other: `StaleHandle` and
/// `UnknownPlugin` differ by whether an instance exists at another generation,
/// and a suite that forced one of them without the other would accept a backend
/// that answered both questions the same way.
///
/// The suite leaves the backend as it found it: nothing loaded.
pub async fn check_lifecycle<B: PluginExecutionBackend + ?Sized>(
    backend: &B,
    fixture: &LifecycleFixture,
) -> Vec<String> {
    let mut findings = Vec::new();
    let Ok((manifest_sha256, library_sha256)) =
        nemo_relay::plugin::dynamic::plugin_artifact_identity(&fixture.artifact)
    else {
        findings.push(format!(
            "the lifecycle fixture is not a loadable artifact: {}",
            fixture.artifact
        ));
        return findings;
    };
    let identity = FixtureIdentity {
        manifest_sha256,
        library_sha256,
    };

    // Everything below needs a loaded instance, so a failure to reach that state
    // is reported and the rest of the walk is recorded as not established.
    let Some(first) = load_approved(backend, fixture, &identity, &mut findings).await else {
        return findings;
    };
    let Some(second) = unload_and_reload(backend, fixture, &identity, &first, &mut findings).await
    else {
        return findings;
    };
    check_stale_handle(backend, fixture, &first, &mut findings).await;
    leave_nothing_loaded(backend, &second, &mut findings).await;
    findings
}

/// The approved identity of the fixture, and how to build a load request for it.
struct FixtureIdentity {
    manifest_sha256: String,
    library_sha256: String,
}

impl FixtureIdentity {
    fn load(&self, fixture: &LifecycleFixture, manifest_sha256: String) -> PluginLoadRequest {
        PluginLoadRequest {
            plugin_id: fixture.plugin_id.clone(),
            artifact: fixture.artifact.clone(),
            identity: PluginArtifactIdentity {
                manifest_sha256,
                library_sha256: self.library_sha256.clone(),
            },
        }
    }
}

/// Refuse an unapproved artifact, then load the approved one.
async fn load_approved<B: PluginExecutionBackend + ?Sized>(
    backend: &B,
    fixture: &LifecycleFixture,
    identity: &FixtureIdentity,
    findings: &mut Vec<String>,
) -> Option<nemo_relay_plugin_protocol::PluginLoadResponse> {
    // An artifact that is not the approved one must not load, and must not leave
    // the identifier claimed: a reservation that outlived a failed load would
    // wedge the plugin for the lifetime of the backend, and every later attempt
    // would report a load that is not happening. The approved load below is what
    // proves the reservation was released.
    if backend
        .load(
            identity.load(fixture, "0".repeat(64)),
            context("lifecycle-unapproved"),
        )
        .await
        .is_ok()
    {
        findings.push("an artifact whose digest was not the approved one loaded".into());
    }

    let first = match backend
        .load(
            identity.load(fixture, identity.manifest_sha256.clone()),
            context("lifecycle-load"),
        )
        .await
    {
        Ok(loaded) => loaded,
        Err(error) => {
            findings.push(format!(
                "the approved artifact did not load after a failed load: {error}"
            ));
            return None;
        }
    };
    if first.handle.plugin_id != fixture.plugin_id {
        findings.push(format!(
            "a load answered for {} rather than {}",
            first.handle.plugin_id, fixture.plugin_id
        ));
    }
    if first.handle.generation == 0 {
        findings.push("a load produced generation zero, which names no instance".into());
    }
    if first.descriptor.manifest_digest.as_deref() != Some(identity.manifest_sha256.as_str()) {
        findings
            .push("the descriptor does not report the manifest digest the load verified".into());
    }

    // The instance the handle names is the instance inspection describes.
    match backend
        .inspect(
            PluginInspectRequest {
                handle: Some(first.handle.clone()),
            },
            context("lifecycle-inspect"),
        )
        .await
    {
        Ok(descriptors) if descriptors.len() == 1 => {
            if descriptors[0].plugin_id != fixture.plugin_id {
                findings.push("inspecting one handle described another plugin".into());
            }
        }
        Ok(descriptors) => findings.push(format!(
            "inspecting one handle described {} instance(s)",
            descriptors.len()
        )),
        Err(error) => findings.push(format!("inspecting a loaded handle failed: {error}")),
    }

    // A handle from another generation is refused, and the code says which kind
    // of absent it is: the plugin exists, but not at this generation.
    if let Some(other) = first.handle.generation.checked_add(1) {
        refused_with(
            backend
                .inspect(
                    PluginInspectRequest {
                        handle: Some(PluginHandle {
                            plugin_id: fixture.plugin_id.clone(),
                            generation: other,
                        }),
                    },
                    context("lifecycle-inspect-other-generation"),
                )
                .await
                .map(|_| ()),
            PluginFailureCode::StaleHandle,
            "inspecting a generation that is not the loaded one",
            findings,
        );
    }

    // A second load of a loaded plugin is refused rather than answered with a
    // second instance under one identifier.
    refused_with(
        backend
            .load(
                identity.load(fixture, identity.manifest_sha256.clone()),
                context("lifecycle-duplicate-load"),
            )
            .await
            .map(|_| ()),
        PluginFailureCode::AlreadyLoaded,
        "loading a plugin that is already loaded",
        findings,
    );
    Some(first)
}

/// Unload the instance, prove the identifier is unknown, then load it again.
async fn unload_and_reload<B: PluginExecutionBackend + ?Sized>(
    backend: &B,
    fixture: &LifecycleFixture,
    identity: &FixtureIdentity,
    first: &nemo_relay_plugin_protocol::PluginLoadResponse,
    findings: &mut Vec<String>,
) -> Option<nemo_relay_plugin_protocol::PluginLoadResponse> {
    match backend
        .unload(
            PluginUnloadRequest {
                handle: first.handle.clone(),
            },
            context("lifecycle-unload"),
        )
        .await
    {
        Ok(()) => {}
        Err(error) => findings.push(format!("unloading a loaded instance failed: {error}")),
    }

    // Unloaded: the identifier is unknown now, and a second unload says so. It is
    // *not* reported as stale, because nothing is loaded at another generation —
    // which is the difference the two codes exist to carry.
    refused_with(
        backend
            .inspect(
                PluginInspectRequest {
                    handle: Some(first.handle.clone()),
                },
                context("lifecycle-inspect-unloaded"),
            )
            .await
            .map(|_| ()),
        PluginFailureCode::UnknownPlugin,
        "inspecting an unloaded instance",
        findings,
    );
    refused_with(
        backend
            .unload(
                PluginUnloadRequest {
                    handle: first.handle.clone(),
                },
                context("lifecycle-unload-again"),
            )
            .await,
        PluginFailureCode::UnknownPlugin,
        "unloading an instance that is not loaded",
        findings,
    );

    // Reloading takes a new generation, so the handle from before cannot address
    // the instance that replaced it.
    let second = match backend
        .load(
            identity.load(fixture, identity.manifest_sha256.clone()),
            context("lifecycle-reload"),
        )
        .await
    {
        Ok(loaded) => loaded,
        Err(error) => {
            findings.push(format!("an unloaded plugin did not load again: {error}"));
            return None;
        }
    };
    if second.handle.generation <= first.handle.generation {
        findings.push(format!(
            "a reload took generation {} after {}, so a stale handle can address the new \
             instance",
            second.handle.generation, first.handle.generation
        ));
    }
    Some(second)
}

/// A handle from before a reload must not reach the instance that replaced it.
async fn check_stale_handle<B: PluginExecutionBackend + ?Sized>(
    backend: &B,
    fixture: &LifecycleFixture,
    first: &nemo_relay_plugin_protocol::PluginLoadResponse,
    findings: &mut Vec<String>,
) {
    refused_with(
        backend
            .inspect(
                PluginInspectRequest {
                    handle: Some(PluginHandle {
                        plugin_id: fixture.plugin_id.clone(),
                        generation: first.handle.generation,
                    }),
                },
                context("lifecycle-inspect-stale"),
            )
            .await
            .map(|_| ()),
        PluginFailureCode::StaleHandle,
        "inspecting a handle from before a reload",
        findings,
    );
}

/// Leave the backend as the suite found it, and say so if it is not empty.
async fn leave_nothing_loaded<B: PluginExecutionBackend + ?Sized>(
    backend: &B,
    loaded: &nemo_relay_plugin_protocol::PluginLoadResponse,
    findings: &mut Vec<String>,
) {
    match backend
        .unload(
            PluginUnloadRequest {
                handle: loaded.handle.clone(),
            },
            context("lifecycle-unload-reload"),
        )
        .await
    {
        Ok(()) => {}
        Err(error) => findings.push(format!("unloading the reloaded instance failed: {error}")),
    }
    match backend
        .inspect(
            PluginInspectRequest { handle: None },
            context("lifecycle-inspect-all"),
        )
        .await
    {
        Ok(descriptors) if descriptors.is_empty() => {}
        Ok(descriptors) => findings.push(format!(
            "the lifecycle walk left {} instance(s) loaded",
            descriptors.len()
        )),
        Err(error) => findings.push(format!("inspecting everything failed: {error}")),
    }
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
