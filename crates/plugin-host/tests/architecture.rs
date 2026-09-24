// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keeps native loading inside the one place it is allowed to be.
//!
//! The plugin-isolation milestone exists to move dynamic library loading out of
//! the kernel process. Until that happens the loader is still there, so the risk
//! is not the existing code — it is new code that quietly joins it. This test
//! makes that visible immediately rather than at the end of the milestone, when
//! the count would only be larger.
//!
//! Grandfathering is by path and is deliberately narrow. Removing an entry is
//! expected as the loader moves; adding one is the thing this test exists to
//! make a decision rather than an accident.
//!
//! The crate list is read from the workspace manifest rather than written here,
//! because a hand-written list is a list someone has to remember to extend: a new
//! crate that loads a library would be invisible until somebody noticed. The
//! dependency checks close the other half — a crate can reach the loader without
//! naming it, by depending on the crate that owns it.
//!
//! The same reasoning covers time. A budget belongs to an invocation and comes
//! from the runtime, so a duration written into the plugin-execution path is a
//! deadline somebody chose there — the shape the audit found as a `30_000`
//! constant. That check is source-level because the mistake is legible there: a
//! number in these files reads as policy whether or not it reaches a caller.

use std::path::{Path, PathBuf};

/// `<crate>:<crate-relative path>` that may still load a dynamic library.
const LOADER_PATHS: &[&str] = &["core:plugin/dynamic/native.rs"];

/// `<crate>:<crate-relative path>` that may still call the loader entry point.
///
/// `plugin-host` is not a grandfather but the destination: reaching the loader
/// is what that crate exists to do, and the entry is the seam implementation the
/// process backend replaces.
const LOAD_CALL_PATHS: &[&str] = &[
    "core:plugin/dynamic/native.rs",
    "core:plugin/dynamic/host.rs",
    "plugin-host:lib.rs",
];

/// Tokens that only a native loader has any business containing.
///
/// `NemoRelayNativePluginEntry` is deliberately not one of them: the SDK
/// declares that type, because it is the ABI's entry-point signature, and
/// declaring a signature is not loading anything.
const LOADER_TOKENS: &[&str] = &["libloading", "dlopen", "LoadLibraryW", "Library::new"];

/// Core API that loads native plugins inside whichever process calls it.
///
/// Checking for direct calls to the loader alone missed the real path: Node,
/// Python, and FFI do not call `load_native_plugins`, they call this, and core
/// loads on their behalf. Naming the current callers makes the remaining
/// migration visible instead of invisible, and stops a *new* consumer from
/// adopting the same route while it is being replaced.
const INDIRECT_LOAD_CALLERS: &[&str] = &["ffi", "node", "python"];

/// The token that identifies a call through that API.
const INDIRECT_LOAD_TOKEN: &str = "PluginHostActivation::";

/// Crates that may declare the dynamic loader as a dependency.
///
/// One entry, and it shrinks when the loader moves — a second crate appearing
/// here is the decision this test exists to force.
const LOADER_CRATES: &[&str] = &["core"];

/// Crates the kernel may not depend on, because the edge would point upward.
const KERNEL_FORBIDDEN_DEPENDENCIES: &[&str] = &["nemo-relay-plugin-host"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

/// Every directory the workspace manifest declares as a member.
///
/// The manifest is read as text rather than through a TOML parser because the
/// part that matters is a list of paths, and a parser would be a dependency this
/// test does not need. A member written in a form this cannot read is reported
/// rather than skipped.
fn workspace_members(root: &Path) -> Vec<PathBuf> {
    let manifest =
        std::fs::read_to_string(root.join("Cargo.toml")).expect("the workspace manifest");
    let members = manifest
        .split_once("members = [")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(members, _)| members.to_owned())
        .expect("the workspace manifest declares members");

    let mut paths = Vec::new();
    for line in members.lines() {
        let member = line.trim().trim_end_matches(',').trim_matches('"').trim();
        if member.is_empty() || member.starts_with('#') {
            continue;
        }
        if let Some((prefix, _suffix)) = member.split_once('*') {
            let base = root.join(prefix.trim_end_matches('/'));
            let Ok(entries) = std::fs::read_dir(&base) else {
                panic!(
                    "a glob member '{}' names a directory that does not exist",
                    base.display()
                );
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.join("Cargo.toml").exists() {
                    paths.push(path);
                }
            }
        } else {
            paths.push(root.join(member));
        }
    }
    paths.sort();
    paths
}

fn package_name(crate_dir: &Path) -> String {
    let manifest =
        std::fs::read_to_string(crate_dir.join("Cargo.toml")).expect("a member manifest");
    manifest
        .lines()
        .find_map(|line| line.trim().strip_prefix("name = "))
        .map(|name| name.trim().trim_matches('"').to_owned())
        .unwrap_or_else(|| panic!("{} declares no package name", crate_dir.display()))
}

/// Dependencies a manifest declares, as written.
fn declared_dependencies(crate_dir: &Path) -> Vec<String> {
    let manifest =
        std::fs::read_to_string(crate_dir.join("Cargo.toml")).expect("a member manifest");
    manifest
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, _)| name.trim().trim_matches('"').to_owned())
        .collect()
}

fn rust_sources(root: &Path, into: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, into);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            into.push((
                path.to_string_lossy().replace('\\', "/"),
                std::fs::read_to_string(&path).unwrap_or_default(),
            ));
        }
    }
}

fn code_lines(source: &str) -> impl Iterator<Item = &str> {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
}

/// Paths that decide what an invocation may be given, and the fixed durations
/// that would be a deadline chosen locally in each.
///
/// The token list is empty where a fixed duration is transport mechanics rather
/// than policy — how long to wait for a socket to appear, how long to sleep
/// between checks — and non-empty where *any* fixed duration in the file would
/// be a budget nobody configured.
const BUDGET_DECIDING_PATHS: &[(&str, &[&str])] = &[
    (
        "plugin-host:proxy.rs",
        &["Duration::from_secs", "Duration::from_millis"],
    ),
    (
        "core:plugin/execution.rs",
        &["Duration::from_secs", "Duration::from_millis"],
    ),
    ("plugin-host:supervisor.rs", &[]),
];

/// Constants whose name alone says they are a budget chosen in the wrong place.
const BUDGET_CONSTANT_TOKENS: &[&str] =
    &["PROXY_BUDGET", "DEFAULT_PLUGIN_TIMEOUT", "DEFAULT_BUDGET"];

/// The lines of a file that are not behind `#[cfg(test)]`.
///
/// A test fixture may state any duration it likes, so a test module is skipped —
/// but only the block is skipped, not everything after the first marker, because
/// production code below a conditional helper is still production code and a
/// scan that stopped at the first marker would not see it.
fn production_lines(source: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    let mut skipping: Option<i32> = None;
    for (index, line) in source.lines().enumerate() {
        match skipping {
            Some(depth) => {
                let mut next = depth;
                for character in line.chars() {
                    match character {
                        '{' => next += 1,
                        '}' => next -= 1,
                        _ => {}
                    }
                }
                skipping = (next > 0).then_some(next);
            }
            None => {
                if line.trim() == "#[cfg(test)]" {
                    skipping = Some(0);
                    continue;
                }
                lines.push((index + 1, line));
            }
        }
    }
    lines
}

/// A number written in thousands, which in these files is a duration somebody
/// picked: `30_000`, `5_000`, `1_500`. Returns the literal as written.
fn thousand_grouped_literal(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'_' {
            continue;
        }
        let before = &bytes[..index];
        let after = &bytes[index + 1..];
        let digits_before = before.last().is_some_and(u8::is_ascii_digit);
        let digits_after = after.len() >= 3 && after[..3].iter().all(u8::is_ascii_digit);
        if !(digits_before && digits_after) {
            continue;
        }
        let start = before
            .iter()
            .rposition(|byte| !byte.is_ascii_digit())
            .map_or(0, |position| position + 1);
        let end = index
            + 1
            + after
                .iter()
                .position(|byte| !byte.is_ascii_digit())
                .unwrap_or(after.len());
        return Some(&line[start..end]);
    }
    None
}

#[test]
fn no_plugin_execution_path_chooses_its_own_budget() {
    let workspace = workspace_root();
    let mut offenders = Vec::new();

    for member in workspace_members(&workspace) {
        let crate_name = member
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let src = member.join("src");
        if !src.is_dir() {
            continue;
        }
        let mut sources = Vec::new();
        rust_sources(&src, &mut sources);

        for (path, source) in sources {
            let relative = path
                .split(&format!("{crate_name}/src/"))
                .nth(1)
                .unwrap_or(&path)
                .to_owned();
            let qualified = format!("{crate_name}:{relative}");
            let Some((_, duration_tokens)) = BUDGET_DECIDING_PATHS
                .iter()
                .find(|(path, _)| *path == qualified)
            else {
                continue;
            };

            for (number, line) in production_lines(&source) {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if let Some(literal) = thousand_grouped_literal(line) {
                    offenders.push(format!(
                        "{qualified}:{number} states the duration {literal} locally: {}",
                        line.trim()
                    ));
                }
                for token in *duration_tokens {
                    if line.contains(token) {
                        offenders.push(format!(
                            "{qualified}:{number} builds a duration locally with {token}"
                        ));
                    }
                }
                for token in BUDGET_CONSTANT_TOKENS {
                    if line.contains(token) {
                        offenders.push(format!("{qualified}:{number} names {token}"));
                    }
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a plugin-execution path must take its budget from the runtime rather than \
         choose one: {offenders:#?}"
    );
}

#[test]
fn no_new_native_loading_appears_outside_the_grandfathered_paths() {
    let workspace = workspace_root();
    let mut offenders = Vec::new();

    for member in workspace_members(&workspace) {
        // The crate label is the directory name, which is what the grandfathered
        // paths are written in, and it is checked against the package name so a
        // rename cannot quietly move a crate out of the scan.
        let crate_name = member
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let src = member.join("src");
        if !src.is_dir() {
            continue;
        }
        let mut sources = Vec::new();
        rust_sources(&src, &mut sources);

        for (path, source) in sources {
            let relative = path
                .split(&format!("{crate_name}/src/"))
                .nth(1)
                .unwrap_or(&path)
                .to_owned();
            let qualified = format!("{crate_name}:{relative}");

            if !LOADER_PATHS.contains(&qualified.as_str())
                && code_lines(&source)
                    .any(|line| LOADER_TOKENS.iter().any(|token| line.contains(token)))
            {
                offenders.push(format!(
                    "{crate_name}:{relative} contains native-loading code"
                ));
            }

            if !LOAD_CALL_PATHS.contains(&qualified.as_str())
                && code_lines(&source).any(|line| line.contains("load_native_plugins("))
            {
                offenders.push(format!("{crate_name}:{relative} calls the native loader"));
            }

            if !INDIRECT_LOAD_CALLERS.contains(&crate_name.as_str())
                && code_lines(&source).any(|line| line.contains(INDIRECT_LOAD_TOKEN))
            {
                offenders.push(format!(
                    "{crate_name}:{relative} loads native plugins through the core \
                     activation API instead of the backend seam"
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "native loading must stay where it is until it moves to a process boundary: {offenders:#?}"
    );
}

/// Tokens that mean a crate is assembling the boundary itself.
///
/// `ProcessLoadedPlugins` exists so the four consumers that will select isolated
/// plugins compose it once. A consumer that spawned its own supervisor, loaded
/// through its own backend and installed its own proxies would be four subtly
/// different lifecycle semantics wearing one interface, and the differences
/// would show up as failures only one of them could reproduce.
const COMPOSITION_TOKENS: &[&str] = &[
    "ProcessPluginBackend::launch(",
    "PluginHostSupervisor::spawn(",
    "proxy::install(",
];

/// The crate that owns the composition, and the only one that may assemble it.
const COMPOSITION_OWNER: &str = "plugin-host";

#[test]
fn only_the_composition_owner_assembles_the_process_boundary() {
    let workspace = workspace_root();
    let mut offenders = Vec::new();

    for member in workspace_members(&workspace) {
        let crate_name = member
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if crate_name == COMPOSITION_OWNER {
            continue;
        }
        for directory in ["src", "tests"] {
            let root = member.join(directory);
            if !root.is_dir() {
                continue;
            }
            let mut sources = Vec::new();
            rust_sources(&root, &mut sources);
            for (path, source) in sources {
                for (index, line) in production_lines(&source) {
                    if line.trim_start().starts_with("//") {
                        continue;
                    }
                    for token in COMPOSITION_TOKENS {
                        if line.contains(token) {
                            offenders.push(format!(
                                "{path}:{index} assembles the boundary with {token}; \
                                 call ProcessLoadedPlugins instead"
                            ));
                        }
                    }
                }
            }
        }
    }

    assert!(offenders.is_empty(), "{offenders:#?}");
}

#[test]
fn the_loader_is_a_dependency_of_one_crate_and_the_kernel_does_not_depend_on_the_implementation() {
    let workspace = workspace_root();
    let mut problems = Vec::new();

    for member in workspace_members(&workspace) {
        let crate_name = member
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dependencies = declared_dependencies(&member);

        // The loader is a dependency of exactly the crate that owns it. A second
        // crate naming it is either a mistake or a decision, and either way it is
        // one this test makes visible.
        if dependencies.iter().any(|name| name == "libloading")
            && !LOADER_CRATES.contains(&crate_name.as_str())
        {
            problems.push(format!(
                "{crate_name} declares the dynamic loader, which only {} may",
                LOADER_CRATES.join(", ")
            ));
        }

        // The kernel must not depend on the implementation of its own seam:
        // whoever composes the runtime chooses a backend, and an edge from the
        // kernel to one of them is the upward dependency this milestone exists
        // to prevent.
        if crate_name == "core" {
            for forbidden in KERNEL_FORBIDDEN_DEPENDENCIES {
                if dependencies.iter().any(|name| name == forbidden) {
                    problems.push(format!("the kernel depends on {forbidden}"));
                }
            }
        }

        // And a crate that names a package has a package name, so a manifest
        // this scan cannot read is a failure rather than a silent gap.
        let package = package_name(&member);
        if package.is_empty() {
            problems.push(format!("{crate_name} declares no package name"));
        }
    }

    assert!(problems.is_empty(), "{problems:#?}");
}

/// The registration classes the boundary serves today, and the ones it does not.
///
/// This is the number that gates the rest of the migration. The CLI has cut
/// over, and the three entries in [`INDIRECT_LOAD_CALLERS`] have not — not
/// because their composition is different, but because of this list: a plugin
/// that registers any class the boundary cannot serve is refused **whole**, and
/// the bindings' plugin fixtures register all sixteen. Widening this set is what
/// makes the last three consumers interchangeable with the CLI, and it is also
/// what those grandfather entries wait on.
///
/// The test is written as an equality rather than a subset so that growth is a
/// decision with a diff, and as two lists so that the gap is visible rather than
/// implied. The first entry to move was the tool execution intercept: the class
/// that wraps a call, which needed the kernel to hold a suspended chain position
/// and resume it when the host asked. The last, so far, is the LLM stream execution
/// intercept: the class whose answer is a stream, which needed the duplex session, a
/// kernel that routes instead of producing, and the mark window that follows
/// execution across the plugin's own task — all of it qualified before it was
/// advertised.
///
/// The last three to move are the event sanitizers — mark, scope start, scope end —
/// and they moved together because they are one shape: a *projection* goes down (the
/// name a sanitizer decides on, the phase when it is a scope event, and the mutable
/// fields it may change) and the fields come back, so the class, the registration and
/// the event's identity stay the kernel's. What each one needed was a proxy, a
/// host-side runner and a core door that runs exactly the registration the kernel
/// names, and all three were qualified through a real child before this list grew.
#[test]
fn the_boundary_serves_a_named_subset_of_the_registration_surface() {
    use nemo_relay_plugin_host::supervisor::ProcessPluginBackend;
    use nemo_relay_plugin_protocol::PluginRegistrationOperation as Operation;

    let served = ProcessPluginBackend::supported_registration_operations();

    let expected = [
        Operation::ToolRequestIntercept,
        Operation::LlmRequestIntercept,
        Operation::Subscriber,
        Operation::EventMetadataInjector,
        Operation::ToolConditionalExecutionGuardrail,
        Operation::LlmConditionalExecutionGuardrail,
        Operation::ToolSanitizeRequestGuardrail,
        Operation::ToolSanitizeResponseGuardrail,
        Operation::ToolExecutionIntercept,
        Operation::LlmExecutionIntercept,
        Operation::LlmStreamExecutionIntercept,
        Operation::MarkSanitizeGuardrail,
        Operation::ScopeSanitizeStartGuardrail,
        Operation::ScopeSanitizeEndGuardrail,
    ];
    assert_eq!(
        served, expected,
        "the classes the boundary serves changed; each new entry needs a proxy, a \
         host-side invocation path, and a core entry point that runs exactly that \
         registration"
    );

    // The pair that does not cross, named so the gap is a fact in the tree and not
    // something to rediscover: an LLM sanitize call is given a codec capability
    // beside the request, and in the host that capability exists only as a
    // *completion*-scoped ABI object. A unary invocation across the boundary has no
    // completion to hang one on, so this pair is the one the codec-reference
    // protocol has to be settled for before either direction can be advertised.
    let not_served = [
        Operation::LlmSanitizeRequestGuardrail,
        Operation::LlmSanitizeResponseGuardrail,
    ];
    for operation in not_served {
        assert!(
            !served.contains(&operation),
            "{operation:?} is not served yet; if it has become servable, this list \
             is what the bindings' cutover was waiting for"
        );
    }
    assert_eq!(
        served.len() + not_served.len(),
        16,
        "the registration surface is sixteen classes; a change here means the ABI \
         grew and both lists need revisiting"
    );
}
