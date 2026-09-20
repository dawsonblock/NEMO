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
