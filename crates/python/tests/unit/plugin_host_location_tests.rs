// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The layouts an installed Python package can have, and what each resolves to.
//!
//! These are layout tests rather than resolver tests: each one builds the
//! directory shape an installation actually produces — a virtual environment, a
//! user install, a distribution-package tree, a wheel that carries the host inside
//! the package — and asserts which companion the binding would run. The interpreter
//! is deliberately absent from all of them, because deriving the security-critical
//! companion from `sys.executable`'s directory is the thing being removed.

use std::path::{Path, PathBuf};

use super::{executable_name, host_candidates, resolve};

/// The host a layout resolves to, with nothing in the environment naming one.
fn resolved_in(module_directory: &Path) -> Option<PathBuf> {
    resolve(None, Some(module_directory))
}

/// Build one directory tree from the files it holds.
fn layout(root: &Path, files: &[&str]) -> Vec<PathBuf> {
    files
        .iter()
        .map(|relative| {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
            std::fs::write(&path, b"").expect("a file");
            path
        })
        .collect()
}

/// The directory an installation's scripts live in.
fn scripts_directory() -> &'static str {
    if cfg!(windows) { "Scripts" } else { "bin" }
}

#[test]
fn a_virtual_environment_resolves_the_host_in_its_own_bin() {
    let root = tempfile::tempdir().expect("a layout");
    let host = layout(
        root.path(),
        &[
            "lib/python3.11/site-packages/nemo_relay/_native.abi3.so",
            "bin/nemo-plugin-host",
        ],
    );
    let module = root.path().join("lib/python3.11/site-packages/nemo_relay");

    assert_eq!(
        resolved_in(&module).as_deref(),
        Some(host[1].as_path()),
        "the environment's bin holds the host the wheel installed there"
    );
}

#[test]
fn a_user_install_resolves_the_users_bin_and_not_the_interpreters() {
    let root = tempfile::tempdir().expect("a layout");
    let host = layout(
        root.path(),
        &[
            ".local/lib/python3.11/site-packages/nemo_relay/_native.abi3.so",
            ".local/bin/nemo-plugin-host",
        ],
    );
    let module = root
        .path()
        .join(".local/lib/python3.11/site-packages/nemo_relay");

    assert_eq!(
        resolved_in(&module).as_deref(),
        Some(host[1].as_path()),
        "a user install's scripts are in the user's bin, which is derived from the package"
    );
}

#[test]
fn a_distribution_package_tree_resolves_its_own_prefix() {
    // The spelling a distribution uses: `dist-packages` directly under the
    // interpreter's version directory, and a prefix that is not the user's.
    let root = tempfile::tempdir().expect("a layout");
    let host = layout(
        root.path(),
        &[
            "lib/python3/dist-packages/nemo_relay/_native.abi3.so",
            "bin/nemo-plugin-host",
        ],
    );
    let module = root.path().join("lib/python3/dist-packages/nemo_relay");

    assert_eq!(resolved_in(&module).as_deref(), Some(host[1].as_path()));
}

#[test]
fn a_package_that_carries_its_own_host_means_that_one() {
    let root = tempfile::tempdir().expect("a layout");
    let both = layout(
        root.path(),
        &[
            "lib/python3.11/site-packages/nemo_relay/bin/nemo-plugin-host",
            "bin/nemo-plugin-host",
        ],
    );
    let module = root.path().join("lib/python3.11/site-packages/nemo_relay");

    assert_eq!(
        resolved_in(&module).as_deref(),
        Some(both[0].as_path()),
        "the companion inside the package wins over the environment's scripts"
    );
}

#[test]
fn an_installation_without_a_host_names_where_the_prefix_puts_it() {
    // Nothing is installed, so the answer is the path the environment would have
    // held it at — the failure a deployment reads then names its own environment
    // rather than a directory that belongs to the interpreter.
    let root = tempfile::tempdir().expect("a layout");
    layout(
        root.path(),
        &["lib/python3.11/site-packages/nemo_relay/_native.abi3.so"],
    );
    // The environment's scripts directory is there, because an installation that
    // has the package has that: what it lacks is the host the wheel puts in it.
    std::fs::create_dir_all(root.path().join(scripts_directory())).expect("the scripts directory");
    let module = root.path().join("lib/python3.11/site-packages/nemo_relay");

    assert_eq!(
        resolved_in(&module),
        Some(
            root.path()
                .join(scripts_directory())
                .join(executable_name())
        )
    );
}

#[test]
fn a_configured_host_is_the_host_that_is_used() {
    // The environment is an instruction rather than a guess, so it is read before
    // anything is derived — and it is used exactly as given, even when it is not
    // there, because a deployment that named a host gets that host or a failure.
    let root = tempfile::tempdir().expect("a layout");
    layout(
        root.path(),
        &[
            "lib/python3.11/site-packages/nemo_relay/_native.abi3.so",
            "bin/nemo-plugin-host",
        ],
    );
    let module = root.path().join("lib/python3.11/site-packages/nemo_relay");
    let configured = PathBuf::from("/somewhere/else/nemo-plugin-host");

    assert_eq!(
        resolve(Some(configured.clone().into_os_string()), Some(&module)),
        Some(configured)
    );
}

#[test]
fn the_candidates_never_leave_the_installation() {
    // The bound is the point: a candidate above the prefix would be outside the
    // installation that put the package where it is, which is how a derivation
    // turns into a search.
    let root = tempfile::tempdir().expect("a layout");
    layout(
        root.path(),
        &["lib/python3.11/site-packages/nemo_relay/_native.abi3.so"],
    );
    std::fs::create_dir_all(root.path().join(scripts_directory())).expect("the scripts directory");
    let module = root.path().join("lib/python3.11/site-packages/nemo_relay");
    let candidates = host_candidates(&module);

    assert_eq!(candidates.len(), 2, "{candidates:?}");
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.starts_with(root.path())),
        "every candidate is inside the installation: {candidates:?}"
    );
    assert_eq!(
        candidates[1],
        root.path()
            .join(scripts_directory())
            .join(executable_name())
    );
}
