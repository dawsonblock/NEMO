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

use std::path::{Path, PathBuf};

/// Crates whose sources are scanned for new native-loading code.
const SHIPPED_CRATES: &[&str] = &["core", "cli", "python", "node", "ffi"];

/// `<crate>:<crate-relative path>` that may still load a dynamic library.
const LOADER_PATHS: &[&str] = &["core:plugin/dynamic/native.rs"];

/// `<crate>:<crate-relative path>` that may still call the loader entry point.
const LOAD_CALL_PATHS: &[&str] = &[
    "core:plugin/dynamic/native.rs",
    "core:plugin/dynamic/host.rs",
    // The CLI reaches the loader directly today. This is the exception the
    // milestone's third increment removes, and it is listed rather than left
    // implicit so the guard keeps meaning something for everyone else.
    "cli:server/mod.rs",
];

/// Tokens that only a native loader has any business containing.
const LOADER_TOKENS: &[&str] = &[
    "libloading",
    "dlopen",
    "LoadLibraryW",
    "Library::new",
    "NemoRelayNativePluginEntry",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
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

    for crate_name in SHIPPED_CRATES {
        let src = workspace.join("crates").join(crate_name).join("src");
        let mut sources = Vec::new();
        rust_sources(&src, &mut sources);

        for (path, source) in sources {
            let relative = path
                .split(&format!("crates/{crate_name}/src/"))
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
        }
    }

    assert!(
        offenders.is_empty(),
        "native loading must stay where it is until it moves to a process boundary: {offenders:#?}"
    );
}
