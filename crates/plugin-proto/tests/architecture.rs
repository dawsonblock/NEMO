// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keeps the plugin wire protocol in exactly one place.
//!
//! The plan requires that the process host cannot invent a second, hidden
//! vocabulary. Checking that by hand is what a reviewer forgets, so it is a
//! test: `.proto` files and protobuf code generation are allowed in this crate
//! and in the worker protocol crate that predates it, and nowhere else.

use std::path::{Path, PathBuf};

/// Crates allowed to declare a protobuf schema of their own.
const WIRE_CRATES: &[&str] = &["plugin-proto", "worker-proto"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn rust_sources(root: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, into);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            into.push(path);
        }
    }
}

fn proto_files(root: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name == "target" || name == "node_modules" {
            continue;
        }
        if path.is_dir() {
            proto_files(&path, into);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "proto")
        {
            into.push(path);
        }
    }
}

#[test]
fn only_a_wire_crate_declares_the_plugin_protocol() {
    let workspace = workspace_root();
    let mut offenders = Vec::new();

    for crate_name in WIRE_CRATES {
        assert!(
            workspace.join("crates").join(crate_name).is_dir(),
            "{crate_name} is named as a wire crate but does not exist"
        );
    }

    let mut protos = Vec::new();
    proto_files(&workspace.join("crates"), &mut protos);
    for path in protos {
        let relative = path.strip_prefix(&workspace).unwrap_or(&path);
        let allowed = WIRE_CRATES
            .iter()
            .any(|crate_name| relative.starts_with(Path::new("crates").join(crate_name)));
        if !allowed {
            offenders.push(format!("{} declares a schema", relative.display()));
        }
    }

    let mut sources = Vec::new();
    rust_sources(&workspace.join("crates"), &mut sources);
    for path in sources {
        let relative = path.strip_prefix(&workspace).unwrap_or(&path);
        let allowed = WIRE_CRATES
            .iter()
            .any(|crate_name| relative.starts_with(Path::new("crates").join(crate_name)));
        if allowed {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        if source.contains("include_proto!") {
            offenders.push(format!("{} generates protobuf types", relative.display()));
        }
    }

    assert!(
        offenders.is_empty(),
        "the plugin wire protocol must live in one place: {offenders:#?}"
    );
}
