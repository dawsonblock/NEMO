// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test support shared by the plugin-host suites.
//!
//! Two suites load a real native fixture: the process suite watches a child load
//! it, and the lifecycle suite runs the same checks against the in-process
//! backend. Both need the same artifact prepared the same way, so that
//! preparation lives here rather than in two copies that would drift the first
//! time a manifest field changed.

// Each test target compiles its own copy of this module, so an item only one of
// them uses is not dead code — it is the other target's.
#![allow(dead_code)]

use std::path::PathBuf;

use nemo_relay_plugin_host::conformance::LifecycleFixture;

/// A fixture library, and the manifest written to describe it.
///
/// The manifest lives in its own directory under the temporary directory and is
/// removed when this is dropped, so a suite that loads a plugin leaves the
/// filesystem as it found it even when an assertion fails.
pub struct PreparedFixture {
    /// The identifier the manifest declares, and the one a load is made under.
    plugin_id: String,
    /// Directory holding the manifest.
    directory: PathBuf,
    /// Path to the manifest.
    artifact: String,
}

impl PreparedFixture {
    /// Write a manifest describing `library` under `plugin_id`.
    ///
    /// The library is resolved by the caller, so a suite says which fixture it
    /// means rather than inheriting whichever one the environment happens to
    /// name.
    pub fn write(plugin_id: &str, directory_prefix: &str, library: PathBuf, symbol: &str) -> Self {
        assert!(
            library.exists(),
            "the native fixture is missing; run `just build-test-plugin-fixtures`: {}",
            library.display()
        );
        let directory = std::env::temp_dir().join(format!(
            "{directory_prefix}-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&directory).expect("a manifest directory");
        let manifest = directory.join("relay-plugin.toml");
        std::fs::write(
            &manifest,
            format!(
                "manifest_version = 1\n\n[plugin]\nid = \"{plugin_id}\"\nkind = \
                 \"rust_dynamic\"\n\n[compat]\nrelay = \"={}\"\nnative_api = \
                 \"1\"\n\n[defaults]\nenabled = false\n\n[capabilities]\nitems = \
                 [\"plugin_native\"]\n\n[load]\nlibrary = \"{}\"\nsymbol = \"{symbol}\"\n",
                env!("CARGO_PKG_VERSION"),
                library.display()
            ),
        )
        .expect("write the manifest");
        Self {
            plugin_id: plugin_id.to_owned(),
            directory,
            artifact: manifest.to_string_lossy().into_owned(),
        }
    }

    /// The same artifact, as the shared lifecycle suite takes it.
    pub fn lifecycle(&self) -> LifecycleFixture {
        LifecycleFixture {
            plugin_id: self.plugin_id.clone(),
            artifact: self.artifact.clone(),
        }
    }

    /// Path to the manifest, for a load made directly.
    pub fn artifact(&self) -> String {
        self.artifact.clone()
    }
}

impl Drop for PreparedFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// The full native fixture, from the environment or from the workspace build.
pub fn native_fixture() -> PathBuf {
    fixture_path(
        "NEMO_RELAY_TEST_NATIVE_PLUGIN",
        "libnemo_relay_plugin_fixture.dylib",
    )
}

/// The single-registration native fixture.
pub fn intercept_fixture() -> PathBuf {
    fixture_path(
        "NEMO_RELAY_TEST_NATIVE_INTERCEPT_PLUGIN",
        "libnemo_relay_native_intercept_fixture.dylib",
    )
}

fn fixture_path(variable: &str, file_name: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/test-plugin-fixtures/debug")
                .join(file_name)
        })
}
