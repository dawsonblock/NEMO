// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Where this installation's plugin host is.
//!
//! The host runs native plugin code beside the runtime, so which binary it is has
//! to come from the artifact that shipped it rather than from the process that
//! happens to be running. This binding used to leave that to the runtime's own
//! rule, which derives the companion from the directory holding `sys.executable`.
//! That is the right directory in one layout and the wrong one in the rest: a
//! virtual environment puts its interpreter and its scripts in the same place, a
//! user install puts the package's scripts in the user's bin and the interpreter
//! in the system's, and an interpreter that is not the environment's — a symlink,
//! an embedded interpreter, a wrapper — names a directory that has nothing to do
//! with this package. In those layouts the old rule looked in a shared location
//! for a binary that runs plugin code, and found whatever answered to that name.
//!
//! What it does instead is derive the answer from the package's own path, which
//! needs no interpreter at all. The extension records where it was loaded from at
//! module init, and the candidates follow from that: the package's own `bin/`, and
//! the scripts directory of the installation prefix the package sits inside.
//!
//! A deployment that names a host in `NEMO_RELAY_PLUGIN_HOST` is still the one in
//! charge: the environment is an instruction rather than a guess, and it is read
//! before anything is derived.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// How far above the extension the installation prefix can be.
///
/// A package is installed at `<prefix>/lib/pythonX.Y/site-packages/nemo_relay` or
/// `<prefix>/lib/pythonX/dist-packages/nemo_relay` on POSIX, and at
/// `<prefix>/Lib/site-packages/nemo_relay` on Windows, so the prefix is at most
/// four levels up. The bound is what keeps this a derivation rather than a search:
/// a candidate above it would be outside the installation that put the package
/// where it is.
const PREFIX_DEPTH: usize = 4;

/// The directory the extension was loaded from, recorded once at module init.
static MODULE_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

/// Record where this extension lives.
///
/// Called from module init, which is the only moment the answer is available
/// without asking the import system again. A second call is ignored: the first
/// answer is where this process loaded the extension from.
pub(crate) fn remember_module_file(file: &Path) {
    if let Some(directory) = file.parent() {
        let _ = MODULE_DIRECTORY.set(directory.to_path_buf());
    }
}

/// The host this binding should run plugins in.
///
/// `None` only when nothing named one *and* this extension never learned where it
/// lives, which leaves the runtime's own resolution in place. Every other answer
/// is a path: a host that is not there is a failure that names where the
/// installation would have put it, rather than a fall back to somewhere else.
pub(crate) fn resolved_host() -> Option<PathBuf> {
    resolve(
        std::env::var_os(crate::plugin_host_location::EXECUTABLE_ENV),
        MODULE_DIRECTORY.get().map(PathBuf::as_path),
    )
}

/// The variable a deployment names a host in.
///
/// The same one the runtime reads, named here rather than spelled again, so a
/// deployment that exports it and a runtime that honours it cannot disagree.
pub(crate) const EXECUTABLE_ENV: &str = nemo_relay_plugin_host::supervisor::EXECUTABLE_ENV;

/// The rule, with both of its inputs passed in.
///
/// Split out for the reason the supervisor splits its own: reading the environment
/// and asking where the module was loaded from are the parts a test cannot vary
/// without touching process-wide state, and the part that matters — which input
/// wins, and what the candidates are — is neither of them.
pub(crate) fn resolve(
    configured: Option<std::ffi::OsString>,
    module: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(configured) = configured {
        return Some(PathBuf::from(configured));
    }
    let module = module?;
    let candidates = host_candidates(module);
    candidates
        .iter()
        .find(|candidate| candidate.is_file())
        .or_else(|| candidates.last())
        .cloned()
}

/// Where an installation of this package puts the host, nearest first.
///
/// 1. `bin/` inside the package itself: a wheel that carries the host inside
///    `nemo_relay/` puts it here, and a package that carries its own companion
///    means it.
/// 2. the scripts directory of the installation prefix the package sits inside,
///    which is where an installer puts a wheel's script entries — and the layout
///    this repository's wheel uses today.
///
/// The environment candidate is last because it is also the one reported when
/// neither exists: a deployment told to look in its own environment is being told
/// something true about where the install puts things, which a path derived from
/// the interpreter would not be.
pub(crate) fn host_candidates(module_directory: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![module_directory.join("bin").join(executable_name())];
    if let Some(scripts) = environment_scripts(module_directory) {
        candidates.push(scripts.join(executable_name()));
    }
    candidates
}

/// The scripts directory of the installation this package sits inside.
///
/// The prefix is the nearest ancestor that has a scripts directory, because that
/// is what an installation prefix is: a package directory has none, a
/// `site-packages` has none, and the environment holding both does. Asking what a
/// directory *is* keeps this a derivation; asking whether a host is inside it
/// would be a search, and a search is what this module exists to remove.
pub(crate) fn environment_scripts(module_directory: &Path) -> Option<PathBuf> {
    module_directory
        .ancestors()
        .skip(1)
        .take(PREFIX_DEPTH)
        .map(|prefix| prefix.join(scripts_directory_name()))
        .find(|candidate| candidate.is_dir())
}

fn scripts_directory_name() -> &'static str {
    if cfg!(windows) { "Scripts" } else { "bin" }
}

fn executable_name() -> &'static str {
    if cfg!(windows) {
        "nemo-plugin-host.exe"
    } else {
        "nemo-plugin-host"
    }
}

#[cfg(test)]
#[path = "../tests/unit/plugin_host_location_tests.rs"]
mod tests;
