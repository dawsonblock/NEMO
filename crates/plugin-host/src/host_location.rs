// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Which host to start, and the identity its sessions are bound to.
//!
//! Two decisions live here and nothing else does: where the executable is, and
//! what a session started from it is bound to. Both are inputs to starting a host
//! rather than parts of supervising one — the supervisor decides *when* a host is
//! started, how long it may take, and what happens when it dies; this module
//! decides *what* is started and under whose identity.
//!
//! They are separate because they have to be answered by different parties. A
//! deployment answers the first through `NEMO_RELAY_PLUGIN_HOST`, or by installing
//! the host beside the runtime that starts it, and the runtime answers the second
//! because a host that named its own identity would be a host that could claim to
//! be another runtime's. Keeping them together with the session lifecycle is how
//! a binding ends up deriving a security-critical executable from whichever
//! directory it happens to be running in; keeping them here is what makes the
//! rule one thing to read, one thing to test, and one thing to move when the
//! loader itself moves out of the kernel.
//!
//! The rule for the first is deliberately not a search. An environment variable
//! that names a host is authoritative — a deployment that said which host to use
//! gets that host or a failure, never a quiet fallback to whichever executable
//! happens to sit beside the process, because a typo in an override is a
//! configuration mistake and finding it at startup as "the host is not there" is
//! the only reading that keeps the operator's choice meaningful.

use std::path::{Path, PathBuf};

/// Environment variable naming the host executable, for deployments that do not
/// install it beside the process that starts it.
pub const EXECUTABLE_ENV: &str = "NEMO_RELAY_PLUGIN_HOST";

/// Expected Team ID for the restricted host signature. Development qualification
/// may explicitly set `not set` for an ad hoc signature.
pub const TEAM_ID_ENV: &str = "NEMO_RELAY_PLUGIN_HOST_TEAM_ID";

/// The bundle a confined host is installed as.
///
/// A bare executable and a bundle are the same program; what differs is the
/// signature around it. macOS applies App Sandbox through the entitlements a
/// signed bundle carries, so a host that has to be confined has to be installed
/// as one — see [`crate::isolation_policy::NativeIsolationPolicy`].
pub const BUNDLE_NAME: &str = "nemo-plugin-host.app";

/// The identifier whose App Sandbox container receives transferred artifacts.
#[cfg(target_os = "macos")]
pub(crate) const BUNDLE_IDENTIFIER: &str = "com.nvidia.nemo-relay.nemo-plugin-host";

/// The identity a runtime's plugin sessions are bound to.
///
/// Bound to the implementation that asked and to the process it asked from, so a
/// host started for one runtime is refused by another and a host started by a
/// process that has since exited cannot be adopted. Built here rather than in
/// each consumer because the binding is the *host's* check: four consumers
/// computing four spellings of it is four ways to get it wrong.
///
/// An identity rather than a hash: the value is compared and never parsed, the
/// facts it carries are the whole of what a peer can check, and hashing them
/// would add a digest dependency to a crate whose job is to hold no more than it
/// needs. The separators are characters no field can contain, because the value
/// has to be unambiguous as well as unique.
pub fn plugin_runtime_binding(implementation: &str) -> String {
    format!(
        "{implementation}/{version}/{protocol}/{process}",
        implementation = implementation,
        version = env!("CARGO_PKG_VERSION"),
        protocol = nemo_relay_plugin_protocol::PROTOCOL_VERSION,
        process = std::process::id(),
    )
}

/// Where the host executable is, given where this process is.
#[cfg(unix)]
pub(crate) fn resolve_executable() -> PathBuf {
    resolve_from(
        std::env::var_os(EXECUTABLE_ENV),
        &directory_holding_this_process(),
    )
}

/// Where the host lives inside the bundle that carries it.
///
/// The layout is Apple's rather than this project's: an application bundle puts
/// its executable at `Contents/MacOS/<name>`, and the signing that carries the
/// sandbox covers the bundle rather than the file.
pub(crate) fn bundle_executable(bundle: &Path) -> PathBuf {
    bundle
        .join("Contents")
        .join("MacOS")
        .join(executable_name())
}

/// The bundled host installed beside this process, when there is one.
///
/// The same two places a bare host is looked for, because a deployment that
/// installs the host beside the runtime installs the bundle there too: a test
/// harness runs from `deps/` while what it exercises is one directory above.
pub(crate) fn bundled_beside(beside: &Path) -> Option<PathBuf> {
    for directory in beside_directories(beside) {
        let bundle = directory.join(BUNDLE_NAME);
        let executable = bundle_executable(&bundle);
        if executable.is_file() {
            return Some(executable);
        }
    }
    None
}

/// Whether `path` is the executable inside an application bundle.
///
/// Structural rather than a comparison against one known location: a deployment
/// may install a bundle anywhere, and what has to be refused is a *bare*
/// executable being treated as a confined one. `.../X.app/Contents/MacOS/X` is
/// the layout whose signature macOS applies entitlements from.
pub(crate) fn is_bundled_executable(path: &Path) -> bool {
    let Some(macos) = path.parent() else {
        return false;
    };
    if macos.file_name().is_none_or(|name| name != "MacOS") {
        return false;
    }
    let Some(contents) = macos.parent() else {
        return false;
    };
    if contents.file_name().is_none_or(|name| name != "Contents") {
        return false;
    }
    contents
        .parent()
        .and_then(Path::extension)
        .is_some_and(|extension| extension == "app")
}

/// The same decision, with the two things it reads passed in.
///
/// Split out so the rule can be tested as a rule: reading the environment and
/// asking where this process lives are the parts a test cannot vary without
/// touching process-wide state, and the part that matters — which input wins —
/// is neither of them.
#[cfg(any(unix, test))]
pub(crate) fn resolve_from(configured: Option<std::ffi::OsString>, beside: &Path) -> PathBuf {
    if let Some(configured) = configured {
        return PathBuf::from(configured);
    }
    for candidate in beside_this_process(beside) {
        if candidate.exists() {
            return candidate;
        }
    }
    beside.join(executable_name())
}

/// The directory holding the executable that started this process.
///
/// It is the interpreter's own directory for a binding loaded into Python or
/// Node rather than a plugin host's, which is what makes an installation beside
/// the interpreter an installation beside the thing that starts the host. A
/// binding that knows where its own package is resolves there instead, and says
/// so through the policy it hands the composition.
#[cfg(unix)]
fn directory_holding_this_process() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_default()
}

/// The same directory, for the one caller that has to hand it to a policy.
///
/// The supervisor decides *which* executable to start, and under a confinement
/// policy that decision needs the place a host is installed: the module that owns
/// the rule answers it rather than the supervisor guessing.
#[cfg(unix)]
pub(crate) fn this_process_directory() -> PathBuf {
    directory_holding_this_process()
}

/// The places a host is looked for once nothing has named one.
#[cfg(any(unix, test))]
fn beside_this_process(beside: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![beside.join(executable_name())];
    candidates.extend(
        beside_directories(beside)
            .into_iter()
            .skip(1)
            .map(|directory| directory.join(executable_name())),
    );
    candidates
}

/// The directories a host is looked for in: this process's own, then its parent.
fn beside_directories(beside: &Path) -> Vec<PathBuf> {
    let mut directories = vec![beside.to_path_buf()];
    if let Some(above) = beside.parent() {
        directories.push(above.to_path_buf());
    }
    directories
}

/// Where a bundled host would have been found, in the order it was looked for.
///
/// The confinement travels with the bundle, so a deployment that selected a
/// restricted policy and installed none is told which bundles were expected —
/// the same reason [`host_search_locations`] exists for the bare host.
pub(crate) fn bundle_search_locations(beside: &Path) -> Vec<PathBuf> {
    beside_directories(beside)
        .into_iter()
        .map(|directory| bundle_executable(&directory.join(BUNDLE_NAME)))
        .collect()
}

/// Where a host would have been found, in the order it was looked for.
///
/// Read by the failure the supervisor reports rather than by the resolution
/// above, so a deployment that received a runtime without the host is told which
/// locations it was expected to fill instead of only which file was missing.
#[cfg(unix)]
pub(crate) fn host_search_locations() -> Vec<PathBuf> {
    let mut locations = Vec::new();
    if let Some(configured) = std::env::var_os(EXECUTABLE_ENV) {
        locations.push(PathBuf::from(configured));
    }
    locations.extend(beside_this_process(&directory_holding_this_process()));
    // And the confined spelling of the same installation: a deployment that
    // selected the restricted policy and received no bundle is told which bundle
    // was expected, not only that a file was missing.
    locations.extend(bundle_search_locations(&directory_holding_this_process()));
    locations
}

pub(crate) fn executable_name() -> &'static str {
    if cfg!(windows) {
        "nemo-plugin-host.exe"
    } else {
        "nemo-plugin-host"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_override_that_names_a_host_is_the_host_that_is_used() {
        // A deployment that said which host to use gets that host or a failure.
        // Falling back to whichever executable happens to sit beside the process
        // would make the operator's choice advisory, and a typo in it invisible
        // until the mismatched host answered a handshake.
        let directory = std::env::temp_dir();
        let beside = directory.join(format!(
            "nemo-ph-override-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&beside).expect("a directory for the beside case");
        let neighbour = beside.join(executable_name());
        std::fs::write(&neighbour, b"a host this deployment did not ask for").expect("a neighbour");

        let configured = PathBuf::from("/nonexistent/by/override/nemo-plugin-host");
        let resolved = resolve_from(Some(configured.clone().into_os_string()), &beside);

        std::fs::remove_dir_all(&beside).ok();
        assert_eq!(
            resolved, configured,
            "the override has to be authoritative even when it does not exist"
        );
        assert!(
            !neighbour.exists(),
            "the neighbour a fallback would have found was removed with its directory"
        );
    }

    #[test]
    fn a_host_beside_the_process_is_found_when_nothing_names_one() {
        let directory = std::env::temp_dir();
        let beside = directory.join(format!(
            "nemo-ph-beside-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&beside).expect("a directory for the beside case");
        let installed = beside.join(executable_name());
        std::fs::write(&installed, b"a host installed beside the runtime").expect("a host");

        let resolved = resolve_from(None, &beside);

        std::fs::remove_dir_all(&beside).ok();
        assert_eq!(resolved, installed);
    }

    #[test]
    fn a_host_that_is_nowhere_is_named_rather_than_invented() {
        // Fail closed, and fail with the path that was expected: the caller
        // reports it, and a deployment can repair a path it was told.
        let beside = PathBuf::from("/nonexistent/nemo-relay/");
        assert_eq!(
            resolve_from(None, &beside),
            beside.join(executable_name()),
            "nothing is invented when nothing is installed"
        );
    }
}
