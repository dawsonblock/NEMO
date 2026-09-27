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
pub(crate) fn resolve_executable() -> PathBuf {
    resolve_from(
        std::env::var_os(EXECUTABLE_ENV),
        &directory_holding_this_process(),
    )
}

/// The same decision, with the two things it reads passed in.
///
/// Split out so the rule can be tested as a rule: reading the environment and
/// asking where this process lives are the parts a test cannot vary without
/// touching process-wide state, and the part that matters — which input wins —
/// is neither of them.
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
fn directory_holding_this_process() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_default()
}

/// The places a host is looked for once nothing has named one.
fn beside_this_process(beside: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![beside.join(executable_name())];
    if let Some(above) = beside.parent() {
        candidates.push(above.join(executable_name()));
    }
    candidates
}

/// Where a host would have been found, in the order it was looked for.
///
/// Read by the failure the supervisor reports rather than by the resolution
/// above, so a deployment that received a runtime without the host is told which
/// locations it was expected to fill instead of only which file was missing.
pub(crate) fn host_search_locations() -> Vec<PathBuf> {
    let mut locations = Vec::new();
    if let Some(configured) = std::env::var_os(EXECUTABLE_ENV) {
        locations.push(PathBuf::from(configured));
    }
    locations.extend(beside_this_process(&directory_holding_this_process()));
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
