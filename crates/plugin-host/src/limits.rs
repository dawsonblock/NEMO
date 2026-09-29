// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The bounds the host process runs under.
//!
//! Process separation contains a plugin that crashes or hangs. It does not
//! contain a plugin that allocates, opens files or spawns processes without
//! limit: those consume the *machine's* resources, not the plugin's, and the
//! child inherits the kernel's ability to take as much as it likes.
//!
//! These are the bounds that stop that: the host is started with the limits
//! below, applied between `fork` and `exec`, so nothing it does afterwards can
//! raise them. They are ceilings rather than budgets — a plugin that needs more
//! than the default is a plugin whose deployment has to say so — and they are
//! deliberately not the whole of a sandbox: address-space and descriptor limits
//! bound what one process takes from the machine, and they do not bound what it
//! may read, write or connect to. That is a separate decision, recorded in
//! `security/PLUGIN-ISOLATION.md`.

/// Bounds a host process is started under.
///
/// Every field is a choice a deployment makes. The defaults are the ones this
/// repository ships with, and an operator who needs different ones sets them
/// here rather than in the plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginHostLimits {
    /// Largest address space the host may use, in bytes.
    ///
    /// A ceiling rather than a budget: a host that needs more than this to run a
    /// plugin is doing something other than hosting one. Set to `None` only
    /// where the deployment has another way to bound memory — a cgroup, a
    /// container, or a machine it owns outright.
    ///
    /// Applied where the platform honours it. Linux does; macOS rejects a small
    /// `RLIMIT_AS` with `EINVAL` and does not enforce one meaningfully, so the
    /// shipped default leaves it unset there and a macOS deployment bounds
    /// memory some other way. A limit that is set and refused is a failure to
    /// start rather than a limit quietly skipped: a host running without the
    /// bound its deployment asked for is the thing this exists to prevent.
    pub maximum_address_space_bytes: Option<u64>,
    /// Largest number of processes the host may have while it runs.
    ///
    /// `None` by default, and not because a limit would be unwelcome:
    /// `RLIMIT_NPROC` counts the *user's* processes rather than this process's,
    /// so a value chosen without knowing the machine can stop the host from
    /// creating the threads its own runtime needs. A deployment that knows the
    /// machine's shape can set one.
    pub maximum_processes: Option<u64>,
    /// Largest number of open files the host may hold.
    pub maximum_open_files: Option<u64>,
    /// Whether the host may gain privileges by executing a set-user-ID binary.
    ///
    /// Applied where the platform has the notion (Linux). The host runs a
    /// plugin's code, and a plugin that could escalate through an inherited
    /// privilege would be outside every other bound here.
    pub no_new_privileges: bool,
}

impl Default for PluginHostLimits {
    fn default() -> Self {
        Self {
            maximum_address_space_bytes: default_address_space_limit(),
            maximum_processes: None,
            maximum_open_files: Some(4096),
            no_new_privileges: true,
        }
    }
}

/// The address-space ceiling the shipped profile asks for, where it is one the
/// platform can honour.
///
/// Measured rather than assumed: the same value that Linux applies is refused by
/// macOS with `EINVAL`, and there is no smaller value macOS accepts. Asking for
/// a bound a platform cannot enforce would turn a default into a host that never
/// starts.
const fn default_address_space_limit() -> Option<u64> {
    if cfg!(target_os = "linux") {
        Some(8 * 1024 * 1024 * 1024)
    } else {
        None
    }
}

/// Apply `limits` to the calling process.
///
/// The supervisor calls this between `fork` and `exec`, where only
/// async-signal-safe work may run: it sets limits and nothing else, allocates
/// nothing, and takes no locks. It is public because that is also the useful
/// shape for anything else that wants to start a child under these bounds, and
/// because the evidence that the bounds reach a child belongs in `tests/`
/// rather than inside the measured surface.
///
/// # Errors
/// Returns the platform's refusal. A limit the platform will not accept is a
/// failure rather than a limit quietly skipped: a process started without the
/// bound its deployment asked for is the thing this exists to prevent.
///
/// # Platform
/// Unix. The `limits` module is compiled only where these calls exist.
#[cfg(unix)]
pub fn apply(limits: &PluginHostLimits) -> std::io::Result<()> {
    use rustix::process::{Resource, Rlimit, setrlimit};

    for (resource, value) in [
        (Resource::As, limits.maximum_address_space_bytes),
        (Resource::Nproc, limits.maximum_processes),
        (Resource::Nofile, limits.maximum_open_files),
    ] {
        let Some(value) = value else {
            continue;
        };
        // Soft and hard together: a child that could put the soft limit back up
        // to a higher hard limit would not be bounded by either.
        setrlimit(
            resource,
            Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        )
        .map_err(std::io::Error::from)?;
    }

    #[cfg(target_os = "linux")]
    if limits.no_new_privileges {
        rustix::thread::set_no_new_privs(true).map_err(std::io::Error::from)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped profile asks for the bounds the crate documents.
    ///
    /// The evidence that those bounds reach a child process is in
    /// `tests/limits.rs`, which starts one through the same call the supervisor
    /// uses: a test that spawns processes does not belong in the module whose
    /// size the TCB budget measures.
    #[test]
    fn the_default_profile_bounds_what_one_plugin_can_take() {
        let limits = PluginHostLimits::default();
        assert!(
            limits.maximum_address_space_bytes.is_some() == cfg!(target_os = "linux"),
            "an address-space bound is asked for exactly where the platform honours it: {:?}",
            limits.maximum_address_space_bytes
        );
        assert!(
            limits.maximum_open_files.is_some(),
            "a plugin that opens files without limit takes the machine's descriptors"
        );
        assert!(
            limits.no_new_privileges,
            "a plugin runs with whatever privileges its host had"
        );
    }
}
