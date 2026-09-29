// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! How much a host process is contained, and what has to exist before it starts.
//!
//! Process separation is the first bound and it is already here: a plugin that
//! crashes or hangs takes its host down rather than the kernel's process, and the
//! supervisor kills what it started. What separation does *not* do is bound what
//! a plugin may read, write or connect to — the host inherits the kernel's
//! ambient authority, which means a plugin's code does too.
//!
//! The levels below are the deployment's statement about that. They are explicit
//! rather than automatic, because a runtime that silently confined a plugin that
//! needs a network connection would break working installations, and a runtime
//! that silently *did not* confine one whose deployment asked for it would be
//! worse than either: the configuration would describe a boundary that is not
//! there. Selecting a level this build cannot deliver is therefore a failure to
//! start, which is the same rule the resource limits follow.
//!
//! Third level, deliberately not a variant: a VM boundary for code assumed
//! hostile. It is a different mechanism with a different host image, and a
//! variant nothing can honor would read as a feature.

use std::path::{Path, PathBuf};

use nemo_relay_plugin_protocol::{PluginFailureCode, PluginProtocolError};

use crate::host_location;

/// Whether the end-to-end approved artifact load path is qualified for restriction.
///
/// The restricted host now creates its two Unix-domain endpoints inside the
/// sandbox container and reports them through the startup pipe. The parent binds
/// the callback endpoint there before releasing host startup. However, the macOS
/// process test has not completed a plugin load: App Sandbox denies removal of
/// the quarantine metadata on the staged copy, and `dlopen` cannot be qualified.
/// Keep the policy fail-closed until that platform behavior has a supported fix.
const RESTRICTED_ARTIFACT_LOAD_QUALIFIED: bool = false;

/// How much a host process is contained.
///
/// The name is about the *host*, not the plugin: what changes between the levels
/// is which process the plugin's code runs in and what the platform lets that
/// process do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NativeIsolationPolicy {
    /// The host is an ordinary child process of the runtime.
    ///
    /// Crash and hang containment, the resource ceilings in
    /// [`crate::limits::PluginHostLimits`], and the kernel-side boundary — the
    /// loader is not in this process and the session is authenticated. The plugin
    /// keeps the account's ambient authority.
    #[default]
    TrustedProcess,
    /// The host runs inside the platform's own resource confinement.
    ///
    /// On macOS that is App Sandbox, applied through the entitlements the host
    /// bundle is signed with: the host reaches its container and the files it was
    /// handed, and nothing else — no user files, no devices, no outbound network
    /// unless a later capability grants it. The confinement is a property of the
    /// signature, which is why a restricted host is a bundle rather than a bare
    /// executable.
    RestrictedMacOS,
}

/// Something a restricted host cannot be started without.
///
/// Named individually rather than collapsed into one sentence, because the three
/// have different repairs: one is a different machine, one is a packaging step,
/// and one is a capability of this runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestrictionRequirement {
    /// The platform the confinement is written for.
    MacOS,
    /// A host installed as a bundle, because the sandbox travels with the signature.
    BundledHost,
    /// Approved artifact bytes delivered over the session rather than as a path.
    StagedArtifactTransfer,
}

impl RestrictionRequirement {
    /// What a caller is told when this is missing.
    pub const fn message(self) -> &'static str {
        match self {
            Self::MacOS => "the platform is not macOS, where this confinement is defined",
            Self::BundledHost => {
                "no bundled host is installed beside this runtime, and the sandbox is applied \
                 through the bundle's signature"
            }
            Self::StagedArtifactTransfer => {
                "this build cannot complete an approved artifact transfer and native load \
                 inside the confined host"
            }
        }
    }
}

impl NativeIsolationPolicy {
    /// The spelling a deployment configures this policy by.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustedProcess => "trusted-process",
            Self::RestrictedMacOS => "restricted-macos",
        }
    }

    /// Whether a host started under this policy is confined by the platform.
    pub const fn confines_resources(self) -> bool {
        matches!(self, Self::RestrictedMacOS)
    }

    /// What this policy needs that the deployment does not have.
    ///
    /// `bundle` is the bundled host found beside the runtime, if one is there.
    /// The empty answer means the policy can be honored.
    pub fn unmet_requirements(self, bundle: Option<&Path>) -> Vec<RestrictionRequirement> {
        if !self.confines_resources() {
            return Vec::new();
        }
        let mut unmet = Vec::new();
        if !cfg!(target_os = "macos") {
            unmet.push(RestrictionRequirement::MacOS);
        }
        if bundle.is_none() {
            unmet.push(RestrictionRequirement::BundledHost);
        }
        if !RESTRICTED_ARTIFACT_LOAD_QUALIFIED {
            unmet.push(RestrictionRequirement::StagedArtifactTransfer);
        }
        unmet
    }

    /// The executable to start under this policy: the host it names, or why not.
    ///
    /// The two policies start different artifacts. A trusted host is whichever
    /// executable the deployment named or installed — the rule in
    /// [`crate::host_location`] is unchanged, and an override stays authoritative
    /// even when it names nothing that exists. A restricted host has to be a
    /// bundled one, because the confinement is a property of the bundle's
    /// signature: a path the caller resolved is used when it is already that
    /// shape, the bundle installed beside the runtime is used when it is not, and
    /// a deployment that offers neither is refused rather than started — running
    /// a bare executable here would be a host without the confinement the policy
    /// states.
    pub fn host_executable(
        self,
        resolved: &Path,
        beside: &Path,
    ) -> Result<PathBuf, PluginProtocolError> {
        if !self.confines_resources() {
            return Ok(resolved.to_path_buf());
        }
        if !cfg!(target_os = "macos") {
            return Err(refused(format!(
                "the '{}' policy cannot be honored here: {}",
                self.as_str(),
                RestrictionRequirement::MacOS.message()
            )));
        }
        // A path the caller resolved itself is used when it is already the
        // confined spelling — a package that ships the bundle knows where its own
        // `Contents/MacOS` is. Anything else means the policy has to find the
        // bundle it requires, and a deployment that supplied neither gets a
        // refusal that names what was expected rather than a host without the
        // confinement the policy states.
        let bundle = host_location::bundled_beside(beside);
        let executable = if host_location::is_bundled_executable(resolved) {
            Some(resolved.to_path_buf())
        } else {
            bundle
        };
        let Some(executable) = executable else {
            let looked = host_location::bundle_search_locations(beside)
                .into_iter()
                .map(|location| format!("'{}'", location.display()))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(refused(format!(
                "the '{}' policy needs a host inside a bundle: '{}' is not in one, and no \
                 '{}' is installed beside this runtime (looked for {looked})",
                self.as_str(),
                resolved.display(),
                host_location::BUNDLE_NAME
            )));
        };
        // The packaging requirement is answered by what was chosen rather than by
        // what was found: a caller that resolved the bundle's own executable
        // supplied one, whether or not a second copy is installed beside it.
        let unmet = self.unmet_requirements(Some(executable.as_path()));
        if !unmet.is_empty() {
            let reasons = unmet
                .iter()
                .map(|requirement| requirement.message())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(refused(format!(
                "the '{}' policy cannot be honored here: {reasons}",
                self.as_str()
            )));
        }
        Ok(executable)
    }
}

/// A configuration this runtime cannot honor, in the code the boundary already uses.
fn refused(message: String) -> PluginProtocolError {
    PluginProtocolError::new(PluginFailureCode::Unavailable, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "nemo-isolation-policy-{name}-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&directory).expect("a directory for the policy rule");
        directory
    }

    /// Lay a bundled host out where the resolver looks for one.
    fn install_bundle(beside: &Path) -> PathBuf {
        let inner = beside
            .join(host_location::BUNDLE_NAME)
            .join("Contents")
            .join("MacOS")
            .join("nemo-plugin-host");
        std::fs::create_dir_all(inner.parent().expect("the bundle's MacOS directory"))
            .expect("a bundle directory");
        std::fs::write(&inner, b"a host inside a bundle").expect("a bundled host");
        inner
    }

    #[test]
    fn a_trusted_policy_is_the_rule_that_was_always_there() {
        // The default policy changes nothing: the deployment's override wins, and
        // nothing about bundles is consulted.
        let beside = temporary_directory("trusted");
        let configured = PathBuf::from("/nonexistent/by/override/nemo-plugin-host");
        let resolved = NativeIsolationPolicy::TrustedProcess.host_executable(&configured, &beside);

        std::fs::remove_dir_all(&beside).ok();
        assert_eq!(resolved.expect("a trusted host"), configured);
        assert!(
            NativeIsolationPolicy::default() == NativeIsolationPolicy::TrustedProcess,
            "the policy a runtime gets when it does not choose is the one that was implicit"
        );
    }

    #[test]
    fn a_restricted_policy_starts_only_when_every_boundary_is_deliverable() {
        let beside = temporary_directory("bundled");
        let inner = install_bundle(&beside);
        let bare = beside.join("nemo-plugin-host");
        std::fs::write(&bare, b"a bare host").expect("a bare host beside the bundle");

        let requirements = NativeIsolationPolicy::RestrictedMacOS
            .unmet_requirements(Some(&beside.join(host_location::BUNDLE_NAME)));
        let resolved = NativeIsolationPolicy::RestrictedMacOS.host_executable(&bare, &beside);

        std::fs::remove_dir_all(&beside).ok();
        assert_eq!(
            host_location::bundled_beside(&beside),
            None,
            "the bundle was removed with its directory"
        );
        assert!(
            !requirements.contains(&RestrictionRequirement::BundledHost),
            "an installed bundle answers the packaging requirement"
        );
        match resolved {
            Err(error) if !cfg!(target_os = "macos") => assert!(
                error
                    .failure
                    .message
                    .contains(RestrictionRequirement::MacOS.message()),
                "a non-macOS host names the platform restriction: {}",
                error.failure.message
            ),
            Err(error) if cfg!(target_os = "macos") => assert!(
                error
                    .failure
                    .message
                    .contains(RestrictionRequirement::StagedArtifactTransfer.message()),
                "the complete restricted artifact load is not qualified: {}",
                error.failure.message
            ),
            Err(error) => panic!("unexpected restricted-host refusal: {error}"),
            Ok(path) => {
                let installed = inner.clone();
                assert_eq!(
                    path, installed,
                    "a restricted host is the bundled executable"
                );
            }
        }
    }

    #[test]
    fn a_restricted_host_outside_a_bundle_is_refused() {
        // Honoring this would run an unconfined host under a policy that says the
        // opposite, which is the failure mode the policy exists to remove.
        let beside = temporary_directory("unbundled");
        let named = beside.join("nemo-plugin-host");
        std::fs::write(&named, b"a host this deployment pointed at").expect("a named host");

        let resolved = NativeIsolationPolicy::RestrictedMacOS.host_executable(&named, &beside);

        std::fs::remove_dir_all(&beside).ok();
        let error = resolved.expect_err("a host outside a bundle is not a confined host");
        assert!(
            error.failure.message.contains(host_location::BUNDLE_NAME),
            "the refusal names the bundle that was expected: {}",
            error.failure.message
        );
    }

    #[test]
    fn the_bundle_layout_is_structurally_recognised() {
        // The check is structural rather than a search for one exact path, because
        // a deployment may install an application bundle anywhere; what it may not
        // do is call a bare executable a confined one.
        assert!(host_location::is_bundled_executable(Path::new(
            "/Applications/nemo-plugin-host.app/Contents/MacOS/nemo-plugin-host"
        )));
        assert!(!host_location::is_bundled_executable(Path::new(
            "/usr/local/bin/nemo-plugin-host"
        )));
        assert!(!host_location::is_bundled_executable(Path::new(
            "/Applications/nemo-plugin-host.app/Contents/Resources/nemo-plugin-host"
        )));
    }
}
