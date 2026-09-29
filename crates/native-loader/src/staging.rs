// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Staging an artifact the kernel sent, and the rules for whether it may load.
//!
//! A confined host cannot read the path the kernel approved: App Sandbox gives it
//! its own container and nothing else, so the artifact arrives as bytes over the
//! authenticated session and the host writes them where it is allowed to write.
//! That moves the artifact's integrity story onto this side of the boundary, and
//! this module is where it is kept:
//!
//! ```text
//! NONE --begin--> RECEIVING --chunks--> RECEIVING --finalize--> VERIFYING --rename--> APPROVED
//!                                                                    |
//!                              anything else anywhere ---------------+--> nothing
//! ```
//!
//! Four properties carry it, and each one is cheap to lose:
//!
//! * **The limit exists before the bytes do.** A length is declared in the begin
//!   message and refused if it exceeds [`MAX_PLUGIN_ARTIFACT_BYTES`], and every
//!   chunk is refused if it would take the total past what was declared. Disk
//!   exhaustion is not a limiter; it is what happens when there is not one.
//! * **Offsets are checked, not assumed.** Ordered delivery is a property of one
//!   transport at one moment, so a chunk says where it belongs and a chunk that
//!   does not land exactly where the last one ended is refused — which is what
//!   makes a duplicate, a skip and a replay the same refusal.
//! * **The digest is measured twice, on two paths.** The stream is hashed as it is
//!   written, the closed file is hashed again by reading it, and both have to equal
//!   what the kernel approved. A bug in the writer that this module's own logic
//!   cannot see shows up as the two disagreeing.
//! * **Only one path is loadable.** Bytes land in `incoming/` and leave it only by
//!   an atomic rename into `approved/`, after verification. Nothing ever returns a
//!   path under `incoming/`, so there is no window in which a partially written
//!   file has a name a loader could be given.
//!
//! Per-session rather than persistent, deliberately: the staging area belongs to
//! the session that received it, an artifact staged by one session is not visible
//! to another, and the directory goes away with the session. This is not a cache
//! and does not survive a restart, which is the honest description of what a
//! plugin host needs — see the durability note on [`StagedArtifact::finalize`].

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use nemo_relay::plugin::dynamic::{
    DYNAMIC_PLUGIN_MANIFEST_FILENAME, DynamicPluginManifest, DynamicPluginManifestLoad,
};

/// Largest artifact this host will accept.
///
/// Stated before the first byte arrives and enforced on every chunk, because the
/// alternative limiter is the disk filling up. A plugin library larger than this is
/// a deployment that has to say so.
pub const MAX_PLUGIN_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

/// Largest manifest this host will accept.
///
/// Manifests are a few hundred bytes of TOML. The ceiling exists so a begin
/// message cannot carry an arbitrarily large payload under a name that means
/// "metadata".
pub const MAX_PLUGIN_MANIFEST_BYTES: usize = 64 * 1024;

/// Why an artifact is not stageable or not staged.
///
/// Every variant means the same thing operationally — the artifact is unusable,
/// its temporary file is gone and nothing was activated — and they are named
/// separately because the repairs differ and a log that says "staging failed" is
/// a log nobody can act on.
#[derive(Debug)]
pub enum StagingError {
    /// The declared length exceeds [`MAX_PLUGIN_ARTIFACT_BYTES`].
    LengthRefused { declared: u64, limit: u64 },
    /// The manifest exceeds [`MAX_PLUGIN_MANIFEST_BYTES`], or does not hash to what
    /// the kernel approved.
    ManifestRefused { reason: String },
    /// The manifest does not describe a loadable native plugin.
    ManifestInvalid { reason: String },
    /// A chunk arrived before the begin message, after the finalize, or for a
    /// different transfer than the one in flight.
    StateRefused { reason: String },
    /// A chunk does not begin where the last one ended.
    OffsetRefused { expected: u64, received: u64 },
    /// The bytes received so far would exceed the declared length.
    OverflowRefused { declared: u64, would_receive: u64 },
    /// Verification finished and the bytes are not what was approved.
    DigestRefused { expected: String, measured: String },
    /// The file could not be written, read back, or moved into place.
    Io { path: PathBuf, reason: String },
}

impl std::fmt::Display for StagingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LengthRefused { declared, limit } => write!(
                formatter,
                "the artifact declares {declared} bytes, and this host accepts at most {limit}"
            ),
            Self::ManifestRefused { reason } => {
                write!(formatter, "the manifest was refused: {reason}")
            }
            Self::ManifestInvalid { reason } => {
                write!(formatter, "the manifest is not loadable: {reason}")
            }
            Self::StateRefused { reason } => {
                write!(formatter, "the transfer is out of order: {reason}")
            }
            Self::OffsetRefused { expected, received } => write!(
                formatter,
                "a chunk arrived at offset {received}, and this transfer is at {expected}"
            ),
            Self::OverflowRefused {
                declared,
                would_receive,
            } => write!(
                formatter,
                "a chunk would take the transfer to {would_receive} bytes, past the declared {declared}"
            ),
            Self::DigestRefused { expected, measured } => write!(
                formatter,
                "the staged artifact hashes to {measured}, and {expected} was approved"
            ),
            Self::Io { path, reason } => {
                write!(formatter, "staging '{}' failed: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for StagingError {}

/// Where this host stages what it receives.
///
/// Under App Sandbox `HOME` is the container's own data directory — the sandbox
/// sets it even for a process started with an empty environment — so this resolves
/// inside the container without the parent knowing where that is. Outside a
/// sandbox it is the ordinary home, which is what makes the whole path testable
/// without a signed bundle.
pub fn staging_root() -> PathBuf {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("Library")
        .join("Application Support")
        .join("NeMo Relay")
        .join("staging")
}

/// What the kernel says is arriving.
///
/// The identity is the approval, not a hint: the manifest bytes have to hash to
/// it and the streamed library has to hash to it, or nothing is staged.
#[derive(Debug, Clone)]
pub struct ArtifactTransfer {
    /// Kernel-minted name for this transfer.
    pub artifact_id: String,
    /// The plugin the artifact will be loaded as.
    pub plugin_id: String,
    /// The approved manifest bytes.
    pub manifest: Vec<u8>,
    /// SHA-256 of `manifest`.
    pub manifest_sha256: String,
    /// SHA-256 of the library that is about to be streamed.
    pub library_sha256: String,
    /// Exact length of that library, in bytes.
    pub library_length: u64,
}

/// An artifact the kernel approved, staged and verified by this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedArtifact {
    /// The directory holding the manifest and the library, laid out so the
    /// loader's manifest-relative resolution finds the library.
    pub directory: PathBuf,
    /// The verified library.
    pub library: PathBuf,
    /// The digest the bytes were verified against.
    pub library_sha256: String,
}

/// One artifact being received, and what happens to it if it never completes.
#[derive(Debug)]
pub struct StagedArtifact {
    artifact_id: String,
    incoming_path: PathBuf,
    approved_directory: PathBuf,
    library_relative: String,
    manifest: Vec<u8>,
    file: Option<File>,
    hasher: Sha256,
    received: u64,
    declared_length: u64,
    expected_sha256: String,
    /// Set by [`StagedArtifact::finalize`] once the rename has happened, so the
    /// drop guard below stops treating the file as its responsibility.
    staged: bool,
}

/// The directory name one session stages under.
///
/// A hash rather than the identifier itself: the identifier crosses the boundary,
/// and a name that crosses the boundary is a name that can contain `..`, a
/// separator, or a symlink's worth of meaning. This cannot.
fn session_directory(root: &Path, session_id: &str) -> PathBuf {
    root.join(hash_name(session_id))
}

impl StagedArtifact {
    /// Start receiving `transfer` under `root`, for `session_id`.
    ///
    /// Everything that can refuse the transfer happens here, before a byte of the
    /// library arrives: the declared length against the ceiling, the manifest
    /// against the digest that was approved, and the manifest against what a
    /// native plugin has to declare.
    pub fn begin(
        root: &Path,
        session_id: &str,
        transfer: &ArtifactTransfer,
    ) -> Result<Self, StagingError> {
        if transfer.library_length > MAX_PLUGIN_ARTIFACT_BYTES {
            return Err(StagingError::LengthRefused {
                declared: transfer.library_length,
                limit: MAX_PLUGIN_ARTIFACT_BYTES,
            });
        }
        if transfer.manifest.len() > MAX_PLUGIN_MANIFEST_BYTES {
            return Err(StagingError::ManifestRefused {
                reason: format!(
                    "it is {} bytes, and a manifest is at most {}",
                    transfer.manifest.len(),
                    MAX_PLUGIN_MANIFEST_BYTES
                ),
            });
        }
        let measured = hash_bytes(&transfer.manifest);
        if measured != transfer.manifest_sha256 {
            return Err(StagingError::ManifestRefused {
                reason: StagingError::DigestRefused {
                    expected: transfer.manifest_sha256.clone(),
                    measured,
                }
                .to_string(),
            });
        }
        let text = std::str::from_utf8(&transfer.manifest).map_err(|error| {
            StagingError::ManifestInvalid {
                reason: format!("it is not UTF-8: {error}"),
            }
        })?;
        let manifest = DynamicPluginManifest::parse_toml(text).map_err(|error| {
            StagingError::ManifestInvalid {
                reason: error.to_string(),
            }
        })?;
        if manifest.plugin.id.trim() != transfer.plugin_id {
            return Err(StagingError::ManifestInvalid {
                reason: format!(
                    "it declares plugin id '{}', and '{}' was approved",
                    manifest.plugin.id, transfer.plugin_id
                ),
            });
        }
        let DynamicPluginManifestLoad::RustDynamic(load) = &manifest.load else {
            return Err(StagingError::ManifestInvalid {
                reason: "it does not declare a rust_dynamic load contract".to_string(),
            });
        };
        let library_relative = load
            .library
            .as_deref()
            .ok_or_else(|| StagingError::ManifestInvalid {
                reason: "it does not declare load.library".to_string(),
            })?
            .to_string();

        let canonical_root = canonical_staging_root(root)?;
        let session_directory = session_directory(&canonical_root, session_id);
        let incoming_directory = session_directory.join("incoming");
        let approved_root = session_directory.join("approved");
        create_directory_tree(&canonical_root)?;
        for directory in [&session_directory, &incoming_directory, &approved_root] {
            create_directory(directory)?;
        }
        // The kernel mints artifact IDs before transfer. Deriving the directory
        // from that ID lets the unconfined supervisor address this one staged
        // file for the macOS quarantine handoff without accepting a path from
        // the confined host. Repeated or concurrent transfer IDs cannot replace
        // an earlier approved path because creation remains exclusive.
        let approved_directory =
            approved_root.join(format!("artifact-{}", hash_name(&transfer.artifact_id)));
        // A fresh name this host chose, created exclusively: the plugin never
        // names the file it is written to, the file cannot be a symlink someone
        // placed in advance, and a name already taken is a name this transfer
        // does not use.
        let incoming_path = incoming_directory.join(format!(
            "artifact-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&incoming_path)
            .map_err(|error| StagingError::Io {
                path: incoming_path.clone(),
                reason: error.to_string(),
            })?;
        if let Err(error) = create_new_directory(&approved_directory) {
            drop(file);
            let _ = std::fs::remove_file(&incoming_path);
            return Err(error);
        }

        Ok(Self {
            artifact_id: transfer.artifact_id.clone(),
            incoming_path,
            approved_directory,
            library_relative,
            manifest: transfer.manifest.clone(),
            file: Some(file),
            hasher: Sha256::new(),
            received: 0,
            declared_length: transfer.library_length,
            expected_sha256: transfer.library_sha256.clone(),
            staged: false,
        })
    }

    /// Append one chunk, which has to begin where the last one ended.
    pub fn append(
        &mut self,
        artifact_id: &str,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), StagingError> {
        if artifact_id != self.artifact_id {
            return Err(StagingError::StateRefused {
                reason: format!(
                    "a chunk names artifact '{artifact_id}', and this transfer is '{}'",
                    self.artifact_id
                ),
            });
        }
        if offset != self.received {
            return Err(StagingError::OffsetRefused {
                expected: self.received,
                received: offset,
            });
        }
        let would_receive = self.received.saturating_add(bytes.len() as u64);
        if would_receive > self.declared_length {
            return Err(StagingError::OverflowRefused {
                declared: self.declared_length,
                would_receive,
            });
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| StagingError::StateRefused {
                reason: "the transfer is no longer receiving".to_string(),
            })?;
        file.write_all(bytes).map_err(|error| StagingError::Io {
            path: self.incoming_path.clone(),
            reason: error.to_string(),
        })?;
        self.hasher.update(bytes);
        self.received = would_receive;
        Ok(())
    }

    /// Finish the transfer: verify what was written, and move it into place.
    ///
    /// Durability is deliberate rather than accidental. The file is flushed and
    /// synced, closed, read back and hashed again, renamed into `approved/`, and
    /// the containing directory is synced — so a crash cannot leave a name in
    /// `approved/` that points at a partial file. What is *not* promised is that
    /// the artifact outlives the session: the staging area belongs to one session
    /// and is removed with it, which is why this is not a cache and why nothing
    /// here tries to be content-addressed.
    pub fn finalize(mut self, artifact_id: &str) -> Result<ApprovedArtifact, StagingError> {
        if artifact_id != self.artifact_id {
            return Err(StagingError::StateRefused {
                reason: format!(
                    "a finalize names artifact '{artifact_id}', and this transfer is '{}'",
                    self.artifact_id
                ),
            });
        }
        if self.received != self.declared_length {
            return Err(StagingError::LengthRefused {
                declared: self.declared_length,
                limit: self.received,
            });
        }
        let file = self.file.take().ok_or_else(|| StagingError::StateRefused {
            reason: "the transfer is no longer receiving".to_string(),
        })?;
        file.sync_all().map_err(|error| StagingError::Io {
            path: self.incoming_path.clone(),
            reason: error.to_string(),
        })?;
        drop(file);

        // The stream digest and the file's own digest, compared to each other and
        // to what was approved. Two paths rather than one, because the writer and
        // the verifier disagreeing is the bug this catches.
        let stream_digest = hex(self.hasher.clone().finalize());
        let file_digest = hash_path(&self.incoming_path).map_err(|error| StagingError::Io {
            path: self.incoming_path.clone(),
            reason: error.to_string(),
        })?;
        if stream_digest != self.expected_sha256 {
            return Err(StagingError::DigestRefused {
                expected: self.expected_sha256.clone(),
                measured: stream_digest,
            });
        }
        if file_digest != self.expected_sha256 {
            return Err(StagingError::DigestRefused {
                expected: self.expected_sha256.clone(),
                measured: file_digest,
            });
        }

        // The layout the loader already resolves: the manifest names the library
        // relative to itself, so both go into one directory under the names the
        // manifest expects.
        let manifest_path = self
            .approved_directory
            .join(DYNAMIC_PLUGIN_MANIFEST_FILENAME);
        let library_path = resolved_below(&self.approved_directory, &self.library_relative)?;
        if let Some(parent) = library_path.parent() {
            create_directory_chain(&self.approved_directory, parent)?;
        }
        let mut manifest_options = OpenOptions::new();
        manifest_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            manifest_options.mode(0o600);
        }
        let mut manifest_file =
            manifest_options
                .open(&manifest_path)
                .map_err(|error| StagingError::Io {
                    path: manifest_path.clone(),
                    reason: error.to_string(),
                })?;
        manifest_file
            .write_all(&self.manifest)
            .and_then(|()| manifest_file.sync_all())
            .map_err(|error| StagingError::Io {
                path: manifest_path.clone(),
                reason: error.to_string(),
            })?;
        drop(manifest_file);
        std::fs::rename(&self.incoming_path, &library_path).map_err(|error| StagingError::Io {
            path: library_path.clone(),
            reason: error.to_string(),
        })?;
        sync_directory(&self.approved_directory)?;
        if let Some(parent) = self.approved_directory.parent() {
            sync_directory(parent)?;
        }
        self.staged = true;

        Ok(ApprovedArtifact {
            directory: self.approved_directory.clone(),
            library: library_path,
            library_sha256: self.expected_sha256.clone(),
        })
    }
}

impl Drop for StagedArtifact {
    fn drop(&mut self) {
        // Every abnormal path ends here: a disconnected stream, a deadline, a
        // refused chunk, a host shutting down. Nothing that has not been verified
        // and renamed is left for anything to find.
        if !self.staged {
            self.file.take();
            let _ = std::fs::remove_file(&self.incoming_path);
            let _ = std::fs::remove_dir_all(&self.approved_directory);
        }
    }
}

/// Resolve `reference` inside `directory`, refusing anything that leaves it.
///
/// The manifest is approved content, so this is not about distrust of the plugin:
/// it is that an approved manifest naming `../../..` would otherwise turn the
/// host's own staging area into an arbitrary write from a plugin's configuration.
fn resolved_below(directory: &Path, reference: &str) -> Result<PathBuf, StagingError> {
    let candidate = Path::new(reference);
    if candidate.is_absolute() {
        return Err(StagingError::ManifestInvalid {
            reason: format!("load.library '{reference}' is an absolute path"),
        });
    }
    let mut resolved = directory.to_path_buf();
    for component in candidate.components() {
        match component {
            std::path::Component::Normal(name) => resolved.push(name),
            std::path::Component::CurDir => {}
            _ => {
                return Err(StagingError::ManifestInvalid {
                    reason: format!("load.library '{reference}' leaves the artifact directory"),
                });
            }
        }
    }
    Ok(resolved)
}

/// Create one directory without accepting a pre-planted symlink or file.
fn create_directory(directory: &Path) -> Result<(), StagingError> {
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(StagingError::Io {
            path: directory.to_path_buf(),
            reason: "the staging directory is not a real directory".to_string(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_new_directory(directory)
        }
        Err(error) => Err(StagingError::Io {
            path: directory.to_path_buf(),
            reason: error.to_string(),
        }),
    }
}

/// Create a new private directory, refusing an existing path of any kind.
fn create_new_directory(directory: &Path) -> Result<(), StagingError> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory).map_err(|error| StagingError::Io {
        path: directory.to_path_buf(),
        reason: error.to_string(),
    })
}

/// Check or create every component from the filesystem root to the staging root.
fn create_directory_tree(root: &Path) -> Result<(), StagingError> {
    let mut current = PathBuf::new();
    for component in root.components() {
        match component {
            std::path::Component::RootDir => current.push(component.as_os_str()),
            std::path::Component::Normal(name) => {
                current.push(name);
                create_directory(&current)?;
            }
            std::path::Component::CurDir => {}
            _ => {
                return Err(StagingError::Io {
                    path: root.to_path_buf(),
                    reason: "the staging root is not an absolute, normal path".to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Resolve existing platform aliases such as macOS `/var` before applying the
/// no-symlink checks. Nonexistent suffixes are appended to the canonical parent.
fn canonical_staging_root(root: &Path) -> Result<PathBuf, StagingError> {
    let mut ancestor = root.to_path_buf();
    let mut suffix = Vec::new();
    while !ancestor.exists() {
        let Some(component) = ancestor.file_name().map(std::ffi::OsStr::to_os_string) else {
            return Err(StagingError::Io {
                path: root.to_path_buf(),
                reason: "the staging root has no existing parent".to_string(),
            });
        };
        suffix.push(component);
        if !ancestor.pop() {
            return Err(StagingError::Io {
                path: root.to_path_buf(),
                reason: "the staging root has no existing parent".to_string(),
            });
        }
    }
    let mut canonical = std::fs::canonicalize(&ancestor).map_err(|error| StagingError::Io {
        path: ancestor.clone(),
        reason: error.to_string(),
    })?;
    for component in suffix.iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

/// Create each manifest-selected subdirectory after checking every component.
fn create_directory_chain(root: &Path, target: &Path) -> Result<(), StagingError> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| StagingError::ManifestInvalid {
            reason: "the library parent leaves the artifact directory".to_string(),
        })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if let std::path::Component::Normal(name) = component {
            current.push(name);
            create_directory(&current)?;
        }
    }
    Ok(())
}

/// Flush a directory's own entry list, so the rename in it survives a crash.
fn sync_directory(directory: &Path) -> Result<(), StagingError> {
    let handle = File::open(directory).map_err(|error| StagingError::Io {
        path: directory.to_path_buf(),
        reason: error.to_string(),
    })?;
    handle.sync_all().map_err(|error| StagingError::Io {
        path: directory.to_path_buf(),
        reason: error.to_string(),
    })
}

/// Lowercase hex, which is how every other digest in this repository is written.
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// SHA-256 of some bytes, lowercase hex.
pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(hasher.finalize())
}

/// SHA-256 of a name, used where a name crosses the boundary.
///
/// The digest is truncated to sixteen bytes: this is a directory name, not an
/// integrity claim, and the identifiers it stands for are already unique.
fn hash_name(name: &str) -> String {
    hash_bytes(name.as_bytes())[..32].to_string()
}

/// Read one file and hash it, for the second measurement.
fn hash_path(path: &Path) -> Result<String, StagingError> {
    let mut file = File::open(path).map_err(|error| StagingError::Io {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| StagingError::Io {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(hasher.finalize()))
}

/// Remove a session's staging area.
///
/// Called when a session ends: the artifact belongs to the session that received
/// it, and leaving it behind is how a staging area becomes an undocumented cache.
pub fn discard_session(root: &Path, session_id: &str) {
    let _ = std::fs::remove_dir_all(session_directory(root, session_id));
}

#[path = "../tests/unit/staging_tests.rs"]
#[cfg(test)]
mod tests;
