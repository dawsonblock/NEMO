// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kernel-side handoff for App Sandbox quarantine metadata.
//!
//! After authenticated transfer, the unconfined supervisor derives the staged
//! file from kernel-minted IDs, opens each path component without following
//! symlinks, rechecks the approved digest, and removes only quarantine from the
//! open file descriptor. This narrow filesystem mutation is in the kernel's TCB.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{self, Mode, OFlags};
use rustix::io::Errno;

const MAX_PLUGIN_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

/// Remove quarantine from the deterministic staged copy after verifying it.
pub(crate) fn clear_approved_quarantine(
    session_id: &str,
    artifact_id: &str,
    library_relative_path: &str,
    expected_sha256: &str,
) -> Result<(), String> {
    clear_approved_quarantine_under_root(
        &container_staging_root()?,
        session_id,
        artifact_id,
        library_relative_path,
        expected_sha256,
    )
}

fn clear_approved_quarantine_under_root(
    staging_root: &Path,
    session_id: &str,
    artifact_id: &str,
    library_relative_path: &str,
    expected_sha256: &str,
) -> Result<(), String> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("the approved library digest is not a SHA-256 hex digest".into());
    }
    let relative_library = safe_relative_path(library_relative_path)?;
    let staging_root = std::fs::canonicalize(staging_root)
        .map_err(|error| format!("cannot resolve the host container staging root: {error}"))?;
    let mut relative = PathBuf::from(hash_name(session_id));
    relative.push("approved");
    relative.push(format!("artifact-{}", hash_name(artifact_id)));
    relative.push(relative_library);
    let (parent, filename) = relative
        .parent()
        .zip(relative.file_name())
        .ok_or_else(|| "the approved library path has no file name".to_string())?;

    let root = open_absolute_directory(&staging_root)?;
    let parent = open_relative_directory(root, parent)?;
    let file = fs::openat(
        &parent,
        filename,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| format!("cannot open the approved staged library safely: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect the staged library: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_PLUGIN_ARTIFACT_BYTES {
        return Err("the staged library is not a bounded regular file".into());
    }

    let mut reader = file
        .try_clone()
        .map_err(|error| format!("cannot verify the staged library: {error}"))?;
    let measured = nemo_relay::plugin::dynamic::NativeHostRuntime::new()
        .hash_open_file(&mut reader)
        .map_err(|error| format!("cannot hash the staged library: {error}"))?;
    if !measured.eq_ignore_ascii_case(expected_sha256) {
        return Err(format!(
            "the staged library hashes to {measured}, not the approved digest"
        ));
    }

    match fs::fremovexattr(&file, "com.apple.quarantine") {
        Ok(()) | Err(Errno::NOATTR) => {}
        Err(error) => {
            return Err(format!(
                "macOS refused to remove quarantine from the approved staged library: {error}"
            ));
        }
    }
    file.sync_all()
        .map_err(|error| format!("cannot sync staged library metadata: {error}"))
}

fn container_staging_root() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "the kernel process has no HOME for the host container".to_string())?;
    Ok(home
        .join("Library")
        .join("Containers")
        .join(crate::host_location::BUNDLE_IDENTIFIER)
        .join("Data")
        .join("Library")
        .join("Application Support")
        .join("NeMo Relay")
        .join("staging"))
}

fn safe_relative_path(value: &str) -> Result<PathBuf, String> {
    let mut result = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::Normal(name) => result.push(name),
            Component::CurDir => {}
            _ => return Err("the approved library path leaves its artifact directory".into()),
        }
    }
    if result.as_os_str().is_empty() {
        return Err("the approved library path is empty".into());
    }
    Ok(result)
}

fn open_absolute_directory(path: &Path) -> Result<OwnedFd, String> {
    if !path.is_absolute() {
        return Err("the host container path is not absolute".into());
    }
    let mut directory = fs::open(
        "/",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open the filesystem root: {error}"))?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err("the host container path contains a non-normal component".into());
        };
        directory = open_directory_at(&directory, name)?;
    }
    Ok(directory)
}

fn open_relative_directory(mut directory: OwnedFd, path: &Path) -> Result<OwnedFd, String> {
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err("the staged library path contains a non-normal directory".into());
        };
        directory = open_directory_at(&directory, name)?;
    }
    Ok(directory)
}

fn open_directory_at(directory: &OwnedFd, name: &std::ffi::OsStr) -> Result<OwnedFd, String> {
    fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open a real directory in the host container: {error}"))
}

fn hash_name(value: &str) -> String {
    nemo_relay::plugin::dynamic::NativeHostRuntime::new().hash_bytes(value.as_bytes())[..32]
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::XattrFlags;

    const SESSION: &str = "macos-quarantine-test-session";
    const ARTIFACT: &str = "macos-quarantine-test-artifact";
    const RELATIVE_LIBRARY: &str = "nested/libfixture.dylib";
    const CONTENT: &[u8] = b"approved native plugin fixture";

    fn staged_fixture() -> (tempfile::TempDir, PathBuf, String) {
        let temporary = tempfile::tempdir().expect("temporary staging root");
        let path = temporary
            .path()
            .join(hash_name(SESSION))
            .join("approved")
            .join(format!("artifact-{}", hash_name(ARTIFACT)))
            .join(RELATIVE_LIBRARY);
        std::fs::create_dir_all(path.parent().expect("library parent"))
            .expect("staged artifact directories");
        std::fs::write(&path, CONTENT).expect("write staged artifact");
        let digest = nemo_relay::plugin::dynamic::NativeHostRuntime::new().hash_bytes(CONTENT);
        (temporary, path, digest)
    }

    fn add_quarantine(path: &Path) {
        let file = File::open(path).expect("open staged fixture");
        fs::fsetxattr(
            &file,
            "com.apple.quarantine",
            b"0081;00000000;NeMo Relay;",
            XattrFlags::empty(),
        )
        .expect("set quarantine fixture attribute");
    }

    fn has_quarantine(path: &Path) -> bool {
        let file = File::open(path).expect("open staged fixture");
        let mut attribute: Vec<u8> = Vec::new();
        match fs::fgetxattr(&file, "com.apple.quarantine", &mut attribute) {
            Ok(_) => true,
            Err(Errno::NOATTR) => false,
            Err(error) => panic!("unexpected quarantine lookup error: {error}"),
        }
    }

    #[test]
    fn clears_only_quarantine_after_rechecking_the_approved_digest() {
        let (temporary, path, digest) = staged_fixture();
        add_quarantine(&path);
        clear_approved_quarantine_under_root(
            temporary.path(),
            SESSION,
            ARTIFACT,
            RELATIVE_LIBRARY,
            &digest,
        )
        .expect("approved staged file should be cleared");
        assert!(!has_quarantine(&path));
        assert_eq!(std::fs::read(path).expect("read staged file"), CONTENT);
    }

    #[test]
    fn refuses_a_digest_mismatch_without_changing_quarantine() {
        let (temporary, path, _) = staged_fixture();
        add_quarantine(&path);
        let error = clear_approved_quarantine_under_root(
            temporary.path(),
            SESSION,
            ARTIFACT,
            RELATIVE_LIBRARY,
            &"0".repeat(64),
        )
        .expect_err("mismatched staged file must be refused");
        assert!(error.contains("approved digest"));
        assert!(has_quarantine(&path));
    }

    #[test]
    fn refuses_paths_that_leave_the_approved_artifact_directory() {
        let (temporary, _, digest) = staged_fixture();
        let error = clear_approved_quarantine_under_root(
            temporary.path(),
            SESSION,
            ARTIFACT,
            "../outside.dylib",
            &digest,
        )
        .expect_err("path traversal must be refused");
        assert!(error.contains("leaves its artifact directory"));
    }
}
