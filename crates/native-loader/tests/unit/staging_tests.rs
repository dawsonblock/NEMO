// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for staging an artifact a confined host received.

use super::*;

/// A manifest that declares the library this suite stages.
fn manifest(plugin_id: &str, library: &str) -> String {
    format!(
        r#"
manifest_version = 1

[plugin]
id = "{plugin_id}"
kind = "rust_dynamic"
version = "0.1.0"

[compat]
relay = ">=0.9,<1.0"
native_api = "1"

[defaults]
enabled = false

[capabilities]
items = ["plugin_native"]

[load]
library = "{library}"
symbol = "nemo_relay_plugin_entry"
"#
    )
}

/// The approved shape of one transfer, with the digests computed from the bytes.
fn transfer(plugin_id: &str, library_name: &str, library: &[u8]) -> ArtifactTransfer {
    let manifest = manifest(plugin_id, library_name);
    ArtifactTransfer {
        artifact_id: "artifact-one".to_string(),
        plugin_id: plugin_id.to_string(),
        manifest_sha256: hash_bytes(manifest.as_bytes()),
        manifest: manifest.into_bytes(),
        library_sha256: hash_bytes(library),
        library_length: library.len() as u64,
    }
}

/// A directory this test owns, removed when it is dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "nemo-staging-{name}-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&directory).expect("a directory for the staging tests");
        Self(directory)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn receive(
    root: &Path,
    transfer: &ArtifactTransfer,
    library: &[u8],
) -> Result<ApprovedArtifact, StagingError> {
    let mut staged = StagedArtifact::begin(root, "session-one", transfer)?;
    for (index, chunk) in library.chunks(8).enumerate() {
        staged.append("artifact-one", (index * 8) as u64, chunk)?;
    }
    staged.finalize("artifact-one")
}

#[test]
fn a_verified_artifact_lands_in_approved_and_nowhere_else() {
    // The whole point of the layout: what a loader may be given is a path under
    // `approved/`, and the manifest sits beside the library under the name the
    // loader's own resolution expects.
    let scratch = Scratch::new("verified");
    let library = b"the approved library bytes";
    let transfer = transfer("fixture", "libfixture.dylib", library);

    let approved = receive(scratch.path(), &transfer, library).expect("an approved artifact");

    assert_eq!(
        approved.library_sha256,
        hash_path(&approved.library).expect("a digest")
    );
    assert_eq!(
        std::fs::read(&approved.library).expect("the staged bytes"),
        library
    );
    assert!(
        approved.library.starts_with(&approved.directory)
            && approved
                .directory
                .components()
                .any(|part| part.as_os_str() == "approved"),
        "the artifact is staged under approved/: {}",
        approved.library.display()
    );
    assert!(
        approved
            .directory
            .join(DYNAMIC_PLUGIN_MANIFEST_FILENAME)
            .is_file(),
        "the manifest the loader resolves against is staged beside the library"
    );
    // Nothing is left in incoming/: what is not approved does not exist.
    let incoming = approved
        .directory
        .parent()
        .and_then(Path::parent)
        .expect("the session directory")
        .join("incoming");
    let leftovers: Vec<_> = std::fs::read_dir(&incoming)
        .expect("the incoming directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    assert!(leftovers.is_empty(), "incoming/ holds {leftovers:?}");
}

#[test]
fn the_incoming_file_is_private_and_created_exclusively() {
    // Restrictive creation semantics, asserted rather than assumed: the file is
    // this host's, under a name this host chose, at a mode that denies other users
    // — and the plugin never sees either decision.
    let scratch = Scratch::new("mode");
    let library = b"bytes";
    let transfer = transfer("fixture", "libfixture.dylib", library);
    let staged =
        StagedArtifact::begin(scratch.path(), "session-one", &transfer).expect("a transfer");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&staged.incoming_path)
            .expect("the incoming file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the incoming file denies other users");
    }
    assert!(
        staged
            .incoming_path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("artifact-")),
        "the file's name is this host's, not the transfer's: {}",
        staged.incoming_path.display()
    );
}

#[test]
fn a_length_past_the_ceiling_is_refused_before_any_bytes() {
    let scratch = Scratch::new("length");
    let library = b"bytes";
    let mut transfer = transfer("fixture", "libfixture.dylib", library);
    transfer.library_length = MAX_PLUGIN_ARTIFACT_BYTES + 1;

    let refused = StagedArtifact::begin(scratch.path(), "session-one", &transfer)
        .expect_err("a length past the ceiling is refused");

    assert!(
        matches!(refused, StagingError::LengthRefused { .. }),
        "{refused}"
    );
    assert!(
        !scratch.path().join(hash_name("session-one")).exists(),
        "nothing was created for a transfer that was refused on its first message"
    );
}

#[test]
fn a_chunk_that_does_not_continue_the_transfer_is_refused() {
    // Duplicate, skipped and replayed chunks are one refusal, because a chunk only
    // has one legal place: exactly where the last one ended.
    let scratch = Scratch::new("offset");
    let library = b"0123456789";
    let transfer = transfer("fixture", "libfixture.dylib", library);
    let mut staged =
        StagedArtifact::begin(scratch.path(), "session-one", &transfer).expect("a transfer");
    staged
        .append("artifact-one", 0, &library[..4])
        .expect("the first chunk");

    let replayed = staged
        .append("artifact-one", 0, &library[..4])
        .expect_err("a replay");
    assert!(
        matches!(
            replayed,
            StagingError::OffsetRefused {
                expected: 4,
                received: 0
            }
        ),
        "{replayed}"
    );
    let skipped = staged
        .append("artifact-one", 6, &library[6..])
        .expect_err("a gap");
    assert!(
        matches!(skipped, StagingError::OffsetRefused { .. }),
        "{skipped}"
    );
    let relabelled = staged
        .append("artifact-two", 4, &library[4..])
        .expect_err("a chunk for another transfer");
    assert!(
        matches!(relabelled, StagingError::StateRefused { .. }),
        "{relabelled}"
    );
}

#[test]
fn a_chunk_past_the_declared_length_is_refused() {
    // The declared length is the limiter, not the disk: a host that relied on the
    // filesystem filling up would have no limit at all.
    let scratch = Scratch::new("overflow");
    let library = b"01234567";
    let transfer = transfer("fixture", "libfixture.dylib", library);
    let mut staged =
        StagedArtifact::begin(scratch.path(), "session-one", &transfer).expect("a transfer");
    staged
        .append("artifact-one", 0, &library[..6])
        .expect("a legal chunk");

    let refused = staged
        .append("artifact-one", 6, b"past the end")
        .expect_err("a chunk past the declared length");

    assert!(
        matches!(refused, StagingError::OverflowRefused { .. }),
        "{refused}"
    );
}

#[test]
fn bytes_that_do_not_hash_to_the_approval_are_refused_and_removed() {
    // This is the property the whole boundary rests on: the kernel approved a
    // digest, and what arrives is loaded only if it is that digest. A refused
    // artifact leaves nothing behind for a loader to find.
    let scratch = Scratch::new("digest");
    let approved_library = b"the bytes the kernel approved";
    let transfer = transfer("fixture", "libfixture.dylib", approved_library);
    let mut different_bytes = approved_library.to_vec();
    different_bytes[0] ^= 1;

    let refused = receive(scratch.path(), &transfer, &different_bytes)
        .expect_err("bytes that are not the approved ones");
    assert!(
        matches!(refused, StagingError::DigestRefused { .. }),
        "{refused}"
    );

    let session = scratch.path().join(hash_name("session-one"));
    let leftovers: Vec<_> = walk(&session);
    assert!(
        leftovers.is_empty(),
        "a refused transfer left {leftovers:?}"
    );
}

#[test]
fn a_manifest_that_is_not_the_approved_one_is_refused() {
    let scratch = Scratch::new("manifest");
    let library = b"bytes";
    let mut transfer = transfer("fixture", "libfixture.dylib", library);
    transfer.manifest = manifest("fixture", "other.dylib").into_bytes();

    let refused = StagedArtifact::begin(scratch.path(), "session-one", &transfer)
        .expect_err("a manifest that is not the approved bytes");

    assert!(
        matches!(refused, StagingError::ManifestRefused { .. }),
        "{refused}"
    );
}

#[test]
fn a_manifest_that_disagrees_with_the_plugin_id_is_refused() {
    let scratch = Scratch::new("manifest-id");
    let library = b"bytes";
    let mut transfer = transfer("fixture", "libfixture.dylib", library);
    let manifest = manifest("another-plugin", "libfixture.dylib");
    transfer.manifest_sha256 = hash_bytes(manifest.as_bytes());
    transfer.manifest = manifest.into_bytes();

    let refused = StagedArtifact::begin(scratch.path(), "session-one", &transfer)
        .expect_err("a manifest for another plugin");

    assert!(
        matches!(refused, StagingError::ManifestInvalid { .. }),
        "{refused}"
    );
}

#[test]
fn a_library_outside_the_artifact_directory_is_refused() {
    // An approved manifest naming `../..` would otherwise make the staging area an
    // arbitrary write driven by a plugin's own configuration.
    let scratch = Scratch::new("traversal");
    let library = b"bytes";
    let transfer = transfer("fixture", "../../escaped.dylib", library);

    let refused =
        receive(scratch.path(), &transfer, library).expect_err("a library outside the artifact");

    assert!(
        matches!(refused, StagingError::ManifestInvalid { .. }),
        "{refused}"
    );
    assert!(!scratch.path().join("escaped.dylib").exists());
}

#[test]
fn an_interrupted_transfer_leaves_nothing_to_load() {
    // Every abnormal path ends the same way. Dropping the transfer is what a
    // disconnected stream, an expired deadline and a shutting-down host all do.
    let scratch = Scratch::new("interrupted");
    let library = b"0123456789";
    let transfer = transfer("fixture", "libfixture.dylib", library);
    let mut staged =
        StagedArtifact::begin(scratch.path(), "session-one", &transfer).expect("a transfer");
    staged
        .append("artifact-one", 0, &library[..4])
        .expect("a partial chunk");
    drop(staged);

    let session = scratch.path().join(hash_name("session-one"));
    let leftovers: Vec<_> = walk(&session);
    assert!(
        leftovers.is_empty(),
        "an interrupted transfer left {leftovers:?}"
    );
}

#[test]
fn a_short_transfer_is_refused_even_when_it_hashes_nothing() {
    // `finalize` before the declared length has arrived is the same refusal as a
    // streaming peer that disconnected, and it is refused rather than padded.
    let scratch = Scratch::new("short");
    let library = b"0123456789";
    let transfer = transfer("fixture", "libfixture.dylib", library);
    let mut staged =
        StagedArtifact::begin(scratch.path(), "session-one", &transfer).expect("a transfer");
    staged
        .append("artifact-one", 0, &library[..4])
        .expect("a partial chunk");

    let refused = staged
        .finalize("artifact-one")
        .expect_err("a short transfer");

    assert!(
        matches!(refused, StagingError::LengthRefused { .. }),
        "{refused}"
    );
}

#[test]
fn two_sessions_stage_under_different_directories() {
    // Session authority: the staging area belongs to the session that received the
    // artifact, so a digest that matches is not by itself enough to reuse another
    // session's copy.
    let scratch = Scratch::new("sessions");
    let library = b"the approved library bytes";
    let transfer = transfer("fixture", "libfixture.dylib", library);

    let mut first = StagedArtifact::begin(scratch.path(), "session-one", &transfer).expect("one");
    first.append("artifact-one", 0, library).expect("the bytes");
    let first = first.finalize("artifact-one").expect("approved");
    let mut second = StagedArtifact::begin(scratch.path(), "session-two", &transfer).expect("two");
    second
        .append("artifact-one", 0, library)
        .expect("the bytes");
    let second = second.finalize("artifact-one").expect("approved");

    assert_ne!(first.directory, second.directory);
    discard_session(scratch.path(), "session-one");
    assert!(
        !first.directory.exists(),
        "one session's artifact goes away with it"
    );
    assert!(
        second.directory.exists(),
        "and the other session's does not"
    );
}

/// Every path under one directory tree, for the "nothing was left" assertions.
fn walk(directory: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return found;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found
}
