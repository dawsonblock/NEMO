// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What an artifact *is*, before anything loads it.
//
//! Identity, hashing and manifest-relative resolution: the questions the kernel
//! asks about a plugin artifact without owning a way to run one. `plugin_artifact_identity`
//! is asked by the side that supervises a host process — before it starts one and
//! again while it runs — so it cannot live with the loader, and it needs nothing
//! the loader has.
//!
//! This module is deliberately the inert half of what used to be one file. The
//! loader next to it is the half that knows about `dlopen`, symbol tables and the
//! native ABI, and the two are being separated so that the loader can leave the
//! kernel's dependency graph without taking the kernel's own questions with it.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::manifest::{DynamicPluginManifest, DynamicPluginManifestLoad};
use super::DYNAMIC_PLUGIN_MANIFEST_FILENAME;
use crate::plugin::PluginError;

/// The identity of one plugin artifact: its manifest and the library it names.
///
/// Both digests in one answer, from one read, because the pair is what a caller
/// compares: a manifest from one state beside a library from another describes
/// something that never existed.
///
/// # Errors
/// Returns what could not be read or parsed, naming the reference that failed.
pub fn plugin_artifact_identity(manifest_ref: &str) -> crate::plugin::Result<(String, String)> {
    // One read, one hash, one parse. The manifest that is hashed has to be the
    // manifest the library is resolved from: reading the path a second time
    // could return different bytes, and the pair returned here would then
    // describe a state no artifact was ever in — a digest from one manifest
    // beside a library another one named.
    let manifest_path = {
        let path = PathBuf::from(manifest_ref);
        if path.is_dir() {
            path.join(DYNAMIC_PLUGIN_MANIFEST_FILENAME)
        } else {
            path
        }
    };
    let manifest_bytes =
        std::fs::read(&manifest_path).map_err(|error| missing_artifact(manifest_ref, &error))?;
    let manifest_sha256 = sha256_hex(&manifest_bytes);

    let manifest = DynamicPluginManifest::parse_toml(
        std::str::from_utf8(&manifest_bytes).map_err(|error| {
            PluginError::InvalidConfig(format!(
                "'{}' is not UTF-8: {error}",
                manifest_path.display()
            ))
        })?,
    )?;
    let DynamicPluginManifestLoad::RustDynamic(load) = &manifest.load else {
        return Err(PluginError::InvalidConfig(format!(
            "dynamic plugin manifest {manifest_ref} is not a rust_dynamic load contract"
        )));
    };
    let library_path = resolve_manifest_relative_path(
        &manifest_path,
        load.library.as_deref().ok_or_else(|| {
            PluginError::InvalidConfig(format!("{manifest_ref} does not declare load.library"))
        })?,
    );
    // Hashed through an open handle rather than from the path, so the digest
    // describes the bytes of one file instance rather than whatever the name
    // points at when the read happens.
    let mut library = std::fs::File::open(&library_path)
        .map_err(|error| missing_artifact(&library_path.display().to_string(), &error))?;
    let library_sha256 = sha256_of_reader(&mut library)?;

    Ok((manifest_sha256, library_sha256))
}

/// The error one failed read becomes.
///
/// A missing artifact says so plainly, because that is the common case and the
/// one a caller has to act on. Anything else keeps the operating system's
/// detail, which is what separates a permissions problem from a bad path.
pub(crate) fn missing_artifact(reference: &str, error: &std::io::Error) -> PluginError {
    if error.kind() == std::io::ErrorKind::NotFound {
        PluginError::NotFound(format!("{reference} does not exist"))
    } else {
        PluginError::NotFound(format!("cannot read {reference}: {error}"))
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Hash the bytes of an already-open file.
///
/// Reading a handle rather than a path is what ties the digest to a specific
/// file instance: a path can be repointed between the hash and the open, and a
/// handle cannot.
pub(crate) fn sha256_of_reader(reader: &mut std::fs::File) -> crate::plugin::Result<String> {
    use std::io::Read;

    let mut reader = std::io::BufReader::new(reader);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            PluginError::Internal(format!("failed to read a plugin artifact: {error}"))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_digest(hasher.finalize()))
}

/// Hash a file by path.
pub(crate) fn sha256_of_path(path: &Path) -> crate::plugin::Result<String> {
    let bytes = std::fs::read(path).map_err(|error| {
        PluginError::Internal(format!("failed to read '{}': {error}", path.display()))
    })?;
    Ok(sha256_hex(&bytes))
}

pub(crate) fn resolve_manifest_relative_path(manifest_path: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        manifest_path
            .parent()
            .map(|parent| parent.join(&path))
            .unwrap_or(path)
    }
}

pub(crate) fn verify_sha256(path: &Path, expected: &str) -> crate::plugin::Result<()> {
    let expected = expected
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(expected.trim());
    let bytes = std::fs::read(path).map_err(|err| {
        PluginError::Internal(format!("failed to read '{}': {err}", path.display()))
    })?;
    let actual = hex_digest(Sha256::digest(bytes));
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(PluginError::InvalidConfig(format!(
            "native plugin library '{}' sha256 mismatch",
            path.display()
        )))
    }
}

pub(crate) fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
