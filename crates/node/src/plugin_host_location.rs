// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Where this package's plugin host is, when nothing named one.
//!
//! The Node runtime cannot ask "where is the host beside the process that started
//! me", because the process that started the addon is `node`: the interpreter a
//! user happens to be running says nothing about which package loaded this module.
//! What the addon does know is where *it* was loaded from, and the platform
//! package that carries the addon carries the host in its own `bin/` — so the
//! module's own directory is the one place a guess is not a guess.
//!
//! This is the fallback rather than the contract. A package wrapper knows its own
//! installation better than a shared object can and passes the path explicitly;
//! this exists so a directly-required addon still finds its companion instead of
//! searching `PATH`, which is the one thing a security-critical companion must
//! never be resolved from.

use std::path::PathBuf;

/// The host shipped beside this addon, when the addon can tell where it is.
pub(crate) fn beside_this_module() -> Option<PathBuf> {
    let directory = module_directory()?;
    let candidate = directory.join("bin").join(host_executable_name());
    candidate.is_file().then_some(candidate)
}

fn host_executable_name() -> &'static str {
    if cfg!(windows) {
        "nemo-plugin-host.exe"
    } else {
        "nemo-plugin-host"
    }
}

#[cfg(unix)]
fn module_directory() -> Option<PathBuf> {
    /// A symbol that lives in this shared object, so the loader can be asked
    /// which file it came from.
    extern "C" fn anchor() {}

    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let found = unsafe { libc::dladdr(anchor as *const libc::c_void, &mut info) };
    if found == 0 || info.dli_fname.is_null() {
        return None;
    }
    let path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }
        .to_str()
        .ok()?;
    // The loader reports the file it mapped, which is what this module is; the
    // package root is the directory holding it.
    PathBuf::from(path)
        .parent()
        .map(std::path::Path::to_path_buf)
}

/// Windows has no isolated plugin runtime yet, so there is no host to find.
#[cfg(not(unix))]
fn module_directory() -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_module_directory_is_where_this_test_binary_was_loaded_from() {
        // Under `cargo test` the anchor is in the test executable, so the answer
        // is its directory: the mechanism works, and what it returns is a real
        // location rather than a guess.
        let directory = module_directory().expect("the loader can name this module");
        assert!(directory.is_dir(), "{}", directory.display());
    }
}
