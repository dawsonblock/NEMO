// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The hosted-plugin seam, checked as the boundary it claims to be.
//!
//! `plugin/dynamic/hosted.rs` says what a hosted plugin's code may ask this
//! runtime to do, and the loader crate's `native.rs`/`host.rs` are the code that
//! does the asking. These tests hold the two together: the loader must not spell a
//! kernel item the seam replaced, every operation in the mapping must still be
//! called, and — the one that catches what nobody anticipated — the hosted side
//! must not name any other module-level kernel item that is not `pub` at all.
//!
//! They stayed in the kernel's crate on purpose when the loader moved out: the
//! seam and the operations are the kernel's, and a boundary is best checked from
//! the side that has to keep it.
//!
//! They live outside `src/` on purpose. A scan that has to write down declaration
//! keywords is a scan whose keyword list would otherwise be counted as part of the
//! kernel's textual `unsafe` budget, and inflating a security number to say
//! "the word appears in a test" is the kind of movement this repository's TCB
//! policy exists to prevent.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The kernel functions the hosted side used to name, and the operation that
/// replaced each one.
///
/// This table is the design rather than a summary of it: the loader speaks the
/// operation, the kernel keeps the item, and neither half of that is true if a
/// call site can still spell the item's name. The tests below fail on a name that
/// comes back and on an operation nobody calls, so the table cannot rot into a
/// description of a boundary that moved.
const REPLACED_CALLS: &[(&str, &str)] = &[
    ("register_plugin_tracked", "install_plugin"),
    ("deregister_plugin_registration_checked", "remove_plugin"),
    ("deregister_tracked_registrations_checked", "tear_down"),
    ("run_owned_plugin_mutation", "run_owned_mutation"),
    ("current_mark_forwarder", "capture_mark_window"),
    ("forwarded_mark", "forward_mark"),
    ("isolated_for_current_invocation", "isolate_invocation"),
    ("active_runtime_diagnostics_snapshot", "runtime_diagnostics"),
    (
        "uses_plugin_component_namespace",
        "qualifies_component_names",
    ),
    ("encode_plugin_component_field", "qualify_component_field"),
    ("plugin_artifact_identity", "artifact_identity"),
    ("sha256_hex", "hash_bytes"),
    ("sha256_of_reader", "hash_open_file"),
    ("sha256_of_path", "hash_path"),
    ("verify_sha256", "verify_path"),
    (
        "resolve_manifest_relative_path",
        "resolve_manifest_relative",
    ),
    (
        "validate_dynamic_plugin_relay_compatibility",
        "validate_relay_compatibility",
    ),
    (
        "validate_annotated_request_consumer_compatibility",
        "validate_request_consumer_compatibility",
    ),
];

/// The kernel types the hosted side used to name, and the vocabulary that
/// replaced each one.
const REPLACED_TYPES: &[(&str, &str)] = &[
    ("PluginDeregistrationOutcome", "RegistrationRemoval"),
    ("DynamicPluginTeardownOutcome", "RegistrationTeardown"),
];

/// Kernel items the hosted side may still name although they are not public.
///
/// Empty, and it is a decision rather than an accident: an entry here is a private
/// name the loader is allowed to spell, which is the thing the seam exists to
/// stop. The list stays so that a future entry has to be written down with a
/// reason instead of arriving as a compile fix.
const ALLOWED_INTERNALS: &[(&str, &str)] = &[];

/// The files that make up the hosted side, relative to this crate's root.
///
/// They are in another crate now — that is what the move was — so the scan reaches
/// across the workspace rather than into `src/`. A test that reads a sibling
/// crate's source is the price of checking a boundary from the side that owns it.
const HOSTED_SIDE_PATHS: &[&str] = &[
    "../native-loader/src/native.rs",
    "../native-loader/src/host.rs",
];

/// The file that carries the seam.
const SEAM_PATH: &str = "src/plugin/dynamic/hosted.rs";

fn crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read_relative(relative: &str) -> String {
    std::fs::read_to_string(crate_root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn hosted_side() -> Vec<(&'static str, String)> {
    HOSTED_SIDE_PATHS
        .iter()
        .map(|relative| (*relative, read_relative(relative)))
        .collect()
}

fn core_source_files(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("read a core source directory") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            core_source_files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// The name a module-level declaration introduces, when it is not `pub`.
///
/// Only column-zero declarations count. That is not a shortcut: an indented `fn`
/// is a method or a nested item, and the hosted side cannot reach one by naming it
/// from another module, so treating those as part of the inventory would fill it
/// with words like `begin` and `new` that mean nothing here.
///
/// The keyword list is the declaration forms this crate actually uses at module
/// level; a form nobody writes adds no coverage, and one that appears here later
/// without being listed is a gap this comment names rather than hides.
fn declared_name(line: &str) -> Option<&str> {
    let mut rest = line;
    let mut private = false;
    for prefix in ["pub(crate) ", "pub(super) ", "pub(in crate::plugin) "] {
        if let Some(after) = rest.strip_prefix(prefix) {
            rest = after;
            private = true;
            break;
        }
    }
    if !private && rest.starts_with("pub") {
        return None;
    }
    for keyword in [
        "async fn ",
        "unsafe extern \"C\" fn ",
        "unsafe fn ",
        "fn ",
        "struct ",
        "enum ",
        "trait ",
        "type ",
        "const ",
        "static ",
    ] {
        if let Some(after) = rest.strip_prefix(keyword) {
            let name: &str = after
                .split(|character: char| !(character.is_alphanumeric() || character == '_'))
                .next()
                .unwrap_or("");
            // `pub(crate) const fn new` reaches `fn` before it reaches `new`.
            if matches!(
                name,
                "fn" | "const" | "static" | "unsafe" | "async" | "extern"
            ) {
                continue;
            }
            return (!name.is_empty()).then_some(name);
        }
    }
    None
}

/// The hosted side's code, with whole-line comments dropped.
///
/// Prose is not evidence of reach: a doc comment that says a loader "resyncs the
/// resolver" would otherwise read as a call into one. Only whole-line comments
/// are removed, because a line that runs code is a line this check must read.
fn code_of(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_identifier_character(character: Option<char>) -> bool {
    character.is_some_and(|character| character.is_alphanumeric() || character == '_')
}

/// Whether the path ending at `before` starts at `crate`, `super` or `self`.
///
/// `NemoRelayNativeScopeType::Guardrail` and `crate::api::registry::Guardrail`
/// both end in a name preceded by `::`, and only the second one is reach; the
/// difference is which module the path starts in.
fn root_path_is_module(before: &str) -> bool {
    let path = before.trim_end_matches(':');
    let root = path.split("::").next().unwrap_or("");
    matches!(root, "crate" | "super" | "self")
}

/// Whether `text` names `name`, as a word or as a path rooted in this crate.
fn mentions(text: &str, name: &str) -> bool {
    let mut from = 0;
    while let Some(offset) = text[from..].find(name) {
        let start = from + offset;
        let end = start + name.len();
        let before = text[..start].trim_end();
        if is_identifier_character(text[end..].chars().next()) {
            from = end;
            continue;
        }
        let previous = before.chars().next_back();
        // A bare name is a module-level one. `.name(` is a method of whatever is
        // to the left, and `SomeType::name` is that type's associated item;
        // neither is a kernel function this check is about.
        if !is_identifier_character(previous) && !matches!(previous, Some('.') | Some(':')) {
            return true;
        }
        if before.ends_with("::") && root_path_is_module(before) {
            return true;
        }
        from = end;
    }
    false
}

#[test]
fn the_hosted_side_speaks_the_seam_rather_than_the_items_behind_it() {
    let mut problems = Vec::new();
    for (item, operation) in REPLACED_CALLS.iter().chain(REPLACED_TYPES) {
        for (label, text) in hosted_side() {
            if mentions(&code_of(&text), item) {
                problems.push(format!(
                    "{label} names the kernel item '{item}' instead of '{operation}'"
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "the hosted side reaches past its seam: {problems:#?}"
    );
}

#[test]
fn every_operation_replaces_something() {
    let side = hosted_side();
    for (item, operation) in REPLACED_CALLS {
        let used = side
            .iter()
            .any(|(_, text)| code_of(text).contains(&format!(".{operation}(")));
        assert!(
            used,
            "the seam maps '{item}' to '{operation}', and nothing calls it"
        );
    }
    let seam = read_relative(SEAM_PATH);
    for (item, vocabulary) in REPLACED_TYPES {
        assert!(
            seam.contains(&format!("pub enum {vocabulary} "))
                || seam.contains(&format!("pub struct {vocabulary} ")),
            "the seam maps '{item}' to '{vocabulary}', and the seam does not declare it"
        );
    }
}

#[test]
fn the_hosted_side_names_no_kernel_internal_that_is_not_mapped() {
    let side = hosted_side();
    let mut declared: BTreeMap<String, String> = BTreeMap::new();
    let mut files = Vec::new();
    core_source_files(&crate_root().join("src"), &mut files);
    for path in files {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if HOSTED_SIDE_PATHS
            .iter()
            .chain(std::iter::once(&SEAM_PATH))
            .any(|relative| relative.ends_with(name))
        {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read a core source file");
        for line in source.lines() {
            if line != line.trim_start() {
                continue;
            }
            if let Some(name) = declared_name(line) {
                declared
                    .entry(name.to_string())
                    .or_insert_with(|| path.display().to_string());
            }
        }
    }
    // What the hosted side declares itself is its own, not a kernel internal that
    // happens to share the name.
    let mut own: BTreeSet<String> = BTreeSet::new();
    for (_, text) in &side {
        for line in code_of(text).lines() {
            if line != line.trim_start() {
                continue;
            }
            if let Some(name) = declared_name(line) {
                own.insert(name.to_string());
            }
        }
    }
    let allowed: BTreeSet<&str> = ALLOWED_INTERNALS.iter().map(|(name, _)| *name).collect();
    let mut reached = BTreeSet::new();
    for (label, text) in &side {
        let code = code_of(text);
        for (name, file) in &declared {
            if allowed.contains(name.as_str()) || own.contains(name) || !mentions(&code, name) {
                continue;
            }
            reached.insert(format!("{label} names '{name}' from {file}"));
        }
    }
    assert!(
        reached.is_empty(),
        "the hosted side names kernel internals that no seam operation maps: {reached:#?}"
    );
}
