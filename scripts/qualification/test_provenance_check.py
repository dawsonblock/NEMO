# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Mandatory provenance tests for the E3 exact-source-tree contract.

The candidate set must come from the filesystem. These tests add, delete,
retype, re-mode, re-target, and traverse entries after evidence is captured and
require every case to fail verification.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import capture_provenance  # noqa: E402
import gitignore  # noqa: E402
import provenance_check  # noqa: E402
import source_tree  # noqa: E402

EVIDENCE = pathlib.Path("qualification/source-manifest.json")


@pytest.fixture()
def tree(tmp_path: pathlib.Path) -> pathlib.Path:
    """Create a small source tree with a captured, verified manifest."""

    root = tmp_path / "tree"
    (root / "crates" / "core" / "src").mkdir(parents=True)
    (root / "scripts" / "qualification").mkdir(parents=True)
    (root / "crates" / "core" / "src" / "kernel.rs").write_text("pub fn boot() {}\n")
    (root / "scripts" / "release.sh").write_text("#!/bin/sh\necho release\n")
    (root / "scripts" / "release.sh").chmod(0o755)
    (root / "Cargo.toml").write_text("[workspace]\nmembers = []\n")
    (root / ".gitignore").write_text("target/\n*.tmp\n")
    capture_provenance.capture(root, root / "qualification", "full")
    assert provenance_check.verify(root, EVIDENCE)[0] == []
    return root


def expected_substring(findings: list[str], needle: str) -> bool:
    """Return whether any finding mentions ``needle``."""

    return any(needle in finding for finding in findings)


# -- Acceptance gate: the exact build-3 regression ---------------------------


def test_stale_manifest_cannot_verify_a_tree_with_new_effect_runtime_files(
    tree: pathlib.Path,
) -> None:
    """The E3.0 regression: a whole new crate must not verify clean."""

    (tree / "crates" / "effect-runtime" / "src").mkdir(parents=True)
    (tree / "crates" / "effect-runtime" / "Cargo.toml").write_text("[package]\nname = 'x'\n")
    (tree / "crates" / "effect-runtime" / "src" / "lib.rs").write_text("// runtime\n")

    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert findings
    assert expected_substring(findings, "2 tree entry(s) absent from the manifest")
    assert expected_substring(findings, "crates/effect-runtime/src/lib.rs")


def test_manifest_from_an_older_schema_is_rejected(tmp_path: pathlib.Path) -> None:
    """Evidence produced under the flat schema cannot describe today's tree."""

    root = tmp_path / "tree"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n")
    evidence = root / "qualification" / "source-manifest.json"
    evidence.parent.mkdir()
    evidence.write_text(json.dumps({"schema_version": 1, "files": {"hello.txt": "abc"}}))

    findings, _ = provenance_check.verify(root, EVIDENCE)
    assert expected_substring(findings, "schema_version is 1")


# -- Mandatory provenance cases ---------------------------------------------


def test_new_unmanifested_rust_file_fails(tree: pathlib.Path) -> None:
    (tree / "crates" / "core" / "src" / "runtime.rs").write_text("// new\n")
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "absent from the manifest")
    assert expected_substring(findings, "crates/core/src/runtime.rs")


def test_new_executable_shell_script_fails(tree: pathlib.Path) -> None:
    script = tree / "scripts" / "deploy.sh"
    script.write_text("#!/bin/sh\necho deploy\n")
    script.chmod(0o755)
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "scripts/deploy.sh")


def test_new_configuration_file_fails(tree: pathlib.Path) -> None:
    (tree / "deny.toml").write_text("[advisories]\n")
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "deny.toml")


def test_deleted_known_file_fails(tree: pathlib.Path) -> None:
    (tree / "crates" / "core" / "src" / "kernel.rs").unlink()
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "missing from the tree")
    assert expected_substring(findings, "crates/core/src/kernel.rs")


def test_modified_known_file_fails(tree: pathlib.Path) -> None:
    (tree / "Cargo.toml").write_text("[workspace]\nmembers = ['evil']\n")
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "content mismatch")
    assert expected_substring(findings, "Cargo.toml")


def test_regular_file_replaced_by_symlink_fails(tree: pathlib.Path) -> None:
    target = tree / "Cargo.toml"
    target.unlink()
    os.symlink("crates/core/src/kernel.rs", target)
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "type mismatch")
    assert expected_substring(findings, "Cargo.toml")


def test_symlink_replaced_by_regular_file_fails(tree: pathlib.Path) -> None:
    link = tree / "CLAUDE.md"
    os.symlink("AGENTS.md", link)
    (tree / "AGENTS.md").write_text("# agents\n")
    capture_provenance.capture(tree, tree / "qualification", "full")
    assert provenance_check.verify(tree, EVIDENCE)[0] == []

    link.unlink()
    link.write_text("# agents\n")
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "type mismatch")
    assert expected_substring(findings, "CLAUDE.md")


def test_symlink_target_change_fails(tree: pathlib.Path) -> None:
    (tree / "AGENTS.md").write_text("# agents\n")
    (tree / "OTHER.md").write_text("# other\n")
    os.symlink("AGENTS.md", tree / "CLAUDE.md")
    capture_provenance.capture(tree, tree / "qualification", "full")
    assert provenance_check.verify(tree, EVIDENCE)[0] == []

    (tree / "CLAUDE.md").unlink()
    os.symlink("OTHER.md", tree / "CLAUDE.md")
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "symlink target mismatch")
    assert expected_substring(findings, "CLAUDE.md")


def test_executable_bit_change_fails(tree: pathlib.Path) -> None:
    (tree / "scripts" / "release.sh").chmod(0o644)
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "mode mismatch")
    assert expected_substring(findings, "scripts/release.sh")


def test_nested_unexpected_directory_and_file_fails(tree: pathlib.Path) -> None:
    nested = tree / "crates" / "core" / "src" / "internal" / "deep"
    nested.mkdir(parents=True)
    (nested / "secret.rs").write_text("// hidden\n")
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "crates/core/src/internal/deep/secret.rs")


def test_nested_unexpected_empty_directory_fails(tree: pathlib.Path) -> None:
    (tree / "crates" / "unexpected").mkdir()
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "crates/unexpected")


def test_path_traversal_attempt_in_manifest_is_rejected(tree: pathlib.Path) -> None:
    evidence = tree / EVIDENCE
    manifest = json.loads(evidence.read_text())
    manifest["entries"]["../escape.rs"] = {"kind": "file", "sha256": "0" * 64, "mode": "0644"}
    evidence.write_text(json.dumps(manifest))

    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "traversal segment")


def test_absolute_manifest_path_is_rejected(tree: pathlib.Path) -> None:
    evidence = tree / EVIDENCE
    manifest = json.loads(evidence.read_text())
    manifest["entries"]["/etc/passwd"] = {"kind": "file", "sha256": "0" * 64, "mode": "0644"}
    evidence.write_text(json.dumps(manifest))

    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "absolute")


def test_absolute_symlink_target_is_rejected(tree: pathlib.Path) -> None:
    evidence = tree / EVIDENCE
    manifest = json.loads(evidence.read_text())
    manifest["entries"]["CLAUDE.md"] = {"kind": "symlink", "target": "/etc/passwd", "mode": "0777"}
    evidence.write_text(json.dumps(manifest))

    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "prohibited absolute target")


def test_escaping_symlink_target_is_rejected(tree: pathlib.Path) -> None:
    evidence = tree / EVIDENCE
    manifest = json.loads(evidence.read_text())
    manifest["entries"]["CLAUDE.md"] = {"kind": "symlink", "target": "../../outside", "mode": "0777"}
    evidence.write_text(json.dumps(manifest))

    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "escapes the source root")


def test_lockfile_traversal_path_is_rejected(tree: pathlib.Path) -> None:
    evidence = tree / EVIDENCE
    manifest = json.loads(evidence.read_text())
    manifest["lockfiles"] = {"../../outside-file": "sha256:" + "0" * 64}
    evidence.write_text(json.dumps(manifest))

    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "not a safe manifest path")


def test_lockfile_absolute_path_is_rejected(tree: pathlib.Path) -> None:
    evidence = tree / EVIDENCE
    manifest = json.loads(evidence.read_text())
    manifest["lockfiles"] = {"/etc/passwd": "sha256:" + "0" * 64}
    evidence.write_text(json.dumps(manifest))

    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "not a safe manifest path")


def test_lockfile_noncanonical_path_is_rejected(tree: pathlib.Path) -> None:
    evidence = tree / EVIDENCE
    manifest = json.loads(evidence.read_text())
    manifest["lockfiles"] = {"./Cargo.toml": "sha256:" + "0" * 64}
    evidence.write_text(json.dumps(manifest))

    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "not a safe manifest path")


# -- Exclusion policy --------------------------------------------------------


def test_ignored_build_output_does_not_invalidate(tree: pathlib.Path) -> None:
    """Generated, ignored artifacts stay outside the source contract."""

    (tree / "target").mkdir()
    (tree / "target" / "debug.bin").write_bytes(b"\x00")
    (tree / "scratch.tmp").write_text("temporary\n")
    assert provenance_check.verify(tree, EVIDENCE)[0] == []


def test_changing_gitignore_invalidates(tree: pathlib.Path) -> None:
    """Ignore rules are source content, so editing them is a source change."""

    (tree / ".gitignore").write_text("target/\n*.tmp\n*.bak\n")
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, ".gitignore")


def test_exclusion_policy_is_recorded_in_the_manifest(tree: pathlib.Path) -> None:
    manifest = json.loads((tree / EVIDENCE).read_text())
    assert manifest["schema_version"] == source_tree.SCHEMA_VERSION
    assert manifest["enumeration_policy_version"] == source_tree.ENUMERATION_POLICY_VERSION
    policy = manifest["policy"]
    assert policy["enumeration_policy_version"] == source_tree.ENUMERATION_POLICY_VERSION
    assert policy["gitignore_policy_version"] == gitignore.GITIGNORE_POLICY_VERSION
    assert "target" in policy["pruned_directory_names"]
    assert ".gitignore" in policy["authoritative_ignore_files"]


def test_unsupported_ignore_construct_is_rejected(tmp_path: pathlib.Path) -> None:
    """An unrepresentable pattern must fail closed, not silently not-match."""

    root = tmp_path / "tree"
    root.mkdir()
    (root / "keep.txt").write_text("keep\n")
    (root / ".gitignore").write_text("a**b\n")
    with pytest.raises(source_tree.SourceTreeError, match="whole path segment"):
        source_tree.enumerate_tree(root)


def test_posix_bracket_expression_is_rejected(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "keep.txt").write_text("keep\n")
    (root / ".gitignore").write_text("*.py[[:digit:]]\n")
    with pytest.raises(source_tree.SourceTreeError, match="POSIX bracket"):
        source_tree.enumerate_tree(root)


def test_ineffective_negation_is_rejected(tmp_path: pathlib.Path) -> None:
    """Git cannot re-include inside an excluded directory."""

    root = tmp_path / "tree"
    root.mkdir()
    (root / "keep.txt").write_text("keep\n")
    (root / ".gitignore").write_text("build/\n!build/keep.txt\n")
    with pytest.raises(source_tree.SourceTreeError, match="cannot re-include"):
        source_tree.enumerate_tree(root)


def test_policy_version_change_invalidates_older_manifests(tree: pathlib.Path) -> None:
    """Ignore semantics are immutable: a version bump retires old evidence."""

    evidence = tree / EVIDENCE
    manifest = json.loads(evidence.read_text())
    manifest["enumeration_policy_version"] = "nemo-source-tree-v0"
    evidence.write_text(json.dumps(manifest))
    findings, _ = provenance_check.verify(tree, EVIDENCE)
    assert expected_substring(findings, "enumeration_policy_version")


# -- Host independence -------------------------------------------------------


def test_enumeration_ignores_host_git_configuration(
    tree: pathlib.Path, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Identical trees must enumerate identically on any developer machine.

    Global Git configuration, `core.excludesFile`, `.git/info/exclude`, and the
    XDG ignore file would all make the entry set host-dependent if enumeration
    consulted them. Nothing in the walk does, and this proves it.
    """

    baseline = source_tree.enumerate_tree(tree).digest

    hostile_home = tmp_path / "hostile-home"
    (hostile_home / ".config" / "git").mkdir(parents=True)
    (hostile_home / ".config" / "git" / "ignore").write_text("*.rs\nCargo.toml\n")
    global_config = tmp_path / "global-gitconfig"
    global_config.write_text("[core]\n\texcludesFile = " + str(hostile_home / ".config" / "git" / "ignore") + "\n")
    (tree / ".git" / "info").mkdir(parents=True, exist_ok=True)
    (tree / ".git" / "info" / "exclude").write_text("crates/\n")

    monkeypatch.setenv("HOME", str(hostile_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(hostile_home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(global_config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "0")
    monkeypatch.setenv("GIT_DIR", str(tree / ".git"))

    assert source_tree.enumerate_tree(tree).digest == baseline
    # `.git` is pruned, so its info/exclude can never participate either.
    assert not any(path == ".git" or path.startswith(".git/") for path in source_tree.enumerate_tree(tree).entries)


def test_policy_declares_the_host_independent_choices(tree: pathlib.Path) -> None:
    manifest = json.loads((tree / EVIDENCE).read_text())
    policy = manifest["policy"]
    assert policy["enumeration_policy_version"] == source_tree.ENUMERATION_POLICY_VERSION
    assert policy["global_git_excludes"] == "ignored"
    assert policy["git_info_exclude"] == "ignored"
    assert policy["authoritative_ignore_sources"] == "repository-contained .gitignore files only"


def test_authoritative_ignore_files_are_themselves_manifested(tree: pathlib.Path) -> None:
    """The rules that decided the entry set must be verified source entries."""

    nested = tree / "crates" / "core"
    (nested / ".gitignore").write_text("generated/\n")
    capture_provenance.capture(tree, tree / "qualification", "full")
    manifest = json.loads((tree / EVIDENCE).read_text())
    for path in manifest["policy"]["authoritative_ignore_files"]:
        assert path in manifest["entries"], path


def test_entries_are_typed_objects(tree: pathlib.Path) -> None:
    manifest = json.loads((tree / EVIDENCE).read_text())
    entry = manifest["entries"]["crates/core/src/kernel.rs"]
    assert entry["kind"] == "file"
    assert entry["mode"] == "0644"
    assert len(entry["sha256"]) == 64


def test_repository_ignore_rules_cover_generated_outputs() -> None:
    """Generated outputs this repository produces must not enter the manifest.

    The enumeration reads `.gitignore` from the tree instead of asking Git, so
    this pins the rules that matter for a tree where `just` recipes have already
    written build products.
    """

    repository = SCRIPT_DIR.parents[1]
    ignore = gitignore.collect(repository, iter([".gitignore"]))
    generated_paths = [
        "crates/node/index.js",
        "crates/node/index.d.ts",
        "crates/node/nemo-relay.darwin-arm64.node",
        "docs/reference/api/rust-library-reference/example.mdx",
        "docs/reference/api/python/_generated/thing.mdx",
        "go/nemo_relay/nemo-relay-events-2026-09-10-09.31.17.jsonl",
        "python/nemo_relay/_native.cpython-313-darwin.so",
        "examples/rust-native-plugin/relay-plugin.local.toml",
    ]
    for path in generated_paths:
        assert source_tree.path_is_excluded(ignore, path, False) or (
            source_tree.statically_excluded(pathlib.PurePosixPath(path))
        ), path


# -- CLI contract ------------------------------------------------------------


def test_cli_reports_pass_and_fail_clearly(tree: pathlib.Path) -> None:
    passing = subprocess.run(
        [sys.executable, str(SCRIPT_DIR / "provenance_check.py"), "--root", str(tree)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert passing.returncode == 0, passing.stdout + passing.stderr
    assert "PROVENANCE PASS" in passing.stdout

    (tree / "extra.rs").write_text("// extra\n")
    failing = subprocess.run(
        [sys.executable, str(SCRIPT_DIR / "provenance_check.py"), "--root", str(tree)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert failing.returncode == 1
    assert "PROVENANCE FAIL" in failing.stdout
    assert "extra.rs" in failing.stdout
