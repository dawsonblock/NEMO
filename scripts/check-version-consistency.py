#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verify that every release-bearing NeMo Relay surface has one version."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RELEASE_CRATES = {
    "nemo-relay-types",
    "nemo-relay-plugin",
    "nemo-relay-worker-proto",
    "nemo-relay-worker",
    "nemo-relay",
    "nemo-relay-adaptive",
    "nemo-relay-pii-redaction",
    "nemo-relay-ffi",
    "nemo-relay-cli",
}


@dataclass(frozen=True)
class Check:
    name: str
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors


def toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def json_file(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def pep440_version(version: str) -> str:
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)\.(\d+))?", version)
    if not match:
        raise ValueError(f"unsupported release version: {version}")
    release, label, number = match.groups()
    labels = {"alpha": "a", "beta": "b", "rc": "rc"}
    return release if label is None else f"{release}{labels[label]}{number}"


def equal(actual: Any, expected: str, description: str) -> list[str]:
    return [] if actual == expected else [f"{description}: expected {expected!r}, found {actual!r}"]


def cargo_check(expected: str) -> Check:
    root = toml(ROOT / "Cargo.toml")
    errors = equal(root["workspace"]["package"]["version"], expected, "workspace.package.version")
    dependencies = root["workspace"]["dependencies"]
    for name in sorted(RELEASE_CRATES):
        dependency = dependencies.get(name, {})
        errors.extend(equal(dependency.get("version"), expected, f"workspace.dependencies.{name}.version"))

    for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        package = toml(manifest).get("package", {})
        name = package.get("name", "")
        if not name.startswith("nemo-relay"):
            continue
        version = package.get("version")
        if version != {"workspace": True}:
            errors.append(f"{manifest.relative_to(ROOT)} must use version.workspace = true")
    return Check("Cargo workspace", tuple(errors))


def node_check(expected: str) -> Check:
    errors: list[str] = []
    node = json_file(ROOT / "crates/node/package.json")
    openclaw = json_file(ROOT / "integrations/openclaw/package.json")
    pi = json_file(ROOT / "integrations/pi/package.json")
    example = json_file(ROOT / "examples/language-binding-plugin/node/package.json")
    lock = json_file(ROOT / "package-lock.json")["packages"]
    errors.extend(equal(node.get("version"), expected, "crates/node/package.json"))
    errors.extend(equal(openclaw.get("version"), expected, "integrations/openclaw/package.json"))
    errors.extend(equal(openclaw.get("dependencies", {}).get("nemo-relay-node"), expected, "OpenClaw node dependency"))
    errors.extend(equal(pi.get("version"), expected, "integrations/pi/package.json"))
    errors.extend(
        equal(
            example.get("dependencies", {}).get("nemo-relay-node"),
            expected,
            "Node language-binding example dependency",
        )
    )
    for path, package_name in (
        ("crates/node", "nemo-relay-node"),
        ("integrations/openclaw", "nemo-relay-openclaw"),
        ("integrations/pi", "nemo-relay-pi"),
    ):
        package = lock.get(path, {})
        errors.extend(equal(package.get("version"), expected, f"package-lock.json {path}"))
        errors.extend(equal(package.get("name"), package_name, f"package-lock.json {path} name"))
    errors.extend(
        equal(
            lock.get("integrations/openclaw", {}).get("dependencies", {}).get("nemo-relay-node"),
            expected,
            "package-lock OpenClaw node dependency",
        )
    )
    errors.extend(
        equal(
            lock.get("examples/language-binding-plugin/node", {}).get("dependencies", {}).get("nemo-relay-node"),
            expected,
            "package-lock Node language-binding example dependency",
        )
    )
    return Check("Node packages", tuple(errors))


def python_check(expected: str) -> Check:
    pep440 = pep440_version(expected)
    errors: list[str] = []
    root = toml(ROOT / "pyproject.toml")
    cli_bin = toml(ROOT / "python/cli-bin/pyproject.toml")
    plugin = toml(ROOT / "python/plugin/pyproject.toml")
    errors.extend(equal(root.get("project", {}).get("dynamic"), ["version"], "pyproject dynamic version"))
    errors.extend(
        equal(
            root["project"]["optional-dependencies"]["cli"],
            [f"nemo-relay-cli-bin=={pep440}"],
            "nemo-relay CLI extra",
        )
    )
    errors.extend(equal(cli_bin["project"].get("version"), pep440, "python CLI binary package"))
    errors.extend(equal(plugin["project"].get("version"), pep440, "python plugin package"))
    return Check("Python packages", tuple(errors))


def integration_check(expected: str) -> Check:
    errors: list[str] = []
    for path in (
        ROOT / "integrations/coding-agents/claude-code/.claude-plugin/plugin.json",
        ROOT / "integrations/coding-agents/codex/.codex-plugin/plugin.json",
    ):
        errors.extend(equal(json_file(path).get("version"), expected, str(path.relative_to(ROOT))))
    return Check("Integration metadata", tuple(errors))


def ffi_check() -> Check:
    package = toml(ROOT / "crates/ffi/Cargo.toml")["package"]
    errors = [] if package.get("version") == {"workspace": True} else ["crates/ffi/Cargo.toml must use version.workspace = true"]
    return Check("FFI metadata", tuple(errors))


def qualification_check(expected: str) -> Check:
    errors: list[str] = []
    report = json_file(ROOT / "qualification/qualification.json")
    release = json_file(ROOT / "release/provenance.json")
    errors.extend(equal(report.get("release_version"), expected, "qualification release_version"))
    errors.extend(equal(release.get("fork", {}).get("version"), expected, "release provenance fork version"))
    return Check("Qualification metadata", tuple(errors))


def documentation_check(expected: str) -> Check:
    stale = "0.9.1-rc." + "1"
    stale_badge = stale.replace("-rc.", "--rc.")
    allowed = {
        ROOT / "FORK_PROVENANCE.md",
        ROOT / "release/provenance.json",
    }
    errors: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path in allowed or any(
            part in {".git", ".venv", ".uv-cache", "target", "node_modules", "qualification"}
            for part in path.parts
        ):
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        if stale in text or stale_badge in text:
            errors.append(f"stale current release reference in {path.relative_to(ROOT)}")
    return Check("Current-version references", tuple(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected_version", nargs="?", help="SemVer release version; defaults to Cargo.toml")
    args = parser.parse_args()
    expected = args.expected_version or toml(ROOT / "Cargo.toml")["workspace"]["package"]["version"]

    checks = [
        cargo_check(expected),
        node_check(expected),
        python_check(expected),
        ffi_check(),
        integration_check(expected),
        qualification_check(expected),
        documentation_check(expected),
    ]
    print(f"Expected release: {expected}")
    for check in checks:
        print(f"{check.name:<30} {'PASS' if check.passed else 'FAIL'}")
        for error in check.errors:
            print(f"  - {error}")
    return 0 if all(check.passed for check in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
