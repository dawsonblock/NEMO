#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Probe App Sandbox behavior using a purpose-built bundled executable.

The restricted policy hands a plugin host to App Sandbox. What makes that a
security boundary rather than a claim is that the operations a plugin must not
perform *fail*, and that the operations it must perform still work: a host that
cannot stage an approved artifact is not confined, it is broken, and a host that
can write `/tmp` or read the account's home is not confined at all.

This checks the sandbox contract on a real machine:

* the probe bundle carries the sandbox entitlement, launches, gets a container,
  and the container is writable where the host stages;
* shared temporary storage, the account's home, outbound
  network and a library outside the container are all refused.

The supplied release host path is checked to ensure the release artifact exists,
but this executable is a focused probe rather than the host itself. The separate
opt-in process-backend test combines a signed host bundle with artifact transfer
and load; it currently documents the temporary-socket denial and must pass after
the IPC transport is changed before restricted mode can be enabled.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROBE_SOURCE = REPO_ROOT / "scripts" / "qualification" / "macos_sandbox_probe.c"
PACKAGER = REPO_ROOT / "scripts" / "package-plugin-host-app.py"

#: The outcome each probe line has to have for the confinement to be real. The
#: value before the first `:` is what is compared, so `denied:1` and `denied` both
#: mean the operation was refused and the errno stays in the log.
EXPECTED = {
    "home_set": "set",
    "write_container": "allowed",
    "create_app_support": "allowed",
    "write_app_support": "allowed",
    "write_tmp": "denied",
    "read_real_home": "denied",
    "write_real_home": "denied",
    "connect_outbound": "denied",
    "dlopen_external": "denied",
}

#: A library the probe tries to load from outside its container. Small, real, and
#: compiled here rather than shipped: the point is that it exists and is readable
#: by the unconfined parent, so a refusal is the sandbox rather than a typo.
EXTERNAL_LIBRARY_SOURCE = "int nemo_relay_probe_symbol(void) { return 1; }\n"


def load_packager():
    """Import the packaging script, which owns the bundle layout and signing."""
    spec = importlib.util.spec_from_file_location("package_plugin_host_app", PACKAGER)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load {PACKAGER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    """Run a command and fail loudly if it does not succeed."""
    completed = subprocess.run(command, capture_output=True, text=True, **kwargs)
    if completed.returncode != 0:
        raise SystemExit(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{completed.stdout}\n{completed.stderr}"
        )
    return completed


def build_probe(directory: Path) -> tuple[Path, Path]:
    """Compile the probe and the library it must not be able to load."""
    probe = directory / "sandbox-probe"
    run(["cc", "-O0", "-o", str(probe), str(PROBE_SOURCE)])
    external = directory / "external.dylib"
    run(
        ["cc", "-dynamiclib", "-x", "c", "-", "-o", str(external)],
        input=EXTERNAL_LIBRARY_SOURCE,
    )
    return probe, external


def parse_probe(output: str) -> dict[str, str]:
    """Read the `PROBE <name>=<outcome>` lines the probe prints."""
    observed: dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith("PROBE "):
            continue
        name, _, value = line[len("PROBE ") :].partition("=")
        observed[name.strip()] = value.strip()
    return observed


def outcome_kind(observed: str) -> str:
    """The part of an outcome that is compared: `denied:1` is a denial."""
    return observed.split(":", 1)[0]


def problems(observed: dict[str, str]) -> list[str]:
    """Return every way the run failed to demonstrate confinement.

    A missing line is a failure of its own: a probe that never reached the
    operation cannot have shown that the operation was refused, and treating an
    absent line as a pass is how a lane reports confinement for a host that
    crashed on startup.
    """
    found: list[str] = []
    for name, expected in EXPECTED.items():
        if name not in observed:
            found.append(f"the probe never reported {name!r}")
            continue
        actual = outcome_kind(observed[name])
        if actual != expected:
            found.append(f"{name}: expected {expected}, the sandbox gave {observed[name]!r}")
    return found


def bundle_entitlements(bundle: Path) -> set[str]:
    """Return the entitlement keys the bundle's signature carries."""
    completed = subprocess.run(
        ["codesign", "-d", "--entitlements", "-", str(bundle)],
        capture_output=True,
        text=True,
    )
    keys = set()
    for line in (completed.stdout + completed.stderr).splitlines():
        stripped = line.strip()
        if stripped.startswith("[Key] "):
            keys.add(stripped[len("[Key] ") :].strip())
    return keys


def parse_args() -> argparse.Namespace:
    """Parse the lane's arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--host-binary",
        type=Path,
        required=True,
        help="the built nemo-plugin-host for this machine; checked alongside the sandbox probe",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        help="where to build; a temporary directory by default",
    )
    parser.add_argument(
        "--real-home",
        type=Path,
        default=Path.home(),
        help="the account's home, which the confined process must not reach",
    )
    return parser.parse_args()


def main() -> int:
    """Build the bundle, run the probe inside it, and judge the outcomes."""
    args = parse_args()
    if sys.platform != "darwin":
        raise SystemExit("the macOS sandbox lane runs on macOS: App Sandbox is macOS's")
    if not args.host_binary.is_file():
        raise SystemExit(f"plugin host binary does not exist: {args.host_binary}")

    packager = load_packager()
    directory = args.output_directory or Path(tempfile.mkdtemp(prefix="nemo-sandbox-lane-"))
    directory.mkdir(parents=True, exist_ok=True)
    try:
        probe, external = build_probe(directory)
        bundle = packager.write_bundle(probe, directory, version="0.0.1")
        packager.sign_bundle(bundle, packager.entitlements_for("restricted"))

        entitlements = bundle_entitlements(bundle)
        if "com.apple.security.app-sandbox" not in entitlements:
            raise SystemExit(f"the bundle is not signed with the sandbox entitlement: {sorted(entitlements)}")

        executable = bundle / "Contents" / "MacOS" / "nemo-plugin-host"
        completed = subprocess.run(
            [str(executable), str(args.real_home), str(external)],
            capture_output=True,
            text=True,
        )
        observed = parse_probe(completed.stdout)

        print(f"sandbox probe lane (host artifact present): {args.host_binary}")
        print(f"  probe bundle: {bundle}")
        print(f"  entitlements: {', '.join(sorted(entitlements)) or '(none)'}")
        for name in EXPECTED:
            print(f"  {name:<20} {observed.get(name, '(not reported)')}")
        print(f"  probe exit status: {completed.returncode}")

        found = problems(observed)
        if found:
            print()
            for problem in found:
                print(f"error: {problem}", file=sys.stderr)
            return 1
    finally:
        if args.output_directory is None:
            shutil.rmtree(directory, ignore_errors=True)

    print()
    print("the confined host is confined to its own container")
    return 0


if __name__ == "__main__":
    os.chdir(REPO_ROOT)
    raise SystemExit(main())
