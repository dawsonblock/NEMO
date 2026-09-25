#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verify that an installed CLI wheel can find and run its plugin host.

The installation is the thing under test, not the checkout: the wheel is built
from the two binaries named on the command line, installed into a virtual
environment that has nothing else in it, and then exercised from there. A
repository-relative run proves neither half of what matters — that the host
travels with the artifact (so a deployment receives it) and that the location it
lands in is one the supervisor looks in (so a deployment finds it).

What the supervisor looks in, and what this asserts, is the directory holding
the executable that started the process: for a binding loaded into Python that
is the interpreter itself, and a wheel's `.data/scripts` entries install into
exactly that directory. Proving the two are the same place is the point; a host
that installed somewhere else would be a host no deployment ever starts.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("package_cli_bin", ROOT / "scripts" / "package-cli-bin.py")
assert SPEC is not None and SPEC.loader is not None
PACKAGE_CLI_BIN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PACKAGE_CLI_BIN
SPEC.loader.exec_module(PACKAGE_CLI_BIN)

# The message the host prints when it is started with nothing to serve. A
# binary that prints it is the host rather than something else that happened to
# be copied under the host's name.
HOST_IDENTITY_MESSAGE = "NEMO_RELAY_PLUGIN_HOST_SOCKET is not set"


def host_target() -> str:
    """Return the packaging target for the machine running this verification."""
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Darwin":
        if machine in {"arm64", "aarch64"}:
            return "aarch64-apple-darwin"
        raise SystemExit(f"verification does not cover {system} on {machine}")
    if system == "Linux":
        if machine in {"x86_64", "amd64"}:
            return "x86_64-unknown-linux-gnu"
        if machine in {"aarch64", "arm64"}:
            return "aarch64-unknown-linux-gnu"
        raise SystemExit(f"verification does not cover {system} on {machine}")
    raise SystemExit(f"verification does not cover {system}")


def scripts_directory(environment: Path) -> Path:
    """Return the directory an installation puts executables in."""
    if os.name == "nt":
        return environment / "Scripts"
    return environment / "bin"


def run(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    """Run one command, returning its completed process without raising."""
    return subprocess.run(command, capture_output=True, check=False, env=env)  # noqa: S603


def without_host_configuration() -> dict[str, str]:
    """Return the environment, with nothing in it that names a plugin host.

    The check below is that the host identifies itself when nothing has told it
    anything, so an inherited `NEMO_RELAY_PLUGIN_HOST*` variable would be the
    verification answering its own question.
    """
    return {name: value for name, value in os.environ.items() if not name.startswith("NEMO_RELAY_PLUGIN_HOST")}


def verify(binary: Path, host_binary: Path, target: str, version: str) -> None:
    """Build, install, and exercise the wheel named by the arguments."""
    platform_record = PACKAGE_CLI_BIN.PLATFORMS[target]
    with tempfile.TemporaryDirectory() as temporary:
        workspace = Path(temporary)
        wheel = PACKAGE_CLI_BIN.build_wheel(binary, host_binary, platform_record, version, workspace)
        print(f"built {wheel.name}")

        environment = workspace / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        interpreter = scripts_directory(environment) / ("python.exe" if os.name == "nt" else "python")

        installed = run(
            [
                str(interpreter),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--disable-pip-version-check",
                str(wheel),
            ]
        )
        if installed.returncode != 0:
            raise SystemExit(
                "installing the wheel failed:\n"
                + installed.stdout.decode(errors="replace")
                + installed.stderr.decode(errors="replace")
            )

        # The executables land here because that is where the wheel's
        # `.data/scripts` entries install, and it is the directory holding the
        # executable that started the process — which is what the supervisor
        # probes first when nothing names a host.
        scripts = scripts_directory(environment)
        installed_cli = scripts / platform_record.executable
        installed_host = scripts / platform_record.host_executable
        for executable in (installed_cli, installed_host):
            if not executable.is_file():
                raise SystemExit(f"the installed wheel is missing {executable.name}")
            if os.name != "nt" and not os.access(executable, os.X_OK):
                raise SystemExit(f"the installed {executable.name} is not executable")
        print(f"installed {installed_cli.name} and {installed_host.name} beside the interpreter")

        # The host, run with nothing to serve, says what it is and exits rather
        # than pretending to serve a session. A copy of the CLI under the host's
        # name would answer differently, so this distinguishes delivery from
        # delivery of the right thing.
        identity = run([str(installed_host)], env=without_host_configuration())
        if identity.returncode != 2:
            raise SystemExit(
                f"{installed_host.name} exited {identity.returncode} with no socket: "
                + identity.stderr.decode(errors="replace")
            )
        if HOST_IDENTITY_MESSAGE not in identity.stderr.decode(errors="replace"):
            raise SystemExit(
                f"{installed_host.name} did not identify itself as the plugin host: "
                + identity.stderr.decode(errors="replace")
            )
        print("the installed plugin host runs and identifies itself")

        version_run = run([str(installed_cli), "--version"])
        if version_run.returncode != 0:
            raise SystemExit(f"{installed_cli.name} --version failed: " + version_run.stderr.decode(errors="replace"))
        print("the installed CLI runs: " + version_run.stdout.decode(errors="replace").strip())


def parse_args() -> argparse.Namespace:
    """Parse verification arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--host-binary", type=Path, required=True)
    parser.add_argument("--target", default=None)
    parser.add_argument("--version", default="0.0.0")
    return parser.parse_args()


def main() -> None:
    """Verify the wheel built from the named binaries."""
    args = parse_args()
    if not args.binary.is_file():
        raise SystemExit(f"CLI binary does not exist: {args.binary}")
    if not args.host_binary.is_file():
        raise SystemExit(f"plugin host binary does not exist: {args.host_binary}")
    target = args.target or host_target()
    if shutil.which("python") is None and not Path(sys.executable).is_file():
        raise SystemExit("no interpreter to build a virtual environment with")
    verify(args.binary, args.host_binary, target, args.version)


if __name__ == "__main__":
    main()
