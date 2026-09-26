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
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
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


def run(
    command: list[str], env: dict[str, str] | None = None, cwd: str | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Run one command, returning its completed process without raising."""
    return subprocess.run(command, capture_output=True, check=False, env=env, cwd=cwd)  # noqa: S603


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
        verify_wheel(wheel, cli_executable=platform_record.executable)


def host_executable_for(wheel_name: str) -> str:
    """Return the host's installed name for the platform the wheel targets."""
    tags = Path(wheel_name).name.removesuffix(".whl").split("-")
    if any(tag.startswith("win") for tag in tags[-3:]):
        return "nemo-plugin-host.exe"
    return "nemo-plugin-host"


def verify_wheel(wheel: Path, cli_executable: str | None = None) -> None:
    """Install one built wheel into a clean environment and exercise it.

    The installation is what is under test: the wheel goes into a virtual
    environment that has nothing else in it, and the executables are then looked
    for where a binding looks for them — beside the interpreter the wheel was
    installed for, which is where a wheel's `.data/scripts` entries land.
    """
    with tempfile.TemporaryDirectory() as temporary:
        environment = Path(temporary) / "venv"
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

        scripts = scripts_directory(environment)
        installed_host = scripts / host_executable_for(wheel.name)
        installed_cli = scripts / cli_executable if cli_executable else None
        for executable in (installed_cli, installed_host):
            if executable is None:
                continue
            if not executable.is_file():
                raise SystemExit(f"the installed wheel is missing {executable.name}")
            if os.name != "nt" and not os.access(executable, os.X_OK):
                raise SystemExit(f"the installed {executable.name} is not executable")
        delivered = [item.name for item in (installed_cli, installed_host) if item is not None]
        print("installed " + ", ".join(delivered) + " beside the interpreter")

        # The host, run with nothing to serve, says what it is and exits rather
        # than pretending to serve a session. A copy of something else under the
        # host's name would answer differently, so this distinguishes delivery
        # from delivery of the right thing.
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

        if installed_cli is None:
            return
        version_run = run([str(installed_cli), "--version"])
        if version_run.returncode != 0:
            raise SystemExit(f"{installed_cli.name} --version failed: " + version_run.stderr.decode(errors="replace"))
        print("the installed CLI runs: " + version_run.stdout.decode(errors="replace").strip())


def verify_npm_package(tarball: Path) -> None:
    """Install one built Node platform package and run the host it carries.

    npm is asked to install the tarball into an empty project, which is the only
    way to learn what a deployment receives: the package's own manifest decides
    what npm unpacks, so a host the packer forgot is a host this cannot find
    either. The addon resolves the executable from this same directory rather
    than from `PATH`, which is why the check is about the installed tree and not
    about whatever happens to be beside `node`.
    """
    if shutil.which("npm") is None:
        raise SystemExit("npm is not on PATH, and a Node package cannot be installed without it")
    with tarfile.open(tarball) as archive:
        member = archive.extractfile("package/package.json")
        if member is None:
            raise SystemExit(f"{tarball.name} has no package/package.json")
        manifest = json.load(member)
    name = manifest["name"]
    host_path = (
        "bin/nemo-plugin-host.exe"
        if any(os_name == "win32" for os_name in manifest.get("os", []))
        else "bin/nemo-plugin-host"
    )

    with tempfile.TemporaryDirectory() as temporary:
        project = Path(temporary)
        (project / "package.json").write_text(
            json.dumps({"name": "verify-installed-plugin-host", "private": True}) + "\n"
        )
        installed = run(
            ["npm", "install", "--no-audit", "--no-fund", "--loglevel=error", str(tarball)],
            cwd=str(project),
        )
        if installed.returncode != 0:
            raise SystemExit(
                "installing the npm package failed:\n"
                + installed.stdout.decode(errors="replace")
                + installed.stderr.decode(errors="replace")
            )

        installed_host = project / "node_modules" / name / host_path
        if not installed_host.is_file():
            raise SystemExit(f"{name} installed without {host_path}")
        if os.name != "nt" and not os.access(installed_host, os.X_OK):
            raise SystemExit(f"{installed_host} is not executable")
        print(f"installed {name} with a plugin host at {host_path}")

        identity = run([str(installed_host)], env=without_host_configuration())
        if identity.returncode != 2:
            raise SystemExit(
                f"{host_path} exited {identity.returncode} with no socket: " + identity.stderr.decode(errors="replace")
            )
        if HOST_IDENTITY_MESSAGE not in identity.stderr.decode(errors="replace"):
            raise SystemExit(
                f"{host_path} did not identify itself as the plugin host: " + identity.stderr.decode(errors="replace")
            )
        print("the installed plugin host runs and identifies itself")


def parse_args() -> argparse.Namespace:
    """Parse verification arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--host-binary", type=Path, default=None)
    parser.add_argument(
        "--wheel",
        type=Path,
        default=None,
        help="an already-built wheel to install and check instead of building one",
    )
    parser.add_argument(
        "--npm-package",
        type=Path,
        default=None,
        help="an already-built Node platform package to install and check",
    )
    parser.add_argument(
        "--cli",
        default=None,
        help="the CLI's file name inside the wheel, when the wheel carries one",
    )
    parser.add_argument("--target", default=None)
    parser.add_argument("--version", default="0.0.0")
    return parser.parse_args()


def main() -> None:
    """Verify an installed wheel, either built here or named as one already built."""
    args = parse_args()
    if shutil.which("python") is None and not Path(sys.executable).is_file():
        raise SystemExit("no interpreter to build a virtual environment with")
    if args.npm_package is not None:
        if not args.npm_package.is_file():
            raise SystemExit(f"npm package does not exist: {args.npm_package}")
        print(f"installing {args.npm_package.name}")
        verify_npm_package(args.npm_package)
        return
    if args.wheel is not None:
        if not args.wheel.is_file():
            raise SystemExit(f"wheel does not exist: {args.wheel}")
        print(f"installing {args.wheel.name}")
        verify_wheel(args.wheel, cli_executable=args.cli)
        return
    if args.binary is None or args.host_binary is None:
        raise SystemExit("name either --wheel, or both --binary and --host-binary")
    if not args.binary.is_file():
        raise SystemExit(f"CLI binary does not exist: {args.binary}")
    if not args.host_binary.is_file():
        raise SystemExit(f"plugin host binary does not exist: {args.host_binary}")
    target = args.target or host_target()
    verify(args.binary, args.host_binary, target, args.version)


if __name__ == "__main__":
    main()
