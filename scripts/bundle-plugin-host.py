#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bundle `nemo-plugin-host` into an already-built wheel.

The host is not an optional utility in the isolation model; it is the executable
that performs the loading a binding is no longer allowed to perform. Shipping it
in a distribution of its own would give the pair two versions to keep in step —
binding, protocol, host, native ABI — where shipping it inside the platform
artifact makes them atomic by construction.

It goes in the wheel's `.data/scripts`, which is where pip installs executables:
the directory holding the interpreter, and therefore the directory the
supervisor probes when a binding starts a host without naming one. Building the
package and patching it are separate steps because maturin produces the wheel
and knows nothing about a cargo binary; the patch is a zip rewrite with a
regenerated `RECORD`, which is the only part of a wheel that describes files a
later step added.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

# The name the supervisor looks for, per platform. A wheel tagged for Windows
# has to carry the `.exe` spelling: a file named without it is a file nothing
# starts.
HOST_EXECUTABLE = "nemo-plugin-host"


def host_executable_for_wheel(filename: str) -> str:
    """Return the host's file name for the platform the wheel is tagged for."""
    tags = Path(filename).name.removesuffix(".whl").split("-")
    if len(tags) < 5:
        raise ValueError(f"{filename} does not carry a wheel platform tag")
    if any(tag.startswith("win") for tag in tags[-3:]):
        return f"{HOST_EXECUTABLE}.exe"
    return HOST_EXECUTABLE


def record_entry(path: str, content: bytes) -> str:
    """Return one `RECORD` line for the provided file."""
    digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
    return f"{path},sha256={digest},{len(content)}"


def scripts_directory(archive: zipfile.ZipFile, wheel_name: str) -> str:
    """Return the `.data/scripts` prefix this wheel installs executables into."""
    dist_info = next(
        (name.split("/")[0] for name in archive.namelist() if name.endswith(".dist-info/METADATA")),
        None,
    )
    if dist_info is None:
        raise ValueError(f"{wheel_name} has no .dist-info/METADATA to name the install root")
    # `<normalized name>-<version>.data/scripts`, which is the dist-info
    # directory without its suffix: pip installs these beside the interpreter,
    # and it derives the location from the same name the metadata uses.
    return f"{dist_info.removesuffix('.dist-info')}.data/scripts"


def add_host_to_wheel(wheel: Path, host_binary: Path) -> Path:
    """Add the host to a built wheel, in place, and return the wheel.

    Refusing a wheel that already carries one is deliberate rather than
    convenient: two hosts in one distribution would install a file whose
    provenance depends on zip ordering, and the question this step answers is
    exactly which binary a deployment receives.
    """
    if not wheel.is_file():
        raise ValueError(f"wheel does not exist: {wheel}")
    if not host_binary.is_file():
        raise ValueError(f"plugin host binary does not exist: {host_binary}")
    entry = f"{host_executable_for_wheel(wheel.name)}"
    host_bytes = host_binary.read_bytes()

    with zipfile.ZipFile(wheel) as archive:
        scripts = scripts_directory(archive, wheel.name)
        target = f"{scripts}/{entry}"
        if target in archive.namelist():
            raise ValueError(f"{wheel.name} already carries {target}")
        record_name = next(name for name in archive.namelist() if name.endswith(".dist-info/RECORD"))
        record_lines = archive.read(record_name).decode().splitlines()

    record_lines = [line for line in record_lines if line.split(",")[0] != record_name]
    record_lines.append(record_entry(target, host_bytes))
    record_lines.append(f"{record_name},,")
    record_content = ("\n".join(record_lines) + "\n").encode()

    staging = Path(tempfile.mkdtemp(dir=wheel.parent, prefix=".nemo-relay-wheel-"))
    try:
        patched = staging / wheel.name
        with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(patched, "w") as destination:
            for info in source.infolist():
                if info.filename == record_name:
                    continue
                destination.writestr(info, source.read(info.filename))
            entry_info = zipfile.ZipInfo(target)
            entry_info.compress_type = zipfile.ZIP_DEFLATED
            entry_info.create_system = 3
            entry_info.external_attr = (stat.S_IFREG | 0o755) << 16
            destination.writestr(entry_info, host_bytes)
            record_info = zipfile.ZipInfo(record_name)
            record_info.compress_type = zipfile.ZIP_DEFLATED
            destination.writestr(record_info, record_content)
        shutil.move(str(patched), str(wheel))
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return wheel


def parse_args() -> argparse.Namespace:
    """Parse bundling arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument(
        "--host-binary",
        type=Path,
        required=True,
        help="the nemo-plugin-host executable built for the wheel's platform",
    )
    return parser.parse_args()


def main() -> None:
    """Bundle the host named on the command line into the wheel named with it."""
    args = parse_args()
    try:
        add_host_to_wheel(args.wheel, args.host_binary)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print(f"bundled {args.host_binary.name} into {args.wheel.name}", file=sys.stderr)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parent.parent)
    main()
