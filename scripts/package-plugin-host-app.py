#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Package the plugin host as a macOS application bundle and sign it ad hoc.

macOS applies App Sandbox through the entitlements a *signed bundle* carries. A
bare Mach-O that claims `com.apple.security.app-sandbox` is refused at launch —
the entitlement is in the signature but there is no bundle for the system to
create a container from — so confinement is not a property a flag can add to the
executable this repository already builds. It is a second packaging step, and
this is it.

What the bundle is for:

* the executable lives at `Contents/MacOS/nemo-plugin-host`, which is the layout
  `crates/plugin-host` resolves and the layout whose signature the system reads;
* `Contents/Info.plist` gives the bundle an identifier, which is what names the
  container the host is allowed to write;
* the entitlements come from `security/entitlements/`, and the strict variant is
  the default: the weaker one exists for plugins signed by someone else and is
  chosen explicitly.

Signing here is ad hoc (`codesign --sign -`). That is what makes the *security
architecture* implementable and testable on a machine with no Apple certificate,
and it is not a distribution story: an ad-hoc signature is not notarizable and
not accepted for a downloaded artifact, so shipping this to users still needs a
Developer ID and a notarization step in CI.
"""

from __future__ import annotations

import argparse
import os
import plistlib
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The name the supervisor resolves beside the runtime. One name for the bundle
#: rather than one per entitlement variant: what a deployment selects is a
#: policy, and a second name would make the resolver choose between them.
BUNDLE_NAME = "nemo-plugin-host.app"

#: The executable inside the bundle, without the Windows spelling: this is the
#: macOS bundle and there is no other platform it is produced for.
EXECUTABLE_NAME = "nemo-plugin-host"

#: The identifier the container is named after. Stable, because a container is
#: where a host keeps what it was handed, and a new identifier per build would
#: strand what a previous one staged.
BUNDLE_IDENTIFIER = "com.nvidia.nemo-relay.nemo-plugin-host"

#: The entitlement variants, by the name a packaging caller selects one with.
ENTITLEMENTS = {
    "restricted": REPO_ROOT / "security" / "entitlements" / "nemo-plugin-host-restricted.plist",
    "third-party": (REPO_ROOT / "security" / "entitlements" / "nemo-plugin-host-restricted-third-party.plist"),
}

#: The default variant, and the reason the default is the strict one: the weaker
#: signature is for plugins from another signer, and a build that weakens library
#: validation without being asked to would silently drop a layer on every plugin.
DEFAULT_VARIANT = "restricted"


def write_bundle(
    host_binary: Path,
    output_directory: Path,
    *,
    version: str,
    bundle_identifier: str = BUNDLE_IDENTIFIER,
    bundle_name: str = BUNDLE_NAME,
) -> Path:
    """Lay the bundle out around `host_binary` and return the bundle path.

    A pure file-layout step rather than one that runs a tool, so the layout is
    testable on any machine: what Apple requires of it is a plist naming the
    executable and a `Contents/MacOS` directory holding it, and the signing that
    turns it into a confined process is a separate call.
    """
    if not host_binary.is_file():
        raise ValueError(f"plugin host binary does not exist: {host_binary}")

    bundle = output_directory / bundle_name
    macos_directory = bundle / "Contents" / "MacOS"
    if bundle.exists():
        shutil.rmtree(bundle)
    macos_directory.mkdir(parents=True)

    executable = macos_directory / EXECUTABLE_NAME
    shutil.copyfile(host_binary, executable)
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    info = {
        "CFBundleExecutable": EXECUTABLE_NAME,
        "CFBundleIdentifier": bundle_identifier,
        "CFBundleName": "nemo-plugin-host",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": version,
        "LSMinimumSystemVersion": "11.0",
    }
    with (bundle / "Contents" / "Info.plist").open("wb") as handle:
        plistlib.dump(info, handle)
    return bundle


def entitlements_for(variant: str) -> Path:
    """Return the entitlement file a variant signs with, refusing an unknown one."""
    try:
        return ENTITLEMENTS[variant]
    except KeyError as error:
        known = ", ".join(sorted(ENTITLEMENTS))
        raise ValueError(f"unknown entitlement variant '{variant}'; known variants: {known}") from error


def sign_bundle(
    bundle: Path,
    entitlements: Path,
    *,
    bundle_identifier: str = BUNDLE_IDENTIFIER,
    run: Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> None:
    """Sign the bundle ad hoc with `entitlements`.

    Ad hoc (`--sign -`) on purpose: the entitlement is what the sandbox is read
    from, and requiring an Apple certificate to *test* the architecture would put
    the security design behind a purchasing decision. Distribution is a separate
    step with a real identity and notarization, and this signature is not one.
    """
    if not entitlements.is_file():
        raise ValueError(f"entitlements file does not exist: {entitlements}")
    command = [
        "codesign",
        "--force",
        "--sign",
        "-",
        "--identifier",
        bundle_identifier,
        "--entitlements",
        str(entitlements),
        str(bundle),
    ]
    completed = run(command)
    if completed.returncode != 0:
        raise ValueError(f"codesign failed for {bundle}: {completed.stderr.decode(errors='replace')}")


def parse_args() -> argparse.Namespace:
    """Parse packaging arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--host-binary",
        type=Path,
        required=True,
        help="the nemo-plugin-host executable built for macOS arm64",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        required=True,
        help="where nemo-plugin-host.app is written",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="the version the bundle reports, which is the runtime's own",
    )
    parser.add_argument(
        "--variant",
        default=DEFAULT_VARIANT,
        choices=sorted(ENTITLEMENTS),
        help="which entitlements to sign with (default: restricted)",
    )
    parser.add_argument(
        "--no-sign",
        action="store_true",
        help="lay the bundle out without signing it, for packaging tests",
    )
    return parser.parse_args()


def main() -> None:
    """Package the host named on the command line as a signed bundle."""
    args = parse_args()
    if sys.platform != "darwin" and not args.no_sign:
        raise SystemExit(
            "the macOS plugin host bundle is signed with codesign, which is only available on "
            "macOS; pass --no-sign to lay out the bundle without a signature"
        )
    try:
        bundle = write_bundle(
            args.host_binary,
            args.output_directory,
            version=args.version,
        )
        if not args.no_sign:
            sign_bundle(bundle, entitlements_for(args.variant))
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print(f"packaged {bundle}", file=sys.stderr)


if __name__ == "__main__":
    os.chdir(REPO_ROOT)
    main()
