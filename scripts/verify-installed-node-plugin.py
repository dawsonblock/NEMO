#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prove an installed Node.js package hosts a native plugin, or says why it cannot.

The Python verifier asks this question of a wheel; this asks it of the two npm
tarballs a deployment installs — the portable metapackage and the platform package
that carries both the addon and the plugin host. "The package imports" is not the
property under test. The property is that the addon finds the host the platform
package shipped with nothing in the environment naming one, that the host runs the
plugin in a process of its own, and that a managed call still reaches the plugin
from the runtime's process.

Both halves matter and they fail differently: a package that carries no host must
say where it looked, rather than loading plugin code in process, which is what
`--expect refused` checks by removing the host from an install that had one.

The fixture and the manifest are built here, so what runs is the installed runtime
rather than anything from the checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

# What the fixture registers. Its tool-request intercept answers with this key,
# which is how the runner knows the plugin ran rather than the call merely
# succeeding.
PLUGIN_ID = "fixture_native"
PLUGIN_SYMBOL = "nemo_relay_fixture_native_plugin"
PLUGIN_TOOL = "installed-node-native"
HOST_EXECUTABLES = ("nemo-plugin-host", "nemo-plugin-host.exe")

RUNNER = """
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const lib = require('nemo-relay-node');
const plugin = require('nemo-relay-node/plugin');

const manifest = process.argv[2];
const activation = await plugin.initializeWithDynamicPlugins(
  { version: 1, components: [] },
  [{ pluginId: '__PLUGIN_ID__', kind: 'rust_dynamic', manifestRef: manifest, config: {} }],
);
const result = await lib.toolCallExecute(
  '__PLUGIN_TOOL__',
  { input: true },
  (args) => ({ result: { args } }),
  null,
  null,
  null,
  null,
);
// The plugin's kind is registered where its library is, which is the host
// process. A local registry holding it would mean the runtime had loaded the
// plugin itself, which is the thing that must not happen.
const localKinds = lib.listPluginKinds();
const hostPid = activation.hostPid;
await activation.close();
console.log(JSON.stringify({
  result: result.result,
  local_kinds: localKinds,
  host_pid: hostPid,
  pid: process.pid,
}));
"""


def write_manifest(directory: Path, library: Path, version: str) -> Path:
    """Write a manifest describing the fixture library."""
    digest = hashlib.sha256(library.read_bytes()).hexdigest()
    manifest = directory / "relay-plugin.toml"
    manifest.write_text(
        "\n".join(
            [
                "manifest_version = 1",
                "",
                "[plugin]",
                f'id = "{PLUGIN_ID}"',
                'kind = "rust_dynamic"',
                "",
                "[compat]",
                f'relay = "={version}"',
                'native_api = "1"',
                "",
                "[defaults]",
                "enabled = false",
                "",
                "[capabilities]",
                'items = ["plugin_native"]',
                "",
                "[integrity]",
                f'sha256 = "sha256:{digest}"',
                "",
                "[load]",
                f"library = {json.dumps(library.as_posix())}",
                f'symbol = "{PLUGIN_SYMBOL}"',
                "",
            ]
        )
    )
    return manifest


def checkout_version() -> str:
    """Return the workspace version the artifact under test was built from.

    Read from the checkout rather than from the installed package because the
    manifest's compatibility requirement is the *core* crate's spelling, and the
    artifact is one this checkout produced.
    """
    manifest = Path(__file__).resolve().parent.parent / "Cargo.toml"
    for line in manifest.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("version = ") and "workspace" not in stripped:
            return stripped.split('"')[1]
    raise SystemExit(f"could not read the workspace version from {manifest}")


def remove_carried_host(project: Path) -> None:
    """Remove the host an installed platform package carries.

    This is the fault the refusal half exists for: a packager that ships the addon
    without the executable beside it. Removing it from an install that had one
    asks the question against the real layout rather than against a hand-built
    directory that resembles one.
    """
    removed = []
    for candidate in sorted((project / "node_modules").glob("*/bin/*")):
        if candidate.name in HOST_EXECUTABLES:
            candidate.unlink()
            removed.append(candidate)
    if not removed:
        raise SystemExit("the installed package carried no host to remove")


def main() -> int:
    """Run one expected outcome against an installed Node.js package."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", default=None, help="the node executable to run the check with")
    parser.add_argument("--metapackage", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument(
        "--host",
        type=Path,
        default=None,
        help="a host to point the runtime at; omit to check what the package resolves itself",
    )
    parser.add_argument(
        "--expect",
        choices=("runs", "refused"),
        required=True,
        help="what the installed artifact is expected to do",
    )
    args = parser.parse_args()

    node = args.node or shutil.which("node")
    if node is None:
        raise SystemExit("node is not on PATH, and an installed Node package cannot be run without it")
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("npm is not on PATH, and an npm package cannot be installed without it")
    for artifact in (args.metapackage, args.native):
        if not artifact.is_file():
            raise SystemExit(f"npm package does not exist: {artifact}")
    if not args.fixture.is_file():
        raise SystemExit(f"plugin fixture does not exist: {args.fixture}")
    if args.host is not None and not args.host.is_file():
        raise SystemExit(f"plugin host does not exist: {args.host}")

    env = {name: value for name, value in os.environ.items() if not name.startswith("NEMO_RELAY_PLUGIN_HOST")}
    if args.host is not None:
        env["NEMO_RELAY_PLUGIN_HOST"] = str(args.host)

    with tempfile.TemporaryDirectory() as temporary:
        project = Path(temporary)
        (project / "package.json").write_text(
            json.dumps({"name": "verify-installed-node-plugin", "private": True, "type": "module"}) + "\n"
        )
        installed = subprocess.run(  # noqa: S603
            [
                npm,
                "install",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                str(args.native),
                str(args.metapackage),
            ],
            capture_output=True,
            check=False,
            text=True,
            cwd=project,
            env=env,
        )
        if installed.returncode != 0:
            raise SystemExit(
                f"installing {args.native.name} and {args.metapackage.name} failed:\n"
                + installed.stdout
                + installed.stderr
            )
        if args.expect == "refused":
            remove_carried_host(project)
        manifest = write_manifest(project, args.fixture, checkout_version())
        runner = project / "qualify.mjs"
        runner.write_text(RUNNER.replace("__PLUGIN_ID__", PLUGIN_ID).replace("__PLUGIN_TOOL__", PLUGIN_TOOL))
        completed = subprocess.run(  # noqa: S603
            [node, str(runner), str(manifest)],
            capture_output=True,
            check=False,
            text=True,
            cwd=project,
            env=env,
        )

    output = completed.stdout + completed.stderr
    if args.expect == "refused":
        if completed.returncode == 0:
            raise SystemExit("an installation without a host ran a native plugin anyway:\n" + output)
        # The refusal has to be the actionable one: a deployment that cannot host
        # a plugin is told where the host was expected, not merely that something
        # failed.
        for expected in ("nemo-plugin-host", "initializeWithDynamicPlugins"):
            if expected not in output:
                raise SystemExit(f"the refusal does not mention {expected!r}:\n" + output)
        print("an installation without a host refused the plugin and said where it looked")
        return 0

    if completed.returncode != 0:
        raise SystemExit("the installed runtime could not run the plugin:\n" + output)
    report = json.loads(completed.stdout.strip().splitlines()[-1])
    # The fixture's tool-request intercept marks what it was shown, so its marker
    # appearing anywhere in the result is the plugin having run rather than the
    # call merely having succeeded.
    if "native_plugin" not in json.dumps(report["result"]):
        raise SystemExit(f"the plugin did not answer the call: {report}")
    if PLUGIN_ID in report["local_kinds"]:
        raise SystemExit(f"the runtime loaded the plugin into its own process: {report['local_kinds']}")
    # And where it did load is a process of its own, which is the claim the
    # registry check above can only imply.
    if report["host_pid"] is None:
        raise SystemExit(f"the activation reported no host process: {report}")
    if report["host_pid"] == report["pid"]:
        raise SystemExit(f"the plugin ran in the process that asked for it: {report}")
    print(
        "the installed runtime ran the plugin out of process "
        f"(host {report['host_pid']}, runtime {report['pid']}) and did not load it here"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
