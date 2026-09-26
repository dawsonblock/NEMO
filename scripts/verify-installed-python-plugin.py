#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prove an installed Python artifact runs a native plugin, or says why it cannot.

The distribution question this answers is not "does the package import" but "can
the thing a deployment installs do the work": a wheel carries the plugin host and
must run a native plugin out of process, and a source install carries no host and
must fail with the message that says where one was looked for rather than falling
back to loading plugin code in process.

Run against any interpreter the artifact was installed into. The plugin fixture
and the manifest are built here, so the check exercises the installed runtime
rather than anything from the checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

# What the fixture registers. The plugin's tool-request intercept answers with
# this key, which is how the runner knows the plugin ran rather than the call
# merely succeeding.
PLUGIN_ID = "fixture_native"
PLUGIN_SYMBOL = "nemo_relay_fixture_native_plugin"
PLUGIN_TOOL = "installed-python-native"

RUNNER = """
import asyncio
import json
import sys

from nemo_relay import plugin
from nemo_relay.typed import ToolExecutionResult, tools

PLUGIN_ID = "__PLUGIN_ID__"
PLUGIN_TOOL = "__PLUGIN_TOOL__"


async def main() -> int:
    manifest = sys.argv[1]
    activation = await plugin.initialize_with_dynamic_plugins(
        {},
        [{"plugin_id": PLUGIN_ID, "kind": "rust_dynamic", "manifest_ref": manifest, "config": {}}],
    )
    result = await tools.execute(
        PLUGIN_TOOL,
        {"input": True},
        lambda args: ToolExecutionResult({"args": args}),
    )
    # The plugin's kind is registered where its library is, which is the host
    # process. A local registry holding it would mean the runtime had loaded the
    # plugin itself, which is the thing that must not happen.
    local_kinds = plugin.list_kinds()
    await activation.close()
    print(json.dumps({"result": result.result, "local_kinds": local_kinds}))
    return 0


raise SystemExit(asyncio.run(main()))
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


def main() -> int:
    """Run one expected outcome against an installed interpreter."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument(
        "--host",
        type=Path,
        default=None,
        help="the host to point the runtime at; omit to expect the refusal",
    )
    parser.add_argument(
        "--expect",
        choices=("runs", "refused"),
        required=True,
        help="what the installed artifact is expected to do",
    )
    args = parser.parse_args()

    if not args.fixture.is_file():
        raise SystemExit(f"plugin fixture does not exist: {args.fixture}")
    if args.host is not None and not args.host.is_file():
        raise SystemExit(f"plugin host does not exist: {args.host}")

    with tempfile.TemporaryDirectory() as temporary:
        workspace = Path(temporary)
        manifest = write_manifest(workspace, args.fixture, checkout_version())
        runner = workspace / "runner.py"
        runner.write_text(RUNNER.replace("__PLUGIN_ID__", PLUGIN_ID).replace("__PLUGIN_TOOL__", PLUGIN_TOOL))
        env = dict(os.environ)
        env.pop("NEMO_RELAY_PLUGIN_HOST", None)
        if args.host is not None:
            env["NEMO_RELAY_PLUGIN_HOST"] = str(args.host)
        completed = subprocess.run(
            [str(args.python), str(runner), str(manifest)],
            capture_output=True,
            check=False,
            text=True,
            env=env,
        )

    output = completed.stdout + completed.stderr
    if args.expect == "refused":
        if completed.returncode == 0:
            raise SystemExit("an installation without a host ran a native plugin anyway:\n" + output)
        # The refusal has to be the actionable one: a deployment that cannot host
        # a plugin is told where the host was expected, not merely that something
        # failed.
        for expected in ("native plugin load failed", "NEMO_RELAY_PLUGIN_HOST"):
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
    print("the installed runtime ran the plugin out of process and did not load it here")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
