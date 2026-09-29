# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for packaging the plugin host as a macOS application bundle."""

import importlib.util
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "package_plugin_host_app", ROOT / "scripts" / "package-plugin-host-app.py"
)
assert SPEC is not None and SPEC.loader is not None
PACKAGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PACKAGE
SPEC.loader.exec_module(PACKAGE)


def host_binary(directory: Path) -> Path:
    """Write a stand-in for the built host and return its path."""
    host = directory / "nemo-plugin-host"
    host.write_bytes(b"the-host")
    return host


class PackagePluginHostAppTests(unittest.TestCase):
    def test_the_bundle_has_the_layout_macos_reads_entitlements_from(self) -> None:
        # The layout is the requirement rather than a preference: the executable
        # has to be at Contents/MacOS/<CFBundleExecutable>, because that is the
        # file the signature covers and the path the resolver looks for.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            host = host_binary(directory)

            bundle = PACKAGE.write_bundle(host, directory, version="0.9.1")

            self.assertEqual(bundle.name, "nemo-plugin-host.app")
            executable = bundle / "Contents" / "MacOS" / "nemo-plugin-host"
            self.assertTrue(executable.is_file())
            self.assertEqual(executable.read_bytes(), b"the-host")
            self.assertTrue(stat.S_IMODE(executable.stat().st_mode) & stat.S_IXUSR)
            with (bundle / "Contents" / "Info.plist").open("rb") as handle:
                info = plistlib.load(handle)
            self.assertEqual(info["CFBundleExecutable"], "nemo-plugin-host")
            self.assertEqual(info["CFBundleIdentifier"], PACKAGE.BUNDLE_IDENTIFIER)
            self.assertEqual(info["CFBundleShortVersionString"], "0.9.1")

    def test_a_rebuilt_bundle_replaces_the_previous_one(self) -> None:
        # Packaging runs over a directory that a previous build already filled. A
        # stale file left inside the new bundle would be covered by the new
        # signature while coming from the old build.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            host = host_binary(directory)
            first = PACKAGE.write_bundle(host, directory, version="0.9.0")
            stale = first / "Contents" / "MacOS" / "left-behind"
            stale.write_bytes(b"from the previous build")

            second = PACKAGE.write_bundle(host, directory, version="0.9.1")

            self.assertEqual(second, first)
            self.assertFalse(stale.exists(), "the bundle is built rather than patched")

    def test_signing_names_the_entitlements_and_the_identifier(self) -> None:
        # The entitlement is what the sandbox is read from, so the command that
        # installs it is worth pinning: signing without it produces a bundle that
        # runs unconfined while looking exactly like one that does not.
        commands: list[list[str]] = []

        def run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
            commands.append(list(command))
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            host = host_binary(directory)
            bundle = PACKAGE.write_bundle(host, directory, version="0.9.1")
            entitlements = PACKAGE.entitlements_for("restricted")

            PACKAGE.sign_bundle(bundle, entitlements, run=run)

            self.assertEqual(len(commands), 1)
            command = commands[0]
            self.assertEqual(command[0], "codesign")
            self.assertEqual(command[command.index("--sign") + 1], "-")
            self.assertEqual(command[command.index("--entitlements") + 1], str(entitlements))
            self.assertEqual(command[command.index("--identifier") + 1], PACKAGE.BUNDLE_IDENTIFIER)
            self.assertEqual(command[-1], str(bundle))

    def test_a_failed_signature_is_reported_rather_than_ignored(self) -> None:
        def run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess(command, 1, b"", b"codesign said no")

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            bundle = PACKAGE.write_bundle(host_binary(directory), directory, version="0.9.1")

            with self.assertRaises(ValueError) as raised:
                PACKAGE.sign_bundle(bundle, PACKAGE.entitlements_for("restricted"), run=run)

            self.assertIn("codesign said no", str(raised.exception))

    def test_the_weakening_variant_is_not_the_default(self) -> None:
        # Library validation is one of Apple's layers. A build that dropped it
        # without being asked would widen every confined host, so the strict file
        # is the default and the weak one has to be named.
        self.assertEqual(PACKAGE.DEFAULT_VARIANT, "restricted")
        strict = plistlib.loads(PACKAGE.entitlements_for("restricted").read_bytes())
        weak = plistlib.loads(PACKAGE.entitlements_for("third-party").read_bytes())

        self.assertEqual(strict, {"com.apple.security.app-sandbox": True})
        self.assertEqual(
            set(weak),
            {"com.apple.security.app-sandbox", "com.apple.security.cs.disable-library-validation"},
        )

    def test_an_unknown_variant_is_refused(self) -> None:
        with self.assertRaises(ValueError) as raised:
            PACKAGE.entitlements_for("whatever-is-convenient")

        self.assertIn("known variants", str(raised.exception))

    def test_a_missing_host_binary_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)

            with self.assertRaises(ValueError) as raised:
                PACKAGE.write_bundle(directory / "nothing-here", directory, version="0.9.1")

            self.assertIn("does not exist", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
