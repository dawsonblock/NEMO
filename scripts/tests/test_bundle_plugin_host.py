# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for bundling the plugin host into a built wheel."""

import base64
import hashlib
import importlib.util
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("bundle_plugin_host", ROOT / "scripts" / "bundle-plugin-host.py")
assert SPEC is not None and SPEC.loader is not None
BUNDLE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUNDLE
SPEC.loader.exec_module(BUNDLE)


def write_wheel(directory: Path, name: str, *, with_dist_info: bool = True) -> Path:
    """Write a minimal wheel to patch."""
    wheel = directory / name
    dist_info = "nemo_relay-0.9.1rc4.dist-info"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("nemo_relay/__init__.py", b'"""A package."""\n')
        if with_dist_info:
            archive.writestr(f"{dist_info}/METADATA", b"Metadata-Version: 2.4\nName: nemo-relay\n")
            archive.writestr(f"{dist_info}/WHEEL", b"Wheel-Version: 1.0\n")
            archive.writestr(f"{dist_info}/RECORD", b"nemo_relay/__init__.py,,\n")
    return wheel


class BundlePluginHostTests(unittest.TestCase):
    def test_adds_the_host_to_the_install_scripts_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wheel = write_wheel(directory, "nemo_relay-0.9.1rc4-cp311-cp311-macosx_11_0_arm64.whl")
            host = directory / "nemo-plugin-host"
            host.write_bytes(b"the-host")

            BUNDLE.add_host_to_wheel(wheel, host)

            with zipfile.ZipFile(wheel) as archive:
                target = "nemo_relay-0.9.1rc4.data/scripts/nemo-plugin-host"
                self.assertIn(target, archive.namelist())
                info = archive.getinfo(target)
                mode = info.external_attr >> 16
                self.assertTrue(stat.S_ISREG(mode))
                self.assertEqual(stat.S_IMODE(mode), 0o755)
                self.assertEqual(archive.read(target), b"the-host")
                # Everything the build produced is still there, byte for byte:
                # the patch adds a file rather than rebuilding the wheel.
                self.assertEqual(archive.read("nemo_relay/__init__.py"), b'"""A package."""\n')
                record = archive.read("nemo_relay-0.9.1rc4.dist-info/RECORD").decode()

            digest = base64.urlsafe_b64encode(hashlib.sha256(b"the-host").digest()).rstrip(b"=")
            self.assertIn(f"{target},sha256={digest.decode()},8", record)
            # The RECORD describes itself last and with no digest, which is what
            # makes it the one line that cannot be checked against its content.
            self.assertTrue(record.rstrip().endswith("nemo_relay-0.9.1rc4.dist-info/RECORD,,"))
            self.assertEqual([line for line in record.splitlines() if "RECORD" in line].__len__(), 1)

    def test_names_the_windows_spelling_for_a_windows_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wheel = write_wheel(directory, "nemo_relay-0.9.1rc4-cp311-cp311-win_amd64.whl")
            host = directory / "nemo-plugin-host.exe"
            host.write_bytes(b"the-host")

            BUNDLE.add_host_to_wheel(wheel, host)

            with zipfile.ZipFile(wheel) as archive:
                self.assertIn(
                    "nemo_relay-0.9.1rc4.data/scripts/nemo-plugin-host.exe",
                    archive.namelist(),
                )

    def test_refuses_a_wheel_that_already_carries_a_host(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wheel = write_wheel(directory, "nemo_relay-0.9.1rc4-cp311-cp311-manylinux_2_17_x86_64.whl")
            host = directory / "nemo-plugin-host"
            host.write_bytes(b"the-host")

            BUNDLE.add_host_to_wheel(wheel, host)

            with self.assertRaisesRegex(ValueError, "already carries"):
                BUNDLE.add_host_to_wheel(wheel, host)

    def test_refuses_something_that_is_not_a_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wheel = write_wheel(directory, "nemo_relay-0.9.1rc4-py3-none-any.whl", with_dist_info=False)
            host = directory / "nemo-plugin-host"
            host.write_bytes(b"the-host")

            with self.assertRaisesRegex(ValueError, "dist-info"):
                BUNDLE.add_host_to_wheel(wheel, host)

    def test_refuses_a_missing_host_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wheel = write_wheel(directory, "nemo_relay-0.9.1rc4-py3-none-any.whl")

            with self.assertRaisesRegex(ValueError, "does not exist"):
                BUNDLE.add_host_to_wheel(wheel, directory / "absent")

    def test_reads_the_platform_from_the_wheel_name(self) -> None:
        self.assertEqual(
            BUNDLE.host_executable_for_wheel("nemo_relay-0.9.1rc4-cp311-cp311-win_arm64.whl"),
            "nemo-plugin-host.exe",
        )
        self.assertEqual(
            BUNDLE.host_executable_for_wheel("nemo_relay-0.9.1rc4-cp311-cp311-musllinux_1_2_aarch64.whl"),
            "nemo-plugin-host",
        )
        with self.assertRaisesRegex(ValueError, "platform tag"):
            BUNDLE.host_executable_for_wheel("nemo-relay.whl")


if __name__ == "__main__":
    unittest.main()
