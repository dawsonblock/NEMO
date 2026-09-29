# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the verdict the macOS sandbox lane reaches."""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "macos_sandbox_probe", ROOT / "scripts" / "qualification" / "macos_sandbox_probe.py"
)
assert SPEC is not None and SPEC.loader is not None
LANE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LANE
SPEC.loader.exec_module(LANE)

#: What a confined run looks like, errnos and all: `/tmp` and the account's home
#: are refused, the container is not. The errnos differ by operation because the
#: sandbox refuses by hiding a path as well as by denying a syscall, which is why
#: the comparison is on the outcome rather than on the number.
CONFINED = """\
PROBE home_set=set
PROBE write_container=allowed
PROBE create_app_support=allowed
PROBE write_app_support=allowed
PROBE write_tmp=denied:1
PROBE read_real_home=denied:2
PROBE write_real_home=denied:1
PROBE connect_outbound=denied:1
PROBE dlopen_external=denied
"""


class MacOSSandboxProbeTests(unittest.TestCase):
    def test_a_confined_run_has_no_problems(self) -> None:
        self.assertEqual(LANE.problems(LANE.parse_probe(CONFINED)), [])

    def test_an_outcome_is_compared_before_its_errno(self) -> None:
        # `denied`, `denied:1` and `denied:2` are one outcome: the operation was
        # refused. Which errno a refusal carries is the sandbox's business.
        self.assertEqual(LANE.outcome_kind("denied"), "denied")
        self.assertEqual(LANE.outcome_kind("denied:13"), "denied")
        self.assertEqual(LANE.outcome_kind("allowed:64"), "allowed")

    def test_a_writable_tmp_is_a_failure(self) -> None:
        # The failure this lane exists for. A host that can write shared temporary
        # storage is not confined, and reporting that as a pass because the bundle
        # carried the entitlement and started would be the whole mistake.
        observed = LANE.parse_probe(CONFINED.replace("write_tmp=denied:1", "write_tmp=allowed"))
        problems = LANE.problems(observed)
        self.assertEqual(len(problems), 1)
        self.assertIn("write_tmp", problems[0])
        self.assertIn("'allowed'", problems[0])

    def test_an_unreported_operation_is_a_failure(self) -> None:
        # A probe that never reached the operation cannot have shown the operation
        # was refused, so a missing line is not a pass.
        observed = LANE.parse_probe(CONFINED.replace("PROBE dlopen_external=denied\n", ""))
        problems = LANE.problems(observed)
        self.assertEqual(len(problems), 1)
        self.assertIn("never reported", problems[0])

    def test_a_host_that_cannot_stage_is_a_failure(self) -> None:
        # The other direction: confinement that also blocks what the host is for is
        # not a stronger boundary, it is a broken host.
        observed = LANE.parse_probe(CONFINED.replace("create_app_support=allowed", "create_app_support=denied:1"))
        problems = LANE.problems(observed)
        self.assertEqual(len(problems), 1)
        self.assertIn("create_app_support", problems[0])

    def test_lines_that_are_not_probe_lines_are_ignored(self) -> None:
        observed = LANE.parse_probe("noise\n" + CONFINED + "more noise\n")
        self.assertEqual(len(observed), len(LANE.EXPECTED))
        self.assertEqual(LANE.problems(observed), [])


if __name__ == "__main__":
    unittest.main()
