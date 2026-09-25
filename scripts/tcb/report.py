#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Report and enforce the trusted computing base (TCB) budget.

The TCB is the set of crates whose failure could directly violate NEMO's core
security and correctness guarantees. Repository size is not the constraint that
matters; the reachable surface of those crates is. This script measures the
trusted crates declared in ``security/tcb.toml`` and enforces two things:

* ``[forbidden]`` lists packages that must never appear anywhere in a trusted
  crate's resolved dependency tree, so an implementation cannot leak into a
  boundary that is supposed to depend only on interfaces.
* ``[limits]`` are ratchet budgets. Exceeding one fails the gate, so growing the
  trusted surface has to be an explicit, reviewable edit to the policy file
  rather than an invisible side effect of an unrelated change.

Dependencies are measured with ``cargo tree`` against ``--all-features``, so a
package cannot hide behind a feature flag. ``cargo metadata`` alone is not
enough: it resolves optional dependencies whether or not a build activates
them, which reports coupling that no build actually links.

Two resolution properties are pinned rather than only counted. The transitive
metric counts *resolved identities* (name and version), so two versions of one
package are two entries instead of collapsing to one name. Each crate's direct
and transitive dependency sets are also hashed and compared against the
recorded digest, and those digests cover the resolved identities too, so neither
replacing a dependency nor changing its version can pass by keeping the count
the same. The size budgets stay ceilings, and the policy file says so.

Source metrics cover every file under a crate's ``src`` directory, including
inline test modules, and count every textual ``unsafe`` token without trying to
strip comments. A regular expression cannot tell a comment from a `//` inside a
string literal, so stripping can only ever hide a token; overcounting is the
correct direction for an upper bound.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_POLICY = REPO_ROOT / "security" / "tcb.toml"

UNSAFE = re.compile(r"\bunsafe\b")

# Budget keys mapped to the measurement they cap.
LIMIT_FIELDS = {
    "max_direct_dependencies": "direct_dependencies",
    "max_transitive_packages": "transitive_packages",
    "max_source_lines": "source_lines",
    "max_unsafe_occurrences": "unsafe_occurrences",
}

# Recorded digests, mapped to the measurement they pin.
DIGEST_FIELDS = {
    "direct_dependency_digest": "direct_dependency_digest",
    "transitive_dependency_digest": "transitive_dependency_digest",
}


@dataclass(frozen=True)
class Metrics:
    """Measurements for one trusted crate."""

    crate: str
    source_files: int
    source_lines: int
    unsafe_occurrences: int
    direct_dependencies: int
    transitive_packages: int
    direct_dependency_digest: str
    transitive_dependency_digest: str


def load_policy(path: pathlib.Path) -> dict:
    """Read the TCB policy file."""
    with pathlib.Path(path).open("rb") as handle:
        return tomllib.load(handle)


def cargo_metadata(repo_root: pathlib.Path) -> dict:
    """Return resolved Cargo metadata for the workspace.

    ``--locked`` is deliberate: a report that silently rewrote the lockfile
    would measure something other than what the repository records.
    """
    completed = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def package_index(metadata: dict) -> tuple[dict, dict]:
    """Return ``(by_id, by_name)`` indexes over the resolved packages."""
    by_id = {package["id"]: package for package in metadata["packages"]}
    by_name = {package["name"]: package for package in metadata["packages"]}
    return by_id, by_name


def dependency_identities(repo_root: pathlib.Path, crate: str) -> list[str]:
    """Return resolved ``name@version`` identities for the crate's widest build.

    Counting names instead would collapse two resolved versions of one package
    into a single entry, so a graph could gain a duplicate version without the
    metric moving.
    """
    completed = subprocess.run(
        [
            "cargo",
            "tree",
            "-p",
            crate,
            "--all-features",
            "--locked",
            "--prefix",
            "none",
        ],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    identities = set()
    for line in completed.stdout.splitlines():
        fields = line.split()
        if not fields or fields[0] == crate:
            continue
        version = fields[1] if len(fields) > 1 else ""
        identities.add(f"{fields[0]}@{version}" if version else fields[0])
    return sorted(identities)


def identity_names(identities: list[str]) -> set[str]:
    """Return the package names behind a list of ``name@version`` identities."""
    return {identity.split("@", 1)[0] for identity in identities}


def dependency_digest(names: set[str]) -> str:
    """Return a stable digest over a dependency set."""
    return hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest()


def direct_dependency_names(metadata: dict, identities: list[str], crate: str) -> list[str]:
    """Return the crate's declared direct dependencies that a build links."""
    _, by_name = package_index(metadata)
    declared = {
        dependency["name"] for dependency in by_name[crate].get("dependencies", []) if dependency.get("kind") is None
    }
    return sorted(declared.intersection(identity_names(identities)))


def source_metrics(crate_dir: pathlib.Path) -> tuple[int, int, int]:
    """Return ``(files, lines, unsafe_occurrences)`` for the crate's sources."""
    files = sorted(pathlib.Path(crate_dir).rglob("*.rs"))
    lines = 0
    unsafe_occurrences = 0
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines += text.count("\n")
        unsafe_occurrences += len(UNSAFE.findall(text))
    return len(files), lines, unsafe_occurrences


def measure(metadata: dict, identities: list[str], crate: str) -> Metrics:
    """Measure one crate against the resolved metadata."""
    _, by_name = package_index(metadata)
    crate_dir = pathlib.Path(by_name[crate]["manifest_path"]).parent / "src"
    source_files, source_lines, unsafe_occurrences = source_metrics(crate_dir)
    direct = direct_dependency_names(metadata, identities, crate)
    direct_names = set(direct)
    # Pin the resolved identities, not just the package names. Hashing names
    # alone would let a dependency change version without moving either the
    # count or the digest, which is the whole point of pinning the set.
    direct_identities = {identity for identity in identities if identity.split("@", 1)[0] in direct_names}
    return Metrics(
        crate=crate,
        source_files=source_files,
        source_lines=source_lines,
        unsafe_occurrences=unsafe_occurrences,
        direct_dependencies=len(direct),
        transitive_packages=len(identities),
        direct_dependency_digest=dependency_digest(direct_identities),
        transitive_dependency_digest=dependency_digest(set(identities)),
    )


def enforcement_crates(policy: dict) -> list[str]:
    """Return the crates whose failure could violate a kernel invariant."""
    trusted = policy.get("trusted", {}).get("crates", [])
    return sorted(trusted)


def in_process_crates(policy: dict) -> list[str]:
    """Return every crate linked into the same process as the kernel.

    A memory-safety bug in an in-process component can subvert an invariant
    that the component does not itself enforce, so the effective surface is
    wider than the set of crates that name an invariant.
    """
    members = set(enforcement_crates(policy))
    members.update(policy.get("in_process", {}).get("crates", []))
    return sorted(members)


def plugin_host_crates(policy: dict) -> list[str]:
    """Return the crates that host native plugins.

    A separate tier rather than part of the in-process one: once the loader
    moves, this code is the attack surface the kernel is protected *from*, and
    its `unsafe` count should be reported without either hiding it or counting
    it against the kernel.
    """
    return sorted(policy.get("plugin_host", {}).get("crates", []))


def find_violations(metadata: dict, identities: dict[str, list[str]], policy: dict) -> tuple[list[Metrics], list[str]]:
    """Return the per-crate report and every policy violation."""
    reports: list[Metrics] = []
    problems: list[str] = []

    for crate, forbidden in sorted(policy.get("forbidden", {}).items()):
        hits = sorted(identity_names(identities[crate]).intersection(forbidden))
        if hits:
            problems.append(f"{crate} reaches forbidden package(s): {', '.join(hits)}")

    for crate, limits in sorted(policy.get("limits", {}).items()):
        metrics = measure(metadata, identities[crate], crate)
        reports.append(metrics)
        for field, attribute in LIMIT_FIELDS.items():
            if field not in limits:
                continue
            actual = getattr(metrics, attribute)
            budget = limits[field]
            if actual > budget:
                problems.append(
                    f"{crate}: {attribute} is {actual}, budget is {budget}; "
                    "raising the budget is a security review recorded in "
                    "security/tcb.toml"
                )
        for field, attribute in DIGEST_FIELDS.items():
            if field not in limits:
                continue
            if getattr(metrics, attribute) != limits[field]:
                problems.append(
                    f"{crate}: {attribute} changed; the resolved dependency set "
                    "is not the recorded one. Review the change and update the "
                    "digest in security/tcb.toml"
                )

    return reports, problems


def find_temporary_problems(policy: dict, reports: list[Metrics]) -> list[str]:
    """Check the temporary ceilings: every one has to promise a decrease, and keep it.

    A budget that only moves upward is a counter, not a ratchet. These entries are the
    raises a migration needed and the milestones that have to give them back: each names a
    ceiling, the milestone that removes it and the value it must fall to. Three rules make
    that enforceable rather than aspirational.

    - The promise is a *decrease*: a target at or above the raised ceiling is refused, so
      an entry cannot exist without saying what it gives back.
    - The entry describes the *current* ceiling: if the budget moved on, the entry is
      stale and fails rather than quietly describing a ceiling nobody has.
    - The entry is retired by satisfying it: once the measurement reaches the target, the
      entry and the budget it raised have to go together, which is what stops a temporary
      ceiling from becoming a permanent one.
    """
    problems: list[str] = []
    measured = {
        (report.crate, field): getattr(report, attribute)
        for report in reports
        for field, attribute in LIMIT_FIELDS.items()
    }
    required = ("crate", "field", "raised_to", "reason", "introduced", "must_fall_by", "target")
    for index, entry in enumerate(policy.get("temporary", [])):
        # Present and empty is missing: a milestone nobody named and a reason nobody
        # wrote promise nothing, and a key that exists is not a statement.
        missing = [name for name in required if not entry.get(name)]
        if missing:
            problems.append(
                f"temporary ceiling #{index} is missing {', '.join(missing)}; a raise that "
                "is meant to come back down has to say what takes it back"
            )
            continue
        crate = entry["crate"]
        field = entry["field"]
        if field not in LIMIT_FIELDS:
            problems.append(f"temporary ceiling #{index} names an unknown budget {field}")
            continue
        limits = policy.get("limits", {}).get(crate, {})
        if limits.get(field) != entry["raised_to"]:
            problems.append(
                f"{crate}.{field} is recorded as a temporary ceiling of "
                f"{entry['raised_to']}, and the budget is {limits.get(field)}; the entry "
                "describes a ceiling this policy does not have"
            )
            continue
        if entry["target"] >= entry["raised_to"]:
            problems.append(
                f"{crate}.{field}: a temporary ceiling must promise a decrease from "
                f"{entry['raised_to']} to its target {entry['target']}"
            )
            continue
        actual = measured.get((crate, field))
        if actual is not None and actual <= entry["target"]:
            problems.append(
                f"{crate}.{field} has already fallen to {actual}, at or below the target "
                f"{entry['target']} of the temporary ceiling introduced for "
                f"{entry['must_fall_by']}; lower the budget, delete the entry, and let the "
                "ratchet close"
            )
    return problems


def render_temporary(policy: dict) -> str:
    """Render the outstanding temporary ceilings, so every run shows what is owed."""
    entries = policy.get("temporary", [])
    if not entries:
        return "temporary ceilings: none"
    lines = ["temporary ceilings (raise -> target, removed by):"]
    for entry in entries:
        lines.append(
            f"  {entry.get('crate')}.{entry.get('field')}: "
            f"{entry.get('raised_to')} -> {entry.get('target')} "
            f"by {entry.get('must_fall_by')} (introduced {entry.get('introduced')})"
        )
    return "\n".join(lines)


def render(reports: list[Metrics]) -> str:
    """Render the report table."""
    header = f"{'crate':<22}{'files':>7}{'lines':>9}{'unsafe':>8}{'direct':>8}{'transitive':>12}"
    rows = [header, "-" * len(header)]
    for metrics in reports:
        rows.append(
            f"{metrics.crate:<22}{metrics.source_files:>7}"
            f"{metrics.source_lines:>9}{metrics.unsafe_occurrences:>8}"
            f"{metrics.direct_dependencies:>8}{metrics.transitive_packages:>12}"
        )
    return "\n".join(rows)


def render_surface(metadata: dict, identities: dict[str, list[str]], policy: dict) -> str:
    """Render the two-tier surface: invariant enforcers, then everything in-process."""
    rows = [
        "surface",
        "",
        f"  {'tier':<26}{'crates':>7}{'lines':>10}{'unsafe':>9}",
    ]
    kernel_process_unsafe = 0
    for label, crates in (
        ("invariant-enforcing", enforcement_crates(policy)),
        ("in-process", in_process_crates(policy)),
        # A target classification rather than a current one: until the loader
        # physically crosses a process boundary its crate is also part of the
        # in-process tier above.
        ("plugin host (target)", plugin_host_crates(policy)),
    ):
        measured = [measure(metadata, identities[crate], crate) for crate in crates]
        total_lines = sum(item.source_lines for item in measured)
        total_unsafe = sum(item.unsafe_occurrences for item in measured)
        if label == "in-process":
            kernel_process_unsafe = total_unsafe
        rows.append(f"  {label:<26}{len(crates):>7}{total_lines:>10}{total_unsafe:>9}")
    # The milestone that moves native plugin loading across a process boundary is
    # measured by this number rather than by the total over the logical core
    # crates. The question is what can corrupt the kernel, and a loader in a
    # different crate inside the same process still can.
    rows.extend(["", f"  kernel-process unsafe tokens: {kernel_process_unsafe}"])
    return "\n".join(rows)


def measured_kernel_unsafe(surface: str) -> int | None:
    """Return the kernel-process unsafe figure from a rendered surface table."""
    for line in surface.splitlines():
        prefix = "kernel-process unsafe tokens:"
        if prefix in line:
            return int(line.split(prefix, 1)[1].strip())
    return None


def documented_kernel_unsafe(repo_root: pathlib.Path) -> int | None:
    """Return the figure quoted by the milestone document, if it quotes one."""
    document = pathlib.Path(repo_root) / "security" / "PLUGIN-ISOLATION.md"
    if not document.exists():
        return None
    for line in document.read_text(encoding="utf-8").splitlines():
        prefix = "kernel-process unsafe tokens:"
        if prefix in line:
            figure = line.split(prefix, 1)[1].strip().strip("`").strip()
            try:
                return int(figure)
            except ValueError:
                return None
    return None


def main(argv: list[str] | None = None) -> int:
    """Run the TCB gate."""
    parser = argparse.ArgumentParser(description="Report and enforce the trusted computing base budget.")
    parser.add_argument(
        "--policy",
        type=pathlib.Path,
        default=DEFAULT_POLICY,
        help="TCB policy file (default: security/tcb.toml)",
    )
    parser.add_argument(
        "--metadata",
        type=pathlib.Path,
        help="read resolved Cargo metadata from this file instead of running cargo",
    )
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=REPO_ROOT,
        help="workspace root used when invoking cargo",
    )
    arguments = parser.parse_args(argv)

    if arguments.metadata:
        metadata = json.loads(arguments.metadata.read_text(encoding="utf-8"))
    else:
        metadata = cargo_metadata(arguments.repo_root)

    policy = load_policy(arguments.policy)
    crates = sorted(
        set(policy.get("limits", {}))
        | set(policy.get("forbidden", {}))
        | set(enforcement_crates(policy))
        | set(in_process_crates(policy))
        | set(plugin_host_crates(policy))
    )
    identities = {crate: dependency_identities(arguments.repo_root, crate) for crate in crates}
    reports, problems = find_violations(metadata, identities, policy)
    problems.extend(find_temporary_problems(policy, reports))

    print(render(reports))
    print()
    surface = render_surface(metadata, identities, policy)
    print(surface)
    print()
    print(render_temporary(policy))
    if problems:
        print(file=sys.stderr)
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    # The document that describes the milestone quotes this number, and a quoted
    # number that is maintained by hand drifts: a revision said 617 in one
    # paragraph and 621 in another. The figure is checked here instead, so the
    # prose cannot disagree with the measurement.
    documented = documented_kernel_unsafe(arguments.repo_root)
    measured = measured_kernel_unsafe(surface)
    if documented is not None and measured is not None and documented != measured:
        print(
            f"error: security/PLUGIN-ISOLATION.md says kernel-process unsafe tokens: "
            f"{documented}, and the measurement says {measured}",
            file=sys.stderr,
        )
        return 1
    print("\nTCB budgets satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
