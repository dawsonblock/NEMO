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

Every dependency measurement is also resolved for a named target rather than for
whichever machine runs the gate. ``cargo tree`` answers for the host platform
(``--target`` aside), and the platform-specific tail of a graph is real — Linux and
macOS resolve different TLS, entropy and certificate-store crates, and a
build-dependency is resolved for the machine that builds — so a baseline recorded on
one host and enforced on another disagrees with itself. A budget that passes where it
was recorded and fails where it is enforced is not a budget, and the fix is to name
the target rather than to keep re-recording whatever the last machine saw. The two
questions this script asks name different targets, and ``BUDGET_TARGET`` and
``CLOSURE_TARGET`` say why.

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

#: The target the per-crate budgets and digests are resolved for: every one.
#:
#: A budget is a number somebody compares against, so it has to be the same number
#: wherever it is computed. Resolving for the host made it the recorder's platform
#: instead: Linux pulls `openssl-sys` where macOS pulls `security-framework`, and a
#: build-dependency is resolved for the machine doing the building, so two machines
#: disagreed about the same lockfile. ``all`` is the union over every platform cargo
#: knows, which contains the host's own resolve on any of them and therefore does not
#: depend on which one is asking. It is also the conservative direction: a package
#: that only one platform's build would resolve is still a package this crate's build
#: can resolve, and the budgets are upper bounds rather than per-artifact counts.
BUDGET_TARGET = "all"

#: The targets a closure check is resolved for when the policy names none.
#:
#: Not the union, because the closure asks a different question — what the kernel's
#: own process can reach — and the answer for a composed platform is not the union of
#: the answers for each one: under `--target all` the Node binding's `napi-sys` pulls
#: `libloading` on Windows, which is a fact about that platform's binding rather than
#: about the composition this milestone closes.
#:
#: The list is the platforms the plugin-hosting packages are built for, so one
#: target's graph cannot stand in for the others: a dependency edge that resolves
#: only on macOS or only for musl would otherwise escape a check that named one
#: platform. The host platform is not among the questions for the same reason it is
#: not among the answers — a gate whose result depends on who ran it is not a gate.
DEFAULT_CLOSURE_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
)

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
    metric moving. The set is resolved for ``BUDGET_TARGET`` rather than for the
    host, so two machines recording the same lockfile record the same numbers.
    """
    completed = subprocess.run(
        [
            "cargo",
            "tree",
            "-p",
            crate,
            "--all-features",
            "--locked",
            "--target",
            BUDGET_TARGET,
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


def kernel_closure_names(
    repo_root: pathlib.Path,
    roots: list[str],
    edges: str = "normal,build",
    target: str = DEFAULT_CLOSURE_TARGETS[0],
) -> set[str]:
    """Return every package name the kernel's own process can reach.

    The kernel's roots are asked together, so the answer is the union of what any
    of them links: a crate that only the CLI pulls in is still in the kernel's
    process when the CLI runs, and the question this answers is what that process
    can reach rather than what one library of it can.

    `edges` selects which dependency kinds count. The default is what a build
    links — normal and build dependencies — because the property being measured is
    about the *artifact*: a dev-dependency is not in the binary, and counting it
    would make the target unreachable for a reason the symbol proof already covers.
    Callers that want to know about the test tree as well pass `edges="all"` and
    report the difference rather than hiding it.

    The closure is resolved for a named ``target`` rather than for the host, so the
    answer does not depend on the machine that asked for it, and the caller decides
    which platform it is asking about.
    """
    completed = subprocess.run(
        [
            "cargo",
            "tree",
            *[f"-p{root}" for root in roots],
            "--all-features",
            "--locked",
            "--target",
            target,
            "--edges",
            edges,
            "--prefix",
            "none",
        ],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    names = set()
    for line in completed.stdout.splitlines():
        fields = line.split()
        if fields:
            names.add(fields[0])
    return names


def kernel_closure_reachability(policy: dict, reachable: set[str]) -> set[str]:
    """Return the packages the closure may not reach but still does.

    The milestone's decisive property is structural: the kernel's resolved closure
    and the things that load native code must not intersect. Today they do, because
    the loader still runs in the kernel's address space, and a gate that is red on
    arrival enforces nothing — so the intersection is *recorded*, and this returns
    what the closure reaches rather than what the policy says it should.
    """
    forbidden = set(policy.get("kernel_closure", {}).get("forbidden", []))
    return forbidden.intersection(reachable)


def closure_targets(policy: dict) -> list[str]:
    """Return every target a closure check has to be resolved for.

    The enforced targets, then whatever a platform-external record names: an
    exemption that is never measured is a comment, and this gate's whole argument is
    that a recorded fact is checked rather than remembered.
    """
    targets: list[str] = []
    for section in ("kernel_closure", "kernel_library_closure"):
        for target in (policy.get(section) or {}).get("targets", DEFAULT_CLOSURE_TARGETS):
            if target not in targets:
                targets.append(target)
    for record in platform_external_records(policy):
        target = record.get("target")
        if isinstance(target, str) and target and target not in targets:
            targets.append(target)
    return targets


def platform_external_records(policy: dict) -> list[dict]:
    """Return the recorded platform loaders, as the policy writes them."""
    records = (policy.get("kernel_closure") or {}).get("platform_external", [])
    return [record for record in records if isinstance(record, dict)]


def find_closure_problems(policy: dict, reachable_by_target: dict[str, set[str]]) -> list[str]:
    """Return a forbidden package a composition's closure gained, per target.

    A package on the recorded list is the known remaining work; one that is not is
    a dependency edge somebody added, which is the failure this check exists for. Each
    target is reported by name, because the answer is per platform: a reach that only
    one platform's graph has is still a reach, and a message that named no platform
    would leave the reader to guess which build to look at.
    """
    closure = policy.get("kernel_closure")
    if not closure:
        return []
    recorded = set(closure.get("reachable_now", []))
    found = []
    for target, reachable in sorted(reachable_by_target.items()):
        reached = kernel_closure_reachability(policy, reachable)
        found.extend(
            f"the kernel's closure reaches '{name}' on {target}, which is not one of "
            f"the loader packages the policy records as still reachable"
            for name in sorted(reached - recorded)
        )
    return found


def find_library_closure_problems(policy: dict, reachable_by_target: dict[str, set[str]]) -> list[str]:
    """Return a loader package the kernel *library* can still reach, per target.

    This is the milestone's property rather than its progress: the kernel library
    reaching a package that loads native code means the boundary is architectural
    only. It is a separate block from the composition ratchet because it is a
    different question — the library may not reach the loader at all, while the
    composition surfaces still do until the child moves out of them — and because a
    property that is allowed to grow is not a property.
    """
    library = policy.get("kernel_library_closure")
    if not library:
        return []
    found = []
    for target, reachable in sorted(reachable_by_target.items()):
        reached = kernel_closure_reachability({"kernel_closure": library}, reachable)
        found.extend(
            f"the kernel library reaches '{name}' on {target}, which loads native code; "
            f"the kernel must not link the loader at all"
            for name in sorted(reached)
        )
    return found


def find_platform_external_problems(policy: dict, reachable_by_target: dict[str, set[str]]) -> list[str]:
    """Return every recorded platform loader whose record no longer holds.

    `libloading` is two things, and which one it is depends on who reached it. It is
    this milestone's native loader when the kernel or a shipping composition reaches
    it, and it is a platform binding's own dynamic loader when the runtime the
    binding wraps pulls one in — the Windows N-API machinery does, which is why the
    union of every platform cannot be the set the composition property is stated
    over. The first is forbidden on every enforced target. The second is recorded
    here with the target it happens on, so the exemption is a named fact rather than
    an omission somebody has to notice.

    Both directions are checked. A record the tree no longer needs is refused, for
    the same reason a temporary ceiling is: an exemption nobody re-earns is one that
    hides the next reach. And the exemption covers only the packages it names, so a
    platform's own loader cannot become cover for this repository's.
    """
    closure = policy.get("kernel_closure") or {}
    enforced = set(closure.get("targets", DEFAULT_CLOSURE_TARGETS))
    found: list[str] = []
    for record in platform_external_records(policy):
        target = record.get("target")
        packages = record.get("packages")
        if not isinstance(target, str) or not isinstance(packages, list) or not packages:
            found.append("a platform-external record names no target, or no packages to exempt")
            continue
        if not str(record.get("reason", "")).strip():
            found.append(
                f"the platform exemption for '{target}' gives no reason: an exemption "
                f"without one is an omission the next reader has to reverse-engineer"
            )
        if target in enforced:
            found.append(
                f"'{target}' is both enforced and recorded as a platform exemption: the "
                f"closure either holds there or it does not, and no target may be both"
            )
            continue
        reachable = reachable_by_target.get(target)
        if reachable is None:
            found.append(f"the platform exemption for '{target}' was never measured")
            continue
        for package in packages:
            if package not in reachable:
                found.append(
                    f"the platform exemption for '{package}' on '{target}' is stale: that "
                    f"resolve no longer reaches it, so the record permits a reach that is "
                    f"not there rather than describing one that is"
                )
        uncovered = set(closure.get("forbidden", [])) - set(packages)
        for name in sorted(uncovered.intersection(reachable)):
            found.append(
                f"the kernel's closure reaches '{name}' on '{target}', which the platform "
                f"exemption for {', '.join(sorted(packages))} does not cover"
            )
    return found


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
        # Present and empty is missing: a milestone nobody named and a reason nobody wrote
        # promise nothing, and a key that exists is not a statement. Zero is not empty — a
        # target of zero is how an entry says the crate leaves the tier entirely.
        missing = [
            name
            for name in required
            if name not in entry or entry[name] is None or (isinstance(entry[name], str) and not entry[name].strip())
        ]
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


def render_surface(
    metadata: dict,
    identities: dict[str, list[str]],
    policy: dict,
    reachable: dict[str, set[str]] | None = None,
    test_only: set[str] | None = None,
    library_reached: dict[str, set[str]] | None = None,
) -> str:
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
    # And the figure that has to become zero: what the kernel can still reach that
    # loads native code. This is a dependency-graph fact rather than a line count,
    # which is why it is the one the split is judged on.
    closure = policy.get("kernel_closure")
    if closure and reachable is not None:
        # One line per target: the property is per platform, and a single line would
        # have to say which platform it was about and why the others were not asked.
        for target, names in sorted(reachable.items()):
            reached = sorted(kernel_closure_reachability(policy, names))
            rendered = ", ".join(reached) if reached else "nothing"
            rows.append(f"  kernel closure reaches ({target}): {rendered}")
        # What only the test tree reaches is a different fact, and it is reported
        # rather than folded in or left out: the artifact does not link it, and a
        # reader deciding whether the target is reachable should see both numbers.
        if test_only:
            extra = ", ".join(sorted(test_only))
            rows.append(f"  and the test tree alone reaches: {extra}")
        # The platform that is recorded rather than enforced says so here as well as
        # in the policy: a reader comparing the rows should see why there is one
        # fewer than the platforms the packages are built for.
        recorded = [
            record["target"] for record in platform_external_records(policy) if isinstance(record.get("target"), str)
        ]
        if recorded:
            rows.append(f"  platform-external loader reach recorded, not enforced, on: {', '.join(recorded)}")
    library = policy.get("kernel_library_closure")
    if library and library_reached is not None:
        for target, names in sorted(library_reached.items()):
            reached = sorted(kernel_closure_reachability({"kernel_closure": library}, names))
            rendered = ", ".join(reached) if reached else "nothing"
            rows.append(f"  kernel library reaches ({target}): {rendered}")
    return "\n".join(rows)


def measured_kernel_unsafe(surface: str) -> int | None:
    """Return the kernel-process unsafe figure from a rendered surface table."""
    for line in surface.splitlines():
        prefix = "kernel-process unsafe tokens:"
        if prefix in line:
            return int(line.split(prefix, 1)[1].strip())
    return None


def documented_kernel_unsafe(repo_root: pathlib.Path) -> tuple[int | None, list[str]]:
    """Return the figure the milestone document quotes, and every disagreement with it.

    The document is a chronological record, so prose inside it may describe numbers
    that were true when a section was written — that is history, not drift. What may
    not happen is the document carrying two *canonical* figures, because the earlier
    revision this check exists for did exactly that: one paragraph said 617 and
    another said 621, and a lookup that returns the first number it understands
    cannot see the second. So the canonical form is counted rather than sampled: the
    figure has to appear exactly once, and it has to be the measurement.
    """
    document = pathlib.Path(repo_root) / "security" / "PLUGIN-ISOLATION.md"
    if not document.exists():
        return None, []
    prefix = "kernel-process unsafe tokens:"
    quilted: list[int] = []
    for line in document.read_text(encoding="utf-8").splitlines():
        if prefix not in line:
            continue
        figure = line.split(prefix, 1)[1].strip().strip("`").strip()
        try:
            quilted.append(int(figure))
        except ValueError:
            continue
    if not quilted:
        return None, []
    problems = []
    if len(quilted) > 1:
        problems.append(
            "security/PLUGIN-ISOLATION.md states the kernel-process unsafe figure "
            f"{len(quilted)} times ({', '.join(str(value) for value in quilted)}); "
            "exactly one canonical figure may exist, because a second one is how "
            "this document drifted before"
        )
    return quilted[0], problems


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
    kernel_closure = policy.get("kernel_closure")
    reachable: dict[str, set[str]] | None = None
    test_only: set[str] = set()
    if kernel_closure:
        # Every target the check is about, including the ones an exemption names: an
        # exemption that is not measured is a sentence, and this gate's argument is
        # that a record is checked.
        reachable = {
            target: kernel_closure_names(arguments.repo_root, kernel_closure["roots"], target=target)
            for target in closure_targets(policy)
        }
        enforced = {target: reachable[target] for target in kernel_closure.get("targets", DEFAULT_CLOSURE_TARGETS)}
        problems.extend(find_closure_problems(policy, enforced))
        problems.extend(find_platform_external_problems(policy, reachable))
        # Dev-dependencies reach the same packages the artifact does today, but they
        # are a separate fact: the loader can leave the kernel's build graph while a
        # test still names it, and that is worth being able to see.
        #
        # One target is enough for this comparison: it is about which edge kind
        # resolves a package, not about which platform resolves it.
        first = next(iter(enforced))
        everything = kernel_closure_names(arguments.repo_root, kernel_closure["roots"], edges="all", target=first)
        test_only = kernel_closure_reachability(policy, everything) - kernel_closure_reachability(
            policy, reachable[first]
        )
    library_closure = policy.get("kernel_library_closure")
    library_reachable: dict[str, set[str]] | None = None
    if library_closure:
        library_reachable = {
            target: kernel_closure_names(arguments.repo_root, library_closure["roots"], target=target)
            for target in library_closure.get("targets", DEFAULT_CLOSURE_TARGETS)
        }
        problems.extend(find_library_closure_problems(policy, library_reachable))

    print(render(reports))
    print()
    surface = render_surface(metadata, identities, policy, reachable, test_only, library_reachable)
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
    documented, documented_problems = documented_kernel_unsafe(arguments.repo_root)
    measured = measured_kernel_unsafe(surface)
    if documented_problems:
        for problem in documented_problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
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
