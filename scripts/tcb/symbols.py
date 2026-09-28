#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check a release artifact for the symbols the kernel may not carry.

The dependency proof walks the resolved graph; this one reads the artifact a
deployment actually runs. They answer different questions on purpose: a graph can be
correct while a symbol arrives by a path nobody modelled, and a symbol table says
nothing about what a crate *could* reach. `security/symbols.toml` records the claim
(the tokens that may not appear at all) and the ratchet (the tokens that are present
with a ceiling and a reason).

`nm` demangles Rust symbols with `-C`, which is what makes the check about crates
rather than about mangled names; `llvm-nm` is accepted as a fallback because a machine
without binutils still has a symbol table worth reading.

This gate builds a release artifact, so it is a milestone check rather than a
pre-commit hook: `just symbol-report` runs it, and the release lane runs it against the
binary that lane already built.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys
import tomllib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_POLICY = REPO_ROOT / "security" / "symbols.toml"


class SymbolsError(Exception):
    """A policy or an artifact this gate cannot read."""


class Artifact:
    """One release artifact, and what its symbol table may contain."""

    def __init__(self, name: str, package: str, path: str, forbidden: list[str], recorded: list[dict]):
        self.name = name
        self.package = package
        self.path = path
        self.forbidden = forbidden
        self.recorded = recorded


def load_policy(path: pathlib.Path) -> list[Artifact]:
    """Read the artifacts and their symbol budgets."""
    with pathlib.Path(path).open("rb") as handle:
        document = tomllib.load(handle)
    artifacts = []
    for entry in document.get("artifact", []):
        missing = [
            field
            for field in ("name", "package", "path", "forbidden")
            if field not in entry or entry[field] in (None, "", [])
        ]
        if missing:
            raise SymbolsError(
                f"an artifact entry is missing {', '.join(missing)}; a check that does "
                "not say what it reads, or what it forbids, checks nothing"
            )
        artifacts.append(
            Artifact(
                name=entry["name"],
                package=entry["package"],
                path=entry["path"],
                forbidden=list(entry["forbidden"]),
                recorded=list(entry.get("recorded", [])),
            )
        )
    if not artifacts:
        raise SymbolsError(f"{path} names no artifacts")
    return artifacts


def symbol_table(artifact: pathlib.Path) -> tuple[list[str], list[str]]:
    """Return the artifact's ``(defined, undefined)`` symbols, demangled.

    A missing symbol tool is an error rather than a pass: a check that cannot read
    the artifact has not checked anything, and reporting success for it is the
    failure this whole gate is written against.
    """
    tool = shutil.which("nm") or shutil.which("llvm-nm")
    if tool is None:
        raise SymbolsError("neither nm nor llvm-nm is on PATH, so no symbol table can be read")
    if not artifact.is_file():
        raise SymbolsError(f"{artifact} does not exist; build it before checking it")
    # `nm` lists undefined entries too, marked `U`; the defined list is what is left.
    # Keeping them apart matters because the same name would otherwise be counted
    # twice — once as a definition nobody has and once as a reference to it.
    defined = [line for line in _nm(tool, ["-C", str(artifact)]) if not _is_undefined(line)]
    undefined = _nm(tool, ["-uC", str(artifact)])
    return defined, undefined


def _is_undefined(line: str) -> bool:
    """Whether one `nm` line describes an undefined symbol."""
    fields = line.split()
    return len(fields) >= 2 and fields[-2] == "U"


def _nm(tool: str, arguments: list[str]) -> list[str]:
    completed = subprocess.run([tool, *arguments], capture_output=True, text=True, check=False)
    if completed.returncode != 0 and not completed.stdout:
        raise SymbolsError(f"{tool} could not read the artifact: {completed.stderr.strip()}")
    return completed.stdout.splitlines()


def matches(symbols: list[str], token: str) -> list[str]:
    """Return the symbols whose name contains ``token``."""
    return [symbol for symbol in symbols if token in symbol]


def problems_for(artifact: Artifact, defined: list[str], undefined: list[str]) -> list[str]:
    """Return everything wrong with one artifact's symbol table."""
    problems = []
    # Distinct names: the ratchet is about which symbols exist, not how many lines
    # `nm` happens to print for them.
    every_symbol = sorted({*defined, *undefined})
    for token in artifact.forbidden:
        hits = matches(every_symbol, token)
        if hits:
            problems.append(
                f"{artifact.name} contains {len(hits)} symbol(s) matching '{token}': "
                f"{hits[0].strip()} — the artifact a deployment runs may not carry a "
                "loader, an ABI or the SDK"
            )
    for entry in artifact.recorded:
        token = entry.get("token")
        budget = entry.get("budget")
        if token is None or budget is None or not str(entry.get("why", "")).strip():
            problems.append(
                "a recorded symbol is missing its token, its budget or its reason; a "
                "number without a reason is a number nobody can revisit"
            )
            continue
        hits = matches(every_symbol, token)
        if len(hits) > budget:
            problems.append(
                f"{artifact.name} contains {len(hits)} symbol(s) matching '{token}', "
                f"and the policy records {budget}: {entry.get('why')}"
            )
    return problems


def render(artifact: Artifact, defined: list[str], undefined: list[str]) -> str:
    """Render what was found, so a reader sees the artifact rather than a verdict."""
    rows = [
        f"{artifact.name}: {artifact.path}",
        f"  defined symbols:   {len(defined)}",
        f"  undefined symbols: {len(undefined)}",
    ]
    every_symbol = sorted({*defined, *undefined})
    for token in artifact.forbidden:
        rows.append(f"  forbidden '{token}': {len(matches(every_symbol, token))}")
    for entry in artifact.recorded:
        token = str(entry.get("token", ""))
        rows.append(f"  recorded '{token}': {len(matches(every_symbol, token))} (budget {entry.get('budget')})")
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    """Run the symbol gate."""
    parser = argparse.ArgumentParser(description="Check a release artifact for loader symbols.")
    parser.add_argument("--policy", type=pathlib.Path, default=DEFAULT_POLICY)
    parser.add_argument("--repo-root", type=pathlib.Path, default=REPO_ROOT)
    parser.add_argument(
        "--artifact",
        type=pathlib.Path,
        help="an artifact to check instead of building one; must be the one the policy names",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="fail rather than build when the artifact is missing",
    )
    arguments = parser.parse_args(argv)

    try:
        artifacts = load_policy(arguments.policy)
    except SymbolsError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    problems: list[str] = []
    for artifact in artifacts:
        path = arguments.artifact or arguments.repo_root / artifact.path
        if not path.is_file() and not arguments.no_build:
            completed = subprocess.run(
                ["cargo", "build", "--release", "-p", artifact.package],
                cwd=arguments.repo_root,
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                print(
                    f"error: could not build {artifact.package}: {completed.stderr.strip()}",
                    file=sys.stderr,
                )
                return 1
        try:
            defined, undefined = symbol_table(path)
        except SymbolsError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        print(render(artifact, defined, undefined))
        problems.extend(problems_for(artifact, defined, undefined))

    if problems:
        print(file=sys.stderr)
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print("\nThe release artifact carries no loader: the symbol proof holds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
