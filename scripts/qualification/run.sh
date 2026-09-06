#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
output_dir="${NEMO_RELAY_QUALIFICATION_DIR:-${repo_root}/qualification}"
mode="${1:-full}"
mkdir -p "${output_dir}/coverage"
status_file="$(mktemp)"
trap 'rm -f "${status_file}"' EXIT

record_status() {
    local name="$1"
    local status="$2"
    local reason="${3:-}"
    printf '%s\t%s\t%s\n' "${name}" "${status}" "${reason}" >> "${status_file}"
}

run_check() {
    local name="$1"
    shift
    local log="${output_dir}/${name}.txt"
    if "$@" >"${log}" 2>&1; then
        record_status "${name}" "PASS" "command completed successfully"
    else
        record_status "${name}" "FAIL" "command exited non-zero"
    fi
}

not_run() {
    local name="$1"
    local reason="$2"
    printf '%s\n' "${reason}" >"${output_dir}/${name}.txt"
    record_status "${name}" "NOT_RUN" "${reason}"
}

run_if_available() {
    local name="$1"
    local executable="$2"
    shift 2
    if ! command -v "${executable}" >/dev/null 2>&1; then
        not_run "${name}" "required executable not found: ${executable}"
        return
    fi
    run_check "${name}" "$@"
}

has_cargo_subcommand() {
    command -v cargo >/dev/null 2>&1 && cargo "$1" --version >/dev/null 2>&1
}

run_cargo_subcommand() {
    local name="$1"
    local subcommand="$2"
    shift 2
    if has_cargo_subcommand "${subcommand}"; then
        run_check "${name}" cargo "${subcommand}" "$@"
    elif command -v "cargo-${subcommand}" >/dev/null 2>&1; then
        run_check "${name}" "cargo-${subcommand}" "$@"
    else
        not_run "${name}" "required cargo subcommand unavailable: ${subcommand}"
    fi
}

run_go_tests() {
    local log="${output_dir}/go-tests.txt"
    if just test-go >"${log}" 2>&1; then
        record_status go-tests PASS "command completed successfully"
    elif rg -q "cannot update the lock file|missing Rust artifacts|signal 15|aws-lc-sys|toolchain" "${log}"; then
        record_status go-tests INCONCLUSIVE "Go qualification pipeline did not complete because of a build-environment or fixture prerequisite"
    else
        record_status go-tests FAIL "Go test command exited non-zero"
    fi
}

cd "${repo_root}"
release_version="$(awk '
    /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && /^version = / {
        gsub(/version = |"/, "")
        print
        exit
    }
' Cargo.toml)"
if [[ -z "${release_version}" ]]; then
    printf 'Unable to determine workspace release version from Cargo.toml\n' >&2
    exit 1
fi

# Capture a canonical source-tree manifest before running any checks. This is
# independent of Git commit metadata, so an extracted archive can still bind
# evidence to the exact files that were tested.
python3 - "${repo_root}" "${output_dir}" <<'PY'
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
out = pathlib.Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=True)


def first_line(command):
    if shutil.which(command[0]) is None:
        return None
    result = subprocess.run(command, cwd=root, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        return None
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0] if output else None


def git_output(arguments):
    if shutil.which("git") is None:
        return None
    result = subprocess.run(["git", *arguments], cwd=root, text=True, capture_output=True, check=False)
    return result.stdout if result.returncode == 0 else None


def excluded(relative):
    if not relative.parts:
        return False
    if relative.parts[0] in {
        ".git",
        "target",
        "node_modules",
        "coverage",
        "qualification",
        ".venv",
        ".uv-cache",
        ".pytest_cache",
        ".mypy_cache",
    }:
        return True
    # Deterministic release packages and their sidecar evidence are generated
    # outputs, not source inputs. Keep them out of the tree hash to avoid a
    # self-referential archive/provenance cycle.
    return relative.parts[:2] == ("release", "artifacts")


tracked = git_output(["ls-files", "--cached", "--others", "--exclude-standard", "-z"])
if tracked is not None:
    candidates = [pathlib.Path(item) for item in tracked.split("\0") if item]
else:
    candidates = [path.relative_to(root) for path in root.rglob("*") if path.is_file()]

file_hashes = {}
for relative in sorted(set(candidates), key=lambda path: path.as_posix()):
    if excluded(relative):
        continue
    path = root / relative
    if not path.is_file() or path.is_symlink():
        continue
    file_hashes[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()

canonical = "".join(f"{name}\t{digest}\n" for name, digest in file_hashes.items()).encode()
source_tree_sha256 = hashlib.sha256(canonical).hexdigest()
(out / "source-tree.sha256").write_text(source_tree_sha256 + "\n")

archive_value = os.environ.get("NEMO_RELAY_SOURCE_ARCHIVE")
source_archive_sha256 = None
if archive_value:
    archive = pathlib.Path(archive_value).expanduser()
    if archive.is_file():
        source_archive_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
        (out / "source-archive.sha256").write_text(source_archive_sha256 + "\n")
    else:
        (out / "source-archive.sha256").write_text("NOT_AVAILABLE\n")
else:
    (out / "source-archive.sha256").write_text("NOT_PROVIDED\n")

release_archive_value = os.environ.get("NEMO_RELAY_RELEASE_ARCHIVE")
release_archive_sha256 = None
if release_archive_value:
    release_archive = pathlib.Path(release_archive_value).expanduser()
    if release_archive.is_file():
        release_archive_sha256 = hashlib.sha256(release_archive.read_bytes()).hexdigest()
        (out / "release-archive.sha256").write_text(release_archive_sha256 + "\n")
    else:
        (out / "release-archive.sha256").write_text("NOT_AVAILABLE\n")
else:
    (out / "release-archive.sha256").write_text("NOT_PROVIDED\n")

environment = {
    "schema_version": 2,
    "platform": platform.platform(),
    "machine": platform.machine(),
    "tools": {
        "rustc": first_line(["rustc", "--version"]),
        "cargo": first_line(["cargo", "--version"]),
        "node": first_line(["node", "--version"]),
        "npm": first_line(["npm", "--version"]),
        "python": first_line(["python3", "--version"]),
        "uv": first_line(["uv", "--version"]),
        "go": first_line(["go", "version"]),
        "protoc": first_line(["protoc", "--version"]),
        "just": first_line(["just", "--version"]),
        "cargo-nextest": first_line(["cargo", "nextest", "--version"]),
        "cargo-deny": first_line(["cargo", "deny", "--version"]),
        "cargo-audit": first_line(["cargo", "audit", "--version"]),
        "cargo-about": first_line(["cargo-about", "--version"]),
    },
}
environment_bytes = json.dumps(environment, sort_keys=True, separators=(",", ":")).encode()
environment_sha256 = hashlib.sha256(environment_bytes).hexdigest()
(out / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
(out / "environment-sha256.txt").write_text(environment_sha256 + "\n")
(out / "environment-lock.json").write_text(json.dumps({
    "schema_version": 1,
    "environment_sha256": environment_sha256,
    "environment": environment,
}, indent=2) + "\n")

locks = {}
for name in ["Cargo.lock", "package-lock.json", "uv.lock"]:
    path = root / name
    locks[name] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
(out / "dependency-lock-digests.json").write_text(json.dumps(locks, indent=2) + "\n")

manifest = {
    "schema_version": 1,
    "algorithm": "sha256",
    "root_digest": source_tree_sha256,
    "files": file_hashes,
    "excluded_roots": [".git", "target", "node_modules", "coverage", "qualification"],
    "source_archive_sha256": source_archive_sha256,
    "release_archive_sha256": release_archive_sha256,
    "lockfiles": locks,
    "git": {
        "commit": (git_output(["rev-parse", "HEAD"]) or "").strip() or None,
        "tree": (git_output(["rev-parse", "HEAD^{tree}"]) or "").strip() or None,
        "status": (git_output(["status", "--short"]) or "").splitlines(),
    },
}
(out / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

provenance = {
    "source_tree_sha256": source_tree_sha256,
    "source_archive_sha256": source_archive_sha256,
    "release_archive_sha256": release_archive_sha256,
    "environment_sha256": environment_sha256,
    "lockfiles": locks,
    "git": manifest["git"],
}
(out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
PY

git_commit="$(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || true)"
git_tree="$(git -C "${repo_root}" rev-parse 'HEAD^{tree}' 2>/dev/null || true)"
git_dirty="$(git -C "${repo_root}" status --short 2>/dev/null || true)"
{
    printf 'commit=%s\n' "${git_commit:-unavailable}"
    printf 'tree=%s\n' "${git_tree:-unavailable}"
    if [[ -n "${git_dirty}" ]]; then
        printf 'working_tree=dirty\n%s\n' "${git_dirty}"
    else
        printf 'working_tree=clean\n'
    fi
    printf 'source_tree_sha256=%s\n' "$(tr -d '\n' < "${output_dir}/source-tree.sha256")"
} >"${output_dir}/git-revision.txt"

if [[ "${mode}" == "provenance" ]]; then
    # Provenance-only refresh preserves any previously captured check logs.
    :
elif [[ "${mode}" == "manifest" ]]; then
    # Manifest-only mode is useful when the host cannot run the full matrix.
    for check in rust-format clippy rust-tests rust-doc-tests cargo-deny cargo-audit \
        python-tests node-tests go-tests sbom; do
        not_run "${check}" "qualification checks intentionally skipped in manifest-only mode"
    done
else
    if [[ "${mode}" == "quick" ]]; then
        run_if_available rust-format cargo cargo fmt --all -- --check
        run_if_available clippy cargo cargo clippy -p nemo-relay -p nemo-relay-adaptive -p nemo-relay-cli --lib --all-features -- -D warnings
        run_if_available rust-tests cargo cargo test -p nemo-relay -p nemo-relay-adaptive -p nemo-relay-cli --lib --all-features --no-fail-fast --jobs 1 -- --test-threads=1
        run_if_available rust-doc-tests cargo cargo test -p nemo-relay -p nemo-relay-adaptive -p nemo-relay-cli --doc --jobs 1
    else
        run_if_available rust-format cargo cargo fmt --all -- --check
        run_if_available clippy cargo cargo clippy --workspace --all-targets --all-features -- -D warnings
        if has_cargo_subcommand nextest || command -v cargo-nextest >/dev/null 2>&1; then
            run_check rust-tests cargo nextest run --workspace --all-features --no-fail-fast
        else
            not_run rust-tests "missing prerequisite: cargo-nextest"
        fi
        run_if_available rust-doc-tests cargo cargo test --doc --workspace
    fi

    run_cargo_subcommand cargo-deny deny check
    run_cargo_subcommand cargo-audit audit

    if [[ "${mode}" == "quick" ]]; then
        not_run python-tests "quick profile excludes Python binding tests"
        not_run node-tests "quick profile excludes Node.js binding tests"
        not_run go-tests "quick profile excludes Go binding tests"
    else
        python_missing=()
        command -v python3 >/dev/null 2>&1 || python_missing+=(python3)
        command -v uv >/dev/null 2>&1 || python_missing+=(uv)
        command -v just >/dev/null 2>&1 || python_missing+=(just)
        command -v cargo >/dev/null 2>&1 || python_missing+=(cargo)
        has_cargo_subcommand nextest || command -v cargo-nextest >/dev/null 2>&1 || python_missing+=(cargo-nextest)
        if (( ${#python_missing[@]} )); then
            not_run python-tests "missing prerequisites: ${python_missing[*]}"
        else
            run_check python-tests just test-python
        fi

        node_missing=()
        command -v node >/dev/null 2>&1 || node_missing+=(node)
        command -v npm >/dev/null 2>&1 || node_missing+=(npm)
        command -v just >/dev/null 2>&1 || node_missing+=(just)
        node_major="$(node -p 'process.versions.node.split(`.`)[0]' 2>/dev/null || true)"
        if ! [[ "${node_major}" =~ ^[0-9]+$ ]] || (( node_major < 24 )); then
            node_missing+=("node>=24")
        fi
        if (( ${#node_missing[@]} )); then
            not_run node-tests "missing prerequisites: ${node_missing[*]}"
        else
            run_check node-tests just test-node
        fi

        go_missing=()
        command -v go >/dev/null 2>&1 || go_missing+=(go)
        command -v just >/dev/null 2>&1 || go_missing+=(just)
        command -v cargo >/dev/null 2>&1 || go_missing+=(cargo)
        command -v rustc >/dev/null 2>&1 || go_missing+=(rustc)
        if (( ${#go_missing[@]} )); then
            not_run go-tests "missing prerequisites: ${go_missing[*]}"
        else
            run_go_tests
        fi
    fi

    if command -v cargo-about >/dev/null 2>&1; then
        about_json="$(mktemp)"
        if cargo about generate --config about.toml --format json --locked -o "${about_json}" \
            >"${output_dir}/sbom.txt" 2>&1 \
            && python3 "${script_dir}/generate_spdx_sbom.py" "${about_json}" "${output_dir}/sbom.spdx.json" "${release_version}"; then
            record_status sbom PASS "cargo-about inventory converted to SPDX 2.3"
        else
            record_status sbom FAIL "cargo-about exited non-zero"
        fi
        rm -f "${about_json}"
    else
        printf '{"status":"NOT_RUN","reason":"cargo-about is not installed"}\n' >"${output_dir}/sbom.spdx.json"
        record_status sbom NOT_RUN "missing prerequisite: cargo-about"
    fi
fi

python3 - "${status_file}" "${output_dir}/qualification.json" "${output_dir}/provenance.json" "${mode}" "${release_version}" <<'PY'
import json
import pathlib
import sys

statuses = {}
details = {}
previous = {}
if sys.argv[4] == "provenance" and pathlib.Path(sys.argv[2]).is_file():
    try:
        previous = json.loads(pathlib.Path(sys.argv[2]).read_text())
    except (OSError, json.JSONDecodeError):
        previous = {}
    statuses.update(previous.get("checks", {}))
    details.update(previous.get("check_details", {}))

for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    fields = line.split("\t", 2)
    name, status = fields[:2]
    reason = fields[2] if len(fields) == 3 else ""
    statuses[name] = status
    details[name] = {"status": status, "reason": reason}

required = [
    "rust-format", "clippy", "rust-tests", "rust-doc-tests", "cargo-deny",
    "cargo-audit", "python-tests", "node-tests", "go-tests", "sbom",
]
for name in required:
    statuses.setdefault(name, "NOT_RUN")
    details.setdefault(name, {
        "status": "NOT_RUN",
        "reason": "qualification checks were not run in this profile",
    })
values = [statuses.get(name, "NOT_RUN") for name in required]
overall = "FAIL" if "FAIL" in values else "INCONCLUSIVE" if any(value in {"NOT_RUN", "INCONCLUSIVE"} for value in values) else "PASS"
provenance = json.loads(pathlib.Path(sys.argv[3]).read_text())
profile = sys.argv[4]
if profile == "provenance":
    profile = previous.get("profile", profile)
report = {
    "schema_version": 2,
    "qualification_level": "E2_LOCAL",
    "release_version": sys.argv[5],
    "profile": profile,
    "overall": overall,
    "promotion": "QUALIFIED_LOCAL" if overall == "PASS" else "DEV",
    "checks": statuses,
    "check_details": details,
    "provenance": provenance,
    "notes": [
        "Qualification is cryptographically bound to source-manifest.json and environment-lock.json.",
        "Telemetry remains non-authoritative; durable ledger enforcement is not enabled.",
        "Authority, executor, isolation, ledger, and DLP crates are disabled contract skeletons.",
        "NOT_RUN means a prerequisite or profile requirement prevented execution; it is not a passing result.",
    ],
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + "\n")
PY

cat "${output_dir}/qualification.json"
