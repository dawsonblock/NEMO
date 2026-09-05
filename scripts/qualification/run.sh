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
    printf '%s\t%s\n' "$1" "$2" >> "${status_file}"
}

run_check() {
    name="$1"
    shift
    log="${output_dir}/${name}.txt"
    if "$@" >"${log}" 2>&1; then
        record_status "${name}" "PASS"
    else
        record_status "${name}" "FAIL"
    fi
}

run_if_available() {
    name="$1"
    executable="$2"
    shift 2
    if ! command -v "${executable}" >/dev/null 2>&1; then
        printf 'Required executable not found: %s\n' "${executable}" >"${output_dir}/${name}.txt"
        record_status "${name}" "NOT_RUN"
        return
    fi
    run_check "${name}" "$@"
}

cd "${repo_root}"

python3 - "${repo_root}" "${output_dir}" <<'PY'
import hashlib
import json
import pathlib
import platform
import shutil
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])

def version(command):
    executable = shutil.which(command[0])
    if executable is None:
        return None
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    return (result.stdout or result.stderr).strip().splitlines()[0]

environment = {
    "schema_version": 1,
    "platform": platform.platform(),
    "machine": platform.machine(),
    "tools": {
        "rustc": version(["rustc", "--version"]),
        "cargo": version(["cargo", "--version"]),
        "node": version(["node", "--version"]),
        "npm": version(["npm", "--version"]),
        "python": version(["python3", "--version"]),
        "uv": version(["uv", "--version"]),
        "go": version(["go", "version"]),
        "protoc": version(["protoc", "--version"]),
        "just": version(["just", "--version"]),
        "cargo-nextest": version(["cargo", "nextest", "--version"]),
        "cargo-deny": version(["cargo", "deny", "--version"]),
        "cargo-audit": version(["cargo", "audit", "--version"]),
    },
}
(out / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")

locks = {}
for name in ["Cargo.lock", "package-lock.json", "uv.lock"]:
    path = root / name
    locks[name] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
(out / "dependency-lock-digests.json").write_text(json.dumps(locks, indent=2) + "\n")
PY

if git -C "${repo_root}" rev-parse HEAD >"${output_dir}/git-revision.txt" 2>/dev/null; then
    git -C "${repo_root}" status --short >>"${output_dir}/git-revision.txt"
else
    printf 'SOURCE_ARCHIVE\ngit metadata unavailable in supplied tree\n' >"${output_dir}/git-revision.txt"
fi

if [[ "${mode}" == "quick" ]]; then
    # The quick profile stays bounded enough for laptops while checking the
    # runtime and adaptive libraries that define the qualification contract.
    # Full CI adds the remaining crates, nextest, audits, and binding matrices.
    run_if_available rust-format cargo cargo fmt --all -- --check
    run_if_available clippy cargo cargo clippy -p nemo-relay -p nemo-relay-adaptive -p nemo-relay-cli --lib --all-features -- -D warnings
    run_if_available rust-tests cargo cargo test -p nemo-relay -p nemo-relay-adaptive -p nemo-relay-cli --lib --all-features --no-fail-fast --jobs 1 -- --test-threads=1
else
    run_if_available rust-format cargo cargo fmt --all -- --check
    run_if_available clippy cargo cargo clippy --workspace --all-targets --all-features -- -D warnings
    if command -v cargo-nextest >/dev/null 2>&1 || cargo nextest --version >/dev/null 2>&1; then
        run_check rust-tests cargo nextest run --workspace --all-features --no-fail-fast
    else
        printf 'cargo-nextest is not installed\n' >"${output_dir}/rust-tests.txt"
        record_status rust-tests NOT_RUN
    fi
fi
if [[ "${mode}" == "quick" ]]; then
    run_if_available rust-doc-tests cargo cargo test -p nemo-relay -p nemo-relay-adaptive -p nemo-relay-cli --doc --jobs 1
else
    run_if_available rust-doc-tests cargo cargo test --doc --workspace
fi
run_if_available cargo-deny cargo-deny cargo deny check
run_if_available cargo-audit cargo-audit cargo audit

if [[ "${mode}" != "quick" ]] && command -v uv >/dev/null 2>&1 && command -v just >/dev/null 2>&1; then
    run_check python-tests just test-python
else
    printf 'uv and just are required\n' >"${output_dir}/python-tests.txt"
    record_status python-tests NOT_RUN
fi

node_major="$(node -p 'process.versions.node.split(`.`)[0]' 2>/dev/null || true)"
if [[ "${mode}" != "quick" ]] && [[ "${node_major}" =~ ^[0-9]+$ ]] && (( node_major >= 24 )) && command -v just >/dev/null 2>&1; then
    run_check node-tests just test-node
else
    printf 'Node.js 24+ and just are required\n' >"${output_dir}/node-tests.txt"
    record_status node-tests NOT_RUN
fi

if [[ "${mode}" != "quick" ]] && command -v go >/dev/null 2>&1 && command -v just >/dev/null 2>&1; then
    run_check go-tests just test-go
else
    printf 'Go and just are required\n' >"${output_dir}/go-tests.txt"
    record_status go-tests NOT_RUN
fi

if command -v cargo-about >/dev/null 2>&1; then
    if cargo about generate --config about.toml about.hbs -o "${output_dir}/sbom.spdx.json" \
        >"${output_dir}/sbom.txt" 2>&1; then
        record_status sbom PASS
    else
        record_status sbom FAIL
    fi
else
    printf '{"status":"NOT_RUN","reason":"cargo-about is not installed"}\n' >"${output_dir}/sbom.spdx.json"
    record_status sbom NOT_RUN
fi

python3 - "${status_file}" "${output_dir}/qualification.json" <<'PY'
import json
import pathlib
import sys

statuses = {}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    name, status = line.split("\t", 1)
    statuses[name] = status
required = [
    "rust-format", "clippy", "rust-tests", "rust-doc-tests", "cargo-deny",
    "cargo-audit", "python-tests", "node-tests", "go-tests", "sbom",
]
values = [statuses.get(name, "NOT_RUN") for name in required]
overall = "FAIL" if "FAIL" in values else "INCONCLUSIVE" if "NOT_RUN" in values else "PASS"
report = {
    "schema_version": 1,
    "qualification_level": "E2_LOCAL",
    "overall": overall,
    "promotion": "QUALIFIED_LOCAL" if overall == "PASS" else "DEV",
    "checks": statuses,
    "notes": [
        "Telemetry remains non-authoritative; durable ledger enforcement is not enabled.",
        "Authority, executor, isolation, ledger, and DLP crates are disabled contract skeletons.",
    ],
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + "\n")
PY

cat "${output_dir}/qualification.json"
