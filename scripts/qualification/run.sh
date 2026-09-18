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
    local duration_ms="${4:-0}"
    printf '%s\t%s\t%s\t%s\n' "${name}" "${status}" "${reason}" "${duration_ms}" >> "${status_file}"
}

# Portable millisecond clock. BSD `date` has no %N, and gate evidence records a
# duration so qualification can show where a run actually spent its time.
now_ms() {
    python3 -c 'import time; print(int(time.time() * 1000))'
}

run_check() {
    local name="$1"
    shift
    local log="${output_dir}/${name}.txt"
    local started
    started="$(now_ms)"
    if "$@" >"${log}" 2>&1; then
        record_status "${name}" "PASS" "command completed successfully" "$(( $(now_ms) - started ))"
    else
        record_status "${name}" "FAIL" "command exited non-zero" "$(( $(now_ms) - started ))"
    fi
}

not_run() {
    local name="$1"
    local reason="$2"
    printf '%s\n' "${reason}" >"${output_dir}/${name}.txt"
    record_status "${name}" "NOT_RUN" "${reason}" "0"
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
        record_status go-tests PASS "command completed successfully" 0
    elif rg -q "cannot update the lock file|missing Rust artifacts|signal 15|aws-lc-sys|toolchain" "${log}"; then
        record_status go-tests INCONCLUSIVE "Go qualification pipeline did not complete because of a build-environment or fixture prerequisite" 0
    else
        record_status go-tests FAIL "Go test command exited non-zero" 0
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

# Provenance refresh is only allowed to bind new archive metadata to a source
# tree that was already qualified. It must never reinterpret a previous PASS
# as evidence for source modified after that run.
if [[ "${mode}" == "provenance" ]]; then
    if [[ ! -f "${output_dir}/qualification.json" || ! -f "${output_dir}/source-manifest.json" ]]; then
        printf 'Cannot refresh provenance without an existing qualification report and source manifest. Run a full qualification first.\n' >&2
        exit 1
    fi
    if ! NEMO_RELAY_SOURCE_MANIFEST="${output_dir}/source-manifest.json" \
        python3 "${script_dir}/provenance_check.py" >"${output_dir}/source-stability.txt" 2>&1; then
        python3 - "${output_dir}/qualification.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
report = json.loads(path.read_text())
report["schema_version"] = max(int(report.get("schema_version", 1)), 3)
report["overall"] = "FAIL"
report["promotion"] = "DEV"
report["qualification_level"] = "DEV"
report["qualification_status"] = "INVALIDATED"
report["invalidation_reason"] = "SOURCE_TREE_CHANGED_AFTER_QUALIFICATION"
report["tier_evaluation_source"] = "invalidated_before_tier_evaluation"
report["blocking_reasons"] = ["source changed after qualification; rerun the full matrix"]
checks = report.setdefault("checks", {})
details = report.setdefault("check_details", {})
checks["source-stability"] = "FAIL"
details["source-stability"] = {
    "status": "FAIL",
    "reason": "current source no longer matches the source manifest qualified by this report",
}
report.setdefault("notes", []).append(
    "Qualification was invalidated because provenance refresh detected source changes after qualification."
)
path.write_text(json.dumps(report, indent=2) + "\n")
PY
        cat "${output_dir}/source-stability.txt" >&2
        exit 1
    fi
    if ! python3 - "${output_dir}/qualification.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text())
if report.get("overall") != "PASS" or report.get("qualification_status", "VALID") != "VALID":
    raise SystemExit("A provenance refresh can only bind archive metadata to an existing valid PASS qualification.")
PY
    then
        printf 'Cannot refresh provenance for an invalid or non-passing qualification report. Run a full qualification first.\n' >&2
        exit 1
    fi
fi

# Capture a canonical source-tree manifest before running any checks. This is
# independent of Git commit metadata, so an extracted archive can still bind
# evidence to the exact files that were tested. The capture shares its
# enumeration with provenance_check.py, so the producer and the verifier
# cannot disagree about which entries are source content.
python3 "${script_dir}/capture_provenance.py" \
    --root "${repo_root}" --out "${output_dir}" --mode "${mode}"

git_commit="$(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || true)"
git_tree="$(git -C "${repo_root}" rev-parse 'HEAD^{tree}' 2>/dev/null || true)"
# Generated evidence is intentionally excluded from the cleanliness signal;
# source and release inputs remain visible to the qualification record.
git_dirty="$(git -C "${repo_root}" status --short 2>/dev/null | grep -v 'qualification/' | grep -v 'release/artifacts/' || true)"
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

if [[ -n "${git_dirty}" ]]; then
    record_status source-cleanliness FAIL "source tree was dirty before qualification began" 0
else
    record_status source-cleanliness PASS "source tree was clean before qualification began" 0
fi

if [[ "${mode}" == "provenance" ]]; then
    # Provenance-only refresh preserves any previously captured check logs.
    :
elif [[ "${mode}" == "manifest" ]]; then
    # Manifest-only mode is useful when the host cannot run the full matrix.
    for check in rust-format clippy rust-tests rust-doc-tests effect-contracts postgres-transport-security cargo-deny cargo-audit \
        migration-integrity physical-schema-verification db-failure-boundaries \
        postgres-effect-store postgres-concurrency postgres-restart postgres-crash-recovery postgres-kernel-restart \
        python-tests node-tests go-tests sbom; do
        not_run "${check}" "qualification checks intentionally skipped in manifest-only mode"
    done
else
    if [[ "${mode}" == "quick" ]]; then
        run_if_available rust-format cargo cargo fmt --all -- --check
        run_if_available clippy cargo cargo clippy -p nemo-relay -p nemo-relay-adaptive -p nemo-relay-cli --lib --all-features -- -D warnings
        run_if_available rust-tests cargo cargo test -p nemo-relay -p nemo-relay-adaptive -p nemo-relay-cli --lib --all-features --no-fail-fast --jobs 1 -- --test-threads=1
        run_if_available rust-doc-tests cargo cargo test -p nemo-relay -p nemo-relay-adaptive -p nemo-relay-cli --doc --jobs 1
        run_if_available effect-contracts just just test-effect-contracts
    else
        run_if_available rust-format cargo cargo fmt --all -- --check
        run_if_available clippy cargo cargo clippy --workspace --all-targets --all-features -- -D warnings
        # The canonical Rust recipe builds the native and worker plugin
        # fixtures before invoking nextest. Calling nextest directly leaves
        # the workspace integration suite with missing fixture binaries and
        # produces a false source failure on an otherwise valid checkout.
        run_if_available rust-tests just just test-rust
        run_if_available rust-doc-tests cargo cargo test --doc --workspace
        run_if_available effect-contracts just just test-effect-contracts
    fi

    run_if_available postgres-transport-security just just test-postgres-transport-security

    if [[ -n "${NEMO_RELAY_TEST_POSTGRES_URL:-}" ]]; then
        # E3-011 and E3-012 are separate gates: an intact migration ledger and a
        # physically verified schema are different facts, and either can fail
        # while the other passes.
        export NEMO_RELAY_SCHEMA_EVIDENCE_DIR="${output_dir}"
        run_check migration-integrity just test-postgres-migration-integrity
        run_check physical-schema-verification just test-postgres-schema-verification
        # The boundary invariant is mandatory for E3.1: a database failure must
        # not be allowed to decide, by itself, whether an external effect
        # happened.
        run_check db-failure-boundaries just test-postgres-db-failure-boundaries
        run_check postgres-effect-store just test-postgres-effect-store
        run_check postgres-concurrency just test-postgres-effect-store-concurrency
        run_check postgres-restart just test-postgres-effect-store-restart
        run_check postgres-crash-recovery just test-postgres-crash-recovery
        run_check postgres-kernel-restart just test-postgres-kernel-restart
    else
        not_run migration-integrity "NEMO_RELAY_TEST_POSTGRES_URL is required for live PostgreSQL qualification"
        not_run physical-schema-verification "NEMO_RELAY_TEST_POSTGRES_URL is required for live PostgreSQL qualification"
        not_run db-failure-boundaries "NEMO_RELAY_TEST_POSTGRES_URL is required for live PostgreSQL qualification"
        not_run postgres-effect-store "NEMO_RELAY_TEST_POSTGRES_URL is required for live PostgreSQL qualification"
        not_run postgres-concurrency "NEMO_RELAY_TEST_POSTGRES_URL is required for live PostgreSQL qualification"
        not_run postgres-restart "NEMO_RELAY_TEST_POSTGRES_URL is required for live PostgreSQL qualification"
        not_run postgres-crash-recovery "NEMO_RELAY_TEST_POSTGRES_URL is required for live PostgreSQL qualification"
        not_run postgres-kernel-restart "NEMO_RELAY_TEST_POSTGRES_URL is required for live PostgreSQL qualification"
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
            record_status sbom PASS "cargo-about inventory converted to SPDX 2.3" 0
        else
            record_status sbom FAIL "cargo-about exited non-zero" 0
        fi
        rm -f "${about_json}"
    else
        printf '{"status":"NOT_RUN","reason":"cargo-about is not installed"}\n' >"${output_dir}/sbom.spdx.json"
        record_status sbom NOT_RUN "missing prerequisite: cargo-about"
    fi
fi

# The manifest was captured before checks started. Re-verify it after every
# profile so a source edit during qualification cannot inherit a PASS.
if NEMO_RELAY_SOURCE_MANIFEST="${output_dir}/source-manifest.json" \
    python3 "${script_dir}/provenance_check.py" >"${output_dir}/source-stability.txt" 2>&1; then
    record_status source-stability PASS "source tree remained identical throughout qualification" 0
else
    record_status source-stability FAIL "source tree changed during qualification" 0
fi

python3 - "${status_file}" "${output_dir}/qualification.json" "${output_dir}/provenance.json" \
    "${mode}" "${release_version}" "${script_dir}" "${output_dir}" "${repo_root}" <<'PY'
import json
import pathlib
import sys

statuses = {}
details = {}
previous = {}
script_dir = pathlib.Path(sys.argv[6])
output_dir = pathlib.Path(sys.argv[7])
repo_root = pathlib.Path(sys.argv[8])
sys.path.insert(0, str(script_dir))
import capture_provenance
import qualification_levels

if sys.argv[4] == "provenance" and pathlib.Path(sys.argv[2]).is_file():
    try:
        previous = json.loads(pathlib.Path(sys.argv[2]).read_text())
    except (OSError, json.JSONDecodeError):
        previous = {}
    statuses.update(previous.get("checks", {}))
    details.update(previous.get("check_details", {}))

for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    fields = line.split("\t", 3)
    name, status = fields[:2]
    reason = fields[2] if len(fields) >= 3 else ""
    duration_ms = int(fields[3]) if len(fields) == 4 and fields[3].isdigit() else 0
    statuses[name] = status
    details[name] = {"status": status, "reason": reason, "duration_ms": duration_ms}

required = [
    "source-cleanliness", "source-stability", "rust-format", "clippy", "rust-tests", "rust-doc-tests",
    "effect-contracts", "postgres-transport-security", "migration-integrity", "physical-schema-verification",
    "db-failure-boundaries",
    "postgres-effect-store", "postgres-concurrency", "postgres-restart",
    "postgres-crash-recovery", "postgres-kernel-restart",
    "cargo-deny", "cargo-audit", "python-tests", "node-tests", "go-tests", "sbom",
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
mode_argument = sys.argv[4]
profile = previous.get("profile", mode_argument) if mode_argument == "provenance" else mode_argument

source_manifest_path = output_dir / "source-manifest.json"
source_manifest = (
    json.loads(source_manifest_path.read_text()) if source_manifest_path.is_file() else {}
)

report = {
    "schema_version": 4,
    "release_version": sys.argv[5],
    "profile": profile,
    "overall": overall,
    "qualification_status": "VALID" if overall == "PASS" else "INVALID",
    "checks": statuses,
    "check_details": details,
    "provenance": provenance,
    "_source_manifest": source_manifest,
    "notes": [
        "Qualification is cryptographically bound to source-manifest.json, environment-lock.json, and evidence-manifest.json.",
        "The source manifest enumerates the filesystem directly and is verified both before and after checks; source changes invalidate qualification.",
        "Live PostgreSQL conformance, concurrency, restart, and process-crash checks are required for a PASS qualification.",
        "Promotion is the highest tier whose evidence is actually present; blocked tiers are recorded with reasons.",
        "Only the pinned Linux release environment can reach QUALIFIED_CI or above.",
        "Telemetry remains non-authoritative; durable ledger enforcement is not enabled.",
        "Kernel contracts and adapters are present; authority enforcement, durable effects, isolation enforcement, and outbound DLP remain disabled until external providers are configured.",
        "NOT_RUN means a prerequisite or profile requirement prevented execution; it is not a passing result.",
    ],
}

if mode_argument == "provenance" and previous.get("promotion"):
    # A provenance refresh re-binds archive metadata to a tree that was already
    # qualified on a different host. It must not re-derive a tier from this
    # host's environment.
    report["promotion"] = previous["promotion"]
    report["qualification_level"] = previous.get("qualification_level", previous["promotion"])
    report["tier_evaluation"] = previous.get("tier_evaluation", {})
    report["tier_evaluation_source"] = "inherited_from_full_run"
    report["blocking_reasons"] = previous.get("blocking_reasons", [])
else:
    lock_path = output_dir / "environment-lock.json"
    recorded_environment = (
        json.loads(lock_path.read_text()).get("environment") if lock_path.is_file() else None
    )
    current_environment, _ = capture_provenance.capture_environment(repo_root)
    # The evidence bundle is written after this report, so the signature state is
    # decided here from what the run can actually produce and then re-checked
    # against the bundle once it exists.
    sign_requested = bool(__import__("os").environ.get("NEMO_RELAY_EVIDENCE_SIGN"))
    evidence_signature = (
        "SIGNED" if sign_requested and __import__("shutil").which("cosign") else "UNSIGNED"
    )
    evaluation = qualification_levels.evaluate(
        report,
        recorded_environment=recorded_environment,
        current_environment=current_environment,
        evidence_signature=evidence_signature,
        attestation_signature="MISSING",
    )
    report["qualification_level"] = evaluation["promotion"]
    report["promotion"] = evaluation["promotion"]
    report["blocking_reasons"] = evaluation["blocking_reasons"]
    report["tier_evaluation"] = {
        "tiers": evaluation["tiers"],
        "environment": evaluation["environment"],
        "gates": evaluation["gates"],
        "signatures": evaluation["signatures"],
        "signature_required_tiers": evaluation["signature_required_tiers"],
    }
    report["tier_evaluation_source"] = "computed_from_this_run"

report.pop("_source_manifest", None)
pathlib.Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + "\n")
PY

cat "${output_dir}/qualification.json"

# Bind every artifact this run produced into one evidence bundle. The bundle is
# written after the report so it covers the final qualification result and the
# complete set of gate logs, and it is verified immediately so a broken bundle
# cannot leave the run looking successful. The final distributed artifact is
# bound separately by attest_release.py, outside the artifact it describes.
# Set NEMO_RELAY_EVIDENCE_SIGN to request a cosign signature from the ambient CI
# identity.
evidence_args=(--root "${repo_root}" --qualification-dir "${output_dir}")
if [[ -n "${NEMO_RELAY_EVIDENCE_SIGN:-}" ]]; then
    evidence_args+=(--sign)
fi
if ! python3 "${script_dir}/build_evidence_manifest.py" "${evidence_args[@]}"; then
    printf 'Evidence bundle generation failed.\n' >&2
    exit 1
fi
if ! python3 "${script_dir}/build_evidence_manifest.py" "${evidence_args[@]}" --verify; then
    printf 'Evidence bundle verification failed.\n' >&2
    exit 1
fi

# A run must not claim a signature it did not produce. The report decided the
# signature state before the bundle existed; this reconciles the two, so a
# requested-but-failed signature downgrades the record instead of leaving an
# unsigned bundle carrying a signed tier.
if [[ "${mode}" != "manifest" ]] && ! python3 - "${output_dir}/qualification.json" "${output_dir}/evidence-manifest.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text())
bundle = json.loads(pathlib.Path(sys.argv[2]).read_text())
claimed = report.get("tier_evaluation", {}).get("signatures", {}).get("evidence")
actual = bundle.get("signing", {}).get("status")
if claimed and claimed != actual:
    raise SystemExit(
        f"qualification report claims evidence signature {claimed!r} but the "
        f"evidence bundle records {actual!r}"
    )
PY
then
    printf 'Evidence signature state does not match the qualification report.\n' >&2
    exit 1
fi

# The report is the contract for callers: an incomplete or failed gate must
# fail the recipe as well as remain visible in the JSON evidence.  Without
# this check a shell redirection or unavailable prerequisite could produce a
# DEV/FAIL report while CI still observed exit status zero.
overall="$(python3 - "${output_dir}/qualification.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(report.get("overall", "INCONCLUSIVE"))
PY
)"
if [[ "${overall}" != "PASS" ]]; then
    exit 1
fi
