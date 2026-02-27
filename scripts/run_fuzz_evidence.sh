#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="${ROOT_DIR}/fuzz"

TARGETS="${FUZZ_TARGETS:-dsl_parser proof_envelope_decode log_entry_deserialize}"
DURATION_SECONDS="${FUZZ_DURATION_SECONDS:-600}"
FAIL_ON_CRASH="${FUZZ_FAIL_ON_CRASH:-1}"
EVIDENCE_BASE_DIR="${FUZZ_EVIDENCE_DIR:-${FUZZ_DIR}/evidence}"

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "cargo-fuzz is required. Install with: cargo install cargo-fuzz --locked" >&2
  exit 2
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${EVIDENCE_BASE_DIR}/${RUN_ID}"
mkdir -p "${RUN_DIR}"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
json_file="${RUN_DIR}/fuzz-evidence.json"
summary_file="${RUN_DIR}/summary.md"

declare -a entries=()
overall_crash_count=0

for target in ${TARGETS}; do
  mkdir -p "${FUZZ_DIR}/corpus/${target}" "${FUZZ_DIR}/artifacts/${target}"
  log_file="${RUN_DIR}/${target}.log"

  started_epoch="$(date +%s)"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  set +e
  (
    cd "${FUZZ_DIR}"
    cargo fuzz run "${target}" -- \
      -max_total_time="${DURATION_SECONDS}" \
      -print_final_stats=1
  ) 2>&1 | tee "${log_file}"
  exit_code="${PIPESTATUS[0]}"
  set -e

  ended_epoch="$(date +%s)"
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  elapsed="$((ended_epoch - started_epoch))"

  corpus_count="$(find "${FUZZ_DIR}/corpus/${target}" -type f | wc -l | tr -d ' ')"
  crash_count="$(find "${FUZZ_DIR}/artifacts/${target}" -type f | wc -l | tr -d ' ')"
  overall_crash_count="$((overall_crash_count + crash_count))"

  entries+=("{\"target\":\"${target}\",\"started_at\":\"${started_at}\",\"ended_at\":\"${ended_at}\",\"duration_seconds\":${elapsed},\"configured_duration_seconds\":${DURATION_SECONDS},\"exit_code\":${exit_code},\"corpus_file_count\":${corpus_count},\"artifact_crash_count\":${crash_count},\"log_file\":\"$(basename "${log_file}")\"}")
done

{
  printf '{\n'
  printf '  "generated_at": "%s",\n' "${generated_at}"
  printf '  "run_id": "%s",\n' "${RUN_ID}"
  printf '  "configured_duration_seconds": %s,\n' "${DURATION_SECONDS}"
  printf '  "targets": [\n'
  for i in "${!entries[@]}"; do
    sep=","
    if [[ "${i}" -eq "$((${#entries[@]} - 1))" ]]; then
      sep=""
    fi
    printf '    %s%s\n' "${entries[${i}]}" "${sep}"
  done
  printf '  ]\n'
  printf '}\n'
} > "${json_file}"

{
  echo "# Fuzz Campaign Evidence"
  echo
  echo "- Generated at: \`${generated_at}\`"
  echo "- Run ID: \`${RUN_ID}\`"
  echo "- Configured duration per target (seconds): \`${DURATION_SECONDS}\`"
  echo "- Targets: \`${TARGETS}\`"
  echo "- Total crash artifacts: \`${overall_crash_count}\`"
  echo
  echo "Evidence file: \`$(basename "${json_file}")\`"
} > "${summary_file}"

if [[ "${FAIL_ON_CRASH}" == "1" && "${overall_crash_count}" -gt 0 ]]; then
  echo "Fuzzing produced crash artifacts (${overall_crash_count}). See ${RUN_DIR}." >&2
  exit 1
fi

echo "Fuzz evidence generated at ${RUN_DIR}"
