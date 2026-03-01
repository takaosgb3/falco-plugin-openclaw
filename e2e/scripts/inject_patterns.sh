#!/usr/bin/env bash
# inject_patterns.sh — Pattern injection + Falco execution script for E2E tests
#
# Injects test patterns into a log file and captures Falco alerts.
# OpenClaw version: writes directly to log files (no k6/nginx needed).
#
# Usage: inject_patterns.sh [OPTIONS]
#
# Options:
#   -c, --config <path>       Falco config template path (required for non-dry-run)
#   -p, --patterns <dir>      Pattern JSON directory (default: test/e2e/patterns/categories)
#   -o, --output <path>       Falco output capture file (default: e2e/results/falco-output.log)
#   -l, --log-file <path>     Test log file path (default: /tmp/openclaw-e2e-test.jsonl)
#   -f, --falco <path>        Falco binary path (default: falco or $FALCO_BIN)
#   -t, --timeout <sec>       Falco startup timeout seconds (default: 30)
#   -w, --wait <ms>           Wait time between patterns in ms (default: 100)
#   --dry-run                 Show injection commands without starting Falco
#   -v, --verbose             Enable debug log output
#
# Exit codes:
#   0  All patterns injected successfully
#   1  Argument error / file not found
#   2  Falco startup failure (timeout)
#   3  Falco abnormal exit
#
# Environment variables:
#   FALCO_BIN                 Falco binary path (alternative to --falco)
#   FALCO_OPENCLAW_DEBUG      "true" to enable plugin debug logging

set -euo pipefail

# ---- Constants ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly PROJECT_ROOT
readonly DEFAULT_PATTERNS_DIR="${PROJECT_ROOT}/test/e2e/patterns/categories"
readonly DEFAULT_OUTPUT="${PROJECT_ROOT}/e2e/results/falco-output.log"
readonly DEFAULT_LOG_FILE="/tmp/openclaw-e2e-test.jsonl"
readonly DEFAULT_TIMEOUT=30
readonly DEFAULT_WAIT_MS=100
readonly RESULTS_DIR="${PROJECT_ROOT}/e2e/results"

# ---- Global variables ----
CONFIG_TEMPLATE=""
PATTERNS_DIR="${DEFAULT_PATTERNS_DIR}"
OUTPUT_FILE="${DEFAULT_OUTPUT}"
LOG_FILE="${DEFAULT_LOG_FILE}"
FALCO_CMD="${FALCO_BIN:-falco}"
TIMEOUT_SEC="${DEFAULT_TIMEOUT}"
WAIT_MS="${DEFAULT_WAIT_MS}"
DRY_RUN=false
VERBOSE=false
FALCO_PID=""

# ---- Logging ----
log_info() {
    echo "[INFO] $*" >&2
}

log_debug() {
    if [ "${VERBOSE}" = true ]; then
        echo "[DEBUG] $*" >&2
    fi
}

log_error() {
    echo "[ERROR] $*" >&2
}

# ---- Cleanup handler ----
cleanup() {
    if [ -n "${FALCO_PID}" ] && kill -0 "${FALCO_PID}" 2>/dev/null; then
        log_info "Stopping Falco (PID: ${FALCO_PID})..."
        kill -TERM "${FALCO_PID}" 2>/dev/null || true
        local waited=0
        while kill -0 "${FALCO_PID}" 2>/dev/null && [ "${waited}" -lt 5 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        if kill -0 "${FALCO_PID}" 2>/dev/null; then
            log_info "Falco did not stop, sending SIGKILL..."
            kill -KILL "${FALCO_PID}" 2>/dev/null || true
        fi
    fi
}

trap cleanup EXIT

# ---- Usage ----
usage() {
    cat <<'USAGE'
Usage: inject_patterns.sh [OPTIONS]

Options:
  -c, --config <path>       Falco config template path (required for non-dry-run)
  -p, --patterns <dir>      Pattern JSON directory (default: test/e2e/patterns/categories)
  -o, --output <path>       Falco output capture file (default: e2e/results/falco-output.log)
  -l, --log-file <path>     Test log file path (default: /tmp/openclaw-e2e-test.jsonl)
  -f, --falco <path>        Falco binary path (default: falco or $FALCO_BIN)
  -t, --timeout <sec>       Falco startup timeout (default: 30)
  -w, --wait <ms>           Wait between patterns in ms (default: 100)
  --dry-run                 Show injection commands without starting Falco
  -v, --verbose             Enable debug log output

Exit codes:
  0  All patterns injected successfully
  1  Argument error / file not found
  2  Falco startup failure (timeout)
  3  Falco abnormal exit
USAGE
}

# ---- Argument parsing ----
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -c|--config)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument"
                    exit 1
                fi
                CONFIG_TEMPLATE="$2"
                shift 2
                ;;
            -p|--patterns)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument"
                    exit 1
                fi
                PATTERNS_DIR="$2"
                shift 2
                ;;
            -o|--output)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument"
                    exit 1
                fi
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -l|--log-file)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument"
                    exit 1
                fi
                LOG_FILE="$2"
                shift 2
                ;;
            -f|--falco)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument"
                    exit 1
                fi
                FALCO_CMD="$2"
                shift 2
                ;;
            -t|--timeout)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument"
                    exit 1
                fi
                TIMEOUT_SEC="$2"
                shift 2
                ;;
            -w|--wait)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument"
                    exit 1
                fi
                WAIT_MS="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# ---- Validation ----
validate_args() {
    if [ "${DRY_RUN}" = false ] && [ -z "${CONFIG_TEMPLATE}" ]; then
        log_error "Config template path is required (use -c or --config). Use --dry-run to skip Falco."
        exit 1
    fi

    if [ -n "${CONFIG_TEMPLATE}" ] && [ ! -f "${CONFIG_TEMPLATE}" ]; then
        log_error "Config template not found: ${CONFIG_TEMPLATE}"
        exit 1
    fi

    if [ ! -d "${PATTERNS_DIR}" ]; then
        log_error "Patterns directory not found: ${PATTERNS_DIR}"
        exit 1
    fi

    if [ "${DRY_RUN}" = false ] && ! command -v "${FALCO_CMD}" >/dev/null 2>&1; then
        log_error "Falco binary not found: ${FALCO_CMD}"
        exit 1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq is required but not found"
        exit 1
    fi
}

# ---- Millisecond timestamp (cross-platform) ----
get_epoch_ms() {
    python3 -c "import time; print(int(time.time()*1000))"
}

# ---- Detect library path ----
detect_library_path() {
    local os_name
    os_name="$(uname -s)"

    case "${os_name}" in
        Linux)
            local lib_path
            lib_path=$(find "${PROJECT_ROOT}/build/" -name "libopenclaw.so" 2>/dev/null | head -1)
            if [ -z "${lib_path}" ]; then
                log_error "Library not found: build/libopenclaw.so (run 'make build' first)"
                exit 1
            fi
            echo "${lib_path}"
            ;;
        Darwin)
            local lib_path
            lib_path=$(find "${PROJECT_ROOT}/build/" -name "libopenclaw.dylib" 2>/dev/null | head -1)
            if [ -z "${lib_path}" ]; then
                log_error "Library not found: build/libopenclaw.dylib (run 'make build' first)"
                exit 1
            fi
            echo "${lib_path}"
            ;;
        *)
            log_error "Unsupported OS: ${os_name}"
            exit 1
            ;;
    esac
}

# ---- Generate Falco CI config ----
generate_falco_config() {
    local library_path="$1"
    local log_file_path="$2"
    local rules_path="${PROJECT_ROOT}/rules/openclaw_rules.yaml"
    local output_path="${RESULTS_DIR}/falco-ci.yaml"

    if [ ! -f "${rules_path}" ]; then
        log_error "Rules file not found: ${rules_path}"
        exit 1
    fi

    cat > "${output_path}" <<EOF
plugins:
  - name: openclaw
    library_path: ${library_path}
    init_config: '{"log_paths":["${log_file_path}"],"event_buffer_size":1000}'
load_plugins: [openclaw]
rules_files:
  - ${rules_path}
json_output: true
stdout_output:
  enabled: true
EOF

    log_info "Generated Falco config: ${output_path}"
    log_debug "  library_path: ${library_path}"
    log_debug "  log_file: ${log_file_path}"
    log_debug "  rules_path: ${rules_path}"
    echo "${output_path}"
}

# ---- Start Falco ----
start_falco() {
    local config_path="$1"

    log_info "Starting Falco..."
    log_debug "  Command: ${FALCO_CMD} -c ${config_path} --disable-source syscall -U"

    # Start Falco in background, capture stdout to output file, stderr to temp file
    local stderr_file
    stderr_file=$(mktemp)

    ${FALCO_CMD} -c "${config_path}" --disable-source syscall -U \
        > "${OUTPUT_FILE}" \
        2> "${stderr_file}" &
    FALCO_PID=$!

    log_info "Falco started (PID: ${FALCO_PID})"

    # Wait for startup completion by monitoring stderr for "Enabled event sources:"
    # Fallback: if process is alive after 5 seconds with no stderr errors, assume ready
    # (macOS MINIMAL_BUILD does not emit startup messages to stderr)
    local elapsed=0
    local fallback_sec=5
    while [ "${elapsed}" -lt "${TIMEOUT_SEC}" ]; do
        if ! kill -0 "${FALCO_PID}" 2>/dev/null; then
            log_error "Falco exited prematurely"
            log_error "stderr output:"
            cat "${stderr_file}" >&2
            rm -f "${stderr_file}"
            FALCO_PID=""
            exit 3
        fi

        if grep -q "Enabled event sources:" "${stderr_file}" 2>/dev/null; then
            log_info "Falco startup complete (${elapsed}s, detected via stderr)"
            rm -f "${stderr_file}"
            return 0
        fi

        # Fallback: if process alive and no stderr errors after fallback_sec, assume ready
        if [ "${elapsed}" -ge "${fallback_sec}" ]; then
            local stderr_size
            stderr_size=$(wc -c < "${stderr_file}" | tr -d ' ')
            if [ "${stderr_size}" -eq 0 ]; then
                log_info "Falco startup assumed ready (${elapsed}s, process alive, no stderr errors)"
                rm -f "${stderr_file}"
                return 0
            fi
        fi

        sleep 1
        elapsed=$((elapsed + 1))
        log_debug "Waiting for Falco startup... (${elapsed}/${TIMEOUT_SEC}s)"
    done

    log_error "Falco startup timeout after ${TIMEOUT_SEC}s"
    log_error "stderr output:"
    cat "${stderr_file}" >&2
    rm -f "${stderr_file}"
    kill -TERM "${FALCO_PID}" 2>/dev/null || true
    FALCO_PID=""
    exit 2
}

# ---- Process a single pattern ----
inject_pattern() {
    local pattern_id="$1"
    local payload="$2"
    local format="$3"
    local category="$4"
    local log_file_path="$5"

    # Replace session_id with pattern_id for correlation
    local modified_payload
    if [ "${format}" = "plaintext" ]; then
        # shellcheck disable=SC2001
        modified_payload=$(echo "${payload}" | sed "s/session=[^ ]*/session=${pattern_id}/")
    else
        modified_payload=$(echo "${payload}" | jq -c --arg sid "${pattern_id}" '.session_id = $sid')
    fi

    if [ "${DRY_RUN}" = true ]; then
        echo "[DRY-RUN] Would inject: ${pattern_id} (${category}/${format})" >&2
        echo "  Payload: ${modified_payload}" >&2
        return 0
    fi

    # Append to log file
    echo "${modified_payload}" >> "${log_file_path}"
    log_debug "Injected: ${pattern_id} (${category})"
}

# ---- Main injection loop ----
inject_all_patterns() {
    local log_file_path="$1"
    local test_ids_file="${RESULTS_DIR}/test-ids.json"
    local wait_sec
    wait_sec=$(echo "scale=3; ${WAIT_MS} / 1000" | bc)

    local total_injected=0
    local test_ids_json="["

    log_info "Scanning patterns in: ${PATTERNS_DIR}"

    # Process each category JSON file
    for pattern_file in "${PATTERNS_DIR}"/*.json; do
        if [ ! -f "${pattern_file}" ]; then
            continue
        fi

        local filename
        filename=$(basename "${pattern_file}")
        local category
        category=$(jq -r '.category' "${pattern_file}")
        local pattern_count
        pattern_count=$(jq '.patterns | length' "${pattern_file}")

        log_info "Processing ${filename}: ${pattern_count} patterns (category: ${category})"

        # Iterate over patterns in the file
        local i=0
        while [ "${i}" -lt "${pattern_count}" ]; do
            local pattern_id
            pattern_id=$(jq -r ".patterns[${i}].id" "${pattern_file}")
            local payload
            payload=$(jq -r ".patterns[${i}].payload" "${pattern_file}")
            local format
            format=$(jq -r ".patterns[${i}].format // \"json\"" "${pattern_file}")

            # Get current timestamp
            local sent_at
            sent_at=$(get_epoch_ms)

            # Inject the pattern
            inject_pattern "${pattern_id}" "${payload}" "${format}" "${category}" "${log_file_path}"

            # Record in test-ids.json
            if [ "${total_injected}" -gt 0 ]; then
                test_ids_json="${test_ids_json},"
            fi
            test_ids_json="${test_ids_json}{\"test_id\":\"${pattern_id}\",\"pattern_id\":\"${pattern_id}\",\"category\":\"${category}\",\"sent_at\":${sent_at}}"

            total_injected=$((total_injected + 1))

            # Wait between patterns
            if [ "${DRY_RUN}" = false ]; then
                sleep "${wait_sec}"
            fi

            i=$((i + 1))
        done
    done

    test_ids_json="${test_ids_json}]"

    # Write test-ids.json
    echo "${test_ids_json}" | jq '.' > "${test_ids_file}"
    log_info "Wrote test-ids.json: ${test_ids_file} (${total_injected} patterns)"

    echo "${total_injected}"
}

# ---- Stop Falco gracefully ----
stop_falco() {
    if [ -z "${FALCO_PID}" ] || ! kill -0 "${FALCO_PID}" 2>/dev/null; then
        log_info "Falco is not running"
        return 0
    fi

    log_info "Stopping Falco (PID: ${FALCO_PID})..."
    kill -TERM "${FALCO_PID}" 2>/dev/null || true

    local waited=0
    while kill -0 "${FALCO_PID}" 2>/dev/null && [ "${waited}" -lt 5 ]; do
        sleep 1
        waited=$((waited + 1))
    done

    if kill -0 "${FALCO_PID}" 2>/dev/null; then
        log_info "Falco did not stop gracefully, sending SIGKILL..."
        kill -KILL "${FALCO_PID}" 2>/dev/null || true
    fi

    # Clear PID to prevent cleanup handler from double-stopping
    FALCO_PID=""
    log_info "Falco stopped"
}

# ---- Verify results ----
verify_results() {
    if [ ! -f "${OUTPUT_FILE}" ]; then
        log_error "Falco output file not found: ${OUTPUT_FILE}"
        return 1
    fi

    local line_count
    line_count=$(wc -l < "${OUTPUT_FILE}" | tr -d ' ')
    if [ "${line_count}" -eq 0 ]; then
        log_error "Falco output file is empty: ${OUTPUT_FILE}"
        return 1
    fi

    log_info "Falco output: ${line_count} lines in ${OUTPUT_FILE}"
    return 0
}

# ---- Main ----
main() {
    parse_args "$@"
    validate_args

    log_info "=== OpenClaw E2E Pattern Injection ==="
    log_info "Patterns dir: ${PATTERNS_DIR}"
    log_info "Log file: ${LOG_FILE}"
    log_info "Dry run: ${DRY_RUN}"

    # Ensure results directory exists
    mkdir -p "${RESULTS_DIR}"

    # Step 2: Create empty log file
    mkdir -p "$(dirname "${LOG_FILE}")"
    : > "${LOG_FILE}"
    log_info "Created empty log file: ${LOG_FILE}"

    if [ "${DRY_RUN}" = false ]; then
        # Step 3: Detect library and generate config
        local library_path
        library_path=$(detect_library_path)
        log_info "Detected library: ${library_path}"

        local config_path
        config_path=$(generate_falco_config "${library_path}" "${LOG_FILE}")

        # Step 4: Start Falco
        start_falco "${config_path}"

        # Give Falco a moment to fully initialize the plugin
        sleep 1
    fi

    # Step 5: Inject patterns
    local total
    total=$(inject_all_patterns "${LOG_FILE}")

    if [ "${DRY_RUN}" = true ]; then
        log_info "=== Dry run complete: ${total} patterns would be injected ==="
        exit 0
    fi

    # Step 6: Wait for final pattern processing
    log_info "Waiting 2 seconds for final pattern processing..."
    sleep 2

    # Step 7: Stop Falco
    stop_falco

    # Step 8: Verify results
    if verify_results; then
        log_info "=== E2E injection complete: ${total} patterns injected ==="
        exit 0
    else
        log_error "=== E2E injection completed but verification failed ==="
        exit 3
    fi
}

main "$@"
