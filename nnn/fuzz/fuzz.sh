#!/usr/bin/env bash
# Fuzzing script for nnn using AFL++
# NOTE: nnn is an interactive terminal file manager, not ideal for AFL++ fuzzing
# This script provides basic fuzzing infrastructure but may not be effective

set -e

echo "WARNING: nnn is an interactive file manager and not well-suited for AFL++ fuzzing."
echo "This fuzzing setup is provided for completeness but may not find meaningful bugs."
echo ""

# --- Default Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
IN_DIR="${SCRIPT_DIR}/in"
DICT="${SCRIPT_DIR}/dict"
CMPLOG_BIN="${SCRIPT_DIR}/nnn.cmplog"
TARGET_BIN="${SCRIPT_DIR}/nnn"
PARALLEL=1

# --- Usage Function ---
usage() {
    echo "Usage: $0 [-j N]"
    echo "  -j N   Number of parallel fuzzers (Default: 1)"
    exit 1
}

# --- Parse Arguments ---
while getopts ":j:" opt; do
  case ${opt} in
    j)
      PARALLEL=${OPTARG}
      ;;
    \?)
      echo "Invalid option: -${OPTARG}" >&2
      usage
      ;;
    :)
      echo "Option -${OPTARG} requires an argument." >&2
      usage
      ;;
  esac
done

# Validate Parallel Number
if ! [[ "$PARALLEL" =~ ^[0-9]+$ ]] || [ "$PARALLEL" -le 0 ]; then
    echo "Error: Parallel count must be an integer > 0."
    exit 1
fi

# Ensure output directory exists
mkdir -p "${OUT_DIR}"

echo "=== nnn AFL++ Fuzzing (Limited Effectiveness) ==="
echo "Target:           ${TARGET_BIN}"
echo "Input corpus:     ${IN_DIR}"
echo "Output directory: ${OUT_DIR}"
echo "Dictionary:       ${DICT}"
echo "Parallel jobs:    ${PARALLEL}"
echo "Memory Limit:     Unlimited (-m none)"
echo ""

# Check for binaries
if [ ! -x "$TARGET_BIN" ]; then
    echo "Error: Target binary not found at $TARGET_BIN"
    exit 1
fi

# Base AFL arguments
AFL_ARGS="-i ${IN_DIR} -o ${OUT_DIR} -x ${DICT} -m none"

# --- Fuzzing Logic ---
if [ "${PARALLEL}" -eq 1 ]; then
    echo "Starting single fuzzer (Interactive Mode)..."
    
    CMPLOG_ARGS=""
    if [ -x "${CMPLOG_BIN}" ]; then
        echo "Enabled CMPLOG."
        CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    fi

    # nnn expects terminal input; fuzzing via stdin may not be effective
    afl-fuzz \
        ${AFL_ARGS} \
        ${CMPLOG_ARGS} \
        -- "${TARGET_BIN}" < @@

else
    echo "Starting parallel fuzzers..."
    pids=()
    trap 'echo "Stopping all fuzzers..."; kill ${pids[@]} 2>/dev/null; wait; exit' SIGINT SIGTERM

    CMPLOG_ARGS=""
    if [ -x "${CMPLOG_BIN}" ]; then
        CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    fi

    echo "[+] Starting Master fuzzer..."
    afl-fuzz \
        ${AFL_ARGS} \
        ${CMPLOG_ARGS} \
        -M main \
        -- "${TARGET_BIN}" < @@ >/dev/null 2>&1 &
    pids+=($!)
    sleep 2

    for i in $(seq 1 $((PARALLEL - 1))); do
        echo "[+] Starting Slave fuzzer #$i..."
        afl-fuzz \
            ${AFL_ARGS} \
            -S "slave${i}" \
            -- "${TARGET_BIN}" < @@ >/dev/null 2>&1 &
        pids+=($!)
    done

    echo ""
    echo "All ${PARALLEL} fuzzers are running in background."
    echo "Press Ctrl+C to stop all instances."
    wait
fi
