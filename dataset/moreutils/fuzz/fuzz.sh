#!/usr/bin/env bash
# Fuzzing script for moreutils using AFL++

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
IN_DIR="${SCRIPT_DIR}/in"
DICT="${SCRIPT_DIR}/dict"
CMPLOG_BIN="${SCRIPT_DIR}/bin-cmplog"
TARGET_BIN="${SCRIPT_DIR}/bin-fuzz"
PARALLEL=1

usage() {
    echo "Usage: $0 [-j N]"
    echo "  -j N   Number of parallel fuzzers (Default: 1)"
    exit 1
}

while getopts ":j:" opt; do
  case ${opt} in
    j) PARALLEL=${OPTARG} ;;
    \?) echo "Invalid option: -${OPTARG}" >&2; usage ;;
    :) echo "Option -${OPTARG} requires an argument." >&2; usage ;;
  esac
done

if ! [[ "$PARALLEL" =~ ^[0-9]+$ ]] || [ "$PARALLEL" -le 0 ]; then
    echo "Error: Parallel count must be an integer > 0."
    exit 1
fi

mkdir -p "${OUT_DIR}"

echo "=== moreutils (pee) AFL++ Fuzzing ==="
echo "Target:           ${TARGET_BIN}"
echo "Input corpus:     ${IN_DIR}"
echo "Output directory: ${OUT_DIR}"
echo "Dictionary:       ${DICT}"
echo "Parallel jobs:    ${PARALLEL}"
echo ""

if [ ! -x "$TARGET_BIN" ]; then
    echo "Error: Target binary not found at $TARGET_BIN"
    exit 1
fi

AFL_ARGS="-i ${IN_DIR} -o ${OUT_DIR} -x ${DICT} -m none"

if [ "${PARALLEL}" -eq 1 ]; then
    echo "Starting single fuzzer (Interactive Mode)..."
    CMPLOG_ARGS=""
    if [ -x "${CMPLOG_BIN}" ]; then
        echo "Enabled CMPLOG."
        CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    fi

    afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -- "${TARGET_BIN}" cat
else
    echo "Starting parallel fuzzers..."
    pids=()
    trap 'echo "Stopping all fuzzers..."; kill ${pids[@]} 2>/dev/null; wait; exit' SIGINT SIGTERM

    CMPLOG_ARGS=""
    if [ -x "${CMPLOG_BIN}" ]; then
        CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    fi

    echo "[+] Starting Master fuzzer..."
    afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -M main -- "${TARGET_BIN}" cat >/dev/null 2>&1 &
    pids+=($!)
    sleep 2

    for i in $(seq 1 $((PARALLEL - 1))); do
        echo "[+] Starting Slave fuzzer #$i..."
        afl-fuzz ${AFL_ARGS} -S "slave${i}" -- "${TARGET_BIN}" cat >/dev/null 2>&1 &
        pids+=($!)
    done

    echo ""
    echo "All ${PARALLEL} fuzzers are running in background."
    echo "Press Ctrl+C to stop all instances."
    wait
fi
