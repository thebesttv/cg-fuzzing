#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
IN_DIR="${SCRIPT_DIR}/in"
DICT="${SCRIPT_DIR}/dict"
CMPLOG_BIN="${SCRIPT_DIR}/test_ssh.cmplog"
TARGET_BIN="${SCRIPT_DIR}/test_ssh"
PARALLEL=1

usage() {
    echo "Usage: $0 [-j N]"
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

echo "=== libssh AFL++ Fuzzing ==="
echo "Target: ${TARGET_BIN}"
echo "Parallel jobs: ${PARALLEL}"

if [ ! -x "$TARGET_BIN" ]; then
    echo "Error: Target binary not found"
    exit 1
fi

AFL_ARGS="-i ${IN_DIR} -o ${OUT_DIR} -x ${DICT} -m none"

if [ "${PARALLEL}" -eq 1 ]; then
    CMPLOG_ARGS=""
    [ -x "${CMPLOG_BIN}" ] && CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -- "${TARGET_BIN}" @@
else
    pids=()
    trap 'kill ${pids[@]} 2>/dev/null; wait; exit' SIGINT SIGTERM
    
    CMPLOG_ARGS=""
    [ -x "${CMPLOG_BIN}" ] && CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -M main -- "${TARGET_BIN}" @@ >/dev/null 2>&1 &
    pids+=($!)
    sleep 2
    
    for i in $(seq 1 $((PARALLEL - 1))); do
        afl-fuzz ${AFL_ARGS} -S "slave${i}" -- "${TARGET_BIN}" @@ >/dev/null 2>&1 &
        pids+=($!)
    done
    
    echo "All ${PARALLEL} fuzzers running. Press Ctrl+C to stop."
    wait
fi
