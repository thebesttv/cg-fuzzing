#!/usr/bin/env bash
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
echo "=== calc AFL++ Fuzzing ==="
echo "Target: ${TARGET_BIN}"
echo "Input corpus: ${IN_DIR}"
echo "Output directory: ${OUT_DIR}"

if [ ! -x "$TARGET_BIN" ]; then
    echo "Error: Target binary not found"
    exit 1
fi

# Enable autoresume to allow resuming fuzzing sessions
export AFL_AUTORESUME=1

AFL_ARGS="-i ${IN_DIR} -o ${OUT_DIR} -x ${DICT} -m none -V 172800"

if [ "${PARALLEL}" -eq 1 ]; then
    CMPLOG_ARGS=""
    [ -x "${CMPLOG_BIN}" ] && CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -- "${TARGET_BIN}" -f @@
else
    pids=()
    trap 'kill ${pids[@]} 2>/dev/null; wait; exit' SIGINT SIGTERM
    
    CMPLOG_ARGS=""
    [ -x "${CMPLOG_BIN}" ] && CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    
    afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -M main -- "${TARGET_BIN}" -f @@ >/dev/null 2>&1 &
    pids+=($!)
    sleep 2
    
    for i in $(seq 1 $((PARALLEL - 1))); do
        afl-fuzz ${AFL_ARGS} -S "slave${i}" -- "${TARGET_BIN}" -f @@ >/dev/null 2>&1 &
        pids+=($!)
    done
    
    echo "All ${PARALLEL} fuzzers running. Press Ctrl+C to stop."
    wait
fi
