#!/usr/bin/env bash
# Fuzzing script for cJSON using AFL++
# Optimized: Parallel execution support (-j), unlimited memory, cleanup handling.

set -e

# --- Default Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
IN_DIR="${SCRIPT_DIR}/in"
DICT="${SCRIPT_DIR}/dict"
CMPLOG_BIN="${SCRIPT_DIR}/bin-cmplog"
TARGET_BIN="${SCRIPT_DIR}/bin-fuzz"
PARALLEL=1

# --- Usage Function ---
usage() {
    echo "Usage: $0 [-j N]"
    echo "  -j N   Number of parallel fuzzers (Default: 1)"
    echo "         If N=1: Runs in foreground with TUI."
    echo "         If N>1: Runs in background (headless) with 1 Master and N-1 Slaves."
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

echo "=== cJSON AFL++ Fuzzing ==="
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
# -m none: No memory limit
AFL_ARGS="-i ${IN_DIR} -o ${OUT_DIR} -x ${DICT} -m none"

# --- Fuzzing Logic ---

if [ "${PARALLEL}" -eq 1 ]; then
    # === Serial Mode (Interactive TUI) ===
    echo "Starting single fuzzer (Interactive Mode)..."

    # Check if cmplog binary exists
    CMPLOG_ARGS=""
    if [ -x "${CMPLOG_BIN}" ]; then
        echo "Enabled CMPLOG."
        CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    fi

    afl-fuzz \
        ${AFL_ARGS} \
        ${CMPLOG_ARGS} \
        -- "${TARGET_BIN}" @@

else
    # === Parallel Mode (Headless) ===
    echo "Starting parallel fuzzers..."
    echo "Mode: 1 Master + $((PARALLEL - 1)) Slaves"
    echo "Logs are suppressed. Use 'afl-whatsup ${OUT_DIR}' to monitor progress."

    # Trap Ctrl+C (SIGINT) to kill all background processes
    pids=()
    trap 'echo "Stopping all fuzzers..."; kill ${pids[@]} 2>/dev/null; wait; exit' SIGINT SIGTERM

    # 1. Start Master (Main)
    # Master handles CMPLOG (if available) and deterministic checks
    CMPLOG_ARGS=""
    if [ -x "${CMPLOG_BIN}" ]; then
        CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    fi

    echo "[+] Starting Master fuzzer..."
    afl-fuzz \
        ${AFL_ARGS} \
        ${CMPLOG_ARGS} \
        -M main \
        -- "${TARGET_BIN}" @@ >/dev/null 2>&1 &

    pids+=($!)

    # Give master a moment to initialize structure
    sleep 2

    # 2. Start Slaves (Secondary)
    # Slaves focus on throughput/havoc, usually don't need CMPLOG to save CPU
    for i in $(seq 1 $((PARALLEL - 1))); do
        echo "[+] Starting Slave fuzzer #$i..."
        afl-fuzz \
            ${AFL_ARGS} \
            -S "slave${i}" \
            -- "${TARGET_BIN}" @@ >/dev/null 2>&1 &

        pids+=($!)
    done

    echo ""
    echo "All ${PARALLEL} fuzzers are running in background."
    echo "PID list: ${pids[@]}"
    echo "Press Ctrl+C to stop all instances."

    # Wait indefinitely for children
    wait
fi
