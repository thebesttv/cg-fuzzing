#!/bin/bash
# Fuzzing script for jq using AFL++
# This script fuzzes the jq CLI binary using JSON input

set -e

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
IN_DIR="${SCRIPT_DIR}/in"
DICT="${SCRIPT_DIR}/dict"

# Create output directory if needed
mkdir -p "${OUT_DIR}"

# Number of parallel fuzzers (adjust based on available CPUs)
PARALLEL=${AFL_PARALLEL:-1}

echo "=== jq AFL++ Fuzzing ==="
echo "Input corpus: ${IN_DIR}"
echo "Output directory: ${OUT_DIR}"
echo "Dictionary: ${DICT}"
echo "Parallel fuzzers: ${PARALLEL}"
echo ""

# Fuzzing the jq binary with a simple filter
# The input is JSON data that jq will parse and process
# Using '.' filter which just pretty-prints JSON

if [ "${PARALLEL}" -eq 1 ]; then
    # Single fuzzer with CMPLOG
    echo "Starting single fuzzer with CMPLOG..."
    afl-fuzz \
        -i "${IN_DIR}" \
        -o "${OUT_DIR}" \
        -x "${DICT}" \
        -c "${SCRIPT_DIR}/jq.cmplog" \
        -- "${SCRIPT_DIR}/jq" '.' @@
else
    # Master fuzzer
    echo "Starting master fuzzer..."
    afl-fuzz \
        -i "${IN_DIR}" \
        -o "${OUT_DIR}" \
        -x "${DICT}" \
        -c "${SCRIPT_DIR}/jq.cmplog" \
        -M main \
        -- "${SCRIPT_DIR}/jq" '.' @@ &

    # Wait a bit for master to initialize
    sleep 2

    # Secondary fuzzers
    for i in $(seq 2 ${PARALLEL}); do
        echo "Starting secondary fuzzer ${i}..."
        afl-fuzz \
            -i "${IN_DIR}" \
            -o "${OUT_DIR}" \
            -x "${DICT}" \
            -S "secondary${i}" \
            -- "${SCRIPT_DIR}/jq" '.' @@ &
    done

    echo ""
    echo "All fuzzers started. Press Ctrl+C to stop."
    wait
fi
