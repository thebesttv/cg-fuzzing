#!/usr/bin/env bash
# Monitor AFL++ fuzzing progress
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"

if ! command -v afl-whatsup &> /dev/null; then
    echo "Error: 'afl-whatsup' not found."
    exit 1
fi

if [ ! -d "${OUT_DIR}" ]; then
    echo "Error: Output directory '${OUT_DIR}' does not exist."
    exit 1
fi

if [ "$1" = "-w" ]; then
    watch -n 2 -c "afl-whatsup -s ${OUT_DIR}"
else
    afl-whatsup -s "${OUT_DIR}"
fi
