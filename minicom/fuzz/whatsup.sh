#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
if ! command -v afl-whatsup &> /dev/null; then
    echo "Error: afl-whatsup not found"
    exit 1
fi
if [ ! -d "${OUT_DIR}" ]; then
    echo "Error: Output directory does not exist"
    exit 1
fi
afl-whatsup -s "${OUT_DIR}"
