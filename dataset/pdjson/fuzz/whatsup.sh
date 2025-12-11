#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
command -v afl-whatsup &>/dev/null || { echo "Error: afl-whatsup not found"; exit 1; }
[ -d "${OUT_DIR}" ] || { echo "Error: Output dir not found"; exit 1; }
afl-whatsup -s "${OUT_DIR}"
