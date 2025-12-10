#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"

if ! command -v afl-whatsup &> /dev/null; then
    echo "Error: 'afl-whatsup' not found"
    exit 1
fi

if [ ! -d "${OUT_DIR}" ]; then
    echo "Error: Output directory does not exist"
    exit 1
fi

WATCH_MODE=0
while getopts ":w" opt; do
  case ${opt} in
    w) WATCH_MODE=1 ;;
  esac
done

if [ "${WATCH_MODE}" -eq 1 ] && command -v watch &> /dev/null; then
    watch -n 2 -c "afl-whatsup -s ${OUT_DIR}"
else
    afl-whatsup -s "${OUT_DIR}"
fi
