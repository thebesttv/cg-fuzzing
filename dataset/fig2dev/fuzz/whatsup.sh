#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
if ! command -v afl-whatsup &> /dev/null; then
    echo "Error: afl-whatsup not found"
    exit 1
fi
[ ! -d "${OUT_DIR}" ] && echo "Error: ${OUT_DIR} does not exist" && exit 1
WATCH_MODE=0
[ "$1" = "-w" ] && WATCH_MODE=1
if [ "${WATCH_MODE}" -eq 1 ]; then
    [ -x "$(command -v watch)" ] && watch -n 2 -c "afl-whatsup -s ${OUT_DIR}" || afl-whatsup -s "${OUT_DIR}"
else
    afl-whatsup -s "${OUT_DIR}"
fi
