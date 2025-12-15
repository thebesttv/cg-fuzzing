#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
IN_DIR="${SCRIPT_DIR}/in"
DICT="${SCRIPT_DIR}/dict"
CMPLOG_BIN="${SCRIPT_DIR}/bin-cmplog"
TARGET_BIN="${SCRIPT_DIR}/bin-fuzz"
mkdir -p "${OUT_DIR}"
echo "=== schedtool AFL++ Fuzzing ==="
AFL_ARGS="-i ${IN_DIR} -o ${OUT_DIR} -x ${DICT} -m none"
if [ -x "${CMPLOG_BIN}" ]; then
    CMPLOG_ARGS="-c ${CMPLOG_BIN}"
fi
afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -- "${TARGET_BIN}" @@
