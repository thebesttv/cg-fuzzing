#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
IN_DIR="${SCRIPT_DIR}/in"
DICT="${SCRIPT_DIR}/dict"
CMPLOG_BIN="${SCRIPT_DIR}/minicom.cmplog"
TARGET_BIN="${SCRIPT_DIR}/minicom"
PARALLEL=1

mkdir -p "${OUT_DIR}"
AFL_ARGS="-i ${IN_DIR} -o ${OUT_DIR} -x ${DICT} -m none"

if [ "${PARALLEL}" -eq 1 ]; then
    CMPLOG_ARGS=""
    if [ -x "${CMPLOG_BIN}" ]; then
        CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    fi
    afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -- "${TARGET_BIN}" -S @@
else
    echo "Parallel mode not implemented yet"
fi
