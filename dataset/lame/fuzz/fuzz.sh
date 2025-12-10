#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
IN_DIR="${SCRIPT_DIR}/in"
DICT="${SCRIPT_DIR}/dict"
CMPLOG_BIN="${SCRIPT_DIR}/lame.cmplog"
TARGET_BIN="${SCRIPT_DIR}/lame"
PARALLEL=1

while getopts ":j:" opt; do
  case ${opt} in
    j) PARALLEL=${OPTARG} ;;
  esac
done

mkdir -p "${OUT_DIR}"
AFL_ARGS="-i ${IN_DIR} -o ${OUT_DIR} -x ${DICT} -m none"

if [ "${PARALLEL}" -eq 1 ]; then
    CMPLOG_ARGS=""
    [ -x "${CMPLOG_BIN}" ] && CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -- "${TARGET_BIN}" @@ /dev/null
else
    pids=()
    trap 'kill ${pids[@]} 2>/dev/null; wait; exit' SIGINT SIGTERM
    CMPLOG_ARGS=""
    [ -x "${CMPLOG_BIN}" ] && CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -M main -- "${TARGET_BIN}" @@ /dev/null >/dev/null 2>&1 &
    pids+=($!)
    sleep 2
    for i in $(seq 1 $((PARALLEL - 1))); do
        afl-fuzz ${AFL_ARGS} -S "slave${i}" -- "${TARGET_BIN}" @@ /dev/null >/dev/null 2>&1 &
        pids+=($!)
    done
    wait
fi
