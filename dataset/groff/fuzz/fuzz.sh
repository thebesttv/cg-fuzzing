#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AFL_ARGS="-i ${SCRIPT_DIR}/in -o ${SCRIPT_DIR}/findings -x ${SCRIPT_DIR}/dict -m none"
CMPLOG_ARGS=""
[ -x "${SCRIPT_DIR}/groff.cmplog" ] && CMPLOG_ARGS="-c ${SCRIPT_DIR}/groff.cmplog"
afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -- "${SCRIPT_DIR}/groff" -Tascii @@
