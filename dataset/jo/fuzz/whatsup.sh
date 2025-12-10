#!/usr/bin/env bash
# Monitor AFL++ fuzzing progress
# Usage: ./whatsup.sh [-w]
#   -w: Watch mode (refresh every 2 seconds)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"

# Check if afl-whatsup exists
if ! command -v afl-whatsup &> /dev/null; then
    echo "Error: 'afl-whatsup' command not found. Please ensure AFL++ is installed and in your PATH."
    exit 1
fi

# Check if output directory exists
if [ ! -d "${OUT_DIR}" ]; then
    echo "Error: Output directory '${OUT_DIR}' does not exist yet."
    echo "Please start the fuzzing script first."
    exit 1
fi

# Parse arguments
WATCH_MODE=0

while getopts ":w" opt; do
  case ${opt} in
    w)
      WATCH_MODE=1
      ;;
    \?)
      echo "Invalid option: -${OPTARG}" >&2
      exit 1
      ;;
  esac
done

if [ "${WATCH_MODE}" -eq 1 ]; then
    # Check if watch command exists
    if command -v watch &> /dev/null; then
        echo "Starting watch mode (Press Ctrl+C to exit)..."
        # Use watch command to refresh every 2 seconds, -c for color output
        watch -n 2 -c "afl-whatsup -s ${OUT_DIR}"
    else
        echo "Error: 'watch' command not found. Running once instead."
        afl-whatsup -s "${OUT_DIR}"
    fi
else
    # Single run
    echo "=== AFL++ Status Report ==="
    echo "Dir: ${OUT_DIR}"
    echo ""
    # -s parameter means summary, remove -s for detailed per-core status
    afl-whatsup -s "${OUT_DIR}"
fi
