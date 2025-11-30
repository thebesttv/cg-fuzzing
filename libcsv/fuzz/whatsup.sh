#!/usr/bin/env bash
# Monitor AFL++ fuzzing progress
# Usage: ./whatsup.sh [-w]
#   -w: Watch mode (refresh every 2 seconds)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"

# 检查 afl-whatsup 是否存在
if ! command -v afl-whatsup &> /dev/null; then
    echo "Error: 'afl-whatsup' command not found. Please ensure AFL++ is installed and in your PATH."
    exit 1
fi

# 检查输出目录是否存在
if [ ! -d "${OUT_DIR}" ]; then
    echo "Error: Output directory '${OUT_DIR}' does not exist yet."
    echo "Please start the fuzzing script first."
    exit 1
fi

# 处理参数
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
    # 检查 watch 命令是否存在
    if command -v watch &> /dev/null; then
        echo "Starting watch mode (Press Ctrl+C to exit)..."
        # 使用 watch 命令每 2 秒刷新一次，-c 支持颜色输出
        watch -n 2 -c "afl-whatsup -s ${OUT_DIR}"
    else
        echo "Error: 'watch' command not found. Running once instead."
        afl-whatsup -s "${OUT_DIR}"
    fi
else
    # 单次运行
    echo "=== AFL++ Status Report ==="
    echo "Dir: ${OUT_DIR}"
    echo ""
    # -s 参数表示 summary (摘要)，如果想看详细每个核心的状态，去掉 -s
    afl-whatsup -s "${OUT_DIR}"
fi
