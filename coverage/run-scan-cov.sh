#!/bin/bash

# 获取当前脚本所在的绝对目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 设定 scan-cov.py 的绝对路径
SCAN_SCRIPT="${SCRIPT_DIR}/scan-cov.py"

# 1. 设定默认并发数
JOBS=1

# 2. 解析命令行选项 (-j)
# getopts "j:" 可以同时处理 -j8 和 -j 8 两种格式
while getopts "j:" opt; do
  case $opt in
    j)
      # 验证 -j 的参数必须是正整数
      if [[ ! "$OPTARG" =~ ^[0-9]+$ ]]; then
          echo "Error: Invalid argument for -j. Must be a positive integer." >&2
          echo "Usage: $0 [-jN] <bc_dir> <profiles_dir>"
          exit 1
      fi
      JOBS=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

# 移除已解析的选项，只保留位置参数
shift $((OPTIND-1))

# 3. 检查位置参数
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 [-jN] <bc_dir> <profiles_dir>"
    echo "Example: $0 -j8 ./data/bc_files ./data/profiles"
    exit 1
fi

BC_DIR="$1"
PROFILES_DIR="$2"

# 检查 parallel 是否安装
if ! command -v parallel &> /dev/null; then
    echo "Error: GNU parallel is not installed."
    exit 1
fi

# 检查扫描脚本是否存在
if [ ! -f "$SCAN_SCRIPT" ]; then
    echo "Error: $SCAN_SCRIPT not found."
    exit 1
fi

echo "Scanning files and generating job list for ${JOBS} parallel job(s)..."

# 4. 遍历与生成任务
find "$BC_DIR" -mindepth 3 -maxdepth 3 -path "*/bc/*.json" | while read -r json_file; do

    # 解析路径变量
    bc_subdir=$(dirname "$json_file")
    proj_dir=$(dirname "$bc_subdir")
    proj_name=$(basename "$proj_dir")
    bin_name=$(basename "$json_file" .json)

    covout_file="${bc_subdir}/${bin_name}.covout"
    target_prof_dir="${PROFILES_DIR}/${proj_name}/profiles"

    # 检查前提条件：目录存在 且 包含 .csv 文件
    if [ -d "$target_prof_dir" ]; then
        if find "$target_prof_dir" -maxdepth 1 -name "*.csv" -print -quit | grep -q .; then
            cmd="${SCAN_SCRIPT} \"${json_file}\" \"${target_prof_dir}/\" --project \"${proj_name}\" | tee \"${covout_file}\""
            echo "$cmd"
        fi
    fi
# 5. 执行
done | cat # parallel -j "$JOBS" --bar
