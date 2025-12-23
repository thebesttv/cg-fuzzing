#!/usr/bin/env bash

# ================= 配置 =================
TARGET_BINARY="./bin-cov"
OUTPUT_DIR="/out/minimized_profiles"
# OUTPUT_DIR="/out/raw_profiles"
# JOBS=$(nproc)
JOBS=64

LLVM_SUFFIX=""
if [ "$IS_DOCKER" = "1" ]; then
    LLVM_SUFFIX="-${LLVM_VERSION}"
fi
# =======================================

# 检查 binary
if [ ! -f "$TARGET_BINARY" ]; then
    echo "Error: Binary '$TARGET_BINARY' not found!"
    exit 1
fi

# 检查 profiles 目录
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Error: Directory '$OUTPUT_DIR' not found!"
    exit 1
fi

# 定义处理单个 profdata 的函数
process_profdata() {
    local profdata_file="$1"

    # 提取基础名称（不含扩展名）
    local base_name=$(basename "$profdata_file" .profdata)
    local coverage_file="$OUTPUT_DIR/${base_name}.csv"

    # 生成 CSV 覆盖率报告
    llvm-cov${LLVM_SUFFIX} export -format=text "$TARGET_BINARY" -instr-profile="$profdata_file" | \
        python3 collect-branch.py -o "$coverage_file"

    # 删除 profdata 文件
    if [ -f "$coverage_file" ]; then
        rm "$profdata_file"
    fi
}

export TARGET_BINARY OUTPUT_DIR LLVM_SUFFIX
export -f process_profdata

echo "Starting branch coverage generation..."
echo "Processing .profdata files in: $OUTPUT_DIR"

# 并行处理所有 .profdata 文件
find "$OUTPUT_DIR" -name "*.profdata" -type f | \
    parallel --bar -j "$JOBS" process_profdata {}

echo "Done! CSV files generated in $OUTPUT_DIR"
