#!/bin/bash

# ================= 配置 =================
TARGET_BINARY="./jq-cov"
FINDINGS_DIR="findings"
OUTPUT_DIR="profiles"
# JOBS=$(nproc)
JOBS=3
# =======================================

# 检查 binary
if [ ! -f "$TARGET_BINARY" ]; then
    echo "Error: Binary '$TARGET_BINARY' not found!"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# 定义处理单个输入的函数
process_one_to_one() {
    local input_path="$1"

    # 1. 生成唯一标识名 (把路径里的 / 换成 _)
    local safe_name=$(echo "$input_path" | tr '/' '_')

    # 定义文件名
    local profraw_file="$OUTPUT_DIR/${safe_name}.profraw"
    local profdata_file="$OUTPUT_DIR/${safe_name}.profdata"
    local coverage_file="$OUTPUT_DIR/${safe_name}.csv"

    # 2. 运行并生成 .profraw
    export LLVM_PROFILE_FILE="$profraw_file"
    "$TARGET_BINARY" . "$input_path" > /dev/null 2>&1

    # 3. 检查是否生成了 .profraw (有些 crash 可能导致未生成)
    if [ -f "$profraw_file" ]; then
        # 4. 转换为 .profdata
        # -sparse 选项非常重要，能显著减小单个文件体积
        llvm-profdata merge -sparse "$profraw_file" -o "$profdata_file"

        llvm-cov export -format=text "$TARGET_BINARY" -instr-profile="$profdata_file" | \
            python3 collect-branch.py -o "$coverage_file"

        # 5. 删除中间产物
        rm -f "$profraw_file" "$profdata_file"
    fi
}

export TARGET_BINARY OUTPUT_DIR
export -f process_one_to_one

echo "Starting individual coverage generation..."
echo "Output directory: $OUTPUT_DIR"

# 并行执行
find "$FINDINGS_DIR" -path "*/queue/id:*" -type f | \
    parallel --bar -j "$JOBS" process_one_to_one {}
