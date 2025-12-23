#!/usr/bin/env bash

# ================= 配置 =================
TARGET_BINARY="./bin-cov"
JOBS=1  # 默认值

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -j*)
            JOBS="${1#-j}"
            shift
            ;;
        *)
            if [ -z "$FINDINGS_DIR" ]; then
                FINDINGS_DIR="$1"
            else
                OUTPUT_DIR="$1"
            fi
            shift
            ;;
    esac
done

# 检查参数是否被设定
if [ -z "$FINDINGS_DIR" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <FINDINGS_DIR> <OUTPUT_DIR> [-jN]"
    echo "  FINDINGS_DIR: Directory containing input files"
    echo "  OUTPUT_DIR: Directory for output profiles"
    echo "  -jN: Number of parallel jobs (default: 1)"
    exit 1
fi

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

mkdir -p "$OUTPUT_DIR"

# 定义处理单个输入的函数
process_one_to_one() {
    local input_path="$1"

    # filename without directory
    local safe_name=$(basename "$input_path")

    # 定义文件名
    local profraw_file="$OUTPUT_DIR/${safe_name}.profraw"
    local profdata_file="$OUTPUT_DIR/${safe_name}.profdata"

    # 2. 运行并生成 .profraw
    export LLVM_PROFILE_FILE="$profraw_file"
    # cmark / capstone
    # "$TARGET_BINARY" "$input_path" >/dev/null 2>&1
    # bison
    # "$TARGET_BINARY" -o /dev/null "$input_path" >/dev/null 2>&1
    # yasm
    "$TARGET_BINARY" -f elf -o /dev/null "$input_path" >/dev/null 2>&1

    # 3. 检查是否生成了 .profraw (有些 crash 可能导致未生成)
    if [ -f "$profraw_file" ]; then
        # 4. 转换为 .profdata
        # -sparse 选项非常重要，能显著减小单个文件体积
        llvm-profdata${LLVM_SUFFIX} merge -sparse "$profraw_file" -o "$profdata_file"

        rm "$profraw_file"
    fi
}

export TARGET_BINARY OUTPUT_DIR LLVM_SUFFIX
export -f process_one_to_one

echo "Starting individual coverage generation..."
echo "Output directory: $OUTPUT_DIR"

# 并行执行
find "$FINDINGS_DIR" -type f | \
    parallel --bar -j "$JOBS" process_one_to_one {}
