#!/usr/bin/env bash
set -euo pipefail

# 1. 创建临时目录，并确保脚本退出时自动清理 (无论成功/失败/中断)
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# 防止无声失败：遇到未捕获的错误时打印行号
trap 'echo "Error: Script failed unexpectedly on line $LINENO"' ERR

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR="$ROOT_DIR/tests"
GO_SH="$ROOT_DIR/go.sh"
COLLECT_PY="$ROOT_DIR/collect-branch.py"

# 检查依赖
if [[ ! -x "$GO_SH" ]]; then
  echo "Error: go.sh not found or not executable at $GO_SH" >&2
  exit 2
fi
if [[ ! -f "$COLLECT_PY" ]]; then
  echo "Error: collect-branch.py not found at $COLLECT_PY" >&2
  exit 2
fi

shopt -s nullglob

total=0
passed=0
failed=0
skipped=0

echo "Running coverage tests in $TEST_DIR"

for cov in "$TEST_DIR"/*.cov; do
  [[ -e "$cov" ]] || continue
  name="$(basename "$cov" .cov)"

  echo "Testing coverage binary: $name"

  # 查找输入文件
  candidate_inputs=("$TEST_DIR/${name}.in."*)
  inputs=()
  for entry in "${candidate_inputs[@]}"; do
    base="$(basename "$entry")"
    suffix="${base#${name}.in.}"
    # 确保后缀是纯数字
    if [[ "$base" == "${name}.in."* && "$suffix" =~ ^[0-9]+$ ]]; then
      inputs+=("$entry")
    fi
  done

  if [[ ${#inputs[@]} -eq 0 ]]; then
    echo "  No inputs found for $name, skipping"
    skipped=$((skipped + 1))
    continue
  fi

  # 排序输入文件 (自然排序)
  IFS=$'\n' sorted_inputs=($(sort -V <<<"${inputs[*]}"))
  unset IFS

  echo "  Found ${#sorted_inputs[@]} inputs for $name"

  for input in "${sorted_inputs[@]}"; do
    input_name="$(basename "$input")"
    input_suffix="${input_name#${name}.in.}"

    # --- 关键修改：所有中间文件都放在临时目录 WORK_DIR 中 ---
    # default.json 通常由 go.sh 在当前目录生成，我们需要处理它
    json_path="$ROOT_DIR/default.json"

    # 临时文件路径
    actual_csv="$WORK_DIR/${name}.${input_suffix}.actual.csv"
    diff_temp="$WORK_DIR/${name}.${input_suffix}.diff"
    log_file="$WORK_DIR/${name}.${input_suffix}.log"

    expected_base="$TEST_DIR/${name}.out.${input_suffix}"

    # 计数器安全递增
    total=$((total + 1))

    echo "  Processing input: $input_name"

    # 清理可能存在的旧 json (防止读取上次运行的结果)
    rm -f "$json_path"

    # 1. 运行 go.sh (日志重定向到临时文件)
    if (cd "$ROOT_DIR" && "$GO_SH" "$cov" < "$input" > "$log_file" 2>&1); then
      if [[ ! -f "$json_path" ]]; then
        echo "    ✗ Error: go.sh succeeded but '$json_path' was not created." >&2
        echo "      Log content:" >&2
        sed 's/^/      /' "$log_file" >&2
        failed=$((failed + 1))
        continue
      fi
    else
      echo "    ✗ Error: go.sh failed for $input" >&2
      echo "      Log content:" >&2
      sed 's/^/      /' "$log_file" >&2
      failed=$((failed + 1))
      continue
    fi

    # 2. 运行 collect-branch.py (输出到临时 CSV)
    if ! python3 "$COLLECT_PY" "$json_path" -o "$actual_csv" >> "$log_file" 2>&1; then
      echo "    ✗ Error: collect-branch.py failed for $input" >&2
      echo "      Log content:" >&2
      sed 's/^/      /' "$log_file" >&2
      # 清理 json 防止污染
      rm -f "$json_path"
      failed=$((failed + 1))
      continue
    fi

    # 既然已经转成了 CSV，删除 default.json 保持目录整洁
    rm -f "$json_path"

    # 3. 确定期望输出文件
    if [[ -f "$expected_base" ]]; then
      expected="$expected_base"
    elif [[ -f "${expected_base}.csv" ]]; then
      expected="${expected_base}.csv"
    else
      echo "    ✗ Error: expected output not found for $input" >&2
      failed=$((failed + 1))
      continue
    fi

    # 4. 对比结果 (Diff 输出到临时文件)
    if diff -u "$expected" "$actual_csv" > "$diff_temp"; then
      echo "    ✔ $input_name matches expected"
      passed=$((passed + 1))
    else
      # Diff 返回非0，说明有差异 (或者 diff 命令出错)
      diff_status=$?
      if [[ $diff_status -eq 1 ]]; then
        echo "    ✗ Mismatch for $input_name. Diff output:"
        echo "---------------------------------------------------"
        # 直接打印 Diff 内容，不保留文件
        cat "$diff_temp"
        echo "---------------------------------------------------"
        failed=$((failed + 1))
      else
        echo "    ✗ Error: diff command failed (exit code $diff_status)" >&2
        failed=$((failed + 1))
      fi
    fi
  done
done

echo
echo "Summary: total=$total passed=$passed failed=$failed skipped=$skipped"

# 解除 ERR trap，避免 exit 0 被误报
trap - ERR

if [[ $failed -gt 0 ]]; then
  exit 1
else
  exit 0
fi
