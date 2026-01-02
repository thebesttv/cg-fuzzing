#!/usr/bin/env python3
import os
import json
import argparse
import random
import sys
from pathlib import Path

def parse_sort_value(value):
    """
    尝试将值转换为数字以便排序。
    支持整数、浮点数以及带 '%' 的百分比字符串。
    """
    if isinstance(value, (int, float)):
        return value

    if isinstance(value, str):
        if value.endswith('%'):
            try:
                return float(value.rstrip('%'))
            except ValueError:
                pass
        try:
            return float(value)
        except ValueError:
            pass

    return -float('inf')

def suggest_keys_and_exit(files):
    """
    随机读取部分文件，提取可用的 statistics keys 并打印，然后退出。
    """
    sample_count = min(len(files), 5)
    # 随机采样文件
    sampled_files = random.sample(files, sample_count)

    found_keys = set()

    print(f"错误: 未提供排序 Key。")
    print(f"正在随机检查 {sample_count} 个文件以寻找可用 Key...\n")

    for file_path in sampled_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                stats = data.get("statistics", {})
                # 将发现的 key 加入集合
                found_keys.update(stats.keys())
        except Exception:
            # 忽略采样过程中的读取错误
            continue

    if found_keys:
        print("在 .covout 文件中发现以下可用 Key (statistics):")
        print("-" * 40)
        for k in sorted(found_keys):
            print(f"  {k}")
        print("-" * 40)
        print("\n请选择一个 Key 并重试。例如:")
        print(f"python script.py <folder> \"{list(found_keys)[0]}\"")
    else:
        print("未能从采样文件中提取到任何 statistics key。")

    # 报错退出
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="递归查找 .covout 文件并根据 statistics 中的 key 进行排序。")

    # 位置参数
    parser.add_argument("folder", type=str, help="要搜索的文件夹路径")
    # key 变为可选参数 (nargs='?')
    parser.add_argument("key", type=str, nargs='?', help="statistics 中用于排序的 key (例如 'Total nodes')。如果不填，将列出可用 key。")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--inc", action="store_true", help="按升序排序 (从小到大)")
    group.add_argument("--dec", action="store_true", default=True, help="按降序排序 (从大到小, 默认)")

    args = parser.parse_args()

    target_folder = Path(args.folder)
    if not target_folder.exists():
        print(f"错误: 文件夹 '{args.folder}' 不存在。")
        sys.exit(1)

    # 1. 先查找文件
    print(f"正在 '{args.folder}' 中搜索 .covout 文件...")
    files = list(target_folder.rglob("*.covout"))

    if not files:
        print("未找到任何 .covout 文件。")
        sys.exit(0)

    # 2. 如果没有提供 Key，执行“提示并退出”逻辑
    if not args.key:
        suggest_keys_and_exit(files)

    # 3. 如果提供了 Key，执行正常的排序逻辑
    reverse_order = not args.inc
    results = []

    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                stats = data.get("statistics", {})

                raw_value = stats.get(args.key)

                if raw_value is None:
                    sort_value = -float('inf')
                else:
                    sort_value = parse_sort_value(raw_value)

                results.append({
                    "filename": file_path.name,
                    "fullpath": str(file_path),
                    "statistics": stats,
                    "sort_value": sort_value,
                    "raw_value": raw_value
                })

        except json.JSONDecodeError:
            print(f"警告: 文件 '{file_path.name}' 不是有效的 JSON 格式，已跳过。")
        except Exception as e:
            print(f"警告: 处理文件 '{file_path.name}' 时出错: {e}")

    # 排序
    results.sort(key=lambda x: x["sort_value"], reverse=reverse_order)

    print(f"\n找到 {len(results)} 个文件，按 '{args.key}' {'降序' if reverse_order else '升序'} 排列:\n")
    print("=" * 60)

    for item in results:
        print(f"文件名: {item['fullpath']}")
        print(f"排序依据 ({args.key}): {item['raw_value']}")
        print("Statistics 内容:")
        stats_str = json.dumps(item['statistics'], indent=4, ensure_ascii=False)
        print(stats_str)
        print("-" * 60)

if __name__ == "__main__":
    main()
