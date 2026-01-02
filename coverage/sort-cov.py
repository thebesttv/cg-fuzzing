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

    # 无法转换的值赋予极小值，排在最后
    return -float('inf')

def suggest_keys_and_exit(files):
    """
    随机读取部分文件，提取可用的 statistics keys 并打印，然后退出。
    注意：这里不再对 keys 进行排序。
    """
    sample_count = min(len(files), 5)
    sampled_files = random.sample(files, sample_count)

    found_keys = set()

    print(f"错误: 未提供排序 Key。")
    print(f"正在随机检查 {sample_count} 个文件以寻找可用 Key...\n")

    for file_path in sampled_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                stats = data.get("statistics", {})
                found_keys.update(stats.keys())
        except Exception:
            continue

    if found_keys:
        print("在 .covout 文件中发现以下可用 Key (statistics):")
        print("-" * 40)
        # 直接转为列表显示，不使用 sorted()
        for k in list(found_keys):
            print(f"  {k}")
        print("-" * 40)
        print("\n请选择一个 Key 并重试。例如:")
        # 随便取一个 key 做示例
        example_key = list(found_keys)[0]
        print(f"python script.py <folder> \"{example_key}\"")
    else:
        print("未能从采样文件中提取到任何 statistics key。")

    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="递归查找 .covout 文件并根据 statistics 中的 key 进行排序。")

    # 位置参数
    parser.add_argument("folder", type=str, help="要搜索的文件夹路径")
    parser.add_argument("key", type=str, nargs='?', help="statistics 中用于排序的 key。如果不填，将列出可用 key 并退出。")

    # 可选参数
    parser.add_argument("-n", type=int, default=-1, help="只显示前 N 个结果。默认 -1 表示显示所有。")

    # 排序互斥组
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--inc", action="store_true", help="按升序排序 (从小到大)")
    group.add_argument("--dec", action="store_true", default=True, help="按降序排序 (从大到小, 默认)")

    args = parser.parse_args()

    target_folder = Path(args.folder)
    if not target_folder.exists():
        print(f"错误: 文件夹 '{args.folder}' 不存在。")
        sys.exit(1)

    # 1. 查找文件
    # print(f"正在 '{args.folder}' 中搜索 .covout 文件...") # 保持简洁，这行可注释掉
    files = list(target_folder.rglob("*.covout"))

    if not files:
        print("未找到任何 .covout 文件。")
        sys.exit(0)

    # 2. 如果没有 Key，提示可用 Key 并退出
    if not args.key:
        suggest_keys_and_exit(files)

    # 3. 处理文件与排序
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
            print(f"警告: 文件 '{file_path.name}' JSON 格式错误，跳过。")
        except Exception as e:
            print(f"警告: 读取 '{file_path.name}' 失败: {e}")

    # 执行排序
    results.sort(key=lambda x: x["sort_value"], reverse=reverse_order)

    # 4. 截取 Top N
    total_found = len(results)
    if args.n >= 0:
        results = results[:args.n]
        display_msg = f"前 {len(results)} 个"
    else:
        display_msg = "所有"

    # 输出结果
    print(f"\n共找到 {total_found} 个文件，显示{display_msg} (按 '{args.key}' {'降序' if reverse_order else '升序'}):\n")
    print("=" * 60)

    for item in results:
        print(f"文件名: {item['fullpath']}")
        print(f"排序值: {item['raw_value']}")
        print("Statistics:")
        # json.dumps 默认会保留字典顺序（Python 3.7+），且不进行键排序
        print(json.dumps(item['statistics'], indent=4, ensure_ascii=False))
        print("-" * 60)

if __name__ == "__main__":
    main()
