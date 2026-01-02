#!/usr/bin/env python3
import os
import json
import argparse
from pathlib import Path

def parse_sort_value(value):
    """
    尝试将值转换为数字以便排序。
    支持整数、浮点数以及带 '%' 的百分比字符串。
    """
    if isinstance(value, (int, float)):
        return value

    if isinstance(value, str):
        # 处理百分比，例如 "0.12%" -> 0.12
        if value.endswith('%'):
            try:
                return float(value.rstrip('%'))
            except ValueError:
                pass
        # 尝试直接转换为数字
        try:
            return float(value)
        except ValueError:
            pass

    # 如果无法转换（例如纯文本），返回原值或者 0（视需求而定，这里返回原值让python尝试比较，或返回-1作为兜底）
    # 为了保证数字排序不报错，如果无法转数字且是混合类型，建议返回一个极小值
    return -float('inf')

def main():
    parser = argparse.ArgumentParser(description="递归查找 .covout 文件并根据 statistics 中的 key 进行排序。")

    # 位置参数
    parser.add_argument("folder", type=str, help="要搜索的文件夹路径")
    parser.add_argument("key", type=str, help="statistics 中用于排序的 key (例如 'Total nodes')")

    # 互斥参数组：升序或降序
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--inc", action="store_true", help="按升序排序 (从小到大)")
    group.add_argument("--dec", action="store_true", default=True, help="按降序排序 (从大到小, 默认)")

    args = parser.parse_args()

    # 确定排序顺序
    reverse_order = not args.inc  # 如果是 --inc，reverse为False；否则默认True

    target_folder = Path(args.folder)
    if not target_folder.exists():
        print(f"错误: 文件夹 '{args.folder}' 不存在。")
        return

    results = []

    # 递归查找所有 .covout 文件
    files = list(target_folder.rglob("*.covout"))

    print(f"正在 '{args.folder}' 中搜索 .covout 文件...")

    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

                # 获取 statistics 节点
                stats = data.get("statistics", {})

                # 获取排序用的值
                raw_value = stats.get(args.key)

                # 如果 key 不存在，给出警告并跳过（或者你可以选择赋值为 0）
                if raw_value is None:
                    # print(f"警告: 文件 {file_path.name} 中缺少 key '{args.key}'")
                    sort_value = -float('inf') # 缺失值的放到最后
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
            print(f"错误: 文件 '{file_path.name}' 不是有效的 JSON 格式。")
        except Exception as e:
            print(f"处理文件 '{file_path.name}' 时出错: {e}")

    # 执行排序
    # key 指定根据解析后的数值排序
    results.sort(key=lambda x: x["sort_value"], reverse=reverse_order)

    # 输出结果
    print(f"\n找到 {len(results)} 个文件，按 '{args.key}' {'降序' if reverse_order else '升序'} 排列:\n")
    print("=" * 60)

    for item in results:
        print(f"文件名: {item['fullpath']}")
        # 显示排序用的值，方便确认
        print(f"排序依据 ({args.key}): {item['raw_value']}")
        print("Statistics 内容:")

        # 将字典格式化为类似于文本/JSON 的样式输出
        # indent=4 让输出更美观
        stats_str = json.dumps(item['statistics'], indent=4, ensure_ascii=False)
        print(stats_str)
        print("-" * 60)

if __name__ == "__main__":
    main()
