#!/usr/bin/env python3
"""
Collect branch coverage information from LLVM coverage JSON export.

llvm-cov JSON 格式参考：
https://stackoverflow.com/a/56792192
https://github.com/llvm/llvm-project/blob/24a30daaa559829ad079f2ff7f73eb4e18095f88/llvm/tools/llvm-cov/CoverageExporterJson.cpp#L96
"""

import json
import csv
import argparse
import sys


def collect_branches(coverage_json_path=None, keep_inactive=False):
    """
    Parse the coverage JSON file and extract branch information.

    If coverage_json_path is None, reads from stdin.
    Returns a list of dictionaries with branch coverage data.
    """
    if coverage_json_path is None:
        coverage_data = json.load(sys.stdin)
    else:
        with open(coverage_json_path, 'r') as f:
            coverage_data = json.load(f)

    branches = []

    # Navigate through the JSON structure
    for data_entry in coverage_data.get('data', []):
        for file_entry in data_entry.get('files', []):
            filename = file_entry.get('filename', 'unknown')

            # Process each branch
            for branch in file_entry.get('branches', []):
                if len(branch) >= 9:
                    # Branch format: [LineStart, ColumnStart, LineEnd, ColumnEnd,
                    #                 ExecutionCount, FalseExecutionCount, FileID, ExpandedFileID, Kind]
                    # ExecutionCount and FalseExecutionCount are indices 4 and 5
                    true_count = branch[4]
                    false_count = branch[5]

                    # If not keeping inactive branches and both counts are zero, skip
                    if not keep_inactive and true_count == 0 and false_count == 0:
                        continue

                    branch_info = {
                        'filename': filename,
                        'start_line': branch[0],
                        'start_col': branch[1],
                        'end_line': branch[2],
                        'end_col': branch[3],
                        'true_count': true_count,  # ExecutionCount
                        'false_count': false_count  # FalseExecutionCount
                    }
                    branches.append(branch_info)

    return branches


def write_csv(branches, output_path=None):
    """
    Write branch coverage data to a CSV file or stdout.

    If output_path is None, writes to stdout.
    """
    if not branches:
        print("Warning: No branch data found", file=sys.stderr)
        return

    fieldnames = ['filename', 'start_line', 'start_col', 'end_line', 'end_col',
                  'true_count', 'false_count']

    if output_path is None:
        # Write to stdout
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        for branch in branches:
            writer.writerow(branch)
    else:
        # Write to file
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for branch in branches:
                writer.writerow(branch)
        print(f"Wrote {len(branches)} branches to {output_path}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Collect branch coverage information from LLVM coverage JSON export'
    )
    parser.add_argument('coverage_json', nargs='?', default=None,
                        help='Path to the coverage JSON file (if not provided, reads from stdin)')
    parser.add_argument('-o', '--output', default=None,
                        help='Output CSV file path (if not provided, writes to stdout)')
    parser.add_argument('--keep-inactive', action='store_true', default=False,
                        help='Include branches that have zero executions for both true and false')

    args = parser.parse_args()

    try:
        branches = collect_branches(args.coverage_json, keep_inactive=args.keep_inactive)
        write_csv(branches, args.output)
    except FileNotFoundError:
        print(f"Error: File '{args.coverage_json}' not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON format: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
