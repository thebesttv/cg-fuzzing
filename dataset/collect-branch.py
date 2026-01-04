#!/usr/bin/env python3
"""
Collect branch and segment coverage information from LLVM coverage JSON export.

llvm-cov JSON 格式参考：
https://stackoverflow.com/a/56792192
https://github.com/llvm/llvm-project/blob/24a30daaa559829ad079f2ff7f73eb4e18095f88/llvm/tools/llvm-cov/CoverageExporterJson.cpp#L96
"""

import json
import csv
import argparse
import sys
from typing import List, Dict, Any


def collect_branches(coverage_data, keep_inactive=False):
    """
    Extract branch information from coverage data dict.

    Returns a list of dictionaries with branch coverage data.
    """
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


def collect_segments(coverage_data) -> List[Dict[str, Any]]:
    """
    Extract segment information from coverage data dict.

    Segment format: [Line, Col, Count, HasCount, IsRegionEntry, IsGapRegion]
    Only processes segments where HasCount is true.
    Uses a dict to deduplicate: (filename, line, col) -> executed
    If any count is non-zero, mark as executed.
    Returns a sorted list of dictionaries with filename, line, col, executed.
    """
    # Use dict to deduplicate segments by (filename, line, col)
    segment_dict = {}

    # Navigate through the JSON structure
    for data_entry in coverage_data.get('data', []):
        for file_entry in data_entry.get('files', []):
            filename = file_entry.get('filename', 'unknown')

            # Process each segment
            for segment in file_entry.get('segments', []):
                if len(segment) >= 6:
                    # Segment format: [Line, Col, Count, HasCount, IsRegionEntry, IsGapRegion]
                    has_count = segment[3]

                    # Only process segments where has_count is true
                    if not has_count:
                        continue

                    line = segment[0]
                    col = segment[1]
                    count = segment[2]

                    key = (filename, line, col)

                    # If already exists, update executed if count is non-zero
                    if key in segment_dict:
                        if count != 0:
                            segment_dict[key] = True
                    else:
                        # New entry: executed if count is non-zero
                        segment_dict[key] = (count != 0)

    # Convert dict to list of dictionaries
    segments = []
    for (filename, line, col), executed in segment_dict.items():
        segments.append({
            'filename': filename,
            'line': line,
            'col': col,
            'executed': executed
        })

    # Sort by filename, then by line, then by column
    segments.sort(key=lambda x: (x['filename'], x['line'], x['col']))

    return segments




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


def write_segments_csv(segments, output_path):
    """
    Write segment coverage data to a CSV file.

    output_path is required (cannot be None).
    Columns: filename, line, col, executed
    """
    if not segments:
        print("Warning: No segment data found", file=sys.stderr)
        return

    fieldnames = ['filename', 'line', 'col', 'executed']

    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for segment in segments:
            writer.writerow(segment)

    print(f"Wrote {len(segments)} segments to {output_path}", file=sys.stderr)



def main():
    parser = argparse.ArgumentParser(
        description='Collect branch and segment coverage information from LLVM coverage JSON export'
    )
    parser.add_argument('coverage_json', nargs='?', default=None,
                        help='Path to the coverage JSON file (if not provided, reads from stdin)')
    parser.add_argument('--branch', required=True,
                        help='Output CSV file path for branch coverage data (required)')
    parser.add_argument('--segment', required=True,
                        help='Output CSV file path for segment coverage data (required)')
    parser.add_argument('--keep-inactive', action='store_true', default=False,
                        help='Include branches that have zero executions for both true and false')

    args = parser.parse_args()

    try:
        # Read JSON once
        if args.coverage_json is None:
            coverage_data = json.load(sys.stdin)
        else:
            with open(args.coverage_json, 'r') as f:
                coverage_data = json.load(f)

        branches = collect_branches(coverage_data, keep_inactive=args.keep_inactive)
        segments = collect_segments(coverage_data)

        write_csv(branches, args.branch)
        write_segments_csv(segments, args.segment)
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

