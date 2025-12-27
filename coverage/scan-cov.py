#!/usr/bin/env python3

import json
import sys
import os
import re
import argparse
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

# Try to import tqdm, use fallback if not available
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    # Fallback: tqdm is just the identity function
    def tqdm(iterable, **kwargs):
        return iterable


def parse_csv_file(csv_path: str) -> Dict:
    """
    Parse a CSV file and return a dictionary mapping location to (true_count, false_count).
    Only uses filename (with /work/build-cov/ prefix removed), start_line, start_col.

    Returns:
        Dict mapping: filename -> (start_line, start_col, end_line, end_col) -> (true_count, false_count)
    """
    coverage_data = {}

    with open(csv_path, 'r') as f:
        lines = f.readlines()

    # Skip header
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue

        parts = line.split(',')
        if len(parts) < 6:
            continue

        filename = parts[0]
        # Remove /work/build-cov/ prefix if present
        if filename.startswith('/work/build-cov/'):
            filename = filename[len('/work/build-cov/'):]

        try:
            start_line = int(parts[1])
            start_col = int(parts[2])
            end_line = int(parts[3])
            end_col = int(parts[4])
            true_count = int(parts[5])
            false_count = int(parts[6]) if len(parts) > 6 else 0
        except (ValueError, IndexError):
            continue

        if filename not in coverage_data:
            coverage_data[filename] = {}
        coverage_data[filename][(start_line, start_col, end_line, end_col)] = (true_count, false_count)

    return coverage_data


def load_output_json(json_path: str) -> dict:
    """Load the output.json file."""
    with open(json_path, 'r') as f:
        return json.load(f)


def guess_json_prefix_from_project(project: str) -> str:
    """Guess json_prefix by reading the last WORKDIR from the project's bc.dockerfile.

    The bc.dockerfile is located at ../dataset/<project>/bc.dockerfile relative to this script.
    The last WORKDIR path is used as the json_prefix.
    """
    script_dir = Path(__file__).resolve().parent
    dockerfile_path = (script_dir / '..' / 'dataset' / project / 'bc.dockerfile').resolve()

    if not dockerfile_path.exists():
        raise FileNotFoundError(f"Dockerfile not found: {dockerfile_path}")

    workdir_value = None
    workdir_regex = re.compile(r"^\s*WORKDIR\s+(.+?)\s*$", re.IGNORECASE)

    with open(dockerfile_path, 'r') as f:
        for line in f:
            # Ignore comment-only lines
            if line.strip().startswith('#'):
                continue
            m = workdir_regex.match(line)
            if m:
                workdir_value = m.group(1).strip()

    if not workdir_value:
        raise ValueError(f"No WORKDIR found in {dockerfile_path}")

    return workdir_value

def within_range(line: int, col: int, start_line: int, start_col: int, end_line: int, end_col: int) -> bool:
    """Check if a given line and column is within the specified range."""
    if line < start_line or line > end_line:
        return False
    if line == start_line and col < start_col:
        return False
    if line == end_line and col > end_col:
        return False
    return True

def check_path_coverage(path: dict, csv_coverage: Dict, locations: dict) -> bool:
    """
    Check if a single path is covered by the CSV coverage data.

    A path is covered if:
    - All conditions in 'covers' have the corresponding branch (index) count > 0
    - All conditions in 'avoids' either don't exist or have count == 0
    """
    # Check covers
    if 'covers' in path:
        for cover in path['covers']:
            cond_id = cover['cond']
            index = cover['index']  # 0 for true branch, 1 for false branch

            loc = locations.get(cond_id)
            if not loc:
                return False
            filename, line, col = loc

            if csv_coverage.get(filename) is None:
                return False

            for (start_line, start_col, end_line, end_col), (true_count, false_count) in csv_coverage[filename].items():
                if within_range(line, col, start_line, start_col, end_line, end_col):
                    if index == 0:  # True branch
                        if true_count == 0:
                            return False
                    else:  # False branch
                        if false_count == 0:
                            return False
                    break
            else:
                return False  # No matching location found in CSV

    # Check avoids
    if 'avoids' in path:
        for avoid in path['avoids']:
            cond_id = avoid['cond']
            index = avoid['index']

            loc = locations.get(cond_id)
            if not loc:
                continue  # If location not found, okay to assume not covered
            filename, line, col = loc

            if csv_coverage.get(filename) is None:
                continue  # If location not in CSV, okay to assume not covered

            for (start_line, start_col, end_line, end_col), (true_count, false_count) in csv_coverage[filename].items():
                if within_range(line, col, start_line, start_col, end_line, end_col):
                    if index == 0:  # True branch
                        if true_count > 0:
                            return False
                    else:  # False branch
                        if false_count > 0:
                            return False
                    break
            else:
                continue

    return True


def check_json_csv_filename_match(locations: dict, csv_coverage_map: dict):
    """Check if any location filenames match between JSON and CSV coverage data."""
    json_filenames = set()
    for loc in locations.values():
        filename = loc[0]
        json_filenames.add(filename)

    csv_filenames = set()
    csv_iter = tqdm(csv_coverage_map.values(), desc="Processing CSV coverage", unit="file") if HAS_TQDM else csv_coverage_map.values()
    for csv_coverage in csv_iter:
        for filename in csv_coverage.keys():
            csv_filenames.add(filename)

    print("\n" + "="*80)
    print("FILENAME MATCH CHECK")
    print("="*80)
    print(f"JSON filenames: {len(json_filenames)}")
    print(f"CSV filenames: {len(csv_filenames)}")
    matching_filenames = json_filenames.intersection(csv_filenames)
    print(f"Matching filenames: {len(matching_filenames)}")

def scan_coverage(output_json_path: str, cov_dir: str, json_prefix: str):
    """Main function to scan coverage and update output.json."""

    # Load output.json
    data = load_output_json(output_json_path)
    combos = data.get('combos', {})
    locations = data.get('locations', {}).copy()

    # remove json_prefix from location filenames
    for loc_id, loc in locations.items():
        if loc.startswith(json_prefix):
            loc = loc[len(json_prefix):]
        loc = loc.split(':')
        assert len(loc) == 3, f"Invalid location format: {locations[loc_id]}"
        loc = (loc[0], int(loc[1]), int(loc[2]))
        locations[loc_id] = loc

    # Parse all CSV files in cov_dir
    csv_files = list(Path(cov_dir).glob('*.csv'))
    print(f"Found {len(csv_files)} CSV files in {cov_dir}")

    csv_coverage_map = {}
    csv_iter = tqdm(csv_files, desc="Parsing CSV files", unit="file") if HAS_TQDM else csv_files
    for csv_file in csv_iter:
        csv_path = str(csv_file.absolute())
        csv_coverage_map[csv_path] = parse_csv_file(csv_path)
        # if not HAS_TQDM:
        #     print(f"Parsed {csv_file.name}: {len(csv_coverage_map[csv_path])} coverage entries")

    check_json_csv_filename_match(locations, csv_coverage_map)

    # Track statistics
    fully_covered_with_paths = []
    fully_covered_no_paths = []
    partially_covered_nodes = []

    # Process each node in combos
    combos_iter = tqdm(combos.items(), desc="Checking coverage", unit="node") if HAS_TQDM else combos.items()
    for node_name, node_data in combos_iter:
        branch_combos = node_data.get('branchCombos', [])

        # If no paths to cover, node is fully covered (no paths)
        if not branch_combos:
            fully_covered_no_paths.append({
                'node': node_name,
                'total_paths': 0
            })
            continue

        total_paths = len(branch_combos)
        covered_paths = 0

        # Check each path against all CSV files
        for path_idx, path in enumerate(branch_combos):
            path_covered = False

            for csv_path, csv_coverage in csv_coverage_map.items():
                if check_path_coverage(path, csv_coverage, locations):
                    # Mark this path as covered by this CSV
                    path['coveredBy'] = csv_path
                    path_covered = True
                    covered_paths += 1
                    break

        # Determine if node is fully or partially covered
        if covered_paths == total_paths:
            fully_covered_with_paths.append({
                'node': node_name,
                'total_paths': total_paths
            })
        elif covered_paths > 0:
            partially_covered_nodes.append({
                'node': node_name,
                'total_paths': total_paths,
                'covered_paths': covered_paths
            })

    # Write updated output.json
    with open(output_json_path, 'w') as f:
        json.dump(data, f, indent=4)

    # Print statistics
    print("\n" + "="*80)
    print("COVERAGE STATISTICS")
    print("="*80)

    print(f"\nFully covered nodes with paths ({len(fully_covered_with_paths)}):")
    for node_info in fully_covered_with_paths:
        node = node_info['node']
        total = node_info['total_paths']
        print(f"  ✓ {node} ({total} paths)")

    print(f"\nFully covered nodes with no paths ({len(fully_covered_no_paths)}):")
    for node_info in fully_covered_no_paths:
        node = node_info['node']
        print(f"  ✓ {node} (no paths to cover)")

    print(f"\nPartially covered nodes ({len(partially_covered_nodes)}):")
    for node_info in partially_covered_nodes:
        node = node_info['node']
        total = node_info['total_paths']
        covered = node_info['covered_paths']
        percentage = (covered / total * 100) if total > 0 else 0
        print(f"  ✗ {node}: {covered}/{total} paths covered ({percentage:.1f}%)")

    print(f"\nSummary:")
    print(f"  Total nodes: {len(combos)}")
    print(f"  Fully covered (with paths): {len(fully_covered_with_paths)}")
    print(f"  Fully covered (no paths): {len(fully_covered_no_paths)}")
    print(f"  Partially covered: {len(partially_covered_nodes)}")
    print(f"  Uncovered: {len(combos) - len(fully_covered_with_paths) - len(fully_covered_no_paths) - len(partially_covered_nodes)}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Scan coverage CSVs and update output.json")
    parser.add_argument("output_json", help="Path to output.json")
    parser.add_argument("cov_dir", help="Directory containing CSV coverage files")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prefix", dest="json_prefix", help="Explicit json_prefix to strip from location filenames")
    group.add_argument("--project", dest="project", help="Project name to infer json_prefix from ../dataset/<project>/bc.dockerfile")

    args = parser.parse_args()

    output_json_path = args.output_json
    cov_dir = args.cov_dir

    if args.json_prefix:
        json_prefix = args.json_prefix
    else:
        # Infer from project
        try:
            json_prefix = guess_json_prefix_from_project(args.project)
        except Exception as e:
            print(f"Error guessing json_prefix from project '{args.project}': {e}")
            sys.exit(1)

    if not os.path.exists(output_json_path):
        print(f"Error: {output_json_path} does not exist")
        sys.exit(1)

    if not os.path.isdir(cov_dir):
        print(f"Error: {cov_dir} is not a directory")
        sys.exit(1)

    if not json_prefix.endswith('/'):
        json_prefix += '/'

    print(f'json_prefix: {json_prefix}')

    scan_coverage(output_json_path, cov_dir, json_prefix)
