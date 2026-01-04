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


def load_uftrace_files(uftrace_dir: str) -> Dict[str, Set[str]]:
    """Load all uftrace files from directory and return merged callgraph.

    Args:
        uftrace_dir: Directory containing .uftrace JSON files

    Returns:
        Dict mapping function name to set of callee names
    """
    merged_callgraph = defaultdict(set)
    uftrace_files = list(Path(uftrace_dir).glob('*.uftrace'))

    if not uftrace_files:
        print(f"Warning: No .uftrace files found in {uftrace_dir}")
        return merged_callgraph

    print(f"Found {len(uftrace_files)} uftrace files in {uftrace_dir}")

    uftrace_iter = tqdm(uftrace_files, desc="Loading uftrace files", unit="file") if HAS_TQDM else uftrace_files
    for uftrace_file in uftrace_iter:
        try:
            with open(uftrace_file, 'r') as f:
                callgraph = json.load(f)
            # Merge into the combined callgraph
            for func, callees in callgraph.items():
                if isinstance(callees, list):
                    merged_callgraph[func].update(callees)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Failed to load {uftrace_file}: {e}")

    return dict(merged_callgraph)


def build_static_callgraph(callsites: dict) -> Dict[str, Set[str]]:
    """Build static call graph from callSites data.

    Args:
        callsites: Dict with structure func_name -> {ICFGNode_xxx: node_info, ...}

    Returns:
        Dict mapping function name to set of target function names
    """
    static_callgraph = defaultdict(set)
    static_direct_callgraph = defaultdict(set)
    static_indirect_callgraph = defaultdict(set)

    for func_name, nodes in callsites.items():
        for node_id, node_info in nodes.items():
            if not node_id.startswith('ICFGNode'):
                continue

            if node_info['type'] == 'direct':
                target = node_info.get('target')
                if target:
                    static_callgraph[func_name].add(target)
                    static_direct_callgraph[func_name].add(target)
            else:
                targets = node_info.get('targets', [])
                if isinstance(targets, list):
                    static_callgraph[func_name].update(targets)
                    static_indirect_callgraph[func_name].update(targets)

    return dict(static_callgraph), dict(static_direct_callgraph), dict(static_indirect_callgraph)


def count_callgraph_edges(callgraph: Dict[str, Set[str]]) -> int:
    """Count total number of edges in call graph.

    Args:
        callgraph: Call graph (func -> set of callees)

    Returns:
        Total number of edges
    """
    total_edges = 0
    for callees in callgraph.values():
        total_edges += len(callees)
    return total_edges


def update_callgraph(output_data: dict, data: dict, uftrace_dir: str, functions_to_optimize: List[str]) -> None:
    """Update call graph based on coverage results and uftrace data.

    Directly modifies output_data by adding:
    - 'static-cg': static call graph from static analysis
    - 'dynamic-cg': merged dynamic call graph from uftrace
    - statistics about edges removed and reduction

    Args:
        output_data: Output data dict to be modified (will add 'static-cg', 'dynamic-cg', and stats)
        data: Original input.json data (contains callSites)
        uftrace_dir: Directory containing uftrace files
        functions_to_optimize: List of functions that can be optimized
    """
    callsites = data.get('callSites', {}) or {}

    # Build static call graph from static analysis
    static_callgraph, static_direct_callgraph, static_indirect_callgraph = build_static_callgraph(callsites)
    static_edge_count = count_callgraph_edges(static_callgraph)

    print(f"\nStatic call graph edges: {static_edge_count}")

    # Load and merge dynamic call graphs from uftrace
    dynamic_callgraph = load_uftrace_files(uftrace_dir)
    dynamic_edge_count = count_callgraph_edges(dynamic_callgraph)

    print(f"Dynamic call graph edges: {dynamic_edge_count}")
    print(f"Functions with dynamic info: {len(dynamic_callgraph)}")

    # Optimize call graph for selected functions
    optimized_callgraph = {}
    reduced_indirect_edge_count = 0
    increased_indirect_edge_count = 0
    for func_name, callees in static_callgraph.items():
        if func_name in functions_to_optimize:
            dynamic_callees = dynamic_callgraph.get(func_name, set())
            optimized_callgraph[func_name] = static_direct_callgraph.get(func_name, set()) | dynamic_callees

            static_indirect_callees = static_indirect_callgraph.get(func_name, set())
            reduced_indirect_edge_count += len(static_indirect_callees - dynamic_callees)
            increased_indirect_edge_count += len(dynamic_callees - static_indirect_callees)
        else:
            # Keep original for non-optimized functions
            optimized_callgraph[func_name] = set(callees)

    optimized_edge_count = count_callgraph_edges(optimized_callgraph)

    # Calculate statistics
    reduction_percentage = (reduced_indirect_edge_count / static_edge_count * 100) if static_edge_count > 0 else 0

    # Convert sets to lists for JSON serialization
    static_cg_json = {func: sorted(list(callees)) for func, callees in static_callgraph.items()}
    dynamic_cg_json = {func: sorted(list(callees)) for func, callees in dynamic_callgraph.items()}

    # Add call graphs to output
    output_data['static-cg'] = static_cg_json
    output_data['dynamic-cg'] = dynamic_cg_json

    # Add statistics to output
    stats = {
        'Static call graph edges': static_edge_count,
        'Dynamic call graph edges': dynamic_edge_count,
        'Optimized call graph edges': optimized_edge_count,
        'Reduced indirect call graph edges': reduced_indirect_edge_count,
        'Increased indirect call graph edges': increased_indirect_edge_count,
        'Edge reduction percentage': f"{reduction_percentage:.2f}%"
    }
    output_data['statistics'].update(stats)



def scan_coverage(input_json_path: str, cov_dir: str, json_prefix: str) -> dict:
    """Main function to scan coverage and return output data.

    Returns:
        Dict containing 'coverage', 'functions-cg', and 'statistics' keys.
    """

    # Load input.json
    data = load_output_json(input_json_path)
    combos = data.get('combos') or {}
    locations = data.get('locations') or {}

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

    check_json_csv_filename_match(locations, csv_coverage_map)

    # Coverage output structure: node_name -> {totalPaths, coveredPaths, coveredBy}
    coverage_output = {}

    # Process each node in combos
    combos_iter = tqdm(combos.items(), desc="Checking coverage", unit="node") if HAS_TQDM else combos.items()
    for node_name, node_data in combos_iter:
        branch_combos = node_data.get('branchCombos', [])

        # If no paths to cover, node is considered covered (no paths)
        if not branch_combos:
            coverage_output[node_name] = {
                'totalPaths': 0,
                'coveredPaths': 0,
                'covered': True
            }
            continue

        total_paths = len(branch_combos)
        covered_paths = 0

        # Check each path against all CSV files
        for path_idx, path in enumerate(branch_combos):
            for csv_path, csv_coverage in csv_coverage_map.items():
                if check_path_coverage(path, csv_coverage, locations):
                    # Mark this path as covered (boolean)
                    path['covered'] = True
                    covered_paths += 1
                    break

        # Store coverage data; a node is considered 'covered' when all its paths are covered
        coverage_output[node_name] = {
            'totalPaths': total_paths,
            'coveredPaths': covered_paths,
            'covered': (covered_paths == total_paths)
        }

        # no per-node stat arrays maintained; summary will be computed later

    # === Functions to optimize ===
    functions_to_optimize = []
    callsites = data.get('callSites', {}) or {}

    for func_name, nodes in callsites.items():
        # collect ICFGNode keys
        icfg_nodes = [nid for nid in nodes.keys() if nid.startswith('ICFGNode')]
        if not icfg_nodes:
            continue

        has_indirect_ir = False
        indirect_nonir_nodes = []
        affected_by_loop = False

        for nid in icfg_nodes:
            node_info = nodes.get(nid, {})
            t = node_info.get('type')
            if t == 'indirect-IR':
                has_indirect_ir = True
                break
            if t == 'indirect-nonIR':
                indirect_nonir_nodes.append(nid)
                if combos.get(nid, {}).get('affectedByLoop', False):
                    affected_by_loop = True
                    break

        if has_indirect_ir:
            continue
        if not indirect_nonir_nodes:
            continue
        if affected_by_loop:
            continue

        all_nonir_nodes_covered = True
        # For each indirect-nonIR node, check if its branchCombos (if any) are all covered
        for nid in indirect_nonir_nodes:
            # Use previously computed node-level coverage (coverage_output)
            node_cov = coverage_output.get(nid)
            if not node_cov:
                # No coverage info -> treat as covered
                continue
            if not node_cov.get('covered'):
                all_nonir_nodes_covered = False
                break

        if all_nonir_nodes_covered:
            functions_to_optimize.append(func_name)

    def compute_summary(coverage_map: dict, functions_list: list) -> dict:
        """Compute summary statistics from coverage_output."""
        total_nodes = len(coverage_map)
        fully_with_paths = 0
        fully_no_paths = 0
        partially = 0
        uncovered = 0

        for node, info in coverage_map.items():
            tp = info.get('totalPaths', 0)
            cp = info.get('coveredPaths', 0)
            covered_flag = info.get('covered', False)

            if tp == 0:
                fully_no_paths += 1
            else:
                if cp == tp:
                    fully_with_paths += 1
                elif cp == 0:
                    uncovered += 1
                else:
                    partially += 1

        return {
            'Total nodes': total_nodes,
            'Fully covered (with paths)': fully_with_paths,
            'Fully covered (no paths)': fully_no_paths,
            'Partially covered': partially,
            'Uncovered': uncovered,
            'Functions to optimize': len(functions_list)
        }

    statistics = compute_summary(coverage_output, functions_to_optimize)

    # Build output JSON structure
    output_data = {
        'coverage': coverage_output,
        'functions-cg': functions_to_optimize,
        'statistics': statistics
    }

    return output_data


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Scan coverage CSVs and optionally write output.json")
    parser.add_argument("input_json", help="Path to input.json (contains locations and combos)")
    parser.add_argument("cov_dir", help="Directory containing CSV coverage files")
    parser.add_argument("-o", "--output", dest="output_json", help="Path to output.json (optional)")
    parser.add_argument("-u", "--uftrace-dir", dest="uftrace_dir", help="Directory containing uftrace files for call graph optimization (optional)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prefix", dest="json_prefix", help="Explicit json_prefix to strip from location filenames")
    group.add_argument("--project", dest="project", help="Project name to infer json_prefix from ../dataset/<project>/bc.dockerfile")

    args = parser.parse_args()

    if args.json_prefix:
        json_prefix = args.json_prefix
    else:
        # Infer from project
        try:
            json_prefix = guess_json_prefix_from_project(args.project)
        except Exception as e:
            print(f"Error guessing json_prefix from project '{args.project}': {e}")
            sys.exit(1)

    if not os.path.exists(args.input_json):
        print(f"Error: {args.input_json} does not exist")
        sys.exit(1)

    if not os.path.isdir(args.cov_dir):
        print(f"Error: {args.cov_dir} is not a directory")
        sys.exit(1)

    if not json_prefix.endswith('/'):
        json_prefix += '/'

    print(f'json_prefix: {json_prefix}')

    output_data = scan_coverage(args.input_json, args.cov_dir, json_prefix)

    # Optionally optimize call graph if uftrace_dir is provided
    if args.uftrace_dir:
        if not os.path.isdir(args.uftrace_dir):
            print(f"Error: {args.uftrace_dir} is not a directory")
            sys.exit(1)

        # Load input data to get callSites
        data = load_output_json(args.input_json)

        # Get functions to optimize from coverage results
        functions_to_optimize = output_data.get('functions-cg', [])

        # Update call graph and output data (modifies output_data in place)
        update_callgraph(output_data, data, args.uftrace_dir, functions_to_optimize)

    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    for k, v in output_data['statistics'].items():
        print(f"{k}: {v}")

    # Optionally write output.json if provided
    if args.output_json:
        with open(args.output_json, 'w') as f:
            json.dump(output_data, f, indent=4)
