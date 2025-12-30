#!/usr/bin/env python3

import sys
import json
import re
from collections import defaultdict


def parse_uftrace_dump(input_stream):
    """
    Parse uftrace dump output and build a call graph.

    Returns:
        dict: A dictionary mapping caller -> list of callees
    """
    call_graph = defaultdict(set)
    depth_stack = {}  # Maps tid -> stack of function names by depth

    # Pattern to match trace lines
    # Example: 15256.997215023     83: [entry] f(55fcee48b270) depth: 1
    pattern = re.compile(r'^\s*[\d.]+\s+(\d+):\s+\[(entry|exit)\s*\]\s+(\w+)\([^)]*\)\s+depth:\s+(\d+)')

    for line in input_stream:
        line = line.strip()
        match = pattern.match(line)

        if not match:
            continue

        tid = match.group(1)
        event_type = match.group(2)
        func_name = match.group(3)
        depth = int(match.group(4))

        # Initialize stack for this thread if not exists
        if tid not in depth_stack:
            depth_stack[tid] = {}

        if event_type == 'entry':
            # Record the function at this depth
            depth_stack[tid][depth] = func_name

            # If there's a caller at depth-1, record the call relationship
            if depth > 0 and (depth - 1) in depth_stack[tid]:
                caller = depth_stack[tid][depth - 1]
                call_graph[caller].add(func_name)

        elif event_type == 'exit':
            # Clean up the stack at this depth
            if depth in depth_stack[tid]:
                del depth_stack[tid][depth]

    # Convert sets to sorted lists for consistent output
    result = {caller: sorted(list(callees)) for caller, callees in sorted(call_graph.items())}

    return result


def main():
    """Main function to read from stdin and output JSON to stdout."""
    call_graph = parse_uftrace_dump(sys.stdin)
    json.dump(call_graph, sys.stdout, indent=2)
    print()  # Add newline at end


if __name__ == '__main__':
    main()
