#!/usr/bin/env python3
"""
Compute changed projects from dataset files and pair them for parallel builds.
This script replaces the bash logic in the GitHub Actions workflow.
"""

import json
import sys
from typing import List, Dict


def parse_changed_files(files_json: str) -> List[str]:
    """
    Parse the JSON array of changed files and extract unique project names.
    
    Args:
        files_json: JSON string containing array of file paths (e.g., '["dataset/proj1/file", ...]')
    
    Returns:
        Sorted list of unique project names extracted from the file paths
    """
    if not files_json or files_json == "[]":
        return []
    
    try:
        files = json.loads(files_json)
    except json.JSONDecodeError:
        print(f"Error: Failed to parse files JSON: {files_json}", file=sys.stderr)
        return []
    
    # Extract unique project names from changed dataset files
    # Files are in format: dataset/PROJECT_NAME/...
    projects = set()
    for file_path in files:
        if not isinstance(file_path, str):
            continue  # Skip non-string elements
        parts = file_path.split('/')
        if len(parts) >= 2 and parts[0] == 'dataset':
            projects.add(parts[1])
    
    return sorted(list(projects))


def filter_projects_with_dockerfiles(changed_projects: List[str], all_projects: List[str]) -> List[str]:
    """
    Filter changed projects to only those that exist in all_projects (have dockerfiles).
    
    Args:
        changed_projects: List of project names that have changed files
        all_projects: List of all valid project names (projects with dockerfiles)
    
    Returns:
        Filtered list of changed projects that also exist in all_projects
    """
    all_projects_set = set(all_projects)
    return [p for p in changed_projects if p in all_projects_set]


def pair_projects(projects: List[str]) -> List[Dict[str, str]]:
    """
    Pair projects into groups of 2 where proj1 and proj2 are always different.
    Both proj1 and proj2 can be empty strings (meaning no project to build).
    
    Returns:
        List of dicts with keys 'proj1' and 'proj2', where:
        - proj1 != proj2 (always different)
        - Either can be empty string "" (skip building)
    """
    if not projects:
        return []
    
    pairs = []
    for i in range(0, len(projects), 2):
        proj1 = projects[i]
        # Always ensure proj1 != proj2
        # If only one project left, proj2 is empty
        proj2 = projects[i + 1] if i + 1 < len(projects) else ""
        pairs.append({
            "proj1": proj1,
            "proj2": proj2
        })
    
    return pairs


def main():
    """Main function to compute changed projects and output paired JSON."""
    if len(sys.argv) < 3:
        print("Usage: compute_changed_projects.py <changed_files_json> <all_projects_json>", file=sys.stderr)
        sys.exit(1)
    
    changed_files_json = sys.argv[1]
    all_projects_json = sys.argv[2]
    
    # Parse all projects
    try:
        all_projects = json.loads(all_projects_json)
    except json.JSONDecodeError:
        print(f"Error: Failed to parse all_projects JSON: {all_projects_json}", file=sys.stderr)
        sys.exit(1)
    
    # Parse and filter changed projects
    changed_projects = parse_changed_files(changed_files_json)
    if not changed_projects:
        print(json.dumps([]))
        return
    
    # Filter to only projects with dockerfiles
    valid_projects = filter_projects_with_dockerfiles(changed_projects, all_projects)
    if not valid_projects:
        print(json.dumps([]))
        return
    
    # Pair projects
    paired_projects = pair_projects(valid_projects)
    
    # Output as JSON
    print(json.dumps(paired_projects))


if __name__ == "__main__":
    main()
