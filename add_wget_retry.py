#!/usr/bin/env python3
"""
Script to automatically add retry parameters to wget commands in Dockerfiles.

This script:
1. Finds all *.dockerfile files in the repository
2. Identifies wget commands without retry parameters
3. Adds standard retry parameters: --tries=3 --retry-connrefused --waitretry=5
4. Replaces existing different retry parameters with standard ones (with warning)
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple


# Standard retry parameters to add
STANDARD_RETRY_PARAMS = "--tries=3 --retry-connrefused --waitretry=5"

# Regex patterns
# Match wget commands with various patterns
WGET_PATTERN = re.compile(r'wget\s+')
# Match existing retry parameters
RETRY_PARAMS_PATTERN = re.compile(
    r'--tries[=\s]+\d+|'
    r'--retry-connrefused|'
    r'--waitretry[=\s]+\d+|'
    r'-t\s+\d+|'
    r'--timeout[=\s]+\d+'
)


def find_dockerfiles(root_dir: Path) -> List[Path]:
    """Find all .dockerfile files in the repository."""
    return sorted(root_dir.glob("**/*.dockerfile"))


def is_download_url(text: str) -> bool:
    """Check if text starts with a download URL (http/https/ftp)."""
    return text.startswith('http://') or text.startswith('https://') or text.startswith('ftp://')


def extract_wget_commands(line: str) -> List[Tuple[int, int]]:
    """
    Extract positions of wget commands in a line.
    Returns list of (start, end) positions for each wget command.
    Filters out 'apt-get install wget' and similar package installation commands.
    Also filters out lines where wget appears as part of a binary name (e.g., "src/wget", "extract-bc src/wget").
    Only processes wget commands that are downloading files (i.e., have a URL).
    """
    positions = []
    for match in WGET_PATTERN.finditer(line):
        # Check if this is part of a package installation command
        # Look backwards from wget position to see if it's preceded by 'install'
        before_wget = line[:match.start()].strip()
        after_wget = line[match.end():].strip()
        
        # Skip if it looks like package installation
        if before_wget.endswith('install') or 'apt-get' in before_wget or 'yum install' in before_wget:
            continue
        
        # Skip if 'wget' is part of a path or binary name (e.g., "src/wget", "/path/to/wget")
        # Check if the character before 'wget' is a path separator or alphanumeric
        if before_wget and before_wget[-1] in '/-_':
            continue
        
        # Only process wget commands that have a URL somewhere after them
        # Split by whitespace and check if any token is a URL
        tokens = after_wget.split()
        has_url = False
        for token in tokens:
            # Remove common prefixes that might be stuck to the URL
            clean_token = token.lstrip('-').split('=')[-1]
            if is_download_url(clean_token):
                has_url = True
                break
        
        if not has_url:
            continue
        
        positions.append(match.span())
    return positions


def has_retry_params(wget_segment: str) -> bool:
    """Check if a wget command segment has any retry parameters."""
    return bool(RETRY_PARAMS_PATTERN.search(wget_segment))


def get_wget_command_end(line: str, start_pos: int) -> int:
    """
    Find the end of a wget command.
    Assumes wget command ends at && or \\ or end of line.
    """
    # Find the end of this wget command (up to && or \ or end of line)
    end_markers = []
    
    # Look for && after the wget
    and_pos = line.find('&&', start_pos)
    if and_pos != -1:
        end_markers.append(and_pos)
    
    # Look for \ (line continuation)
    backslash_pos = line.find('\\', start_pos)
    if backslash_pos != -1:
        end_markers.append(backslash_pos)
    
    # If no markers found, command goes to end of line
    if not end_markers:
        return len(line)
    
    return min(end_markers)


def extract_existing_retry_params(wget_segment: str) -> List[str]:
    """Extract all existing retry parameter strings from wget command."""
    return RETRY_PARAMS_PATTERN.findall(wget_segment)


def remove_retry_params(wget_segment: str) -> str:
    """Remove all existing retry parameters from wget command."""
    return RETRY_PARAMS_PATTERN.sub('', wget_segment)


def normalize_whitespace(text: str) -> str:
    """Normalize multiple spaces to single space, but preserve newlines."""
    # Only normalize spaces and tabs, not newlines
    return re.sub(r'[ \t]+', ' ', text)


def process_line(line: str, line_num: int, filepath: Path, warnings_list: List[str]) -> Tuple[str, bool]:
    """
    Process a single line to add/update wget retry parameters.
    Returns (modified_line, was_modified).
    """
    if 'wget' not in line:
        return line, False
    
    modified = False
    result = line
    offset = 0  # Track position changes as we modify the line
    
    # Find all wget commands in the line
    wget_positions = extract_wget_commands(line)
    
    for wget_start, wget_end in wget_positions:
        # Adjust positions based on previous modifications
        adj_start = wget_start + offset
        adj_end = wget_end + offset
        
        # Find the end of this wget command
        cmd_end = get_wget_command_end(result, adj_end)
        
        # Extract the wget command segment
        wget_segment = result[adj_start:cmd_end]
        
        # Check if it already has retry parameters
        if has_retry_params(wget_segment):
            existing_params = extract_existing_retry_params(wget_segment)
            existing_params_str = ' '.join(existing_params)
            
            # Check if it matches our standard
            if existing_params_str != STANDARD_RETRY_PARAMS:
                warning_msg = (
                    f"WARNING: {filepath}:{line_num}\n"
                    f"  Found different retry parameters: {existing_params_str}\n"
                    f"  Replacing with standard: {STANDARD_RETRY_PARAMS}"
                )
                warnings_list.append(warning_msg)
                
                # Remove existing retry params
                cleaned_segment = remove_retry_params(wget_segment)
                cleaned_segment = normalize_whitespace(cleaned_segment)
                
                # Add standard retry params after 'wget '
                wget_match = WGET_PATTERN.search(cleaned_segment)
                if wget_match:
                    insert_pos = wget_match.end()
                    new_segment = (
                        cleaned_segment[:insert_pos] +
                        STANDARD_RETRY_PARAMS + ' ' +
                        cleaned_segment[insert_pos:]
                    )
                    new_segment = normalize_whitespace(new_segment)
                    
                    # Replace in result
                    result = result[:adj_start] + new_segment + result[cmd_end:]
                    offset += len(new_segment) - len(wget_segment)
                    modified = True
        else:
            # No retry parameters, add them (silently)
            # Add standard retry params after 'wget '
            wget_match = WGET_PATTERN.search(wget_segment)
            if wget_match:
                insert_pos = wget_match.end()
                new_segment = (
                    wget_segment[:insert_pos] +
                    STANDARD_RETRY_PARAMS + ' ' +
                    wget_segment[insert_pos:]
                )
                new_segment = normalize_whitespace(new_segment)
                
                # Replace in result
                result = result[:adj_start] + new_segment + result[cmd_end:]
                offset += len(new_segment) - len(wget_segment)
                modified = True
    
    return result, modified


def process_dockerfile(filepath: Path, dry_run: bool = False, warnings_list: List[str] = None) -> bool:
    """
    Process a single Dockerfile to add/update wget retry parameters.
    Returns True if file was modified.
    """
    if warnings_list is None:
        warnings_list = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"ERROR: Failed to read {filepath}: {e}")
        return False
    
    modified_lines = []
    file_modified = False
    
    for line_num, line in enumerate(lines, start=1):
        modified_line, was_modified = process_line(line, line_num, filepath, warnings_list)
        modified_lines.append(modified_line)
        if was_modified:
            file_modified = True
    
    if file_modified and not dry_run:
        try:
            # Write modified content directly (inplace)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(modified_lines)
            return True
        except Exception as e:
            print(f"ERROR: Failed to write {filepath}: {e}")
            return False
    
    return file_modified


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Add retry parameters to wget commands in Dockerfiles'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be changed without modifying files'
    )
    parser.add_argument(
        '--root-dir',
        type=Path,
        default=Path.cwd(),
        help='Root directory to search for Dockerfiles (default: current directory)'
    )
    
    args = parser.parse_args()
    
    # Find all Dockerfiles
    dockerfiles = find_dockerfiles(args.root_dir)
    
    if not dockerfiles:
        print("No .dockerfile files found")
        return 0
    
    if args.dry_run:
        print(f"Found {len(dockerfiles)} Dockerfile(s)")
        print("=== DRY RUN MODE ===")
        print()
    
    modified_count = 0
    warnings_list = []
    
    for dockerfile in dockerfiles:
        if process_dockerfile(dockerfile, dry_run=args.dry_run, warnings_list=warnings_list):
            modified_count += 1
    
    # Print all warnings
    if warnings_list:
        print()
        for warning in warnings_list:
            print(warning)
        print()
    
    # Print summary
    print("="*60)
    if args.dry_run:
        print(f"Found {len(dockerfiles)} Dockerfile(s)")
        print(f"Would modify {modified_count} file(s)")
        if warnings_list:
            print(f"Found {len(warnings_list)} warning(s)")
    else:
        print(f"Processed {len(dockerfiles)} Dockerfile(s)")
        print(f"Modified {modified_count} file(s)")
        if warnings_list:
            print(f"Found {len(warnings_list)} warning(s)")
    print("="*60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
