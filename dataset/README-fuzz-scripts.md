# Fuzz Script Management

This directory contains infrastructure for managing AFL++ fuzzing scripts across all projects.

## Overview

Instead of maintaining separate `fuzz.sh` files for each project, we now use:
- A **template** (`fuzz.sh`) with a placeholder for the AFL command
- Project-specific **AFL command templates** (`*/afl-cmd.template`)
- A **Makefile** to generate project-specific `fuzz.sh` files

## Files

### Template and Infrastructure

- `fuzz.sh` - Template fuzzing script with `AFL_CMD_REPLACE_ME` placeholder
- `Makefile` - Generates project-specific fuzz.sh files from template
- `.gitignore` - Ignores generated `*/fuzz/fuzz.sh` files (except the template)

### Project-Specific Files

Each project with a `fuzz.dockerfile` has:
- `<project>/afl-cmd.template` - Contains the AFL fuzzing command for that project
  - Example (jq): `"${TARGET_BIN}" '.' @@`
  - Example (entr): `/bin/sh -c "cat @@ | ${TARGET_BIN} -n true"`
  - Example (file): `"${TARGET_BIN}" -m "${MAGIC_FILE}" @@`

## Usage

### Generate fuzz.sh files for all projects

```bash
cd dataset
make update-fuzz-scripts
```

This creates `*/fuzz/fuzz.sh` for all 263 projects by replacing `AFL_CMD_REPLACE_ME` in the template with the content from each project's `afl-cmd.template`.

### Remove all generated fuzz.sh files

```bash
cd dataset
make clean
```

### Get help

```bash
cd dataset
make help
```

## Adding a New Project

When adding a new project:

1. Create the project's `fuzz.dockerfile` as usual
2. Create `<project>/afl-cmd.template` containing just the AFL command
   - Example: `"${TARGET_BIN}" @@`
3. Run `make update-fuzz-scripts` to generate the fuzz.sh file
4. Commit only the `afl-cmd.template`, not the generated `fuzz.sh`

## Modifying the Template

To update the template for all projects:

1. Edit `dataset/fuzz.sh`
2. Run `make update-fuzz-scripts` to regenerate all project-specific files
3. Test the changes with a few projects
4. Commit the updated template

## Why This Approach?

### Benefits

1. **Consistency**: All projects use the same fuzzing logic and best practices
2. **Maintainability**: Bug fixes and improvements apply to all projects at once
3. **Reduced duplication**: 263 nearly-identical scripts → 1 template + 263 one-liners
4. **Easy updates**: Change template once instead of updating 263 files
5. **Smaller repository**: Generated files are ignored by git

### What's Different Per-Project

Only the AFL command varies between projects, which is why we extract just that part into `afl-cmd.template`.

Common variations include:
- Different arguments: `jq '.' @@` vs `bzip2 -d -k -f @@`
- Shell wrappers: `/bin/sh -c "cat @@ | entr -n true"`
- Additional files: `file -m "${MAGIC_FILE}" @@`
- Output redirection: `wavpack -q @@ -o /tmp/output.wav`

## Implementation Details

The Makefile uses `awk` to safely replace the placeholder with the AFL command, handling:
- Special characters (pipes, quotes, etc.)
- Multi-word commands
- Shell metacharacters

Example transformation:

Template:
```bash
afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -- AFL_CMD_REPLACE_ME
```

With jq's `afl-cmd.template` (`"${TARGET_BIN}" '.' @@`):
```bash
afl-fuzz ${AFL_ARGS} ${CMPLOG_ARGS} -- "${TARGET_BIN}" '.' @@
```

## Statistics

- **Projects**: 263 (all with `fuzz.dockerfile`)
- **Template**: 1 file (140 lines)
- **AFL commands**: 265 files (1 line each)
- **Generated fuzz.sh**: 263 files (140 lines each, not committed)
- **Space saved**: ~35,000 lines of duplicated code removed from repository
