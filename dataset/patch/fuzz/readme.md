# GNU patch Fuzzing Resources

This directory contains resources for fuzzing GNU patch using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with patch format keywords
- `in/` - Initial input corpus (various patch format files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on unified diff, context diff, and git diff formats.

The initial input corpus contains various patch format samples:
- Unified diff format (unified1.patch, unified2.patch)
- Context diff format (context1.patch)
- Normal diff format (normal1.patch)
- Git diff format (git1.patch)
- New file creation (newfile.patch)
- File deletion (delete.patch)
- Multi-hunk patches (multi.patch)

## Usage

Build the fuzzing Docker image:
```bash
docker build -f patch/fuzz.dockerfile -t patch-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm patch-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm patch-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: GNU patch CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Patch files (unified, context, git diff formats)
- **Static linking**: For better performance and reproducibility
- **Options**: `-p0 -i` for reading patch from file with no path stripping

## Version

This fuzzing setup uses GNU patch version 2.8, matching the bc.dockerfile.
