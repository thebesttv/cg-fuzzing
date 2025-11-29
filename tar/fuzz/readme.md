# tar Fuzzing Resources

This directory contains resources for fuzzing tar using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (tar archive files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on tar command-line options and tar archive format specification.

The initial input corpus contains various tar archive samples:
- `minimal.tar` - Simple single-file tar archive
- `multi.tar` - Multi-file tar archive
- `gzip.tar.gz` - Gzip compressed tar archive
- `empty.tar` - Empty tar archive

## Usage

Build the fuzzing Docker image:
```bash
docker build -f tar/fuzz.dockerfile -t tar-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm tar-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm tar-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: tar CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Tar archive files for tar to list/extract
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses tar version 1.35, matching the bc.dockerfile.
