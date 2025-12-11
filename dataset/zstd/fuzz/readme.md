# zstd Fuzzing Resources

This directory contains resources for fuzzing zstd using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (zstd frame format tokens)
- `in/` - Initial input corpus (zstd compressed files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on the zstd frame format specification:
- Source: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md

The initial input corpus contains zstd compressed samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f zstd/fuzz.dockerfile -t zstd-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm zstd-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm zstd-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: zstd CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: zstd compressed files, decompressed with -d flag
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses zstd version 1.5.7, matching the bc.dockerfile.
