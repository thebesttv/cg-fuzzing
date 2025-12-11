# lzfse Fuzzing Resources

This directory contains resources for fuzzing Apple's LZFSE compression library using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (LZFSE format tokens)
- `in/` - Initial input corpus (LZFSE compressed files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- LZFSE format specification from Apple's open source release
- LZFSE block magic bytes and common patterns

The initial input corpus contains minimal LZFSE format samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f lzfse/fuzz.dockerfile -t lzfse-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm lzfse-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm lzfse-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: lzfse CLI binary (decompression mode)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: LZFSE compressed files (decode mode)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses lzfse version 1.0, matching the bc.dockerfile.
