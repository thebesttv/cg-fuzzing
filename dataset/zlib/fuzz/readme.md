# zlib Fuzzing Resources

This directory contains resources for fuzzing zlib using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (gzip/zlib magic numbers and patterns)
- `in/` - Initial input corpus (compressed data files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on gzip/zlib specification:
- gzip magic numbers and header fields
- zlib header bytes
- Common deflate patterns

The initial input corpus contains small compressed samples.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f zlib/fuzz.dockerfile -t zlib-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm zlib-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm zlib-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: minigzip CLI binary (decompression mode with -d flag)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: gzip compressed data files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses zlib version 1.3.1, matching the bc.dockerfile.
