# miniz Fuzzing Resources

This directory contains resources for fuzzing miniz (compression library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (zlib/deflate magic bytes)
- `in/` - Initial input corpus (compressed data samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file contains common zlib/deflate/gzip magic bytes and headers.

The initial input corpus contains sample compressed data for testing decompression.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f miniz/fuzz.dockerfile -t miniz-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm miniz-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm miniz-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: miniz_fuzz binary (exercises zlib uncompress and inflate APIs)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Compressed data files (zlib, deflate format)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses miniz version 3.1.0, matching the bc.dockerfile.
