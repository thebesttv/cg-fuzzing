# zlib-ng Fuzzing Resources

This directory contains resources for fuzzing zlib-ng minigzip using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (zlib/gzip specific bytes)
- `in/` - Initial input corpus (text and gzip files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains zlib/gzip specific bytes such as:
- Gzip magic bytes (\\x1f\\x8b\\x08)
- Zlib header bytes
- Command line options

The initial input corpus contains sample text and compressed files.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f zlib-ng/fuzz.dockerfile -t zlib-ng-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm zlib-ng-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm zlib-ng-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: minigzip CLI binary (from zlib-ng, same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Data to be compressed with -c option
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses zlib-ng version 2.3.1, matching the bc.dockerfile.
