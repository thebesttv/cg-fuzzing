# minizip-ng Fuzzing Resources

This directory contains resources for fuzzing minizip-ng ZIP library using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (from minizip-ng project)
- `in/` - Initial input corpus (ZIP file samples from minizip-ng seed corpus)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress
- `harness/` - AFL++ harness source code

## External Resources

The dictionary file (`dict`) and seed corpus are from the minizip-ng project:
- Source: https://github.com/zlib-ng/minizip-ng/tree/develop/test/fuzz

## Usage

Build the fuzzing Docker image:
```bash
docker build -f minizip-ng/fuzz.dockerfile -t minizip-ng-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm minizip-ng-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm minizip-ng-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm minizip-ng-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: minizip_unzip_fuzz binary (ZIP file parser fuzzer)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: ZIP archive files
- **Dependencies**: zlib, bz2, lzma, openssl

## Version

This fuzzing setup uses minizip-ng version 4.0.10, matching the bc.dockerfile.
