# libuv Fuzzing Resources

This directory contains resources for fuzzing libuv (async I/O library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with libuv-related keywords
- `in/` - Initial input corpus (various test files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- Dictionary: Created based on libuv API and async I/O patterns
- Input corpus: Minimal test files created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libuv/fuzz.dockerfile -t libuv-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libuv-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libuv-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm libuv-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: test_uv binary that uses libuv API
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Various test files to exercise async I/O operations
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libuv version 1.48.0, matching the bc.dockerfile.
