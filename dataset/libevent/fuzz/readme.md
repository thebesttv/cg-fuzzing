# libevent Fuzzing Resources

This directory contains resources for fuzzing libevent (event notification library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with event-related keywords
- `in/` - Initial input corpus (various test files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- Dictionary: Created based on libevent API and event handling patterns
- Input corpus: Minimal test files created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libevent/fuzz.dockerfile -t libevent-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libevent-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libevent-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm libevent-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: test_event binary that uses libevent API
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Various test files to exercise event handling
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libevent version 2.1.12-stable, matching the bc.dockerfile.
