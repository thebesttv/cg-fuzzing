# cproto Fuzzing Resources

This directory contains resources for fuzzing cproto (C prototype generator) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with C language keywords
- `in/` - Initial input corpus (C source files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

Dictionary keywords based on C language specification and common constructs.

The initial input corpus contains example C source files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f cproto/fuzz.dockerfile -t cproto-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm cproto-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm cproto-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: cproto CLI binary (C prototype generator)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: C source files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses cproto version 4.7w, matching the bc.dockerfile.
