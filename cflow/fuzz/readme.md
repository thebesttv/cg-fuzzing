# cflow Fuzzing Resources

This directory contains resources for fuzzing cflow using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with C language keywords
- `in/` - Initial input corpus (C source files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Created based on C language keywords and common patterns
- in/: Sample C source files created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f cflow/fuzz.dockerfile -t cflow-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm cflow-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm cflow-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm cflow-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: cflow CLI binary (C call graph analyzer)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: C source code files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses cflow version 1.7, matching the bc.dockerfile.
