# TCC (Tiny C Compiler) Fuzzing Resources

This directory contains resources for fuzzing TCC using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (C language keywords and operators)
- `in/` - Initial input corpus (small C source files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project based on C language keywords, operators, and preprocessor directives.

The initial input corpus contains basic C source files created for this project, covering:
- Simple hello world
- Functions
- Structs
- Arrays
- Pointers
- Enums
- Macros
- Loops

## Usage

Build the fuzzing Docker image:
```bash
docker build -f tcc/fuzz.dockerfile -t tcc-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm tcc-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm tcc-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: TCC (Tiny C Compiler) binary
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: C source files compiled with `-c` flag (compile only, no linking)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses TCC version 0.9.27, matching the bc.dockerfile.
