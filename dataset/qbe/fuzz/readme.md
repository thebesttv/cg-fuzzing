# qbe Fuzzing Resources

This directory contains resources for fuzzing QBE (a simple compiler backend) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (QBE IL keywords and operators)
- `in/` - Initial input corpus (QBE SSA/IL files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- QBE intermediate language specification: https://c9x.me/compile/doc/il.html
- QBE instruction set and syntax

The initial input corpus contains minimal QBE IL samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f qbe/fuzz.dockerfile -t qbe-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm qbe-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm qbe-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: qbe compiler backend binary
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: QBE intermediate language (.ssa) files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses qbe version 1.2, matching the bc.dockerfile.
