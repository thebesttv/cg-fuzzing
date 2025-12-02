# picoc Fuzzing Resources

This directory contains resources for fuzzing picoc (small C interpreter) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with C language keywords
- `in/` - Initial input corpus (C source files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains C language keywords and operators
commonly used in C programs.

The initial input corpus contains basic C programs created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f picoc/fuzz.dockerfile -t picoc-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm picoc-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm picoc-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: picoc CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: C source files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses picoc version 3.2.2, matching the bc.dockerfile.
