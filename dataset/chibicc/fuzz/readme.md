# chibicc Fuzzing Resources

This directory contains resources for fuzzing chibicc (small C compiler) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with C language keywords
- `in/` - Initial input corpus (C source files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

Dictionary keywords based on C language specification.

The initial input corpus contains example C source files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f chibicc/fuzz.dockerfile -t chibicc-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm chibicc-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm chibicc-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: chibicc CLI binary (C compiler)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: C source files
- **Output**: Assembly output (discarded with -S -o /dev/null)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses chibicc from the main branch.
