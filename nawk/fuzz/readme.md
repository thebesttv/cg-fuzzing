# nawk (One True AWK) Fuzzing Resources

This directory contains resources for fuzzing nawk (One True AWK by Brian Kernighan) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (AWK keywords and operators)
- `in/` - Initial input corpus (AWK program files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project based on:
- AWK language keywords (BEGIN, END, print, etc.)
- Built-in variables (NF, NR, FS, etc.)
- Built-in functions (length, substr, split, etc.)
- Operators

The initial input corpus contains:
- `hello.awk` - Simple BEGIN block
- `lines.awk` - Line numbering
- `sum.awk` - Sum first field
- `regex.awk` - Pattern matching with regex
- `field.awk` - Field separator usage
- `func.awk` - User-defined function

## Usage

Build the fuzzing Docker image:
```bash
docker build -f nawk/fuzz.dockerfile -t nawk-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm nawk-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm nawk-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: nawk binary (One True AWK interpreter)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: AWK program files (using -f flag)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses nawk version 20240728, matching the bc.dockerfile.
