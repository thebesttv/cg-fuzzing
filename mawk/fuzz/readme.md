# mawk Fuzzing Resources

This directory contains resources for fuzzing mawk using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (AWK syntax tokens)
- `in/` - Initial input corpus (AWK program files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project, containing:
- AWK keywords (BEGIN, END, if, while, etc.)
- Built-in variables (NR, NF, FS, RS, etc.)
- Built-in functions (length, substr, split, etc.)
- Operators and special characters

The initial input corpus contains sample AWK programs.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mawk/fuzz.dockerfile -t mawk-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mawk-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mawk-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: mawk CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: AWK program files (-f option)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses mawk version 1.3.4-20240905, matching the bc.dockerfile.
