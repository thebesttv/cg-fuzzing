# dash Fuzzing Resources

This directory contains resources for fuzzing dash using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (POSIX shell tokens)
- `in/` - Initial input corpus (shell scripts)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- POSIX shell specification
- dash man page and documentation

The initial input corpus contains:
- Simple shell scripts (echo, variables, loops)
- Control flow examples (if, case, for)
- Edge cases (empty files, minimal scripts)

## Usage

Build the fuzzing Docker image:
```bash
docker build -f dash/fuzz.dockerfile -t dash-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm dash-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm dash-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: dash CLI binary (POSIX shell interpreter)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Shell script files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses dash version 0.5.12, matching the bc.dockerfile.
