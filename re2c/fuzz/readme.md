# re2c Fuzzing Resources

This directory contains resources for fuzzing re2c lexer generator using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (re2c syntax tokens)
- `in/` - Initial input corpus (re2c source files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on re2c language specification.

The initial input corpus contains sample re2c files covering various re2c features.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f re2c/fuzz.dockerfile -t re2c-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm re2c-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm re2c-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: re2c CLI binary (generates C/C++ lexer code from re2c specs)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: re2c specification files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses re2c version 4.3.
