# unifdef Fuzzing Resources

This directory contains resources for fuzzing unifdef using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with C preprocessor keywords
- `in/` - Initial input corpus (C source files with preprocessor directives)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains C preprocessor keywords created for this project.

The initial input corpus contains basic C files with preprocessor conditionals created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f unifdef/fuzz.dockerfile -t unifdef-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm unifdef-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm unifdef-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: unifdef CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: C source files with preprocessor conditionals
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses unifdef version 2.12, matching the bc.dockerfile.
