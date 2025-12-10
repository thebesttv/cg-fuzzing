# diffutils Fuzzing Resources

This directory contains resources for fuzzing diff using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (based on diff/unified diff format)
- `in/` - Initial input corpus (text files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on unified diff format and common text patterns.

The initial input corpus contains basic text files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f diffutils/fuzz.dockerfile -t diffutils-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm diffutils-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm diffutils-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: diff CLI binary
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text files compared against /dev/null
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses diffutils version 3.12, matching the bc.dockerfile.
