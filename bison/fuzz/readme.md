# bison Fuzzing Resources

This directory contains resources for fuzzing bison using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (bison grammar files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on bison documentation and keywords.

The initial input corpus contains basic bison grammar samples.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f bison/fuzz.dockerfile -t bison-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm bison-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm bison-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: bison CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Bison grammar files (.y files)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses bison version 3.8.2, matching the bc.dockerfile.
