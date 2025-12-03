# uchardet Fuzzing Resources

This directory contains resources for fuzzing uchardet (universal charset detection library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with charset names and BOM markers
- `in/` - Initial input corpus (text files with various encodings)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains common charset names and byte order marks (BOMs)
used for character encoding detection.

The initial input corpus contains sample files in various character encodings.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f uchardet/fuzz.dockerfile -t uchardet-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm uchardet-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm uchardet-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: uchardet CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Binary/text files with various character encodings
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses uchardet version 0.0.8, matching the bc.dockerfile.
