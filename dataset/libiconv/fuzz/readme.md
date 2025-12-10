# libiconv Fuzzing Resources

This directory contains resources for fuzzing GNU libiconv using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file and input corpus are created for this project based on
common character encodings and test patterns.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libiconv/fuzz.dockerfile -t libiconv-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libiconv-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libiconv-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: iconv CLI binary
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text data for encoding conversion
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libiconv version 1.18, matching the bc.dockerfile.
