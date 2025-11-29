# cpio Fuzzing Resources

This directory contains resources for fuzzing GNU cpio using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (cpio archive samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file and input corpus are created for this project based on
cpio archive format specification.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f cpio/fuzz.dockerfile -t cpio-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm cpio-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm cpio-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: cpio CLI binary (copy-in mode)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: cpio archive data
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses GNU cpio version 2.15, matching the bc.dockerfile.
