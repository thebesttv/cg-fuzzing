# tinf (tgunzip) Fuzzing Resources

This directory contains resources for fuzzing tinf (tiny inflate library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with gzip/deflate magic bytes
- `in/` - Initial input corpus (gzip files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains gzip/deflate related magic bytes and keywords.

The initial input corpus contains simple gzip compressed files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f tinf/fuzz.dockerfile -t tinf-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm tinf-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm tinf-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: tgunzip CLI binary (gzip decompressor example)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: gzip compressed files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses tinf version 1.2.1, matching the bc.dockerfile.
