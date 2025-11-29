# gzip Fuzzing Resources

This directory contains resources for fuzzing gzip using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (based on RFC 1952 GZIP format)
- `in/` - Initial input corpus (small gzip compressed files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on RFC 1952 - GZIP file format specification.

The initial input corpus contains small gzip compressed samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f gzip/fuzz.dockerfile -t gzip-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm gzip-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm gzip-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: gzip CLI binary (decompression mode with -d -c flags)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: gzip compressed files to be decompressed
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses gzip version 1.14, matching the bc.dockerfile.
