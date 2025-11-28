# libpng Fuzzing Resources

This directory contains resources for fuzzing libpng using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (PNG chunk types and magic numbers)
- `in/` - Initial input corpus (small PNG files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on PNG specification:
- PNG signature and chunk types
- Color types and bit depths
- Common metadata keywords

The initial input corpus contains small valid PNG samples from libpng's test suite.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libpng/fuzz.dockerfile -t libpng-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libpng-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libpng-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: png2pnm CLI binary (reads PNG and outputs PNM format)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: PNG image files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libpng version 1.6.47, matching the bc.dockerfile.
