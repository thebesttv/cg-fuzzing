# potrace Fuzzing Resources

This directory contains resources for fuzzing potrace (bitmap to vector graphics tracer) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (PBM/PGM/PPM/BMP tokens)
- `in/` - Initial input corpus (minimal bitmap files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- PBM/PGM/PPM (Netpbm) format specifications
- BMP file format headers
- potrace command line options

The initial input corpus contains minimal bitmap files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f potrace/fuzz.dockerfile -t potrace-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm potrace-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm potrace-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: potrace CLI binary (converts bitmap images to vector graphics)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: PBM/PGM/PPM/BMP bitmap files
- **Output**: SVG (discarded to /dev/null)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses potrace version 1.16, matching the bc.dockerfile.
