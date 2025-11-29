# libtiff Fuzzing Resources

This directory contains resources for fuzzing libtiff tiffinfo using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with TIFF format keywords
- `in/` - Initial input corpus (TIFF files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Created based on TIFF file format specification
- in/: Minimal TIFF samples created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libtiff/fuzz.dockerfile -t libtiff-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libtiff-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libtiff-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm libtiff-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: tiffinfo CLI binary (TIFF file information extractor)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: TIFF image files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libtiff version 4.7.0, matching the bc.dockerfile.
