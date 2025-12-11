# zopfli Fuzzing Resources

This directory contains resources for fuzzing zopfli using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (compression-related tokens)
- `in/` - Initial input corpus (small text/binary files to compress)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- DEFLATE/Gzip format specifications
- Common patterns in compressible data

The initial input corpus contains small sample files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f zopfli/fuzz.dockerfile -t zopfli-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm zopfli-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm zopfli-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: zopfli CLI binary (compression with -c flag, outputs to stdout)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Various text and binary files for compression
- **Static linking**: For better performance and reproducibility

## Note

Zopfli is a compression tool (not decompression), so we fuzz the compression
path. It's known for being slow but producing very compact output.

## Version

This fuzzing setup uses zopfli version 1.0.3, matching the bc.dockerfile.
