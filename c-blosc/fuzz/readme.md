# c-blosc Fuzzing Resources

This directory contains resources for fuzzing c-blosc compression library using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with blosc format keywords
- `in/` - Initial input corpus (blosc compressed data samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress
- `harness/` - AFL++ harness source code

## External Resources

The dictionary file (`dict`) contains blosc chunk format patterns created for this project.
The initial input corpus contains minimal valid blosc headers.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f c-blosc/fuzz.dockerfile -t c-blosc-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm c-blosc-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm c-blosc-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm c-blosc-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: blosc_decompress_fuzz binary (blosc decompression fuzzer)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Blosc compressed data chunks
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses c-blosc version 1.21.6, matching the bc.dockerfile.
