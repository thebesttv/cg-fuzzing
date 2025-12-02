# libwebp Fuzzing Resources

This directory contains resources for fuzzing libwebp's dwebp decoder using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (WebP format tokens)
- `in/` - Initial input corpus (minimal WebP files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- WebP file format specification: https://developers.google.com/speed/webp/docs/riff_container
- VP8/VP8L bitstream specifications

The initial input corpus contains minimal WebP files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libwebp/fuzz.dockerfile -t libwebp-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libwebp-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libwebp-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: dwebp CLI binary (WebP decoder)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: WebP image files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libwebp version 1.5.0, matching the bc.dockerfile.
