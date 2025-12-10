# stb_image Fuzzing Resources

This directory contains resources for fuzzing stb_image using AFL++.

## About stb_image

stb_image is a single-file public domain image loading library that supports:
- JPEG (baseline & progressive)
- PNG (1/2/4/8/16-bit-per-channel)
- TGA
- BMP
- PSD (composited view only)
- GIF
- HDR (radiance rgbE format)
- PIC (Softimage)
- PNM (PPM and PGM binary only)

Since stb_image is a header-only library, a harness program (`stb_image_harness.c`) is created that implements the library and loads images from file input.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with image format tokens
- `in/` - Initial input corpus (minimal sample images)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains tokens for various image formats supported by stb_image:
- PNG chunk signatures
- JPEG markers
- BMP signatures
- GIF signatures
- Other format headers (PSD, TGA, HDR, PIC, PNM)

Based on:
- AFL++ dictionaries: https://github.com/AFLplusplus/AFLplusplus/tree/stable/dictionaries
- Image format specifications

The initial input corpus contains minimal valid images in various formats.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f stb/fuzz.dockerfile -t stb-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm stb-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm stb-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: stb_image_harness CLI binary (loads image files using stb_image.h)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Image files (PNG, JPEG, BMP, GIF, etc.)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses the latest stb commit from https://github.com/nothings/stb
