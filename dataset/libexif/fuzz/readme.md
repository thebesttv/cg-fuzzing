# libexif/exif Fuzzing Resources

This directory contains resources for fuzzing the exif CLI tool (libexif) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (EXIF/JPEG format tokens)
- `in/` - Initial input corpus (minimal JPEG files with EXIF data)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- EXIF 2.32 specification
- JPEG/JFIF file format
- Common EXIF tag names

The initial input corpus contains minimal JPEG samples with EXIF headers created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libexif/fuzz.dockerfile -t libexif-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libexif-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libexif-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: exif CLI binary (libexif command-line interface)
- **Library**: libexif v0.6.25
- **CLI Tool**: exif v0.6.22
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JPEG files with EXIF data
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses:
- libexif version 0.6.25
- exif CLI version 0.6.22
Both matching the bc.dockerfile.
