# jhead Fuzzing Resources

This directory contains resources for fuzzing jhead (EXIF JPEG header manipulation tool) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (JPEG/EXIF tokens)
- `in/` - Initial input corpus (minimal JPEG files with EXIF data)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- AFL++ jpeg.dict: https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/jpeg.dict
- EXIF specification markers and common strings

The initial input corpus contains minimal JPEG files with EXIF data created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f jhead/fuzz.dockerfile -t jhead-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm jhead-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm jhead-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: jhead CLI binary (parses JPEG files and reads/modifies EXIF data)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JPEG files with EXIF data
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses jhead version 3.08, matching the bc.dockerfile.
