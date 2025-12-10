# xz Fuzzing Resources

This directory contains resources for fuzzing xz using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (XZ/LZMA format tokens)
- `in/` - Initial input corpus (XZ and LZMA compressed files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- XZ file format specification: https://tukaani.org/xz/xz-file-format.txt
- LZMA SDK documentation

The initial input corpus contains:
- Small XZ compressed files
- LZMA format files
- Edge cases (empty files, tiny files)

## Usage

Build the fuzzing Docker image:
```bash
docker build -f xz/fuzz.dockerfile -t xz-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm xz-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm xz-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: xz CLI binary (decompression mode with `-d` flag)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Compressed files (XZ, LZMA formats)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses xz version 5.8.1, matching the bc.dockerfile.
