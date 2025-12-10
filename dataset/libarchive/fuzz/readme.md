# libarchive Fuzzing Resources

This directory contains resources for fuzzing bsdtar (libarchive CLI tool) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with archive format tokens
- `in/` - Initial input corpus (archive files: tar, gz, bz2, xz)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on common archive format signatures and options.
- Reference: https://github.com/libarchive/libarchive

The initial input corpus contains sample archives created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libarchive/fuzz.dockerfile -t libarchive-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libarchive-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libarchive-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: bsdtar CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Archive files (tar, gz, bz2, xz) processed by bsdtar with `-tf` option (list contents)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libarchive version 3.8.3, matching the bc.dockerfile.
