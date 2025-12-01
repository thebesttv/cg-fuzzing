# libplist Fuzzing Resources

This directory contains resources for fuzzing libplist (plistutil) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with plist keywords
- `in/` - Initial input corpus (plist files in XML, JSON, and OpenStep formats)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on plist format keywords and elements.

The initial input corpus contains basic plist samples in various formats created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libplist/fuzz.dockerfile -t libplist-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libplist-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libplist-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: plistutil CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: plist files (XML, binary, JSON, OpenStep formats)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libplist version 2.7.0, matching the bc.dockerfile.
