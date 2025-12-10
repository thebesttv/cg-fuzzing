# libzip (zipcmp) Fuzzing Resources

This directory contains resources for fuzzing zipcmp (from libzip) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (ZIP format tokens)
- `in/` - Initial input corpus (ZIP files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- ZIP file format specification (PKWARE APPNOTE)
- Common ZIP headers and signatures
- Compression method identifiers

The initial input corpus contains:
- `minimal.zip` - Minimal valid ZIP archive
- `empty_file.zip` - ZIP with empty file
- `bad_magic.zip` - Invalid magic signature
- `eocd_only.zip` - Just end of central directory

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libzip/fuzz.dockerfile -t libzip-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libzip-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libzip-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: zipcmp CLI binary (compares input file with itself)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: ZIP archive files
- **Note**: bzip2, lzma, and zstd support disabled to avoid linking issues

## Version

This fuzzing setup uses libzip version 1.11.4, matching the bc.dockerfile.
