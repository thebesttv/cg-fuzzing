# libdeflate Fuzzing Resources

This directory contains resources for fuzzing libdeflate-gzip using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (gzip/deflate format tokens)
- `in/` - Initial input corpus (small gzip files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- RFC 1951 (DEFLATE Compressed Data Format)
- RFC 1952 (GZIP file format)
- Zlib format specifications

The initial input corpus contains minimal gzip samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libdeflate/fuzz.dockerfile -t libdeflate-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libdeflate-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libdeflate-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: libdeflate-gzip CLI binary (decompression with -d -c flags)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Gzip compressed files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libdeflate version 1.25, matching the bc.dockerfile.
