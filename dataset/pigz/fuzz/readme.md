# pigz Fuzzing Resources

This directory contains resources for fuzzing pigz using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (gzip/zlib related tokens)
- `in/` - Initial input corpus (gzip compressed files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains gzip/zlib magic numbers and common tokens.

The initial input corpus contains sample gzip-compressed files.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f pigz/fuzz.dockerfile -t pigz-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm pigz-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm pigz-fuzz ./fuzz.sh -j 4
```

Monitor progress:
```bash
docker run -it --rm pigz-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: pigz CLI binary (decompression mode with `-d -k -c`)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: gzip compressed files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses pigz version 2.8, matching the bc.dockerfile.
