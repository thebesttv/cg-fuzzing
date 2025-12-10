# uriparser Fuzzing Resources

This directory contains resources for fuzzing uriparser using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing containing URI-related tokens
- `in/` - Initial input corpus (URI samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project, containing common URI components:
- Scheme names (http, https, ftp, file, mailto, etc.)
- URI delimiters (://, @, :, ?, #, /)
- Percent-encoded characters
- IPv4 and IPv6 address patterns
- Common path and query patterns

The initial input corpus contains basic URI samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f uriparser/fuzz.dockerfile -t uriparser-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm uriparser-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm uriparser-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: uriparse CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: URI files processed by uriparse
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses uriparser version 0.9.9, matching the bc.dockerfile.
