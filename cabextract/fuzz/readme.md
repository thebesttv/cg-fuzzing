# cabextract Fuzzing Resources

This directory contains resources for fuzzing cabextract using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (CAB file format tokens)
- `in/` - Initial input corpus (CAB files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- Microsoft Cabinet file format specification
- CAB header and compression type markers
- Common cabinet file structures

The initial input corpus contains:
- `minimal.cab` - Minimal valid CAB structure
- `empty.cab` - CAB header with no files
- `bad_magic.cab` - Invalid magic signature for edge case testing
- `multi.cab` - Multi-cabinet spanning CAB

## Usage

Build the fuzzing Docker image:
```bash
docker build -f cabextract/fuzz.dockerfile -t cabextract-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm cabextract-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm cabextract-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: cabextract CLI binary with `-t` flag (test mode, no extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: CAB archive files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses cabextract version 1.11, matching the bc.dockerfile.
