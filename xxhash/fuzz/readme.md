# xxHash Fuzzing Resources

This directory contains resources for fuzzing xxhsum (xxHash CLI tool) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with xxhsum command-line options
- `in/` - Initial input corpus (binary/text files to hash)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on xxhsum command-line options.
- Reference: https://github.com/Cyan4973/xxHash

The initial input corpus contains sample files of various sizes.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f xxhash/fuzz.dockerfile -t xxhash-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm xxhash-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm xxhash-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: xxhsum CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Files to be hashed by xxhsum
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses xxHash version 0.8.3, matching the bc.dockerfile.
