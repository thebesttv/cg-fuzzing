# rhash Fuzzing Resources

This directory contains resources for fuzzing rhash using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created specifically for rhash, containing:
- Hash algorithm names (md5, sha256, etc.)
- Command line options
- Special characters

The initial input corpus contains sample files for hash computation.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f rhash/fuzz.dockerfile -t rhash-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm rhash-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm rhash-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: rhash CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Files to be hashed
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses RHash version 1.4.5, matching the bc.dockerfile.
