# argon2 Fuzzing Resources

This directory contains resources for fuzzing argon2 using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Argon2 specific keywords)
- `in/` - Initial input corpus (passwords to hash)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains Argon2 specific keywords such as:
- Argon2 variants (Argon2i, Argon2d, Argon2id)
- Command line options (-t, -m, -p, -l, etc.)
- Encoded hash prefixes ($argon2i$, $argon2d$, $argon2id$)

The initial input corpus contains sample passwords of various lengths.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f argon2/fuzz.dockerfile -t argon2-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm argon2-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm argon2-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: argon2 CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Password strings read from file, hashed with minimal parameters
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses argon2 version 20190702, matching the bc.dockerfile.
