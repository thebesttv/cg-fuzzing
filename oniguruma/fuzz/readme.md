# oniguruma Fuzzing Resources

This directory contains resources for fuzzing the oniguruma regex library using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with regex syntax tokens
- `in/` - Initial input corpus (regex patterns)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on common regex syntax:
- Reference: https://github.com/kkos/oniguruma

The initial input corpus contains sample regex patterns created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f oniguruma/fuzz.dockerfile -t oniguruma-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm oniguruma-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm oniguruma-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: simple sample utility (regex matcher from oniguruma samples)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Regex patterns to be compiled and matched
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses oniguruma version 6.9.10, matching the bc.dockerfile.
