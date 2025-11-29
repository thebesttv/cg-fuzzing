# findutils Fuzzing Resources

This directory contains resources for fuzzing xargs (from findutils) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (input files for xargs)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on xargs command-line options and special characters.

The initial input corpus contains various input formats for xargs.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f findutils/fuzz.dockerfile -t findutils-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm findutils-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm findutils-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: xargs CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Files containing filenames/arguments for xargs to process
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses findutils version 4.10.0, matching the bc.dockerfile.
