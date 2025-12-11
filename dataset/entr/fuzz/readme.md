# entr Fuzzing Resources

This directory contains resources for fuzzing entr using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (path tokens)
- `in/` - Initial input corpus (file path lists)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project, containing:
- Command line options (-c, -d, -n, etc.)
- Path separators and components
- Special characters in paths
- Common path patterns

The initial input corpus contains sample file path lists.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f entr/fuzz.dockerfile -t entr-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm entr-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm entr-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: entr CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: File path lists piped to stdin
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses entr version 5.6, matching the bc.dockerfile.
