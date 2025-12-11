# lowdown Fuzzing Resources

This directory contains resources for fuzzing lowdown using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Markdown syntax tokens)
- `in/` - Initial input corpus (Markdown files from lowdown's own AFL resources)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The initial input corpus (`in/`) is taken from lowdown's built-in AFL fuzzing resources:
- Source: https://github.com/kristapsdz/lowdown/tree/master/afl/in

The dictionary file (`dict`) was created for this project, containing:
- Markdown syntax tokens
- Header markers
- Emphasis characters
- List markers
- Code blocks
- Links and images syntax
- Table syntax
- HTML entities

## Usage

Build the fuzzing Docker image:
```bash
docker build -f lowdown/fuzz.dockerfile -t lowdown-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm lowdown-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm lowdown-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: lowdown CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Markdown files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses lowdown version 1.1.0, matching the bc.dockerfile.
